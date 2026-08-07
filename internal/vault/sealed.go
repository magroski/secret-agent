package vault

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// The sealed file uses envelope encryption: every entry owns a random data key
// (DEK) which encrypts that entry's fields, and each DEK is itself wrapped by the
// master key (KEK). Rotating the KEK therefore rewraps a handful of small keys
// instead of re-encrypting every value.
//
// Each ciphertext is bound to its identity via AEAD additional data
// ("<entry>/<field>"), so a value cannot be moved between entries or fields
// without detection.

const sealedVersion = 1

// KeySize is the length of both the KEK and each DEK.
const KeySize = chacha20poly1305.KeySize

type sealedBox struct {
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ct"`
}

type sealedEntry struct {
	// WrappedDEK is this entry's data key, encrypted under the KEK.
	WrappedDEK sealedBox `json:"wrapped_dek"`
	// Fields maps a field name to its value encrypted under the DEK.
	Fields map[string]sealedBox `json:"fields"`
}

type sealedFile struct {
	Version int                    `json:"version"`
	Entries map[string]sealedEntry `json:"entries"`
}

var (
	// ErrWrongKey means the master key did not decrypt the vault. Usually the
	// Keychain item was replaced, or the wrong passphrase was supplied.
	ErrWrongKey = errors.New("vault: master key does not decrypt this vault")
	// ErrNoSuchField means the entry exists but carries no such sealed field.
	ErrNoSuchField = errors.New("vault: no such field")
)

func seal(key, plaintext, aad []byte) (sealedBox, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return sealedBox{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return sealedBox{}, fmt.Errorf("generate nonce: %w", err)
	}
	return sealedBox{Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, plaintext, aad)}, nil
}

func open(key []byte, box sealedBox, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(box.Nonce) != aead.NonceSize() {
		return nil, ErrWrongKey
	}
	out, err := aead.Open(nil, box.Nonce, box.Ciphertext, aad)
	if err != nil {
		return nil, ErrWrongKey
	}
	return out, nil
}

// aad binds a ciphertext to the entry and field it belongs to.
func aad(entry, field string) []byte { return []byte(entry + "/" + field) }

// dekAAD binds a wrapped data key to its entry.
func dekAAD(entry string) []byte { return []byte("dek/" + entry) }

func newKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return key, nil
}

// setFields seals values for one entry, replacing any fields of the same name
// and preserving the rest. It reuses the entry's existing DEK when present so
// unchanged fields keep their ciphertext.
func (s *sealedFile) setFields(kek []byte, entryName string, values map[string]string) error {
	if s.Entries == nil {
		s.Entries = map[string]sealedEntry{}
	}

	entry, exists := s.Entries[entryName]
	var dek []byte
	if exists {
		var err error
		if dek, err = open(kek, entry.WrappedDEK, dekAAD(entryName)); err != nil {
			return err
		}
	} else {
		var err error
		if dek, err = newKey(); err != nil {
			return err
		}
		wrapped, err := seal(kek, dek, dekAAD(entryName))
		if err != nil {
			return err
		}
		entry = sealedEntry{WrappedDEK: wrapped, Fields: map[string]sealedBox{}}
	}
	if entry.Fields == nil {
		entry.Fields = map[string]sealedBox{}
	}

	for field, value := range values {
		box, err := seal(dek, []byte(value), aad(entryName, field))
		if err != nil {
			return err
		}
		entry.Fields[field] = box
	}

	s.Entries[entryName] = entry
	return nil
}

// getFields unseals every field of one entry.
func (s *sealedFile) getFields(kek []byte, entryName string) (map[string]string, error) {
	entry, ok := s.Entries[entryName]
	if !ok {
		return nil, fmt.Errorf("vault: %q has no sealed values", entryName)
	}
	dek, err := open(kek, entry.WrappedDEK, dekAAD(entryName))
	if err != nil {
		return nil, err
	}

	out := make(map[string]string, len(entry.Fields))
	for field, box := range entry.Fields {
		value, err := open(dek, box, aad(entryName, field))
		if err != nil {
			return nil, fmt.Errorf("vault: field %q of %q: %w", field, entryName, err)
		}
		out[field] = string(value)
	}
	return out, nil
}

// getField unseals a single field, avoiding the cost of the whole entry.
func (s *sealedFile) getField(kek []byte, entryName, field string) (string, error) {
	entry, ok := s.Entries[entryName]
	if !ok {
		return "", fmt.Errorf("vault: %q has no sealed values", entryName)
	}
	box, ok := entry.Fields[field]
	if !ok {
		return "", ErrNoSuchField
	}
	dek, err := open(kek, entry.WrappedDEK, dekAAD(entryName))
	if err != nil {
		return "", err
	}
	value, err := open(dek, box, aad(entryName, field))
	if err != nil {
		return "", err
	}
	return string(value), nil
}

// hasField reports whether ciphertext exists for one field.
func (s *sealedFile) hasField(entryName, field string) bool {
	entry, ok := s.Entries[entryName]
	if !ok {
		return false
	}
	_, ok = entry.Fields[field]
	return ok
}

// retainFields drops any sealed field the entry no longer declares, so a removed
// variable leaves no ciphertext behind.
func (s *sealedFile) retainFields(entryName string, keep []string) {
	entry, ok := s.Entries[entryName]
	if !ok {
		return
	}
	wanted := make(map[string]bool, len(keep))
	for _, name := range keep {
		wanted[name] = true
	}
	for field := range entry.Fields {
		if !wanted[field] {
			delete(entry.Fields, field)
		}
	}
	s.Entries[entryName] = entry
}

func (s *sealedFile) remove(entryName string) { delete(s.Entries, entryName) }

func (s *sealedFile) marshal() ([]byte, error) {
	s.Version = sealedVersion
	return json.MarshalIndent(s, "", "  ")
}

func unmarshalSealed(data []byte) (*sealedFile, error) {
	s := &sealedFile{Entries: map[string]sealedEntry{}}
	if len(data) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("vault: sealed file is corrupt: %w", err)
	}
	if s.Version != sealedVersion {
		return nil, fmt.Errorf("vault: sealed file version %d is not supported", s.Version)
	}
	if s.Entries == nil {
		s.Entries = map[string]sealedEntry{}
	}
	return s, nil
}
