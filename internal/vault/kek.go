package vault

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
)

// KeySource supplies the master key (KEK) that wraps every entry's data key.
type KeySource interface {
	// Load returns the master key, or ErrNoKey if none has been created yet.
	Load() ([]byte, error)
	// Store persists a newly generated master key.
	Store(key []byte) error
	// Describe reports exactly where this source reads from, so `sa-vault doctor` can
	// show the user precisely what will be touched.
	Describe() string
}

// ErrNoKey means no master key exists yet — the vault has not been initialized.
var ErrNoKey = errors.New("vault: no master key found")

// Keychain identity. Both attributes are always supplied together; see
// keychain_darwin.go for why that matters.
const (
	KeychainService = "com.magroski.sa-vault"
	KeychainAccount = "vault-kek"
)

// NewKeySource picks a key source from the environment, most explicit first.
//
//	SA_VAULT_KEK_FILE    a 0600 file holding a base64 master key
//	SA_VAULT_PASSPHRASE  derive the key from a passphrase (CI, Linux, SSH)
//	(default)                the OS keychain, where one is available
func NewKeySource(dir string) KeySource {
	if path := os.Getenv("SA_VAULT_KEK_FILE"); path != "" {
		return &fileSource{path: path}
	}
	if passphrase := os.Getenv("SA_VAULT_PASSPHRASE"); passphrase != "" {
		return &passphraseSource{passphrase: passphrase, saltPath: filepath.Join(dir, "kek.salt")}
	}
	return newOSKeySource()
}

// fileSource keeps the master key in a 0600 file. It has no keychain surface at
// all, which some people prefer; at rest it is only as strong as the filesystem.
type fileSource struct{ path string }

func (f *fileSource) Describe() string { return "key file " + f.path }

func (f *fileSource) Load() ([]byte, error) {
	data, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoKey
	}
	if err != nil {
		return nil, err
	}
	if err := checkPrivatePerms(f.path); err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("vault: key file %s is not valid base64: %w", f.path, err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("vault: key file %s holds %d bytes, want %d", f.path, len(key), KeySize)
	}
	return key, nil
}

func (f *fileSource) Store(key []byte) error {
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	return writePrivate(f.path, []byte(encoded+"\n"))
}

// passphraseSource derives the master key from a passphrase with argon2id. The
// salt is stored alongside the vault; it is not secret.
type passphraseSource struct {
	passphrase string
	saltPath   string
}

func (p *passphraseSource) Describe() string {
	return "passphrase from $SA_VAULT_PASSPHRASE (salt " + p.saltPath + ")"
}

// Argon2id parameters, chosen for an interactive-latency unlock on a laptop.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	saltSize     = 16
)

func (p *passphraseSource) Load() ([]byte, error) {
	salt, err := os.ReadFile(p.saltPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoKey
	}
	if err != nil {
		return nil, err
	}
	return p.derive(salt), nil
}

// Store records a fresh salt. The key itself is never written: it is recomputed
// from the passphrase on every load, so the supplied key is discarded.
func (p *passphraseSource) Store([]byte) error {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.saltPath), 0o700); err != nil {
		return err
	}
	return writePrivate(p.saltPath, salt)
}

func (p *passphraseSource) derive(salt []byte) []byte {
	return argon2.IDKey([]byte(p.passphrase), salt, argonTime, argonMemory, argonThreads, KeySize)
}
