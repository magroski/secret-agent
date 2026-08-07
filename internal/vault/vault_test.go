package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestVault builds an initialized vault backed by a temporary key file, so
// tests never touch the real keychain.
func newTestVault(t *testing.T) *Vault {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SA_VAULT_KEK_FILE", filepath.Join(dir, "kek"))
	t.Setenv("SA_VAULT_PASSPHRASE", "")

	v, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := v.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return v
}

func sampleEntry() Entry {
	return Entry{
		Name:        "cdp-es",
		Description: "candidate Elasticsearch cluster",
		Tags:        []string{"cdp"},
		Vars: []Var{
			{Name: "ES_ENDPOINT", Value: "https://logs.internal:9200"},
			{Name: "ES_API_KEY", Secret: true},
		},
	}
}

func TestPutAndUnsealRoundTrip(t *testing.T) {
	v := newTestVault(t)
	const key = "correct horse battery staple"

	if err := v.Put(sampleEntry(), map[string]string{"ES_API_KEY": key}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := v.UnsealVar("cdp-es", "ES_API_KEY")
	if err != nil {
		t.Fatalf("UnsealVar: %v", err)
	}
	if got != key {
		t.Errorf("value = %q, want %q", got, key)
	}
}

// The whole point of splitting metadata from sealed values is that discovery
// works with no key at all. If this breaks, `ls` starts prompting.
func TestMetadataReadableWithoutMasterKey(t *testing.T) {
	v := newTestVault(t)
	if err := v.Put(sampleEntry(), map[string]string{"ES_API_KEY": "hunter2"}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Reopen with the key file pointed somewhere that does not exist.
	t.Setenv("SA_VAULT_KEK_FILE", filepath.Join(t.TempDir(), "absent"))
	reopened, err := Open(v.Dir())
	if err != nil {
		t.Fatalf("Open without key: %v", err)
	}

	entry, ok := reopened.Get("cdp-es")
	if !ok {
		t.Fatal("entry not found without master key")
	}
	endpoint, _ := entry.Var("ES_ENDPOINT")
	if endpoint.Value != "https://logs.internal:9200" {
		t.Errorf("ES_ENDPOINT = %q, want the cluster URL", endpoint.Value)
	}
	if _, err := reopened.UnsealVar("cdp-es", "ES_API_KEY"); err == nil {
		t.Error("UnsealVar succeeded without a master key; it must not")
	}
}

// Metadata must never contain secret material, however the caller supplies it.
func TestMetadataFileHoldsNoPlaintext(t *testing.T) {
	v := newTestVault(t)
	const key = "s3cr3t-needle-value"
	if err := v.Put(sampleEntry(), map[string]string{"ES_API_KEY": key}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	for _, name := range []string{MetadataFile, SealedFile} {
		data, err := os.ReadFile(filepath.Join(v.Dir(), name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if strings.Contains(string(data), key) {
			t.Errorf("%s contains the plaintext value", name)
		}
	}
}

// A variable marked secret must not carry a cleartext value, or Put would write
// it straight into the metadata file the previous test guards.
func TestSecretVarWithCleartextValueIsRejected(t *testing.T) {
	v := newTestVault(t)
	entry := Entry{
		Name: "leaky",
		Vars: []Var{{Name: "TOKEN", Value: "in-the-clear", Secret: true}},
	}
	if err := v.Put(entry, nil); err == nil {
		t.Fatal("Put accepted a secret variable carrying a cleartext value")
	}
}

// An entry that declares a secret with nothing sealed behind it would promise a
// variable `env` could not produce.
func TestPutRejectsSecretWithNoValue(t *testing.T) {
	v := newTestVault(t)
	entry := Entry{Name: "empty", Vars: []Var{{Name: "TOKEN", Secret: true}}}
	if err := v.Put(entry, nil); err == nil {
		t.Fatal("Put accepted a declared secret with no value")
	}
}

// Values may only be supplied for variables the entry actually declares secret;
// otherwise a caller could seal a value that nothing ever reads.
func TestPutRejectsValueForUndeclaredVar(t *testing.T) {
	v := newTestVault(t)
	err := v.Put(sampleEntry(), map[string]string{"ES_API_KEY": "k", "STRAY": "x"})
	if err == nil || !strings.Contains(err.Error(), "STRAY") {
		t.Fatalf("Put error = %v, want a complaint about STRAY", err)
	}
}

// Removing a variable must remove its ciphertext too, not orphan it.
func TestRemovingAVarDropsItsCiphertext(t *testing.T) {
	v := newTestVault(t)
	entry := Entry{
		Name: "pair",
		Vars: []Var{{Name: "A", Secret: true}, {Name: "B", Secret: true}},
	}
	if err := v.Put(entry, map[string]string{"A": "a-value", "B": "b-value"}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	entry.Vars = []Var{{Name: "A", Secret: true}}
	if err := v.Put(entry, nil); err != nil {
		t.Fatalf("Put after removing B: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(v.Dir(), SealedFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"B"`) {
		t.Error("sealed file still holds a box for the removed variable B")
	}
	if _, err := v.UnsealVar("pair", "B"); err == nil {
		t.Error("B is still readable after being removed")
	}
	if got, err := v.UnsealVar("pair", "A"); err != nil || got != "a-value" {
		t.Errorf("A = %q, %v; want it untouched", got, err)
	}
}

// AAD binds each ciphertext to its entry and field, so a value cannot be moved
// between variables by editing the sealed file.
func TestFieldCiphertextIsBoundToItsIdentity(t *testing.T) {
	key, err := newKey()
	if err != nil {
		t.Fatal(err)
	}
	s, _ := unmarshalSealed(nil)
	if err := s.setFields(key, "entry-a", map[string]string{"PASSWORD": "value-a"}); err != nil {
		t.Fatalf("setFields: %v", err)
	}
	if err := s.setFields(key, "entry-a", map[string]string{"API_KEY": "value-b"}); err != nil {
		t.Fatalf("setFields: %v", err)
	}

	// Swap the two ciphertexts, as a tamperer with file access would.
	entry := s.Entries["entry-a"]
	entry.Fields["PASSWORD"], entry.Fields["API_KEY"] = entry.Fields["API_KEY"], entry.Fields["PASSWORD"]
	s.Entries["entry-a"] = entry

	if _, err := s.getField(key, "entry-a", "PASSWORD"); !errors.Is(err, ErrWrongKey) {
		t.Errorf("swapped ciphertext error = %v, want ErrWrongKey", err)
	}
}

func TestWrongMasterKeyIsRejected(t *testing.T) {
	key, _ := newKey()
	other, _ := newKey()

	s, _ := unmarshalSealed(nil)
	if err := s.setFields(key, "e", map[string]string{"PASSWORD": "v"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.getField(other, "e", "PASSWORD"); !errors.Is(err, ErrWrongKey) {
		t.Errorf("error = %v, want ErrWrongKey", err)
	}
}

// A metadata-only edit must not require resupplying the secret.
func TestPutPreservesUnsuppliedValues(t *testing.T) {
	v := newTestVault(t)
	if err := v.Put(sampleEntry(), map[string]string{"ES_API_KEY": "keepme"}); err != nil {
		t.Fatal(err)
	}

	updated := sampleEntry()
	updated.Description = "now with a different description"
	if err := v.Put(updated, nil); err != nil {
		t.Fatalf("Put without values: %v", err)
	}

	got, err := v.UnsealVar("cdp-es", "ES_API_KEY")
	if err != nil {
		t.Fatalf("UnsealVar: %v", err)
	}
	if got != "keepme" {
		t.Errorf("value = %q, want keepme", got)
	}
}

func TestRemoveDeletesSealedValues(t *testing.T) {
	v := newTestVault(t)
	if err := v.Put(sampleEntry(), map[string]string{"ES_API_KEY": "x"}); err != nil {
		t.Fatal(err)
	}
	if err := v.Remove("cdp-es"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, ok := v.Get("cdp-es"); ok {
		t.Error("entry still present after Remove")
	}
	if _, err := v.UnsealVar("cdp-es", "ES_API_KEY"); err == nil {
		t.Error("sealed value survived Remove")
	}
}

// A vault inside a repository would eventually be committed.
func TestInitRefusesInsideGitRepo(t *testing.T) {
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(repo, "nested", "vault")
	t.Setenv("SA_VAULT_KEK_FILE", filepath.Join(t.TempDir(), "kek"))

	v, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	err = v.Init()
	if err == nil || !strings.Contains(err.Error(), "git repository") {
		t.Errorf("Init error = %v, want a refusal mentioning the git repository", err)
	}
}

func TestSummaryMasksOnlySecrets(t *testing.T) {
	entry := sampleEntry()
	summary := entry.Summary()

	if !strings.Contains(summary, "ES_API_KEY="+Mask) {
		t.Errorf("summary %q does not mask the sealed variable", summary)
	}
	if !strings.Contains(summary, "ES_ENDPOINT=https://logs.internal:9200") {
		t.Errorf("summary %q hides the public variable, which is not a secret", summary)
	}
}

// Variable names become shell syntax in `sa-vault env` output, where quoting
// cannot contain them. Anything that is not a POSIX name must be refused at the
// door.
func TestValidateVarNameRejectsShellSyntax(t *testing.T) {
	valid := []string{"A", "_", "ES_API_KEY", "_x9", "a1"}
	for _, name := range valid {
		if err := ValidateVarName(name); err != nil {
			t.Errorf("ValidateVarName(%q) = %v, want nil", name, err)
		}
	}

	invalid := []string{
		"", "1LEADING_DIGIT", "has space", "semi;colon", "quo'te", `dou"ble`,
		"dollar$sign", "back`tick`", "paren(s)", "new\nline", "dash-ed", "dot.ted",
		"a=b", "a&b", "a|b", "a>b", "$(id)", "x;curl evil.example",
	}
	for _, name := range invalid {
		if err := ValidateVarName(name); err == nil {
			t.Errorf("ValidateVarName(%q) = nil, want a rejection", name)
		}
	}
}

func TestValidateEntryNameRejectsPathAndShellCharacters(t *testing.T) {
	for _, name := range []string{"cdp-es", "pg_ro", "a.b", "X1"} {
		if err := ValidateEntryName(name); err != nil {
			t.Errorf("ValidateEntryName(%q) = %v, want nil", name, err)
		}
	}
	for _, name := range []string{"", "../escape", "with space", "semi;colon", "sub/dir", "$(id)"} {
		if err := ValidateEntryName(name); err == nil {
			t.Errorf("ValidateEntryName(%q) = nil, want a rejection", name)
		}
	}
}

func TestPrimaryVarRefusesToGuess(t *testing.T) {
	// One secret among public variables: unambiguous.
	sample := sampleEntry()
	if v, ok := sample.PrimaryVar(); !ok || v.Name != "ES_API_KEY" {
		t.Errorf("PrimaryVar = %v, %t; want ES_API_KEY", v, ok)
	}

	// Two secrets: no primary, because picking one would be a guess.
	two := Entry{Name: "two", Vars: []Var{
		{Name: "A", Secret: true}, {Name: "B", Secret: true},
	}}
	if v, ok := two.PrimaryVar(); ok {
		t.Errorf("PrimaryVar = %v; want no primary for an ambiguous entry", v)
	}

	// A single public variable is still unambiguous.
	one := Entry{Name: "one", Vars: []Var{{Name: "URL", Value: "https://x"}}}
	if v, ok := one.PrimaryVar(); !ok || v.Name != "URL" {
		t.Errorf("PrimaryVar = %v, %t; want URL", v, ok)
	}
}

func TestKeyFileRejectsLoosePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kek")
	t.Setenv("SA_VAULT_KEK_FILE", path)

	v, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Init(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := (&fileSource{path: path}).Load(); err == nil ||
		!strings.Contains(err.Error(), "permissions") {
		t.Errorf("Load error = %v, want a permissions complaint", err)
	}
}
