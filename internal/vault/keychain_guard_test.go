package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The safety claim in kek_darwin.go is that this binary can only ever ask the
// keychain for one specific item: it never enumerates, and never issues a query
// missing either identifying attribute. macOS enforces the rest via item ACLs,
// but that only helps if we don't hand it a broad query in the first place.
//
// These tests keep that property from regressing silently. They read source
// rather than behavior deliberately — the failure mode being guarded against is
// someone adding a new call site, which no runtime test would cover.

// forbidden lists keychain APIs and constants that would widen a query beyond a
// single known item.
var forbidden = []string{
	"MatchLimitAll", // returns every matching item
	"QueryItemRef",  // returns a live reference, bypassing our accessors
	"SecClassInternetPassword",
	"kSecMatchLimitAll",
	"DeleteItemRef",
}

func goSourceFiles(t *testing.T) map[string]string {
	t.Helper()

	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}

	sources := map[string]string{}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name := entry.Name(); name == ".git" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		sources[rel] = string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) == 0 {
		t.Fatal("found no Go source to scan; the guard would pass vacuously")
	}
	return sources
}

func TestNoKeychainEnumerationAPIs(t *testing.T) {
	for path, src := range goSourceFiles(t) {
		for _, api := range forbidden {
			if strings.Contains(src, api) {
				t.Errorf("%s references %s: keychain access must stay limited to a single "+
					"exact-match item (see kek_darwin.go)", path, api)
			}
		}
	}
}

// Every keychain query must set both the service and the account. A query
// missing either would match items this binary did not create.
func TestKeychainQueriesAreFullyQualified(t *testing.T) {
	sources := goSourceFiles(t)

	var callSites int
	for path, src := range sources {
		if !strings.Contains(src, "keychain.NewItem()") {
			continue
		}
		callSites++
		for _, required := range []string{"SetService(KeychainService)", "SetAccount(KeychainAccount)"} {
			if !strings.Contains(src, required) {
				t.Errorf("%s builds a keychain item but never calls %s", path, required)
			}
		}
	}

	if callSites == 0 {
		t.Skip("no keychain call sites on this platform")
	}
	if callSites > 1 {
		t.Errorf("keychain items are built in %d files; keep access in one place so it "+
			"stays auditable", callSites)
	}
}
