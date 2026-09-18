// SPDX-License-Identifier: MIT

package credstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func storeWith(t *testing.T, files map[string]string) (*NamedStore, string) {
	t.Helper()
	dir := t.TempDir()
	for name, value := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	store := NewNamedStore(dir)
	store.environ = func(string) string { return "" }
	return store, dir
}

func TestANamedCredentialResolvesToItsContents(t *testing.T) {
	store, _ := storeWith(t, map[string]string{"anthropic": "sk-ant-real\n"})

	value, err := store.Resolve("anthropic")
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}
	// The trailing newline is what a shell redirect leaves behind, and is not
	// part of anybody's API key.
	if value != "sk-ant-real" {
		t.Errorf("got %q, want %q", value, "sk-ant-real")
	}
}

func TestRotationIsReplacingAFile(t *testing.T) {
	store, dir := storeWith(t, map[string]string{"anthropic": "first"})

	if value, _ := store.Resolve("anthropic"); value != "first" {
		t.Fatalf("got %q before rotation", value)
	}
	if err := os.WriteFile(filepath.Join(dir, "anthropic"), []byte("second"), 0o600); err != nil {
		t.Fatalf("rotating: %v", err)
	}
	// Resolved per request, so no token has to be reissued for this to take.
	if value, _ := store.Resolve("anthropic"); value != "second" {
		t.Errorf("got %q after rotation, want %q", value, "second")
	}
}

func TestANameCannotBeAPath(t *testing.T) {
	store, _ := storeWith(t, map[string]string{"anthropic": "sk-ant-real"})

	// A reference arrives over the control API. Anything that could name a file
	// outside the directories the operator chose is not a name.
	for _, name := range []string{
		"../../etc/passwd",
		"/etc/passwd",
		"sub/anthropic",
		"..",
		".",
		"",
		"anthropic\x00",
		"anthropic name",
	} {
		if _, err := store.Resolve(name); err == nil {
			t.Errorf("%q was accepted as a credential name", name)
		}
	}
}

func TestAnUnknownNameSaysWhereItLooked(t *testing.T) {
	store, dir := storeWith(t, map[string]string{"anthropic": "sk-ant-real"})

	_, err := store.Resolve("github")
	if err == nil {
		t.Fatal("an unregistered name resolved")
	}
	// An operator reading this should not have to guess which directory to put
	// the file in.
	if got := err.Error(); !strings.Contains(got, dir) || !strings.Contains(got, "KEYFENCE_CREDENTIAL_GITHUB") {
		t.Errorf("the error does not say where it looked: %q", got)
	}
}

func TestTheEnvironmentIsTheLastResort(t *testing.T) {
	store, _ := storeWith(t, map[string]string{})
	store.environ = func(name string) string {
		if name == "KEYFENCE_CREDENTIAL_MY_API" {
			return "from-the-environment"
		}
		return ""
	}

	// Dashes and dots become underscores, upper-cased, which is the convention
	// the env-mapped backend already used.
	value, err := store.Resolve("my-api")
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}
	if value != "from-the-environment" {
		t.Errorf("got %q", value)
	}
}

func TestAnEmptyCredentialFileIsAnError(t *testing.T) {
	store, _ := storeWith(t, map[string]string{"blank": "\n"})

	if _, err := store.Resolve("blank"); err == nil {
		t.Error("an empty credential file resolved to an empty credential")
	}
}

func TestNamesListsWhatIsRegisteredWithoutValues(t *testing.T) {
	store, _ := storeWith(t, map[string]string{
		"anthropic": "sk-ant-real",
		"github":    "ghp-real",
	})

	names := store.Names()
	if len(names) != 2 || names[0] != "anthropic" || names[1] != "github" {
		t.Errorf("got %v, want [anthropic github]", names)
	}
}
