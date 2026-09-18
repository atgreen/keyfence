// SPDX-License-Identifier: MIT

package credstore

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// The reason to use the keyring is that a credential in a file is plaintext on
// disk, and 0600 does nothing about a backup or a stolen disk.

func fakeKeyring(t *testing.T, entries map[string]string) (*Keyring, *int) {
	t.Helper()
	calls := 0
	return &Keyring{
		ttl:    time.Minute,
		cached: map[string]cachedSecret{},
		lookup: func(_ context.Context, name string) (string, error) {
			calls++
			value, ok := entries[name]
			if !ok {
				return "", fmt.Errorf("exit status 1")
			}
			return value + "\n", nil // secret-tool adds a newline
		},
	}, &calls
}

func TestAKeyringEntryResolves(t *testing.T) {
	keyring, _ := fakeKeyring(t, map[string]string{"github": "gho_real"})

	value, err := keyring.Resolve("github")
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}
	// The newline secret-tool adds is not part of the secret.
	if value != "gho_real" {
		t.Errorf("got %q, want %q", value, "gho_real")
	}
}

func TestAMissingEntrySaysHowToStoreOne(t *testing.T) {
	keyring, _ := fakeKeyring(t, nil)

	_, err := keyring.Resolve("github")
	if err == nil {
		t.Fatal("a missing entry resolved")
	}
	// An operator reading this should not have to look up the attributes.
	if got := err.Error(); !contains(got, "service keyfence credential github") {
		t.Errorf("the error does not say how to store one: %q", got)
	}
}

func TestLookupsAreCachedSoEveryRequestIsNotASubprocess(t *testing.T) {
	keyring, calls := fakeKeyring(t, map[string]string{"github": "gho_real"})

	for i := 0; i < 5; i++ {
		if _, err := keyring.Resolve("github"); err != nil {
			t.Fatalf("resolving: %v", err)
		}
	}
	if *calls != 1 {
		t.Errorf("asked the keyring %d times for five requests", *calls)
	}

	// And rotation still lands, once the entry is stale.
	keyring.Forget()
	if _, err := keyring.Resolve("github"); err != nil {
		t.Fatalf("resolving after Forget: %v", err)
	}
	if *calls != 2 {
		t.Errorf("Forget did not make the next request ask again (%d calls)", *calls)
	}
}

func TestACachedEntryExpires(t *testing.T) {
	keyring, calls := fakeKeyring(t, map[string]string{"github": "gho_real"})
	keyring.ttl = 10 * time.Millisecond

	if _, err := keyring.Resolve("github"); err != nil {
		t.Fatalf("resolving: %v", err)
	}
	time.Sleep(30 * time.Millisecond)
	if _, err := keyring.Resolve("github"); err != nil {
		t.Fatalf("resolving again: %v", err)
	}
	if *calls != 2 {
		t.Errorf("a stale entry was reused (%d calls)", *calls)
	}
}

func TestAKeyringNameIsStillAName(t *testing.T) {
	keyring, calls := fakeKeyring(t, map[string]string{"github": "gho_real"})

	// The same rule as a file-backed name: what arrives over the control API is
	// not allowed to be a path or anything stranger.
	for _, name := range []string{"../../etc/passwd", "a b", "", "x;y"} {
		if _, err := keyring.Resolve(name); err == nil {
			t.Errorf("%q was accepted as a credential name", name)
		}
	}
	if *calls != 0 {
		t.Errorf("a rejected name still reached the keyring (%d calls)", *calls)
	}
}

func TestANamedStoreSearchesTheKeyringAfterItsDirectories(t *testing.T) {
	store, dir := storeWith(t, map[string]string{"onfile": "from-the-file"})
	keyring, _ := fakeKeyring(t, map[string]string{
		"onfile":      "from-the-keyring",
		"keyringonly": "only-here",
	})
	store.UseKeyring(keyring)

	// A file wins, because it is the more explicit statement of the two.
	if value, _ := store.Resolve("onfile"); value != "from-the-file" {
		t.Errorf("the keyring overrode %s: got %q", dir, value)
	}
	if value, _ := store.Resolve("keyringonly"); value != "only-here" {
		t.Errorf("a keyring-only credential did not resolve: %q", value)
	}
	if !store.KeyringEnabled() {
		t.Error("the store does not report the keyring it is using")
	}
}
