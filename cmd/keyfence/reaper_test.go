// SPDX-License-Identifier: MIT

package main

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyfence/keyfence/internal/credstore"
	"github.com/keyfence/keyfence/internal/policy"
	"github.com/keyfence/keyfence/internal/tokenstore"
)

// A credential handed over at issuance is held here so it can be swapped in on
// each request. When the last token that needed it is gone, so should it be --
// otherwise a broker that runs for a week holds every secret it was ever given,
// which is the accumulation it exists to prevent.

func newReaper() (*credentialReaper, *tokenstore.Store, credstore.Backend) {
	store := tokenstore.New()
	creds := credstore.NewEnvBackend()
	return &credentialReaper{
		store:    store,
		creds:    creds,
		certs:    credstore.NewCertStore(),
		sshKeys:  credstore.NewSSHKeyStore(),
		policies: policy.NewEngine(),
	}, store, creds
}

func issueWithCredential(t *testing.T, store *tokenstore.Store, creds credstore.Backend, secret string, ttl time.Duration) (string, string) {
	t.Helper()
	id, err := creds.Store(secret)
	if err != nil {
		t.Fatalf("storing the credential: %v", err)
	}
	token, err := store.Issue(tokenstore.IssueParams{
		CredentialID:        id,
		AllowedDestinations: []string{"api.example.com"},
		TTL:                 ttl,
	})
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	return token.Value, id
}

func TestRevokingATokenForgetsItsCredential(t *testing.T) {
	reaper, store, creds := newReaper()
	value, id := issueWithCredential(t, store, creds, "sk-ant-real", time.Hour)

	if _, err := creds.Fetch(id); err != nil {
		t.Fatalf("the credential was not stored to begin with: %v", err)
	}

	revoked := store.Lookup(value)
	store.Revoke(value)
	reaper.forget(revoked)

	if _, err := creds.Fetch(id); err == nil {
		t.Error("the credential outlived the token it was stored for")
	}
}

func TestACredentialTwoTokensShareSurvivesRevokingOne(t *testing.T) {
	reaper, store, creds := newReaper()
	value, id := issueWithCredential(t, store, creds, "sk-ant-real", time.Hour)

	// A second token against the same stored credential, as rotation-by-id and
	// CountByCredentialID both imply is possible.
	second, err := store.Issue(tokenstore.IssueParams{
		CredentialID:        id,
		AllowedDestinations: []string{"api.example.com"},
		TTL:                 time.Hour,
	})
	if err != nil {
		t.Fatalf("issuing the second token: %v", err)
	}

	revoked := store.Lookup(value)
	store.Revoke(value)
	reaper.forget(revoked)

	if _, err := creds.Fetch(id); err != nil {
		t.Errorf("a credential another live token still needs was forgotten: %v", err)
	}

	// And once that one goes too, it goes.
	stillThere := store.Lookup(second.Value)
	store.Revoke(second.Value)
	reaper.forget(stillThere)
	if _, err := creds.Fetch(id); err == nil {
		t.Error("the credential survived the last token that referenced it")
	}
}

func TestTheSweepForgetsExpiredTokensAndTheirCredentials(t *testing.T) {
	reaper, store, creds := newReaper()
	value, id := issueWithCredential(t, store, creds, "sk-ant-real", 10*time.Millisecond)

	time.Sleep(30 * time.Millisecond)
	reaper.sweep()

	if store.Lookup(value) != nil {
		t.Error("an expired token record was not removed")
	}
	if _, err := creds.Fetch(id); err == nil {
		t.Error("an expired token's credential is still held")
	}
}

func TestTheSweepLeavesLiveTokensAlone(t *testing.T) {
	reaper, store, creds := newReaper()
	value, id := issueWithCredential(t, store, creds, "sk-ant-real", time.Hour)

	reaper.sweep()

	if store.Lookup(value) == nil {
		t.Error("a live token was swept")
	}
	if _, err := creds.Fetch(id); err != nil {
		t.Errorf("a live token's credential was forgotten: %v", err)
	}
}

func TestPolicyStateSurvivesAChildButNotTheWholeLineage(t *testing.T) {
	reaper, store, _ := newReaper()
	reaper.policies.Register(&policy.Policy{Name: "one", MaxRequests: 1})
	root, err := store.Issue(tokenstore.IssueParams{
		AllowedDestinations: []string{"api.example.com"},
		TTL:                 time.Hour,
		PolicyName:          "one",
	})
	if err != nil {
		t.Fatal(err)
	}
	child, err := store.IssueChild(root.Value, tokenstore.ChildParams{})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "https://api.example.com/", nil)
	if deny := reaper.policies.Check("one", root.ID, request); deny != nil {
		t.Fatalf("first request denied: %v", deny)
	}

	store.Revoke(child.Value)
	reaper.forget(child)
	if deny := reaper.policies.Check("one", root.ID, request); deny == nil {
		t.Fatal("revoking one child erased policy state shared with its live parent")
	}

	store.Revoke(root.Value)
	reaper.forget(root)
	if deny := reaper.policies.Check("one", root.ID, request); deny != nil {
		t.Fatalf("policy state survived the entire lineage: %v", deny)
	}
}
