// SPDX-License-Identifier: MIT

package tokenstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tempStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tokens.json")
	store, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	return store, path
}

func TestATokenOutlivesTheProcessThatIssuedIt(t *testing.T) {
	store, path := tempStore(t)
	issued, err := store.Issue(IssueParams{
		CredentialID:        "cred-1",
		AllowedDestinations: []string{"api.github.com"},
		TTL:                 time.Hour,
		TaskID:              "task-7",
		PolicyName:          "tight",
		MaxRequests:         10,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	restarted, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}

	token := restarted.Resolve(issued.Value)
	if token == nil {
		t.Fatal("the token the agent still holds no longer resolves after a restart")
	}
	if token.CredentialID != "cred-1" || token.TaskID != "task-7" || token.PolicyName != "tight" {
		t.Errorf("grant did not survive: %+v", token)
	}
	if !token.IsDestinationAllowed("api.github.com", "/user") {
		t.Error("destination scope did not survive")
	}
	if token.ID != issued.ID {
		t.Errorf("public id changed across restart: %q then %q", issued.ID, token.ID)
	}
}

func TestTheStoredFileCannotAuthenticateAnything(t *testing.T) {
	store, path := tempStore(t)
	issued, err := store.Issue(IssueParams{CredentialID: "cred-1", TTL: time.Hour})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the store: %v", err)
	}
	if strings.Contains(string(written), issued.Value) {
		t.Fatal("the token value is on disk; the file is a bearer secret and was not supposed to be")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("store mode is %o, want 600", mode)
	}
}

func TestRevocationIsNotUndoneByARestart(t *testing.T) {
	store, path := tempStore(t)
	issued, err := store.Issue(IssueParams{CredentialID: "cred-1", TTL: time.Hour})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !store.Revoke(issued.Value) {
		t.Fatal("Revoke reported nothing to revoke")
	}

	restarted, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	if restarted.Resolve(issued.Value) != nil {
		t.Fatal("a revoked token came back to life across a restart")
	}
}

func TestALifetimeBudgetIsNotRefilledByARestart(t *testing.T) {
	store, path := tempStore(t)
	issued, err := store.Issue(IssueParams{CredentialID: "cred-1", TTL: time.Hour, MaxRequests: 2})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !store.CheckBudget(issued.Value) || !store.CheckBudget(issued.Value) {
		t.Fatal("the first two requests should have been allowed")
	}
	if store.CheckBudget(issued.Value) {
		t.Fatal("the third request should have been refused")
	}
	if err := store.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	restarted, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	if restarted.CheckBudget(issued.Value) {
		t.Error("a restart refilled a spent lifetime budget")
	}
}

func TestADelegationChainSurvivesARestart(t *testing.T) {
	store, path := tempStore(t)
	root, err := store.Issue(IssueParams{
		CredentialID:        "cred-1",
		AllowedDestinations: []string{"api.github.com"},
		TTL:                 time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	child, err := store.IssueChild(root.Value, ChildParams{})
	if err != nil {
		t.Fatalf("IssueChild: %v", err)
	}

	restarted, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	if restarted.Resolve(child.Value) == nil {
		t.Fatal("a delegated token did not survive the restart")
	}

	// Revoking the parent must still reach the child, which only works if the
	// lineage was reloaded and not just the individual grants.
	if !restarted.Revoke(root.Value) {
		t.Fatal("Revoke reported nothing to revoke")
	}
	if restarted.Resolve(child.Value) != nil {
		t.Error("the child outlived its revoked parent after a restart")
	}
}

func TestAnAbsentStoreIsAnEmptyOne(t *testing.T) {
	store, err := LoadOrCreate(filepath.Join(t.TempDir(), "nested", "tokens.json"))
	if err != nil {
		t.Fatalf("LoadOrCreate on a fresh data directory: %v", err)
	}
	if got := len(store.List()); got != 0 {
		t.Errorf("a new store holds %d tokens, want 0", got)
	}
}

func TestAReloadedTokenStillReportsItselfValid(t *testing.T) {
	store, path := tempStore(t)
	issued, err := store.Issue(IssueParams{CredentialID: "cred-1", TTL: time.Hour})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	restarted, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	listed := restarted.List()
	if len(listed) != 1 {
		t.Fatalf("store holds %d tokens, want 1", len(listed))
	}
	// The value is the one thing never written down, so anything asking after
	// a reloaded token has to ask by the record rather than by the secret.
	if !restarted.Valid(listed[0]) {
		t.Error("a reloaded token reports itself invalid")
	}
	if listed[0].Value != "" {
		t.Error("a reloaded token carries a value it should not have")
	}
	_ = issued
}
