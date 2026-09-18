package main

import (
	"strings"
	"testing"

	"github.com/keyfence/keyfence/internal/tokenstore"
)

// The audit trail is the one thing here designed to be copied elsewhere, so a
// token value in it is a credential in a log.
func TestRevokingDoesNotLogTheTokenValue(t *testing.T) {
	store := tokenstore.New()
	token, err := store.Issue(tokenstore.IssueParams{
		CredentialID:        "cred_1",
		AllowedDestinations: []string{"api.example.com"},
		TTL:                 60_000_000_000,
		TaskID:              "run-abc",
	})
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	if !strings.HasPrefix(token.Value, "kf_") {
		t.Fatalf("unexpected token shape %q", token.Value)
	}
	if token.ID == token.Value {
		t.Error("the token's id is its value, so logging the id would log the credential")
	}
	if strings.Contains(token.Value, token.ID) {
		t.Error("the id is a substring of the value; logging it leaks part of the credential")
	}
	// Stable, so it identifies the same token across entries.
	second, err := store.Issue(tokenstore.IssueParams{
		CredentialID:        "cred_1",
		AllowedDestinations: []string{"api.example.com"},
		TTL:                 60_000_000_000,
	})
	if err != nil {
		t.Fatalf("issuing a second: %v", err)
	}
	if second.ID == token.ID {
		t.Error("two tokens share an id")
	}
}
