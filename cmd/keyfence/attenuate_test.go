// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyfence/keyfence/internal/audit"
	"github.com/keyfence/keyfence/internal/policy"
	"github.com/keyfence/keyfence/internal/tokenstore"
)

func TestAttenuateEndpointUsesParentAsAuthorityAndAuditsLineage(t *testing.T) {
	store := tokenstore.New()
	parent, err := store.Issue(tokenstore.IssueParams{
		CredentialID:        "credential-1",
		AllowedDestinations: []string{"api.example.com"},
		TTL:                 time.Hour,
		PolicyName:          "readonly",
	})
	if err != nil {
		t.Fatalf("issuing parent: %v", err)
	}
	policies := policy.NewEngine()
	policies.Register(&policy.Policy{Name: "readonly", AllowedMethods: []string{"GET", "HEAD"}})
	var auditOutput bytes.Buffer
	handler := handleAttenuateToken(store, policies, audit.New(&auditOutput))

	request := httptest.NewRequest(http.MethodPost, "/tokens/attenuate",
		strings.NewReader(`{"destinations":["api.example.com/v1/models"],"allowed_methods":["GET"],"ttl_seconds":60}`))
	request.Header.Set("Authorization", "Bearer "+parent.Value)
	response := httptest.NewRecorder()
	handler(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}

	var issued issueResponse
	if err := json.Unmarshal(response.Body.Bytes(), &issued); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	child := store.Resolve(issued.Token)
	if child == nil {
		t.Fatal("response did not contain a valid child token")
	}
	if child.ParentID != parent.ID || child.RootID != parent.ID {
		t.Fatalf("child lineage = parent %q root %q; want %q", child.ParentID, child.RootID, parent.ID)
	}
	if strings.Contains(auditOutput.String(), parent.Value) || strings.Contains(auditOutput.String(), child.Value) {
		t.Fatal("audit event contains a token value")
	}
	if !strings.Contains(auditOutput.String(), `"event":"delegate"`) ||
		!strings.Contains(auditOutput.String(), `"parent_token_id":"`+parent.ID+`"`) {
		t.Fatalf("audit event does not record delegation lineage: %s", auditOutput.String())
	}
}

func TestAttenuateEndpointCannotWidenNamedPolicy(t *testing.T) {
	store := tokenstore.New()
	parent, err := store.Issue(tokenstore.IssueParams{
		AllowedDestinations: []string{"api.example.com"},
		TTL:                 time.Hour,
		PolicyName:          "readonly",
	})
	if err != nil {
		t.Fatal(err)
	}
	policies := policy.NewEngine()
	policies.Register(&policy.Policy{Name: "readonly", AllowedMethods: []string{"GET", "HEAD"}})
	handler := handleAttenuateToken(store, policies, audit.New(&bytes.Buffer{}))

	request := httptest.NewRequest(http.MethodPost, "/tokens/attenuate", strings.NewReader(`{"allowed_methods":["POST"]}`))
	request.Header.Set("Authorization", "Bearer "+parent.Value)
	response := httptest.NewRecorder()
	handler(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestAttenuateEndpointRejectsControlKeyInPlaceOfParent(t *testing.T) {
	handler := handleAttenuateToken(tokenstore.New(), policy.NewEngine(), audit.New(&bytes.Buffer{}))
	request := httptest.NewRequest(http.MethodPost, "/tokens/attenuate", strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer control-api-key")
	response := httptest.NewRecorder()
	handler(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want %d", response.Code, http.StatusUnauthorized)
	}
}
