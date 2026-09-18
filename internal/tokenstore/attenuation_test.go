// SPDX-License-Identifier: MIT

package tokenstore

import (
	"testing"
	"time"
)

func TestChildTokenInheritsCredentialAndNarrowsAuthority(t *testing.T) {
	store := New()
	root, err := store.Issue(IssueParams{
		CredentialID:        "credential-1",
		AllowedDestinations: []string{"api.example.com/v1/*"},
		TTL:                 time.Hour,
		PolicyName:          "strict",
		AgentID:             "agent-1",
		TaskID:              "task-1",
		RateLimit:           10,
		RateWindow:          time.Minute,
		MaxRequests:         20,
		AllowedMethods:      []string{"GET", "POST"},
		AllowedPaths:        []string{"/v1/*"},
		ClientCertID:        "cert-1",
		SSHKeyID:            "ssh-1",
	})
	if err != nil {
		t.Fatalf("issuing root: %v", err)
	}

	rate := 4
	window := time.Minute
	budget := 8
	child, err := store.IssueChild(root.Value, ChildParams{
		AllowedDestinations: []string{"api.example.com/v1/messages"},
		TTL:                 10 * time.Minute,
		Label:               "tools only",
		AllowedMethods:      []string{"POST"},
		AllowedPaths:        []string{"/v1/messages"},
		DeniedPaths:         []string{"/v1/messages/admin"},
		RateLimit:           &rate,
		RateWindow:          &window,
		MaxRequests:         &budget,
	})
	if err != nil {
		t.Fatalf("issuing child: %v", err)
	}
	if child.CredentialID != root.CredentialID || child.ClientCertID != root.ClientCertID || child.SSHKeyID != root.SSHKeyID {
		t.Fatal("child did not inherit the parent's credential references")
	}
	if child.PolicyName != root.PolicyName || child.AgentID != root.AgentID || child.TaskID != root.TaskID {
		t.Fatal("child did not inherit the parent's policy and audit identity")
	}
	if child.ParentID != root.ID || child.RootID != root.ID {
		t.Fatalf("child lineage = parent %q root %q; want %q", child.ParentID, child.RootID, root.ID)
	}
	if !child.ExpiresAt.Before(root.ExpiresAt) {
		t.Fatal("child did not expire before its parent")
	}
	if child.RateLimit != rate || child.RateWindow != window || child.MaxRequests != budget {
		t.Fatal("child did not retain its narrowed quotas")
	}

	grandchild, err := store.IssueChild(child.Value, ChildParams{})
	if err != nil {
		t.Fatalf("issuing grandchild: %v", err)
	}
	if grandchild.ParentID != child.ID || grandchild.RootID != root.ID {
		t.Fatalf("grandchild lineage = parent %q root %q", grandchild.ParentID, grandchild.RootID)
	}
}

func TestChildTokenCannotWidenParent(t *testing.T) {
	store := New()
	root, err := store.Issue(IssueParams{
		AllowedDestinations: []string{"api.example.com/v1/*"},
		TTL:                 time.Hour,
		RateLimit:           10,
		RateWindow:          time.Minute,
		MaxRequests:         20,
		AllowedMethods:      []string{"GET", "POST"},
		AllowedPaths:        []string{"/v1/*"},
	})
	if err != nil {
		t.Fatalf("issuing root: %v", err)
	}

	higherRate := 11
	wrongWindow := 2 * time.Minute
	higherBudget := 21
	tests := []struct {
		name  string
		child ChildParams
	}{
		{"destination", ChildParams{AllowedDestinations: []string{"admin.example.com"}}},
		{"method", ChildParams{AllowedMethods: []string{"DELETE"}}},
		{"path", ChildParams{AllowedPaths: []string{"/admin/*"}}},
		{"ttl", ChildParams{TTL: 2 * time.Hour}},
		{"rate", ChildParams{RateLimit: &higherRate, RateWindow: durationPointer(time.Minute)}},
		{"rate window", ChildParams{RateLimit: intPointer(5), RateWindow: &wrongWindow}},
		{"budget", ChildParams{MaxRequests: &higherBudget}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := store.IssueChild(root.Value, test.child); err == nil {
				t.Fatal("widening child was accepted")
			}
		})
	}
}

func TestRevokingParentRevokesAllDescendants(t *testing.T) {
	store := New()
	root, _ := store.Issue(IssueParams{AllowedDestinations: []string{"api.example.com"}, TTL: time.Hour})
	child, _ := store.IssueChild(root.Value, ChildParams{})
	grandchild, _ := store.IssueChild(child.Value, ChildParams{})

	if !store.Revoke(root.Value) {
		t.Fatal("root token was not revoked")
	}
	if store.Resolve(child.Value) != nil || store.Resolve(grandchild.Value) != nil {
		t.Fatal("a descendant remained valid after its parent was revoked")
	}
}

func TestExpiredParentInvalidatesAndCleansUpChild(t *testing.T) {
	store := New()
	root, _ := store.Issue(IssueParams{AllowedDestinations: []string{"api.example.com"}, TTL: time.Hour})
	child, _ := store.IssueChild(root.Value, ChildParams{})
	root.ExpiresAt = time.Now().Add(-time.Second)

	if store.Resolve(child.Value) != nil {
		t.Fatal("child remained valid after its parent expired")
	}
	store.Cleanup()
	if store.Lookup(child.Value) != nil {
		t.Fatal("cleanup retained a child whose parent expired")
	}
}

func TestChildRequestsConsumeAncestorRateAndBudget(t *testing.T) {
	store := New()
	root, _ := store.Issue(IssueParams{
		AllowedDestinations: []string{"api.example.com"},
		TTL:                 time.Hour,
		RateLimit:           2,
		RateWindow:          time.Hour,
		MaxRequests:         2,
	})
	child, _ := store.IssueChild(root.Value, ChildParams{})

	if !store.CheckRate(child.Value) || !store.CheckRate(root.Value) || store.CheckRate(child.Value) {
		t.Fatal("derived requests did not share the ancestor rate limit")
	}
	if !store.CheckBudget(child.Value) || !store.CheckBudget(root.Value) || store.CheckBudget(child.Value) {
		t.Fatal("derived requests did not share the ancestor request budget")
	}
}

func TestDestinationAttenuation(t *testing.T) {
	tests := []struct {
		parent []string
		child  []string
		want   bool
	}{
		{[]string{"*"}, []string{"api.example.com/v1/messages"}, true},
		{[]string{"api.example.com"}, []string{"api.example.com/v1/*"}, true},
		{[]string{"api.example.com/v1/*"}, []string{"api.example.com/v1/messages"}, true},
		{[]string{"api.example.com/v1/messages"}, []string{"api.example.com"}, false},
		{[]string{"api.example.com/v1/*"}, []string{"api.example.com/v2/messages"}, false},
		{[]string{"api.example.com"}, []string{"other.example.com"}, false},
	}
	for _, test := range tests {
		if got := DestinationsAreSubset(test.parent, test.child); got != test.want {
			t.Errorf("DestinationsAreSubset(%v, %v) = %t; want %t", test.parent, test.child, got, test.want)
		}
	}
}

func intPointer(value int) *int { return &value }

func durationPointer(value time.Duration) *time.Duration { return &value }
