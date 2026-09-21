// SPDX-License-Identifier: MIT

package tokenstore

import (
	"testing"
	"time"
)

func TestACgroupBoundTokenPassesItsBindingToItsChildren(t *testing.T) {
	store := New()
	parent, err := store.Issue(IssueParams{
		CredentialID:        "cred-1",
		AllowedDestinations: []string{"api.github.com"},
		TTL:                 time.Hour,
		AllowedCgroupID:     4242,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	child, err := store.IssueChild(parent.Value, ChildParams{})
	if err != nil {
		t.Fatalf("IssueChild: %v", err)
	}
	if child.AllowedCgroupID != 4242 {
		t.Errorf("child is bound to cgroup %d, want its parent's 4242", child.AllowedCgroupID)
	}
}

func TestADelegatedTokenCannotEscapeItsParentsCgroup(t *testing.T) {
	store := New()
	parent, err := store.Issue(IssueParams{
		CredentialID:        "cred-1",
		AllowedDestinations: []string{"api.github.com"},
		TTL:                 time.Hour,
		AllowedCgroupID:     4242,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	elsewhere := uint64(99)
	if _, err := store.IssueChild(parent.Value, ChildParams{AllowedCgroupID: &elsewhere}); err == nil {
		t.Error("a child was allowed to name a cgroup its parent was not bound to")
	}

	unbound := uint64(0)
	if _, err := store.IssueChild(parent.Value, ChildParams{AllowedCgroupID: &unbound}); err == nil {
		t.Error("a child was allowed to drop its parent's binding")
	}
}

func TestAnUnboundTokenMayDelegateABoundOne(t *testing.T) {
	store := New()
	parent, err := store.Issue(IssueParams{
		CredentialID:        "cred-1",
		AllowedDestinations: []string{"api.github.com"},
		TTL:                 time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	narrowed := uint64(4242)
	child, err := store.IssueChild(parent.Value, ChildParams{AllowedCgroupID: &narrowed})
	if err != nil {
		t.Fatalf("IssueChild: %v", err)
	}
	if child.AllowedCgroupID != 4242 {
		t.Errorf("child is bound to %d, want 4242", child.AllowedCgroupID)
	}
}
