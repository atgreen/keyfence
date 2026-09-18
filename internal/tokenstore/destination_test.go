// SPDX-License-Identifier: MIT

package tokenstore

import "testing"

// A token's destination list is what makes it worth less than the credential it
// stands for. The interesting case is the empty one: it used to mean "anywhere",
// which is the opposite of what an empty allow list should mean anywhere else in
// a security tool.

func TestATokenWithNoDestinationsPermitsNothing(t *testing.T) {
	token := &Token{}

	if token.IsDestinationAllowed("api.anthropic.com", "/v1/messages") {
		t.Error("a token with no destinations allowed a request; empty means none, not all")
	}
	if token.AllowsAnyDestination() {
		t.Error("an empty list reported itself as deliberately unrestricted")
	}
}

func TestAWildcardHasToBeAskedForByName(t *testing.T) {
	token := &Token{AllowedDestinations: []string{AnyDestination}}

	if !token.IsDestinationAllowed("anywhere.example", "/whatever") {
		t.Error(`a token issued with ["*"] refused a request`)
	}
	if !token.AllowsAnyDestination() {
		t.Error(`a token issued with ["*"] does not report itself as unrestricted`)
	}
}

func TestAWildcardBesideNamedHostsStillWidensToAnything(t *testing.T) {
	// Worth pinning: "*" is not one entry among several to be matched in turn,
	// it is the absence of a lock, and mixing it with named hosts does not
	// narrow it back down.
	token := &Token{AllowedDestinations: []string{"api.anthropic.com", AnyDestination}}

	if !token.IsDestinationAllowed("elsewhere.example", "/") {
		t.Error("a list containing * refused a host, which hides what it really permits")
	}
}

func TestDestinationsMatchHostAndPath(t *testing.T) {
	cases := []struct {
		name         string
		destinations []string
		host         string
		path         string
		allowed      bool
	}{
		{"host only matches any path", []string{"api.example.com"},
			"api.example.com", "/v1/anything", true},
		{"another host is refused", []string{"api.example.com"},
			"evil.example", "/v1/anything", false},
		{"exact path matches", []string{"api.example.com/v1/chat"},
			"api.example.com", "/v1/chat", true},
		{"a different path on the same host is refused", []string{"api.example.com/v1/chat"},
			"api.example.com", "/v1/admin", false},
		{"a path glob matches beneath it", []string{"api.example.com/v1/*"},
			"api.example.com", "/v1/messages", true},
		{"a path glob matches the prefix itself", []string{"api.example.com/v1/*"},
			"api.example.com", "/v1", true},
		{"a path glob does not match a sibling", []string{"api.example.com/v1/*"},
			"api.example.com", "/v2/messages", false},
		{"one of several entries is enough", []string{"a.example.com", "b.example.com"},
			"b.example.com", "/", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			token := &Token{AllowedDestinations: c.destinations}
			if got := token.IsDestinationAllowed(c.host, c.path); got != c.allowed {
				t.Errorf("%v against %s%s: got %v, want %v",
					c.destinations, c.host, c.path, got, c.allowed)
			}
		})
	}
}
