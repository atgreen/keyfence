// SPDX-License-Identifier: MIT

package proxy

import (
	"net/http"
	"testing"
)

// KeyFence is the only way out of a sandbox, so it decides the fate of requests
// that need no credential at all -- a connectivity probe, a changelog, an OAuth
// discovery document. Refusing them means an agent cannot start.

func TestOnlyNamedHostsArePassedThroughWithoutAToken(t *testing.T) {
	p := New("127.0.0.1:0", nil, nil, nil, nil, nil, nil, nil,
		[]string{"api.anthropic.com", " Platform.Claude.com ", ""}, false)

	for host, expected := range map[string]bool{
		"api.anthropic.com":   true,
		"platform.claude.com": true, // named with different case and spacing
		"API.ANTHROPIC.COM":   true,
		"api.github.com":      false,
		"evil.example":        false,
		"":                    false,
	} {
		if got := p.passthrough[normaliseHost(host)]; got != expected {
			t.Errorf("%q passthrough=%v, want %v", host, got, expected)
		}
	}
}

func TestNoPassthroughHostsMeansNone(t *testing.T) {
	p := New("127.0.0.1:0", nil, nil, nil, nil, nil, nil, nil, nil, false)
	if len(p.passthrough) != 0 {
		t.Errorf("expected an empty passthrough set, got %v", p.passthrough)
	}
}

func TestAResponseWithoutFramingEndsTheConnection(t *testing.T) {
	// Not reusable, and not rewritten to become so: a response whose headers
	// describe the original framing cannot have that framing changed underneath
	// them without producing something no client can parse.
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ContentLength: -1,
		Header:        http.Header{},
	}
	if framedDeterminately(resp) {
		t.Error("a response with no length and no chunking was called reusable")
	}
}

// Some hosts cannot be named in advance. Codex fetches its plugin bundles from
// sdmntprsouthcentralus.oaiusercontent.com, a per-region name you would only
// learn by being refused first, so a pattern has to be allowed -- and has to stop
// where a careless one would not.

func TestASuffixPatternMatchesSubdomainsAndNothingAdjacent(t *testing.T) {
	p := New("127.0.0.1:0", nil, nil, nil, nil, nil, nil, nil,
		[]string{"*.oaiusercontent.com", ".files.example.test", "api.github.com"}, false)

	for host, expected := range map[string]bool{
		"sdmntprsouthcentralus.oaiusercontent.com": true,
		"anything.deeper.oaiusercontent.com":       true,
		"SDMNT.OAIUSERCONTENT.COM":                 true,  // case is not a way in
		"cdn.files.example.test":                   true,  // written with a leading dot
		"api.github.com":                           true,  // an exact name still works
		"oaiusercontent.com":                       false, // the domain itself was not named
		"notoaiusercontent.com":                    false, // suffix, not a label boundary
		"oaiusercontent.com.evil.test":             false, // the pattern is not in the right place
		"files.example.test":                       false,
		"github.com":                               false,
		"":                                         false,
	} {
		if got := p.passedThrough(host); got != expected {
			t.Errorf("passedThrough(%q) = %v, want %v", host, got, expected)
		}
	}
}

func TestAnExactHostIsNotTurnedIntoAPattern(t *testing.T) {
	p := New("127.0.0.1:0", nil, nil, nil, nil, nil, nil, nil,
		[]string{"api.anthropic.com"}, false)
	if p.passedThrough("evil.api.anthropic.com") {
		t.Error("an exact name let a subdomain through")
	}
	if len(p.passthroughSuffixes) != 0 {
		t.Errorf("an exact name became a suffix pattern: %v", p.passthroughSuffixes)
	}
}
