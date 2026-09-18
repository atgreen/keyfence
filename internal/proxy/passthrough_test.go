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
