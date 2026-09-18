// SPDX-License-Identifier: MIT

package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/keyfence/keyfence/internal/audit"
	"github.com/keyfence/keyfence/internal/luaengine"
	"github.com/keyfence/keyfence/internal/tokenstore"
)

// A response has to arrive at the client exactly as the upstream sent it,
// whatever KeyFence wanted to do with it on the way past. Inspecting a body
// means holding it in memory, holding it in memory means a limit, and a limit
// met by truncating the body -- with Content-Length rewritten to match -- hands
// the client something that looks complete and is not.

func newTestProxy() (*Proxy, *bytes.Buffer) {
	trail := &bytes.Buffer{}
	return &Proxy{
		audit: audit.New(trail),
		lua:   luaengine.New(),
	}, trail
}

func tokenWithRules(scripts ...string) *tokenstore.Token {
	rules := make([]tokenstore.ResponseRule, 0, len(scripts))
	for _, script := range scripts {
		rules = append(rules, tokenstore.ResponseRule{Script: script})
	}
	return &tokenstore.Token{
		ID:            "test-token",
		ResponseRules: rules,
		RuleState:     map[string]interface{}{},
	}
}

func jsonResponse(body []byte, chunked bool) *http.Response {
	resp := &http.Response{
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
	if chunked {
		resp.ContentLength = -1
		resp.TransferEncoding = []string{"chunked"}
	} else {
		resp.ContentLength = int64(len(body))
	}
	return resp
}

// forward runs one response through the proxy and answers what a client reading
// the other end of the connection actually received.
func forward(t *testing.T, p *Proxy, resp *http.Response, token *tokenstore.Token) []byte {
	t.Helper()

	proxySide, clientSide := net.Pipe()
	defer func() { _ = clientSide.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = proxySide.Close() }()
		p.inspectAndForwardResponse(proxySide, resp, token, "kf_test")
	}()

	// net.Pipe is unbuffered and never times out by itself, so a test that
	// would otherwise hang on a framing mistake fails instead.
	if err := clientSide.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("setting a deadline: %v", err)
	}

	received, err := http.ReadResponse(bufio.NewReader(clientSide), nil)
	if err != nil {
		t.Fatalf("reading the forwarded response: %v", err)
	}
	body, err := io.ReadAll(received.Body)
	if err != nil {
		t.Fatalf("reading the forwarded body: %v", err)
	}
	_ = received.Body.Close()
	<-done
	return body
}

func auditEntries(t *testing.T, trail *bytes.Buffer) []audit.Entry {
	t.Helper()
	var entries []audit.Entry
	for _, line := range strings.Split(strings.TrimSpace(trail.String()), "\n") {
		if line == "" {
			continue
		}
		var entry audit.Entry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("audit line is not JSON: %v (%q)", err, line)
		}
		entries = append(entries, entry)
	}
	return entries
}

func TestAResponseTooLargeToInspectIsStillDeliveredWhole(t *testing.T) {
	p, trail := newTestProxy()
	body := bytes.Repeat([]byte("x"), maxResponseBuffer+4096)

	received := forward(t, p, jsonResponse(body, false), tokenWithRules("return nil"))

	if len(received) != len(body) {
		t.Errorf("client received %d bytes of a %d byte response: it was truncated",
			len(received), len(body))
	}
	if !bytes.Equal(received, body) {
		t.Error("the body the client received is not the body the upstream sent")
	}

	// And the skipped evaluation is recorded, because a budget that silently
	// stops counting is worse than one that says it stopped.
	var skipped bool
	for _, entry := range auditEntries(t, trail) {
		if entry.RuleAction == "skipped" {
			skipped = true
			if !strings.Contains(entry.RuleReason, "larger than") {
				t.Errorf("the reason does not say why: %q", entry.RuleReason)
			}
		}
	}
	if !skipped {
		t.Error("nothing in the audit trail says the response rules did not run")
	}
}

func TestAChunkedResponseTooLargeToInspectIsAlsoWhole(t *testing.T) {
	p, _ := newTestProxy()
	body := bytes.Repeat([]byte("y"), maxResponseBuffer+4096)

	received := forward(t, p, jsonResponse(body, true), tokenWithRules("return nil"))

	if !bytes.Equal(received, body) {
		t.Errorf("chunked response arrived as %d bytes of %d", len(received), len(body))
	}
}

func TestAResponseWithinTheLimitStillReachesTheRules(t *testing.T) {
	p, trail := newTestProxy()
	body := []byte(`{"usage":{"output_tokens":7}}`)

	received := forward(t, p, jsonResponse(body, false),
		tokenWithRules(`return {action = "alert", reason = "rule ran"}`))

	if !bytes.Equal(received, body) {
		t.Errorf("body changed on the way through: %q", received)
	}

	var alerted bool
	for _, entry := range auditEntries(t, trail) {
		if entry.RuleAction == "alert" {
			alerted = true
		}
		if entry.RuleAction == "skipped" {
			t.Error("a response inside the limit was not inspected")
		}
	}
	if !alerted {
		t.Error("the rule did not run on a response small enough to inspect")
	}
}

func TestARuleCanStillAccumulateStateAcrossResponses(t *testing.T) {
	p, _ := newTestProxy()
	token := tokenWithRules(`state.calls = (state.calls or 0) + 1; return nil`)

	for i := 0; i < 3; i++ {
		forward(t, p, jsonResponse([]byte(`{"ok":true}`), false), token)
	}

	token.RuleStateMu.Lock()
	calls, _ := token.RuleState["calls"].(float64)
	token.RuleStateMu.Unlock()
	if calls != 3 {
		t.Errorf("rule state counted %v responses, expected 3", calls)
	}
}

func TestAResponseNobodyWillInspectIsNotBuffered(t *testing.T) {
	p, trail := newTestProxy()
	body := bytes.Repeat([]byte("z"), maxResponseBuffer+4096)

	// No response rules, so there is nothing to look for in this body and no
	// reason to hold it in memory before passing it on.
	received := forward(t, p, jsonResponse(body, false), tokenWithRules())

	if !bytes.Equal(received, body) {
		t.Errorf("body arrived as %d bytes of %d", len(received), len(body))
	}
	if entries := auditEntries(t, trail); len(entries) != 0 {
		t.Errorf("expected a quiet audit trail, got %d entries", len(entries))
	}
}
