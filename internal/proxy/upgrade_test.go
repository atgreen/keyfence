// SPDX-License-Identifier: MIT

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/keyfence/keyfence/internal/audit"
)

// An agent that streams its turn over a WebSocket is the ordinary case now, not
// an exotic one. These tests are about the handshake -- which KeyFence has to
// pass through intact -- and about the bytes afterwards, which it has to relay
// without pretending to understand them.

func TestAnUpgradeRequestIsRecognisedOnlyWhenConnectionSaysSo(t *testing.T) {
	for name, tc := range map[string]struct {
		headers  map[string][]string
		expected string
	}{
		"a websocket upgrade": {
			headers:  map[string][]string{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}},
			expected: "websocket",
		},
		"connection carrying several tokens": {
			headers:  map[string][]string{"Connection": {"keep-alive, Upgrade"}, "Upgrade": {"websocket"}},
			expected: "websocket",
		},
		"odd capitalisation": {
			headers:  map[string][]string{"Connection": {"UPGRADE"}, "Upgrade": {"WebSocket"}},
			expected: "WebSocket",
		},
		"upgrade offered but not requested": {
			// A hint that the client could switch, which is not a request to.
			headers:  map[string][]string{"Connection": {"keep-alive"}, "Upgrade": {"websocket"}},
			expected: "",
		},
		"an ordinary request": {
			headers:  map[string][]string{"Connection": {"keep-alive"}},
			expected: "",
		},
	} {
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "https://example.test/stream", nil)
			if err != nil {
				t.Fatal(err)
			}
			for key, values := range tc.headers {
				for _, value := range values {
					req.Header.Add(key, value)
				}
			}
			if got := requestedUpgrade(req); got != tc.expected {
				t.Errorf("requestedUpgrade = %q, want %q", got, tc.expected)
			}
		})
	}
}

// echoUpgradeServer answers an upgrade with 101 and then echoes every byte back,
// upper-cased, so a test can tell the relay is carrying traffic both ways rather
// than just completing a handshake.
func echoUpgradeServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestedUpgrade(r) == "" {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ordinary")
			return
		}
		// What the upstream saw is worth asserting on, so it is echoed back in a
		// header the test reads off the 101.
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("test server cannot hijack")
			return
		}
		conn, buffered, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()

		head := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
			"X-Saw-Authorization: " + r.Header.Get("Authorization") + "\r\n\r\n"
		if _, err := io.WriteString(conn, head); err != nil {
			return
		}

		for {
			line, err := buffered.ReadString('\n')
			if line != "" {
				if _, werr := io.WriteString(conn, strings.ToUpper(line)); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// throughProxy runs one request through the proxy's plain-HTTP path and answers
// the client end of the connection.
func throughProxy(t *testing.T, p *Proxy, req *http.Request, host string) (net.Conn, *bufio.Reader) {
	t.Helper()

	proxySide, clientSide := net.Pipe()
	t.Cleanup(func() { _ = clientSide.Close() })
	if err := clientSide.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}

	go func() {
		defer func() { _ = proxySide.Close() }()
		p.processRequest(context.Background(), proxySide, req, host)
	}()
	return clientSide, bufio.NewReader(clientSide)
}

func upgradeRequest(t *testing.T, target string) (*http.Request, string) {
	t.Helper()
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("GET", target+"/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	return req, parsed.Host
}

func TestAWebSocketHandshakeReachesTheClientAndTheFramesFlowBothWays(t *testing.T) {
	upstream := echoUpgradeServer(t)
	trail := &bytes.Buffer{}
	req, host := upgradeRequest(t, upstream.URL)

	p := New("127.0.0.1:0", nil, nil, nil, nil, nil, audit.New(trail), nil, []string{host}, false)
	client, reader := throughProxy(t, p, req, host)

	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		t.Fatalf("reading the handshake answer: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("client saw %d, want 101: the protocol switch never reached it", resp.StatusCode)
	}
	if got := resp.Header.Get("Upgrade"); !strings.EqualFold(got, "websocket") {
		t.Errorf("Upgrade header arrived as %q", got)
	}

	// And the connection now carries whatever the two ends want to say.
	if _, err := io.WriteString(client, "ping\n"); err != nil {
		t.Fatalf("writing a frame: %v", err)
	}
	echoed, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the echo: %v", err)
	}
	if echoed != "PING\n" {
		t.Errorf("the relay carried %q, want %q", echoed, "PING\n")
	}
}

func TestAnUpgradeIsRecordedAsTheEndOfWhatTheTrailCanSee(t *testing.T) {
	upstream := echoUpgradeServer(t)
	trail := &bytes.Buffer{}
	req, host := upgradeRequest(t, upstream.URL)

	p := New("127.0.0.1:0", nil, nil, nil, nil, nil, audit.New(trail), nil, []string{host}, false)
	client, reader := throughProxy(t, p, req, host)
	if _, err := http.ReadResponse(reader, req); err != nil {
		t.Fatalf("reading the handshake answer: %v", err)
	}
	_ = client.Close()

	var found bool
	for _, entry := range auditEntries(t, trail) {
		if entry.Label == "upgrade:websocket" {
			found = true
			if entry.Path != "/stream" {
				t.Errorf("the entry does not say what was upgraded: %q", entry.Path)
			}
		}
	}
	if !found {
		t.Errorf("nothing in the trail records the upgrade:\n%s", trail.String())
	}
}

func TestAnOrdinaryRequestToTheSameHostIsUnaffected(t *testing.T) {
	upstream := echoUpgradeServer(t)
	parsed, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("GET", upstream.URL+"/plain", nil)
	if err != nil {
		t.Fatal(err)
	}

	p := New("127.0.0.1:0", nil, nil, nil, nil, nil, audit.New(&bytes.Buffer{}), nil,
		[]string{parsed.Host}, false)
	_, reader := throughProxy(t, p, req, parsed.Host)

	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "ordinary" {
		t.Errorf("got %d %q, want 200 %q", resp.StatusCode, body, "ordinary")
	}
}

func TestAHeadWithoutAStatusTextIsStillValid(t *testing.T) {
	// resp.Status is empty when a response was built rather than parsed, and a
	// status line has to have something after the code.
	head := &bytes.Buffer{}
	resp := &http.Response{StatusCode: http.StatusSwitchingProtocols, Header: http.Header{}}
	resp.Header.Set("Upgrade", "websocket")
	if err := writeResponseHead(head, resp); err != nil {
		t.Fatal(err)
	}
	expected := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
	if head.String() != expected {
		t.Errorf("wrote %q, want %q", head.String(), expected)
	}
}

func TestTheCredentialReachesTheHandshakeItself(t *testing.T) {
	// The Authorization header is on the upgrade request and nowhere else, so a
	// swap that happened after the handshake would never happen at all.
	upstream := echoUpgradeServer(t)
	req, host := upgradeRequest(t, upstream.URL)
	req.Header.Set("Authorization", "Bearer real-credential")

	p := New("127.0.0.1:0", nil, nil, nil, nil, nil, audit.New(&bytes.Buffer{}), nil,
		[]string{host}, false)
	_, reader := throughProxy(t, p, req, host)

	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		t.Fatalf("reading the handshake answer: %v", err)
	}
	if got := resp.Header.Get("X-Saw-Authorization"); got != "Bearer real-credential" {
		t.Errorf("the upstream saw Authorization %q", got)
	}
	_ = fmt.Sprint(resp.StatusCode)
}
