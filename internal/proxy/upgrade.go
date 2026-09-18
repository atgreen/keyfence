// SPDX-License-Identifier: MIT

package proxy

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/keyfence/keyfence/internal/audit"
)

// A WebSocket is how an agent talks to its model now. Codex streams a turn over
// wss://chatgpt.com/backend-api/codex/responses; other agents are following.
// Without the upgrade handled here, such a request reached the upstream as an
// ordinary GET, the 101 went back as though it were a body-bearing response, and
// the client sat waiting for a protocol switch that never arrived -- which looks
// from the outside exactly like a hung network.
//
// What an upgrade means for KeyFence is that its work happens entirely in the
// handshake. The credential swap applies to the upgrade request, because that is
// the request carrying the Authorization header, and the destination check has
// already happened by the time anything here runs. After the 101 there is no HTTP
// left to inspect: the bytes are frames in a protocol KeyFence does not speak, so
// they are relayed and not read. That is a real reduction in what the audit trail
// can tell you about one connection, and it is recorded as such rather than left
// for someone to infer from a quiet trail.

// requestedUpgrade answers the protocol a request wants to switch to, or "" if it
// is an ordinary request.
//
// Both headers matter: Upgrade names the protocol, and Connection has to list
// "upgrade" for it to be a request rather than a suggestion. Either may arrive
// with any capitalisation, and Connection may carry several tokens.
func requestedUpgrade(req *http.Request) string {
	protocol := strings.TrimSpace(req.Header.Get("Upgrade"))
	if protocol == "" {
		return ""
	}
	for _, value := range req.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return protocol
			}
		}
	}
	return ""
}

// switchedProtocols answers whether the upstream agreed to the switch.
func switchedProtocols(resp *http.Response) bool {
	return resp != nil && resp.StatusCode == http.StatusSwitchingProtocols
}

// spliceUpgrade hands the 101 back to the client and then relays bytes in both
// directions until either end is done.
//
// The response head is written by hand rather than with resp.Write, which would
// try to send the body -- and on a 101 the body is not a body, it is the live
// connection to the upstream.
func (p *Proxy) spliceUpgrade(clientConn net.Conn, resp *http.Response, label string) bool {
	upstream, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		// Go's transport answers a 101 with a body that is also writable. A
		// response that switched protocols without one cannot be relayed, and
		// saying so beats relaying half of it.
		log.Printf("upgrade to %s: upstream connection is not writable", label)
		writeError(clientConn, 502, "upstream switched protocols without a usable connection")
		return false
	}
	defer func() { _ = upstream.Close() }()

	if err := writeResponseHead(clientConn, resp); err != nil {
		log.Printf("upgrade to %s: writing 101 to the client: %v", label, err)
		return false
	}

	relay(clientConn, upstream)

	// The connection is spent either way: it is no longer carrying HTTP, so there
	// is no next request to read from it.
	return false
}

// writeResponseHead writes a status line and headers, and no body.
func writeResponseHead(w io.Writer, resp *http.Response) error {
	status := resp.Status
	if status == "" {
		status = fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	} else if !strings.HasPrefix(status, fmt.Sprintf("%d", resp.StatusCode)) {
		status = fmt.Sprintf("%d %s", resp.StatusCode, status)
	}

	head := &strings.Builder{}
	fmt.Fprintf(head, "HTTP/1.1 %s\r\n", status)
	if err := resp.Header.Write(head); err != nil {
		return err
	}
	head.WriteString("\r\n")
	_, err := io.WriteString(w, head.String())
	return err
}

// relay copies bytes each way until one direction ends, then unblocks the other
// by closing both ends.
//
// A WebSocket can be idle for a long time and either side may be the one to
// finish, so neither direction can be waited on alone.
func relay(client, upstream io.ReadWriteCloser) {
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = client.Close()
			_ = upstream.Close()
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)
	for _, direction := range []struct{ dst, src io.ReadWriteCloser }{
		{client, upstream},
		{upstream, client},
	} {
		go func(dst, src io.ReadWriteCloser) {
			defer wg.Done()
			defer stop()
			_, _ = io.Copy(dst, src)
		}(direction.dst, direction.src)
	}
	wg.Wait()
}

// noteUpgrade records that a connection left HTTP behind, and what that costs the
// trail: response rules cannot run on frames KeyFence does not parse.
func (p *Proxy) noteUpgrade(entry audit.Entry, protocol string, rulesPending bool) {
	entry.Event = audit.EventAllow
	entry.Label = "upgrade:" + strings.ToLower(protocol)
	if rulesPending {
		entry.RuleAction = "skipped"
		entry.RuleReason = fmt.Sprintf(
			"connection upgraded to %s; response rules cannot run on relayed frames",
			strings.ToLower(protocol))
	}
	p.audit.Log(entry)
}
