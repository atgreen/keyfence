// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@moxielogic.com>

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	"github.com/keyfence/keyfence/internal/audit"
	"github.com/keyfence/keyfence/internal/credstore"
	"github.com/keyfence/keyfence/internal/luaengine"
	"github.com/keyfence/keyfence/internal/policy"
	"github.com/keyfence/keyfence/internal/telemetry"
	"github.com/keyfence/keyfence/internal/tokenstore"
)

// Proxy is a TLS-intercepting forward proxy.
//
// It handles HTTP CONNECT (MITM mode):
//  1. Client sends CONNECT api.anthropic.com:443
//  2. Proxy accepts, does TLS handshake with local CA cert
//  3. Reads decrypted HTTP request
//  4. Finds kf_ token in any header, validates it, checks destination
//  5. Replaces kf_ token with real credential in the same header
//  6. Forwards to the real upstream over TLS
//  7. Pipes response back
//
// The proxy is completely service-agnostic. It doesn't know or care
// about Anthropic, OpenAI, or any other API. The token carries all
// the information: what credential to inject and where it's allowed.
type Proxy struct {
	ca     *CA
	store  *tokenstore.Store
	creds  credstore.Backend
	certs  *credstore.CertStore
	policy *policy.Engine
	named  *credstore.NamedStore

	// One transport for upstream connections without a client certificate,
	// which is nearly all of them. Building a transport per request meant a
	// fresh TCP connection and TLS handshake every time, with the pool it
	// maintains discarded immediately afterwards.
	upstream *http.Transport
	audit    *audit.Logger
	lua      *luaengine.Engine
	addr     string
}

func New(addr string, ca *CA, store *tokenstore.Store, creds credstore.Backend, certs *credstore.CertStore, pol *policy.Engine, auditLog *audit.Logger, named *credstore.NamedStore) *Proxy {
	return &Proxy{
		ca:     ca,
		store:  store,
		creds:  creds,
		certs:  certs,
		policy: pol,
		named:  named,
		upstream: &http.Transport{
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   8,
			IdleConnTimeout:       90 * time.Second,
			// HTTP/1.1 upstream deliberately. What reaches the client is
			// re-serialized as HTTP/1.1 either way, and an HTTP/2 response
			// arrives with neither a length nor chunked framing, so it would
			// have to be buffered or re-chunked to be forwarded at all.
			ForceAttemptHTTP2: false,
		},
		audit: auditLog,
		lua:   luaengine.New(),
		addr:  addr,
	}
}

func (p *Proxy) ListenAndServe() error {
	ln, err := net.Listen("tcp", p.addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", p.addr, err)
	}
	return p.Serve(ln)
}

// Serve accepts on a listener the caller already has. That is how a socket
// passed in by systemd is used: the socket is already listening before this
// process existed, so there is nothing here to bind.
func (p *Proxy) Serve(ln net.Listener) error {
	log.Printf("proxy listening on %s", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go p.handleConn(conn)
	}
}

func (p *Proxy) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		p.handleConnect(conn, req)
	} else {
		// Plain HTTP: health check or error
		if req.URL.Path == "/_health" {
			writeJSON(conn, 200, `{"status":"ok","service":"keyfence"}`)
			return
		}
		writeError(conn, 400, "keyfence is an HTTPS proxy. Set HTTPS_PROXY=http://127.0.0.1"+p.addr+" and use https:// URLs")
	}
}

// handleConnect handles HTTPS CONNECT tunneling with MITM.
func (p *Proxy) handleConnect(conn net.Conn, req *http.Request) {
	host := req.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	hostname := strings.Split(host, ":")[0]

	ctx, span := telemetry.Tracer().Start(context.Background(), "proxy.connect",
		telemetry.WithSpanAttributes(
			attribute.String("net.peer.name", hostname),
		),
	)
	defer span.End()

	// Send 200 to establish tunnel
	resp := &http.Response{
		StatusCode: 200,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	if err := resp.Write(conn); err != nil {
		log.Printf("write CONNECT response: %v", err)
		span.SetStatus(codes.Error, "write CONNECT response")
		return
	}

	// TLS handshake with client using our CA-signed cert
	tlsConfig := &tls.Config{
		GetCertificate: p.ca.GetCertificate,
	}
	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(req.Context()); err != nil {
		log.Printf("TLS handshake for %s: %v", hostname, err)
		span.SetStatus(codes.Error, "TLS handshake failed")
		return
	}
	defer func() { _ = tlsConn.Close() }()

	// Read requests inside the TLS tunnel until the client stops sending them.
	//
	// One per tunnel was the old behaviour, which meant an agent making twenty
	// API calls paid twenty TCP connections and twenty TLS handshakes -- to the
	// proxy on loopback, and again to the upstream. HTTP/1.1 keep-alive is the
	// client's default, and this honours it: a request is followed by another on
	// the same connection unless one side says otherwise.
	br := bufio.NewReader(tlsConn)
	for {
		innerReq, err := http.ReadRequest(br)
		if err != nil {
			// EOF is the ordinary end of a keep-alive connection, not a fault.
			if err != io.EOF {
				log.Printf("read inner request for %s: %v", hostname, err)
				span.SetStatus(codes.Error, "read inner request")
			}
			return
		}
		innerReq.URL.Scheme = "https"
		innerReq.URL.Host = hostname

		if !p.processRequest(ctx, tlsConn, innerReq, hostname) {
			return
		}
	}
}

// processRequest is the core: find token, validate, swap, forward.
// processRequest is the core: find token, validate, swap, forward. It answers
// whether the connection can carry another request afterwards.
//
// Anything that ends in an error answers false: the client is told what happened
// and the connection closed, which is simpler to reason about than leaving a
// tunnel open after a refusal.
func (p *Proxy) processRequest(ctx context.Context, clientConn net.Conn, req *http.Request, targetHost string) bool {
	_, span := telemetry.Tracer().Start(ctx, "proxy.request",
		telemetry.WithSpanAttributes(
			attribute.String("http.method", req.Method),
			attribute.String("http.url", req.URL.Path),
			attribute.String("net.peer.name", targetHost),
		),
	)
	defer span.End()

	// Find kf_ token in any header
	tokenValue, tokenHeader := findToken(req)
	if tokenValue == "" {
		p.audit.Log(audit.Entry{
			Event:       audit.EventDeny,
			Destination: targetHost,
			Method:      req.Method,
			Path:        req.URL.Path,
			DenyRule:    "no_token",
			DenyReason:  "no keyfence token found in request headers",
		})
		span.SetStatus(codes.Error, "no_token")
		writeError(clientConn, 401, "no keyfence token found in request headers")
		return false
	}

	// Resolve token
	token := p.store.Resolve(tokenValue)
	if token == nil {
		p.audit.Log(audit.Entry{
			Event:       audit.EventDeny,
			Destination: targetHost,
			Method:      req.Method,
			Path:        req.URL.Path,
			DenyRule:    "invalid_token",
			DenyReason:  "invalid or expired keyfence token",
		})
		span.SetStatus(codes.Error, "invalid_token")
		writeError(clientConn, 403, "invalid or expired keyfence token")
		return false
	}

	span.SetAttributes(
		attribute.String("keyfence.token_id", token.ID),
		attribute.String("keyfence.agent_id", token.AgentID),
		attribute.String("keyfence.task_id", token.TaskID),
		attribute.String("keyfence.policy", token.PolicyName),
	)

	// Per-token rate limit (set by operator at issuance)
	if token.RateLimit > 0 && !p.store.CheckRate(tokenValue) {
		p.audit.Log(audit.Entry{
			Event:       audit.EventDeny,
			TokenID:     token.ID,
			AgentID:     token.AgentID,
			TaskID:      token.TaskID,
			Destination: targetHost,
			Method:      req.Method,
			Path:        req.URL.Path,
			DenyRule:    "rate_limit",
			DenyReason:  fmt.Sprintf("token rate limit exceeded: %d per %s", token.RateLimit, token.RateWindow),
		})
		span.SetStatus(codes.Error, "rate_limit")
		writeError(clientConn, 429, fmt.Sprintf("rate limit exceeded: %d requests per %s", token.RateLimit, token.RateWindow))
		return false
	}

	// Check destination
	if !token.IsDestinationAllowed(targetHost, req.URL.Path) {
		p.audit.Log(audit.Entry{
			Event:       audit.EventDeny,
			TokenID:     token.ID,
			AgentID:     token.AgentID,
			TaskID:      token.TaskID,
			Destination: targetHost,
			Method:      req.Method,
			Path:        req.URL.Path,
			DenyRule:    "destination",
			DenyReason:  fmt.Sprintf("token not allowed for destination %s", targetHost),
		})
		span.SetStatus(codes.Error, "destination_denied")
		writeError(clientConn, 403, fmt.Sprintf("token not allowed for destination %s", targetHost))
		return false
	}

	// Policy check
	if p.policy != nil {
		if deny := p.policy.Check(token.PolicyName, token.ID, req); deny != nil {
			p.audit.Log(audit.Entry{
				Event:       audit.EventDeny,
				TokenID:     token.ID,
				AgentID:     token.AgentID,
				TaskID:      token.TaskID,
				Destination: targetHost,
				Method:      req.Method,
				Path:        req.URL.Path,
				Policy:      token.PolicyName,
				DenyRule:    deny.Rule,
				DenyReason:  deny.Message,
			})
			span.SetStatus(codes.Error, "policy_denied: "+deny.Rule)
			writeError(clientConn, 403, deny.Message)
			return false
		}
	}

	// Fetch and swap header credential (if token has one)
	if token.CredentialID != "" || token.CredentialRef != "" {
		realCredential, err := p.resolveCredential(token)
		if err != nil {
			log.Printf("credential fetch error: %v", err)
			writeError(clientConn, 500, "failed to fetch credential")
			return false
		}

		currentVal := req.Header.Get(tokenHeader)
		if strings.HasPrefix(currentVal, "Basic ") {
			decoded, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(currentVal, "Basic "))
			swapped := strings.Replace(string(decoded), tokenValue, realCredential, 1)
			req.Header.Set(tokenHeader, "Basic "+base64.StdEncoding.EncodeToString([]byte(swapped)))
		} else {
			newVal := strings.Replace(currentVal, tokenValue, realCredential, 1)
			req.Header.Set(tokenHeader, newVal)
		}
	}

	// Fetch client cert (if token has one)
	var clientTLSCert *tls.Certificate
	if token.ClientCertID != "" && p.certs != nil {
		cc, err := p.certs.Fetch(token.ClientCertID)
		if err != nil {
			log.Printf("client cert fetch error: %v", err)
			writeError(clientConn, 500, "failed to fetch client certificate")
			return false
		}

		// Inject cert PEM into header if configured
		if token.ClientCertHeader != "" {
			req.Header.Set(token.ClientCertHeader, cc.CertPEM)
		}

		// Parse for mTLS on the upstream connection
		tlsCert, err := tls.X509KeyPair([]byte(cc.CertPEM), []byte(cc.KeyPEM))
		if err != nil {
			log.Printf("client cert parse error: %v", err)
			writeError(clientConn, 500, "invalid client certificate")
			return false
		}
		clientTLSCert = &tlsCert
	}

	p.audit.Log(audit.Entry{
		Event:       audit.EventAllow,
		TokenID:     token.ID,
		AgentID:     token.AgentID,
		TaskID:      token.TaskID,
		Destination: targetHost,
		Method:      req.Method,
		Path:        req.URL.Path,
		Policy:      token.PolicyName,
	})

	// Forward to upstream
	upstreamResp, err := p.forwardRequest(req, targetHost, clientTLSCert)
	if err != nil {
		log.Printf("upstream error: %v", err)
		span.SetStatus(codes.Error, "upstream_error")
		writeError(clientConn, 502, fmt.Sprintf("upstream error: %v", err))
		return false
	}
	defer func() { _ = upstreamResp.Body.Close() }()

	span.SetAttributes(attribute.Int("http.status_code", upstreamResp.StatusCode))

	// Forward it, inspecting on the way past if the token has rules. Whether the
	// connection can carry another request depends on both ends: the client not
	// having asked to close, and the response having been framed in a way the
	// client can tell the end of.
	reusable := p.inspectAndForwardResponse(clientConn, upstreamResp, token, tokenValue)
	return reusable && !req.Close && req.ProtoAtLeast(1, 1)
}

func (p *Proxy) forwardRequest(req *http.Request, host string, clientCert *tls.Certificate) (*http.Response, error) {
	transport := p.upstream
	if clientCert != nil {
		// A client certificate makes this connection specific to one token, so it
		// cannot share the pool. Its idle connections are closed when the request
		// is done rather than left to a transport nothing will use again.
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:   host,
				Certificates: []tls.Certificate{*clientCert},
			},
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		}
		defer transport.CloseIdleConnections()
	}

	req.RequestURI = ""
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")

	return transport.RoundTrip(req)
}

// resolveCredential answers the real credential behind a token.
//
// A named reference is resolved on every request, which is what makes rotation
// work without reissuing anything: replace the file, and the next request carries
// the new value. A credential handed over at issuance is fetched from the backend
// it was stored in, as before.
func (p *Proxy) resolveCredential(token *tokenstore.Token) (string, error) {
	if token.CredentialRef != "" {
		if p.named == nil {
			return "", fmt.Errorf("token references credential %q but no credential directories are configured",
				token.CredentialRef)
		}
		return p.named.Resolve(token.CredentialRef)
	}
	return p.creds.Fetch(token.CredentialID)
}

const maxResponseBuffer = 10 * 1024 * 1024 // 10 MiB

// inspectAndForwardResponse tees the upstream response to the client while
// capturing the body for Lua rule evaluation. It handles both standard JSON
// responses and SSE streaming responses.
//
// It answers whether the connection can be reused afterwards, which needs the
// client to be able to tell where the response ended: a declared length or
// chunked framing, and not a body that runs until the connection closes.
func (p *Proxy) inspectAndForwardResponse(clientConn net.Conn, resp *http.Response, token *tokenstore.Token, tokenValue string) bool {
	ct := resp.Header.Get("Content-Type")

	if strings.Contains(ct, "text/event-stream") {
		// SSE: wrap body to capture the last data: line while streaming to client
		capture := &sseCapture{src: resp.Body}
		resp.Body = capture
		if err := resp.Write(clientConn); err != nil {
			log.Printf("write response: %v", err)
		}
		if capture.lastData != "" {
			p.evalResponseRules(token, tokenValue, []byte(capture.lastData), resp)
		}
		// A stream ends when the upstream closes it, so there is no next request
		// on this connection.
		return false
	}

	// Nothing to inspect: hand the response straight through. A token with no
	// response rules, or a body no rule could parse, gains nothing from being
	// held in memory first -- and a proxy that buffers what it will not look at
	// is just a slower proxy with a size limit in it.
	if len(token.ResponseRules) == 0 || !strings.Contains(ct, "application/json") {
		makeFramingDeterminate(resp)
		if err := resp.Write(clientConn); err != nil {
			log.Printf("write response: %v", err)
			return false
		}
		return framedDeterminately(resp)
	}

	// One byte past the cap, so that reaching the cap is distinguishable from a
	// body that happens to end exactly on it.
	prefix, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBuffer+1))
	if err != nil {
		// Nothing was written to the client, and the upstream body is in an
		// unknown state, so this connection is finished.
		log.Printf("read response body: %v", err)
		return false
	}

	if len(prefix) > maxResponseBuffer {
		// Too large to inspect, so it does not get inspected -- but it does get
		// delivered whole. Truncating a response to fit a buffer, and rewriting
		// Content-Length to match, hands the client a body that looks complete
		// and is not: JSON that parses, a file that is short, and nothing
		// anywhere saying so.
		//
		// The rules are skipped rather than run on a prefix, because a rule that
		// counts tokens or spends a budget would silently undercount from a
		// fragment. The audit trail records that they did not run, so an
		// accounting gap is visible rather than assumed not to exist.
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), resp.Body))
		makeFramingDeterminate(resp)
		if err := resp.Write(clientConn); err != nil {
			log.Printf("write response: %v", err)
		}
		p.audit.Log(audit.Entry{
			Event:      audit.EventResponseRule,
			TokenID:    token.ID,
			AgentID:    token.AgentID,
			TaskID:     token.TaskID,
			RuleAction: "skipped",
			RuleReason: fmt.Sprintf("response larger than the %d byte inspection limit; forwarded without evaluating %d rule(s)",
				maxResponseBuffer, len(token.ResponseRules)),
		})
		return framedDeterminately(resp)
	}

	resp.Body = io.NopCloser(bytes.NewReader(prefix))
	resp.ContentLength = int64(len(prefix))
	if err := resp.Write(clientConn); err != nil {
		log.Printf("write response: %v", err)
	}

	if len(prefix) > 0 {
		p.evalResponseRules(token, tokenValue, prefix, resp)
	}
	// Buffered, so the length written was exact.
	return true
}

// makeFramingDeterminate arranges for the client to be able to tell where the
// response ends.
//
// A response with neither a declared length nor chunked framing -- an HTTP/2
// response, or an HTTP/1.0 one -- can only be delimited by closing the
// connection, which throws away the connection for every request after it.
// Chunking it instead keeps the body streaming and the connection reusable.
func makeFramingDeterminate(resp *http.Response) {
	if resp.Close || resp.ContentLength >= 0 || len(resp.TransferEncoding) > 0 {
		return
	}
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		return
	}
	resp.TransferEncoding = []string{"chunked"}
	if resp.ProtoMajor != 1 || resp.ProtoMinor != 1 {
		// Written to the client as HTTP/1.1, whatever the upstream spoke.
		resp.Proto, resp.ProtoMajor, resp.ProtoMinor = "HTTP/1.1", 1, 1
	}
}

// framedDeterminately answers whether a client can tell where this response
// ended without waiting for the connection to close.
func framedDeterminately(resp *http.Response) bool {
	if resp.Close {
		return false
	}
	for _, encoding := range resp.TransferEncoding {
		if encoding == "chunked" {
			return true
		}
	}
	return resp.ContentLength >= 0
}

func (p *Proxy) evalResponseRules(token *tokenstore.Token, tokenValue string, body []byte, resp *http.Response) {
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return // not valid JSON, skip
	}

	headers := make(map[string]string, len(resp.Header))
	for k := range resp.Header {
		headers[k] = resp.Header.Get(k)
	}

	for _, rule := range token.ResponseRules {
		// Copy state under lock, evaluate, write back
		token.RuleStateMu.Lock()
		stateCopy := make(map[string]interface{}, len(token.RuleState))
		for k, v := range token.RuleState {
			stateCopy[k] = v
		}
		token.RuleStateMu.Unlock()

		input := &luaengine.EvalInput{
			ResponseBody:    parsed,
			ResponseHeaders: headers,
			ResponseStatus:  resp.StatusCode,
			State:           stateCopy,
		}

		action, err := p.lua.Eval(rule.Script, input)
		if err != nil {
			log.Printf("lua rule error for token %s: %v", token.ID, err)
			p.audit.Log(audit.Entry{
				Event:      audit.EventResponseRule,
				TokenID:    token.ID,
				AgentID:    token.AgentID,
				TaskID:     token.TaskID,
				RuleAction: "error",
				RuleReason: err.Error(),
			})
			continue
		}

		// Write state back
		token.RuleStateMu.Lock()
		for k := range token.RuleState {
			delete(token.RuleState, k)
		}
		for k, v := range stateCopy {
			token.RuleState[k] = v
		}
		token.RuleStateMu.Unlock()

		if action == nil {
			continue
		}

		p.audit.Log(audit.Entry{
			Event:      audit.EventResponseRule,
			TokenID:    token.ID,
			AgentID:    token.AgentID,
			TaskID:     token.TaskID,
			RuleAction: action.Action,
			RuleReason: action.Reason,
		})

		switch action.Action {
		case "revoke":
			p.store.Revoke(tokenValue)
			p.audit.Log(audit.Entry{
				Event:   audit.EventRevoke,
				TokenID: token.ID,
				AgentID: token.AgentID,
				TaskID:  token.TaskID,
				Label:   "revoked by response rule: " + action.Reason,
			})
		case "alert":
			// audit event already logged above
		}
	}
}

// sseCapture wraps a ReadCloser and captures the last SSE "data:" payload
// while passing all bytes through. This allows the proxy to stream the
// response to the client in real-time while recording the final event
// (which typically contains usage data in LLM APIs).
type sseCapture struct {
	src      io.ReadCloser
	buf      bytes.Buffer
	lastData string
}

func (s *sseCapture) Read(p []byte) (int, error) {
	n, err := s.src.Read(p)
	if n > 0 {
		s.buf.Write(p[:n])
		// Scan for complete lines
		for {
			line, lineErr := s.buf.ReadString('\n')
			if lineErr != nil {
				// Incomplete line — put it back for next Read
				s.buf.WriteString(line)
				break
			}
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "data:") && trimmed != "data: [DONE]" {
				s.lastData = strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
			}
		}
	}
	return n, err
}

func (s *sseCapture) Close() error {
	return s.src.Close()
}

// findToken looks for a kf_ token in any request header value.
// It checks plaintext header values first (Bearer tokens, API keys),
// then decodes Basic auth headers to find tokens used as passwords
// (e.g., git over HTTPS sends Authorization: Basic base64(user:kf_token)).
func findToken(req *http.Request) (tokenValue, headerKey string) {
	for key, values := range req.Header {
		for _, val := range values {
			// Check plaintext parts (covers Bearer, API key headers)
			for _, part := range strings.Fields(val) {
				if strings.HasPrefix(part, "kf_") {
					return part, key
				}
			}

			// Check inside Basic auth
			if strings.HasPrefix(val, "Basic ") {
				decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(val, "Basic "))
				if err != nil {
					continue
				}
				parts := strings.SplitN(string(decoded), ":", 2)
				if len(parts) == 2 {
					// Token could be the username or password
					for _, p := range parts {
						if strings.HasPrefix(p, "kf_") {
							return p, key
						}
					}
				}
			}
		}
	}
	return "", ""
}

func writeError(conn net.Conn, status int, message string) {
	body := fmt.Sprintf(`{"error":"%s"}`, message)
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
	_, _ = conn.Write([]byte(resp))
}

func writeJSON(conn net.Conn, status int, body string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
	_, _ = conn.Write([]byte(resp))
}
