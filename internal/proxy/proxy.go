// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@redhat.com>

package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/keyfence/keyfence/internal/audit"
	"github.com/keyfence/keyfence/internal/credstore"
	"github.com/keyfence/keyfence/internal/policy"
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
	audit  *audit.Logger
	addr   string
}

func New(addr string, ca *CA, store *tokenstore.Store, creds credstore.Backend, certs *credstore.CertStore, pol *policy.Engine, auditLog *audit.Logger) *Proxy {
	return &Proxy{
		ca:     ca,
		store:  store,
		creds:  creds,
		certs:  certs,
		policy: pol,
		audit:  auditLog,
		addr:   addr,
	}
}

func (p *Proxy) ListenAndServe() error {
	ln, err := net.Listen("tcp", p.addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", p.addr, err)
	}
	log.Printf("proxy listening on %s", p.addr)
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
	defer conn.Close()

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

	// Send 200 to establish tunnel
	resp := &http.Response{
		StatusCode: 200,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	if err := resp.Write(conn); err != nil {
		log.Printf("write CONNECT response: %v", err)
		return
	}

	// TLS handshake with client using our CA-signed cert
	tlsConfig := &tls.Config{
		GetCertificate: p.ca.GetCertificate,
	}
	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(req.Context()); err != nil {
		log.Printf("TLS handshake for %s: %v", hostname, err)
		return
	}
	defer tlsConn.Close()

	// Read the actual HTTP request inside the TLS tunnel
	br := bufio.NewReader(tlsConn)
	innerReq, err := http.ReadRequest(br)
	if err != nil {
		log.Printf("read inner request for %s: %v", hostname, err)
		return
	}
	innerReq.URL.Scheme = "https"
	innerReq.URL.Host = hostname

	p.processRequest(tlsConn, innerReq, hostname)
}

// processRequest is the core: find token, validate, swap, forward.
func (p *Proxy) processRequest(clientConn net.Conn, req *http.Request, targetHost string) {
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
		writeError(clientConn, 401, "no keyfence token found in request headers")
		return
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
		writeError(clientConn, 403, "invalid or expired keyfence token")
		return
	}

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
		writeError(clientConn, 429, fmt.Sprintf("rate limit exceeded: %d requests per %s", token.RateLimit, token.RateWindow))
		return
	}

	// Check destination
	if !token.IsDestinationAllowed(targetHost) {
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
		writeError(clientConn, 403, fmt.Sprintf("token not allowed for destination %s", targetHost))
		return
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
			writeError(clientConn, 403, deny.Message)
			return
		}
	}

	// Fetch and swap header credential (if token has one)
	if token.CredentialID != "" {
		realCredential, err := p.creds.Fetch(token.CredentialID)
		if err != nil {
			log.Printf("credential fetch error: %v", err)
			writeError(clientConn, 500, "failed to fetch credential")
			return
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
			return
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
			return
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
		writeError(clientConn, 502, fmt.Sprintf("upstream error: %v", err))
		return
	}
	defer upstreamResp.Body.Close()

	if err := upstreamResp.Write(clientConn); err != nil {
		log.Printf("write response: %v", err)
	}
}

func (p *Proxy) forwardRequest(req *http.Request, host string, clientCert *tls.Certificate) (*http.Response, error) {
	tlsConfig := &tls.Config{
		ServerName: host,
	}
	if clientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*clientCert}
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	req.RequestURI = ""
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")

	return transport.RoundTrip(req)
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
	conn.Write([]byte(resp))
}

func writeJSON(conn net.Conn, status int, body string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
	conn.Write([]byte(resp))
}
