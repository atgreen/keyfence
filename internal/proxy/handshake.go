// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@moxielogic.com>

package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/keyfence/keyfence/internal/audit"
)

// An interception layer inherits the job of being debuggable, because when it
// breaks it breaks as somebody else's outage. A client that refuses the leaf
// KeyFence minted reports it against the origin -- "certificate has expired"
// for api.github.com -- naming the one party in the exchange that did not issue
// it. KeyFence minted that certificate and still holds it, so it is the only
// party in a position to say so.

// interceptTLS terminates TLS with a certificate minted here for the host the
// ClientHello names, and answers with that host and that certificate alongside
// the connection.
func (p *Proxy) interceptTLS(ctx context.Context, conn net.Conn) (*tls.Conn, string, *tls.Certificate, error) {
	var (
		host   string
		served *tls.Certificate
	)
	tlsConn := tls.Server(conn, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host = hello.ServerName
			cert, err := p.ca.GetCertificate(hello)
			served = cert
			return cert, err
		},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		p.reportHandshakeFailure(host, served, err)
		return nil, host, served, err
	}
	return tlsConn, host, served, nil
}

// reportHandshakeFailure says what went wrong with a handshake that never
// completed, naming the certificate when the certificate was the complaint.
func (p *Proxy) reportHandshakeFailure(host string, served *tls.Certificate, err error) {
	named := host
	if named == "" {
		// No SNI is the interesting failure here: a client dialling an IP
		// literal cannot say where it meant to go, so there is nothing to
		// proxy it to and nothing to mint a certificate for.
		named = "an unnamed host"
	}

	alert, rejected := clientRejectedCert(err)
	if !rejected {
		log.Printf("TLS handshake for %s: %v", named, err)
		return
	}

	// A client that sent no SNI never got a certificate to refuse, so by here
	// the host is always named.
	opening := fmt.Sprintf("the client rejected the certificate served for %s with alert %q", host, alert)
	p.reportCertTrouble(host, opening, served, alert)
}

// reportSilentClient explains a client that took a KeyFence certificate,
// completed the handshake, and then left without sending a request.
//
// That is what a refusal looks like from this side when the client is
// OpenSSL-based and the connection is TLS 1.3: curl finishes the handshake
// before it decides about the certificate, so crypto/tls here reports a
// successful handshake and the refusal arrives as a connection that carries
// nothing. The alert path above never fires for it -- which is how the failure
// that took an hour to trace came to look like a bare "connection reset by
// peer", if it was logged at all.
//
// A client is entitled to open a connection and say nothing, so this reads as
// the likely cause rather than the certain one. On a broker whose whole job is
// carrying an agent's requests, it is almost always the certificate.
func (p *Proxy) reportSilentClient(host string, served *tls.Certificate, err error) {
	opening := fmt.Sprintf("the client took the certificate served for %s, sent no request, and left (%v)", host, err)
	p.reportCertTrouble(host, opening, served, "")
}

// reportCertTrouble says what happened to the log, for whoever is reading it,
// and to the audit trail, for whoever is supervising the run from outside this
// host -- which is the party least able to guess that the proxy is the problem.
func (p *Proxy) reportCertTrouble(host, opening string, served *tls.Certificate, alert string) {
	explanation := explainCertTrouble(opening, host, served, alert, p.ca.CertPath(), time.Now())
	log.Printf("TLS interception for %s: %s", host, explanation)
	p.audit.Log(audit.Entry{
		Event:       audit.EventCertRejected,
		Destination: host,
		CertReason:  explanation,
	})
}

// alertUnknownCA is the one refusal that names its own cause.
const alertUnknownCA = "unknown certificate authority"

// certAlerts are the refusals that mean "I will not accept this certificate",
// spelled as crypto/tls spells them.
var certAlerts = map[string]bool{
	"bad certificate":         true,
	"unsupported certificate": true,
	"revoked certificate":     true,
	"expired certificate":     true,
	"unknown certificate":     true,
	alertUnknownCA:            true,
}

// clientRejectedCert reports whether err is the client refusing the certificate
// it was served, and the alert it refused with.
//
// A refusal arrives as a remote alert rather than a local error, which is the
// only part of this that crypto/tls makes structural: the alert code itself is
// unexported, so the text is what there is to match on.
func clientRejectedCert(err error) (string, bool) {
	var op *net.OpError
	if !errors.As(err, &op) || op.Op != "remote error" || op.Err == nil {
		return "", false
	}
	alert := strings.TrimPrefix(op.Err.Error(), "tls: ")
	if !certAlerts[alert] {
		return "", false
	}
	return alert, true
}

// explainCertTrouble puts KeyFence's name on a certificate the client is about
// to blame the origin for. opening says what was seen from here; the rest says
// whose certificate it was and what could be wrong with it.
func explainCertTrouble(opening, host string, served *tls.Certificate, alert, caPath string, now time.Time) string {
	return strings.Join([]string{
		opening,
		fmt.Sprintf("KeyFence minted that certificate, not %s -- a client-side error about %s's certificate is pointing at the wrong party", host, host),
		diagnoseLeaf(served, alert, caPath, now),
	}, "; ")
}

// diagnoseLeaf says what KeyFence served and why the client could have refused
// it. The alert is worth little on its own -- Go's client answers an untrusted
// CA, an expired leaf and a wrong hostname with the same "bad certificate" --
// so the leaf is where the rest of the answer has to come from.
func diagnoseLeaf(served *tls.Certificate, alert, caPath string, now time.Time) string {
	if alert == alertUnknownCA {
		return fmt.Sprintf("the client named the issuer as its complaint, so trust the KeyFence CA at %s", caPath)
	}
	if served == nil || served.Leaf == nil {
		return fmt.Sprintf("KeyFence did not keep the leaf it served, so start with whether the KeyFence CA at %s is trusted", caPath)
	}

	leaf := served.Leaf
	window := fmt.Sprintf("the leaf was valid %s to %s",
		leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	switch {
	case now.After(leaf.NotAfter):
		return fmt.Sprintf("%s and expired %s ago, which KeyFence should have reissued rather than served",
			window, now.Sub(leaf.NotAfter).Round(time.Second))
	case now.Before(leaf.NotBefore):
		return fmt.Sprintf("%s and does not become current for another %s, so this host's clock is ahead of the client's",
			window, leaf.NotBefore.Sub(now).Round(time.Second))
	default:
		return fmt.Sprintf("%s, which covers now, so the client most likely does not trust the KeyFence CA at %s",
			window, caPath)
	}
}
