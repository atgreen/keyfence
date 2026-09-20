// SPDX-License-Identifier: MIT

package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/keyfence/keyfence/internal/audit"
	"github.com/keyfence/keyfence/internal/telemetry"
)

// Diagnosing keyfence-bv8 from the client side meant comparing leaf dates across
// several hosts and reading the issuer before the local CA was implicated at
// all: GitHub looked like the outage. Whatever KeyFence knows about a
// certificate it minted has to reach whoever is reading the logs, because the
// client is busy telling them something else.

func leafValid(t *testing.T, from, until time.Time) *tls.Certificate {
	t.Helper()
	ca := newTestCA(t)
	cert := requestCert(t, ca, "api.github.com")
	cert.Leaf.NotBefore = from
	cert.Leaf.NotAfter = until
	return cert
}

// rejectHandshake serves cert to a client that trusts roots, and answers with
// the error the server side of the handshake saw.
func rejectHandshake(t *testing.T, cert *tls.Certificate, roots *x509.CertPool) error {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	served := make(chan error, 1)
	go func() {
		server := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{*cert}})
		served <- server.HandshakeContext(context.Background())
	}()

	client := tls.Client(clientConn, &tls.Config{ServerName: "api.github.com", RootCAs: roots})
	if err := client.HandshakeContext(context.Background()); err == nil {
		t.Fatal("the client accepted a certificate the test meant it to refuse")
	}
	return <-served
}

func TestAClientRefusingTheCertificateIsRecognisedAsSuch(t *testing.T) {
	// crypto/tls keeps the alert code unexported, so this is matched by text.
	// Running a real handshake is what keeps that match honest: if the wording
	// ever moves, this fails rather than the diagnosis quietly going missing.
	ca := newTestCA(t)
	cert := requestCert(t, ca, "api.github.com")

	err := rejectHandshake(t, cert, x509.NewCertPool()) // trusts nothing

	alert, rejected := clientRejectedCert(err)
	if !rejected {
		t.Fatalf("a refused certificate was not recognised as one: %v", err)
	}
	if !certAlerts[alert] {
		t.Errorf("alert %q is not one this code knows about", alert)
	}
}

func TestAHandshakeThatDiedForOtherReasonsIsNotBlamedOnTheCertificate(t *testing.T) {
	for name, err := range map[string]error{
		"connection closed": io.EOF,
		"no SNI":            errors.New("no SNI in ClientHello"),
		"a local timeout":   &net.OpError{Op: "read", Err: errors.New("i/o timeout")},
		"another alert":     &net.OpError{Op: "remote error", Err: errors.New("tls: protocol version not supported")},
	} {
		if _, rejected := clientRejectedCert(err); rejected {
			t.Errorf("%s was reported as a rejected certificate", name)
		}
	}
}

func TestTheExplanationNamesKeyFenceRatherThanTheOrigin(t *testing.T) {
	const opening = "the client rejected the certificate served for api.github.com"
	now := time.Now()
	cert := leafValid(t, now.Add(-time.Hour), now.Add(23*time.Hour))

	explanation := explainCertTrouble(opening, "api.github.com", cert, "bad certificate", "/etc/keyfence/ca.pem", now)

	if !strings.Contains(explanation, "KeyFence") {
		t.Errorf("nothing in %q names KeyFence as the issuer", explanation)
	}
	if !strings.Contains(explanation, "api.github.com") {
		t.Errorf("nothing in %q names the host the certificate was for", explanation)
	}
	if !strings.Contains(explanation, "wrong party") {
		t.Errorf("%q does not say the client is blaming the wrong party", explanation)
	}
}

func TestAnExpiredLeafIsNamedAsKeyFencesOwnFault(t *testing.T) {
	const opening = "the client rejected the certificate served for api.github.com"
	now := time.Now()
	cert := leafValid(t, now.Add(-25*time.Hour), now.Add(-90*time.Minute))

	explanation := explainCertTrouble(opening, "api.github.com", cert, "bad certificate", "/etc/keyfence/ca.pem", now)

	if !strings.Contains(explanation, "expired 1h30m0s ago") {
		t.Errorf("%q does not say how long ago the leaf expired", explanation)
	}
	if !strings.Contains(explanation, "should have reissued") {
		t.Errorf("%q does not own the fault", explanation)
	}
}

func TestALeafFromTheFutureIsReportedAsAClockDisagreement(t *testing.T) {
	const opening = "the client rejected the certificate served for api.github.com"
	now := time.Now()
	cert := leafValid(t, now.Add(2*time.Hour), now.Add(26*time.Hour))

	explanation := explainCertTrouble(opening, "api.github.com", cert, "bad certificate", "/etc/keyfence/ca.pem", now)

	if !strings.Contains(explanation, "not become current for another 2h0m0s") {
		t.Errorf("%q does not say the leaf is not current yet", explanation)
	}
	if !strings.Contains(explanation, "clock") {
		t.Errorf("%q does not raise the clocks, which is the only way this happens", explanation)
	}
}

func TestACurrentLeafPointsAtTrustInstead(t *testing.T) {
	const opening = "the client rejected the certificate served for api.github.com"
	now := time.Now()
	cert := leafValid(t, now.Add(-time.Hour), now.Add(23*time.Hour))

	explanation := explainCertTrouble(opening, "api.github.com", cert, "bad certificate", "/etc/keyfence/ca.pem", now)

	if !strings.Contains(explanation, "which covers now") {
		t.Errorf("%q does not say the leaf was usable", explanation)
	}
	if !strings.Contains(explanation, "/etc/keyfence/ca.pem") {
		t.Errorf("%q does not point at the CA the client has to trust", explanation)
	}
}

func TestAClientThatNamesTheIssuerIsTakenAtItsWord(t *testing.T) {
	// Go's client answers every certificate complaint with "bad certificate",
	// so the leaf has to be read to guess why. A client that says the issuer is
	// its problem has already answered, and the leaf's dates are beside the point.
	const opening = "the client rejected the certificate served for api.github.com"
	now := time.Now()
	cert := leafValid(t, now.Add(-25*time.Hour), now.Add(-time.Hour))

	explanation := explainCertTrouble(opening, "api.github.com", cert, alertUnknownCA, "/etc/keyfence/ca.pem", now)

	if !strings.Contains(explanation, "trust the KeyFence CA at /etc/keyfence/ca.pem") {
		t.Errorf("%q does not say what to trust", explanation)
	}
	if strings.Contains(explanation, "expired") {
		t.Errorf("%q guesses at the leaf when the client already said what was wrong", explanation)
	}
}

func TestACertificateKeyFenceCannotDescribeIsStillActionable(t *testing.T) {
	const opening = "the client rejected the certificate served for api.github.com"
	explanation := explainCertTrouble(opening, "api.github.com", nil, "bad certificate", "/etc/keyfence/ca.pem", time.Now())

	if !strings.Contains(explanation, "KeyFence") || !strings.Contains(explanation, "/etc/keyfence/ca.pem") {
		t.Errorf("%q leaves a reader with nothing to do", explanation)
	}
}

func TestARejectedCertificateReachesTheAuditTrail(t *testing.T) {
	// The log is on the host; a sandbox supervisor reads the audit trail. The
	// party who cannot see the proxy's terminal is exactly the party most
	// likely to conclude the origin is down.
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	recent := audit.NewRecent(10)
	auditLog := audit.New(io.Discard)
	auditLog.AddSink(recent)
	p := New("127.0.0.1:0", newTestCA(t), nil, nil, nil, nil, auditLog, nil, nil, false)

	clientConn, serverConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, _, _, err := p.interceptTLS(context.Background(), serverConn); err == nil {
			t.Error("a handshake the client refused was reported as successful")
		}
	}()

	client := tls.Client(clientConn, &tls.Config{ServerName: "api.github.com", RootCAs: x509.NewCertPool()})
	_ = client.HandshakeContext(context.Background())
	<-done

	entries := recent.Entries("")
	if len(entries) != 1 {
		t.Fatalf("got %d audit entries, want the one rejection: %+v", len(entries), entries)
	}
	if entries[0].Event != audit.EventCertRejected {
		t.Errorf("event is %q, want %q", entries[0].Event, audit.EventCertRejected)
	}
	if entries[0].Destination != "api.github.com" {
		t.Errorf("destination is %q, want the host the certificate was for", entries[0].Destination)
	}
	if !strings.Contains(entries[0].CertReason, "KeyFence minted that certificate") {
		t.Errorf("audited reason %q does not name KeyFence as the issuer", entries[0].CertReason)
	}
}

// A TLS 1.3 client built on OpenSSL -- curl, and so most of what an agent shells
// out to -- finishes the handshake before it decides about the certificate. The
// server side sees a clean handshake and then a connection that carries nothing,
// which is the shape the failure actually had in the field: no alert, no
// handshake error, and a bare "connection reset by peer" if anything was logged
// at all.

func interceptedProxy(t *testing.T) (*Proxy, *audit.Recent) {
	t.Helper()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	recent := audit.NewRecent(10)
	auditLog := audit.New(io.Discard)
	auditLog.AddSink(recent)
	return New("127.0.0.1:0", newTestCA(t), nil, nil, nil, nil, auditLog, nil, nil, false), recent
}

func TestAClientThatTakesACertificateAndSendsNothingIsExplained(t *testing.T) {
	p, recent := interceptedProxy(t)

	trusted := x509.NewCertPool()
	if !trusted.AppendCertsFromPEM(p.ca.CertPEM()) {
		t.Fatal("the CA KeyFence just created is not loadable as a root")
	}

	clientConn, serverConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		tlsConn, host, served, err := p.interceptTLS(context.Background(), serverConn)
		if err != nil {
			t.Errorf("handshake with a client that trusts the CA: %v", err)
			return
		}
		_, span := telemetry.Tracer().Start(context.Background(), "test")
		defer span.End()
		p.serveTunnel(context.Background(), tlsConn, host, served, span)
	}()

	client := tls.Client(clientConn, &tls.Config{ServerName: "api.github.com", RootCAs: trusted})
	if err := client.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("a client trusting the KeyFence CA could not handshake: %v", err)
	}
	_ = client.Close() // verified the certificate, then thought better of it
	<-done

	entries := recent.Entries("")
	if len(entries) != 1 {
		t.Fatalf("got %d audit entries, want the one explanation: %+v", len(entries), entries)
	}
	if entries[0].Event != audit.EventCertRejected {
		t.Errorf("event is %q, want %q", entries[0].Event, audit.EventCertRejected)
	}
	if !strings.Contains(entries[0].CertReason, "sent no request") {
		t.Errorf("reason %q does not say what the client did", entries[0].CertReason)
	}
	if !strings.Contains(entries[0].CertReason, "wrong party") {
		t.Errorf("reason %q does not name KeyFence as the issuer", entries[0].CertReason)
	}
}

func TestAConnectionThatCarriedARequestIsNotBlamedOnTheCertificate(t *testing.T) {
	// Keep-alive means the ordinary end of a working connection is also a read
	// that fails with nothing to show for it. Only the first one is evidence.
	p, recent := interceptedProxy(t)
	cert := requestCert(t, p.ca, "api.github.com")

	clientConn, serverConn := net.Pipe()
	_, span := telemetry.Tracer().Start(context.Background(), "test")
	defer span.End()

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = serverConn.Close() }()
		p.serveRequests(context.Background(), serverConn, bufio.NewReader(serverConn),
			"api.github.com", "https", cert, span)
	}()

	if _, err := io.WriteString(clientConn, "GET / HTTP/1.1\r\nHost: api.github.com\r\n\r\n"); err != nil {
		t.Fatalf("writing a request: %v", err)
	}
	_, _ = io.ReadAll(clientConn) // the refusal for a request carrying no token
	_ = clientConn.Close()
	<-done

	for _, entry := range recent.Entries("") {
		if entry.Event == audit.EventCertRejected {
			t.Errorf("a connection that carried a request was blamed on the certificate: %q", entry.CertReason)
		}
	}
}

func TestACleartextConnectionIsNeverBlamedOnACertificate(t *testing.T) {
	// No interception, no KeyFence certificate, nothing to explain.
	p, recent := interceptedProxy(t)

	clientConn, serverConn := net.Pipe()
	_, span := telemetry.Tracer().Start(context.Background(), "test")
	defer span.End()

	done := make(chan struct{})
	go func() {
		defer close(done)
		p.serveRequests(context.Background(), serverConn, bufio.NewReader(serverConn),
			"api.github.com", "http", nil, span)
	}()
	_ = clientConn.Close()
	<-done

	if entries := recent.Entries(""); len(entries) != 0 {
		t.Errorf("a cleartext connection produced audit entries: %+v", entries)
	}
}
