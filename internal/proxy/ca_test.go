// SPDX-License-Identifier: MIT

package proxy

import (
	"crypto/tls"
	"testing"
	"time"
)

// A KeyFence session outlives the certificates it mints. Each host an agent
// reaches gets a leaf good for a day, so a session that runs past that -- or
// resumes against a cache filled yesterday -- asks for a certificate that has
// already expired. Handing it back anyway breaks that host for the remaining
// life of the process, and breaks it in the client's voice rather than the
// proxy's.

func newTestCA(t *testing.T) *CA {
	t.Helper()
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	return ca
}

func requestCert(t *testing.T, ca *CA, host string) *tls.Certificate {
	t.Helper()
	cert, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
	if err != nil {
		t.Fatalf("GetCertificate(%q): %v", host, err)
	}
	return cert
}

func TestAStillValidCertificateIsServedFromTheCache(t *testing.T) {
	ca := newTestCA(t)

	first := requestCert(t, ca, "api.github.com")
	if second := requestCert(t, ca, "api.github.com"); second != first {
		t.Error("a certificate with its full lifetime left was reissued instead of reused")
	}
}

func TestAnExpiredCertificateIsReissuedRatherThanServed(t *testing.T) {
	ca := newTestCA(t)

	first := requestCert(t, ca, "api.github.com")
	first.Leaf.NotAfter = time.Now().Add(-time.Minute)

	second := requestCert(t, ca, "api.github.com")
	if second == first {
		t.Fatal("an expired certificate was served from the cache")
	}
	if !second.Leaf.NotAfter.After(time.Now()) {
		t.Errorf("reissued certificate expires at %v, already past", second.Leaf.NotAfter)
	}
}

func TestACertificateIsReissuedBeforeItExpires(t *testing.T) {
	// Reissuing exactly at expiry still spends one failed request to discover
	// it, so the window has to open while the leaf is nominally still good.
	ca := newTestCA(t)

	first := requestCert(t, ca, "api.github.com")
	first.Leaf.NotAfter = time.Now().Add(certRenewBefore / 2)

	if second := requestCert(t, ca, "api.github.com"); second == first {
		t.Error("a certificate inside the renewal window was served instead of reissued")
	}
}

func TestAnIssuedCertificateCarriesItsParsedLeaf(t *testing.T) {
	// The leaf is what the expiry check reads; an issuing path that drops it
	// makes every cached certificate permanently unreusable.
	ca := newTestCA(t)

	cert := requestCert(t, ca, "api.github.com")
	if cert.Leaf == nil {
		t.Fatal("issued certificate has no parsed leaf, so its expiry cannot be consulted")
	}
	if got := cert.Leaf.Subject.CommonName; got != "api.github.com" {
		t.Errorf("leaf common name is %q, want %q", got, "api.github.com")
	}
}

func TestACertificateWithNoParsedLeafIsTreatedAsExpiring(t *testing.T) {
	if !expiringSoon(&tls.Certificate{}, time.Now()) {
		t.Error("a certificate with an unknown expiry was treated as reusable")
	}
}
