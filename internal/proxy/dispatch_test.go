// SPDX-License-Identifier: MIT

package proxy

import "testing"

// One byte decides how a connection is served: a client that set HTTPS_PROXY sends
// CONNECT, and one whose destination the kernel rewrote starts talking TLS
// immediately. Getting this wrong would mean either refusing redirected traffic or
// trying to parse a ClientHello as a request.
func TestOneByteTellsTLSFromHTTP(t *testing.T) {
	if !looksLikeTLS(0x16) {
		t.Error("0x16 is the TLS handshake record type")
	}
	// Every HTTP method starts with an upper-case letter, so none of these can be
	// confused with a TLS record.
	for _, first := range []byte{'G', 'P', 'C', 'H', 'D', 'O', 'T', 'g', ' ', '\n', 0x00, 0x17, 0x15} {
		if looksLikeTLS(first) {
			t.Errorf("%q was taken for a TLS record", first)
		}
	}
}
