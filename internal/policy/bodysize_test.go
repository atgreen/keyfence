// SPDX-License-Identifier: MIT

package policy

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// A body limit that only applies to requests which declare their size is not a
// limit; it is a suggestion that well-behaved clients happen to honour.

func chunkedRequest(body string) *http.Request {
	req, _ := http.NewRequest("POST", "https://api.example.com/v1/messages",
		io.NopCloser(strings.NewReader(body)))
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	return req
}

func TestAChunkedBodyOverTheLimitIsDenied(t *testing.T) {
	p := &Policy{MaxBodyBytes: 16}

	deny := p.checkBodySize(chunkedRequest(strings.Repeat("x", 64)))
	if deny == nil {
		t.Fatal("a chunked request over the limit was allowed; the limit applied only to requests that declared their size")
	}
	if deny.Rule != "max_body_bytes" {
		t.Errorf("denied under %q, want max_body_bytes", deny.Rule)
	}
}

func TestAChunkedBodyWithinTheLimitIsForwardedIntact(t *testing.T) {
	p := &Policy{MaxBodyBytes: 1024}
	req := chunkedRequest("hello upstream")

	if deny := p.checkBodySize(req); deny != nil {
		t.Fatalf("a body inside the limit was denied: %s", deny.Message)
	}

	// Read to the end of it: what the upstream gets must be what the client sent.
	forwarded, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading the forwarded body: %v", err)
	}
	if string(forwarded) != "hello upstream" {
		t.Errorf("the body changed on the way through: %q", forwarded)
	}
	if req.ContentLength != int64(len("hello upstream")) {
		t.Errorf("ContentLength is %d, want %d", req.ContentLength, len("hello upstream"))
	}
	if req.TransferEncoding != nil {
		t.Errorf("still chunked after buffering: %v", req.TransferEncoding)
	}
}

func TestADeclaredLengthOverTheLimitIsStillDenied(t *testing.T) {
	p := &Policy{MaxBodyBytes: 16}
	req, _ := http.NewRequest("POST", "https://api.example.com/", strings.NewReader(strings.Repeat("x", 64)))

	if deny := p.checkBodySize(req); deny == nil {
		t.Error("a declared body over the limit was allowed")
	}
}

func TestNoLimitMeansNoBuffering(t *testing.T) {
	// With no limit set there is nothing to enforce, and a proxy that buffered
	// anyway would be holding whole request bodies for no reason.
	p := &Policy{}
	req := chunkedRequest("streamed")

	if deny := p.checkBodySize(req); deny != nil {
		t.Fatalf("denied with no limit set: %s", deny.Message)
	}
	if req.ContentLength != -1 {
		t.Errorf("the request was buffered despite no limit: ContentLength %d", req.ContentLength)
	}
}
