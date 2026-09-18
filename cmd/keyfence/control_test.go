// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"runtime"
	"syscall"
	"testing"
)

func TestControlListenAddress(t *testing.T) {
	tests := []struct {
		input   string
		network string
		address string
	}{
		{"127.0.0.1:10212", "tcp", "127.0.0.1:10212"},
		{"unix:/run/user/1000/keyfence/control.sock", "unix", "/run/user/1000/keyfence/control.sock"},
	}
	for _, test := range tests {
		network, address := controlListenAddress(test.input)
		if network != test.network || address != test.address {
			t.Errorf("controlListenAddress(%q) = %q, %q; want %q, %q", test.input, network, address, test.network, test.address)
		}
	}
}

func TestIDAllowlistRejectsNonNumericID(t *testing.T) {
	var ids idAllowlist
	if err := ids.Set("operators"); err == nil {
		t.Fatal("accepted a non-numeric Unix ID")
	}
	if err := ids.Set("1000"); err != nil {
		t.Fatalf("adding numeric Unix ID: %v", err)
	}
	if _, ok := ids[1000]; !ok {
		t.Fatal("numeric Unix ID was not added")
	}
}

func TestUnixControlAPIReadsPeerCredentials(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SO_PEERCRED test requires Linux")
	}

	descriptors, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("creating Unix socket pair: %v", err)
	}
	files := []*os.File{
		os.NewFile(uintptr(descriptors[0]), "peer-0"),
		os.NewFile(uintptr(descriptors[1]), "peer-1"),
	}
	defer files[0].Close()
	defer files[1].Close()
	conn, err := net.FileConn(files[0])
	if err != nil {
		t.Fatalf("opening Unix connection: %v", err)
	}
	defer conn.Close()

	peer, err := socketPeerIdentity(conn)
	if err != nil {
		t.Fatalf("reading peer credentials: %v", err)
	}
	if peer.uid != uint32(os.Getuid()) || peer.gid != uint32(os.Getgid()) {
		t.Fatalf("peer = uid %d gid %d; want uid %d gid %d", peer.uid, peer.gid, os.Getuid(), os.Getgid())
	}
}

func TestUnixControlAPIRejectsUnlistedPeer(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "/tokens", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(request.Context(), peerIdentityContextKey{}, peerIdentityResult{
		peer: peerIdentity{uid: 1000, gid: 1000},
	})
	request = request.WithContext(ctx)
	request.Header.Set("Authorization", "Bearer bearer-key")

	called := false
	handler := requireControlAuth("bearer-key", peerAllowlist{uids: idAllowlist{2000: {}}}, func(http.ResponseWriter, *http.Request) {
		called = true
	})
	responseWriter := &statusRecorder{header: make(http.Header)}
	handler(responseWriter, request)
	if called {
		t.Fatal("called protected handler for unlisted Unix peer")
	}
	if responseWriter.status != http.StatusForbidden {
		t.Fatalf("status = %d; want %d", responseWriter.status, http.StatusForbidden)
	}
}

func TestUnixControlAPIAllowsListedGroup(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "/tokens", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(request.Context(), peerIdentityContextKey{}, peerIdentityResult{
		peer: peerIdentity{uid: 1000, gid: 2000},
	})
	request = request.WithContext(ctx)

	called := false
	handler := requireControlAuth("not-used-on-unix", peerAllowlist{gids: idAllowlist{2000: {}}}, func(http.ResponseWriter, *http.Request) {
		called = true
	})
	responseWriter := &statusRecorder{header: make(http.Header)}
	handler(responseWriter, request)
	if !called {
		t.Fatal("did not call protected handler for listed Unix group")
	}
}

type statusRecorder struct {
	header http.Header
	status int
}

func (r *statusRecorder) Header() http.Header       { return r.header }
func (r *statusRecorder) Write([]byte) (int, error) { return 0, nil }
func (r *statusRecorder) WriteHeader(status int)    { r.status = status }
