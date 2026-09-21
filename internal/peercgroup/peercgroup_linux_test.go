// SPDX-License-Identifier: MIT

//go:build linux

package peercgroup

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// ownCgroupID reads this process's cgroup the long way round -- the path from
// /proc/self/cgroup, then the inode of that directory under the mount -- so the
// test has something to compare the netlink answer against that did not come
// from netlink.
func ownCgroupID(t *testing.T) uint64 {
	t.Helper()
	contents, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Skipf("no /proc/self/cgroup: %v", err)
	}
	var relative string
	for _, line := range strings.Split(strings.TrimSpace(string(contents)), "\n") {
		// cgroup v2 is the single "0::<path>" line.
		if after, found := strings.CutPrefix(line, "0::"); found {
			relative = after
		}
	}
	if relative == "" {
		t.Skip("not running under cgroup v2")
	}
	info, err := os.Stat(filepath.Join("/sys/fs/cgroup", relative))
	if err != nil {
		t.Skipf("cannot stat own cgroup: %v", err)
	}
	return info.Sys().(*syscall.Stat_t).Ino
}

func TestTheCallerIsIdentifiedByItsCgroup(t *testing.T) {
	want := ownCgroupID(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer listener.Close()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dialling: %v", err)
	}
	defer client.Close()

	served, err := listener.Accept()
	if err != nil {
		t.Fatalf("accepting: %v", err)
	}
	defer served.Close()

	// From the server's side of the connection, as the proxy sees it.
	got, err := Of(served.LocalAddr(), served.RemoteAddr())
	if err != nil {
		t.Fatalf("Of: %v", err)
	}
	if got != want {
		t.Errorf("peer cgroup id %d, want %d (this process's own, both ends being the same process)", got, want)
	}
}

func TestAConnectionThatIsGoneIsNotAttributedToAnybody(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	local := listener.Addr().(*net.TCPAddr)
	listener.Close()

	// A four-tuple nothing holds. The answer must be an error, never a zero
	// that a caller could mistake for "no restriction".
	remote := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: local.Port ^ 0x3ff}
	if _, err := Of(local, remote); err == nil {
		t.Error("a socket that does not exist was attributed to a cgroup")
	}
}

func TestOnlyLoopbackIsAnswered(t *testing.T) {
	local := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 80}
	remote := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 1234}
	if _, err := Of(local, remote); err == nil {
		t.Error("a peer that is not on this machine was attributed to a cgroup")
	}
}
