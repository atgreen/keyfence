// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// idAllowlist is a repeatable flag containing numeric Unix user or group IDs.
// Keeping the command-line contract numeric makes startup deterministic: name
// service availability cannot decide whether the credential broker starts.
type idAllowlist map[uint32]struct{}

func (a *idAllowlist) Set(value string) error {
	id, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return fmt.Errorf("%q is not a numeric Unix ID", value)
	}
	if *a == nil {
		*a = make(idAllowlist)
	}
	(*a)[uint32(id)] = struct{}{}
	return nil
}

func (a *idAllowlist) String() string {
	if a == nil || len(*a) == 0 {
		return ""
	}
	ids := make([]string, 0, len(*a))
	for id := range *a {
		ids = append(ids, strconv.FormatUint(uint64(id), 10))
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

type peerAllowlist struct {
	uids idAllowlist
	gids idAllowlist
}

func (a peerAllowlist) empty() bool {
	return len(a.uids) == 0 && len(a.gids) == 0
}

func (a peerAllowlist) allows(peer peerIdentity) bool {
	_, uidAllowed := a.uids[peer.uid]
	_, gidAllowed := a.gids[peer.gid]
	return uidAllowed || gidAllowed
}

type peerIdentity struct {
	pid int32
	uid uint32
	gid uint32
}

type peerIdentityResult struct {
	peer peerIdentity
	err  error
}

type peerIdentityContextKey struct{}

// controlConnContext records the kernel-authenticated identity for Unix peers.
// TCP connections deliberately carry no result and continue through bearer-key
// authentication instead.
func controlConnContext(ctx context.Context, conn net.Conn) context.Context {
	if _, ok := conn.(*net.UnixConn); !ok {
		return ctx
	}
	peer, err := socketPeerIdentity(conn)
	return context.WithValue(ctx, peerIdentityContextKey{}, peerIdentityResult{peer: peer, err: err})
}

// requireControlAuth selects authentication from the transport. Unix sockets
// are authorized only by their kernel-reported peer; a bearer token cannot
// rescue a disallowed peer. TCP retains the existing bearer-key behavior.
func requireControlAuth(key string, peers peerAllowlist, next http.HandlerFunc) http.HandlerFunc {
	requireTCPKey := requireAPIKey(key, next)
	return func(w http.ResponseWriter, r *http.Request) {
		if result, ok := r.Context().Value(peerIdentityContextKey{}).(peerIdentityResult); ok {
			if result.err != nil {
				http.Error(w, `{"error":"unauthorized: cannot identify unix peer"}`, http.StatusUnauthorized)
				return
			}
			if !peers.allows(result.peer) {
				http.Error(w, `{"error":"forbidden: unix peer is not allowed"}`, http.StatusForbidden)
				return
			}
			next(w, r)
			return
		}

		requireTCPKey(w, r)
	}
}

func controlListenAddress(addr string) (network, address string) {
	if strings.HasPrefix(addr, "unix:") {
		return "unix", strings.TrimPrefix(addr, "unix:")
	}
	return "tcp", addr
}

func listenerIsUnix(listener net.Listener, configuredAddress string) bool {
	if listener != nil {
		return listener.Addr().Network() == "unix" || listener.Addr().Network() == "unixpacket"
	}
	network, _ := controlListenAddress(configuredAddress)
	return network == "unix"
}
