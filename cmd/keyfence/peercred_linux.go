// SPDX-License-Identifier: MIT

//go:build linux

package main

import (
	"fmt"
	"net"
	"syscall"
)

func socketPeerIdentity(conn net.Conn) (peerIdentity, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return peerIdentity{}, fmt.Errorf("connection is not a unix socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return peerIdentity{}, fmt.Errorf("accessing unix socket: %w", err)
	}

	var credentials *syscall.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, socketErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return peerIdentity{}, fmt.Errorf("accessing unix socket descriptor: %w", err)
	}
	if socketErr != nil {
		return peerIdentity{}, fmt.Errorf("reading unix peer credentials: %w", socketErr)
	}
	return peerIdentity{pid: credentials.Pid, uid: credentials.Uid, gid: credentials.Gid}, nil
}
