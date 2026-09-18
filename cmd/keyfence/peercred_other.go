// SPDX-License-Identifier: MIT

//go:build !linux

package main

import (
	"fmt"
	"net"
)

func socketPeerIdentity(net.Conn) (peerIdentity, error) {
	return peerIdentity{}, fmt.Errorf("unix peer credentials are not supported on this platform")
}
