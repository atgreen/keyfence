// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@moxielogic.com>

//go:build linux

// Package peercgroup answers which cgroup opened the other end of a loopback
// connection.
//
// A kf_ token is a bearer credential on a loopback port, so any process on the
// machine that obtains one can present it. Destination locking and a TTL bound
// what a stolen token is worth; they do not stop it being used. The answer the
// CB4A draft gives for this is DPoP, which binds a token to a key the client
// proves it holds -- unavailable here, because it is the upstream API that
// would have to check the proof, and the APIs agents call do not.
//
// The local equivalent is available and needs nothing from anybody. The kernel
// records, on every socket, the cgroup of the process that created it, and
// hands it back through sock_diag. A token issued for one cgroup is then
// useless anywhere else on the host, which is the promise it already makes
// about being carried off the host.
//
// Cgroup rather than pid deliberately. Recovering a pid means walking
// /proc/*/fd looking for a socket inode, which is linear in the process table
// and races with a pid that exits and is reused. The cgroup is bound to the
// socket when it is created and cannot change for that socket's life. It is
// also the right unit: an agent spawns subprocesses, and what should be
// authorised is the tree.
package peercgroup

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

// Netlink and sock_diag constants. They are not in the standard syscall
// package, and pulling golang.org/x/sys in as a direct dependency to name a
// dozen integers is a poor trade for a broker that has none.
const (
	sockDiagByFamily = 20 // nlmsghdr.nlmsg_type for an inet_diag request

	inetDiagCgroupID = 21 // attribute carrying the u64 cgroup id

	nlmsgError = 0x2
	nlmsgDone  = 0x3

	nlmsgHeaderLen = 16
	reqV2Len       = 56 // inet_diag_req_v2, sockid included
	sockidLen      = 48
)

// Of answers the cgroup id of the process that opened the far end of an
// established loopback TCP connection.
//
// local and remote are the connection as the local end sees it: pass a served
// connection's LocalAddr and RemoteAddr, and the answer describes whoever
// dialled in. A connection that no longer exists is an error rather than a
// zero, because a caller comparing the answer to a token's requirement must
// never read "gone" as "unrestricted".
func Of(local, remote net.Addr) (uint64, error) {
	localTCP, remoteTCP := local.(*net.TCPAddr), remote.(*net.TCPAddr)
	if localTCP == nil || remoteTCP == nil {
		return 0, fmt.Errorf("peer cgroup: not a TCP connection")
	}
	// Only a peer on this machine has a cgroup this machine can name. Anything
	// else is a question with no answer, and saying so is better than an id
	// that means nothing.
	if !localTCP.IP.IsLoopback() || !remoteTCP.IP.IsLoopback() {
		return 0, fmt.Errorf("peer cgroup: %s is not on this machine", remoteTCP.IP)
	}
	localIP, remoteIP := localTCP.IP.To4(), remoteTCP.IP.To4()
	if localIP == nil || remoteIP == nil {
		return 0, fmt.Errorf("peer cgroup: only IPv4 loopback is answered")
	}

	socket, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_INET_DIAG)
	if err != nil {
		return 0, fmt.Errorf("peer cgroup: opening netlink: %w", err)
	}
	defer syscall.Close(socket)

	// The query is for the peer's socket, so its source is the remote end of
	// the connection we were handed and its destination is ours.
	request := inetDiagRequest(remoteTCP.Port, localTCP.Port, remoteIP, localIP)
	if err := syscall.Sendto(socket, request, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return 0, fmt.Errorf("peer cgroup: asking netlink: %w", err)
	}

	reply := make([]byte, 8192)
	n, _, err := syscall.Recvfrom(socket, reply, 0)
	if err != nil {
		return 0, fmt.Errorf("peer cgroup: reading netlink: %w", err)
	}
	return cgroupIDFromReply(reply[:n])
}

// inetDiagRequest builds the nlmsghdr and inet_diag_req_v2 that ask about one
// specific established TCP socket.
func inetDiagRequest(sourcePort, destinationPort int, source, destination net.IP) []byte {
	request := make([]byte, nlmsgHeaderLen+reqV2Len)

	binary.NativeEndian.PutUint32(request[0:], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:], sockDiagByFamily)
	binary.NativeEndian.PutUint16(request[6:], syscall.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(request[8:], 1) // sequence
	binary.NativeEndian.PutUint32(request[12:], 0)

	body := request[nlmsgHeaderLen:]
	body[0] = syscall.AF_INET
	body[1] = syscall.IPPROTO_TCP
	body[2] = 0xff // every extension, the cgroup id among them
	body[3] = 0
	// Established only. A socket in any other state is not one carrying a
	// request we are about to serve.
	binary.NativeEndian.PutUint32(body[4:], 1<<1)

	id := body[8 : 8+sockidLen]
	binary.BigEndian.PutUint16(id[0:], uint16(sourcePort))
	binary.BigEndian.PutUint16(id[2:], uint16(destinationPort))
	copy(id[4:8], source)
	copy(id[20:24], destination)
	binary.NativeEndian.PutUint32(id[36:], 0)          // interface
	binary.NativeEndian.PutUint32(id[40:], 0xffffffff) // cookie: unknown
	binary.NativeEndian.PutUint32(id[44:], 0xffffffff)
	return request
}

// cgroupIDFromReply walks the netlink messages for the cgroup attribute.
func cgroupIDFromReply(reply []byte) (uint64, error) {
	for len(reply) >= nlmsgHeaderLen {
		length := int(binary.NativeEndian.Uint32(reply[0:]))
		kind := binary.NativeEndian.Uint16(reply[4:])
		if length < nlmsgHeaderLen || length > len(reply) {
			return 0, fmt.Errorf("peer cgroup: malformed netlink message")
		}
		switch kind {
		case nlmsgDone:
			return 0, fmt.Errorf("peer cgroup: no such connection")
		case nlmsgError:
			if length >= nlmsgHeaderLen+4 {
				if code := int32(binary.NativeEndian.Uint32(reply[nlmsgHeaderLen:])); code != 0 {
					return 0, fmt.Errorf("peer cgroup: netlink refused the query: %w", syscall.Errno(-code))
				}
			}
			return 0, fmt.Errorf("peer cgroup: no such connection")
		case sockDiagByFamily:
			if id, found := cgroupAttribute(reply[nlmsgHeaderLen:length]); found {
				return id, nil
			}
			return 0, fmt.Errorf("peer cgroup: this kernel did not report a cgroup for the connection")
		}
		reply = reply[nlmsgAlign(length):]
	}
	return 0, fmt.Errorf("peer cgroup: no such connection")
}

// cgroupAttribute finds INET_DIAG_CGROUP_ID among the attributes trailing an
// inet_diag_msg.
func cgroupAttribute(message []byte) (uint64, bool) {
	const inetDiagMsgLen = 72 // struct inet_diag_msg, before its attributes
	if len(message) < inetDiagMsgLen {
		return 0, false
	}
	attributes := message[inetDiagMsgLen:]
	for len(attributes) >= 4 {
		length := int(binary.NativeEndian.Uint16(attributes[0:]))
		kind := binary.NativeEndian.Uint16(attributes[2:])
		if length < 4 || length > len(attributes) {
			return 0, false
		}
		if kind == inetDiagCgroupID && length >= 12 {
			return binary.NativeEndian.Uint64(attributes[4:]), true
		}
		attributes = attributes[nlmsgAlign(length):]
	}
	return 0, false
}

func nlmsgAlign(length int) int {
	return (length + syscall.NLMSG_ALIGNTO - 1) &^ (syscall.NLMSG_ALIGNTO - 1)
}
