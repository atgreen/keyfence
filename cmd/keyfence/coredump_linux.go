// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@moxielogic.com>

//go:build linux

package main

import (
	"fmt"
	"syscall"
)

// prctl(2) operations. The stdlib syscall package knows the syscall number but
// offers no wrapper, and golang.org/x/sys would be a direct dependency for two
// integers.
const (
	prSetDumpable = 4
	prGetDumpable = 3
)

// denyCoreDumpsAndTracing marks this process undumpable, which closes two ways
// of reading a credential out of it without ever touching the proxy.
//
// A core dump of KeyFence is every plaintext credential on the machine written
// to disk, where systemd-coredump keeps it for anyone who later runs
// coredumpctl. And a process of the same user needs no privilege at all to
// ptrace a sibling and read its memory directly, which is exactly what a
// compromised agent running beside the broker would try.
//
// Clearing the dumpable flag refuses both: the kernel writes no core, and
// ptrace_may_access(2) denies an attach that is not already privileged. It
// costs the ability to debug a crash, which is the trade this process should
// make.
//
// LimitCORE=0 in the unit file says the same thing for the window before this
// runs and for anything spawned underneath it; neither is a substitute for the
// other, because KeyFence is not always started by systemd.
func denyCoreDumpsAndTracing() error {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0); errno != 0 {
		return fmt.Errorf("clearing the dumpable flag: %w", errno)
	}
	return nil
}
