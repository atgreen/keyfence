// SPDX-License-Identifier: MIT

//go:build linux

package main

import (
	"os"
	"syscall"
	"testing"
)

// procSelfOwner is the kernel's own account of whether this process may be
// read by another: it roots the /proc entries of a process it will not let be
// dumped or traced.
func procSelfOwner(t *testing.T) uint32 {
	t.Helper()
	info, err := os.Stat("/proc/self/status")
	if err != nil {
		t.Fatalf("reading /proc/self/status: %v", err)
	}
	return info.Sys().(*syscall.Stat_t).Uid
}

func TestDenyCoreDumpsAndTracingMakesProcessUndumpable(t *testing.T) {
	previous, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prGetDumpable, 0, 0)
	if errno != 0 {
		t.Fatalf("reading the dumpable flag: %v", errno)
	}
	t.Cleanup(func() {
		syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, previous, 0)
	})
	if previous != 1 {
		t.Fatalf("expected a dumpable test process to begin with, got %d", previous)
	}
	ownedBeforeByUs := procSelfOwner(t) == uint32(os.Geteuid())

	if err := denyCoreDumpsAndTracing(); err != nil {
		t.Fatalf("denyCoreDumpsAndTracing: %v", err)
	}

	dumpable, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prGetDumpable, 0, 0)
	if errno != 0 {
		t.Fatalf("re-reading the dumpable flag: %v", errno)
	}
	if dumpable != 0 {
		t.Errorf("dumpable flag is %d, want 0", dumpable)
	}

	// Corroborate the flag against something the kernel does rather than
	// something it merely remembers -- but only where the handover to root was
	// observable in the first place.
	if ownedBeforeByUs {
		if owner := procSelfOwner(t); owner != 0 {
			t.Errorf("/proc/self/status still owned by uid %d, want root", owner)
		}
	}
}
