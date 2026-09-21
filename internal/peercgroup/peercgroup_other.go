// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@moxielogic.com>

//go:build !linux

package peercgroup

import (
	"fmt"
	"net"
)

// Of has no answer on a platform without cgroups. It reports that rather than
// returning a zero, so a caller comparing against a token's requirement refuses
// the request instead of waving it through.
func Of(net.Addr, net.Addr) (uint64, error) {
	return 0, fmt.Errorf("peer cgroup: not supported on this platform")
}
