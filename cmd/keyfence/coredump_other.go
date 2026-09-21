// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@moxielogic.com>

//go:build !linux

package main

// denyCoreDumpsAndTracing has nothing to clear on a platform with no dumpable
// flag. Core dumps are then the host's business to limit; see the note on the
// Linux implementation for what is at stake.
func denyCoreDumpsAndTracing() error { return nil }
