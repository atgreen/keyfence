// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@redhat.com>

// Package acl provides global allow/deny lists for KeyFence.
//
// The deny list is a hard security boundary — blocked destinations are
// rejected before token resolution, before TLS handshake, before any work.
//
// The allow-without-token list lets specific destinations bypass token
// requirements. Traffic is still logged but has no token attribution.
//
// Domain entries support a leading dot for subdomain matching:
//
//	example.com       — matches example.com only
//	.example.com      — matches example.com and *.example.com
//
// Path entries use the same glob matching as token destinations:
//
//	example.com/api/* — matches example.com with paths under /api/
package acl

import (
	"path"
	"strings"
)

// List is a global allow/deny list evaluated before token resolution.
type List struct {
	deny              []entry // blocked unconditionally
	allowWithoutToken []entry // allowed without a kf_ token
}

type entry struct {
	host        string // hostname (may have leading dot for subdomain match)
	pathPattern string // optional path glob; empty = all paths
}

// New creates an ACL list from deny and allow-without-token entries.
// Each entry is "host" or "host/path" with optional leading dot.
func New(deny, allowWithoutToken []string) *List {
	l := &List{
		deny:              parseEntries(deny),
		allowWithoutToken: parseEntries(allowWithoutToken),
	}
	return l
}

func parseEntries(raw []string) []entry {
	entries := make([]entry, 0, len(raw))
	for _, r := range raw {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		e := entry{}
		if idx := strings.Index(r, "/"); idx != -1 {
			e.host = r[:idx]
			e.pathPattern = r[idx:]
		} else {
			e.host = r
		}
		entries = append(entries, e)
	}
	return entries
}

// IsDenied returns true if the host+path is on the deny list.
func (l *List) IsDenied(host, reqPath string) bool {
	if l == nil {
		return false
	}
	return matchEntries(l.deny, host, reqPath)
}

// IsAllowedWithoutToken returns true if the host+path can bypass token
// requirements. This is a deliberate hole in the containment model —
// use sparingly for public endpoints like package registries.
func (l *List) IsAllowedWithoutToken(host, reqPath string) bool {
	if l == nil {
		return false
	}
	return matchEntries(l.allowWithoutToken, host, reqPath)
}

// IsDeniedHost returns true if the host is on the deny list regardless
// of path. Used for early rejection at CONNECT time before reading the
// inner request.
func (l *List) IsDeniedHost(host string) bool {
	if l == nil {
		return false
	}
	for _, e := range l.deny {
		if e.pathPattern != "" {
			continue // host+path entries can't be evaluated at CONNECT time
		}
		if matchHost(e.host, host) {
			return true
		}
	}
	return false
}

func matchEntries(entries []entry, host, reqPath string) bool {
	for _, e := range entries {
		if !matchHost(e.host, host) {
			continue
		}
		if e.pathPattern == "" {
			return true // host-only entry matches all paths
		}
		if matchPath(e.pathPattern, reqPath) {
			return true
		}
	}
	return false
}

// matchHost checks a host against an entry. Leading dot means subdomain match.
func matchHost(pattern, host string) bool {
	if strings.HasPrefix(pattern, ".") {
		// .example.com matches example.com and *.example.com
		base := pattern[1:]
		return host == base || strings.HasSuffix(host, pattern)
	}
	return host == pattern
}

func matchPath(pattern, reqPath string) bool {
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return reqPath == prefix || strings.HasPrefix(reqPath, prefix+"/")
	}
	matched, _ := path.Match(pattern, reqPath)
	return matched
}
