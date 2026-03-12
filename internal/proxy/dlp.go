// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@redhat.com>

package proxy

import "regexp"

// DLPScanner scans request bodies for credential patterns.
type DLPScanner struct {
	patterns []dlpPattern
	maxBytes int
}

type dlpPattern struct {
	Name    string
	Pattern *regexp.Regexp
}

// DLPResult is returned when a pattern matches.
type DLPResult struct {
	Matched     bool
	PatternName string
}

// NewDLPScanner creates a scanner with default credential patterns.
func NewDLPScanner(maxBytes int) *DLPScanner {
	return &DLPScanner{
		maxBytes: maxBytes,
		patterns: []dlpPattern{
			{Name: "anthropic_key", Pattern: regexp.MustCompile(`sk-ant-[a-zA-Z0-9\-_]{20,}`)},
			{Name: "openai_key", Pattern: regexp.MustCompile(`sk-proj-[a-zA-Z0-9\-_]{20,}`)},
			{Name: "slack_token", Pattern: regexp.MustCompile(`xoxb-[a-zA-Z0-9\-]+`)},
			{Name: "github_pat", Pattern: regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`)},
		},
	}
}

// Scan checks body for credential patterns. Returns nil if body exceeds maxBytes.
func (d *DLPScanner) Scan(body []byte) *DLPResult {
	if len(body) > d.maxBytes {
		return nil // too large to scan
	}
	for _, p := range d.patterns {
		if p.Pattern.Match(body) {
			return &DLPResult{Matched: true, PatternName: p.Name}
		}
	}
	return &DLPResult{Matched: false}
}
