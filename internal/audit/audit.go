// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@redhat.com>

// Package audit provides structured JSON audit logging for KeyFence.
//
// Every proxy action (allow, deny) and control plane action (issue, revoke)
// is recorded as a single JSON line. Each entry is tagged with the token ID,
// agent ID, and task ID from the token metadata — all set by the orchestrator,
// never by the agent.
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Event types.
const (
	EventAllow  = "allow"
	EventDeny   = "deny"
	EventIssue  = "issue"
	EventRevoke = "revoke"
)

// Entry is a single audit log record.
type Entry struct {
	Timestamp   string `json:"ts"`
	Event       string `json:"event"`
	TokenID     string `json:"token_id,omitempty"`
	AgentID     string `json:"agent_id,omitempty"`
	TaskID      string `json:"task_id,omitempty"`
	Destination string `json:"destination,omitempty"`
	Method      string `json:"method,omitempty"`
	Path        string `json:"path,omitempty"`
	DenyReason  string `json:"deny_reason,omitempty"`
	DenyRule    string `json:"deny_rule,omitempty"`
	Label       string `json:"label,omitempty"`
	Policy      string `json:"policy,omitempty"`
	TTL         string `json:"ttl,omitempty"`
}

// Logger writes structured JSON audit entries.
type Logger struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// New creates an audit logger that writes JSON lines to w.
func New(w io.Writer) *Logger {
	return &Logger{enc: json.NewEncoder(w)}
}

// Log writes a single audit entry with the current timestamp.
func (l *Logger) Log(e Entry) {
	e.Timestamp = time.Now().UTC().Format(time.RFC3339)
	l.mu.Lock()
	l.enc.Encode(e)
	l.mu.Unlock()
}
