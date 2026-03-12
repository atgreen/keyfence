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
	EventAllow    = "allow"
	EventDeny     = "deny"
	EventIssue    = "issue"
	EventRevoke   = "revoke"
	EventSSHAllow = "ssh_allow"
	EventSSHDeny  = "ssh_deny"
	EventRotate       = "rotate"
	EventResponseRule = "response_rule"
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
	SSHCommand   string `json:"ssh_command,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`
	RuleAction   string `json:"rule_action,omitempty"`
	RuleReason   string `json:"rule_reason,omitempty"`
	Label        string `json:"label,omitempty"`
	Policy      string `json:"policy,omitempty"`
	TTL         string `json:"ttl,omitempty"`
}

// Sink receives audit entries for fan-out (webhooks, SSE, etc.).
type Sink interface {
	Send(Entry)
}

// Logger writes structured JSON audit entries and fans out to sinks.
type Logger struct {
	mu    sync.Mutex
	enc   *json.Encoder
	sinks []Sink
}

// New creates an audit logger that writes JSON lines to w.
func New(w io.Writer) *Logger {
	return &Logger{enc: json.NewEncoder(w)}
}

// AddSink registers a sink to receive all future audit entries.
func (l *Logger) AddSink(s Sink) {
	l.mu.Lock()
	l.sinks = append(l.sinks, s)
	l.mu.Unlock()
}

// Log writes a single audit entry with the current timestamp.
func (l *Logger) Log(e Entry) {
	e.Timestamp = time.Now().UTC().Format(time.RFC3339)
	l.mu.Lock()
	l.enc.Encode(e)
	sinks := append([]Sink(nil), l.sinks...)
	l.mu.Unlock()
	for _, s := range sinks {
		s.Send(e)
	}
}
