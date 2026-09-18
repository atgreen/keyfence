// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@moxielogic.com>

// Package tokenstore manages KeyFence tokens and their mappings to credentials.
//
// Tokens do not hold raw credential values. They hold a CredentialID that
// references a credential in the credential backend. The proxy fetches the
// real value from the backend at request time.
package tokenstore

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"
)

type Token struct {
	ID                  string
	Value               string                 // kf_<random>
	CredentialID        string                 // reference into credential backend
	CredentialRef       string                 // name of an operator-registered credential
	AllowedDestinations []string               // hosts or host/path patterns this token can be used against
	PolicyName          string                 // optional policy to evaluate on each request
	AgentID             string                 // orchestrator-assigned agent identity
	TaskID              string                 // orchestrator-assigned task scope
	RateLimit           int                    // max requests per window; 0 = unlimited
	RateWindow          time.Duration          // window duration
	ClientCertID        string                 // reference to cert+key in cert store
	ClientCertHeader    string                 // header to inject cert PEM into (optional)
	SSHKeyID            string                 // reference to SSH key in SSH key store
	ResponseRules       []ResponseRule         // Lua scripts evaluated against each response
	RuleState           map[string]interface{} // mutable state persisted across requests
	RuleStateMu         sync.Mutex             // protects RuleState
	CreatedAt           time.Time
	ExpiresAt           time.Time
	Label               string // optional human-readable label
	RenewalSeq          int
	Revoked             bool

	// rate tracking (internal)
	rateCount int
	rateStart time.Time
}

func (t *Token) IsValid() bool {
	if t.Revoked {
		return false
	}
	return time.Now().Before(t.ExpiresAt)
}

// AnyDestination is the destination entry that means "anywhere". A token
// carrying it is a second copy of the credential it stands for, usable against
// any host the proxy can reach, so it has to be asked for by name: an empty
// destination list is not a way to spell it.
const AnyDestination = "*"

// AllowsAnyDestination answers whether this token was deliberately issued
// without a destination lock.
func (t *Token) AllowsAnyDestination() bool {
	for _, d := range t.AllowedDestinations {
		if d == AnyDestination {
			return true
		}
	}
	return false
}

// IsDestinationAllowed checks whether a request to host+path is permitted.
// Destination entries can be:
//   - "api.example.com"          — host only (matches all paths)
//   - "api.example.com/v1/chat"  — host + exact path
//   - "api.example.com/v1/*"     — host + path glob
//   - "*"                        — anywhere, which must be asked for explicitly
//
// A token with no destinations at all permits nothing. The point of a token is
// that it is worth less than the credential behind it, and a token that works
// everywhere is worth exactly as much -- so if it is going to be that, someone
// has to have said so.
func (t *Token) IsDestinationAllowed(host, reqPath string) bool {
	if len(t.AllowedDestinations) == 0 {
		return false
	}
	for _, d := range t.AllowedDestinations {
		if d == AnyDestination {
			return true
		}
		dHost, dPath := splitDestination(d)
		if dHost != host {
			continue
		}
		if dPath == "" {
			return true // host-only entry matches all paths
		}
		if matchPath(dPath, reqPath) {
			return true
		}
	}
	return false
}

func splitDestination(entry string) (host, pathPattern string) {
	idx := strings.Index(entry, "/")
	if idx == -1 {
		return entry, ""
	}
	return entry[:idx], entry[idx:]
}

func matchPath(pattern, reqPath string) bool {
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return reqPath == prefix || strings.HasPrefix(reqPath, prefix+"/")
	}
	matched, _ := path.Match(pattern, reqPath)
	return matched
}

// ResponseRule is a Lua script evaluated against JSON responses.
type ResponseRule struct {
	Script string `json:"script"`
}

type Store struct {
	mu     sync.RWMutex
	tokens map[string]*Token // keyed by token value (kf_...)
}

func New() *Store {
	return &Store{
		tokens: make(map[string]*Token),
	}
}

// IssueParams holds all parameters for token issuance.
type IssueParams struct {
	CredentialID        string
	CredentialRef       string
	AllowedDestinations []string
	TTL                 time.Duration
	Label               string
	PolicyName          string
	AgentID             string
	TaskID              string
	RateLimit           int
	RateWindow          time.Duration
	ClientCertID        string
	ClientCertHeader    string
	SSHKeyID            string
	ResponseRules       []ResponseRule
}

func (s *Store) Issue(p IssueParams) (*Token, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return nil, fmt.Errorf("generating random bytes: %w", err)
	}

	value := "kf_" + hex.EncodeToString(random)
	now := time.Now()

	token := &Token{
		ID:                  hex.EncodeToString(random[:8]),
		Value:               value,
		CredentialID:        p.CredentialID,
		CredentialRef:       p.CredentialRef,
		AllowedDestinations: p.AllowedDestinations,
		PolicyName:          p.PolicyName,
		AgentID:             p.AgentID,
		TaskID:              p.TaskID,
		RateLimit:           p.RateLimit,
		RateWindow:          p.RateWindow,
		ClientCertID:        p.ClientCertID,
		ClientCertHeader:    p.ClientCertHeader,
		SSHKeyID:            p.SSHKeyID,
		ResponseRules:       p.ResponseRules,
		RuleState:           make(map[string]interface{}),
		CreatedAt:           now,
		ExpiresAt:           now.Add(p.TTL),
		Label:               p.Label,
	}

	s.mu.Lock()
	s.tokens[value] = token
	s.mu.Unlock()

	return token, nil
}

// Lookup answers the token record whether or not it is still usable, which is
// what a caller cleaning up after a token needs: Resolve deliberately answers
// nothing for a token that has expired or been revoked.
func (s *Store) Lookup(tokenValue string) *Token {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tokens[tokenValue]
}

func (s *Store) Resolve(tokenValue string) *Token {
	s.mu.RLock()
	defer s.mu.RUnlock()

	t, ok := s.tokens[tokenValue]
	if !ok {
		return nil
	}
	if !t.IsValid() {
		return nil
	}
	return t
}

func (s *Store) Revoke(tokenValue string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.tokens[tokenValue]
	if !ok {
		return false
	}
	t.Revoked = true
	return true
}

// RevokeByTaskID revokes all tokens for a given task. Returns the count revoked.
func (s *Store) RevokeByTaskID(taskID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for _, t := range s.tokens {
		if t.TaskID == taskID && !t.Revoked {
			t.Revoked = true
			count++
		}
	}
	return count
}

func (s *Store) List() []*Token {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Token, 0, len(s.tokens))
	for _, t := range s.tokens {
		result = append(result, t)
	}
	return result
}

// CountByCredentialID returns the number of valid tokens referencing a credential.
func (s *Store) CountByCredentialID(credID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, t := range s.tokens {
		if t.IsValid() && t.CredentialID == credID {
			count++
		}
	}
	return count
}

// CheckRate evaluates the token's per-token rate limit.
// Returns true if the request is allowed, false if rate-limited.
// A token with RateLimit <= 0 always allows.
func (s *Store) CheckRate(tokenValue string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.tokens[tokenValue]
	if !ok {
		return false
	}
	if t.RateLimit <= 0 {
		return true
	}

	now := time.Now()
	if t.rateStart.IsZero() || now.Sub(t.rateStart) >= t.RateWindow {
		t.rateCount = 1
		t.rateStart = now
		return true
	}

	t.rateCount++
	return t.rateCount <= t.RateLimit
}

// Cleanup removes expired and revoked tokens and answers what it removed, so
// that a caller can forget the credentials they were the last reason to keep.
func (s *Store) Cleanup() []*Token {
	s.mu.Lock()
	defer s.mu.Unlock()

	var removed []*Token
	for k, t := range s.tokens {
		if t.Revoked || time.Now().After(t.ExpiresAt) {
			delete(s.tokens, k)
			removed = append(removed, t)
		}
	}
	return removed
}

// CountByClientCertID returns the number of valid tokens using a client cert.
func (s *Store) CountByClientCertID(certID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, t := range s.tokens {
		if t.IsValid() && t.ClientCertID == certID {
			count++
		}
	}
	return count
}

// CountBySSHKeyID returns the number of valid tokens using an SSH key.
func (s *Store) CountBySSHKeyID(keyID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, t := range s.tokens {
		if t.IsValid() && t.SSHKeyID == keyID {
			count++
		}
	}
	return count
}
