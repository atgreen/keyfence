// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@redhat.com>

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
	"sync"
	"time"
)

type Token struct {
	ID                  string
	Value               string   // kf_<random>
	CredentialID        string   // reference into credential backend
	AllowedDestinations []string // hosts this token can be used against
	PolicyName          string   // optional policy to evaluate on each request
	AgentID             string   // orchestrator-assigned agent identity
	TaskID              string   // orchestrator-assigned task scope
	CreatedAt           time.Time
	ExpiresAt           time.Time
	Label               string // optional human-readable label
	RenewalSeq          int
	Revoked             bool
}

func (t *Token) IsValid() bool {
	if t.Revoked {
		return false
	}
	return time.Now().Before(t.ExpiresAt)
}

func (t *Token) IsDestinationAllowed(host string) bool {
	if len(t.AllowedDestinations) == 0 {
		return true // no restrictions
	}
	for _, d := range t.AllowedDestinations {
		if d == host {
			return true
		}
	}
	return false
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

func (s *Store) Issue(credentialID string, allowedDestinations []string, ttl time.Duration, label string, policyName string, agentID string, taskID string) (*Token, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return nil, fmt.Errorf("generating random bytes: %w", err)
	}

	value := "kf_" + hex.EncodeToString(random)
	now := time.Now()

	token := &Token{
		ID:                  hex.EncodeToString(random[:8]),
		Value:               value,
		CredentialID:        credentialID,
		AllowedDestinations: allowedDestinations,
		PolicyName:          policyName,
		AgentID:             agentID,
		TaskID:              taskID,
		CreatedAt:           now,
		ExpiresAt:           now.Add(ttl),
		Label:               label,
	}

	s.mu.Lock()
	s.tokens[value] = token
	s.mu.Unlock()

	return token, nil
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

// Cleanup removes expired and revoked tokens.
func (s *Store) Cleanup() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for k, t := range s.tokens {
		if t.Revoked || time.Now().After(t.ExpiresAt) {
			delete(s.tokens, k)
			removed++
		}
	}
	return removed
}
