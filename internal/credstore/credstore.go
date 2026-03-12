// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@redhat.com>

// Package credstore defines the credential backend interface and implementations.
//
// KeyFence never stores raw credentials in the token store. Instead, tokens
// reference a credential ID, and the backend fetches the real value on each
// request. This keeps raw secrets out of the agent-facing data path.
package credstore

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// Backend fetches real credential values by ID.
type Backend interface {
	// Store saves a credential and returns its ID.
	Store(value string) (id string, err error)

	// Fetch returns the real credential value for a given ID.
	Fetch(id string) (string, error)
}

// EnvBackend stores credentials in-memory, keyed by auto-generated IDs.
// The name "env" reflects that in container deployments, the orchestrator
// typically passes real credentials via KeyFence's environment variables
// or the token issuance API — they're held in KeyFence's process memory,
// never in the agent's.
type EnvBackend struct {
	mu    sync.RWMutex
	creds map[string]string // id → credential value
	seq   int
}

func NewEnvBackend() *EnvBackend {
	return &EnvBackend{
		creds: make(map[string]string),
	}
}

func (e *EnvBackend) Store(value string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.seq++
	id := fmt.Sprintf("cred_%d", e.seq)
	e.creds[id] = value
	return id, nil
}

func (e *EnvBackend) Fetch(id string) (string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	val, ok := e.creds[id]
	if !ok {
		return "", fmt.Errorf("credential %q not found", id)
	}
	return val, nil
}

// EnvMappedBackend reads credentials from environment variables.
// Credential IDs are environment variable names.
type EnvMappedBackend struct{}

func NewEnvMappedBackend() *EnvMappedBackend {
	return &EnvMappedBackend{}
}

func (e *EnvMappedBackend) Store(value string) (string, error) {
	return "", fmt.Errorf("env-mapped backend does not support storing credentials; set them as environment variables on the KeyFence process")
}

func (e *EnvMappedBackend) Fetch(id string) (string, error) {
	if !strings.HasPrefix(id, "KEYFENCE_CREDENTIAL_") {
		id = "KEYFENCE_CREDENTIAL_" + id
	}
	val := os.Getenv(id)
	if val == "" {
		return "", fmt.Errorf("environment variable %q not set", id)
	}
	return val, nil
}
