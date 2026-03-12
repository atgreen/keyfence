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

	// Update replaces the value of an existing credential. All tokens
	// referencing this ID will use the new value on their next request.
	Update(id, newValue string) error
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

func (e *EnvBackend) Update(id, newValue string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.creds[id]; !ok {
		return fmt.Errorf("credential %q not found", id)
	}
	e.creds[id] = newValue
	return nil
}

// ClientCert holds a PEM-encoded client certificate and private key.
type ClientCert struct {
	CertPEM string
	KeyPEM  string
}

// CertStore stores client certificate/key pairs in memory.
type CertStore struct {
	mu    sync.RWMutex
	certs map[string]*ClientCert
	seq   int
}

func NewCertStore() *CertStore {
	return &CertStore{
		certs: make(map[string]*ClientCert),
	}
}

func (c *CertStore) Store(certPEM, keyPEM string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.seq++
	id := fmt.Sprintf("cert_%d", c.seq)
	c.certs[id] = &ClientCert{CertPEM: certPEM, KeyPEM: keyPEM}
	return id, nil
}

func (c *CertStore) Fetch(id string) (*ClientCert, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cert, ok := c.certs[id]
	if !ok {
		return nil, fmt.Errorf("client cert %q not found", id)
	}
	return cert, nil
}

func (c *CertStore) Update(id, certPEM, keyPEM string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.certs[id]; !ok {
		return fmt.Errorf("client cert %q not found", id)
	}
	c.certs[id] = &ClientCert{CertPEM: certPEM, KeyPEM: keyPEM}
	return nil
}

// SSHKey holds an SSH private key and the username to connect as.
type SSHKey struct {
	PrivateKeyPEM string
	Username      string // e.g. "git"
}

// SSHKeyStore stores SSH private keys in memory.
type SSHKeyStore struct {
	mu   sync.RWMutex
	keys map[string]*SSHKey
	seq  int
}

func NewSSHKeyStore() *SSHKeyStore {
	return &SSHKeyStore{
		keys: make(map[string]*SSHKey),
	}
}

func (s *SSHKeyStore) Store(privateKeyPEM, username string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.seq++
	id := fmt.Sprintf("sshkey_%d", s.seq)
	s.keys[id] = &SSHKey{PrivateKeyPEM: privateKeyPEM, Username: username}
	return id, nil
}

func (s *SSHKeyStore) Fetch(id string) (*SSHKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, ok := s.keys[id]
	if !ok {
		return nil, fmt.Errorf("ssh key %q not found", id)
	}
	return key, nil
}

func (s *SSHKeyStore) Update(id, privateKeyPEM, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.keys[id]; !ok {
		return fmt.Errorf("ssh key %q not found", id)
	}
	s.keys[id] = &SSHKey{PrivateKeyPEM: privateKeyPEM, Username: username}
	return nil
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

func (e *EnvMappedBackend) Update(id, newValue string) error {
	return fmt.Errorf("env-mapped backend does not support credential rotation")
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
