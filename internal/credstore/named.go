// SPDX-License-Identifier: MIT

package credstore

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// NamedStore resolves credentials the operator registered under names, rather
// than ones a client handed over when it asked for a token.
//
// This is the difference between "KeyFence holds the secret" and "KeyFence was
// given the secret by something that held it first". A client that mints a token
// against a name never possesses the credential at all: it says "anthropic", and
// the bytes behind that never leave this process. It also means a revoked token
// leaves nothing behind, because nothing was copied in to begin with.
//
// Three places are searched, in this order:
//
//  1. $CREDENTIALS_DIRECTORY/<name> — systemd's credential store, which is what
//     LoadCredential= and SetCredential= populate. Readable only by the service.
//  2. <credentials-dir>/<name> — a directory the operator names.
//  3. KEYFENCE_CREDENTIAL_<NAME> in the environment, upper-cased, which is the
//     convention the env-mapped backend already used.
//
// Resolution happens per request rather than at startup, so rotating a credential
// is a matter of replacing a file: the next request uses the new value and no
// token has to be reissued.
type NamedStore struct {
	mu             sync.RWMutex
	directories    []string
	environ        func(string) string
	rejectedReason map[string]string // name → why it cannot be used, for clear errors
}

// NewNamedStore answers a store searching systemd's credential directory and, if
// given, one more directory.
func NewNamedStore(credentialsDir string) *NamedStore {
	var directories []string
	if systemd := os.Getenv("CREDENTIALS_DIRECTORY"); systemd != "" {
		directories = append(directories, systemd)
	}
	if credentialsDir != "" {
		directories = append(directories, credentialsDir)
	}
	return &NamedStore{
		directories:    directories,
		environ:        os.Getenv,
		rejectedReason: map[string]string{},
	}
}

// Directories answers where this store looks, for diagnostics.
func (n *NamedStore) Directories() []string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return append([]string(nil), n.directories...)
}

// validName rejects anything that could name a file outside the directories the
// operator chose. A credential reference arrives over the control API, and
// "../../etc/shadow" is a path, not a name.
func validName(name string) error {
	if name == "" {
		return fmt.Errorf("a credential name cannot be empty")
	}
	if len(name) > 128 {
		return fmt.Errorf("credential name is longer than 128 characters")
	}
	if name != filepath.Base(name) || name == "." || name == ".." {
		return fmt.Errorf("credential name %q is a path, not a name", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("credential name %q may only contain letters, digits, dash, underscore and dot", name)
		}
	}
	return nil
}

// Resolve answers the credential registered under name.
func (n *NamedStore) Resolve(name string) (string, error) {
	if err := validName(name); err != nil {
		return "", err
	}

	for _, dir := range n.Directories() {
		contents, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		// A trailing newline is what an editor or a shell redirect leaves behind,
		// and is not part of anybody's API key.
		value := strings.TrimRight(string(contents), "\r\n")
		if value == "" {
			return "", fmt.Errorf("credential %q in %s is empty", name, dir)
		}
		return value, nil
	}

	variable := "KEYFENCE_CREDENTIAL_" + strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(name))
	if value := n.environ(variable); value != "" {
		return value, nil
	}

	return "", fmt.Errorf("no credential named %q: looked in %s and for %s",
		name, n.describeDirectories(), variable)
}

// Has answers whether a name resolves, without handing back what it resolves to.
func (n *NamedStore) Has(name string) bool {
	_, err := n.Resolve(name)
	return err == nil
}

// Names answers the credential names this store can see, for an operator asking
// what is registered. It never answers with a value.
func (n *NamedStore) Names() []string {
	seen := map[string]struct{}{}
	for _, dir := range n.Directories() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if validName(entry.Name()) == nil {
				seen[entry.Name()] = struct{}{}
			}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (n *NamedStore) describeDirectories() string {
	directories := n.Directories()
	if len(directories) == 0 {
		return "no credential directories (pass -credentials-dir, or use systemd LoadCredential=)"
	}
	return strings.Join(directories, ", ")
}
