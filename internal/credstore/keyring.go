// SPDX-License-Identifier: MIT

package credstore

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// Keyring resolves credentials from the OS keyring rather than from a file.
//
// The reason to prefer it is narrow and real: a credential in a file is
// plaintext on disk. Mode 0600 keeps other users out, and does nothing about a
// backup, a snapshot, a stolen disk, or anyone who later reads the filesystem
// while nobody is logged in. The keyring keeps it encrypted until the session
// unlocks it.
//
// What it does not give is isolation. The Secret Service API answers any process
// running as this user, so a keyring entry is no harder for a same-uid process to
// read than a 0600 file is -- and neither is reachable from a sandbox, which has
// no D-Bus and no grant for the path. Encryption at rest is the whole of the
// benefit, and it is worth having on its own.
//
// Lookups go through secret-tool, which is libsecret's own client, rather than by
// speaking D-Bus here. That keeps a D-Bus stack out of the process holding the
// credentials, and means this works with whatever Secret Service implementation
// the desktop provides.
type Keyring struct {
	// lookup runs the query. Replaced in tests.
	lookup func(ctx context.Context, name string) (string, error)

	// list enumerates what is stored under KeyFence's attributes.
	list func(ctx context.Context) (string, error)

	ttl time.Duration

	mu     sync.Mutex
	cached map[string]cachedSecret
}

type cachedSecret struct {
	value string
	at    time.Time
}

// DefaultKeyringTTL is how long a looked-up secret is reused before asking the
// keyring again.
//
// Credentials are resolved per request so that rotation needs no restart, and a
// subprocess per request would be a poor trade for that. A minute keeps the cost
// invisible while bounding how long a rotated secret takes to take effect.
const DefaultKeyringTTL = time.Minute

// NewKeyring answers a keyring-backed store, or nil if secret-tool is not
// installed -- in which case nothing has been asked for that cannot be done, and
// the caller falls back to the other sources.
func NewKeyring(ttl time.Duration) *Keyring {
	path, err := exec.LookPath("secret-tool")
	if err != nil {
		return nil
	}
	if ttl <= 0 {
		ttl = DefaultKeyringTTL
	}
	return &Keyring{
		ttl:    ttl,
		cached: map[string]cachedSecret{},
		lookup: func(ctx context.Context, name string) (string, error) {
			// The attributes KeyFence stores under, which is also how an operator
			// puts one there:
			//
			//   secret-tool store --label="keyfence: github" \
			//       service keyfence credential github
			out, err := exec.CommandContext(ctx, path, "lookup",
				"service", "keyfence", "credential", name).Output()
			if err != nil {
				return "", err
			}
			return string(out), nil
		},
		list: func(ctx context.Context) (string, error) {
			out, err := exec.CommandContext(ctx, path, "search", "--all",
				"service", "keyfence").CombinedOutput()
			if err != nil {
				return "", err
			}
			return string(out), nil
		},
	}
}

// Resolve answers the secret stored under name, or an error if there is none.
func (k *Keyring) Resolve(name string) (string, error) {
	if err := validName(name); err != nil {
		return "", err
	}

	k.mu.Lock()
	if entry, ok := k.cached[name]; ok && time.Since(entry.at) < k.ttl {
		k.mu.Unlock()
		return entry.value, nil
	}
	k.mu.Unlock()

	// A bounded wait: an unlock prompt or a wedged agent must not hold up a
	// request forever.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := k.lookup(ctx, name)
	if err != nil {
		return "", fmt.Errorf("no keyring entry for %q (secret-tool lookup service keyfence credential %s): %w",
			name, name, err)
	}
	// secret-tool prints the secret followed by a newline it added itself.
	value := strings.TrimRight(out, "\r\n")
	if value == "" {
		return "", fmt.Errorf("the keyring entry for %q is empty", name)
	}

	k.mu.Lock()
	k.cached[name] = cachedSecret{value: value, at: time.Now()}
	k.mu.Unlock()
	return value, nil
}

// Names answers the credential names the keyring holds under KeyFence's
// attributes, so that an operator who mistypes a reference is told about the
// ones they cannot see on disk.
//
// Only the attribute lines are read. secret-tool's search output includes the
// secret itself, which is never parsed, never logged, and never returned.
func (k *Keyring) Names() []string {
	if k.list == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := k.list(ctx)
	if err != nil {
		return nil
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		rest, found := strings.CutPrefix(strings.TrimSpace(line), "attribute.credential = ")
		if !found {
			continue
		}
		if name := strings.TrimSpace(rest); validName(name) == nil {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// Forget drops anything cached, so the next request asks the keyring again.
func (k *Keyring) Forget() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.cached = map[string]cachedSecret{}
}
