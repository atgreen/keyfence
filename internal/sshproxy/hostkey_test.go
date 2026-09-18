// SPDX-License-Identifier: MIT

package sshproxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The bastion exists so that an agent can use an SSH key it never holds. If the
// bastion will then offer that key to whatever answers the address, the agent is
// the only party it was ever protecting the key from.

func testPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatalf("wrapping the key: %v", err)
	}
	return key
}

func writeKnownHosts(t *testing.T, host string, key ssh.PublicKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	line := fmt.Sprintf("%s %s\n", host, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatalf("writing known_hosts: %v", err)
	}
	return path
}

func remote() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 22}
}

func TestAKnownHostIsAccepted(t *testing.T) {
	key := testPublicKey(t)
	server := &Server{knownHostsPath: writeKnownHosts(t, "git.example.com", key)}

	policy, err := server.hostKeyPolicy()
	if err != nil {
		t.Fatalf("building the policy: %v", err)
	}
	if err := policy("git.example.com:22", remote(), key); err != nil {
		t.Errorf("a host key on file was refused: %v", err)
	}
}

func TestAHostKeyThatDoesNotMatchIsRefused(t *testing.T) {
	onFile := testPublicKey(t)
	impostor := testPublicKey(t)
	server := &Server{knownHostsPath: writeKnownHosts(t, "git.example.com", onFile)}

	policy, err := server.hostKeyPolicy()
	if err != nil {
		t.Fatalf("building the policy: %v", err)
	}
	err = policy("git.example.com:22", remote(), impostor)
	if err == nil {
		t.Fatal("a host presenting the wrong key was accepted; the bastion would have offered its key to it")
	}

	// And the reason says which of the two problems it is, because "changed" and
	// "never seen" call for different reactions.
	described := describeHostKeyFailure(err, "git.example.com", server.knownHostsPath)
	if !strings.Contains(described, "does not match") {
		t.Errorf("a mismatched key was not described as a mismatch: %q", described)
	}
}

func TestAHostNobodyVouchedForIsRefusedWithInstructions(t *testing.T) {
	server := &Server{knownHostsPath: writeKnownHosts(t, "git.example.com", testPublicKey(t))}

	policy, err := server.hostKeyPolicy()
	if err != nil {
		t.Fatalf("building the policy: %v", err)
	}
	err = policy("other.example.com:22", remote(), testPublicKey(t))
	if err == nil {
		t.Fatal("an unknown host was accepted")
	}

	described := describeHostKeyFailure(err, "other.example.com", server.knownHostsPath)
	if !strings.Contains(described, "not in") || !strings.Contains(described, "ssh-keyscan") {
		t.Errorf("the refusal does not say how to fix it: %q", described)
	}
}

func TestAMissingKnownHostsFileIsAnActionableError(t *testing.T) {
	server := &Server{knownHostsPath: filepath.Join(t.TempDir(), "absent", "known_hosts")}

	_, err := server.hostKeyPolicy()
	if err == nil {
		t.Fatal("a missing known_hosts file was treated as permission to trust anything")
	}
	if !strings.Contains(err.Error(), "ssh-keyscan") {
		t.Errorf("the error does not say how to populate it: %v", err)
	}
}

func TestHostKeysCanBeWaivedDeliberately(t *testing.T) {
	// The escape hatch has to exist -- there are networks where it is the right
	// answer -- but only when asked for.
	server := &Server{insecureHostKeys: true}

	policy, err := server.hostKeyPolicy()
	if err != nil {
		t.Fatalf("building the policy: %v", err)
	}
	if err := policy("anything.example.com:22", remote(), testPublicKey(t)); err != nil {
		t.Errorf("-ssh-insecure-host-keys still refused a key: %v", err)
	}
}

func TestAddingAHostKeyDoesNotNeedARestart(t *testing.T) {
	key := testPublicKey(t)
	path := writeKnownHosts(t, "git.example.com", key)
	server := &Server{knownHostsPath: path}

	policy, err := server.hostKeyPolicy()
	if err != nil {
		t.Fatalf("building the policy: %v", err)
	}
	if err := policy("later.example.com:22", remote(), key); err == nil {
		t.Fatal("a host not yet on file was accepted")
	}

	appended, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("appending: %v", err)
	}
	line := fmt.Sprintf("later.example.com %s\n", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))
	if _, err := appended.WriteString(line); err != nil {
		t.Fatalf("appending: %v", err)
	}
	_ = appended.Close()

	// The file is read per connection, so the next session sees the new entry.
	policy, err = server.hostKeyPolicy()
	if err != nil {
		t.Fatalf("rebuilding the policy: %v", err)
	}
	if err := policy("later.example.com:22", remote(), key); err != nil {
		t.Errorf("a host key added while running was not picked up: %v", err)
	}
}
