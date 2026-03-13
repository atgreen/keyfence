// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@redhat.com>

// Package sshproxy implements an SSH bastion for KeyFence.
//
// The bastion provides SSH key injection: the agent authenticates with
// a kf_ token (as the SSH password), and KeyFence holds the real SSH
// private key, authenticating to the upstream SSH server on the agent's
// behalf. The agent never has the key.
//
// This is the SSH equivalent of the HTTPS proxy's credential swap —
// the agent uses an opaque token, KeyFence injects the real credential.
package sshproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/crypto/ssh"

	"github.com/keyfence/keyfence/internal/audit"
	"github.com/keyfence/keyfence/internal/credstore"
	"github.com/keyfence/keyfence/internal/telemetry"
	"github.com/keyfence/keyfence/internal/tokenstore"
)

// Server is an SSH bastion that validates kf_ tokens and bridges
// SSH sessions with real credentials.
type Server struct {
	addr    string
	store   *tokenstore.Store
	sshKeys *credstore.SSHKeyStore
	audit   *audit.Logger
	config  *ssh.ServerConfig
}

// New creates an SSH bastion server. It loads or generates a host key
// from hostKeyDir.
func New(addr string, hostKeyDir string, store *tokenstore.Store, sshKeys *credstore.SSHKeyStore, auditLog *audit.Logger) (*Server, error) {
	hostKey, err := loadOrCreateHostKey(hostKeyDir)
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}

	s := &Server{
		addr:    addr,
		store:   store,
		sshKeys: sshKeys,
		audit:   auditLog,
	}

	s.config = &ssh.ServerConfig{
		PasswordCallback: s.passwordCallback,
	}
	s.config.AddHostKey(hostKey)

	return s, nil
}

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.addr, err)
	}
	log.Printf("ssh bastion listening on %s", s.addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("ssh accept: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

// passwordCallback validates the kf_ token supplied as the SSH password.
// Also checks the username for a kf_ prefix as a fallback.
func (s *Server) passwordCallback(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	tokenValue := string(password)

	// Also check username for kf_ prefix (some clients send token there)
	if !strings.HasPrefix(tokenValue, "kf_") {
		tokenValue = meta.User()
	}
	if !strings.HasPrefix(tokenValue, "kf_") {
		return nil, fmt.Errorf("no keyfence token")
	}

	token := s.store.Resolve(tokenValue)
	if token == nil {
		return nil, fmt.Errorf("invalid or expired token")
	}

	return &ssh.Permissions{
		Extensions: map[string]string{
			"token_value": tokenValue,
		},
	}, nil
}

func (s *Server) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		return
	}
	defer func() { _ = sshConn.Close() }()

	// Discard global requests
	go ssh.DiscardRequests(reqs)

	tokenValue := sshConn.Permissions.Extensions["token_value"]
	token := s.store.Resolve(tokenValue)
	if token == nil {
		return
	}

	for newChan := range chans {
		switch newChan.ChannelType() {
		case "session":
			if token.SSHKeyID == "" {
				_ = newChan.Reject(ssh.Prohibited, "token has no ssh key")
				continue
			}
			channel, requests, err := newChan.Accept()
			if err != nil {
				return
			}
			go s.handleSession(token, tokenValue, channel, requests)
		default:
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}
}

// handleSession handles SSH session channels for exec requests.
// This is used for SSH key injection — KeyFence holds the real SSH
// private key and authenticates to the upstream SSH server.
func (s *Server) handleSession(token *tokenstore.Token, tokenValue string, channel ssh.Channel, requests <-chan *ssh.Request) {
	defer func() { _ = channel.Close() }()

	for req := range requests {
		switch req.Type {
		case "exec":
			if len(req.Payload) < 4 {
				_ = req.Reply(false, nil)
				continue
			}
			// Payload is uint32 length + string
			cmdLen := binary.BigEndian.Uint32(req.Payload[:4])
			if int(cmdLen)+4 > len(req.Payload) {
				_ = req.Reply(false, nil)
				continue
			}
			command := string(req.Payload[4 : 4+cmdLen])
			_ = req.Reply(true, nil)
			s.bridgeSSHSession(token, tokenValue, channel, command)
			return

		case "env":
			// Ignore env requests (git sends some)
			if req.WantReply {
				_ = req.Reply(true, nil)
			}

		default:
			// Reject shell, pty-req, subsystem, etc.
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// bridgeSSHSession opens an SSH connection upstream using the real key
// and bridges the exec session.
func (s *Server) bridgeSSHSession(token *tokenstore.Token, tokenValue string, channel ssh.Channel, command string) {
	_, span := telemetry.Tracer().Start(context.Background(), "ssh.session",
		telemetry.WithSpanAttributes(
			attribute.String("keyfence.token_id", token.ID),
			attribute.String("keyfence.agent_id", token.AgentID),
			attribute.String("keyfence.task_id", token.TaskID),
			attribute.String("ssh.command", command),
		),
	)
	defer span.End()

	// Check rate limit
	if token.RateLimit > 0 && !s.store.CheckRate(tokenValue) {
		s.audit.Log(audit.Entry{
			Event:      audit.EventSSHDeny,
			TokenID:    token.ID,
			AgentID:    token.AgentID,
			TaskID:     token.TaskID,
			SSHCommand: command,
			DenyRule:   "rate_limit",
			DenyReason: fmt.Sprintf("token rate limit exceeded: %d per %s", token.RateLimit, token.RateWindow),
		})
		span.SetStatus(codes.Error, "rate_limit")
		_, _ = fmt.Fprintf(channel.Stderr(), "rate limit exceeded\r\n")
		sendExitStatus(channel, 1)
		return
	}

	// Determine upstream host from allowed destinations
	if len(token.AllowedDestinations) == 0 {
		s.audit.Log(audit.Entry{
			Event:      audit.EventSSHDeny,
			TokenID:    token.ID,
			AgentID:    token.AgentID,
			TaskID:     token.TaskID,
			SSHCommand: command,
			DenyRule:   "no_destination",
			DenyReason: "ssh session requires allowed destinations",
		})
		_, _ = fmt.Fprintf(channel.Stderr(), "ssh session requires allowed destinations\r\n")
		sendExitStatus(channel, 1)
		return
	}

	// Use first allowed destination
	upstream := token.AllowedDestinations[0]
	if !strings.Contains(upstream, ":") {
		upstream += ":22"
	}
	hostname := strings.Split(upstream, ":")[0]

	// Fetch SSH key
	sshKey, err := s.sshKeys.Fetch(token.SSHKeyID)
	if err != nil {
		log.Printf("ssh key fetch error: %v", err)
		_, _ = fmt.Fprintf(channel.Stderr(), "failed to fetch ssh key\r\n")
		sendExitStatus(channel, 1)
		return
	}

	signer, err := ssh.ParsePrivateKey([]byte(sshKey.PrivateKeyPEM))
	if err != nil {
		log.Printf("ssh key parse error: %v", err)
		_, _ = fmt.Fprintf(channel.Stderr(), "invalid ssh key\r\n")
		sendExitStatus(channel, 1)
		return
	}

	// Connect upstream
	clientConfig := &ssh.ClientConfig{
		User:            sshKey.Username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	upstreamConn, err := ssh.Dial("tcp", upstream, clientConfig)
	if err != nil {
		s.audit.Log(audit.Entry{
			Event:       audit.EventSSHDeny,
			TokenID:     token.ID,
			AgentID:     token.AgentID,
			TaskID:      token.TaskID,
			Destination: hostname,
			SSHCommand:  command,
			DenyRule:    "upstream_error",
			DenyReason:  fmt.Sprintf("upstream ssh dial: %v", err),
		})
		_, _ = fmt.Fprintf(channel.Stderr(), "upstream connection failed\r\n")
		sendExitStatus(channel, 1)
		return
	}
	defer func() { _ = upstreamConn.Close() }()

	upstreamSession, err := upstreamConn.NewSession()
	if err != nil {
		log.Printf("upstream session error: %v", err)
		_, _ = fmt.Fprintf(channel.Stderr(), "upstream session failed\r\n")
		sendExitStatus(channel, 1)
		return
	}
	defer func() { _ = upstreamSession.Close() }()

	s.audit.Log(audit.Entry{
		Event:       audit.EventSSHAllow,
		TokenID:     token.ID,
		AgentID:     token.AgentID,
		TaskID:      token.TaskID,
		Destination: hostname,
		SSHCommand:  command,
	})

	// Bridge stdin/stdout/stderr
	upstreamStdin, err := upstreamSession.StdinPipe()
	if err != nil {
		sendExitStatus(channel, 1)
		return
	}
	upstreamStdout, err := upstreamSession.StdoutPipe()
	if err != nil {
		sendExitStatus(channel, 1)
		return
	}
	upstreamStderr, err := upstreamSession.StderrPipe()
	if err != nil {
		sendExitStatus(channel, 1)
		return
	}

	if err := upstreamSession.Start(command); err != nil {
		_, _ = fmt.Fprintf(channel.Stderr(), "upstream exec failed: %v\r\n", err)
		sendExitStatus(channel, 1)
		return
	}

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); _, _ = io.Copy(upstreamStdin, channel); _ = upstreamStdin.Close() }()
	go func() { defer wg.Done(); _, _ = io.Copy(channel, upstreamStdout) }()
	go func() { defer wg.Done(); _, _ = io.Copy(channel.Stderr(), upstreamStderr) }()

	exitCode := 0
	if err := upstreamSession.Wait(); err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			exitCode = exitErr.ExitStatus()
		} else {
			exitCode = 1
		}
	}
	wg.Wait()
	sendExitStatus(channel, exitCode)
}

func sendExitStatus(channel ssh.Channel, code int) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, uint32(code))
	_, _ = channel.SendRequest("exit-status", false, payload)
}

// loadOrCreateHostKey loads an Ed25519 host key from dir, or generates one.
func loadOrCreateHostKey(dir string) (ssh.Signer, error) {
	keyPath := filepath.Join(dir, "host_key")

	data, err := os.ReadFile(keyPath)
	if err == nil {
		return ssh.ParsePrivateKey(data)
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading host key: %w", err)
	}

	// Generate new Ed25519 key
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("creating ssh dir: %w", err)
	}

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating host key: %w", err)
	}

	pemBytes, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		return nil, fmt.Errorf("marshaling host key: %w", err)
	}

	pemData := pem.EncodeToMemory(pemBytes)
	if err := os.WriteFile(keyPath, pemData, 0600); err != nil {
		return nil, fmt.Errorf("writing host key: %w", err)
	}

	return ssh.ParsePrivateKey(pemData)
}
