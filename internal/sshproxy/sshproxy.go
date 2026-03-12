// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@redhat.com>

// Package sshproxy implements an SSH bastion for KeyFence.
//
// It serves two purposes:
//
//  1. TCP forwarding (direct-tcpip): Forward any protocol to allowed
//     destinations. The agent uses ssh -L or -W to tunnel postgres,
//     gRPC, raw TCP, etc. KeyFence enforces destination policy but
//     doesn't touch the bytes.
//
//  2. SSH key injection (session + exec): For SSH-based upstreams like
//     git, KeyFence holds the real private key and authenticates
//     upstream on the agent's behalf. The agent never has the key.
//
// In both cases the agent authenticates to the bastion with a kf_ token
// (as the SSH password). The token's AllowedDestinations controls which
// hosts the agent can reach.
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

// Server is an SSH bastion that validates kf_ tokens and provides
// TCP forwarding and SSH session bridging.
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
// Tokens do NOT require an SSH key — tokens without one can still use
// TCP forwarding (direct-tcpip).
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
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		return
	}
	defer sshConn.Close()

	// Discard global requests
	go ssh.DiscardRequests(reqs)

	tokenValue := sshConn.Permissions.Extensions["token_value"]
	token := s.store.Resolve(tokenValue)
	if token == nil {
		return
	}

	for newChan := range chans {
		switch newChan.ChannelType() {
		case "direct-tcpip":
			go s.handleDirectTCPIP(token, tokenValue, newChan)
		case "session":
			if token.SSHKeyID == "" {
				newChan.Reject(ssh.Prohibited, "token has no ssh key; use TCP forwarding (-L or -W) instead")
				continue
			}
			channel, requests, err := newChan.Accept()
			if err != nil {
				return
			}
			go s.handleSession(token, tokenValue, channel, requests)
		default:
			newChan.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}
}

// directTCPIPData is the payload for a direct-tcpip channel open request.
type directTCPIPData struct {
	DestHost   string
	DestPort   uint32
	OriginHost string
	OriginPort uint32
}

// handleDirectTCPIP forwards arbitrary TCP connections to allowed destinations.
// The agent uses ssh -L (local forward) or ssh -W (stdio forward) to tunnel
// any protocol through KeyFence.
func (s *Server) handleDirectTCPIP(token *tokenstore.Token, tokenValue string, newChan ssh.NewChannel) {
	ctx, span := telemetry.Tracer().Start(context.Background(), "ssh.forward",
		telemetry.WithSpanAttributes(
			attribute.String("keyfence.token_id", token.ID),
			attribute.String("keyfence.agent_id", token.AgentID),
			attribute.String("keyfence.task_id", token.TaskID),
		),
	)
	defer span.End()
	_ = ctx

	var req directTCPIPData
	if err := ssh.Unmarshal(newChan.ExtraData(), &req); err != nil {
		newChan.Reject(ssh.ConnectionFailed, "invalid forward request")
		return
	}

	dest := net.JoinHostPort(req.DestHost, fmt.Sprintf("%d", req.DestPort))
	span.SetAttributes(attribute.String("net.peer.name", dest))

	// Check rate limit
	if token.RateLimit > 0 && !s.store.CheckRate(tokenValue) {
		s.audit.Log(audit.Entry{
			Event:       audit.EventSSHDeny,
			TokenID:     token.ID,
			AgentID:     token.AgentID,
			TaskID:      token.TaskID,
			Destination: dest,
			DenyRule:    "rate_limit",
			DenyReason:  fmt.Sprintf("token rate limit exceeded: %d per %s", token.RateLimit, token.RateWindow),
		})
		span.SetStatus(codes.Error, "rate_limit")
		newChan.Reject(ssh.ConnectionFailed, "rate limit exceeded")
		return
	}

	// Check destination
	if !token.IsDestinationAllowed(req.DestHost, "") {
		s.audit.Log(audit.Entry{
			Event:       audit.EventSSHDeny,
			TokenID:     token.ID,
			AgentID:     token.AgentID,
			TaskID:      token.TaskID,
			Destination: dest,
			DenyRule:    "destination",
			DenyReason:  fmt.Sprintf("token not allowed for destination %s", req.DestHost),
		})
		span.SetStatus(codes.Error, "destination_denied")
		newChan.Reject(ssh.Prohibited, fmt.Sprintf("destination %s not allowed", req.DestHost))
		return
	}

	// Dial upstream
	upstream, err := net.DialTimeout("tcp", dest, 10*1e9) // 10 seconds
	if err != nil {
		s.audit.Log(audit.Entry{
			Event:       audit.EventSSHDeny,
			TokenID:     token.ID,
			AgentID:     token.AgentID,
			TaskID:      token.TaskID,
			Destination: dest,
			DenyRule:    "upstream_error",
			DenyReason:  fmt.Sprintf("dial %s: %v", dest, err),
		})
		newChan.Reject(ssh.ConnectionFailed, "upstream connection failed")
		return
	}
	defer upstream.Close()

	channel, _, err := newChan.Accept()
	if err != nil {
		return
	}
	defer channel.Close()

	s.audit.Log(audit.Entry{
		Event:       audit.EventSSHAllow,
		TokenID:     token.ID,
		AgentID:     token.AgentID,
		TaskID:      token.TaskID,
		Destination: dest,
	})

	// Bridge bytes in both directions
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(upstream, channel) }()
	go func() { defer wg.Done(); io.Copy(channel, upstream) }()
	wg.Wait()
}

// handleSession handles SSH session channels for exec requests.
// This is used for SSH key injection — KeyFence holds the real SSH
// private key and authenticates to the upstream SSH server.
func (s *Server) handleSession(token *tokenstore.Token, tokenValue string, channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	for req := range requests {
		switch req.Type {
		case "exec":
			if len(req.Payload) < 4 {
				req.Reply(false, nil)
				continue
			}
			// Payload is uint32 length + string
			cmdLen := binary.BigEndian.Uint32(req.Payload[:4])
			if int(cmdLen)+4 > len(req.Payload) {
				req.Reply(false, nil)
				continue
			}
			command := string(req.Payload[4 : 4+cmdLen])
			req.Reply(true, nil)
			s.bridgeSSHSession(token, tokenValue, channel, command)
			return

		case "env":
			// Ignore env requests (git sends some)
			if req.WantReply {
				req.Reply(true, nil)
			}

		default:
			// Reject shell, pty-req, subsystem, etc.
			if req.WantReply {
				req.Reply(false, nil)
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
		fmt.Fprintf(channel.Stderr(), "rate limit exceeded\r\n")
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
		fmt.Fprintf(channel.Stderr(), "ssh session requires allowed destinations\r\n")
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
		fmt.Fprintf(channel.Stderr(), "failed to fetch ssh key\r\n")
		sendExitStatus(channel, 1)
		return
	}

	signer, err := ssh.ParsePrivateKey([]byte(sshKey.PrivateKeyPEM))
	if err != nil {
		log.Printf("ssh key parse error: %v", err)
		fmt.Fprintf(channel.Stderr(), "invalid ssh key\r\n")
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
		fmt.Fprintf(channel.Stderr(), "upstream connection failed\r\n")
		sendExitStatus(channel, 1)
		return
	}
	defer upstreamConn.Close()

	upstreamSession, err := upstreamConn.NewSession()
	if err != nil {
		log.Printf("upstream session error: %v", err)
		fmt.Fprintf(channel.Stderr(), "upstream session failed\r\n")
		sendExitStatus(channel, 1)
		return
	}
	defer upstreamSession.Close()

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
		fmt.Fprintf(channel.Stderr(), "upstream exec failed: %v\r\n", err)
		sendExitStatus(channel, 1)
		return
	}

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); io.Copy(upstreamStdin, channel); upstreamStdin.Close() }()
	go func() { defer wg.Done(); io.Copy(channel, upstreamStdout) }()
	go func() { defer wg.Done(); io.Copy(channel.Stderr(), upstreamStderr) }()

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
	channel.SendRequest("exit-status", false, payload)
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
