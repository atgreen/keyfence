// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@redhat.com>

// KeyFence — credential tokenization proxy for AI agents.
//
// Single binary:
//   - MITM forward proxy on :10210 (agents set HTTPS_PROXY here)
//   - SSH bastion on :10211 (agents use as SSH proxy for git)
//   - Token management API on :10212
//
// KeyFence is service-agnostic. It doesn't know about Anthropic, OpenAI,
// or any specific API. You issue a token for any credential, optionally
// lock it to specific destination hosts, and KeyFence swaps it in any
// header where it finds it.
//
// Real credentials never enter the agent's address space. They are stored
// in KeyFence's credential backend and fetched on each request.
//
// Usage:
//
//	keyfence                               # start with defaults
//	keyfence --data-dir ~/.keyfence       # specify data directory
//
// Issue a token:
//
//	curl -X POST http://localhost:10212/tokens \
//	  -d '{"credential":"sk-ant-real-key","destinations":["api.anthropic.com"]}'
//
// Use it:
//
//	export HTTPS_PROXY=http://127.0.0.1:10210
//	export SSL_CERT_FILE=~/.keyfence/ca/ca.pem
//	curl https://api.anthropic.com/v1/messages -H "x-api-key: kf_<token>" ...
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/keyfence/keyfence/internal/acl"
	"github.com/keyfence/keyfence/internal/audit"
	"github.com/keyfence/keyfence/internal/credstore"
	"github.com/keyfence/keyfence/internal/policy"
	"github.com/keyfence/keyfence/internal/proxy"
	"github.com/keyfence/keyfence/internal/sshproxy"
	"github.com/keyfence/keyfence/internal/telemetry"
	"github.com/keyfence/keyfence/internal/tokenstore"
)

func main() {
	proxyAddr := flag.String("proxy", ":10210", "proxy listen address")
	sshAddr := flag.String("ssh", ":10211", "SSH bastion listen address")
	apiAddr := flag.String("api", ":10212", "token management API listen address")
	dataDir := flag.String("data-dir", defaultDataDir(), "data directory for CA certs")
	certsDir := flag.String("certs-dir", "", "directory to export CA cert for agents (optional)")
	apiKey := flag.String("api-key", "", "require this Bearer token on all control API requests (strongly recommended)")
	denyFile := flag.String("deny-file", "", "file containing denied destinations, one per line (e.g. from a ConfigMap)")
	allowNoTokenFile := flag.String("allow-without-token-file", "", "file containing destinations that bypass token requirements, one per line")
	denyList := flag.String("deny", "", "comma-separated deny list (alternative to --deny-file)")
	allowNoToken := flag.String("allow-without-token", "", "comma-separated allow-without-token list (alternative to --allow-without-token-file)")
	flag.Parse()

	// Initialize OpenTelemetry (configured via OTEL_* env vars)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	otelShutdown, err := telemetry.Init(ctx, "dev")
	if err != nil {
		log.Printf("otel init (tracing disabled): %v", err)
	} else {
		defer otelShutdown(context.Background())
	}

	// Load or create local CA
	caDir := filepath.Join(*dataDir, "ca")
	ca, err := proxy.LoadOrCreateCA(caDir)
	if err != nil {
		log.Fatalf("CA: %v", err)
	}

	// Export CA cert to certs dir if specified (for agent volume mount)
	if *certsDir != "" {
		if err := exportCACert(ca, *certsDir); err != nil {
			log.Fatalf("export CA cert: %v", err)
		}
		log.Printf("ca cert exported to %s/ca.pem", *certsDir)
	}

	auditLog := audit.New(os.Stdout)
	sseSink := audit.NewSSESink()
	auditLog.AddSink(sseSink)

	store := tokenstore.New()
	creds := credstore.NewEnvBackend()
	certs := credstore.NewCertStore()
	sshKeys := credstore.NewSSHKeyStore()
	pol := policy.NewEngine()

	// Register built-in policies
	pol.Register(&policy.Policy{
		Name:           "open",
		AllowedMethods: nil, // all methods
	})
	pol.Register(&policy.Policy{
		Name:           "standard",
		AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
		RateLimit:      1000,
		RateWindow:     time.Hour,
	})
	pol.Register(&policy.Policy{
		Name:                "strict",
		AllowedMethods:      []string{"GET", "POST"},
		AllowedContentTypes: []string{"application/json"},
		MaxBodyBytes:        10 * 1024 * 1024, // 10 MiB
		RateLimit:           1000,
		RateWindow:          time.Hour,
	})
	pol.Register(&policy.Policy{
		Name:           "readonly",
		AllowedMethods: []string{"GET", "HEAD"},
	})

	// Build global ACL (file entries + inline entries merged)
	denyEntries := splitCSV(*denyList)
	if *denyFile != "" {
		entries, err := loadListFile(*denyFile)
		if err != nil {
			log.Fatalf("deny-file: %v", err)
		}
		denyEntries = append(denyEntries, entries...)
	}
	allowEntries := splitCSV(*allowNoToken)
	if *allowNoTokenFile != "" {
		entries, err := loadListFile(*allowNoTokenFile)
		if err != nil {
			log.Fatalf("allow-without-token-file: %v", err)
		}
		allowEntries = append(allowEntries, entries...)
	}
	aclList := acl.New(denyEntries, allowEntries)
	if len(denyEntries) > 0 {
		log.Printf("deny list: %d entries", len(denyEntries))
	}
	if len(allowEntries) > 0 {
		log.Printf("WARNING: allow-without-token: %d entries", len(allowEntries))
		log.Printf("WARNING: These destinations bypass token requirements. Use sparingly.")
	}

	// Start HTTPS proxy
	p := proxy.New(*proxyAddr, ca, store, creds, certs, pol, auditLog, aclList)
	go func() {
		if err := p.ListenAndServe(); err != nil {
			log.Fatalf("proxy: %v", err)
		}
	}()

	// Start SSH bastion
	sshDir := filepath.Join(*dataDir, "ssh")
	sshServer, err := sshproxy.New(*sshAddr, sshDir, store, sshKeys, auditLog, aclList)
	if err != nil {
		log.Fatalf("ssh: %v", err)
	}
	go func() {
		if err := sshServer.ListenAndServe(); err != nil {
			log.Fatalf("ssh: %v", err)
		}
	}()

	if *apiKey == "" {
		log.Printf("WARNING: --api-key not set. The control API is unauthenticated.")
		log.Printf("WARNING: Any process that can reach :10212 can issue and revoke tokens.")
		log.Printf("WARNING: Set --api-key in production to prevent agent access to the control plane.")
	}

	// Token management API
	mux := http.NewServeMux()
	mux.HandleFunc("POST /tokens", requireAPIKey(*apiKey, handleIssueToken(store, creds, certs, sshKeys, auditLog)))
	mux.HandleFunc("GET /tokens", requireAPIKey(*apiKey, handleListTokens(store)))
	mux.HandleFunc("DELETE /tokens/{token}", requireAPIKey(*apiKey, handleRevokeToken(store, auditLog)))
	mux.HandleFunc("DELETE /tasks/{task_id}/tokens", requireAPIKey(*apiKey, handleRevokeByTask(store, auditLog)))
	mux.HandleFunc("GET /policies", requireAPIKey(*apiKey, handleListPolicies(pol)))
	mux.HandleFunc("PUT /credentials/{id}", requireAPIKey(*apiKey, handleRotateCredential(creds, store, auditLog)))
	mux.HandleFunc("PUT /credentials/{id}/cert", requireAPIKey(*apiKey, handleRotateCert(certs, auditLog)))
	mux.HandleFunc("PUT /credentials/{id}/sshkey", requireAPIKey(*apiKey, handleRotateSSHKey(sshKeys, auditLog)))
	mux.HandleFunc("POST /webhooks", requireAPIKey(*apiKey, handleRegisterWebhook(auditLog)))
	mux.HandleFunc("GET /events", requireAPIKey(*apiKey, sseSink.ServeHTTP))
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	log.Printf("api on %s", *apiAddr)
	log.Printf("ca cert: %s/ca.pem", caDir)
	log.Printf("")
	log.Printf("to use:")
	log.Printf("  export HTTPS_PROXY=http://127.0.0.1%s", *proxyAddr)
	log.Printf("  export SSL_CERT_FILE=%s/ca.pem", caDir)
	log.Printf("")
	log.Printf("issue a token:")
	log.Printf(`  curl -X POST http://localhost%s/tokens \`, *apiAddr)
	log.Printf(`    -d '{"credential":"sk-ant-...","destinations":["api.anthropic.com"]}'`)

	if err := http.ListenAndServe(*apiAddr, mux); err != nil {
		log.Fatalf("api: %v", err)
	}
}

// loadListFile reads a file with one entry per line. Blank lines and
// lines starting with # are ignored. Designed for ConfigMap mounts.
func loadListFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entries []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, line)
	}
	return entries, nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".keyfence"
	}
	return filepath.Join(home, ".keyfence")
}

// exportCACert copies just the CA public certificate (not the private key)
// to a separate directory. This directory can be mounted read-only into
// agent containers without exposing the CA private key.
func exportCACert(ca *proxy.CA, dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating certs dir: %w", err)
	}
	return os.WriteFile(filepath.Join(dir, "ca.pem"), ca.CertPEM(), 0644)
}

type issueRequest struct {
	Credential        string   `json:"credential"`
	Destinations      []string `json:"destinations"`
	TTLSeconds        int      `json:"ttl_seconds"`
	Label             string   `json:"label"`
	Policy            string   `json:"policy"`
	AgentID           string   `json:"agent_id"`
	TaskID            string   `json:"task_id"`
	RateLimit         int      `json:"rate_limit"`
	RateWindowSeconds int      `json:"rate_window_seconds"`
	ClientCert        string   `json:"client_cert"`
	ClientKey         string   `json:"client_key"`
	ClientCertHeader  string   `json:"client_cert_header"`
	SSHPrivateKey     string                   `json:"ssh_private_key"`
	SSHUsername       string                   `json:"ssh_username"`
	ResponseRules     []tokenstore.ResponseRule `json:"response_rules"`
}

type issueResponse struct {
	Token        string   `json:"token"`
	ExpiresAt    string   `json:"expires_at"`
	Destinations []string `json:"destinations"`
	Label        string   `json:"label,omitempty"`
	Policy       string   `json:"policy,omitempty"`
	AgentID      string   `json:"agent_id,omitempty"`
	TaskID       string   `json:"task_id,omitempty"`
}

func handleIssueToken(store *tokenstore.Store, creds credstore.Backend, certStore *credstore.CertStore, sshKeyStore *credstore.SSHKeyStore, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req issueRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"invalid json: %s"}`, err), 400)
			return
		}
		if req.Credential == "" && req.ClientCert == "" && req.SSHPrivateKey == "" {
			http.Error(w, `{"error":"credential, client_cert, or ssh_private_key is required"}`, 400)
			return
		}

		// Store the header credential (if provided)
		var credID string
		if req.Credential != "" {
			var err error
			credID, err = creds.Store(req.Credential)
			if err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"storing credential: %s"}`, err), 500)
				return
			}
		}

		// Store the client cert+key (if provided)
		var clientCertID string
		if req.ClientCert != "" {
			if req.ClientKey == "" {
				http.Error(w, `{"error":"client_key is required when client_cert is provided"}`, 400)
				return
			}
			var err error
			clientCertID, err = certStore.Store(req.ClientCert, req.ClientKey)
			if err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"storing client cert: %s"}`, err), 500)
				return
			}
		}

		// Store the SSH private key (if provided)
		var sshKeyID string
		if req.SSHPrivateKey != "" {
			username := req.SSHUsername
			if username == "" {
				username = "git"
			}
			var err error
			sshKeyID, err = sshKeyStore.Store(req.SSHPrivateKey, username)
			if err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"storing ssh key: %s"}`, err), 500)
				return
			}
		}

		ttl := time.Duration(req.TTLSeconds) * time.Second
		if ttl <= 0 {
			ttl = 5 * time.Minute
		}

		rateWindow := time.Duration(req.RateWindowSeconds) * time.Second

		token, err := store.Issue(tokenstore.IssueParams{
			CredentialID:        credID,
			AllowedDestinations: req.Destinations,
			TTL:                 ttl,
			Label:               req.Label,
			PolicyName:          req.Policy,
			AgentID:             req.AgentID,
			TaskID:              req.TaskID,
			RateLimit:           req.RateLimit,
			RateWindow:          rateWindow,
			ClientCertID:        clientCertID,
			ClientCertHeader:    req.ClientCertHeader,
			SSHKeyID:            sshKeyID,
			ResponseRules:       req.ResponseRules,
		})
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err), 500)
			return
		}

		auditLog.Log(audit.Entry{
			Event:   audit.EventIssue,
			TokenID: token.ID,
			AgentID: token.AgentID,
			TaskID:  token.TaskID,
			Label:   token.Label,
			Policy:  token.PolicyName,
			TTL:     ttl.String(),
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(issueResponse{
			Token:        token.Value,
			ExpiresAt:    token.ExpiresAt.Format(time.RFC3339),
			Destinations: token.AllowedDestinations,
			Label:        token.Label,
			Policy:       token.PolicyName,
			AgentID:      token.AgentID,
			TaskID:       token.TaskID,
		})
	}
}

func handleListTokens(store *tokenstore.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokens := store.List()
		type entry struct {
			ID           string   `json:"id"`
			ExpiresAt    string   `json:"expires_at"`
			Valid        bool     `json:"valid"`
			Destinations []string `json:"destinations"`
			Label        string   `json:"label,omitempty"`
			Policy       string   `json:"policy,omitempty"`
			AgentID      string   `json:"agent_id,omitempty"`
			TaskID       string   `json:"task_id,omitempty"`
		}
		result := make([]entry, 0, len(tokens))
		for _, t := range tokens {
			result = append(result, entry{
				ID:           t.ID,
				ExpiresAt:    t.ExpiresAt.Format(time.RFC3339),
				Valid:        t.IsValid(),
				Destinations: t.AllowedDestinations,
				Label:        t.Label,
				Policy:       t.PolicyName,
				AgentID:      t.AgentID,
				TaskID:       t.TaskID,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func handleRevokeToken(store *tokenstore.Store, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenValue := r.PathValue("token")
		if store.Revoke(tokenValue) {
			auditLog.Log(audit.Entry{
				Event:   audit.EventRevoke,
				TokenID: tokenValue,
			})
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
		} else {
			http.Error(w, `{"error":"token not found"}`, 404)
		}
	}
}

func handleRevokeByTask(store *tokenstore.Store, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		taskID := r.PathValue("task_id")
		if taskID == "" {
			http.Error(w, `{"error":"task_id is required"}`, 400)
			return
		}
		count := store.RevokeByTaskID(taskID)
		auditLog.Log(audit.Entry{
			Event:  audit.EventRevoke,
			TaskID: taskID,
			Label:  fmt.Sprintf("bulk revoke: %d tokens", count),
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "revoked", "count": count})
	}
}

// requireAPIKey wraps a handler to require a Bearer token on the control API.
// If key is empty, authentication is disabled (development mode).
func requireAPIKey(key string, next http.HandlerFunc) http.HandlerFunc {
	if key == "" {
		return next
	}
	expected := "Bearer " + key
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != expected {
			http.Error(w, `{"error":"unauthorized: invalid or missing api key"}`, 401)
			return
		}
		next(w, r)
	}
}

func handleListPolicies(pol *policy.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Return built-in policy names
		names := []string{"open", "standard", "strict", "readonly"}
		type policyInfo struct {
			Name string `json:"name"`
		}
		result := make([]policyInfo, len(names))
		for i, n := range names {
			result[i] = policyInfo{Name: n}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

// --- Credential rotation handlers ---

func handleRotateCredential(creds credstore.Backend, store *tokenstore.Store, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var req struct {
			Credential string `json:"credential"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"invalid json: %s"}`, err), 400)
			return
		}
		if req.Credential == "" {
			http.Error(w, `{"error":"credential is required"}`, 400)
			return
		}
		if err := creds.Update(id, req.Credential); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err), 404)
			return
		}
		count := store.CountByCredentialID(id)
		auditLog.Log(audit.Entry{
			Event:        audit.EventRotate,
			CredentialID: id,
			Label:        fmt.Sprintf("credential rotated, %d active tokens", count),
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":          "rotated",
			"credential_id":   id,
			"affected_tokens": count,
		})
	}
}

func handleRotateCert(certs *credstore.CertStore, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var req struct {
			ClientCert string `json:"client_cert"`
			ClientKey  string `json:"client_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"invalid json: %s"}`, err), 400)
			return
		}
		if req.ClientCert == "" || req.ClientKey == "" {
			http.Error(w, `{"error":"client_cert and client_key are required"}`, 400)
			return
		}
		if err := certs.Update(id, req.ClientCert, req.ClientKey); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err), 404)
			return
		}
		auditLog.Log(audit.Entry{
			Event:        audit.EventRotate,
			CredentialID: id,
			Label:        "client cert rotated",
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "rotated", "credential_id": id})
	}
}

func handleRotateSSHKey(sshKeys *credstore.SSHKeyStore, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var req struct {
			SSHPrivateKey string `json:"ssh_private_key"`
			SSHUsername   string `json:"ssh_username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"invalid json: %s"}`, err), 400)
			return
		}
		if req.SSHPrivateKey == "" {
			http.Error(w, `{"error":"ssh_private_key is required"}`, 400)
			return
		}
		username := req.SSHUsername
		if username == "" {
			username = "git"
		}
		if err := sshKeys.Update(id, req.SSHPrivateKey, username); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err), 404)
			return
		}
		auditLog.Log(audit.Entry{
			Event:        audit.EventRotate,
			CredentialID: id,
			Label:        "ssh key rotated",
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "rotated", "credential_id": id})
	}
}

// --- Webhook management handler ---

func handleRegisterWebhook(auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			URL    string   `json:"url"`
			Secret string   `json:"secret"`
			Events []string `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"invalid json: %s"}`, err), 400)
			return
		}
		if req.URL == "" {
			http.Error(w, `{"error":"url is required"}`, 400)
			return
		}
		wh := audit.NewWebhookSink(req.URL, req.Secret, req.Events)
		auditLog.AddSink(wh)
		go wh.Run()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "registered", "url": req.URL})
	}
}
