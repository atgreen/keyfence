// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@redhat.com>

// KeyFence — credential tokenization proxy for AI agents.
//
// Single binary:
//   - MITM forward proxy on :10210 (agents set HTTPS_PROXY here)
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
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/keyfence/keyfence/internal/audit"
	"github.com/keyfence/keyfence/internal/credstore"
	"github.com/keyfence/keyfence/internal/policy"
	"github.com/keyfence/keyfence/internal/proxy"
	"github.com/keyfence/keyfence/internal/tokenstore"
)

func main() {
	proxyAddr := flag.String("proxy", ":10210", "proxy listen address")
	apiAddr := flag.String("api", ":10212", "token management API listen address")
	dataDir := flag.String("data-dir", defaultDataDir(), "data directory for CA certs")
	certsDir := flag.String("certs-dir", "", "directory to export CA cert for agents (optional)")
	dlpMaxBytes := flag.Int("dlp-max-bytes", 1048576, "max request body size for DLP scanning")
	flag.Parse()

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

	store := tokenstore.New()
	creds := credstore.NewEnvBackend()
	pol := policy.NewEngine()
	dlp := proxy.NewDLPScanner(*dlpMaxBytes)

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

	// Start proxy
	p := proxy.New(*proxyAddr, ca, store, creds, pol, dlp, auditLog)
	go func() {
		if err := p.ListenAndServe(); err != nil {
			log.Fatalf("proxy: %v", err)
		}
	}()

	// Token management API
	mux := http.NewServeMux()
	mux.HandleFunc("POST /tokens", handleIssueToken(store, creds, auditLog))
	mux.HandleFunc("GET /tokens", handleListTokens(store))
	mux.HandleFunc("DELETE /tokens/{token}", handleRevokeToken(store, auditLog))
	mux.HandleFunc("DELETE /tasks/{task_id}/tokens", handleRevokeByTask(store, auditLog))
	mux.HandleFunc("GET /policies", handleListPolicies(pol))
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
	Credential   string   `json:"credential"`
	Destinations []string `json:"destinations"`
	TTLSeconds   int      `json:"ttl_seconds"`
	Label        string   `json:"label"`
	Policy       string   `json:"policy"`
	AgentID      string   `json:"agent_id"`
	TaskID       string   `json:"task_id"`
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

func handleIssueToken(store *tokenstore.Store, creds credstore.Backend, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req issueRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"invalid json: %s"}`, err), 400)
			return
		}
		if req.Credential == "" {
			http.Error(w, `{"error":"credential is required"}`, 400)
			return
		}

		// Store the real credential in the backend, get a reference ID
		credID, err := creds.Store(req.Credential)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"storing credential: %s"}`, err), 500)
			return
		}

		ttl := time.Duration(req.TTLSeconds) * time.Second
		if ttl <= 0 {
			ttl = 5 * time.Minute
		}

		token, err := store.Issue(credID, req.Destinations, ttl, req.Label, req.Policy, req.AgentID, req.TaskID)
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
