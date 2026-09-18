// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@moxielogic.com>

// KeyFence — credential tokenization proxy for AI agents.
//
// Single binary:
//   - MITM forward proxy on 127.0.0.1:10210 (agents set HTTPS_PROXY here)
//   - SSH bastion on 127.0.0.1:10211 (agents use as SSH proxy for git)
//   - Token management API on 127.0.0.1:10212
//
// All three listen on loopback unless told otherwise, and the control API
// refuses to run without a key unless -insecure-api says to. Under systemd it
// can be socket-activated: see releng/keyfence.socket.
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
//	keyfence -api-key-file ~/.keyfence/api-key
//	keyfence -data-dir ~/.keyfence         # specify data directory
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
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/keyfence/keyfence/internal/activation"
	"github.com/keyfence/keyfence/internal/audit"
	"github.com/keyfence/keyfence/internal/credstore"
	"github.com/keyfence/keyfence/internal/policy"
	"github.com/keyfence/keyfence/internal/proxy"
	"github.com/keyfence/keyfence/internal/sshproxy"
	"github.com/keyfence/keyfence/internal/telemetry"
	"github.com/keyfence/keyfence/internal/tokenstore"
)

func main() {
	// "keyfence credential ..." sets one up and exits; anything else starts the
	// broker as before.
	if handled, status := runCredentialCommand(os.Args[1:]); handled {
		os.Exit(status)
	}

	// Loopback by default. The control API issues credentials, and the proxy
	// carries them; neither is something to publish on every interface because
	// nobody said otherwise. Pass an explicit address to widen it -- in a pod,
	// where the agent's container shares this network namespace, loopback is
	// already what the agent connects to.
	proxyAddr := flag.String("proxy", "127.0.0.1:10210", "proxy listen address")
	sshAddr := flag.String("ssh", "127.0.0.1:10211", "SSH bastion listen address")
	apiAddr := flag.String("api", "127.0.0.1:10212", "token management API listen address")
	dataDir := flag.String("data-dir", defaultDataDir(), "data directory for CA certs")
	certsDir := flag.String("certs-dir", "", "directory to export CA cert for agents (optional)")
	apiKey := flag.String("api-key", "", "require this Bearer token on all control API requests")
	apiKeyFile := flag.String("api-key-file", "", "read the control API key from this file, so it is not in argv")
	insecureAPI := flag.Bool("insecure-api", false, "run the control API with no key at all (it can issue and revoke credentials)")
	noReuse := flag.Bool("no-reuse-connections", false, "close each tunnel after one request instead of keeping it for the next")
	useKeyring := flag.Bool("keyring", false, "also resolve named credentials from the OS keyring (service=keyfence credential=<name>), which keeps them off disk in plaintext")
	passthrough := flag.String("passthrough", "", "comma-separated hosts reachable through the proxy without a token (nothing is injected for them)")
	credentialsDir := flag.String("credentials-dir", "", "directory of credentials registered by name, resolved per request (systemd's $CREDENTIALS_DIRECTORY is always searched)")
	knownHosts := flag.String("ssh-known-hosts", "", "known_hosts file used to authenticate upstream SSH hosts (default <data-dir>/ssh/known_hosts)")
	insecureHostKeys := flag.Bool("ssh-insecure-host-keys", false, "accept any upstream SSH host key (the bastion's key can then be used against an impostor)")
	flag.Parse()

	controlKey, err := resolveAPIKey(*apiKey, *apiKeyFile)
	if err != nil {
		log.Fatalf("api key: %v", err)
	}
	if controlKey == "" && !*insecureAPI {
		log.Fatalf("refusing to start: the control API issues and revokes credentials, and " +
			"no key was given.\n" +
			"  Pass -api-key-file FILE (or -api-key), or -insecure-api if you " +
			"really mean to leave it open.")
	}
	if controlKey == "" {
		log.Printf("WARNING: -insecure-api given. Any process that can reach %s can issue and revoke tokens.", *apiAddr)
	}

	// Sockets systemd may have passed in. With socket activation the broker can
	// be enabled without running: systemd holds the ports and starts this on the
	// first connection.
	activated, err := activation.Listeners()
	if err != nil {
		log.Fatalf("socket activation: %v", err)
	}
	// Taken once, up front, so that what gets logged is where things are
	// actually listening rather than where the flags would have put them.
	proxyListener := activation.Take(activated, "proxy")
	sshListener := activation.Take(activated, "ssh")
	apiListener := activation.Take(activated, "api")
	reportedProxy := listeningOn(proxyListener, *proxyAddr)
	reportedSSH := listeningOn(sshListener, *sshAddr)
	reportedAPI := listeningOn(apiListener, *apiAddr)

	// Initialize OpenTelemetry (configured via OTEL_* env vars)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	otelShutdown, err := telemetry.Init(ctx, "dev")
	if err != nil {
		log.Printf("otel init (tracing disabled): %v", err)
	} else {
		defer func() { _ = otelShutdown(context.Background()) }()
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
	// Credentials the operator registered by name, which a client can ask for
	// without ever holding: it says "anthropic", and the bytes stay here.
	named := credstore.NewNamedStore(*credentialsDir)
	if *useKeyring {
		if keyring := credstore.NewKeyring(0); keyring != nil {
			named.UseKeyring(keyring)
			log.Printf("keyring: resolving credentials from the OS keyring as well")
		} else {
			log.Printf("keyring: -keyring given but secret-tool is not installed; " +
				"install libsecret-tools, or leave credentials in files")
		}
	}
	if directories := named.Directories(); len(directories) > 0 {
		log.Printf("named credentials from %v; %d registered", directories, len(named.Names()))
	}
	certs := credstore.NewCertStore()
	sshKeys := credstore.NewSSHKeyStore()
	pol := policy.NewEngine()

	reaper := &credentialReaper{store: store, creds: creds, certs: certs, sshKeys: sshKeys}
	go reaper.run(ctx, time.Minute)

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

	// Start HTTPS proxy
	passthroughHosts := strings.Split(*passthrough, ",")
	if *passthrough != "" {
		log.Printf("passthrough (no token required): %s", *passthrough)
	}
	p := proxy.New(*proxyAddr, ca, store, creds, certs, pol, auditLog, named, passthroughHosts,
		!*noReuse)
	go func() {
		if proxyListener != nil {
			if err := p.Serve(proxyListener); err != nil {
				log.Fatalf("proxy: %v", err)
			}
			return
		}
		if err := p.ListenAndServe(); err != nil {
			log.Fatalf("proxy: %v", err)
		}
	}()

	// Start SSH bastion
	sshDir := filepath.Join(*dataDir, "ssh")
	knownHostsPath := *knownHosts
	if knownHostsPath == "" {
		knownHostsPath = filepath.Join(sshDir, "known_hosts")
	}
	if *insecureHostKeys {
		log.Printf("WARNING: -ssh-insecure-host-keys given. An upstream host is not authenticated, "+
			"so the private key this bastion holds can be offered to whatever answers %s.", *sshAddr)
	}
	sshServer, err := sshproxy.New(*sshAddr, sshDir, store, sshKeys, auditLog,
		knownHostsPath, *insecureHostKeys)
	if err != nil {
		log.Fatalf("ssh: %v", err)
	}
	go func() {
		if sshListener != nil {
			if err := sshServer.Serve(sshListener); err != nil {
				log.Fatalf("ssh: %v", err)
			}
			return
		}
		if err := sshServer.ListenAndServe(); err != nil {
			log.Fatalf("ssh: %v", err)
		}
	}()

	// Token management API
	mux := http.NewServeMux()
	mux.HandleFunc("POST /tokens", requireAPIKey(controlKey, handleIssueToken(store, creds, certs, sshKeys, auditLog, named)))
	mux.HandleFunc("GET /tokens", requireAPIKey(controlKey, handleListTokens(store)))
	mux.HandleFunc("DELETE /tokens/{token}", requireAPIKey(controlKey, handleRevokeToken(store, auditLog, reaper)))
	mux.HandleFunc("DELETE /tasks/{task_id}/tokens", requireAPIKey(controlKey, handleRevokeByTask(store, auditLog)))
	mux.HandleFunc("GET /policies", requireAPIKey(controlKey, handleListPolicies(pol)))
	// What is registered, by name. Never a value: an operator asking "can the
	// broker use the github credential" should not have to cause an error to find
	// out, which was the only way before this existed.
	mux.HandleFunc("GET /credentials", requireAPIKey(controlKey, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"credentials": named.Names(),
			"sources":     named.Directories(),
			"keyring":     named.KeyringEnabled(),
		})
	}))
	mux.HandleFunc("PUT /credentials/{id}", requireAPIKey(controlKey, handleRotateCredential(creds, store, auditLog)))
	mux.HandleFunc("PUT /credentials/{id}/cert", requireAPIKey(controlKey, handleRotateCert(certs, auditLog)))
	mux.HandleFunc("PUT /credentials/{id}/sshkey", requireAPIKey(controlKey, handleRotateSSHKey(sshKeys, auditLog)))
	mux.HandleFunc("POST /webhooks", requireAPIKey(controlKey, handleRegisterWebhook(auditLog)))
	mux.HandleFunc("GET /events", requireAPIKey(controlKey, sseSink.ServeHTTP))
	// The CA certificate, unauthenticated because it is public by definition:
	// every agent behind this proxy has to trust it, and it is exported
	// world-readable wherever -certs-dir points. Serving it means a client does
	// not have to know where KeyFence keeps its data directory -- which is the
	// sort of thing that goes wrong quietly, as a TLS failure that reads like a
	// network fault.
	mux.HandleFunc("GET /ca", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(ca.CertPEM())
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	log.Printf("api on %s", reportedAPI)
	log.Printf("ssh bastion on %s", reportedSSH)
	log.Printf("ca cert: %s/ca.pem", caDir)
	log.Printf("")
	log.Printf("to use:")
	log.Printf("  export HTTPS_PROXY=http://%s", reportedProxy)
	log.Printf("  export SSL_CERT_FILE=%s/ca.pem", caDir)
	log.Printf("")
	log.Printf("issue a token:")
	log.Printf(`  curl -X POST http://%s/tokens \`, reportedAPI)
	log.Printf(`    -d '{"credential":"sk-ant-...","destinations":["api.anthropic.com"]}'`)

	if apiListener != nil {
		if err := http.Serve(apiListener, mux); err != nil {
			log.Fatalf("api: %v", err)
		}
		return
	}
	if err := http.ListenAndServe(*apiAddr, mux); err != nil {
		log.Fatalf("api: %v", err)
	}
}

// resolveAPIKey answers the control API key, from a file when one is named.
//
// A key on the command line is readable from /proc by every process of this
// user, so a file is the better place for it -- and it is where systemd's
// LoadCredential= puts one, which is why $CREDENTIALS_DIRECTORY is consulted
// without being asked for.
// listeningOn answers where a server will actually be reachable: the activated
// socket's own address when systemd passed one, and otherwise the flag.
func listeningOn(ln net.Listener, addr string) string {
	if ln != nil {
		return ln.Addr().String()
	}
	return addr
}

func resolveAPIKey(key, file string) (string, error) {
	if key != "" && file != "" {
		return "", fmt.Errorf("-api-key and -api-key-file are alternatives; give one")
	}
	if key != "" {
		return key, nil
	}
	if file == "" {
		if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
			candidate := filepath.Join(dir, "api-key")
			if _, err := os.Stat(candidate); err == nil {
				file = candidate
			}
		}
	}
	if file == "" {
		return "", nil
	}
	contents, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", file, err)
	}
	trimmed := strings.TrimSpace(string(contents))
	if trimmed == "" {
		return "", fmt.Errorf("%s is empty", file)
	}
	return trimmed, nil
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
	Credential        string                    `json:"credential"`
	CredentialRef     string                    `json:"credential_ref"`
	Destinations      []string                  `json:"destinations"`
	TTLSeconds        int                       `json:"ttl_seconds"`
	Label             string                    `json:"label"`
	Policy            string                    `json:"policy"`
	AgentID           string                    `json:"agent_id"`
	TaskID            string                    `json:"task_id"`
	RateLimit         int                       `json:"rate_limit"`
	RateWindowSeconds int                       `json:"rate_window_seconds"`
	ClientCert        string                    `json:"client_cert"`
	ClientKey         string                    `json:"client_key"`
	ClientCertHeader  string                    `json:"client_cert_header"`
	SSHPrivateKey     string                    `json:"ssh_private_key"`
	SSHUsername       string                    `json:"ssh_username"`
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

func handleIssueToken(store *tokenstore.Store, creds credstore.Backend, certStore *credstore.CertStore, sshKeyStore *credstore.SSHKeyStore, auditLog *audit.Logger, named *credstore.NamedStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req issueRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"invalid json: %s"}`, err), 400)
			return
		}
		if req.Credential == "" && req.CredentialRef == "" && req.ClientCert == "" && req.SSHPrivateKey == "" {
			http.Error(w, `{"error":"credential, credential_ref, client_cert, or ssh_private_key is required"}`, 400)
			return
		}
		if req.Credential != "" && req.CredentialRef != "" {
			http.Error(w, `{"error":"credential and credential_ref are alternatives; give one"}`, 400)
			return
		}
		// Checked here rather than at request time, so that a mistyped name is a
		// failed issuance the caller sees rather than a 500 the agent sees later.
		if req.CredentialRef != "" && !named.Has(req.CredentialRef) {
			body, _ := json.Marshal(map[string]any{
				"error":     fmt.Sprintf("no credential named %q is registered", req.CredentialRef),
				"available": named.Names(),
			})
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(400)
			_, _ = w.Write(body)
			return
		}
		// A token is worth having because it is worth less than the credential
		// behind it. One with no destinations is worth exactly as much, so that
		// has to be asked for rather than defaulted into by leaving a field out.
		if len(req.Destinations) == 0 {
			http.Error(w, `{"error":"destinations is required; pass [\"*\"] to issue a token that works anywhere"}`, 400)
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
			CredentialRef:       req.CredentialRef,
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
		_ = json.NewEncoder(w).Encode(issueResponse{
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
		_ = json.NewEncoder(w).Encode(result)
	}
}

// credentialReaper forgets credential material nothing valid refers to any more.
//
// A token issued with a credential in the request body causes those bytes to be
// stored here. Revoking the token marked it unusable but left the bytes, so a
// broker that ran for a week held every secret it had ever been handed -- exactly
// the accumulation it exists to prevent. This is the other half of the fix: once
// no valid token needs them, they go.
//
// The token record itself survives an explicit revoke, so that using a revoked
// token still says "revoked" rather than "never heard of it". It is the periodic
// pass that eventually forgets the record too.
type credentialReaper struct {
	store   *tokenstore.Store
	creds   credstore.Backend
	certs   *credstore.CertStore
	sshKeys *credstore.SSHKeyStore
}

// forget drops whatever the given tokens were the last reason to keep.
func (r *credentialReaper) forget(tokens ...*tokenstore.Token) {
	for _, t := range tokens {
		if t == nil {
			continue
		}
		if t.CredentialID != "" && r.store.CountByCredentialID(t.CredentialID) == 0 {
			if err := r.creds.Delete(t.CredentialID); err != nil {
				log.Printf("forgetting credential %s: %v", t.CredentialID, err)
			}
		}
		if t.ClientCertID != "" && r.store.CountByClientCertID(t.ClientCertID) == 0 {
			_ = r.certs.Delete(t.ClientCertID)
		}
		if t.SSHKeyID != "" && r.store.CountBySSHKeyID(t.SSHKeyID) == 0 {
			_ = r.sshKeys.Delete(t.SSHKeyID)
		}
	}
}

// sweep removes expired and revoked tokens, then forgets what they held.
func (r *credentialReaper) sweep() {
	r.forget(r.store.Cleanup()...)
}

// run sweeps on a timer for as long as KeyFence is running. Without this, an
// expired token is never noticed by anything -- Cleanup existed and nobody
// called it -- so both the record and its credential stayed until restart.
func (r *credentialReaper) run(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.sweep()
		}
	}
}

func handleRevokeToken(store *tokenstore.Store, auditLog *audit.Logger, reaper *credentialReaper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenValue := r.PathValue("token")
		revoked := store.Lookup(tokenValue)
		if store.Revoke(tokenValue) {
			// At once, not at the next sweep: a revoked credential that lingers
			// is a credential still usable by whoever copied it.
			reaper.forget(revoked)
			auditLog.Log(audit.Entry{
				Event:   audit.EventRevoke,
				TokenID: tokenValue,
			})
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
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
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "revoked", "count": count})
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
			http.Error(w, `{"error":"unauthorized: invalid or missing api key"}`, http.StatusUnauthorized)
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
		_ = json.NewEncoder(w).Encode(result)
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
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
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
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "rotated", "credential_id": id})
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
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "rotated", "credential_id": id})
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
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "registered", "url": req.URL})
	}
}
