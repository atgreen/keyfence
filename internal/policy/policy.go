// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@redhat.com>

// Package policy implements per-request policy evaluation for KeyFence.
//
// Policies govern what a token is allowed to do beyond basic destination
// checks: HTTP method and path restrictions, rate limits, per-token request
// budgets, and body size limits.
package policy

import (
	"fmt"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"
)

// Policy defines restrictions applied to requests using a specific token.
type Policy struct {
	Name string

	// Method restrictions. Empty = allow all.
	AllowedMethods []string

	// Path restrictions. Supports glob patterns (e.g., "/v1/*").
	// Empty = allow all.
	AllowedPaths []string
	DeniedPaths  []string

	// Rate limiting.
	RateLimit    int           // max requests per window; 0 = unlimited
	RateWindow   time.Duration // window duration

	// Per-token request budget. 0 = unlimited.
	MaxRequests int

	// Body size limit. 0 = unlimited.
	MaxBodyBytes int64

	// Allowed content types. Empty = allow all.
	AllowedContentTypes []string
}

// Deny is returned when a policy check fails.
type Deny struct {
	Rule    string // which rule triggered the deny
	Message string
}

func (d *Deny) Error() string {
	return fmt.Sprintf("policy deny [%s]: %s", d.Rule, d.Message)
}

// Engine evaluates policies against requests.
type Engine struct {
	mu       sync.RWMutex
	policies map[string]*Policy // policy name → policy

	// Rate limit state: token ID → window state
	rateMu sync.Mutex
	rates  map[string]*rateState

	// Request budget state: token ID → count
	budgetMu sync.Mutex
	budgets  map[string]int
}

type rateState struct {
	count      int
	windowStart time.Time
}

func NewEngine() *Engine {
	return &Engine{
		policies: make(map[string]*Policy),
		rates:    make(map[string]*rateState),
		budgets:  make(map[string]int),
	}
}

// Register adds or replaces a policy.
func (e *Engine) Register(p *Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies[p.Name] = p
}

// Get returns a policy by name.
func (e *Engine) Get(name string) *Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.policies[name]
}

// Check evaluates a request against a named policy.
// Returns nil if allowed, or a *Deny if rejected.
// If policyName is empty, the request is allowed (no policy = open).
func (e *Engine) Check(policyName string, tokenID string, req *http.Request) *Deny {
	if policyName == "" {
		return nil
	}

	p := e.Get(policyName)
	if p == nil {
		return nil // unknown policy = open
	}

	if deny := p.checkMethod(req.Method); deny != nil {
		return deny
	}
	if deny := p.checkPath(req.URL.Path); deny != nil {
		return deny
	}
	if deny := p.checkContentType(req); deny != nil {
		return deny
	}
	if deny := p.checkBodySize(req); deny != nil {
		return deny
	}
	if deny := e.checkRateLimit(p, tokenID); deny != nil {
		return deny
	}
	if deny := e.checkBudget(p, tokenID); deny != nil {
		return deny
	}

	return nil
}

func (p *Policy) checkMethod(method string) *Deny {
	if len(p.AllowedMethods) == 0 {
		return nil
	}
	for _, m := range p.AllowedMethods {
		if strings.EqualFold(m, method) {
			return nil
		}
	}
	return &Deny{
		Rule:    "methods",
		Message: fmt.Sprintf("method %s not allowed", method),
	}
}

func (p *Policy) checkPath(reqPath string) *Deny {
	// Check denied paths first (deny takes precedence)
	for _, pattern := range p.DeniedPaths {
		if matchPath(pattern, reqPath) {
			return &Deny{
				Rule:    "paths.deny",
				Message: fmt.Sprintf("path %s is denied", reqPath),
			}
		}
	}

	// If no allowed paths, everything is allowed
	if len(p.AllowedPaths) == 0 {
		return nil
	}

	for _, pattern := range p.AllowedPaths {
		if matchPath(pattern, reqPath) {
			return nil
		}
	}
	return &Deny{
		Rule:    "paths.allow",
		Message: fmt.Sprintf("path %s not allowed", reqPath),
	}
}

func matchPath(pattern, reqPath string) bool {
	// Support trailing wildcard: "/v1/*" matches "/v1/messages", "/v1/models", etc.
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return reqPath == prefix || strings.HasPrefix(reqPath, prefix+"/")
	}
	matched, _ := path.Match(pattern, reqPath)
	return matched
}

func (p *Policy) checkContentType(req *http.Request) *Deny {
	if len(p.AllowedContentTypes) == 0 {
		return nil
	}
	ct := req.Header.Get("Content-Type")
	if ct == "" {
		return nil // no body = no content type to check
	}
	// Strip parameters (e.g., "application/json; charset=utf-8" → "application/json")
	if idx := strings.IndexByte(ct, ';'); idx >= 0 {
		ct = strings.TrimSpace(ct[:idx])
	}
	for _, allowed := range p.AllowedContentTypes {
		if strings.EqualFold(allowed, ct) {
			return nil
		}
	}
	return &Deny{
		Rule:    "content_type",
		Message: fmt.Sprintf("content type %s not allowed", ct),
	}
}

func (p *Policy) checkBodySize(req *http.Request) *Deny {
	if p.MaxBodyBytes <= 0 {
		return nil
	}
	if req.ContentLength > p.MaxBodyBytes {
		return &Deny{
			Rule:    "max_body_bytes",
			Message: fmt.Sprintf("body size %d exceeds limit %d", req.ContentLength, p.MaxBodyBytes),
		}
	}
	return nil
}

func (e *Engine) checkRateLimit(p *Policy, tokenID string) *Deny {
	if p.RateLimit <= 0 || p.RateWindow <= 0 {
		return nil
	}

	e.rateMu.Lock()
	defer e.rateMu.Unlock()

	now := time.Now()
	key := tokenID + ":" + p.Name

	state, ok := e.rates[key]
	if !ok || now.Sub(state.windowStart) >= p.RateWindow {
		e.rates[key] = &rateState{count: 1, windowStart: now}
		return nil
	}

	state.count++
	if state.count > p.RateLimit {
		return &Deny{
			Rule:    "rate_limit",
			Message: fmt.Sprintf("rate limit exceeded: %d requests in %s", p.RateLimit, p.RateWindow),
		}
	}
	return nil
}

func (e *Engine) checkBudget(p *Policy, tokenID string) *Deny {
	if p.MaxRequests <= 0 {
		return nil
	}

	e.budgetMu.Lock()
	defer e.budgetMu.Unlock()

	e.budgets[tokenID]++
	if e.budgets[tokenID] > p.MaxRequests {
		return &Deny{
			Rule:    "max_requests",
			Message: fmt.Sprintf("request budget exhausted: %d requests", p.MaxRequests),
		}
	}
	return nil
}
