// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@moxielogic.com>

// Package tokenstore manages KeyFence tokens and their mappings to credentials.
//
// Tokens do not hold raw credential values. They hold a CredentialID that
// references a credential in the credential backend. The proxy fetches the
// real value from the backend at request time.
package tokenstore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"
)

type Token struct {
	ID                  string
	Value               string                 `json:"-"` // kf_<random>, never stored
	ParentID            string                 // public ID of the token this one was derived from
	RootID              string                 // public ID at the root of the delegation chain
	CredentialID        string                 // reference into credential backend
	CredentialRef       string                 // name of an operator-registered credential
	AllowedDestinations []string               // hosts or host/path patterns this token can be used against
	PolicyName          string                 // optional policy to evaluate on each request
	AgentID             string                 // orchestrator-assigned agent identity
	TaskID              string                 // orchestrator-assigned task scope
	RateLimit           int                    // max requests per window; 0 = unlimited
	RateWindow          time.Duration          // window duration
	MaxRequests         int                    // max requests over the token's life; 0 = unlimited
	AllowedMethods      []string               // optional per-token HTTP method restriction
	AllowedPaths        []string               // optional per-token HTTP path restriction
	DeniedPaths         []string               // per-token HTTP paths denied in addition to its policy
	ClientCertID        string                 // reference to cert+key in cert store
	ClientCertHeader    string                 // header to inject cert PEM into (optional)
	SSHKeyID            string                 // reference to SSH key in SSH key store
	ResponseRules       []ResponseRule         // Lua scripts evaluated against each response
	RuleState           map[string]interface{} // mutable state persisted across requests
	RuleStateMu         sync.Mutex             `json:"-"` // protects RuleState
	CreatedAt           time.Time
	ExpiresAt           time.Time
	Label               string // optional human-readable label
	RenewalSeq          int
	Revoked             bool

	// rate tracking (internal)
	rateCount int
	rateStart time.Time
	requests  int
}

func (t *Token) IsValid() bool {
	if t.Revoked {
		return false
	}
	return time.Now().Before(t.ExpiresAt)
}

// RootTokenID answers the public ID used to account for a whole delegation
// lineage. Root tokens predate the explicit RootID field, so their own ID is
// the root.
func (t *Token) RootTokenID() string {
	if t.RootID != "" {
		return t.RootID
	}
	return t.ID
}

// AnyDestination is the destination entry that means "anywhere". A token
// carrying it is a second copy of the credential it stands for, usable against
// any host the proxy can reach, so it has to be asked for by name: an empty
// destination list is not a way to spell it.
const AnyDestination = "*"

// AllowsAnyDestination answers whether this token was deliberately issued
// without a destination lock.
func (t *Token) AllowsAnyDestination() bool {
	for _, d := range t.AllowedDestinations {
		if d == AnyDestination {
			return true
		}
	}
	return false
}

// IsDestinationAllowed checks whether a request to host+path is permitted.
// Destination entries can be:
//   - "api.example.com"          — host only (matches all paths)
//   - "api.example.com/v1/chat"  — host + exact path
//   - "api.example.com/v1/*"     — host + path glob
//   - "*"                        — anywhere, which must be asked for explicitly
//
// A token with no destinations at all permits nothing. The point of a token is
// that it is worth less than the credential behind it, and a token that works
// everywhere is worth exactly as much -- so if it is going to be that, someone
// has to have said so.
func (t *Token) IsDestinationAllowed(host, reqPath string) bool {
	if len(t.AllowedDestinations) == 0 {
		return false
	}
	for _, d := range t.AllowedDestinations {
		if d == AnyDestination {
			return true
		}
		dHost, dPath := splitDestination(d)
		if dHost != host {
			continue
		}
		if dPath == "" {
			return true // host-only entry matches all paths
		}
		if matchPath(dPath, reqPath) {
			return true
		}
	}
	return false
}

func splitDestination(entry string) (host, pathPattern string) {
	idx := strings.Index(entry, "/")
	if idx == -1 {
		return entry, ""
	}
	return entry[:idx], entry[idx:]
}

func matchPath(pattern, reqPath string) bool {
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return reqPath == prefix || strings.HasPrefix(reqPath, prefix+"/")
	}
	matched, _ := path.Match(pattern, reqPath)
	return matched
}

// DestinationsAreSubset conservatively proves that every child destination is
// contained by a parent destination. Patterns it cannot prove safe are accepted
// only when identical; attenuation may reject a useful glob, but never widens a
// capability by guessing about one.
func DestinationsAreSubset(parent, child []string) bool {
	if len(parent) == 0 {
		return false
	}
	for _, childDestination := range child {
		contained := false
		for _, parentDestination := range parent {
			if destinationContains(parentDestination, childDestination) {
				contained = true
				break
			}
		}
		if !contained {
			return false
		}
	}
	return true
}

func destinationContains(parent, child string) bool {
	if parent == AnyDestination || parent == child {
		return true
	}
	if child == AnyDestination {
		return false
	}
	parentHost, parentPath := splitDestination(parent)
	childHost, childPath := splitDestination(child)
	if parentHost != childHost {
		return false
	}
	if parentPath == "" {
		return true
	}
	if childPath == "" {
		return false
	}
	return patternContains(parentPath, childPath)
}

// PatternsAreSubset applies the same conservative containment rules to HTTP
// path patterns. An empty parent list means unrestricted and contains any
// non-empty child restriction.
func PatternsAreSubset(parent, child []string) bool {
	if len(parent) == 0 {
		return true
	}
	for _, childPattern := range child {
		contained := false
		for _, parentPattern := range parent {
			if patternContains(parentPattern, childPattern) {
				contained = true
				break
			}
		}
		if !contained {
			return false
		}
	}
	return true
}

func patternContains(parent, child string) bool {
	if parent == child {
		return true
	}
	if !strings.HasSuffix(parent, "/*") {
		return false
	}
	prefix := strings.TrimSuffix(parent, "/*")
	return child == prefix || strings.HasPrefix(child, prefix+"/")
}

// MethodsAreSubset compares HTTP method sets case-insensitively. An empty
// parent set means unrestricted.
func MethodsAreSubset(parent, child []string) bool {
	return stringsAreSubsetFold(parent, child)
}

func stringsAreSubsetFold(parent, child []string) bool {
	if len(parent) == 0 {
		return true
	}
	for _, candidate := range child {
		found := false
		for _, allowed := range parent {
			if strings.EqualFold(candidate, allowed) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// ResponseRule is a Lua script evaluated against JSON responses.
type ResponseRule struct {
	Script string `json:"script"`
}

type Store struct {
	mu         sync.RWMutex
	tokens     map[string]*Token // keyed by ValueHash of the token value
	tokensByID map[string]*Token // keyed by public, non-secret token ID

	// path is where the store is kept between runs; empty means in memory
	// only, which is what New gives a caller that does not want a file.
	path  string
	dirty bool
}

func New() *Store {
	return &Store{
		tokens:     make(map[string]*Token),
		tokensByID: make(map[string]*Token),
	}
}

// IssueParams holds all parameters for token issuance.
type IssueParams struct {
	CredentialID        string
	CredentialRef       string
	AllowedDestinations []string
	TTL                 time.Duration
	Label               string
	PolicyName          string
	AgentID             string
	TaskID              string
	RateLimit           int
	RateWindow          time.Duration
	MaxRequests         int
	AllowedMethods      []string
	AllowedPaths        []string
	DeniedPaths         []string
	ClientCertID        string
	ClientCertHeader    string
	SSHKeyID            string
	ResponseRules       []ResponseRule
}

// tokenID answers the stable, public identifier for a token value.
func tokenID(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

func (s *Store) Issue(p IssueParams) (*Token, error) {
	token, err := newToken(p, time.Now(), "", "")
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.tokens[ValueHash(token.Value)] = token
	s.tokensByID[token.ID] = token
	err = s.persistLocked()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}

	return token, nil
}

func newToken(p IssueParams, now time.Time, parentID, rootID string) (*Token, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return nil, fmt.Errorf("generating random bytes: %w", err)
	}

	value := "kf_" + hex.EncodeToString(random)
	return &Token{
		// Derived from the value by hashing rather than taken from it. The id was
		// the first eight of the sixteen random bytes, so every audit entry
		// naming a token handed out half of it -- and the audit trail is the one
		// thing here designed to be copied elsewhere, into a webhook, an SSE
		// subscriber or a log aggregator. A hash identifies the token to anyone
		// holding it and tells anyone else nothing.
		ID:                  tokenID(value),
		Value:               value,
		ParentID:            parentID,
		RootID:              rootID,
		CredentialID:        p.CredentialID,
		CredentialRef:       p.CredentialRef,
		AllowedDestinations: append([]string(nil), p.AllowedDestinations...),
		PolicyName:          p.PolicyName,
		AgentID:             p.AgentID,
		TaskID:              p.TaskID,
		RateLimit:           p.RateLimit,
		RateWindow:          p.RateWindow,
		MaxRequests:         p.MaxRequests,
		AllowedMethods:      append([]string(nil), p.AllowedMethods...),
		AllowedPaths:        append([]string(nil), p.AllowedPaths...),
		DeniedPaths:         append([]string(nil), p.DeniedPaths...),
		ClientCertID:        p.ClientCertID,
		ClientCertHeader:    p.ClientCertHeader,
		SSHKeyID:            p.SSHKeyID,
		ResponseRules:       append([]ResponseRule(nil), p.ResponseRules...),
		RuleState:           make(map[string]interface{}),
		CreatedAt:           now,
		ExpiresAt:           now.Add(p.TTL),
		Label:               p.Label,
	}, nil
}

// ChildParams contains only fields a delegated token is allowed to narrow.
// Nil slices and pointers inherit the corresponding parent restriction.
type ChildParams struct {
	AllowedDestinations []string
	TTL                 time.Duration
	Label               string
	AllowedMethods      []string
	AllowedPaths        []string
	DeniedPaths         []string
	RateLimit           *int
	RateWindow          *time.Duration
	MaxRequests         *int
}

// AttenuationError reports a requested child restriction that would widen or
// otherwise fail to meaningfully describe a child capability.
type AttenuationError struct {
	Reason string
}

func (e *AttenuationError) Error() string { return e.Reason }

// IssueChild derives a token that refers to the same credential material as a
// valid parent but can only reduce its authority.
func (s *Store) IssueChild(parentValue string, child ChildParams) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	parent := s.tokens[ValueHash(parentValue)]
	if parent == nil || !s.isValidLocked(parent) {
		return nil, &AttenuationError{Reason: "parent token is invalid or expired"}
	}

	destinations := child.AllowedDestinations
	if destinations == nil {
		destinations = parent.AllowedDestinations
	}
	if len(destinations) == 0 {
		return nil, &AttenuationError{Reason: "a child token must have at least one destination"}
	}
	if !DestinationsAreSubset(parent.AllowedDestinations, destinations) {
		return nil, &AttenuationError{Reason: "child destinations are not a subset of the parent"}
	}

	methods := child.AllowedMethods
	if methods == nil {
		methods = parent.AllowedMethods
	} else if len(methods) == 0 {
		return nil, &AttenuationError{Reason: "allowed_methods cannot be empty"}
	}
	if !stringsAreSubsetFold(parent.AllowedMethods, methods) {
		return nil, &AttenuationError{Reason: "child methods are not a subset of the parent"}
	}

	paths := child.AllowedPaths
	if paths == nil {
		paths = parent.AllowedPaths
	} else if len(paths) == 0 {
		return nil, &AttenuationError{Reason: "allowed_paths cannot be empty"}
	}
	if !PatternsAreSubset(parent.AllowedPaths, paths) {
		return nil, &AttenuationError{Reason: "child paths are not a subset of the parent"}
	}

	rateLimit := parent.RateLimit
	rateWindow := parent.RateWindow
	if child.RateLimit == nil && child.RateWindow != nil {
		return nil, &AttenuationError{Reason: "rate_window_seconds requires rate_limit"}
	}
	if child.RateLimit != nil {
		if *child.RateLimit <= 0 {
			return nil, &AttenuationError{Reason: "rate_limit must be positive"}
		}
		if child.RateWindow != nil {
			rateWindow = *child.RateWindow
		} else if parent.RateLimit == 0 {
			return nil, &AttenuationError{Reason: "rate_window_seconds is required when the parent has no rate limit"}
		}
		if rateWindow <= 0 {
			return nil, &AttenuationError{Reason: "rate_window_seconds must be positive"}
		}
		if parent.RateLimit > 0 && (*child.RateLimit > parent.RateLimit || rateWindow != parent.RateWindow) {
			return nil, &AttenuationError{Reason: "child rate must use the parent's window and cannot exceed its limit"}
		}
		rateLimit = *child.RateLimit
	}

	maxRequests := parent.MaxRequests
	if child.MaxRequests != nil {
		if *child.MaxRequests <= 0 {
			return nil, &AttenuationError{Reason: "max_requests must be positive"}
		}
		if parent.MaxRequests > 0 && *child.MaxRequests > parent.MaxRequests {
			return nil, &AttenuationError{Reason: "child request budget cannot exceed the parent"}
		}
		maxRequests = *child.MaxRequests
	}

	now := time.Now()
	expiresAt := parent.ExpiresAt
	if child.TTL > 0 {
		expiresAt = now.Add(child.TTL)
		if expiresAt.After(parent.ExpiresAt) {
			return nil, &AttenuationError{Reason: "child TTL cannot outlive the parent"}
		}
	}

	rootID := parent.RootID
	if rootID == "" {
		rootID = parent.ID
	}
	params := IssueParams{
		CredentialID:        parent.CredentialID,
		CredentialRef:       parent.CredentialRef,
		AllowedDestinations: append([]string(nil), destinations...),
		TTL:                 expiresAt.Sub(now),
		Label:               child.Label,
		PolicyName:          parent.PolicyName,
		AgentID:             parent.AgentID,
		TaskID:              parent.TaskID,
		RateLimit:           rateLimit,
		RateWindow:          rateWindow,
		MaxRequests:         maxRequests,
		AllowedMethods:      append([]string(nil), methods...),
		AllowedPaths:        append([]string(nil), paths...),
		DeniedPaths:         append(append([]string(nil), parent.DeniedPaths...), child.DeniedPaths...),
		ClientCertID:        parent.ClientCertID,
		ClientCertHeader:    parent.ClientCertHeader,
		SSHKeyID:            parent.SSHKeyID,
		ResponseRules:       append([]ResponseRule(nil), parent.ResponseRules...),
	}
	token, err := newToken(params, now, parent.ID, rootID)
	if err != nil {
		return nil, err
	}
	s.tokens[ValueHash(token.Value)] = token
	s.tokensByID[token.ID] = token
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return token, nil
}

// Lookup answers the token record whether or not it is still usable, which is
// what a caller cleaning up after a token needs: Resolve deliberately answers
// nothing for a token that has expired or been revoked.
func (s *Store) Lookup(tokenValue string) *Token {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tokens[ValueHash(tokenValue)]
}

func (s *Store) Resolve(tokenValue string) *Token {
	s.mu.RLock()
	defer s.mu.RUnlock()

	t, ok := s.tokens[ValueHash(tokenValue)]
	if !ok {
		return nil
	}
	if !s.isValidLocked(t) {
		return nil
	}
	return t
}

func (s *Store) isValidLocked(token *Token) bool {
	seen := make(map[string]struct{})
	for token != nil {
		if !token.IsValid() {
			return false
		}
		if token.ParentID == "" {
			return true
		}
		if _, duplicate := seen[token.ID]; duplicate {
			return false
		}
		seen[token.ID] = struct{}{}
		token = s.tokensByID[token.ParentID]
	}
	return false
}

func (s *Store) Revoke(tokenValue string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.tokens[ValueHash(tokenValue)]
	if !ok {
		return false
	}
	t.Revoked = true
	s.revokeDescendantsLocked(t.ID)
	_ = s.persistLocked()
	return true
}

func (s *Store) revokeDescendantsLocked(parentID string) {
	parents := []string{parentID}
	for len(parents) > 0 {
		current := parents[0]
		parents = parents[1:]
		for _, candidate := range s.tokens {
			if candidate.ParentID != current {
				continue
			}
			candidate.Revoked = true
			parents = append(parents, candidate.ID)
		}
	}
}

// RevokeByTaskID revokes all tokens for a given task. Returns the count revoked.
func (s *Store) RevokeByTaskID(taskID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for _, t := range s.tokens {
		if t.TaskID == taskID && !t.Revoked {
			t.Revoked = true
			count++
		}
	}
	for _, t := range s.tokens {
		if t.TaskID == taskID {
			s.revokeDescendantsLocked(t.ID)
		}
	}
	if count > 0 {
		_ = s.persistLocked()
	}
	return count
}

func (s *Store) List() []*Token {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Token, 0, len(s.tokens))
	for _, t := range s.tokens {
		result = append(result, t)
	}
	return result
}

// CountByCredentialID returns the number of valid tokens referencing a credential.
func (s *Store) CountByCredentialID(credID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, t := range s.tokens {
		if s.isValidLocked(t) && t.CredentialID == credID {
			count++
		}
	}
	return count
}

// CheckRate evaluates the token's per-token rate limit.
// Returns true if the request is allowed, false if rate-limited.
// A token with RateLimit <= 0 always allows.
func (s *Store) CheckRate(tokenValue string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.tokens[ValueHash(tokenValue)]
	if !ok || !s.isValidLocked(t) {
		return false
	}
	now := time.Now()
	allowed := true
	for current := t; current != nil; current = s.tokensByID[current.ParentID] {
		if current.RateLimit <= 0 {
			continue
		}
		s.touchLocked()
		if current.rateStart.IsZero() || now.Sub(current.rateStart) >= current.RateWindow {
			current.rateCount = 1
			current.rateStart = now
			continue
		}
		current.rateCount++
		if current.rateCount > current.RateLimit {
			allowed = false
		}
	}
	return allowed
}

// CheckBudget consumes one request from a token and every ancestor budget.
// Charging the whole chain prevents deriving children from multiplying the
// number of requests their parent capability authorized.
func (s *Store) CheckBudget(tokenValue string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.tokens[ValueHash(tokenValue)]
	if !ok || !s.isValidLocked(t) {
		return false
	}
	allowed := true
	for current := t; current != nil; current = s.tokensByID[current.ParentID] {
		if current.MaxRequests <= 0 {
			continue
		}
		current.requests++
		s.touchLocked()
		if current.requests > current.MaxRequests {
			allowed = false
		}
	}
	return allowed
}

// Cleanup removes expired and revoked tokens and answers what it removed, so
// that a caller can forget the credentials they were the last reason to keep.
func (s *Store) Cleanup() []*Token {
	s.mu.Lock()
	defer s.mu.Unlock()

	var removed []*Token
	invalid := make(map[string]bool)
	for key, t := range s.tokens {
		invalid[key] = !s.isValidLocked(t)
	}
	for k, t := range s.tokens {
		if invalid[k] {
			delete(s.tokens, k)
			delete(s.tokensByID, t.ID)
			removed = append(removed, t)
		}
	}
	if len(removed) > 0 {
		_ = s.persistLocked()
	}
	return removed
}

// CountByClientCertID returns the number of valid tokens using a client cert.
func (s *Store) CountByClientCertID(certID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, t := range s.tokens {
		if s.isValidLocked(t) && t.ClientCertID == certID {
			count++
		}
	}
	return count
}

// CountBySSHKeyID returns the number of valid tokens using an SSH key.
func (s *Store) CountBySSHKeyID(keyID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, t := range s.tokens {
		if s.isValidLocked(t) && t.SSHKeyID == keyID {
			count++
		}
	}
	return count
}

// CountByRootID returns the number of valid tokens in a delegation lineage.
func (s *Store) CountByRootID(rootID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, t := range s.tokens {
		if t.RootTokenID() == rootID && s.isValidLocked(t) {
			count++
		}
	}
	return count
}
