// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@moxielogic.com>

package tokenstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// storeFormat is written into every file so a future change of shape can be
// recognised rather than guessed at.
const storeFormat = 1

// ValueHash answers the key a token is filed under: the full SHA-256 of its
// value.
//
// It is what makes the store on disk safe to keep. A hash recognises a token
// somebody else presents and cannot be presented as one, so a file that holds
// only hashes grants nothing to whoever reads it -- unlike the token values
// themselves, which are bearer credentials and are never written down.
//
// Token.ID is the first eight bytes of the same digest, which is enough to name
// a token in a log without naming the secret, and too short to file it under.
func ValueHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// persistedToken carries the fields a Token keeps to itself. The rest travel by
// the alias below, so a field added to Token is persisted without anybody
// having to remember to add it here -- forgetting would mean a grant that
// quietly changes shape across a restart.
type persistedToken struct {
	// Named rather than embedded: encoding/json will happily write an embedded
	// pointer to an unexported type and then refuse to allocate one when
	// reading it back.
	Grant     *tokenFields `json:"grant"`
	ValueHash string       `json:"value_hash"`
	RateCount int          `json:"rate_count"`
	RateStart time.Time    `json:"rate_start"`
	Requests  int          `json:"requests"`
}

// tokenFields is Token without its methods, which is what keeps encoding/json
// from calling back into whatever Token might one day marshal itself with.
type tokenFields Token

type storeFile struct {
	Format int               `json:"format"`
	Tokens []*persistedToken `json:"tokens"`
}

// LoadOrCreate opens the token store kept at path, reading back whatever a
// previous process left there.
//
// This is what keeps a restart from stranding an agent. A token was handed to
// the agent in its environment at launch and nothing can replace it in a
// running process, so a broker that forgets its tokens does not inconvenience
// the agent -- it ends it, mid-task, with no way back. The CA already survives
// a restart; this is the rest of the connection catching up.
func LoadOrCreate(path string) (*Store, error) {
	store := New()
	store.path = path

	contents, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading token store: %w", err)
	}

	var file storeFile
	if err := json.Unmarshal(contents, &file); err != nil {
		return nil, fmt.Errorf("parsing token store %s: %w", path, err)
	}
	if file.Format != storeFormat {
		return nil, fmt.Errorf("token store %s is format %d, this build reads %d", path, file.Format, storeFormat)
	}

	for _, record := range file.Tokens {
		if record == nil || record.Grant == nil {
			continue
		}
		token := (*Token)(record.Grant)
		token.rateCount = record.RateCount
		token.rateStart = record.RateStart
		token.requests = record.Requests
		if token.RuleState == nil {
			token.RuleState = make(map[string]interface{})
		}
		store.tokens[record.ValueHash] = token
		store.tokensByID[token.ID] = token
	}
	return store, nil
}

// Flush writes the store out if anything has changed since it was last
// written. Counters move on every request, which is too often to write, so they
// ride along with the next structural change or with a periodic call to this.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	return s.writeLocked()
}

// writeLocked writes the whole store to disk, the caller holding s.mu.
//
// Whole, rather than incrementally: the store holds tens of tokens, not
// thousands, and a rewrite that lands by rename is a file that is either the
// old one or the new one and never a half of each.
func (s *Store) writeLocked() error {
	if s.path == "" {
		s.dirty = false
		return nil
	}

	file := storeFile{Format: storeFormat, Tokens: make([]*persistedToken, 0, len(s.tokens))}
	for hash, token := range s.tokens {
		file.Tokens = append(file.Tokens, &persistedToken{
			Grant:     (*tokenFields)(token),
			ValueHash: hash,
			RateCount: token.rateCount,
			RateStart: token.rateStart,
			Requests:  token.requests,
		})
	}

	encoded, err := json.Marshal(file)
	if err != nil {
		return fmt.Errorf("encoding token store: %w", err)
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	temporary, err := os.CreateTemp(dir, ".tokens-*")
	if err != nil {
		return fmt.Errorf("creating a temporary token store: %w", err)
	}
	defer os.Remove(temporary.Name())

	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("setting token store mode: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return fmt.Errorf("writing token store: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("syncing token store: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("closing token store: %w", err)
	}
	if err := os.Rename(temporary.Name(), s.path); err != nil {
		return fmt.Errorf("replacing token store: %w", err)
	}

	s.dirty = false
	return nil
}

// touchLocked records that something changed without writing it out. Used by
// the per-request counters, which move far too often to write each time.
func (s *Store) touchLocked() { s.dirty = true }

// persistLocked records a change and writes it out at once, for the changes
// that must survive a crash the moment they are made: a token issued, a token
// revoked, a token reaped. A failure leaves the store dirty so the next Flush
// tries again.
func (s *Store) persistLocked() error {
	s.dirty = true
	return s.writeLocked()
}

// FlushEvery writes the store out at each tick until ctx's channel closes,
// carrying the request counters to disk between structural changes. Errors go
// to report, which may be nil.
func (s *Store) FlushEvery(done <-chan struct{}, every time.Duration, report func(error)) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			if err := s.Flush(); err != nil && report != nil {
				report(err)
			}
			return
		case <-ticker.C:
			if err := s.Flush(); err != nil && report != nil {
				report(err)
			}
		}
	}
}
