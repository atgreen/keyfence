// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@redhat.com>

package audit

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

// SSESink fans out audit entries to connected SSE clients.
type SSESink struct {
	mu      sync.RWMutex
	clients map[uint64]chan Entry
	seq     uint64
}

// NewSSESink creates an SSE fan-out sink.
func NewSSESink() *SSESink {
	return &SSESink{
		clients: make(map[uint64]chan Entry),
	}
}

func (s *SSESink) Send(e Entry) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, ch := range s.clients {
		select {
		case ch <- e:
		default:
			// slow client, drop
		}
	}
}

func (s *SSESink) addClient() (uint64, chan Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	id := s.seq
	ch := make(chan Entry, 100)
	s.clients[id] = ch
	return id, ch
}

func (s *SSESink) removeClient(id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch, ok := s.clients[id]; ok {
		close(ch)
		delete(s.clients, id)
	}
}

// ServeHTTP is the SSE endpoint handler. Each connected client receives
// a stream of audit entries as server-sent events.
func (s *SSESink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", 500)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(200)
	flusher.Flush()

	clientID, ch := s.addClient()
	defer s.removeClient(clientID)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(e)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}
