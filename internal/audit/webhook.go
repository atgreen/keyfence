// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@redhat.com>

package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// WebhookSink sends audit entries to an HTTP endpoint.
// Entries are queued and delivered asynchronously. If the queue is full,
// entries are dropped (the proxy is never blocked by a slow webhook).
type WebhookSink struct {
	URL    string
	Secret string // HMAC-SHA256 signing key; empty = no signature
	Events map[string]bool // filter; nil = all events
	queue  chan Entry
	client *http.Client
	done   chan struct{}
}

// NewWebhookSink creates a webhook sink. Start its background goroutine
// by calling Run().
func NewWebhookSink(url, secret string, events []string) *WebhookSink {
	w := &WebhookSink{
		URL:    url,
		Secret: secret,
		queue:  make(chan Entry, 1000),
		client: &http.Client{Timeout: 10 * time.Second},
		done:   make(chan struct{}),
	}
	if len(events) > 0 {
		w.Events = make(map[string]bool, len(events))
		for _, e := range events {
			w.Events[e] = true
		}
	}
	return w
}

func (w *WebhookSink) Send(e Entry) {
	if w.Events != nil && !w.Events[e.Event] {
		return
	}
	select {
	case w.queue <- e:
	default:
		// queue full, drop
	}
}

// Run processes the queue until Close is called.
func (w *WebhookSink) Run() {
	for {
		select {
		case e := <-w.queue:
			w.deliver(e)
		case <-w.done:
			// drain remaining
			for {
				select {
				case e := <-w.queue:
					w.deliver(e)
				default:
					return
				}
			}
		}
	}
}

// Close signals the background goroutine to drain and stop.
func (w *WebhookSink) Close() {
	close(w.done)
}

func (w *WebhookSink) deliver(e Entry) {
	body, err := json.Marshal(e)
	if err != nil {
		return
	}

	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}

		req, err := http.NewRequest("POST", w.URL, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")

		if w.Secret != "" {
			mac := hmac.New(sha256.New, []byte(w.Secret))
			mac.Write(body)
			req.Header.Set("X-KeyFence-Signature", hex.EncodeToString(mac.Sum(nil)))
		}

		resp, err := w.client.Do(req)
		if err != nil {
			log.Printf("webhook delivery to %s failed: %v", w.URL, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return
		}
		log.Printf("webhook delivery to %s returned %d", w.URL, resp.StatusCode)
	}
}
