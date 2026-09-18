// SPDX-License-Identifier: MIT

package audit

import "sync"

// Recent keeps the last entries in memory so that they can be asked for after
// the fact.
//
// KeyFence already writes every entry to its log and streams them to whoever
// subscribes, and neither answers the question a client actually has: "what
// happened during my run?" A sandbox supervisor cannot read the service's
// journal, and a live subscription means holding a connection open for the
// duration of something it is also supervising. A short history it can query when
// the run ends is the simpler shape.
//
// Bounded on purpose. This is a window on the recent past, not storage: entries
// fall off the end, and a caller that needs them all should subscribe to the
// stream or read the log.
type Recent struct {
	mu      sync.Mutex
	entries []Entry
	limit   int
}

// DefaultRecentLimit is how many entries are kept.
const DefaultRecentLimit = 2048

func NewRecent(limit int) *Recent {
	if limit <= 0 {
		limit = DefaultRecentLimit
	}
	return &Recent{limit: limit}
}

// Send takes an entry, which is what makes this a Sink.
func (r *Recent) Send(entry Entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, entry)
	if len(r.entries) > r.limit {
		r.entries = r.entries[len(r.entries)-r.limit:]
	}
}

// Entries answers what is held, most recent last. With a task id, only the
// entries belonging to that task -- which is how one run's events are separated
// from another's.
func (r *Recent) Entries(taskID string) []Entry {
	r.mu.Lock()
	defer r.mu.Unlock()

	answer := make([]Entry, 0, len(r.entries))
	for _, entry := range r.entries {
		if taskID != "" && entry.TaskID != taskID {
			continue
		}
		answer = append(answer, entry)
	}
	return answer
}
