// SPDX-License-Identifier: MIT

package audit

import "testing"

func TestRecentKeepsTheLastEntries(t *testing.T) {
	recent := NewRecent(3)
	for _, event := range []string{"a", "b", "c", "d"} {
		recent.Send(Entry{Event: event})
	}

	entries := recent.Entries("")
	if len(entries) != 3 {
		t.Fatalf("kept %d entries, want 3", len(entries))
	}
	// A window on the recent past: the oldest falls off, and order is preserved.
	if entries[0].Event != "b" || entries[2].Event != "d" {
		t.Errorf("kept %v", []string{entries[0].Event, entries[1].Event, entries[2].Event})
	}
}

func TestRecentSeparatesOneRunFromAnother(t *testing.T) {
	recent := NewRecent(0)
	recent.Send(Entry{Event: "allow", TaskID: "run-1"})
	recent.Send(Entry{Event: "deny", TaskID: "run-2"})
	recent.Send(Entry{Event: "allow", TaskID: "run-1"})
	recent.Send(Entry{Event: "issue"}) // no task at all

	mine := recent.Entries("run-1")
	if len(mine) != 2 {
		t.Fatalf("got %d entries for run-1, want 2", len(mine))
	}
	for _, entry := range mine {
		if entry.TaskID != "run-1" {
			t.Errorf("entry from %q came back for run-1", entry.TaskID)
		}
	}
	if all := recent.Entries(""); len(all) != 4 {
		t.Errorf("asking for everything gave %d of 4", len(all))
	}
}
