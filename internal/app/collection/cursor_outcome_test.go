package collection

// Unit coverage for the §6.5 cursor round-outcome aggregation: how the
// pull phase's and the fair rotation's structured outcomes fold into one
// run-level outcome (mergeCursorOutcome), and which outcomes suppress
// the run's "complete" progress event (cursorRoundIncomplete). The
// end-to-end behavior is pinned by the periodic CLI tests; this table
// pins the merge rules themselves.

import (
	"testing"

	"toktrail-collector/internal/app/cursorsync"
)

func TestMergeCursorOutcome(t *testing.T) {
	cases := []struct {
		name    string
		prev    cursorsync.RoundOutcome
		next    cursorsync.RoundOutcome
		workRan bool
		want    cursorsync.RoundOutcome
	}{
		{"absent prev passes next through", cursorsync.RoundAbsent, cursorsync.RoundPaused, false, cursorsync.RoundPaused},
		{"error sticks over later success", cursorsync.RoundError, cursorsync.RoundRan, true, cursorsync.RoundError},
		{"error arriving later wins", cursorsync.RoundRan, cursorsync.RoundError, true, cursorsync.RoundError},
		{"error beats fence stop", cursorsync.RoundFenceStop, cursorsync.RoundError, true, cursorsync.RoundError},
		{"fence stop sticks over later success", cursorsync.RoundFenceStop, cursorsync.RoundRan, true, cursorsync.RoundFenceStop},
		{"fence stop arriving later wins", cursorsync.RoundRan, cursorsync.RoundFenceStop, false, cursorsync.RoundFenceStop},
		{"fence stop beats paused", cursorsync.RoundPaused, cursorsync.RoundFenceStop, true, cursorsync.RoundFenceStop},
		{"auth withheld before any work stays a verdict", cursorsync.RoundAbsent, cursorsync.RoundAuthWithheld, false, cursorsync.RoundAuthWithheld},
		{"auth withheld after a pull escalates to drift", cursorsync.RoundRan, cursorsync.RoundAuthWithheld, true, cursorsync.RoundFenceStop},
		{"auth withheld after uploads alone escalates", cursorsync.RoundBounded, cursorsync.RoundAuthWithheld, true, cursorsync.RoundFenceStop},
		{"a lifted pause drained clean reads ran", cursorsync.RoundPaused, cursorsync.RoundRan, true, cursorsync.RoundRan},
		{"a phase bound drained past reads ran", cursorsync.RoundBounded, cursorsync.RoundRan, true, cursorsync.RoundRan},
		{"a later pause overwrites success", cursorsync.RoundRan, cursorsync.RoundPaused, true, cursorsync.RoundPaused},
		{"no permit stays the verdict", cursorsync.RoundAbsent, cursorsync.RoundNoPermit, false, cursorsync.RoundNoPermit},
		{"an absent next keeps the previous state", cursorsync.RoundPaused, cursorsync.RoundAbsent, true, cursorsync.RoundPaused},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mergeCursorOutcome(tc.prev, tc.next, tc.workRan); got != tc.want {
				t.Fatalf("merge(%q, %q, workRan=%t) = %q, want %q", tc.prev, tc.next, tc.workRan, got, tc.want)
			}
		})
	}
}

func TestCursorRoundIncompleteSuppressesCompleteEvent(t *testing.T) {
	for _, tc := range []struct {
		outcome cursorsync.RoundOutcome
		want    bool
	}{
		{cursorsync.RoundAbsent, false},
		{cursorsync.RoundRan, false},
		{cursorsync.RoundBounded, false},
		{cursorsync.RoundNoPermit, false},
		{cursorsync.RoundAuthWithheld, false},
		{cursorsync.RoundError, true},
		{cursorsync.RoundFenceStop, true},
		{cursorsync.RoundPaused, true},
	} {
		if got := cursorRoundIncomplete(tc.outcome); got != tc.want {
			t.Fatalf("cursorRoundIncomplete(%q) = %t, want %t", tc.outcome, got, tc.want)
		}
	}
}
