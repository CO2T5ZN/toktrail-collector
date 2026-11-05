package collection

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"toktrail-collector/internal/local/knowncache"
	"toktrail-collector/internal/local/scanledger"
	"toktrail-collector/internal/source/adapter"
)

// A run cut short by its deadline/cancellation must leave the state exactly
// resumable: nothing recorded as exported, no scan state advanced. The next
// run then exports every record exactly once. This is the property the old
// behaviour broke — an expired window aborted the scan before any export
// commit, so every run repeated the same work and no data ever left the
// device.
func TestInterruptedRunResumesWithoutLossOrDuplication(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)
	sessions := filepath.Join(t.TempDir(), "sessions")
	writeMonotonicCodexSession(t, sessions, "a.jsonl", 4)
	writeMonotonicCodexSession(t, sessions, "b.jsonl", 3)
	enableGrant(t, stateDir, "codex-jsonl", sessions)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cancelled := false
	_, runErr := Run(ctx, Options{
		StateDir: stateDir,
		Progress: func(event ProgressEvent) {
			// Cancel as soon as the first source scan starts: the run is
			// inside the scan phase, before any export commit.
			if !cancelled && event.Kind == ProgressStageStart && event.Stage == "source_scan" {
				cancelled = true
				cancel()
			}
		},
	})
	if runErr == nil {
		t.Fatalf("the cancelled run must fail, not report success")
	}
	if !cancelled {
		t.Fatal("the test never reached the scan phase")
	}

	// Nothing may claim to be exported: no scan state, no known cache, no
	// committed record.
	if states, existed, err := scanledger.New(stateDir).Load(adapter.CodexJSONLSource); err != nil || existed && len(states) > 0 {
		t.Fatalf("an interrupted scan must not advance the scan state (existed=%v states=%d err=%v)", existed, len(states), err)
	}
	if _, statErr := os.Stat(knowncache.New(stateDir).Path(adapter.CodexJSONLSource)); statErr == nil {
		t.Fatalf("an interrupted scan must not write the known-record cache")
	}
	if got := committedRecordCount(t, stateDir, adapter.CodexJSONLSource); got != 0 {
		t.Fatalf("an interrupted scan committed %d records, want 0", got)
	}

	// The resume run exports everything exactly once.
	res, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("resume run failed: %v", err)
	}
	if res.ExportedRecords != 5 {
		t.Fatalf("resume run exported %d records, want 5 (3 + 2)", res.ExportedRecords)
	}
	if got := committedRecordCount(t, stateDir, adapter.CodexJSONLSource); got != 5 {
		t.Fatalf("committed records after resume = %d, want exactly 5", got)
	}
	if _, err := os.Stat(scanledger.New(stateDir).Path(adapter.CodexJSONLSource)); err != nil {
		t.Fatalf("the resumed run must record its scan state: %v", err)
	}

	// And a third run finds nothing new: no duplication, no repeated work.
	quiet, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("third run failed: %v", err)
	}
	if quiet.ExportedRecords != 0 {
		t.Fatalf("an unchanged history must export nothing, got %d", quiet.ExportedRecords)
	}
	if got := committedRecordCount(t, stateDir, adapter.CodexJSONLSource); got != 5 {
		t.Fatalf("committed records after the quiet run = %d, want 5", got)
	}
}
