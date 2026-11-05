package collection

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toktrail-collector/internal/local/outbox"
)

// runWithConcurrency runs one scan/drain round over a fixed fixture with the
// given worker bound and returns everything a caller can observe.
func runWithConcurrency(t *testing.T, parallel int) (Result, []string, int) {
	t.Helper()
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)

	sessions := filepath.Join(t.TempDir(), "codex")
	writeMonotonicCodexSession(t, sessions, "a.jsonl", 4)
	writeMonotonicCodexSession(t, sessions, "b.jsonl", 3)
	enableGrant(t, stateDir, "codex-jsonl", sessions)

	claudeDir := filepath.Join(t.TempDir(), "claude")
	writeClaudeSession(t, claudeDir, "s.jsonl",
		claudeLine(t, "2026-10-21T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))
	enableGrant(t, stateDir, "claude-code-jsonl", claudeDir)

	res, err := Run(t.Context(), Options{StateDir: stateDir, MaxParallelScans: parallel, MaxBatches: 10})
	if err != nil {
		t.Fatalf("run failed (parallel=%d): %v", parallel, err)
	}
	ledger, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	batchIDs := make([]string, 0, len(ledger.Batches))
	for _, entry := range ledger.Batches {
		batchIDs = append(batchIDs, entry.BatchID)
	}
	committed := 0
	for _, entry := range ledger.Batches {
		committed += entry.RecordCount
	}
	return res, batchIDs, committed
}

// Scanning two sources concurrently must produce exactly the same outcomes,
// batch identities and record counts as scanning them one at a time: the
// parallelism only overlaps parsing, and every commit keeps grant order.
func TestParallelScanMatchesSequentialScan(t *testing.T) {
	sequential, seqBatches, seqCommitted := runWithConcurrency(t, 1)
	parallel, parBatches, parCommitted := runWithConcurrency(t, 3)

	if sequential.ExportedRecords != parallel.ExportedRecords {
		t.Fatalf("exported records differ: sequential=%d parallel=%d", sequential.ExportedRecords, parallel.ExportedRecords)
	}
	if sequential.ExportedRecords != 6 {
		t.Fatalf("fixture must export codex 5 + claude 1 = 6, got %d", sequential.ExportedRecords)
	}
	if seqCommitted != parCommitted {
		t.Fatalf("committed records differ: sequential=%d parallel=%d", seqCommitted, parCommitted)
	}
	if len(seqBatches) != len(parBatches) {
		t.Fatalf("batch count differs: sequential=%v parallel=%v", seqBatches, parBatches)
	}
	// Batch ids embed a content hash and a timestamp, so two runs never share
	// an id; the grant ordinal inside the id is the part that must agree.
	for i := range seqBatches {
		ordinal := fmt.Sprintf("-%02d-", i)
		if !strings.Contains(seqBatches[i], ordinal) || !strings.Contains(parBatches[i], ordinal) {
			t.Fatalf("batch order differs at %d: sequential=%v parallel=%v", i, seqBatches, parBatches)
		}
	}
	if len(sequential.GrantOutcomes) != len(parallel.GrantOutcomes) {
		t.Fatalf("outcome count differs: %d vs %d", len(sequential.GrantOutcomes), len(parallel.GrantOutcomes))
	}
	for i := range sequential.GrantOutcomes {
		// Inputs and batch ids point at per-run temp directories, so only the
		// source, code, record count and skip reason are comparable.
		a, b := sequential.GrantOutcomes[i], parallel.GrantOutcomes[i]
		if a.Source != b.Source || a.Code != b.Code || a.Skipped != b.Skipped || a.Records != b.Records || a.Exported != b.Exported {
			t.Fatalf("outcome %d differs:\n sequential=%+v\n parallel=%+v", i, a, b)
		}
	}
}

// A source that cannot be read keeps its ordered, skip-and-continue outcome
// under both shapes: parallelism never turns a local failure into a run
// failure, and never reorders the report.
func TestParallelScanKeepsOrderedSkipOutcomes(t *testing.T) {
	build := func(t *testing.T) string {
		stateDir := t.TempDir()
		server := fakeServer(t)
		bindDevice(t, stateDir, server.URL)
		sessions := filepath.Join(t.TempDir(), "codex")
		writeMonotonicCodexSession(t, sessions, "a.jsonl", 3)
		enableGrant(t, stateDir, "codex-jsonl", sessions)
		// Granted first, then removed: the grant survives but its input is
		// inaccessible, which is a per-grant skip and never a run failure.
		claudeDir := filepath.Join(t.TempDir(), "claude")
		writeClaudeSession(t, claudeDir, "s.jsonl",
			claudeLine(t, "2026-10-21T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))
		enableGrant(t, stateDir, "claude-code-jsonl", claudeDir)
		if err := os.RemoveAll(claudeDir); err != nil {
			t.Fatal(err)
		}
		return stateDir
	}

	for _, parallel := range []int{1, 3} {
		stateDir := build(t)
		res, err := Run(t.Context(), Options{StateDir: stateDir, MaxParallelScans: parallel, MaxBatches: 5})
		if err != nil {
			t.Fatalf("run failed (parallel=%d): %v", parallel, err)
		}
		if len(res.GrantOutcomes) != 2 {
			t.Fatalf("parallel=%d outcomes = %+v, want 2", parallel, res.GrantOutcomes)
		}
		if res.GrantOutcomes[0].Source != "codex-jsonl" || res.GrantOutcomes[0].Records == 0 {
			t.Fatalf("parallel=%d first outcome = %+v, want the codex export first", parallel, res.GrantOutcomes[0])
		}
		if res.GrantOutcomes[1].Source != "claude-code-jsonl" || res.GrantOutcomes[1].Code != GrantInputInaccessible {
			t.Fatalf("parallel=%d second outcome = %+v, want the inaccessible claude grant", parallel, res.GrantOutcomes[1])
		}
	}
}
