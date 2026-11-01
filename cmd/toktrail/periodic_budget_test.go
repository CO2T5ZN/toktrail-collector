package main

// Shared POST budget (--max-total-batches) coverage for the periodic CLI
// entry (runPeriodic) beyond periodic_drain_test.go:
//
//   - Full mode (not --drain-only) accepts --max-total-batches and stops
//     incomplete with a non-zero exit when the budget declines a device
//     attempt before its ingest POST; a follow-up run finishes the queue.
//   - Without --max-total-batches the historical behavior is preserved:
//     the per-queue --max-batches bound stops the drain as a normal
//     exit-zero bounded stop with the remainder report (drain-only and
//     full mode alike).
//
// Everything is synthetic: tempdir state directories (never the real
// TOKTRAIL_HOME, which the explicit --state-dir flag overrides), an
// httptest fake for the ingest server, seeded pending outbox batches, and
// a claude-code-jsonl grant over an empty session directory (the scan
// finds no new records, so the only uploads are the seeded batches). No
// test reads real tool state, real credentials, or performs any network
// access beyond the fake server; the account-level cursor source never
// runs (no local permit is seeded in these tests).

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncbudget"
)

// budgetCLIFixture prepares a bound device with three pending device
// batches and one granted (but record-empty) claude-code-jsonl session
// directory, so a full periodic run scans the grant, finds no new
// records, and drains only the seeded queue.
func budgetCLIFixture(t *testing.T) (stateDir string, server *periodicDrainFakeServer) {
	t.Helper()
	stateDir = t.TempDir()
	server = newPeriodicDrainFakeServer(t)
	if err := statedir.New(stateDir).Save(statedir.DeviceState{
		ServerURL:    server.URL,
		DeviceID:     "dev-drain-1",
		DeviceSecret: periodicDrainSecret,
	}); err != nil {
		t.Fatal(err)
	}
	writePeriodicDrainPendingBatch(t, stateDir, "batch-budget-cli-1", 1)
	writePeriodicDrainPendingBatch(t, stateDir, "batch-budget-cli-2", 1)
	writePeriodicDrainPendingBatch(t, stateDir, "batch-budget-cli-3", 1)
	sessions := filepath.Join(t.TempDir(), "sessions")
	if err := os.MkdirAll(sessions, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := grants.New(stateDir).Enable("claude-code-jsonl", sessions); err != nil {
		t.Fatal(err)
	}
	return stateDir, server
}

// TestRunPeriodicFullModeSharedBudgetStopsIncompleteNonZero pins the
// full-mode shared budget: with --max-total-batches 1 and three pending
// device batches, exactly one ingest POST happens, the next attempt is
// declined before its POST, and the run reports itself incomplete and
// returns the budget sentinel (a non-zero exit for the CLI). The grant
// scan still runs (local work is free), the declined batches stay
// pending, and a follow-up run without the budget finishes the queue.
func TestRunPeriodicFullModeSharedBudgetStopsIncompleteNonZero(t *testing.T) {
	stateDir, server := budgetCLIFixture(t)

	args := []string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--max-batches", "5",
		"--max-total-batches", "1",
		"--sync-timeout", "30s",
	}
	out1, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
	if err == nil {
		t.Fatalf("a budget-exhausted full run with pending batches must exit non-zero, stdout:\n%s", out1)
	}
	if !errors.Is(err, syncbudget.ErrTotalExhausted) || !strings.Contains(err.Error(), "periodic incomplete") {
		t.Fatalf("the stop must surface the budget sentinel as an incomplete run, got %v", err)
	}
	// The grant was scanned (its outcome is reported) even though the
	// budget stopped the uploads.
	if !strings.Contains(out1, "grant claude-code-jsonl") || !strings.Contains(out1, "no new records") {
		t.Fatalf("the full-mode run must still scan the granted source, stdout:\n%s", out1)
	}
	if !strings.Contains(out1, "exportedBatches=0 exportedRecords=0") {
		t.Fatalf("the empty session must not export anything, stdout:\n%s", out1)
	}
	if !strings.Contains(out1, "syncedBatches=1 syncedRecords=1") {
		t.Fatalf("expected exactly the one budgeted upload, stdout:\n%s", out1)
	}
	if !strings.Contains(out1, "pendingRemaining=2") || !strings.Contains(out1, "stopped by the shared upload budget") {
		t.Fatalf("expected the budget-stopped remainder report, stdout:\n%s", out1)
	}
	if !strings.Contains(out1, "incomplete: the --max-total-batches 1 shared upload budget is exhausted (devicePending=2 cursorPending=0)") {
		t.Fatalf("expected the incomplete report with both queue pendings, stdout:\n%s", out1)
	}
	// Exactly one real ingest POST; the declined attempt still ran its
	// authorization preflight (the reserve sits right before the POST).
	if got := server.ingest.Load(); got != 1 {
		t.Fatalf("expected exactly one ingest upload under the budget, got %d", got)
	}
	if got := server.self.Load(); got != 3 {
		t.Fatalf("expected three self preflights (grant sync + 1 upload + 1 declined attempt), got %d", got)
	}

	// The declined batches stayed pending and the follow-up run (no
	// budget, its own fresh run) finishes the queue.
	args2 := []string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--max-batches", "5",
		"--sync-timeout", "30s",
	}
	out2, err := capturePeriodicStdout(t, func() error { return runPeriodic(args2) })
	if err != nil {
		t.Fatalf("follow-up run failed: %v\nstdout:\n%s", err, out2)
	}
	if !strings.Contains(out2, "syncedBatches=2 syncedRecords=2") {
		t.Fatalf("expected the remaining two batches to drain, stdout:\n%s", out2)
	}
	if strings.Contains(out2, "pendingRemaining=") || strings.Contains(out2, "incomplete:") {
		t.Fatalf("the finished run must report neither a remainder nor incompleteness, stdout:\n%s", out2)
	}
	if got := server.ingest.Load(); got != 3 {
		t.Fatalf("expected all 3 seeded batches uploaded across both runs, got %d", got)
	}
	final, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, batch := range final.Batches {
		if batch.Status != outbox.StatusSynced {
			t.Fatalf("expected every seeded batch synced after the follow-up run, got %s for %s", batch.Status, batch.BatchID)
		}
	}
}

// TestRunPeriodicWithoutTotalBudgetKeepsBoundedStop pins the historical
// behavior when --max-total-batches is not given (0=unset): the per-queue
// --max-batches bound stops the drain as a normal exit-zero bounded stop
// with the historical remainder report — in drain-only mode and in full
// mode alike.
func TestRunPeriodicWithoutTotalBudgetKeepsBoundedStop(t *testing.T) {
	t.Run("drain_only", func(t *testing.T) {
		stateDir, server := budgetCLIFixture(t)
		args := []string{
			"--state-dir", stateDir,
			"--server", server.URL,
			"--drain-only",
			"--max-batches", "2",
			"--sync-timeout", "30s",
		}
		out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
		if err != nil {
			t.Fatalf("a plain per-queue bounded stop must stay exit-zero, got %v\nstdout:\n%s", err, out)
		}
		if !strings.Contains(out, "syncedBatches=2 syncedRecords=2") {
			t.Fatalf("expected the two per-queue-bounded uploads, stdout:\n%s", out)
		}
		if !strings.Contains(out, "pendingRemaining=1") || !strings.Contains(out, "drain stops at 2 batch(es) per run") {
			t.Fatalf("expected the historical bounded-stop remainder report, stdout:\n%s", out)
		}
		if strings.Contains(out, "incomplete:") {
			t.Fatalf("a plain bounded stop must not report incomplete, stdout:\n%s", out)
		}
		if got := server.ingest.Load(); got != 2 {
			t.Fatalf("expected exactly two ingest uploads, got %d", got)
		}
	})

	t.Run("full_mode", func(t *testing.T) {
		stateDir, server := budgetCLIFixture(t)
		args := []string{
			"--state-dir", stateDir,
			"--server", server.URL,
			"--max-batches", "2",
			"--sync-timeout", "30s",
		}
		out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
		if err != nil {
			t.Fatalf("a plain per-queue bounded stop must stay exit-zero, got %v\nstdout:\n%s", err, out)
		}
		if !strings.Contains(out, "grant claude-code-jsonl") {
			t.Fatalf("the full-mode run must scan the granted source, stdout:\n%s", out)
		}
		if !strings.Contains(out, "syncedBatches=2 syncedRecords=2") {
			t.Fatalf("expected the two per-queue-bounded uploads, stdout:\n%s", out)
		}
		if !strings.Contains(out, "pendingRemaining=1") || !strings.Contains(out, "drain stops at 2 batch(es) per run") {
			t.Fatalf("expected the historical bounded-stop remainder report, stdout:\n%s", out)
		}
		if strings.Contains(out, "incomplete:") {
			t.Fatalf("a plain bounded stop must not report incomplete, stdout:\n%s", out)
		}
		if got := server.ingest.Load(); got != 2 {
			t.Fatalf("expected exactly two ingest uploads, got %d", got)
		}
	})
}
