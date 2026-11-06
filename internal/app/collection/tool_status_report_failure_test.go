package collection

// Targeted regression coverage for the per-batch tool-status receipt
// failure inside deviceQueueDrain.step: after a batch upload is
// CONFIRMED by the server (receipt reconciled, baselines advanced, the
// outbox entry marked synced), the drain reports the tool's "synced"
// status through synccmd.ReportToolStatuses. A failure of that metadata
// round must:
//
//   - fail the run (never a quiet success) through the
//     ErrToolStatusReport sentinel, with the underlying cause still
//     matchable through the wrap;
//   - KEEP the already-confirmed upload counted
//     (Result.SyncedBatches/SyncedRecords);
//   - keep the drain's pending state MEASURED — the stop recounts the
//     durable queue and marks PendingCounted, so the §6.5 summary
//     reports the real backlog instead of "device pending unknown"
//     (the uncounted-queue bug this file pins);
//   - leave the not-yet-uploaded batches pending on disk so the next
//     run resumes exactly where this one stopped.
//
// Everything is synthetic: tempdir state, the budgetFakeServer protocol
// fake (its tool-status endpoint armed to answer a transient 503), and
// injected cursor auth/verify/pull fakes. No real credentials are read
// and no real endpoint is contacted.

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/syncbudget"
)

// TestRunFairDrainToolStatusFailureKeepsConfirmedAndPending pins the
// accounting of the source-status-report stop: one granted source
// exports a batch, the rotation uploads and CONFIRMS it, the tool-status
// report that follows fails with a transient 503, and the run stops —
// with the confirmed upload still counted, the backlog batch still
// pending, and PendingCounted set so the summary never renders the
// measured queue as "device pending unknown". A follow-up run after the
// transient failure clears finishes everything.
func TestRunFairDrainToolStatusFailureKeepsConfirmedAndPending(t *testing.T) {
	stateDir := t.TempDir()
	server := startBudgetFakeServer(t)
	bindCursorDevice(t, stateDir, server.URL)
	writeCursorPermit(t, stateDir)
	sessions := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, sessions, "session-fair-toolstatus.jsonl",
		claudeLine(t, "2026-10-28T09:00:00Z", "s-fair-ts", "msg_fair_ts_1", claudeUsage(10, 0, 0, 5)),
		claudeLine(t, "2026-10-28T09:01:00Z", "s-fair-ts", "msg_fair_ts_2", claudeUsage(11, 0, 0, 6)),
	)
	enableGrant(t, stateDir, "claude-code-jsonl", sessions)
	// A second pending batch stays queued behind the confirmed one: the
	// stop must leave it pending and report it as MEASURED backlog.
	writePendingBatch(t, stateDir, "device-fair-ts-backlog")
	// Every tool-status POST answers a transient 503 with no server
	// error code — the same unclassified shape a real blip produces.
	server.setFailToolStatus(true)

	budget := syncbudget.New(syncbudget.WithTotal(100))
	pull := &fakeCursorPull{}
	res, _, err := runFairPeriodic(t, stateDir, server.URL, server, budget, pull, nil)
	if err == nil {
		t.Fatalf("a failed source status report after a confirmed upload must fail the run, got %+v", res)
	}
	if !errors.Is(err, ErrToolStatusReport) {
		t.Fatalf("the stop must surface the ErrToolStatusReport sentinel, got %v", err)
	}
	// The wrapped cause keeps its identity and text: the 503 body carried
	// no error code, so the underlying error is the plain ingest
	// classification and its text must survive the sentinel wrap.
	if !strings.Contains(err.Error(), "status 503") {
		t.Fatalf("the underlying report failure must stay visible through the wrap, got %v", err)
	}
	// The confirmed upload is real and stays counted.
	if res.SyncedBatches != 1 || res.SyncedRecords != 2 {
		t.Fatalf("the confirmed upload must stay counted after the report failure: synced=%d records=%d", res.SyncedBatches, res.SyncedRecords)
	}
	if res.ExportedBatches != 1 {
		t.Fatalf("the scan's export must stay counted, got %d", res.ExportedBatches)
	}
	// The stop path measured the queue: the backlog shows as a real
	// pending count, never as an unmeasured "pending unknown".
	if !res.PendingCounted {
		t.Fatal("the source-status-report stop must mark the recounted pending queue as counted (PendingCounted)")
	}
	if res.PendingRemaining != 1 {
		t.Fatalf("the backlog batch must stay pending and be reported, got %d", res.PendingRemaining)
	}
	if res.DrainStop != DrainStopFailed {
		t.Fatalf("the stop must record the failed drain code, got %q", res.DrainStop)
	}
	if !strings.Contains(res.DrainStopped, "source status report failed") {
		t.Fatalf("the drain stop must name the failed report, got %q", res.DrainStopped)
	}
	// The §6.5 summary renders the measured queue (PendingObserved),
	// so the CLI can never fall back to "device pending unknown".
	phases := SummarizePhases(res)
	if !phases.Drain.PendingObserved || phases.Drain.PendingRemaining != 1 {
		t.Fatalf("the summary must carry the measured device backlog: observed=%v pending=%d", phases.Drain.PendingObserved, phases.Drain.PendingRemaining)
	}
	if summary := Summarize(res, err, nil, "periodic", 1); summary.StopReason != StopFatalError {
		t.Fatalf("the report failure keeps the historical failure verdict, got %q", summary.StopReason)
	}
	// Durable state: the confirmed batch is synced, the backlog batch
	// stays pending with its file intact.
	ob, loadErr := outbox.New(stateDir).Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	synced, pending := 0, 0
	for _, entry := range ob.Batches {
		switch entry.Status {
		case outbox.StatusSynced:
			synced++
		case outbox.StatusPending:
			pending++
		}
	}
	if synced != 1 || pending != 1 {
		t.Fatalf("the outbox must hold one synced and one pending batch, got synced=%d pending=%d", synced, pending)
	}
	// The failed report was attempted exactly once (no retry inside the
	// run), and the confirmed upload happened exactly once.
	selfRequests, _, devicePosts, toolStatusPosts, _ := server.counters()
	if devicePosts != 1 {
		t.Fatalf("exactly one device ingest POST must have happened, got %d", devicePosts)
	}
	if toolStatusPosts != 0 {
		t.Fatalf("no tool-status report may be counted as delivered, got %d", toolStatusPosts)
	}
	if selfRequests == 0 {
		t.Fatal("the run must have performed its self preflights")
	}

	// The transient failure clears: the next run drains the retained
	// backlog and reports the tool statuses cleanly.
	server.setFailToolStatus(false)
	budget2 := syncbudget.New(syncbudget.WithTotal(100))
	res2, _, err2 := runFairPeriodic(t, stateDir, server.URL, server, budget2, pull, nil)
	if err2 != nil {
		t.Fatalf("the resumed run must finish cleanly after the transient report failure, got %v", err2)
	}
	if res2.SyncedBatches != 1 || res2.SyncedRecords != 1 || res2.PendingRemaining != 0 {
		t.Fatalf("the retained backlog batch must drain: synced=%d records=%d pending=%d", res2.SyncedBatches, res2.SyncedRecords, res2.PendingRemaining)
	}
	if !res2.PendingCounted {
		t.Fatal("the resumed run's clean drain must keep the pending queue measured")
	}
	if n := devicePendingCount(t, stateDir); n != 0 {
		t.Fatalf("nothing may remain pending after the resumed run, got %d", n)
	}
}

// TestRunFairDrainToolStatusFailureLegacyDrainShape runs the identical
// fault through the non-fair bounded drain (Options.FairDrain unset):
// both drain shapes share deviceQueueDrain.step, so the legacy path must
// keep the same confirmed/pending accounting and the same sentinel.
func TestRunFairDrainToolStatusFailureLegacyDrainShape(t *testing.T) {
	stateDir := t.TempDir()
	server := startBudgetFakeServer(t)
	bindDevice(t, stateDir, server.URL)
	sessions := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, sessions, "session-legacy-toolstatus.jsonl",
		claudeLine(t, "2026-10-28T09:00:00Z", "s-legacy-ts", "msg_legacy_ts_1", claudeUsage(9, 0, 0, 4)),
	)
	enableGrant(t, stateDir, "claude-code-jsonl", sessions)
	writePendingBatch(t, stateDir, "device-legacy-ts-backlog")
	server.setFailToolStatus(true)

	res, err := Run(context.Background(), Options{
		StateDir:   stateDir,
		ServerURL:  server.URL,
		HTTPClient: server.Client(),
		HomeDir:    t.TempDir(),
		Now:        func() time.Time { return cursorTestNow },
		FairDrain:  false,
	})
	if err == nil {
		t.Fatalf("the legacy drain must fail the run on the report failure, got %+v", res)
	}
	if !errors.Is(err, ErrToolStatusReport) {
		t.Fatalf("the legacy drain must surface the same sentinel, got %v", err)
	}
	if res.SyncedBatches != 1 || res.SyncedRecords != 1 {
		t.Fatalf("the confirmed upload must stay counted: synced=%d records=%d", res.SyncedBatches, res.SyncedRecords)
	}
	if !res.PendingCounted || res.PendingRemaining != 1 {
		t.Fatalf("the backlog must stay pending and measured: counted=%v pending=%d", res.PendingCounted, res.PendingRemaining)
	}
}
