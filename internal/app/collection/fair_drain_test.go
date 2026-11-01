package collection

// §6.2 fair-drain coverage for the full periodic Run with
// Options.FairDrain: after the run's single scan/pull phase the device
// outbox and the account cursor queue drain in strict rotation — one
// batch per queue per turn — under the run's one lock, until both queues
// are exhausted, a full turn makes no progress, the context is cancelled,
// or the shared budget declines (surfaced as an incomplete run, never
// swallowed):
//
//   - fair rotation: with both queues holding batches the uploads
//     strictly alternate (no queue starves the other), and each queue
//     still drains to empty;
//   - one scan / one pull: the granted source is scanned exactly once
//     (one source_scan progress event, one exported batch) and the
//     account upstream is pulled exactly once, while the rotation drains
//     everything both phases produced;
//   - a shared-total decline mid-rotation stops the run with the
//     sentinel, both queues keep their pending batches, and a follow-up
//     run under a fresh budget finishes;
//   - a decline BEFORE the pull (an exhausted budget at run start)
//     still surfaces as the run error — never swallowed by the
//     non-fatal cursor recording — and the credential is never read;
//   - a budget deadline decline surfaces as an incomplete run;
//   - a mid-run authorization pause preserves the SKIPPED queue's known
//     pending count (a paused cursor round reports its real backlog,
//     never zero) and the rotation stops without spinning: the server
//     preflight count stays bounded.
//
// Everything is synthetic: tempdir state, an httptest fake speaking the
// device self / grant-ack / tool-status / device-batch / source-batch
// protocol, and injected auth/verify/pull fakes. No test reads the real
// Cursor desktop state, calls the Cursor API, or touches real
// credentials.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/pipeline"
	"toktrail-collector/internal/syncbudget"
)

// runFairPeriodic executes one fair-drain periodic Run with the cursor
// wiring and the given shared budget threaded through both queues,
// exactly like the CLI's §6.2 default profile.
func runFairPeriodic(t *testing.T, stateDir, serverURL string, server *budgetFakeServer, budget *syncbudget.Budget, pull *fakeCursorPull, progress func(ProgressEvent)) (Result, *fakeCursorAuth, error) {
	t.Helper()
	authFake := &fakeCursorAuth{}
	res, err := Run(context.Background(), Options{
		StateDir:   stateDir,
		ServerURL:  serverURL,
		HTTPClient: server.Client(),
		HomeDir:    t.TempDir(),
		Now:        func() time.Time { return cursorTestNow },
		Budget:     budget,
		FairDrain:  true,
		Progress:   progress,
		Cursor: &cursorsync.Options{
			StateDir:   stateDir,
			ServerURL:  serverURL,
			HTTPClient: server.Client(),
			Auth:       authFake,
			Verify:     fakeCursorVerify,
			Pull:       pull.Pull,
			Now:        func() time.Time { return cursorTestNow },
			Budget:     budget,
		},
	})
	return res, authFake, err
}

// assertAlternatingUploads fails unless consecutive recorded uploads
// come from different queues: with both queues holding work, a fair
// rotation never lets one queue post twice in a row.
func assertAlternatingUploads(t *testing.T, order []fairUpload) {
	t.Helper()
	if len(order) == 0 {
		t.Fatal("expected at least one recorded upload")
	}
	for i := 1; i < len(order); i++ {
		if order[i].Queue == order[i-1].Queue {
			t.Fatalf("uploads %d and %d came from the same queue (%s) — the rotation is not fair: %+v", i-1, i, order[i].Queue, order)
		}
	}
}

// TestRunFairDrainRotatesDeviceAndCursorQueuesUntilExhausted pins the
// §6.2 rotation: with three pending batches in each queue and a shared
// total well above them, the run uploads every batch in one pass (never
// stopping at the historical per-queue default of 5... and more
// importantly never stopping early at all), the uploads strictly
// alternate between the queues, and both queues end empty.
func TestRunFairDrainRotatesDeviceAndCursorQueuesUntilExhausted(t *testing.T) {
	stateDir := t.TempDir()
	server := startBudgetFakeServer(t)
	bindCursorDevice(t, stateDir, server.URL)
	writeCursorPermit(t, stateDir)
	budgetGrantSession(t, stateDir)
	seedCursorPendingBatch(t, stateDir, "cursor-fair-rot-1", 1)
	seedCursorPendingBatch(t, stateDir, "cursor-fair-rot-2", 1)
	seedCursorPendingBatch(t, stateDir, "cursor-fair-rot-3", 1)
	writePendingBatch(t, stateDir, "device-fair-rot-1")
	writePendingBatch(t, stateDir, "device-fair-rot-2")
	writePendingBatch(t, stateDir, "device-fair-rot-3")

	budget := syncbudget.New(syncbudget.WithTotal(100))
	pull := &fakeCursorPull{}
	res, _, err := runFairPeriodic(t, stateDir, server.URL, server, budget, pull, nil)
	if err != nil {
		t.Fatalf("the fair drain must finish both queues: %v", err)
	}
	if res.SyncedBatches != 3 || res.PendingRemaining != 0 {
		t.Fatalf("the device queue must drain fully: synced=%d pending=%d", res.SyncedBatches, res.PendingRemaining)
	}
	if res.Cursor.SyncedBatches != 3 || res.Cursor.PendingRemaining != 0 {
		t.Fatalf("the cursor queue must drain fully: %+v", res.Cursor)
	}
	if budget.Used() != 6 || budget.QueueUsed("device") != 3 || budget.QueueUsed("cursor") != 3 {
		t.Fatalf("expected six budgeted uploads (3 per queue), used=%d device=%d cursor=%d",
			budget.Used(), budget.QueueUsed("device"), budget.QueueUsed("cursor"))
	}
	order := server.uploadOrder()
	if len(order) != 6 {
		t.Fatalf("expected six recorded uploads, got %+v", order)
	}
	assertAlternatingUploads(t, order)
	if order[0].Queue != "cursor" {
		t.Fatalf("the pull phase's capped drain-first uploads the first cursor batch, got %+v", order)
	}
	if n := cursorPendingCount(t, stateDir); n != 0 {
		t.Fatalf("no cursor batch may remain, got %d", n)
	}
	if pull.calls != 1 {
		t.Fatalf("the account upstream must be pulled exactly once, got %d", pull.calls)
	}
}

// TestRunFairDrainScansAndPullsOnce pins the "once" half of §6.2: one
// run scans the granted source exactly once (a single source_scan
// progress event producing a single exported batch) and pulls the
// account upstream exactly once, while the fair rotation drains
// everything the scan and the pull produced plus the pre-seeded backlog
// of both queues.
func TestRunFairDrainScansAndPullsOnce(t *testing.T) {
	stateDir := t.TempDir()
	server := startBudgetFakeServer(t)
	bindCursorDevice(t, stateDir, server.URL)
	writeCursorPermit(t, stateDir)
	sessions := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, sessions, "session-fair-once.jsonl",
		claudeLine(t, "2026-10-28T09:00:00Z", "s-fair-once", "msg_fair_once_1", claudeUsage(10, 0, 0, 5)),
		claudeLine(t, "2026-10-28T09:01:00Z", "s-fair-once", "msg_fair_once_2", claudeUsage(11, 0, 0, 6)),
	)
	enableGrant(t, stateDir, "claude-code-jsonl", sessions)
	seedCursorPendingBatch(t, stateDir, "cursor-fair-once-1", 1)
	seedCursorPendingBatch(t, stateDir, "cursor-fair-once-2", 1)
	writePendingBatch(t, stateDir, "device-fair-once-1")
	writePendingBatch(t, stateDir, "device-fair-once-2")

	scanStarts := 0
	progress := func(e ProgressEvent) {
		if e.Kind == ProgressStageStart && e.Stage == "source_scan" {
			scanStarts++
		}
	}
	budget := syncbudget.New(syncbudget.WithTotal(100))
	pull := &fakeCursorPull{events: cursorFixtureEvents()}
	res, _, err := runFairPeriodic(t, stateDir, server.URL, server, budget, pull, progress)
	if err != nil {
		t.Fatalf("the fair drain must finish: %v", err)
	}
	if scanStarts != 1 {
		t.Fatalf("the granted source must be scanned exactly once, got %d source_scan stages", scanStarts)
	}
	if pull.calls != 1 {
		t.Fatalf("the account upstream must be pulled exactly once, got %d", pull.calls)
	}
	if res.ExportedBatches != 1 || len(res.GrantOutcomes) != 1 || res.GrantOutcomes[0].Records != 2 {
		t.Fatalf("the scan must export exactly one batch of two records: exported=%d outcomes=%+v", res.ExportedBatches, res.GrantOutcomes)
	}
	if res.Cursor.NewRecords != 2 || res.Cursor.ExportedBatches != 1 {
		t.Fatalf("the pull must persist its two events as one batch: %+v", res.Cursor)
	}
	// 3 device batches (2 seeded + 1 scanned) and 3 cursor batches (2
	// seeded + 1 pulled) all drain in strict alternation.
	if res.SyncedBatches != 3 || res.PendingRemaining != 0 {
		t.Fatalf("the device queue must drain its seeded and scanned batches: synced=%d pending=%d", res.SyncedBatches, res.PendingRemaining)
	}
	if res.Cursor.SyncedBatches != 3 || res.Cursor.PendingRemaining != 0 {
		t.Fatalf("the cursor queue must drain its seeded and pulled batches: %+v", res.Cursor)
	}
	order := server.uploadOrder()
	if len(order) != 6 {
		t.Fatalf("expected six recorded uploads, got %+v", order)
	}
	assertAlternatingUploads(t, order)
	if budget.Used() != 6 {
		t.Fatalf("every upload must reserve the shared budget, used=%d", budget.Used())
	}
}

// TestRunFairDrainSharedBudgetDeclineStopsIncomplete pins the shared
// total under the fair rotation: with a total of 2 and three batches in
// each queue, exactly two uploads happen (one per queue, alternating),
// the next attempt is declined before its POST, and the run fails with
// the budget sentinel while both queues keep their pending batches. A
// follow-up run under its own fresh budget drains everything.
func TestRunFairDrainSharedBudgetDeclineStopsIncomplete(t *testing.T) {
	stateDir := t.TempDir()
	server := startBudgetFakeServer(t)
	bindCursorDevice(t, stateDir, server.URL)
	writeCursorPermit(t, stateDir)
	budgetGrantSession(t, stateDir)
	seedCursorPendingBatch(t, stateDir, "cursor-fair-dec-1", 1)
	seedCursorPendingBatch(t, stateDir, "cursor-fair-dec-2", 1)
	seedCursorPendingBatch(t, stateDir, "cursor-fair-dec-3", 1)
	writePendingBatch(t, stateDir, "device-fair-dec-1")
	writePendingBatch(t, stateDir, "device-fair-dec-2")
	writePendingBatch(t, stateDir, "device-fair-dec-3")

	budget := syncbudget.New(syncbudget.WithTotal(2))
	pull := &fakeCursorPull{}
	res, _, err := runFairPeriodic(t, stateDir, server.URL, server, budget, pull, nil)
	if err == nil {
		t.Fatalf("an exhausted shared budget must fail the fair run, got %+v", res)
	}
	if !errors.Is(err, syncbudget.ErrTotalExhausted) {
		t.Fatalf("the stop must surface the budget sentinel, got %v", err)
	}
	if res.SyncedBatches != 1 || res.PendingRemaining != 2 {
		t.Fatalf("one device batch must sync and two stay pending: synced=%d pending=%d", res.SyncedBatches, res.PendingRemaining)
	}
	if res.Cursor.SyncedBatches != 1 || res.Cursor.PendingRemaining != 2 {
		t.Fatalf("one cursor batch must sync and two stay pending: %+v", res.Cursor)
	}
	if budget.Used() != 2 {
		t.Fatalf("actual POST attempts exceed the budget: used=%d", budget.Used())
	}
	order := server.uploadOrder()
	if len(order) != 2 || order[0].Queue != "cursor" || order[1].Queue != "device" {
		t.Fatalf("expected one alternating upload per queue before the decline, got %+v", order)
	}
	if n := cursorPendingCount(t, stateDir); n != 2 {
		t.Fatalf("the declined cursor batches must stay pending, got %d", n)
	}

	// Follow-up run with its own fresh budget drains both queues.
	budget2 := syncbudget.New(syncbudget.WithTotal(100))
	res2, _, err := runFairPeriodic(t, stateDir, server.URL, server, budget2, pull, nil)
	if err != nil {
		t.Fatalf("the resumed fair run must finish: %v", err)
	}
	if res2.SyncedBatches != 2 || res2.PendingRemaining != 0 {
		t.Fatalf("the retained device batches must drain: synced=%d pending=%d", res2.SyncedBatches, res2.PendingRemaining)
	}
	if res2.Cursor.SyncedBatches != 2 || res2.Cursor.PendingRemaining != 0 {
		t.Fatalf("the retained cursor batches must drain: %+v", res2.Cursor)
	}
	if n := cursorPendingCount(t, stateDir); n != 0 {
		t.Fatalf("nothing may remain after the resumed run, got %d", n)
	}
}

// TestRunFairDrainDeclineBeforePullIsNotSwallowed pins the epilogue
// honesty: a budget that is already exhausted when the run starts
// declines the cursor pull phase's first attempt (before the credential
// read and the upstream pull), and that decline must surface as the
// run's error — the non-fatal cursor recording must never swallow it
// into a clean exit. The declined batch stays pending.
func TestRunFairDrainDeclineBeforePullIsNotSwallowed(t *testing.T) {
	stateDir := t.TempDir()
	server := startBudgetFakeServer(t)
	bindCursorDevice(t, stateDir, server.URL)
	writeCursorPermit(t, stateDir)
	// Cursor-only device (no local grants): the cursor decline is the
	// only queue outcome.
	seedCursorPendingBatch(t, stateDir, "cursor-fair-zero-1", 1)

	budget := syncbudget.New(syncbudget.WithTotal(0))
	pull := &fakeCursorPull{}
	res, authFake, err := runFairPeriodic(t, stateDir, server.URL, server, budget, pull, nil)
	if err == nil {
		t.Fatalf("a pull-phase budget decline must fail the fair run, got %+v", res)
	}
	if !errors.Is(err, syncbudget.ErrTotalExhausted) {
		t.Fatalf("the decline must surface the budget sentinel, got %v", err)
	}
	if pull.calls != 0 || authFake.fetches != 0 {
		t.Fatalf("a declined pull phase must not read the credential or pull, got %d reads / %d pulls", authFake.fetches, pull.calls)
	}
	if res.Cursor.PendingRemaining != 1 {
		t.Fatalf("the declined cursor batch must stay pending on the result, got %+v", res.Cursor)
	}
	if n := cursorPendingCount(t, stateDir); n != 1 {
		t.Fatalf("the declined cursor batch must stay pending, got %d", n)
	}
	if !strings.Contains(res.Cursor.Skipped, "budget") {
		t.Fatalf("the decline must be recorded on the cursor result, got %q", res.Cursor.Skipped)
	}
}

// TestRunFairDrainDeadlineDeclineStopsIncomplete pins the default
// profile's time bound: a budget whose deadline already elapsed
// declines the rotation's first device reserve with
// syncbudget.ErrDeadlineExceeded, and the run reports itself incomplete
// (never a clean bounded stop) while the batches stay pending.
func TestRunFairDrainDeadlineDeclineStopsIncomplete(t *testing.T) {
	stateDir := t.TempDir()
	server := startBudgetFakeServer(t)
	bindCursorDevice(t, stateDir, server.URL)
	writeCursorPermit(t, stateDir)
	writePendingBatch(t, stateDir, "device-fair-deadline-1")
	writePendingBatch(t, stateDir, "device-fair-deadline-2")
	// The cursor queue is empty: the pull phase runs (no POST to
	// decline), and the rotation's first device reserve hits the
	// elapsed deadline.

	budget := syncbudget.New(
		syncbudget.WithTotal(100),
		syncbudget.WithDeadline(time.Now().Add(-time.Second)),
	)
	pull := &fakeCursorPull{}
	res, _, err := runFairPeriodic(t, stateDir, server.URL, server, budget, pull, nil)
	if err == nil {
		t.Fatalf("an elapsed budget deadline must fail the fair run, got %+v", res)
	}
	if !errors.Is(err, syncbudget.ErrDeadlineExceeded) {
		t.Fatalf("the stop must surface the deadline sentinel, got %v", err)
	}
	if res.SyncedBatches != 0 || res.PendingRemaining != 2 {
		t.Fatalf("no device batch may upload under an expired deadline: synced=%d pending=%d", res.SyncedBatches, res.PendingRemaining)
	}
	if pull.calls != 1 {
		t.Fatalf("the pull phase still ran exactly once (the deadline gates POSTs, not the pull), got %d", pull.calls)
	}
	if n := devicePendingCount(t, stateDir); n != 2 {
		t.Fatalf("the declined device batches must stay pending, got %d", n)
	}
}

// TestRunFairDrainPauseMidRotationPreservesSkippedQueuePending pins the
// no-progress review finding: when the server pauses the device after
// the pull phase, the device queue stops with its real pending count,
// the cursor round's skip must PRESERVE the cursor queue's known
// pending (cursorsync's paused skip does not count it itself — a
// skipped queue must never read as an empty one), and the rotation must
// stop after one bounded turn instead of spinning on the paused queues.
// A follow-up run once the pause lifts drains both queues.
func TestRunFairDrainPauseMidRotationPreservesSkippedQueuePending(t *testing.T) {
	stateDir := t.TempDir()
	server := startBudgetFakeServer(t)
	bindCursorDevice(t, stateDir, server.URL)
	writeCursorPermit(t, stateDir)
	seedCursorPendingBatch(t, stateDir, "cursor-fair-pause-1", 1)
	seedCursorPendingBatch(t, stateDir, "cursor-fair-pause-2", 1)
	writePendingBatch(t, stateDir, "device-fair-pause-1")
	writePendingBatch(t, stateDir, "device-fair-pause-2")
	// Self requests: 1 grant sync, 2 cursor pull phase. The third and
	// every later request answer the paused view, so the pause lands
	// exactly between the pull phase and the rotation.
	server.setPauseFromSelfRequest(3)

	budget := syncbudget.New(syncbudget.WithTotal(100))
	pull := &fakeCursorPull{}
	res, _, err := runFairPeriodic(t, stateDir, server.URL, server, budget, pull, nil)
	if err != nil {
		t.Fatalf("a mid-run pause is a queued state, never a run failure: %v", err)
	}
	if res.SyncedBatches != 0 || res.PendingRemaining != 2 {
		t.Fatalf("the paused device queue must keep both batches queued: synced=%d pending=%d", res.SyncedBatches, res.PendingRemaining)
	}
	if !strings.Contains(res.DrainStopped, "paused") {
		t.Fatalf("the drain stop must name the pause, got %q", res.DrainStopped)
	}
	if res.Cursor.SyncedBatches != 1 {
		t.Fatalf("the pull phase must have uploaded one cursor batch before the pause: %+v", res.Cursor)
	}
	// The key assertion: the paused cursor skip reports the queue's real
	// remaining backlog (2 seeded - 1 uploaded), not the zero that
	// cursorsync's paused skip path leaves behind.
	if res.Cursor.PendingRemaining != 1 {
		t.Fatalf("the skipped cursor queue must preserve its known pending count, got %+v", res.Cursor)
	}
	if n := cursorPendingCount(t, stateDir); n != 1 {
		t.Fatalf("one cursor batch must remain pending, got %d", n)
	}
	// Bounded work: exactly four self preflights (grant sync, cursor
	// pull phase, the rotation's paused device step, the rotation's
	// skipped cursor step). A hot-spinning rotation would burn many
	// more.
	selfRequests, _, _, _, _ := server.counters()
	if selfRequests != 4 {
		t.Fatalf("expected exactly four self preflights (no rotation spin), got %d", selfRequests)
	}

	// The pause lifts: the next run drains both queues completely.
	server.setPauseFromSelfRequest(0)
	budget2 := syncbudget.New(syncbudget.WithTotal(100))
	res2, _, err := runFairPeriodic(t, stateDir, server.URL, server, budget2, pull, nil)
	if err != nil {
		t.Fatalf("the resumed run must finish: %v", err)
	}
	if res2.SyncedBatches != 2 || res2.PendingRemaining != 0 {
		t.Fatalf("the retained device batches must drain: synced=%d pending=%d", res2.SyncedBatches, res2.PendingRemaining)
	}
	if res2.Cursor.SyncedBatches != 1 || res2.Cursor.PendingRemaining != 0 {
		t.Fatalf("the retained cursor batch must drain: %+v", res2.Cursor)
	}
}

// TestRunFairDrainPartialRejectionKeepsEpilogue pins the rejected-records
// epilogue under the fair rotation: a receipt that partially rejects a
// batch is settled (the accepted part confirmed, the batch marked synced)
// and the rotation keeps draining later batches, but an otherwise-clean
// run must STILL surface ErrRecordsRejected — the fair drain's finish
// path may never drop the legacy epilogue.
func TestRunFairDrainPartialRejectionKeepsEpilogue(t *testing.T) {
	stateDir := t.TempDir()
	server := startBudgetFakeServer(t)
	bindCursorDevice(t, stateDir, server.URL)
	budgetGrantSession(t, stateDir)
	writePendingBatchRecords(t, stateDir, "device-fair-rej-1", 2)
	writePendingBatchRecords(t, stateDir, "device-fair-rej-2", 1)
	server.rejectRecords = func(records []map[string]any) map[int]string {
		if len(records) >= 2 {
			return map[int]string{0: "synthetic_rejection"}
		}
		return nil
	}

	res, err := Run(context.Background(), Options{
		StateDir:   stateDir,
		ServerURL:  server.URL,
		HTTPClient: server.Client(),
		HomeDir:    t.TempDir(),
		Now:        func() time.Time { return cursorTestNow },
		Budget:     syncbudget.New(syncbudget.WithTotal(10)),
		FairDrain:  true,
	})
	if err == nil {
		t.Fatalf("a clean fair drain with settled rejections must fail with ErrRecordsRejected, got %+v", res)
	}
	if !errors.Is(err, ErrRecordsRejected) {
		t.Fatalf("the fair drain must keep the rejected-records epilogue, got %v", err)
	}
	if res.SyncedBatches != 2 || res.PendingRemaining != 0 {
		t.Fatalf("both batches settle (the partially rejected one counts as synced): synced=%d pending=%d", res.SyncedBatches, res.PendingRemaining)
	}
	if res.RejectedBatches != 1 || res.RejectedRecords != 1 {
		t.Fatalf("the rejected part must be counted separately: batches=%d records=%d", res.RejectedBatches, res.RejectedRecords)
	}
	if !strings.Contains(err.Error(), "rejected 1 record(s) across 1 drained batch(es)") {
		t.Fatalf("the epilogue must carry the rejection diagnosis, got %v", err)
	}
}

// TestRunFairDrainNetworkDropReplayIsIdempotent re-runs the P2
// commit-then-drop fault through the fair rotation: the dropped upload
// fails the run exactly like the legacy drain (no in-run retry, the batch
// stays pending with durable attempt accounting, the export cursor is
// advanced but unconfirmed), and the next fair run re-sends the SAME
// batch id byte-identically for an idempotent replay.
func TestRunFairDrainNetworkDropReplayIsIdempotent(t *testing.T) {
	stateDir := t.TempDir()
	server := newDropAfterCommitServer(t)
	bindDevice(t, stateDir, server.URL)
	sessions := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, sessions, "session-fair-drop.jsonl",
		claudeLine(t, "2026-10-21T05:00:00Z", "s-fair-drop", "msg_fair_drop_1", claudeUsage(15, 2, 0, 8)),
		claudeLine(t, "2026-10-21T05:01:00Z", "s-fair-drop", "msg_fair_drop_2", claudeUsage(10, 0, 0, 5)))
	enableGrant(t, stateDir, "claude-code-jsonl", sessions)

	res1, err1 := Run(t.Context(), Options{
		StateDir:  stateDir,
		ServerURL: server.URL,
		Now:       func() time.Time { return time.Date(2026, 10, 21, 5, 2, 0, 0, time.UTC) },
		FairDrain: true,
	})
	if err1 == nil {
		t.Fatal("expected the fair run to fail when the server drops the connection after committing the batch")
	}
	if !errors.Is(err1, io.EOF) && !strings.Contains(err1.Error(), "EOF") {
		t.Fatalf("expected an EOF-style transport failure from the dropped connection, got %v", err1)
	}
	if res1.ExportedBatches != 1 || res1.SyncedBatches != 0 {
		t.Fatalf("the export must stand while nothing counts as synced: %#v", res1)
	}
	if res1.PendingRemaining != 1 || !strings.Contains(res1.DrainStopped, "upload of batch") {
		t.Fatalf("the fair drain must stop on the failed upload with the legacy accounting: %#v", res1)
	}
	if got := server.ingestRequests(); got != 1 {
		t.Fatalf("the dropped upload must not be retried within the same fair run, got %d ingest POSTs", got)
	}
	ob, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(ob.Batches) != 1 || ob.Batches[0].Status != outbox.StatusPending || ob.Batches[0].LastAttemptAt.IsZero() {
		t.Fatalf("the batch must stay pending with durable attempt accounting: %#v", ob.Batches)
	}
	batchID := ob.Batches[0].BatchID

	res2, err2 := Run(t.Context(), Options{
		StateDir:  stateDir,
		ServerURL: server.URL,
		Now:       func() time.Time { return time.Date(2026, 10, 21, 5, 5, 0, 0, time.UTC) },
		FairDrain: true,
	})
	if err2 != nil {
		t.Fatalf("the replay run must succeed, got %v", err2)
	}
	if res2.SyncedBatches != 1 || res2.SyncedRecords != 2 || res2.PendingRemaining != 0 {
		t.Fatalf("the replayed batch must drain cleanly: %#v", res2)
	}
	bodies := server.ingestBodies()
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatalf("the fair resend must be byte-identical to the dropped upload, got %d bodies", len(bodies))
	}
	var posted struct {
		BatchID string `json:"batchId"`
	}
	if err := json.Unmarshal(bodies[1], &posted); err != nil {
		t.Fatal(err)
	}
	if posted.BatchID != batchID {
		t.Fatalf("the resend must reuse the same batch id %q, got %q", batchID, posted.BatchID)
	}
	if got := server.committedRecordCount(); got != 2 {
		t.Fatalf("the replay must not double count the records, got %d", got)
	}
}

// TestRunFairDrainRecoversInterruptedExportWAL re-runs the interrupted
// export-WAL recovery through the fair drain: an entrance
// export-transaction.json from a crashed run is recovered (the batch is
// materialized and registered pending) and then drained by the rotation,
// even though the run's own grant is idle.
func TestRunFairDrainRecoversInterruptedExportWAL(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)
	sessions := filepath.Join(t.TempDir(), "sessions")
	if err := os.MkdirAll(sessions, 0o700); err != nil {
		t.Fatal(err)
	}
	enableGrant(t, stateDir, "claude-code-jsonl", sessions)

	crashInputDir := t.TempDir()
	crashInput := filepath.Join(crashInputDir, "usage.json")
	usageJSON := `{"records":[{"recordKey":"fair-wal-k1","kind":"delta","occurredAt":"2026-10-21T05:00:00Z","tool":"claude-code","model":"claude-sonnet-4.5","input":"10","cacheRead":"0","cacheWrite":"0","output":"5","adapterVersion":"fixture-v1","sourceType":"fixture"}]}`
	if err := os.WriteFile(crashInput, []byte(usageJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	batchFile := filepath.Join(stateDir, "batches", "batch-fair-wal-recovered.json")
	prepared, err := pipeline.PrepareExport(adapter.Options{
		Input:   crashInput,
		Output:  batchFile,
		BatchID: "batch-fair-wal-recovered",
	})
	if err != nil {
		t.Fatal(err)
	}
	journalJSON, err := json.MarshalIndent(map[string]any{
		"output":      batchFile,
		"batchId":     "batch-fair-wal-recovered",
		"payload":     string(prepared.Payload),
		"source":      adapter.UsageJSONSource,
		"input":       crashInput,
		"recordCount": prepared.Records,
		"committedAt": "2026-10-21T05:50:00Z",
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	txFile := filepath.Join(stateDir, "export-transaction.json")
	if err := os.WriteFile(txFile, journalJSON, 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Run(t.Context(), Options{
		StateDir:  stateDir,
		ServerURL: server.URL,
		Now:       func() time.Time { return time.Date(2026, 10, 21, 6, 0, 0, 0, time.UTC) },
		FairDrain: true,
	})
	if err != nil {
		t.Fatalf("the fair run must recover the crashed WAL transaction: %v", err)
	}
	if res.SyncedBatches != 1 || res.PendingRemaining != 0 || res.ExportedBatches != 0 {
		t.Fatalf("the recovered WAL batch must drain through the rotation: %#v", res)
	}
	if _, statErr := os.Stat(txFile); !os.IsNotExist(statErr) {
		t.Fatalf("the journal must be deleted after recovery, err=%v", statErr)
	}
	ob, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(ob.Batches) != 1 || ob.Batches[0].Status != outbox.StatusSynced {
		t.Fatalf("the recovered batch must be synced: %#v", ob.Batches)
	}
	cur, err := progress.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cur.Cursors) != 1 || cur.Cursors[0].BatchID != "batch-fair-wal-recovered" {
		t.Fatalf("the progress cursor must advance to the recovered batch: %#v", cur.Cursors)
	}
}
