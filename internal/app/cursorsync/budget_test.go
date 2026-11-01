// Shared run budget (syncbudget) wiring for the cursor source uploads:
// Options.Budget threads one run-wide budget through Sync and
// DrainPendingLocked into every real source-batch ingest POST. A decline
// stops the round before the POST — nothing is acknowledged, nothing is
// dropped, the declined batch stays pending and the next run (with a
// fresh budget) resumes the backlog; a POST that fails after the
// reservation still spends its attempt (no refund). Everything here is
// synthetic: a local fake TokTrail server, fake credential, verify and
// pull — no real user state is ever touched.
package cursorsync_test

import (
	"context"
	"errors"
	"testing"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/syncbudget"
)

// TestSyncSharedBudgetExhaustionKeepsPendingAndResumes covers the full
// Sync path: with two pending batches and a one-attempt budget, exactly
// one real ingest POST happens, the round stops on the budget decline
// (before the credential read and the upstream pull), the declined batch
// stays pending, and the next round under its own fresh budget resumes
// it to a fully drained state.
func TestSyncSharedBudgetExhaustionKeepsPendingAndResumes(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-budget-sync-1", 1)
	seedPendingBatch(t, h.dir, "cursor-budget-sync-2", 1)

	budget := syncbudget.New(syncbudget.WithTotal(1))
	opt := h.options()
	opt.Budget = budget
	res, err := cursorsync.Sync(context.Background(), opt, syncGate())
	if !errors.Is(err, syncbudget.ErrTotalExhausted) {
		t.Fatalf("expected the exhausted shared budget to stop the round, got %v", err)
	}
	if res.Outcome != cursorsync.RoundError {
		t.Fatalf("a budget-declined round must classify as an error outcome, got %q", res.Outcome)
	}
	if res.SyncedBatches != 1 || res.SyncedRecords != 1 || res.PendingRemaining != 1 {
		t.Fatalf("one batch must upload and one must stay pending: %+v", res)
	}
	if budget.Used() != 1 || budget.QueueUsed("cursor") != 1 {
		t.Fatalf("actual POST attempts exceed the budget: used=%d cursor-queue=%d", budget.Used(), budget.QueueUsed("cursor"))
	}
	if _, _, ingest, _, batches := h.srv.stats(); ingest != 1 || len(batches) != 1 {
		t.Fatalf("exactly one real ingest POST may happen: ingest=%d batches=%d", ingest, len(batches))
	}
	if n := pendingCount(t, h.dir); n != 1 {
		t.Fatalf("the declined batch must stay pending, pending=%d", n)
	}
	if h.auth.fetchCount() != 0 || len(h.pull.callLog()) != 0 {
		t.Fatal("a budget-stopped round must stop before the credential read and the upstream pull")
	}

	// Next round with its own fresh budget resumes the retained batch.
	opt.Budget = syncbudget.New(syncbudget.WithTotal(1))
	res, err = cursorsync.Sync(context.Background(), opt, syncGate())
	if err != nil {
		t.Fatalf("resume round: %v", err)
	}
	if !res.Ran || res.Outcome != cursorsync.RoundRan || res.SyncedBatches != 1 || res.SyncedRecords != 1 || res.PendingRemaining != 0 || res.NewRecords != 0 {
		t.Fatalf("the retained batch must resume next round: %+v", res)
	}
	if _, _, ingest, _, batches := h.srv.stats(); ingest != 2 || len(batches) != 2 {
		t.Fatalf("the resumed round must upload the retained batch: ingest=%d batches=%d", ingest, len(batches))
	}
}

// TestDrainPendingLockedSharedBudgetExhaustionKeepsPendingAndResumes
// covers the already-held-lock drain entry (connect's backlog pass):
// the same one-attempt budget stops the drain after the first upload
// with the declined batch pending, without reading the credential or
// pulling upstream usage, and the caller keeps the lock; the next
// locked round under a fresh budget drains the remainder.
func TestDrainPendingLockedSharedBudgetExhaustionKeepsPendingAndResumes(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-budget-locked-1", 1)
	seedPendingBatch(t, h.dir, "cursor-budget-locked-2", 1)

	lock, err := runlock.Acquire(h.dir)
	if err != nil {
		t.Fatalf("acquire state lock: %v", err)
	}
	defer lock.Close()

	budget := syncbudget.New(syncbudget.WithTotal(1))
	opt := h.options()
	opt.Budget = budget
	res, err := cursorsync.DrainPendingLocked(context.Background(), opt, syncGate(), lock)
	if !errors.Is(err, syncbudget.ErrTotalExhausted) {
		t.Fatalf("expected the exhausted shared budget to stop the drain, got %v", err)
	}
	if res.Outcome != cursorsync.RoundError {
		t.Fatalf("a budget-declined drain must classify as an error outcome, got %q", res.Outcome)
	}
	if !res.Ran || res.SyncedBatches != 1 || res.SyncedRecords != 1 || res.PendingRemaining != 1 {
		t.Fatalf("one batch must upload and one must stay pending: %+v", res)
	}
	if budget.Used() != 1 {
		t.Fatalf("actual POST attempts exceed the budget: used=%d", budget.Used())
	}
	if _, _, ingest, _, batches := h.srv.stats(); ingest != 1 || len(batches) != 1 {
		t.Fatalf("exactly one real ingest POST may happen: ingest=%d batches=%d", ingest, len(batches))
	}
	if n := pendingCount(t, h.dir); n != 1 {
		t.Fatalf("the declined batch must stay pending, pending=%d", n)
	}
	if h.auth.fetchCount() != 0 || len(h.pull.callLog()) != 0 {
		t.Fatal("a budget-stopped drain must not read credentials or pull upstream usage")
	}
	if err := lock.Validate(h.dir); err != nil {
		t.Fatalf("the locked drain must not release the caller's lock: %v", err)
	}

	// A fresh budget on the next locked round resumes the backlog.
	opt.Budget = syncbudget.New(syncbudget.WithTotal(1))
	res, err = cursorsync.DrainPendingLocked(context.Background(), opt, syncGate(), lock)
	if err != nil {
		t.Fatalf("resume locked drain: %v", err)
	}
	if res.Outcome != cursorsync.RoundRan || res.SyncedBatches != 1 || res.SyncedRecords != 1 || res.PendingRemaining != 0 {
		t.Fatalf("the retained batch must resume next round: %+v", res)
	}
	if n := pendingCount(t, h.dir); n != 0 {
		t.Fatalf("nothing may remain after the resumed drain, pending=%d", n)
	}
}

// TestSyncPostFailureSpendsSharedBudgetWithoutRefund covers the
// no-refund rule through the full wiring: a POST that fails after its
// reservation still spends the attempt, so the next round under the SAME
// budget declines without any further POST (the batch stays pending),
// and only a fresh budget uploads it.
func TestSyncPostFailureSpendsSharedBudgetWithoutRefund(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-budget-postfail-1", 1)

	// The one allowed POST fails server-side (HTTP 503).
	h.srv.setIngestFails(true)
	budget := syncbudget.New(syncbudget.WithTotal(1))
	opt := h.options()
	opt.Budget = budget
	_, err := cursorsync.Sync(context.Background(), opt, syncGate())
	if err == nil || errors.Is(err, syncbudget.ErrTotalExhausted) {
		t.Fatalf("the failed POST must surface as an upload failure, not a budget decline: %v", err)
	}
	if budget.Used() != 1 {
		t.Fatalf("a failed POST must still spend its reserved attempt, used=%d", budget.Used())
	}
	if _, _, ingest, _, batches := h.srv.stats(); ingest != 1 || len(batches) != 0 {
		t.Fatalf("exactly one (failed) ingest POST may happen: ingest=%d batches=%d", ingest, len(batches))
	}
	if n := pendingCount(t, h.dir); n != 1 {
		t.Fatalf("the failed batch must stay pending, pending=%d", n)
	}

	// Server healthy again, but the same run budget is spent: the next
	// round declines before any POST and keeps the batch pending.
	h.srv.setIngestFails(false)
	res, err := cursorsync.Sync(context.Background(), opt, syncGate())
	if !errors.Is(err, syncbudget.ErrTotalExhausted) {
		t.Fatalf("the spent attempt must not be refunded, got %v", err)
	}
	if res.SyncedBatches != 0 || res.PendingRemaining != 1 {
		t.Fatalf("the declined round must upload nothing and keep the batch pending: %+v", res)
	}
	if _, _, ingest, _, batches := h.srv.stats(); ingest != 1 || len(batches) != 0 {
		t.Fatalf("the declined round must not POST again: ingest=%d batches=%d", ingest, len(batches))
	}

	// A fresh budget uploads the still-pending batch.
	opt.Budget = syncbudget.New(syncbudget.WithTotal(1))
	res, err = cursorsync.Sync(context.Background(), opt, syncGate())
	if err != nil {
		t.Fatalf("fresh-budget round: %v", err)
	}
	if res.SyncedBatches != 1 || res.SyncedRecords != 1 || res.PendingRemaining != 0 {
		t.Fatalf("the retained batch must upload under the fresh budget: %+v", res)
	}
}
