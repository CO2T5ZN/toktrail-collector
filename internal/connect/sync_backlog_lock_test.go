package connect

// Backlog-pass single-lock semantics for the shared Sync orchestration:
//
//   - each backlog pass takes the exclusive state lock ONCE, through the
//     shared bounded busy retry, and holds it continuously across its
//     three sub-phases (device authorization refresh and drain, account
//     drain, terminal authorization check);
//   - a busy state directory makes the pass WAIT (bounded retry) instead
//     of failing the drain, and past the retry budget the pass fails with
//     runlock.ErrBusy having performed no work;
//   - the pass's locked sub-phases use the already-held-lock entries
//     (collection.DrainPendingLocked, cursorsync.DrainPendingLocked), so
//     a nested self-acquire would fail immediately with ErrBusy — the
//     white-box test below pins that by holding the lock itself;
//   - observed from the server side, the state lock is held while
//     account batches upload during a backlog pass.
//
// Everything is synthetic: tempdir state, one httptest TokTrail double
// and injected cursor auth/verify/pull fakes. No real Cursor state,
// credential or account is ever read.
import (
	"context"
	"errors"
	"testing"
	"time"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/local/cursorsource"
	"toktrail-collector/internal/local/runlock"
)

// backlogLockCollectOptions wires the collection options one backlog pass
// drains under, with the cursor wiring the seeded permit matches.
func backlogLockCollectOptions(dir, serverURL string, cursorMaxBatches int) collection.Options {
	return collection.Options{
		StateDir:   dir,
		ServerURL:  serverURL,
		MaxBatches: 5,
		Cursor: &cursorsync.Options{
			StateDir:   dir,
			ServerURL:  serverURL,
			Auth:       &cursorBacklogAuth{},
			Verify:     (&cursorBacklogVerify{}).verify,
			Pull:       (&cursorBacklogPull{}).pull,
			Now:        func() time.Time { return cursorBacklogNow },
			MaxBatches: cursorMaxBatches,
		},
	}
}

// TestBacklogPassWaitsForBusyStateLockAndDrains verifies the bounded busy
// retry: while another holder keeps the state lock, the backlog pass waits
// (instead of failing the drain) and completes as soon as the lock frees,
// draining both queues in the same pass.
func TestBacklogPassWaitsForBusyStateLockAndDrains(t *testing.T) {
	withLockRetry(t, 5*time.Second, 25*time.Millisecond)

	dir := t.TempDir()
	homeDir := t.TempDir()
	mock := startCursorBacklogMock(t)
	seedCursorBacklogState(t, dir, mock.URL)
	seedCodexSessionsGrant(t, dir, homeDir)
	seedCursorBacklogPermit(t, dir, cursorsource.StatusActive)
	seedDeviceBacklogBatch(t, dir, homeDir, "bbl-busy-dev-1", "bbl-busy-key-1")
	seedCursorBacklogBatch(t, dir, "bbl-busy-cursor-1", 1)

	held, err := runlock.Acquire(dir)
	if err != nil {
		t.Fatalf("hold the state lock: %v", err)
	}
	releaseAt := time.Now().Add(300 * time.Millisecond)
	timer := time.AfterFunc(300*time.Millisecond, func() { _ = held.Close() })
	defer timer.Stop()

	start := time.Now()
	res, err := runBacklogPass(context.Background(), backlogLockCollectOptions(dir, mock.URL, 5), 1, false, false)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("the backlog pass must wait out the busy lock and then drain: %v", err)
	}
	if elapsed < 300*time.Millisecond {
		t.Fatalf("the pass must have waited for the holder to release (held 300ms), elapsed %s", elapsed)
	}
	if !start.Before(releaseAt) {
		t.Fatalf("the pass must not have started before the lock was free")
	}
	if res.SyncedBatches != 1 || res.PendingRemaining != 0 {
		t.Fatalf("the device queue must be drained in the waiting pass: %+v", res)
	}
	if res.Cursor.SyncedBatches != 1 || res.Cursor.PendingRemaining != 0 {
		t.Fatalf("the cursor queue must be drained in the waiting pass: %+v", res.Cursor)
	}
}

// TestBacklogPassBusyPastBudgetPerformsNoWork verifies the exhaustion
// path: when the state lock stays busy past the retry budget, the pass
// fails with runlock.ErrBusy after honoring the full budget (a bounded
// retry, not a fail-fast) and performs no work at all.
func TestBacklogPassBusyPastBudgetPerformsNoWork(t *testing.T) {
	withLockRetry(t, 250*time.Millisecond, 20*time.Millisecond)

	dir := t.TempDir()
	homeDir := t.TempDir()
	mock := startCursorBacklogMock(t)
	seedCursorBacklogState(t, dir, mock.URL)
	seedCodexSessionsGrant(t, dir, homeDir)
	seedCursorBacklogPermit(t, dir, cursorsource.StatusActive)
	seedDeviceBacklogBatch(t, dir, homeDir, "bbl-exhaust-dev-1", "bbl-exhaust-key-1")
	seedCursorBacklogBatch(t, dir, "bbl-exhaust-cursor-1", 1)

	held, err := runlock.Acquire(dir)
	if err != nil {
		t.Fatalf("hold the state lock: %v", err)
	}
	defer held.Close()

	start := time.Now()
	res, err := runBacklogPass(context.Background(), backlogLockCollectOptions(dir, mock.URL, 5), 1, false, false)
	elapsed := time.Since(start)
	if !errors.Is(err, runlock.ErrBusy) {
		t.Fatalf("a lock held past the retry budget must fail the pass with ErrBusy, got %+v, %v", res, err)
	}
	if elapsed < 250*time.Millisecond {
		t.Fatalf("the pass must honor the full retry budget before giving up, elapsed %s", elapsed)
	}
	if res.SyncedBatches != 0 || res.Cursor.SyncedBatches != 0 || res.AttemptedBatches != 0 {
		t.Fatalf("an exhausted pass must perform no work, got %+v", res)
	}
	if got := mock.srcBatchPosts(); got != 0 {
		t.Fatalf("an exhausted pass must not upload cursor batches, got %d", got)
	}
	if got := mock.deviceBatchPosts(); got != 0 {
		t.Fatalf("an exhausted pass must not upload device batches, got %d", got)
	}
	if got := mock.selfCalls(); got != 0 {
		t.Fatalf("an exhausted pass must not even refresh grants, got %d self calls", got)
	}
}

// TestBacklogPassRunsSubPhasesUnderCallerHeldLock is the nested-lock
// regression: the test itself holds the state lock and drives the pass's
// already-held-lock body directly. All three sub-phases (device drain,
// account drain, terminal authorization check) must complete under that
// one lock — any sub-phase that took the runlock itself would fail
// immediately with ErrBusy, because the lock is per open file
// description.
func TestBacklogPassRunsSubPhasesUnderCallerHeldLock(t *testing.T) {
	dir := t.TempDir()
	homeDir := t.TempDir()
	mock := startCursorBacklogMock(t)
	seedCursorBacklogState(t, dir, mock.URL)
	seedCodexSessionsGrant(t, dir, homeDir)
	seedCursorBacklogPermit(t, dir, cursorsource.StatusActive)
	seedDeviceBacklogBatch(t, dir, homeDir, "bbl-held-dev-1", "bbl-held-key-1")
	seedCursorBacklogBatch(t, dir, "bbl-held-cursor-1", 1)

	lock, err := runlock.Acquire(dir)
	if err != nil {
		t.Fatalf("acquire the state lock: %v", err)
	}
	defer lock.Close()

	res, err := runBacklogPassLocked(context.Background(), backlogLockCollectOptions(dir, mock.URL, 5), 1, false, false, lock)
	if err != nil {
		t.Fatalf("the whole pass must run under the caller's lock without ErrBusy: %v", err)
	}
	// Sub-phase 1: the device batch drained.
	if res.SyncedBatches != 1 || res.PendingRemaining != 0 {
		t.Fatalf("device drain: %+v", res)
	}
	// Sub-phase 2: the cursor batch drained under the same lock.
	if !res.Cursor.Ran || res.Cursor.SyncedBatches != 1 || res.Cursor.PendingRemaining != 0 {
		t.Fatalf("cursor drain: %+v", res.Cursor)
	}
	// Sub-phase 3: the terminal authorization check refreshed the grant
	// view and left no stop reason.
	if res.DrainStopped != "" {
		t.Fatalf("a stable scope must not stop the pass: %s", res.DrainStopped)
	}
	if !res.GrantSync.Active || res.GrantSync.ConsentRevision == 0 {
		t.Fatalf("the terminal check must leave a refreshed grant view: %+v", res.GrantSync)
	}
	if got := mock.srcBatchPosts(); got != 1 {
		t.Fatalf("expected exactly one cursor batch upload, got %d", got)
	}
	// The caller keeps owning the lock after the pass body.
	if err := lock.Validate(dir); err != nil {
		t.Fatalf("the pass body must not release the caller's lock: %v", err)
	}
}

// TestSyncBacklogPassHoldsStateLockThroughAccountDrain observes the lock
// from the server side: every account-source batch upload during a full
// Sync (the initial collection's cursor round AND the backlog passes)
// happens while the state lock is held. A drain that ran unlocked would
// let the probe acquire the lock and be counted as "free".
func TestSyncBacklogPassHoldsStateLockThroughAccountDrain(t *testing.T) {
	dir := t.TempDir()
	mock := startCursorBacklogMock(t)
	mock.probeLockOnSourceBatches(dir)
	seedCursorBacklogState(t, dir, mock.URL)
	seedCursorBacklogPermit(t, dir, cursorsource.StatusActive)
	// Three pending cursor batches against a per-round bound of two: the
	// initial round cannot drain them all, so a backlog pass must run and
	// upload the remainder.
	seedCursorBacklogBatch(t, dir, "bbl-probe-cursor-1", 1)
	seedCursorBacklogBatch(t, dir, "bbl-probe-cursor-2", 1)
	seedCursorBacklogBatch(t, dir, "bbl-probe-cursor-3", 1)

	res, err := Sync(context.Background(), SyncOptions{
		StateDir:  dir,
		ServerURL: mock.URL,
		Now:       func() time.Time { return cursorBacklogNow },
		Cursor: &cursorsync.Options{
			Auth:       &cursorBacklogAuth{},
			Verify:     (&cursorBacklogVerify{}).verify,
			Pull:       (&cursorBacklogPull{}).pull,
			Now:        func() time.Time { return cursorBacklogNow },
			MaxBatches: 2,
		},
	})
	if err != nil {
		t.Fatalf("sync with cursor backlog: %v (incomplete=%v)", err, res.Incomplete)
	}
	if res.Backlog.Passes < 1 || res.Backlog.CursorPendingRemaining != 0 {
		t.Fatalf("the cursor backlog must converge through a backlog pass: %+v", res.Backlog)
	}
	if got := mock.srcBatchPosts(); got != 3 {
		t.Fatalf("expected three cursor batch uploads (two initial, one backlog), got %d", got)
	}
	held, free := mock.lockProbeStats()
	if free != 0 {
		t.Fatalf("every account-source upload must observe the state lock as held, %d saw it free", free)
	}
	if held != 3 {
		t.Fatalf("every account-source upload must observe the state lock as held, got held=%d of 3", held)
	}
}
