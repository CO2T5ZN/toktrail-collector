// Single-writer runlock semantics for cursorsync.DrainPending and
// DrainPendingLocked: the public drain-only entry acquires the collector
// runlock for its whole round (a concurrent holder fails fast with
// runlock.ErrBusy before any work), and releases it again on every exit
// path — the ordinary drain, the fence-changed skip and the busy
// rejection. Sync and Enable continue to rely on their callers' existing
// lock contract. DrainPendingLocked is the already-held-lock path
// (connect's backlog pass): it verifies the handed-over handle
// (runlock.Lock.Validate) before any work, so a nil, closed or foreign
// lock fails closed — even when another holder occupies the state
// directory, which a lock-contention probe could not distinguish from
// "the caller holds the lock".
package cursorsync_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/local/runlock"
)

// TestDrainPendingFailsFastWithErrBusyWhileRunlockHeld verifies the
// single-writer contract: while the collector runlock is held (here by the
// test process itself — the per-open-file-description flock treats a second
// acquire in the same process exactly like another process), DrainPending
// returns runlock.ErrBusy and performs no work: no preflight, no license
// write, no outbox mutation, no upload. Once the holder releases, the same
// call drains the backlog normally.
func TestDrainPendingFailsFastWithErrBusyWhileRunlockHeld(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-drain-busy-1", 1)

	lock, err := runlock.Acquire(h.dir)
	if err != nil {
		t.Fatalf("hold runlock: %v", err)
	}
	res, err := cursorsync.DrainPending(context.Background(), h.options(), syncGate())
	if !errors.Is(err, runlock.ErrBusy) {
		t.Fatalf("expected runlock.ErrBusy while the state lock is held, got %v", err)
	}
	if res.Ran {
		t.Fatal("a busy drain must not report a ran round")
	}
	if n := pendingCount(t, h.dir); n != 1 {
		t.Fatalf("a busy drain must leave the pending batch untouched, pending=%d", n)
	}
	if _, _, ingest, _, batches := h.srv.stats(); ingest != 0 || len(batches) != 0 {
		t.Fatalf("a busy drain must not upload anything: ingest=%d batches=%d", ingest, len(batches))
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("release runlock: %v", err)
	}

	res, err = cursorsync.DrainPending(context.Background(), h.options(), syncGate())
	if err != nil {
		t.Fatalf("drain after release: %v", err)
	}
	if !res.Ran || res.SyncedBatches != 1 || res.SyncedRecords != 1 || res.PendingRemaining != 0 {
		t.Fatalf("drain after release: %+v", res)
	}
}

// TestDrainPendingDrainsUnderOwnRunlockAndReleasesIt covers the ordinary
// drain through the self-acquired lock: pending batches upload without any
// credential read or upstream pull, and the runlock is free again afterwards
// (a leaked lock would starve every later scheduled collection round), so an
// immediate second round also acquires the lock and finds nothing left.
func TestDrainPendingDrainsUnderOwnRunlockAndReleasesIt(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-drain-lock-1", 1)
	seedPendingBatch(t, h.dir, "cursor-drain-lock-2", 1)

	res, err := cursorsync.DrainPending(context.Background(), h.options(), syncGate())
	if err != nil {
		t.Fatalf("drain pending: %v", err)
	}
	if !res.Ran || res.SyncedBatches != 2 || res.SyncedRecords != 2 || res.PendingRemaining != 0 {
		t.Fatalf("drain result: %+v", res)
	}
	if h.auth.fetchCount() != 0 || len(h.pull.callLog()) != 0 {
		t.Fatal("drain-only must not read credentials or pull upstream usage")
	}

	// The runlock must be free again after the round.
	lock, err := runlock.Acquire(h.dir)
	if err != nil {
		t.Fatalf("DrainPending must release the runlock after the round: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("release runlock: %v", err)
	}

	res2, err := cursorsync.DrainPending(context.Background(), h.options(), syncGate())
	if err != nil {
		t.Fatalf("second drain: %v", err)
	}
	if !res2.Ran || res2.SyncedBatches != 0 || res2.PendingRemaining != 0 {
		t.Fatalf("second drain result: %+v", res2)
	}
}

// TestDrainPendingFenceChangeUnderOwnRunlockPreservesRecovery covers the
// fence-moved path through the self-acquired lock — including its early
// return: the drain skips without consuming the pending batch or touching
// the recorded fence/watermark (recovery stays a full Sync's job), the
// runlock is released again on that skip path, and the recovery full sync
// (which runs under its caller's lock, never its own) re-produces the
// fenced history right after.
func TestDrainPendingFenceChangeUnderOwnRunlockPreservesRecovery(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	h.pull.setEvents(ev("evt-fence-1", baseTime.Add(-30*time.Minute), 100, 0, 0, 50))
	h.srv.setIngestFails(true)
	if _, err := cursorsync.Sync(context.Background(), h.options(), syncGate()); err == nil {
		t.Fatal("expected the initial round to fail on upload and leave a pending batch")
	}
	h.srv.setIngestFails(false)
	h.srv.setSource(protocol.Source{SourceInstanceID: "src_inst_1", SourceType: protocol.SourceType, State: "active", FenceVersion: 2, NextRevision: 10})
	before := len(h.pull.callLog())

	res, err := cursorsync.DrainPending(context.Background(), h.options(), syncGate())
	if err != nil || !strings.Contains(res.Skipped, "full sync") || res.PendingRemaining != 1 {
		t.Fatalf("fence change must stop without consuming pending data: %+v, %v", res, err)
	}
	if lic := loadLicense(t, h.dir); lic.FenceVersion != 1 || lic.PullWatermark == nil {
		t.Fatalf("drain must retain the old fence and watermark for recovery: %+v", lic)
	}
	if len(h.pull.callLog()) != before {
		t.Fatal("drain-only must not pull")
	}

	// The fence-skip path returns early; it must not leak the runlock.
	lock, err := runlock.Acquire(h.dir)
	if err != nil {
		t.Fatalf("DrainPending must release the runlock on the fence-skip path: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("release runlock: %v", err)
	}

	full, err := cursorsync.Sync(context.Background(), h.options(), syncGate())
	if err != nil || full.NewRecords != 1 || full.SyncedRecords != 1 || full.PendingRemaining != 0 {
		t.Fatalf("full sync must re-produce the fenced history: %+v, %v", full, err)
	}
}

// assertCursorLockedRejection checks one fail-closed handle rejection of
// cursorsync.DrainPendingLocked: a contract error naming the state lock,
// no upload, and the pending batch untouched.
func assertCursorLockedRejection(t *testing.T, h *harness, res cursorsync.Result, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "state lock") {
		t.Fatalf("expected the lock-contract failure, got %+v, %v", res, err)
	}
	if res.Ran {
		t.Fatal("a rejected locked drain must not report a ran round")
	}
	if n := pendingCount(t, h.dir); n != 1 {
		t.Fatalf("a rejected locked drain must leave the pending batch untouched, pending=%d", n)
	}
	if _, _, ingest, _, batches := h.srv.stats(); ingest != 0 || len(batches) != 0 {
		t.Fatalf("a rejected locked drain must not upload anything: ingest=%d batches=%d", ingest, len(batches))
	}
}

// TestDrainPendingLockedRejectsInvalidLocks covers the fail-closed handle
// contract of the already-held-lock cursor drain: a nil lock, a closed
// lock (even while another holder occupies the state directory — busy
// content must never read as "the caller holds the lock"), and a lock
// acquired for a different state directory.
func TestDrainPendingLockedRejectsInvalidLocks(t *testing.T) {
	t.Run("nil lock", func(t *testing.T) {
		h := newHarness(t)
		h.srv.setSource(defaultSource())
		h.writeLicense(t, activeLicenseForA())
		seedPendingBatch(t, h.dir, "cursor-locked-nil-1", 1)
		lock, err := runlock.Acquire(h.dir)
		if err != nil {
			t.Fatalf("acquire state lock: %v", err)
		}
		defer lock.Close()
		res, err := cursorsync.DrainPendingLocked(context.Background(), h.options(), syncGate(), nil)
		assertCursorLockedRejection(t, h, res, err)
	})
	t.Run("closed lock while another holder occupies", func(t *testing.T) {
		h := newHarness(t)
		h.srv.setSource(defaultSource())
		h.writeLicense(t, activeLicenseForA())
		seedPendingBatch(t, h.dir, "cursor-locked-closed-1", 1)
		lock, err := runlock.Acquire(h.dir)
		if err != nil {
			t.Fatalf("acquire state lock: %v", err)
		}
		if err := lock.Close(); err != nil {
			t.Fatalf("release the caller lock: %v", err)
		}
		// Another holder now occupies the directory's lock; a probe-style
		// check (attempt an acquire, read ErrBusy) would wrongly pass here.
		other, err := runlock.Acquire(h.dir)
		if err != nil {
			t.Fatalf("occupy the state lock: %v", err)
		}
		defer other.Close()
		res, err := cursorsync.DrainPendingLocked(context.Background(), h.options(), syncGate(), lock)
		assertCursorLockedRejection(t, h, res, err)
	})
	t.Run("lock from a different state directory", func(t *testing.T) {
		h := newHarness(t)
		h.srv.setSource(defaultSource())
		h.writeLicense(t, activeLicenseForA())
		seedPendingBatch(t, h.dir, "cursor-locked-foreign-1", 1)
		foreign, err := runlock.Acquire(t.TempDir())
		if err != nil {
			t.Fatalf("acquire foreign lock: %v", err)
		}
		defer foreign.Close()
		res, err := cursorsync.DrainPendingLocked(context.Background(), h.options(), syncGate(), foreign)
		assertCursorLockedRejection(t, h, res, err)
	})
}

// TestDrainPendingLockedDrainsUnderCallerHeldLock covers the positive
// contract: with the caller holding the lock, the locked entry drains the
// pending cursor batches without reading credentials or pulling upstream
// usage (and the public DrainPending still self-locks — it fails fast
// with ErrBusy while the caller holds).
func TestDrainPendingLockedDrainsUnderCallerHeldLock(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-locked-drain-1", 1)
	seedPendingBatch(t, h.dir, "cursor-locked-drain-2", 1)

	lock, err := runlock.Acquire(h.dir)
	if err != nil {
		t.Fatalf("acquire state lock: %v", err)
	}
	// The public entry point keeps its own self-locking contract.
	if _, err := cursorsync.DrainPending(context.Background(), h.options(), syncGate()); !errors.Is(err, runlock.ErrBusy) {
		t.Fatalf("the self-locking DrainPending must fail with ErrBusy while the caller holds the lock, got %v", err)
	}

	res, err := cursorsync.DrainPendingLocked(context.Background(), h.options(), syncGate(), lock)
	if err != nil {
		t.Fatalf("locked cursor drain: %v", err)
	}
	if !res.Ran || res.SyncedBatches != 2 || res.SyncedRecords != 2 || res.PendingRemaining != 0 {
		t.Fatalf("locked drain result: %+v", res)
	}
	if h.auth.fetchCount() != 0 || len(h.pull.callLog()) != 0 {
		t.Fatal("drain-only must not read credentials or pull upstream usage")
	}
	// The caller still owns the lock afterwards.
	if err := lock.Validate(h.dir); err != nil {
		t.Fatalf("the locked drain must not release the caller's lock: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("release the caller lock: %v", err)
	}

	res2, err := cursorsync.DrainPending(context.Background(), h.options(), syncGate())
	if err != nil {
		t.Fatalf("self-locking drain after release: %v", err)
	}
	if !res2.Ran || res2.SyncedBatches != 0 || res2.PendingRemaining != 0 {
		t.Fatalf("nothing may remain after the locked drain, got %+v", res2)
	}
}
