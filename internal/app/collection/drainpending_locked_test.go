package collection

// Contract tests for DrainPendingLocked, the already-held-lock drain-only
// entry connect's backlog pass uses: the handed-over lock handle is
// verified (runlock.Lock.Validate) before any work, so a nil, closed or
// foreign lock fails closed — even when another holder occupies the state
// directory, which is exactly the case a lock-contention probe cannot
// distinguish from "the caller holds the lock". The public DrainPending
// keeps its own self-locking contract.
import (
	"context"
	"errors"
	"strings"
	"testing"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/runlock"
)

// seedLockedDrainCase builds a bound state directory with one pending
// device batch against a fresh fake server, plus a held runlock.
func seedLockedDrainCase(t *testing.T, name string) (stateDir string, server *fakeCollectorServer, lock *runlock.Lock) {
	t.Helper()
	stateDir = t.TempDir()
	server = fakeServer(t)
	bindDevice(t, stateDir, server.URL)
	writePendingBatch(t, stateDir, name)
	lock, err := runlock.Acquire(stateDir)
	if err != nil {
		t.Fatalf("acquire state lock: %v", err)
	}
	return stateDir, server, lock
}

// pendingDeviceBatches counts the outbox's pending entries.
func pendingDeviceBatches(t *testing.T, stateDir string) int {
	t.Helper()
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatalf("load outbox: %v", err)
	}
	count := 0
	for _, b := range out.Batches {
		if b.Status == outbox.StatusPending {
			count++
		}
	}
	return count
}

// assertLockedContractRejection checks one fail-closed handle rejection:
// a contract error naming the state lock, no upload, and the pending
// batch untouched.
func assertLockedContractRejection(t *testing.T, stateDir string, server *fakeCollectorServer, res Result, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "state lock") {
		t.Fatalf("expected the lock-contract failure, got %+v, %v", res, err)
	}
	if res.SyncedBatches != 0 || res.AttemptedBatches != 0 {
		t.Fatalf("a rejected locked drain must not attempt work, got %+v", res)
	}
	if got := server.ingestRequests(); got != 0 {
		t.Fatalf("a rejected locked drain must not upload anything, got %d ingests", got)
	}
	if n := pendingDeviceBatches(t, stateDir); n != 1 {
		t.Fatalf("a rejected locked drain must leave the pending batch untouched, pending=%d", n)
	}
}

// TestDrainPendingLockedRejectsInvalidLocks covers the fail-closed handle
// contract: a nil lock, a closed lock (even while another holder occupies
// the state directory — busy content must never read as "the caller holds
// the lock"), and a lock acquired for a different state directory.
func TestDrainPendingLockedRejectsInvalidLocks(t *testing.T) {
	t.Run("nil lock", func(t *testing.T) {
		stateDir, server, lock := seedLockedDrainCase(t, "locked-nil-1")
		defer lock.Close()
		res, err := DrainPendingLocked(context.Background(), Options{StateDir: stateDir, MaxBatches: 10}, nil)
		assertLockedContractRejection(t, stateDir, server, res, err)
	})
	t.Run("closed lock while another holder occupies", func(t *testing.T) {
		stateDir, server, lock := seedLockedDrainCase(t, "locked-closed-1")
		if err := lock.Close(); err != nil {
			t.Fatalf("release the caller lock: %v", err)
		}
		// Another holder now occupies the directory's lock; a probe-style
		// check (attempt an acquire, read ErrBusy) would wrongly pass here.
		other, err := runlock.Acquire(stateDir)
		if err != nil {
			t.Fatalf("occupy the state lock: %v", err)
		}
		defer other.Close()
		res, err := DrainPendingLocked(context.Background(), Options{StateDir: stateDir, MaxBatches: 10}, lock)
		assertLockedContractRejection(t, stateDir, server, res, err)
	})
	t.Run("lock from a different state directory", func(t *testing.T) {
		stateDir, server, lock := seedLockedDrainCase(t, "locked-foreign-1")
		defer lock.Close()
		foreign, err := runlock.Acquire(t.TempDir())
		if err != nil {
			t.Fatalf("acquire foreign lock: %v", err)
		}
		defer foreign.Close()
		res, err := DrainPendingLocked(context.Background(), Options{StateDir: stateDir, MaxBatches: 10}, foreign)
		assertLockedContractRejection(t, stateDir, server, res, err)
	})
}

// TestDrainPendingLockedDrainsUnderCallerHeldLock covers the positive
// contract: with the caller holding the lock, the locked entry drains the
// pending batches (and the public DrainPending still self-locks — it
// fails fast with ErrBusy while the caller holds, then finds the outbox
// empty once the caller releases).
func TestDrainPendingLockedDrainsUnderCallerHeldLock(t *testing.T) {
	stateDir, server, lock := seedLockedDrainCase(t, "locked-drain-a")
	writePendingBatch(t, stateDir, "locked-drain-b")

	// The public entry point keeps its own self-locking contract.
	if _, err := DrainPending(context.Background(), Options{StateDir: stateDir, MaxBatches: 10}); !errors.Is(err, runlock.ErrBusy) {
		t.Fatalf("the self-locking DrainPending must fail with ErrBusy while the caller holds the lock, got %v", err)
	}

	res, err := DrainPendingLocked(context.Background(), Options{StateDir: stateDir, MaxBatches: 10}, lock)
	if err != nil {
		t.Fatalf("locked drain: %v", err)
	}
	if res.SyncedBatches != 2 || res.PendingRemaining != 0 {
		t.Fatalf("the locked drain must empty the outbox, got %+v", res)
	}
	if got := server.ingestRequests(); got != 2 {
		t.Fatalf("expected two ingest uploads, got %d", got)
	}
	// The caller still owns the lock afterwards.
	if err := lock.Validate(stateDir); err != nil {
		t.Fatalf("the locked drain must not release the caller's lock: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("release the caller lock: %v", err)
	}

	after, err := DrainPending(context.Background(), Options{StateDir: stateDir, MaxBatches: 10})
	if err != nil {
		t.Fatalf("self-locking drain after release: %v", err)
	}
	if after.SyncedBatches != 0 || after.PendingRemaining != 0 {
		t.Fatalf("nothing may remain after the locked drain, got %+v", after)
	}
}
