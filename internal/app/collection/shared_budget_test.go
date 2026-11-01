package collection

import (
	"context"
	"errors"
	"testing"

	"toktrail-collector/internal/syncbudget"
)

func TestDrainPendingSharedBudgetPreservesRemaining(t *testing.T) {
	dir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, dir, server.URL)
	writePendingBatch(t, dir, "budget-pending-1")
	writePendingBatch(t, dir, "budget-pending-2")
	budget := syncbudget.New(syncbudget.WithTotal(1))
	result, err := DrainPending(context.Background(), Options{StateDir: dir, MaxBatches: 10, Budget: budget})
	if !errors.Is(err, syncbudget.ErrTotalExhausted) || result.SyncedBatches != 1 || result.PendingRemaining != 1 {
		t.Fatalf("expected one sent and one pending at budget limit: %+v err=%v", result, err)
	}
	if budget.Used() != 1 || server.ingestRequests() != 1 {
		t.Fatalf("actual POST attempts exceed budget: used=%d posts=%d", budget.Used(), server.ingestRequests())
	}
	result, err = DrainPending(context.Background(), Options{StateDir: dir, MaxBatches: 10})
	if err != nil || result.SyncedBatches != 1 || result.PendingRemaining != 0 {
		t.Fatalf("remaining batch did not resume: %+v err=%v", result, err)
	}
}
