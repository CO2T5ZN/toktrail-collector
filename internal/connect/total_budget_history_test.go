package connect

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
)

func TestSyncMaxTotalBatchesAlsoBoundsHistory(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	mock := startSyncToktrailMock(t, "dev-total-history")
	seedBoundState(t, dir, mock.URL, "dev-total-history")
	seedCodexGrant(t, dir, home)
	for i := 0; i < 5; i++ {
		seedBatch(t, dir, home, fmt.Sprintf("old-%d", i), outbox.StatusSynced, syncRecord(fmt.Sprintf("old-key-%d", i), syncTestNow.Add(-time.Hour).Format(time.RFC3339)))
	}
	for i := 0; i < 3; i++ {
		seedBatch(t, dir, home, fmt.Sprintf("pending-%d", i), outbox.StatusPending, syncRecord(fmt.Sprintf("pending-key-%d", i), syncTestNow.Add(-time.Hour).Format(time.RFC3339)))
	}
	result, err := Sync(context.Background(), SyncOptions{StateDir: dir, ServerURL: mock.URL, HomeDir: home, HTTPClient: mock.Client(), Now: func() time.Time { return syncTestNow }, MaxTotalBatches: 5})
	if !errors.Is(err, ErrSyncIncomplete) {
		t.Fatalf("budget-bound run must report incomplete: %+v, %v", result, err)
	}
	if got := mock.totalIngests(); got != 5 {
		t.Fatalf("device and history must share total budget: got %d posts, want 5", got)
	}
	if !result.BudgetExhausted || result.Resync.Completed {
		t.Fatalf("history remainder must be resumable and incomplete: %+v", result)
	}
}
