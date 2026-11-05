package collection

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
)

// seedPendingBatch writes one pending batch with an explicit record window.
// A zero newest means "written before the window existed" (the historical
// shape), which the selector must never treat as recent.
func seedPendingBatch(t *testing.T, stateDir, batchID string, newest, oldest time.Time) {
	t.Helper()
	dir := filepath.Join(stateDir, "batches")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, batchID+".json")
	payload, err := json.Marshal(map[string]any{
		"batchId": batchID,
		"records": []map[string]any{{
			"recordKey":      batchID + "-record-1",
			"kind":           "delta",
			"occurredAt":     "2026-10-21T04:00:00Z",
			"tool":           "usage-json",
			"input":          "10",
			"cacheRead":      "0",
			"cacheWrite":     "0",
			"output":         "5",
			"adapterVersion": "collection-test-1",
			"sourceType":     "fixture",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{
		BatchID:        batchID,
		File:           path,
		Source:         "usage-json",
		Input:          "fixture",
		RecordCount:    1,
		OldestRecordAt: oldest,
		NewestRecordAt: newest,
	}); err != nil {
		t.Fatal(err)
	}
}

func pendingIDs(t *testing.T, stateDir string) (pending []string, synced []string) {
	t.Helper()
	ledger, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range ledger.Batches {
		switch entry.Status {
		case outbox.StatusPending:
			pending = append(pending, entry.BatchID)
		case outbox.StatusSynced:
			synced = append(synced, entry.BatchID)
		}
	}
	return pending, synced
}

// The selector prefers the batch holding the newest records, falls back to the
// oldest pending batch when nothing is recent, and forces the oldest on the
// anti-starvation turn.
func TestSelectPendingBatchOrdering(t *testing.T) {
	now := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	entries := []outbox.BatchEntry{
		{BatchID: "legacy", Status: outbox.StatusPending},
		{BatchID: "old", Status: outbox.StatusPending, NewestRecordAt: now.AddDate(0, -6, 0)},
		{BatchID: "recent", Status: outbox.StatusPending, NewestRecordAt: now.Add(-2 * time.Hour)},
		{BatchID: "synced", Status: outbox.StatusSynced, NewestRecordAt: now},
	}
	if got, ok := selectPendingBatch(entries, now, recentRecordWindow, false); !ok || got.BatchID != "recent" {
		t.Fatalf("recent data must win, got %q (ok=%v)", got.BatchID, ok)
	}
	if got, ok := selectPendingBatch(entries, now, recentRecordWindow, true); !ok || got.BatchID != "legacy" {
		t.Fatalf("the anti-starvation turn must serve the oldest pending batch, got %q (ok=%v)", got.BatchID, ok)
	}
	// Nothing recent: the historical oldest-first order.
	noRecent := []outbox.BatchEntry{
		{BatchID: "a", Status: outbox.StatusPending, NewestRecordAt: now.AddDate(0, -6, 0)},
		{BatchID: "b", Status: outbox.StatusPending, NewestRecordAt: now.AddDate(0, -3, 0)},
	}
	if got, ok := selectPendingBatch(noRecent, now, recentRecordWindow, false); !ok || got.BatchID != "a" {
		t.Fatalf("with nothing recent the oldest batch goes first, got %q", got.BatchID)
	}
	if _, ok := selectPendingBatch(nil, now, recentRecordWindow, false); ok {
		t.Fatal("an empty queue has no pending batch")
	}
}

// End to end: a device holding a large old backlog uploads its recent batch
// first, so today's usage is not stuck behind history.
func TestDrainUploadsRecentBatchBeforeOldBacklog(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)
	now := time.Now().UTC()
	seedPendingBatch(t, stateDir, "batch-legacy", time.Time{}, time.Time{})
	seedPendingBatch(t, stateDir, "batch-old", now.AddDate(0, -6, 0), now.AddDate(0, -7, 0))
	seedPendingBatch(t, stateDir, "batch-recent", now.Add(-time.Hour), now.Add(-3*time.Hour))

	if _, err := Run(t.Context(), Options{StateDir: stateDir, MaxBatches: 1, Now: func() time.Time { return now }}); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	pending, synced := pendingIDs(t, stateDir)
	if len(synced) != 1 || synced[0] != "batch-recent" {
		t.Fatalf("the recent batch must upload first, synced=%v pending=%v", synced, pending)
	}
	if len(pending) != 2 {
		t.Fatalf("the backlog must stay queued, pending=%v", pending)
	}

	// Without any recent batch left, the backlog resumes in its own order.
	if _, err := Run(t.Context(), Options{StateDir: stateDir, MaxBatches: 2, Now: func() time.Time { return now }}); err != nil {
		t.Fatalf("second run failed: %v", err)
	}
	pending, synced = pendingIDs(t, stateDir)
	if len(synced) != 3 {
		t.Fatalf("the whole queue must drain, synced=%v pending=%v", synced, pending)
	}
}

// The anti-starvation turn is part of the loop: every fourth upload of a run
// serves the oldest pending batch even while recent batches keep arriving.
func TestDrainServesOldestEveryFourthUpload(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)
	now := time.Now().UTC()
	seedPendingBatch(t, stateDir, "batch-oldest", now.AddDate(0, -6, 0), now.AddDate(0, -7, 0))
	for i := 1; i <= 4; i++ {
		seedPendingBatch(t, stateDir, fmt.Sprintf("batch-recent-%d", i), now.Add(-time.Duration(i)*time.Hour), now.Add(-time.Duration(i+2)*time.Hour))
	}

	if _, err := Run(t.Context(), Options{StateDir: stateDir, MaxBatches: 4, Now: func() time.Time { return now }}); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	_, synced := pendingIDs(t, stateDir)
	if len(synced) != 4 {
		t.Fatalf("four uploads expected, got %v", synced)
	}
	found := false
	for _, id := range synced {
		if id == "batch-oldest" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the anti-starvation turn must upload the oldest batch, got %v", synced)
	}
}
