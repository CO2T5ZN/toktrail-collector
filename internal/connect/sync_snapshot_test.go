package connect

// Snapshot-restriction tests for the automatic history retransmission:
// connect captures the synced outbox universe after authorization refresh,
// under the continuous initial-collection lock, before scanning and uploading.
// Retransmission is restricted to that original universe. A nil snapshot
// keeps explicit resync's full-archive semantics; resumed and replanned jobs
// retain their frozen universe even when consent scope changes.

import (
	"context"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
)

// TestSyncRetransmissionCoversOnlyPreConnectSyncedHistory verifies the
// mixed case end to end: pre-existing synced batches ARE retransmitted,
// while the batches this run's collection drains are uploaded once by
// the drain and never immediately replayed.
func TestSyncRetransmissionCoversOnlyPreConnectSyncedHistory(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startSyncToktrailMock(t, "dev-mix-1")
	cfg := startSyncConfigMock(t, mock.URL, []string{"Codex"}, intPtr(30))

	seedBoundState(t, stateDir, mock.URL, "dev-mix-1")
	seedBatch(t, stateDir, homeDir, "mix-old-1", outbox.StatusSynced,
		syncRecord("mix-key-1", syncTestNow.Add(-time.Hour).Format(time.RFC3339)),
		syncRecord("mix-key-2", syncTestNow.Add(-90*time.Minute).Format(time.RFC3339)))
	seedBatch(t, stateDir, homeDir, "mix-old-2", outbox.StatusSynced,
		syncRecord("mix-key-3", syncTestNow.Add(-2*time.Hour).Format(time.RFC3339)))
	seedBatch(t, stateDir, homeDir, "mix-new-1", outbox.StatusPending,
		syncRecord("mix-key-4", syncTestNow.Add(-3*time.Hour).Format(time.RFC3339)))
	seedBatch(t, stateDir, homeDir, "mix-new-2", outbox.StatusPending,
		syncRecord("mix-key-5", syncTestNow.Add(-4*time.Hour).Format(time.RFC3339)))

	res, err := runSyncConnect(t, cfg, stateDir, homeDir, strings.Repeat("2", 64))
	if err != nil {
		t.Fatalf("mixed connect failed: %v", err)
	}
	if len(res.Sync.Incomplete) != 0 {
		t.Fatalf("a fully covered mixed run must be complete, got: %v", res.Sync.Incomplete)
	}
	if !res.Sync.Resync.Completed || res.Sync.Resync.Uploads != 2 || res.Sync.Resync.UploadedRecords != 3 {
		t.Fatalf("the retransmission must cover exactly the 2 pre-connect batches (3 records), got %+v", res.Sync.Resync)
	}
	if res.Sync.Resync.Remaining != 0 || res.Sync.Resync.Blocked != 0 || res.Sync.Resync.ReplayReceipts != 0 {
		t.Fatalf("a clean mixed retransmission has nothing withheld or replayed, got %+v", res.Sync.Resync)
	}
	if res.Sync.Resync.ExcludedAfterSnapshot != 2 {
		t.Fatalf("the 2 batches synced during this run must be reported as excluded by the snapshot, got %+v", res.Sync.Resync)
	}
	if ids := journalBatchIDs(t, stateDir); len(ids) != 2 || ids[0] != "mix-old-2" || ids[1] != "mix-old-1" {
		t.Fatalf("the restricted job must plan exactly the pre-connect synced batches (oldest first), got %v", ids)
	}
	for _, id := range []string{"mix-old-1", "mix-old-2"} {
		if got := mock.ingestCount(id); got != 1 {
			t.Fatalf("pre-connect batch %s must be retransmitted exactly once, got %d posts", id, got)
		}
	}
	for _, id := range []string{"mix-new-1", "mix-new-2"} {
		if got := mock.ingestCount(id); got != 1 {
			t.Fatalf("batch %s synced by this run must be uploaded once by the drain and never replayed, got %d posts", id, got)
		}
	}
	if got := mock.totalIngests(); got != 4 {
		t.Fatalf("expected 2 drain + 2 retransmission uploads, got %d", got)
	}
	for _, key := range []string{"mix-key-1", "mix-key-2", "mix-key-3", "mix-key-4", "mix-key-5"} {
		if !mock.receivedKey(key) {
			t.Fatalf("the server must have received record %s", key)
		}
	}
}

// TestSyncNilSnapshotKeepsFullRetransmission pins the nil-snapshot
// semantics at the Sync level: a caller that passes no ResyncSnapshot
// (the resync CLI) keeps the ORIGINAL behavior — the executed
// retransmission re-plans after the collection and replays the batches
// the same run synced.
func TestSyncNilSnapshotKeepsFullRetransmission(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startSyncToktrailMock(t, "dev-nilsem-1")

	seedBoundState(t, stateDir, mock.URL, "dev-nilsem-1")
	seedCodexGrant(t, stateDir, homeDir)
	seedBatch(t, stateDir, homeDir, "nilsem-old", outbox.StatusSynced,
		syncRecord("nilsem-key-old", syncTestNow.Add(-time.Hour).Format(time.RFC3339)))
	seedBatch(t, stateDir, homeDir, "nilsem-new", outbox.StatusPending,
		syncRecord("nilsem-key-new", syncTestNow.Add(-2*time.Hour).Format(time.RFC3339)))

	res, err := Sync(context.Background(), SyncOptions{
		StateDir:   stateDir,
		ServerURL:  mock.URL,
		HTTPClient: mock.Client(),
		Now:        func() time.Time { return syncTestNow },
	})
	if err != nil {
		t.Fatalf("the nil-snapshot run must complete: %v", err)
	}
	if !res.Resync.Completed || res.Resync.Uploads != 2 {
		t.Fatalf("a nil snapshot must retransmit the complete archive including this run's batch, got %+v", res.Resync)
	}
	if ids := journalBatchIDs(t, stateDir); len(ids) != 2 {
		t.Fatalf("the nil-snapshot job must plan both batches, got %v", ids)
	}
	if got := mock.ingestCount("nilsem-old"); got != 1 {
		t.Fatalf("the pre-existing batch must be uploaded once by the retransmission, got %d", got)
	}
	if got := mock.ingestCount("nilsem-new"); got != 2 {
		t.Fatalf("the freshly synced batch must be uploaded by the drain AND replayed (original semantics), got %d", got)
	}
}

// TestSyncScopeChangePreservesSnapshotHistory verifies that a scope-change
// re-plan preserves the original job's pre-connect history boundary.
func TestSyncScopeChangePreservesSnapshotHistory(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startSyncToktrailMock(t, "dev-replan-1")
	cfg := startSyncConfigMock(t, mock.URL, []string{"Codex"}, intPtr(30))

	seedBoundState(t, stateDir, mock.URL, "dev-replan-1")
	seedBatch(t, stateDir, homeDir, "rp-old", outbox.StatusSynced,
		syncRecord("rp-key-old", syncTestNow.Add(-time.Hour).Format(time.RFC3339)))
	seedBatch(t, stateDir, homeDir, "rp-new", outbox.StatusPending,
		syncRecord("rp-key-new", syncTestNow.Add(-2*time.Hour).Format(time.RFC3339)))

	// Run 1: the collection drains rp-new, but the retransmission (whose
	// snapshot covers only rp-old) fails on its single upload, leaving
	// the restricted job incomplete.
	mock.setFailIngest("rp-old")
	ticket := strings.Repeat("3", 64)
	res1, err := runSyncConnect(t, cfg, stateDir, homeDir, ticket)
	if err == nil || !strings.Contains(err.Error(), "history retransmission failed") {
		t.Fatalf("the failed retransmission must fail the run honestly, got: %v", err)
	}
	if res1.Sync.Resync.Completed {
		t.Fatalf("the restricted job must stay incomplete, got %+v", res1.Sync.Resync)
	}
	if ids := journalBatchIDs(t, stateDir); len(ids) != 1 || ids[0] != "rp-old" {
		t.Fatalf("run 1's job must be restricted to the pre-connect synced batch, got %v", ids)
	}
	if res1.Sync.Resync.ExcludedAfterSnapshot != 1 {
		t.Fatalf("rp-new (synced during run 1) must be reported as excluded by the snapshot, got %+v", res1.Sync.Resync)
	}

	// Run 2 moves the authorization revision and uploads rp-run2. The
	// resumed job must re-plan only the original frozen history (rp-old),
	// not rp-new or rp-run2, and stop before retransmitting.
	mock.setFailIngest("")
	mock.setRevision(2)
	seedBatch(t, stateDir, homeDir, "rp-run2", outbox.StatusPending,
		syncRecord("rp-key-run2", syncTestNow.Add(-3*time.Hour).Format(time.RFC3339)))
	res2, err := runSyncConnect(t, cfg, stateDir, homeDir, ticket)
	if err == nil || !strings.Contains(err.Error(), "consent scope changed") {
		t.Fatalf("the scope-change re-plan must stop the run, got: %v", err)
	}
	if res2.Sync.Resync.Stopped != "consent scope changed" || res2.Sync.Resync.Completed {
		t.Fatalf("the re-plan outcome must be reported, got %+v", res2.Sync.Resync)
	}
	if got := mock.ingestCount("rp-run2"); got != 1 {
		t.Fatalf("run 2's collection must drain rp-run2 once, got %d posts", got)
	}
	ids := journalBatchIDs(t, stateDir)
	if len(ids) != 1 || ids[0] != "rp-old" {
		t.Fatalf("the re-planned job must retain its original history boundary, got %v", ids)
	}

	// Run 3 resumes and completes the re-planned restricted history.
	res3, err := runSyncConnect(t, cfg, stateDir, homeDir, ticket)
	if err != nil {
		t.Fatalf("the re-planned pass must complete: %v", err)
	}
	if len(res3.Sync.Incomplete) != 0 {
		t.Fatalf("the completed re-planned pass must be complete, got: %v", res3.Sync.Incomplete)
	}
	if !res3.Sync.Resync.Resumed || !res3.Sync.Resync.Completed || res3.Sync.Resync.Uploads != 1 {
		t.Fatalf("run 3 must resume and finish the restricted re-planned job, got %+v", res3.Sync.Resync)
	}
	if got := mock.ingestCount("rp-old"); got != 1 {
		t.Fatalf("rp-old must reach the server once (run 1's post failed), got %d", got)
	}
	if got := mock.ingestCount("rp-new"); got != 1 {
		t.Fatalf("rp-new must not be replayed by the re-plan, got %d", got)
	}
	if got := mock.ingestCount("rp-run2"); got != 1 {
		t.Fatalf("rp-run2 must not be replayed by the re-plan, got %d", got)
	}
}
