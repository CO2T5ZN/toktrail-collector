package collection

// Snapshot honesty tests: every gated field (bytes, records, oldest
// age) is unknown rather than a fabricated zero, file stats are
// root-confined (an intermediate-directory symlink escape is refused),
// and a nil emitter performs no reads at all. Everything is synthetic
// tempdir state; no real collector state is ever read.

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"toktrail-collector/internal/local/cursoroutbox"
	"toktrail-collector/internal/local/outbox"
)

func snapshotTestNow() time.Time {
	return time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
}

func writeSnapshotBatch(t *testing.T, stateDir, batchID string, records int, createdAt time.Time) string {
	t.Helper()
	batchesDir := filepath.Join(stateDir, "batches")
	if err := os.MkdirAll(batchesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(batchesDir, batchID+".json")
	if err := os.WriteFile(path, []byte(`{"batchId":"`+batchID+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{
		BatchID:     batchID,
		File:        path,
		RecordCount: records,
	}); err != nil {
		t.Fatal(err)
	}
	// AddPending stamps the real wall clock; rewrite the entry's
	// CreatedAt with the test's intended observation time (zero keeps
	// the "old ledger shape" the age-unknown tests need).
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	for i := range out.Batches {
		if out.Batches[i].BatchID == batchID {
			out.Batches[i].CreatedAt = createdAt
		}
	}
	if err := outbox.New(stateDir).Save(out); err != nil {
		t.Fatal(err)
	}
	return path
}

// A healthy queue: batches, records, bytes and the oldest age are all
// known.
func TestSummarizePendingEntriesHealthy(t *testing.T) {
	stateDir := t.TempDir()
	writeSnapshotBatch(t, stateDir, "snap-1", 10, snapshotTestNow().Add(-time.Hour))
	writeSnapshotBatch(t, stateDir, "snap-2", 5, snapshotTestNow().Add(-2*time.Hour))
	res, err := devicePendingSummary(stateDir, snapshotTestNow())
	if err != nil {
		t.Fatal(err)
	}
	s := res.snapshot
	if !s.Counted || !s.RecordsCounted || !s.BytesCounted || !s.AgeCounted {
		t.Fatalf("a healthy queue must be fully known: %+v", s)
	}
	if s.PendingBatches != 2 || s.PendingRecords != 15 {
		t.Fatalf("counts must sum: %+v", s)
	}
	if s.OldestPendingAge != 2*time.Hour {
		t.Fatalf("the oldest age must be the maximum: %+v", s)
	}
	if res.oldestCreatedAt != snapshotTestNow().Add(-2*time.Hour) {
		t.Fatalf("the oldest CreatedAt must back the age gate: %v", res.oldestCreatedAt)
	}
}

// An empty pending set is a real observation: zero batches, zero bytes,
// known records — but no oldest age.
func TestSummarizePendingEntriesEmptyQueue(t *testing.T) {
	stateDir := t.TempDir()
	res, err := devicePendingSummary(stateDir, snapshotTestNow())
	if err != nil {
		t.Fatal(err)
	}
	s := res.snapshot
	if !s.Counted || !s.RecordsCounted || !s.BytesCounted {
		t.Fatalf("an empty queue is a real observation: %+v", s)
	}
	if s.PendingBatches != 0 || s.PendingRecords != 0 || s.PendingBytes != 0 {
		t.Fatalf("an empty queue observes zeros: %+v", s)
	}
	if s.AgeCounted {
		t.Fatalf("an empty queue has no oldest age: %+v", s)
	}
}

// A failed stat (the batch file is missing) is unknown bytes — the
// other fields stay known.
func TestSummarizePendingEntriesStatFailureIsUnknownBytes(t *testing.T) {
	stateDir := t.TempDir()
	path := writeSnapshotBatch(t, stateDir, "snap-missing", 3, snapshotTestNow().Add(-time.Minute))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	res, err := devicePendingSummary(stateDir, snapshotTestNow())
	if err != nil {
		t.Fatal(err)
	}
	s := res.snapshot
	if s.BytesCounted || s.PendingBytes != 0 {
		t.Fatalf("a missing file must be unknown bytes, never zero: %+v", s)
	}
	if !s.Counted || !s.RecordsCounted || !s.AgeCounted {
		t.Fatalf("the other gates must hold: %+v", s)
	}
}

// A pending entry missing its CreatedAt makes the OLDEST AGE unknown —
// the known entries' maximum must not be presented as the queue's
// oldest.
func TestSummarizePendingEntriesMixedCreatedAtIsUnknownAge(t *testing.T) {
	stateDir := t.TempDir()
	writeSnapshotBatch(t, stateDir, "snap-known", 2, snapshotTestNow().Add(-3*time.Hour))
	writeSnapshotBatch(t, stateDir, "snap-unknown", 4, time.Time{})
	res, err := devicePendingSummary(stateDir, snapshotTestNow())
	if err != nil {
		t.Fatal(err)
	}
	s := res.snapshot
	if s.AgeCounted || s.OldestPendingAge != 0 {
		t.Fatalf("a mixed queue must not claim an oldest age: %+v", s)
	}
	if !s.Counted || !s.RecordsCounted {
		t.Fatalf("counts must stay known: %+v", s)
	}
}

// Negative clock skew clamps the age to zero instead of reporting a
// negative duration.
func TestSummarizePendingEntriesClampsNegativeAge(t *testing.T) {
	stateDir := t.TempDir()
	// CreatedAt in the future relative to the observation clock.
	writeSnapshotBatch(t, stateDir, "snap-future", 1, snapshotTestNow().Add(time.Hour))
	res, err := devicePendingSummary(stateDir, snapshotTestNow())
	if err != nil {
		t.Fatal(err)
	}
	s := res.snapshot
	if !s.AgeCounted || s.OldestPendingAge != 0 {
		t.Fatalf("negative skew must clamp to zero: %+v", s)
	}
}

// An old-ledger entry whose recordCount field was never written decodes
// as zero: the record TOTAL is unknown (never zero), while the batch
// count stays known.
func TestSummarizePendingEntriesOldLedgerMissingRecordCount(t *testing.T) {
	stateDir := t.TempDir()
	writeSnapshotBatch(t, stateDir, "snap-modern", 7, snapshotTestNow().Add(-time.Minute))
	writeSnapshotBatch(t, stateDir, "snap-old", 0, snapshotTestNow().Add(-2*time.Minute))
	res, err := devicePendingSummary(stateDir, snapshotTestNow())
	if err != nil {
		t.Fatal(err)
	}
	s := res.snapshot
	if s.RecordsCounted || s.PendingRecords != 0 {
		t.Fatalf("a missing record count must be unknown records, never a zero total: %+v", s)
	}
	if !s.Counted || s.PendingBatches != 2 {
		t.Fatalf("the batch count must stay known: %+v", s)
	}
}

// The cursor ledger gets the identical conservative treatment.
func TestCursorPendingSummaryMissingRecordCount(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(stateDir, cursoroutbox.BatchesDir), 0o700); err != nil {
		t.Fatal(err)
	}
	entry := cursoroutbox.Entry{
		BatchID:     "cur-old-1",
		File:        filepath.Join(stateDir, cursoroutbox.BatchesDir, "cur-old-1.json"),
		RecordCount: 0, // an old ledger shape: the field never carried a value
		Status:      cursoroutbox.StatusPending,
		CreatedAt:   snapshotTestNow().Add(-time.Minute),
	}
	if err := os.WriteFile(entry.File, []byte(`{"batchId":"cur-old-1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	writeCursorLedger(t, stateDir, entry)
	res, err := cursorPendingSummary(stateDir, snapshotTestNow())
	if err != nil {
		t.Fatal(err)
	}
	s := res.snapshot
	if s.RecordsCounted || s.PendingRecords != 0 {
		t.Fatalf("a missing cursor record count must be unknown records: %+v", s)
	}
	if !s.Counted || s.PendingBatches != 1 {
		t.Fatalf("the cursor batch count must stay known: %+v", s)
	}
}

// A corrupt ledger is an unknown snapshot — never a fabricated empty
// queue.
func TestSummarizePendingEntriesUnreadableLedger(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "outbox.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := devicePendingSummary(stateDir, snapshotTestNow()); err == nil {
		t.Fatalf("a corrupt ledger must surface its read error")
	}
}

// statPendingFile is root-confined: an intermediate-directory symlink
// that escapes the state directory is refused — even though a real
// file exists at the external target, its size must never be observed.
func TestStatPendingFileRefusesIntermediateSymlinkEscape(t *testing.T) {
	stateDir := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "escape.json")
	if err := os.WriteFile(target, []byte("external content"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Replace the batches directory with a symlink to the external dir.
	batches := filepath.Join(stateDir, "batches")
	if err := os.Symlink(outside, batches); err != nil {
		t.Fatal(err)
	}
	if size, ok := statPendingFile(stateDir, filepath.Join(batches, "escape.json")); ok {
		t.Fatalf("an intermediate symlink escape must be refused, got size=%d", size)
	}
}

// A leaf symlink (even one staying inside the root) is refused: only
// regular files count.
func TestStatPendingFileRefusesLeafSymlink(t *testing.T) {
	stateDir := t.TempDir()
	batches := filepath.Join(stateDir, "batches")
	if err := os.MkdirAll(batches, 0o700); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(batches, "real.json")
	if err := os.WriteFile(real, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(batches, "link.json")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, ok := statPendingFile(stateDir, link); ok {
		t.Fatalf("a leaf symlink must be refused")
	}
	if size, ok := statPendingFile(stateDir, real); !ok || size != 1 {
		t.Fatalf("the regular file itself must stat: size=%d ok=%v", size, ok)
	}
}

// A path outside the state directory is refused outright.
func TestStatPendingFileRefusesOutsidePath(t *testing.T) {
	stateDir := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "outside.json")
	if err := os.WriteFile(target, []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := statPendingFile(stateDir, target); ok {
		t.Fatalf("an outside path must be refused")
	}
	if _, ok := statPendingFile(stateDir, filepath.Join(outside, "..", "etc", "passwd")); ok {
		t.Fatalf("a traversal path must be refused")
	}
}

// A nil emitter performs no reads at all: publishDeviceQueue returns
// before touching the ledger even when the ledger is unreadable (an
// unreadable ledger would otherwise fail loudly inside a read).
func TestPublishQueueNilEmitterPerformsNoRead(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, "outbox.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Must not panic and must not attempt the (failing) read.
	publishDeviceQueue(nil, stateDir, "drain")
	publishCursorQueue(nil, stateDir, "drain")
	var nilEmitter *ProgressEmitter
	nilEmitter.ApplyDeviceDrain(stateDir, outbox.BatchEntry{}, "x", 0)
	nilEmitter.ApplyCursorDrain(1, 1)
	nilEmitter.InvalidateDeviceQueue()
}

// The conservative cursor round origin: a pull round is unknown; a
// drain-only round over purely pre-run backlog is provable; a drain
// over anything created during the run is not.
func TestCursorRoundOriginConservative(t *testing.T) {
	stateDir := t.TempDir()
	runStarted := snapshotTestNow()
	seedCursorSnapshotEntry(t, stateDir, "cur-pre-1", 2, runStarted.Add(-time.Hour))

	if got := cursorRoundOrigin(stateDir, false, runStarted); got != OriginUnknown {
		t.Fatalf("a pull round is mixed by construction, got %q", got)
	}
	if got := cursorRoundOrigin(stateDir, true, runStarted); got != OriginPendingBacklog {
		t.Fatalf("a purely pre-run backlog drain is provable, got %q", got)
	}
	// A pending entry created during the run makes it mixed.
	seedCursorSnapshotEntry(t, stateDir, "cur-fresh-1", 1, runStarted.Add(time.Minute))
	if got := cursorRoundOrigin(stateDir, true, runStarted); got != OriginUnknown {
		t.Fatalf("a drain over run-created batches is unknown, got %q", got)
	}
	// An unreadable ledger is unknown.
	if err := os.WriteFile(filepath.Join(stateDir, "cursor-outbox.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := cursorRoundOrigin(stateDir, true, runStarted); got != OriginUnknown {
		t.Fatalf("an unreadable cursor ledger must be unknown, got %q", got)
	}
}

func seedCursorSnapshotEntry(t *testing.T, stateDir, batchID string, records int, createdAt time.Time) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(stateDir, cursoroutbox.BatchesDir), 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(stateDir, cursoroutbox.BatchesDir, batchID+".json")
	if err := os.WriteFile(file, []byte(`{"batchId":"`+batchID+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := cursoroutbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	entries = append(entries, cursoroutbox.Entry{
		BatchID:     batchID,
		File:        file,
		RecordCount: records,
		Status:      cursoroutbox.StatusPending,
		CreatedAt:   createdAt,
	})
	writeCursorLedger(t, stateDir, entries...)
}

// writeCursorLedger writes the cursor ledger file directly (the store's
// save is unexported); only synthetic entries ever land here.
func writeCursorLedger(t *testing.T, stateDir string, entries ...cursoroutbox.Entry) {
	t.Helper()
	b, err := json.MarshalIndent(struct {
		Batches []cursoroutbox.Entry `json:"batches"`
	}{Batches: entries}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cursoroutbox.New(stateDir).Path(), append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The conservative device origin: only a reorg-shaped parent is
// provable; a plain parent may have been split before its POST.
func TestDeviceSentBatchOriginConservative(t *testing.T) {
	if got := deviceSentBatchOrigin(true); got != OriginReorgChild {
		t.Fatalf("a reorg-shaped parent is provable, got %q", got)
	}
	if got := deviceSentBatchOrigin(false); got != OriginUnknown {
		t.Fatalf("a plain parent may have been split, got %q", got)
	}
}

// Old or corrupt ledgers can carry extreme RecordCount values: their
// sum must refuse to wrap — the record total degrades to unknown while
// the batch count stays known.
func TestSummarizePendingEntriesRecordCountOverflow(t *testing.T) {
	stateDir := t.TempDir()
	writeSnapshotBatch(t, stateDir, "snap-huge-1", math.MaxInt, snapshotTestNow().Add(-time.Minute))
	writeSnapshotBatch(t, stateDir, "snap-huge-2", math.MaxInt, snapshotTestNow().Add(-2*time.Minute))
	res, err := devicePendingSummary(stateDir, snapshotTestNow())
	if err != nil {
		t.Fatal(err)
	}
	s := res.snapshot
	if s.RecordsCounted || s.PendingRecords != 0 {
		t.Fatalf("an overflowing record sum must be unknown, never wrapped: %+v", s)
	}
	if !s.Counted || s.PendingBatches != 2 {
		t.Fatalf("the batch count must stay known: %+v", s)
	}
}
