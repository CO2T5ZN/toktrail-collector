// Recovery, scope and budget scenarios for cursorsync.Sync/Enable:
// offline pending retry, source-fence takeover recovery, fresh-self
// scope, history widening backfill, the daily full reconciliation, source
// recreation and confirmed account switches, the per-round drain budget,
// old-server capability gating and logout semantics.
package cursorsync_test

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/cursor/identity"
	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/cursor/usage"
	"toktrail-collector/internal/local/cursoroutbox"
	"toktrail-collector/internal/local/cursorsource"
)

func syncGate() cursorsync.Gate { return cursorsync.Gate{} }

// activeLicenseForA is a collectable permit for account A on src_inst_1.
func activeLicenseForA() cursorsource.License {
	return cursorsource.License{
		SourceInstanceID: "src_inst_1",
		AccountMatchID:   identity.MatchAccount(accountA),
		Status:           cursorsource.StatusActive,
		ConfirmedAt:      baseTime,
		NextRevision:     1,
		FenceVersion:     1,
	}
}

func keySet(records []protocol.Event) map[string]bool {
	set := make(map[string]bool, len(records))
	for _, r := range records {
		set[r.EventKey] = true
	}
	return set
}

// seedPendingBatch persists a hand-built pending batch (fence 1,
// src_inst_1) straight into the cursor outbox, with n distinct records.
func seedPendingBatch(t *testing.T, dir, batchID string, n int) {
	t.Helper()
	records := make([]protocol.Event, 0, n)
	for i := 0; i < n; i++ {
		records = append(records, protocol.Event{
			EventKey:       protocol.EventKeyPrefix + strings.Repeat("0", 63) + strconv.Itoa(i+1),
			Revision:       1,
			Kind:           "event",
			OccurredAt:     baseTime.Format(time.RFC3339Nano),
			Tool:           protocol.Tool,
			AdapterVersion: usage.AdapterVersion,
			SourceType:     protocol.SourceType,
		})
	}
	batch := protocol.Batch{BatchID: batchID, SourceInstanceID: "src_inst_1", Records: records}
	encoded, err := protocol.EncodeBatch(batch)
	if err != nil {
		t.Fatalf("encode seed batch: %v", err)
	}
	if _, err := cursoroutbox.New(dir).AddBatch(batch, 1, encoded); err != nil {
		t.Fatalf("seed pending batch: %v", err)
	}
}

func pendingCount(t *testing.T, dir string) int {
	t.Helper()
	n, err := cursoroutbox.New(dir).CountPending()
	if err != nil {
		t.Fatalf("count pending: %v", err)
	}
	return n
}

// ---------------------------------------------------------------------------
// Offline: pending batches retry with their immutable revisions
// ---------------------------------------------------------------------------

func TestDrainPendingUploadsCursorOutboxWithoutCredentialOrPull(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-drain-only-1", 1)
	seedPendingBatch(t, h.dir, "cursor-drain-only-2", 1)

	res, err := cursorsync.DrainPending(context.Background(), h.options(), syncGate())
	if err != nil {
		t.Fatalf("drain pending: %v", err)
	}
	if !res.Ran || res.SyncedBatches != 2 || res.PendingRemaining != 0 {
		t.Fatalf("drain pending result: %+v", res)
	}
	if res.PulledEvents != 0 || res.NewRecords != 0 || res.ExportedBatches != 0 {
		t.Fatalf("drain-only must not pull or export new cursor records: %+v", res)
	}
	if h.auth.fetchCount() != 0 {
		t.Fatal("drain-only must not read desktop credentials")
	}
	if len(h.pull.callLog()) != 0 {
		t.Fatalf("drain-only must not pull upstream usage: %+v", h.pull.callLog())
	}
}

// TestSyncOfflinePendingRetried verifies an upload failure keeps the
// batch durably pending (watermark and cache already advanced), and the
// next round drains it first with the exact same revisions.
func TestSyncOfflinePendingRetried(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	h.pull.setEvents(
		ev("evt-0001", baseTime.Add(-30*time.Minute), 100, 0, 0, 50),
		ev("evt-0002", baseTime.Add(-40*time.Minute), 7, 0, 0, 3),
	)
	h.srv.setIngestFails(true)

	res1, err := cursorsync.Sync(context.Background(), h.options(), syncGate())
	if err == nil || !strings.Contains(err.Error(), "upload cursor batch") {
		t.Fatalf("offline round must fail on upload, got %v", err)
	}
	if res1.ExportedBatches != 1 || res1.SyncedBatches != 0 {
		t.Fatalf("offline round exported=%d synced=%d, want 1/0", res1.ExportedBatches, res1.SyncedBatches)
	}
	if pendingCount(t, h.dir) != 1 {
		t.Fatalf("pending=%d after offline round, want 1", pendingCount(t, h.dir))
	}
	lic := loadLicense(t, h.dir)
	if lic.PullWatermark == nil || !lic.PullWatermark.Equal(baseTime) || lic.NextRevision != 2 {
		t.Fatalf("offline round must keep the advanced watermark/revision: %+v", lic)
	}
	if cache := loadCache(t, h.dir); true {
		if _, ok := cache.Get(expectedEventKey(t, accountA, "evt-0001")); !ok {
			t.Fatal("offline round must keep the committed cache")
		}
	}

	h.srv.setIngestFails(false)
	res2, err := cursorsync.Sync(context.Background(), h.options(), syncGate())
	if err != nil {
		t.Fatalf("retry round: %v", err)
	}
	if res2.SyncedBatches != 1 || res2.SyncedRecords != 2 || res2.PendingRemaining != 0 {
		t.Fatalf("retry round: %+v", res2)
	}
	if res2.NewRecords != 0 || res2.SkippedUnchanged != 2 {
		t.Fatalf("retry round new=%d unchanged=%d, want 0/2", res2.NewRecords, res2.SkippedUnchanged)
	}
	_, _, _, _, batches := h.srv.stats()
	if len(batches) != 1 || len(batches[0].Records) != 2 {
		t.Fatalf("server batches after retry: %+v", batches)
	}
	for i, rec := range batches[0].Records {
		if rec.Revision != 1 {
			t.Fatalf("retried record %d revision %d, want the immutable 1", i, rec.Revision)
		}
	}
	if loadLicense(t, h.dir).NextRevision != 2 {
		t.Fatal("a retry must not advance nextRevision")
	}
}

// ---------------------------------------------------------------------------
// Source fence takeover: old pending fenced, cache and watermark reset
// ---------------------------------------------------------------------------

func TestDrainPendingFenceChangePreservesRecovery(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	h.pull.setEvents(ev("evt-0001", baseTime.Add(-30*time.Minute), 100, 0, 0, 50))
	h.srv.setIngestFails(true)
	if _, err := cursorsync.Sync(context.Background(), h.options(), syncGate()); err == nil {
		t.Fatal("expected initial upload failure")
	}
	h.srv.setIngestFails(false)
	h.srv.setSource(protocol.Source{SourceInstanceID: "src_inst_1", SourceType: protocol.SourceType, State: "active", FenceVersion: 2, NextRevision: 10})
	before := len(h.pull.callLog())
	res, err := cursorsync.DrainPending(context.Background(), h.options(), syncGate())
	if err != nil || !strings.Contains(res.Skipped, "full sync") || res.PendingRemaining != 1 {
		t.Fatalf("fence change must stop without consuming pending data: %+v, %v", res, err)
	}
	if lic := loadLicense(t, h.dir); lic.FenceVersion != 1 || lic.PullWatermark == nil {
		t.Fatalf("drain must retain old fence and watermark for recovery: %+v", lic)
	}
	if len(h.pull.callLog()) != before {
		t.Fatal("drain-only must not pull")
	}
	full, err := cursorsync.Sync(context.Background(), h.options(), syncGate())
	if err != nil || full.NewRecords != 1 || full.SyncedRecords != 1 {
		t.Fatalf("full sync must re-produce fenced history: %+v, %v", full, err)
	}
}

// TestSyncFenceMovedRecovery covers the takeover fence: after the server
// moves the source fence, an unacknowledged pending batch is fenced out
// (never re-sent), the event ledger and pull watermark reset, and the
// round re-produces the same events with fresh revisions above the
// server's nextRevision — the old pending data is not lost, it is
// re-delivered under the new fence.
func TestSyncFenceMovedRecovery(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	h.pull.setEvents(
		ev("evt-0001", baseTime.Add(-30*time.Minute), 100, 0, 0, 50),
		ev("evt-0002", baseTime.Add(-40*time.Minute), 7, 0, 0, 3),
	)
	h.srv.setIngestFails(true)
	if _, err := cursorsync.Sync(context.Background(), h.options(), syncGate()); err == nil {
		t.Fatal("offline round must fail")
	}

	// The server moved the fence (takeover/reassignment) and raised
	// nextRevision; the ingest path works again.
	h.srv.setIngestFails(false)
	h.srv.setSource(protocol.Source{
		SourceInstanceID: "src_inst_1",
		SourceType:       protocol.SourceType,
		State:            "active",
		FenceVersion:     2,
		NextRevision:     10,
	})

	res, err := cursorsync.Sync(context.Background(), h.options(), syncGate())
	if err != nil {
		t.Fatalf("fence recovery round: %v", err)
	}
	if !strings.Contains(res.Note, "fenced out") || !strings.Contains(res.Note, "reset for recovery") {
		t.Fatalf("fence recovery note %q", res.Note)
	}
	if res.NewRecords != 2 || res.ReplacedRecords != 0 {
		t.Fatalf("recovery must re-produce the events (cache reset): new=%d replaced=%d", res.NewRecords, res.ReplacedRecords)
	}
	if res.SyncedBatches != 1 || res.PendingRemaining != 0 {
		t.Fatalf("recovery upload: %+v", res)
	}

	entries, err := cursoroutbox.New(h.dir).Load()
	if err != nil || len(entries) != 2 {
		t.Fatalf("outbox entries (%v): %+v", err, entries)
	}
	if entries[0].Status != cursoroutbox.StatusFenced {
		t.Fatalf("old pending batch status %q, want fenced", entries[0].Status)
	}
	if entries[1].Status != cursoroutbox.StatusSynced {
		t.Fatalf("re-produced batch status %q, want synced", entries[1].Status)
	}
	fenced, err := cursoroutbox.New(h.dir).LoadBatchBytes(entries[0])
	if err != nil {
		t.Fatalf("load fenced batch: %v", err)
	}
	_, _, _, _, batches := h.srv.stats()
	if len(batches) != 1 {
		t.Fatalf("only the re-produced batch may be uploaded, got %d", len(batches))
	}
	for _, rec := range batches[0].Records {
		if rec.Revision != 10 {
			t.Fatalf("re-produced revision %d, want the fresh 10", rec.Revision)
		}
	}
	if !keySetEqual(keySet(fenced.Records), keySet(batches[0].Records)) {
		t.Fatal("the fenced batch's events must be re-delivered — old pending data lost")
	}
	lic := loadLicense(t, h.dir)
	if lic.FenceVersion != 2 || lic.NextRevision != 11 || lic.PullWatermark == nil {
		t.Fatalf("recovery license: %+v", lic)
	}
	calls := h.pull.callLog()
	if len(calls) != 2 || !calls[1].from.IsZero() {
		t.Fatalf("the recovery pull must start at the authorized start (watermark reset): %+v", calls)
	}
	if cache := loadCache(t, h.dir); true {
		if entry, ok := cache.Get(expectedEventKey(t, accountA, "evt-0001")); !ok || entry.Revision != 10 {
			t.Fatalf("cache must hold the re-produced revision: %+v ok=%t", entry, ok)
		}
	}
}

func keySetEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Fresh self scope
// ---------------------------------------------------------------------------

// TestSyncFreshSelfScopeAllowedTools verifies the direct-CLI unrestricted
// Gate still honors the FRESH server scope: when the live self view
// narrows allowedTools away from Cursor, the round skips before any
// credential read or pull.
func TestSyncFreshSelfScopeAllowedTools(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	h.srv.setAllowedTools([]string{"ClaudeCode", "Codex"})

	res, err := cursorsync.Sync(context.Background(), h.options(), syncGate())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if res.Ran || !strings.Contains(res.Skipped, "not allowed by the effective server grant scope") {
		t.Fatalf("scope skip: ran=%t skipped=%q", res.Ran, res.Skipped)
	}
	if h.auth.fetchCount() != 0 {
		t.Fatal("an out-of-scope round must not read the Cursor credential")
	}
	if len(h.pull.callLog()) != 0 {
		t.Fatal("an out-of-scope round must not pull")
	}
	if _, _, ingest, _, _ := h.srv.stats(); ingest != 0 {
		t.Fatal("an out-of-scope round must not upload")
	}
}

// TestSyncFreshSelfScopeHistoryWindow verifies the fresh self view's
// historyFrom bounds the pull start and uploadUntil caps the pull end
// (the watermark freezes at the cap), and that a later grant-side cutoff
// wins the merge.
func TestSyncFreshSelfScopeHistoryWindow(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	t0 := baseTime.Add(-2 * time.Hour)
	u0 := baseTime.Add(-10 * time.Minute)
	h.srv.setHistory(&t0, &u0)
	h.pull.setEvents(ev("evt-0001", baseTime.Add(-1*time.Hour), 100, 0, 0, 50))

	res, err := cursorsync.Sync(context.Background(), h.options(), syncGate())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	calls := h.pull.callLog()
	if len(calls) != 1 || !calls[0].from.Equal(t0) || !calls[0].to.Equal(u0) {
		t.Fatalf("pull window must follow the fresh self scope, got %+v", calls)
	}
	if res.NewRecords != 1 {
		t.Fatalf("new=%d, want 1", res.NewRecords)
	}
	lic := loadLicense(t, h.dir)
	if lic.PullWatermark == nil || !lic.PullWatermark.Equal(u0) {
		t.Fatalf("watermark must freeze at the upload cap: %+v", lic.PullWatermark)
	}
	if lic.PullCutoff == nil || !lic.PullCutoff.Equal(t0) || lic.PullUnlimited {
		t.Fatalf("cutoff must record the finite fresh bound: %+v", lic.PullCutoff)
	}

	// Merge: a grant-side (Gate) cutoff later than the server's wins.
	h2 := newHarness(t)
	h2.srv.setSource(defaultSource())
	h2.writeLicense(t, activeLicenseForA())
	h2.srv.setHistory(&t0, nil)
	gateFrom := baseTime.Add(-30 * time.Minute)
	h2.pull.setEvents(ev("evt-0001", baseTime.Add(-20*time.Minute), 1, 0, 0, 1))
	if _, err := cursorsync.Sync(context.Background(), h2.options(), cursorsync.Gate{HistoryFrom: &gateFrom}); err != nil {
		t.Fatalf("sync with merged cutoff: %v", err)
	}
	calls2 := h2.pull.callLog()
	if len(calls2) != 1 || !calls2[0].from.Equal(gateFrom) {
		t.Fatalf("the later (more restrictive) cutoff must win the merge, got %+v", calls2)
	}
}

// ---------------------------------------------------------------------------
// History widening backfill (7d -> 30d -> unlimited)
// ---------------------------------------------------------------------------

// TestSyncHistoryWideningBackfill verifies a server-side widening of the
// authorized history actually gets fetched: the recorded finite cutoff
// being later than the fresh one (or becoming unlimited) resets the pull
// watermark back to the new authorized start while the cache keeps
// acknowledged identities from duplicating.
func TestSyncHistoryWideningBackfill(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	t7 := baseTime.Add(-7 * 24 * time.Hour)
	t30 := baseTime.Add(-30 * 24 * time.Hour)
	h.srv.setHistory(&t7, nil)
	in7d := ev("evt-in7d", baseTime.Add(-3*24*time.Hour), 10, 0, 0, 5)
	h.pull.setEvents(in7d)

	if _, err := cursorsync.Sync(context.Background(), h.options(), syncGate()); err != nil {
		t.Fatalf("7d round: %v", err)
	}
	lic := loadLicense(t, h.dir)
	if lic.PullCutoff == nil || !lic.PullCutoff.Equal(t7) {
		t.Fatalf("7d round must record the finite cutoff: %+v", lic.PullCutoff)
	}

	// Widen 7d -> 30d: older history must now be fetched.
	h.srv.setHistory(&t30, nil)
	old1 := ev("evt-old1", baseTime.Add(-20*24*time.Hour), 8, 0, 0, 4)
	old2 := ev("evt-old2", baseTime.Add(-25*24*time.Hour), 6, 0, 0, 2)
	h.pull.setEvents(in7d, old1, old2)
	res, err := cursorsync.Sync(context.Background(), h.options(), syncGate())
	if err != nil {
		t.Fatalf("30d round: %v", err)
	}
	if !strings.Contains(res.Note, "history authorization widened") {
		t.Fatalf("widening note %q", res.Note)
	}
	calls := h.pull.callLog()
	if len(calls) != 2 || !calls[1].from.Equal(t30) {
		t.Fatalf("the widened round must pull from the new authorized start, got %+v", calls)
	}
	if res.NewRecords != 2 || res.SkippedUnchanged != 1 {
		t.Fatalf("widened round new=%d unchanged=%d, want 2/1 (older fetched, known deduped)", res.NewRecords, res.SkippedUnchanged)
	}
	lic = loadLicense(t, h.dir)
	if lic.PullCutoff == nil || !lic.PullCutoff.Equal(t30) {
		t.Fatalf("30d round must record the widened cutoff: %+v", lic.PullCutoff)
	}
	_, _, _, _, batches := h.srv.stats()
	if len(batches) != 2 || len(batches[1].Records) != 2 {
		t.Fatalf("widened upload: %+v", batches)
	}
	wantOld := keySet([]protocol.Event{
		{EventKey: expectedEventKey(t, accountA, "evt-old1")},
		{EventKey: expectedEventKey(t, accountA, "evt-old2")},
	})
	if !keySetEqual(wantOld, keySet(batches[1].Records)) {
		t.Fatal("the widened round must upload the newly authorized older events")
	}

	// Widen finite -> unlimited: re-pull from the start, all unchanged
	// (cache retention avoids duplicates).
	h.srv.setHistory(nil, nil)
	res3, err := cursorsync.Sync(context.Background(), h.options(), syncGate())
	if err != nil {
		t.Fatalf("unlimited round: %v", err)
	}
	if !strings.Contains(res3.Note, "history authorization widened") {
		t.Fatalf("unlimited widening note %q", res3.Note)
	}
	calls = h.pull.callLog()
	if len(calls) != 3 || !calls[2].from.IsZero() {
		t.Fatalf("the unlimited round must pull from the start, got %+v", calls)
	}
	if res3.NewRecords != 0 || res3.SkippedUnchanged != 3 {
		t.Fatalf("unlimited round new=%d unchanged=%d, want 0/3", res3.NewRecords, res3.SkippedUnchanged)
	}
	if _, _, _, _, batches = h.srv.stats(); len(batches) != 2 {
		t.Fatalf("an all-unchanged round must not upload, got %d batches", len(batches))
	}
}

// ---------------------------------------------------------------------------
// Daily full reconciliation
// ---------------------------------------------------------------------------

// TestSyncDailyFullReconciliation verifies the once-daily full-window
// pull: a late upstream correction older than the 1-hour overlap is
// invisible to same-day rounds (no full scan before the daily boundary)
// and is picked up — including downward — by the first round of the next
// UTC day.
func TestSyncDailyFullReconciliation(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	recent := ev("evt-recent", baseTime.Add(-30*time.Minute), 100, 0, 0, 50)
	oldOriginal := ev("evt-old", baseTime.Add(-2*time.Hour), 30, 0, 0, 15)
	h.pull.setEvents(recent, oldOriginal)

	if _, err := cursorsync.Sync(context.Background(), h.options(), syncGate()); err != nil {
		t.Fatalf("day-1 full pull: %v", err)
	}
	lic := loadLicense(t, h.dir)
	if lic.LastFullPullAt == nil || !lic.LastFullPullAt.Equal(baseTime) {
		t.Fatalf("day-1 must stamp the full pull: %+v", lic.LastFullPullAt)
	}

	// Same day, +2h: the corrected old event sits outside the 1h overlap
	// and must NOT be fetched (no full scan before the daily boundary).
	h.clock.Set(baseTime.Add(2 * time.Hour))
	corrected := ev("evt-old", baseTime.Add(-2*time.Hour), 12, 0, 0, 5)
	h.pull.setEvents(recent, corrected)
	res2, err := cursorsync.Sync(context.Background(), h.options(), syncGate())
	if err != nil {
		t.Fatalf("same-day round: %v", err)
	}
	calls := h.pull.callLog()
	if len(calls) != 2 || !calls[1].from.Equal(baseTime.Add(-cursorsync.PullOverlap)) {
		t.Fatalf("same-day rounds must use the overlap window, got %+v", calls)
	}
	if res2.NewRecords != 0 || res2.ReplacedRecords != 0 || res2.SkippedUnchanged != 1 {
		t.Fatalf("same-day round must not see the out-of-overlap correction: %+v", res2)
	}
	if lic = loadLicense(t, h.dir); !lic.LastFullPullAt.Equal(baseTime) {
		t.Fatal("a non-full round must not restamp the daily clock")
	}

	// Next UTC day: full reconciliation picks up the downward correction.
	h.clock.Set(baseTime.Add(26 * time.Hour))
	res3, err := cursorsync.Sync(context.Background(), h.options(), syncGate())
	if err != nil {
		t.Fatalf("next-day round: %v", err)
	}
	calls = h.pull.callLog()
	if len(calls) != 3 || !calls[2].from.IsZero() {
		t.Fatalf("the daily round must pull the whole authorized window, got %+v", calls)
	}
	if res3.ReplacedRecords != 1 || res3.SkippedUnchanged != 1 {
		t.Fatalf("daily round replaced=%d unchanged=%d, want 1/1", res3.ReplacedRecords, res3.SkippedUnchanged)
	}
	_, _, _, _, batches := h.srv.stats()
	last := batches[len(batches)-1]
	if len(last.Records) != 1 || last.Records[0].Input == nil || *last.Records[0].Input != "12" {
		t.Fatalf("the late downward correction must reach the server, got %+v", last.Records)
	}
	lic = loadLicense(t, h.dir)
	if lic.LastFullPullAt == nil || !lic.LastFullPullAt.Equal(baseTime.Add(26*time.Hour)) {
		t.Fatalf("the daily round must restamp the full pull: %+v", lic.LastFullPullAt)
	}
}

// ---------------------------------------------------------------------------
// Enable: source recreation and confirmed account switch
// ---------------------------------------------------------------------------

// TestEnableSourceRecreatedResetsHistory covers a server-side source
// deletion + recreation (e.g. deleteData): the new source instance starts
// empty while the local cache would skip-unchanged its history, and a
// stale pending batch of the old source would block the drain. The
// continuity gate must fence the stale batch, reset the ledger and
// watermark, and re-pull the full history under the new instance — same
// account, so no new confirmation.
func TestEnableSourceRecreatedResetsHistory(t *testing.T) {
	h := newHarness(t)
	h.pull.setEvents(
		ev("evt-0001", baseTime.Add(-30*time.Minute), 100, 0, 0, 50),
		ev("evt-0002", baseTime.Add(-40*time.Minute), 7, 0, 0, 3),
	)
	confirm := &fakeConfirm{answer: true}
	if _, err := cursorsync.Enable(context.Background(), h.options(), confirm.confirm); err != nil {
		t.Fatalf("first enable: %v", err)
	}

	// Leave an unacknowledged pending batch behind (offline round).
	h.srv.setIngestFails(true)
	h.pull.setEvents(
		ev("evt-0001", baseTime.Add(-30*time.Minute), 100, 0, 0, 50),
		ev("evt-0002", baseTime.Add(-40*time.Minute), 7, 0, 0, 3),
		ev("evt-0003", baseTime.Add(-50*time.Minute), 9, 0, 0, 6),
	)
	if _, err := cursorsync.Sync(context.Background(), h.options(), syncGate()); err == nil {
		t.Fatal("offline round must fail")
	}

	// The server recreated the source (fresh instance, empty history).
	h.srv.setIngestFails(false)
	h.srv.dropSource()

	confirm.mu.Lock()
	confirm.calls = 0
	confirm.mu.Unlock()
	res, err := cursorsync.Enable(context.Background(), h.options(), confirm.confirm)
	if err != nil {
		t.Fatalf("re-enable after recreation: %v", err)
	}
	if confirm.callCount() != 0 {
		t.Fatal("the same account must re-enable without a new confirmation")
	}
	if !res.ServerEnabled {
		t.Fatal("the server enable call must run after recreation")
	}
	if res.License.SourceInstanceID == "src_inst_1" {
		t.Fatalf("license must carry the recreated instance, got %q", res.License.SourceInstanceID)
	}
	if res.Sync.NewRecords != 3 {
		t.Fatalf("recreation must re-pull the whole history (ledger reset): new=%d", res.Sync.NewRecords)
	}
	if res.Sync.PendingRemaining != 0 || res.Sync.SyncedBatches != 1 {
		t.Fatalf("re-created source upload: %+v", res.Sync)
	}

	entries, err := cursoroutbox.New(h.dir).Load()
	if err != nil || len(entries) != 3 {
		t.Fatalf("outbox entries (%v): %+v", err, entries)
	}
	if entries[1].Status != cursoroutbox.StatusFenced || entries[1].SourceInstanceID != "src_inst_1" {
		t.Fatalf("the old source's pending batch must be terminally fenced: %+v", entries[1])
	}
	if entries[2].Status != cursoroutbox.StatusSynced || entries[2].SourceInstanceID != res.License.SourceInstanceID {
		t.Fatalf("the re-produced batch must be synced under the new source: %+v", entries[2])
	}
	fenced, err := cursoroutbox.New(h.dir).LoadBatchBytes(entries[1])
	if err != nil {
		t.Fatalf("load fenced batch: %v", err)
	}
	_, _, _, _, batches := h.srv.stats()
	reproduced := batches[len(batches)-1]
	fencedKeys := keySet(fenced.Records)
	reproducedKeys := keySet(reproduced.Records)
	for k := range fencedKeys {
		if !reproducedKeys[k] {
			t.Fatal("the fenced batch's events must be re-delivered under the new source")
		}
	}
	if reproduced.SourceInstanceID != res.License.SourceInstanceID {
		t.Fatalf("re-produced batch carries source %q, want %q", reproduced.SourceInstanceID, res.License.SourceInstanceID)
	}
	if cache := loadCache(t, h.dir); true {
		if _, ok := cache.Get(expectedEventKey(t, accountA, "evt-0003")); !ok {
			t.Fatal("the ledger must be rebuilt from the re-pull")
		}
	}
}

// TestEnableAccountSwitchFullHistoryNewKeys covers the confirmed account
// switch: after the switch pause, a confirmed re-enable re-binds the
// permit, resets the pull window so the FULL history of the new account
// is fetched (its events predate the old watermark), and every record
// carries new event keys derived from the new account.
func TestEnableAccountSwitchFullHistoryNewKeys(t *testing.T) {
	h := newHarness(t)
	h.pull.setEvents(ev("evt-a1", baseTime.Add(-30*time.Minute), 100, 0, 0, 50))
	confirm := &fakeConfirm{answer: true}
	if _, err := cursorsync.Enable(context.Background(), h.options(), confirm.confirm); err != nil {
		t.Fatalf("first enable: %v", err)
	}
	aKey := expectedEventKey(t, accountA, "evt-a1")
	if _, ok := loadCache(t, h.dir).Get(aKey); !ok {
		t.Fatal("account A events must be in the ledger")
	}

	// The desktop login switches to account B; sync pauses.
	h.auth.setToken("tok-B")
	if _, err := cursorsync.Sync(context.Background(), h.options(), syncGate()); err != nil {
		t.Fatalf("switch pause: %v", err)
	}
	if loadLicense(t, h.dir).Status != cursorsource.StatusPausedAccountSwitch {
		t.Fatal("permit must be paused after the switch")
	}

	// B's history predates A's watermark: only a window reset fetches it.
	bEvent := ev("evt-b1", baseTime.Add(-25*time.Hour), 60, 0, 0, 30)
	h.pull.setEvents(bEvent)
	res, err := cursorsync.Enable(context.Background(), h.options(), confirm.confirm)
	if err != nil {
		t.Fatalf("confirmed switch re-enable: %v", err)
	}
	if !res.Confirmed || res.License.Status != cursorsource.StatusActive {
		t.Fatalf("switch re-enable must confirm and reactivate: confirmed=%t status=%q", res.Confirmed, res.License.Status)
	}
	if res.License.AccountMatchID != identity.MatchAccount(accountB) {
		t.Fatal("the permit must re-bind to account B")
	}
	calls := h.pull.callLog()
	if len(calls) != 2 || !calls[1].from.IsZero() {
		t.Fatalf("the switch re-enable must re-pull from the authorized start, got %+v", calls)
	}
	if res.Sync.NewRecords != 1 {
		t.Fatalf("the new account's full history must be fetched: new=%d", res.Sync.NewRecords)
	}
	_, _, _, _, batches := h.srv.stats()
	last := batches[len(batches)-1]
	bKey := expectedEventKey(t, accountB, "evt-b1")
	if len(last.Records) != 1 || last.Records[0].EventKey != bKey {
		t.Fatalf("records must carry the new account's event keys: %+v", last.Records)
	}
	if bKey == aKey {
		t.Fatal("different accounts must derive different event keys")
	}
	cache := loadCache(t, h.dir)
	if _, ok := cache.Get(aKey); ok {
		t.Fatal("the old account's ledger entries must not survive the re-bind")
	}
	if _, ok := cache.Get(bKey); !ok {
		t.Fatal("the new account's ledger entries must be present")
	}
}

// ---------------------------------------------------------------------------
// Per-round drain budget
// ---------------------------------------------------------------------------

// TestSyncDrainBudgetSharedAcrossPhases verifies MaxBatches bounds the
// ROUND total: the pre-pull drain and the post-pull drain together never
// upload more than MaxBatches batches, and leftover batches drain on
// later rounds.
func TestSyncDrainBudgetSharedAcrossPhases(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "seed-batch-1", 1)
	seedPendingBatch(t, h.dir, "seed-batch-2", 1)
	h.pull.setEvents(ev("evt-0001", baseTime.Add(-30*time.Minute), 100, 0, 0, 50))
	opt := h.options()
	opt.MaxBatches = 1

	// Two seeded pending batches plus this round's new batch: only one
	// upload may happen this round.
	res1, err := cursorsync.Sync(context.Background(), opt, syncGate())
	if err != nil {
		t.Fatalf("budget round 1: %v", err)
	}
	if res1.SyncedBatches != 1 || res1.PendingRemaining != 2 {
		t.Fatalf("round 1 synced=%d pending=%d, want 1/2 (budget shared across both drains)", res1.SyncedBatches, res1.PendingRemaining)
	}

	res2, err := cursorsync.Sync(context.Background(), opt, syncGate())
	if err != nil {
		t.Fatalf("budget round 2: %v", err)
	}
	if res2.SyncedBatches != 1 || res2.PendingRemaining != 1 {
		t.Fatalf("round 2 synced=%d pending=%d, want 1/1", res2.SyncedBatches, res2.PendingRemaining)
	}

	res3, err := cursorsync.Sync(context.Background(), opt, syncGate())
	if err != nil {
		t.Fatalf("budget round 3: %v", err)
	}
	if res3.SyncedBatches != 1 || res3.PendingRemaining != 0 {
		t.Fatalf("round 3 synced=%d pending=%d, want 1/0", res3.SyncedBatches, res3.PendingRemaining)
	}
	_, _, ingest, _, batches := h.srv.stats()
	if ingest != 3 || len(batches) != 3 {
		t.Fatalf("total uploads=%d batches=%d, want 3/3", ingest, len(batches))
	}
}

// ---------------------------------------------------------------------------
// Old server capability gate
// ---------------------------------------------------------------------------

// TestEnableOldServerNeverReadsCredential verifies a server without the
// account-sources capability aborts the enable before the credential read,
// without ever touching the desktop login. The consent notice is printed first
// (it states what would happen); no confirmation is asked, because the website
// grant is the authorization.
func TestEnableOldServerNeverReadsCredential(t *testing.T) {
	// First-time flow: capability gate before any credential read.
	h := newHarness(t)
	h.srv.setCapsEnabled(false)
	confirm := &fakeConfirm{answer: true}
	_, err := cursorsync.Enable(context.Background(), h.options(), confirm.confirm)
	if err == nil || !errors.Is(err, cursorsync.ErrEnableNeedsAccountSources) {
		t.Fatalf("old server must fail the enable with the capability class, got %v", err)
	}
	if confirm.callCount() != 0 {
		t.Fatalf("the first enable must not ask a second time, got %d call(s)", confirm.callCount())
	}
	if h.auth.fetchCount() != 0 || h.verify.callCount() != 0 {
		t.Fatal("an old server must never see the desktop credential read or verified")
	}
	if _, enable, _, caps, _ := h.srv.stats(); enable != 0 || caps != 1 {
		t.Fatalf("old server: enable=%d caps=%d, want 0/1", enable, caps)
	}
	if _, ok, err := cursorsource.New(h.dir).Load(); err != nil || ok {
		t.Fatalf("no license may be written against an old server (ok=%t err=%v)", ok, err)
	}

	// Existing permit: the gate runs before the credential read, so the
	// login is not read needlessly against an old server.
	h2 := newHarness(t)
	h2.srv.setSource(defaultSource())
	h2.writeLicense(t, activeLicenseForA())
	h2.srv.dropSource()
	h2.srv.setCapsEnabled(false)
	if _, err := cursorsync.Enable(context.Background(), h2.options(), confirm.confirm); err == nil || !strings.Contains(err.Error(), "account-source support") {
		t.Fatalf("old server with existing permit must fail the enable, got %v", err)
	}
	if h2.auth.fetchCount() != 0 {
		t.Fatal("an old server must never trigger a credential read for an existing permit")
	}
	if _, ok, _ := cursorsource.New(h2.dir).Load(); !ok {
		t.Fatal("the existing permit must survive the failed re-enable")
	}
}

// ---------------------------------------------------------------------------
// Logout semantics
// ---------------------------------------------------------------------------

// TestLogoutDeletesLicense verifies logout removes the permit (there is
// no persisted disabled state to bypass the first-time confirmation), and
// purge additionally removes the event ledger and the cursor outbox.
func TestLogoutDeletesLicense(t *testing.T) {
	h := newHarness(t)
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "seed-batch-1", 1)
	cache := loadCache(t, h.dir)
	cache.Apply(map[string]usage.CacheEntry{
		expectedEventKey(t, accountA, "evt-0001"): {Revision: 1, Digest: "deadbeef"},
	})
	if err := cache.Commit(); err != nil {
		t.Fatalf("commit cache: %v", err)
	}

	removed, purged, err := cursorsync.Logout(h.options(), false)
	if err != nil || !removed || purged {
		t.Fatalf("logout without purge: removed=%t purged=%t err=%v", removed, purged, err)
	}
	if _, ok, err := cursorsource.New(h.dir).Load(); err != nil || ok {
		t.Fatalf("logout must delete the license (ok=%t err=%v)", ok, err)
	}
	if pendingCount(t, h.dir) != 1 {
		t.Fatal("logout without purge must keep pending batches")
	}
	if _, ok := loadCache(t, h.dir).Get(expectedEventKey(t, accountA, "evt-0001")); !ok {
		t.Fatal("logout without purge must keep the event ledger")
	}

	removed, purged, err = cursorsync.Logout(h.options(), true)
	if err != nil || removed || !purged {
		t.Fatalf("logout with purge: removed=%t purged=%t err=%v", removed, purged, err)
	}
	if pendingCount(t, h.dir) != 0 {
		t.Fatal("logout with purge must remove the cursor outbox")
	}
	if _, err := os.Stat(cachePath(h.dir)); !os.IsNotExist(err) {
		t.Fatalf("logout with purge must remove the event ledger: %v", err)
	}
}

// TestSyncClampsUpstreamRowsToAuthorizedWindow makes the fake pull
// deliberately answer rows outside the requested window (a future row
// past the server's UploadUntil cap and a row older than the authorized
// start): none of them may be cached or uploaded, and the future row is
// picked up by a later round once it is genuinely inside the window.
func TestSyncClampsUpstreamRowsToAuthorizedWindow(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	t0 := baseTime.Add(-2 * time.Hour)
	u0 := baseTime.Add(-10 * time.Minute)
	h.srv.setHistory(&t0, &u0)
	inWindow := ev("evt-in", baseTime.Add(-1*time.Hour), 100, 0, 0, 50)
	future := ev("evt-future", baseTime.Add(-1*time.Minute), 7, 0, 0, 3) // at/after UploadUntil
	tooOld := ev("evt-tooold", baseTime.Add(-3*time.Hour), 9, 0, 0, 6)   // before the authorized start
	h.pull.setEvents(inWindow, future, tooOld)
	h.pull.setUnfiltered(true)

	res, err := cursorsync.Sync(context.Background(), h.options(), syncGate())
	if err != nil {
		t.Fatalf("sync with out-of-window rows: %v", err)
	}
	if res.PulledEvents != 3 {
		t.Fatalf("the upstream answered 3 rows, got %d", res.PulledEvents)
	}
	if res.NewRecords != 1 {
		t.Fatalf("only the in-window row may produce a record, got new=%d", res.NewRecords)
	}
	_, _, _, _, batches := h.srv.stats()
	if len(batches) != 1 || len(batches[0].Records) != 1 || batches[0].Records[0].EventKey != expectedEventKey(t, accountA, "evt-in") {
		t.Fatalf("out-of-window rows must not be uploaded: %+v", batches)
	}
	cache := loadCache(t, h.dir)
	for _, id := range []string{"evt-future", "evt-tooold"} {
		if _, ok := cache.Get(expectedEventKey(t, accountA, id)); ok {
			t.Fatalf("out-of-window row %s must not be cached", id)
		}
	}

	// Lift the upload cap: the future row is now inside the window and
	// the next round's overlap picks it up.
	h.srv.setHistory(&t0, nil)
	res2, err := cursorsync.Sync(context.Background(), h.options(), syncGate())
	if err != nil {
		t.Fatalf("catch-up round: %v", err)
	}
	if res2.NewRecords != 1 {
		t.Fatalf("the future row must come back through the overlap, got new=%d", res2.NewRecords)
	}
	_, _, _, _, batches = h.srv.stats()
	if len(batches) != 2 {
		t.Fatalf("catch-up upload: %d batches", len(batches))
	}
	last := batches[len(batches)-1]
	if len(last.Records) != 1 || last.Records[0].EventKey != expectedEventKey(t, accountA, "evt-future") {
		t.Fatalf("the catch-up upload must carry the future row: %+v", last.Records)
	}
}

func cachePath(dir string) string {
	return dir + string(os.PathSeparator) + "cursor-events.json"
}

// ---------------------------------------------------------------------------
// Drain terminal stops and partial rejections
// ---------------------------------------------------------------------------

// watermarkedLicenseForA is an active permit that already completed a
// pull (watermark set), so a stopped round must leave it untouched.
func watermarkedLicenseForA() cursorsource.License {
	license := activeLicenseForA()
	license.NextRevision = 2
	watermark := baseTime
	license.PullWatermark = &watermark
	return license
}

// TestDrainStopsMidRoundWithoutPull walks every terminal control-plane
// stop code for the upload: the drain stops, the round ends WITHOUT
// pulling (no credential read either), the watermark stays put and the
// batch stays pending — nothing is dropped and nothing advances under a
// stale authorization.
func TestDrainStopsMidRoundWithoutPull(t *testing.T) {
	cases := []struct {
		name   string
		code   string // stable server error code; empty means plain HTTP 401
		use401 bool
	}{
		{name: "scope_changed", code: "scope_changed"},
		{name: "source_fence_changed", code: "source_fence_changed"},
		{name: "source_paused", code: "source_paused"},
		{name: "source_deleted", code: "source_deleted"},
		{name: "stale_revision", code: "stale_revision"},
		{name: "device_unauthorized_401", use401: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.srv.setSource(defaultSource())
			h.writeLicense(t, watermarkedLicenseForA())
			seedPendingBatch(t, h.dir, "seed-batch-1", 1)
			// Would produce a new record if the round ever pulled.
			h.pull.setEvents(ev("evt-new", baseTime.Add(-30*time.Minute), 100, 0, 0, 50))
			if tc.use401 {
				h.srv.setIngestStatus(401)
			} else {
				h.srv.setIngestCode(tc.code)
			}

			res, err := cursorsync.Sync(context.Background(), h.options(), syncGate())
			if err != nil {
				t.Fatalf("a terminal stop is not an error: %v", err)
			}
			if !res.Ran || !strings.Contains(res.Note, "stopped") {
				t.Fatalf("stop result: ran=%t note=%q", res.Ran, res.Note)
			}
			if len(h.pull.callLog()) != 0 {
				t.Fatal("a stopped round must not pull")
			}
			if h.auth.fetchCount() != 0 {
				t.Fatal("a stopped round must not read the Cursor credential")
			}
			if res.SyncedBatches != 0 || res.PendingRemaining != 1 {
				t.Fatalf("stop accounting: %+v", res)
			}
			if pendingCount(t, h.dir) != 1 {
				t.Fatal("the stopped batch must stay pending")
			}
			lic := loadLicense(t, h.dir)
			if lic.PullWatermark == nil || !lic.PullWatermark.Equal(baseTime) || lic.LastFullPullAt != nil {
				t.Fatalf("a stopped round must not advance the pull memory: %+v", lic)
			}
			if _, _, ingest, _, batches := h.srv.stats(); ingest != 1 || len(batches) != 0 {
				t.Fatalf("exactly one upload attempt may happen: ingest=%d accepted=%d", ingest, len(batches))
			}
		})
	}
}

// TestDrainPartialRejectionStaysPending walks partial_error receipts
// (stale_revision, record_conflict): the rejection surfaces with the
// record index and the sanitized code, the batch stays pending (never
// MarkSynced, no false-positive success) and the round ends before any
// pull.
func TestDrainPartialRejectionStaysPending(t *testing.T) {
	for _, code := range []string{"stale_revision", "record_conflict"} {
		t.Run(code, func(t *testing.T) {
			h := newHarness(t)
			h.srv.setSource(defaultSource())
			h.writeLicense(t, watermarkedLicenseForA())
			seedPendingBatch(t, h.dir, "seed-batch-1", 2)
			h.pull.setEvents(ev("evt-new", baseTime.Add(-30*time.Minute), 100, 0, 0, 50))
			h.srv.setIngestPartialRejection(1, code)

			res, err := cursorsync.Sync(context.Background(), h.options(), syncGate())
			if err == nil || !strings.Contains(err.Error(), "rejected by the server") {
				t.Fatalf("a partial rejection must fail the round, got %v", err)
			}
			if !strings.Contains(err.Error(), "record 1: "+code) {
				t.Fatalf("the rejection must name the record index and code, got %v", err)
			}
			if res.SyncedBatches != 0 || res.SyncedRecords != 0 {
				t.Fatalf("a partial receipt is never a success: %+v", res)
			}
			if len(h.pull.callLog()) != 0 {
				t.Fatal("a rejected pre-pull drain must stop the round before pulling")
			}
			entries, err := cursoroutbox.New(h.dir).Load()
			if err != nil || len(entries) != 1 {
				t.Fatalf("outbox entries (%v): %+v", err, entries)
			}
			if entries[0].Status != cursoroutbox.StatusPending || entries[0].ReceiptStatus != "" {
				t.Fatalf("the partially rejected batch must stay unacknowledged: %+v", entries[0])
			}
			lic := loadLicense(t, h.dir)
			if lic.PullWatermark == nil || !lic.PullWatermark.Equal(baseTime) {
				t.Fatalf("a rejected round must not advance the watermark: %+v", lic.PullWatermark)
			}
		})
	}
}

// TestSyncLoginExpiredClassification covers the login_expired permit
// classification: a live verification rejection pauses the permit with an
// actionable message, without pulling, and the paused permit skips later
// rounds before any credential read.
func TestSyncLoginExpiredClassification(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	h.auth.setToken("tok-expired") // unknown to fakeVerify → ErrSessionExpired

	_, err := cursorsync.Sync(context.Background(), h.options(), syncGate())
	if err == nil || !strings.Contains(err.Error(), "log into Cursor") {
		t.Fatalf("an expired login must surface an actionable error, got %v", err)
	}
	if loadLicense(t, h.dir).Status != cursorsource.StatusLoginExpired {
		t.Fatal("the permit must be classified login_expired")
	}
	if len(h.pull.callLog()) != 0 {
		t.Fatal("an expired login must not pull")
	}

	fetches := h.auth.fetchCount()
	res, err := cursorsync.Sync(context.Background(), h.options(), syncGate())
	if err != nil {
		t.Fatalf("sync under login_expired permit: %v", err)
	}
	if res.Ran || !strings.Contains(res.Skipped, "login expired") {
		t.Fatalf("login_expired round: ran=%t skipped=%q", res.Ran, res.Skipped)
	}
	if h.auth.fetchCount() != fetches {
		t.Fatal("a login_expired permit must not re-read the credential")
	}
}

// The account switch is the one place a local answer is still required: a
// different Cursor account must not silently continue another account's history
// and caches. Declining there is a distinct, named outcome (never a read of the
// new credential into the ledger).
func TestEnableAccountSwitchDeclineIsNamed(t *testing.T) {
	h := newHarness(t)
	h.pull.setEvents(ev("evt-a1", baseTime.Add(-30*time.Minute), 100, 0, 0, 50))
	if _, err := cursorsync.Enable(context.Background(), h.options(), nil); err != nil {
		t.Fatalf("first enable: %v", err)
	}
	h.auth.setToken("tok-B")
	if _, err := cursorsync.Sync(context.Background(), h.options(), syncGate()); err != nil {
		t.Fatalf("switch pause: %v", err)
	}

	decline := &fakeConfirm{answer: false}
	_, err := cursorsync.Enable(context.Background(), h.options(), decline.confirm)
	if !errors.Is(err, cursorsync.ErrConfirmationDeclined) {
		t.Fatalf("a declined switch must be ErrConfirmationDeclined, got %v", err)
	}
	if decline.callCount() != 1 {
		t.Fatalf("the switch must ask exactly once, got %d", decline.callCount())
	}
	license := loadLicense(t, h.dir)
	if license.Status != cursorsource.StatusPausedAccountSwitch {
		t.Fatalf("a declined switch must leave the permit paused, got %q", license.Status)
	}
	if license.AccountMatchID != identity.MatchAccount(accountA) {
		t.Fatalf("the permit must still belong to account A after a decline")
	}
}
