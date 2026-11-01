package pipeline

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"testing"
	"time"

	"toktrail-collector/internal/local/filtertxn"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/adapter"
)

// cancelAfterContext is a synthetic cancellation scope for deterministic
// cancellation tests: it reports context.Canceled from the cancelAfter-th
// Err call onward, so a test can cancel at any chosen checkpoint without
// sleeping or racing a real timer. It mirrors the helper the source loader
// packages use (see their cancellation_test.go) and also counts every Err
// call, which lets a test measure how many cancellation checks one
// complete run performs and then cancel exactly at each of them.
type cancelAfterContext struct {
	context.Context
	cancelAfter int
	calls       int
	cancelled   bool
}

func (c *cancelAfterContext) Err() error {
	c.calls++
	if c.calls >= c.cancelAfter {
		c.cancelled = true
	}
	if c.cancelled {
		return context.Canceled
	}
	return nil
}

// cutoffFixture describes one synthetic FilterHistoryCutoff input: six
// records around the cutoff (three strictly before it, three after) with
// matching message updates, so the record partition, the update partition,
// and the quarantine-entry building loops all have real work to interrupt.
// Everything is inline data; no real collector state is read.
func cutoffFixture() (cutoff time.Time, records []adapter.Record, updates []progress.MessagePendingUpdate) {
	cutoff = time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	tok := uint64(100)
	for i := 1; i <= 3; i++ {
		records = append(records, adapter.Record{
			"recordKey":  fmt.Sprintf("rec-old-%d", i),
			"occurredAt": "2026-10-15T00:00:00Z",
			"source":     adapter.ClaudeCodeJSONLSource,
		})
		updates = append(updates, progress.MessagePendingUpdate{
			MessageID: fmt.Sprintf("msg-old-%d", i),
			RecordKey: fmt.Sprintf("rec-old-%d", i),
			To:        &progress.MessageUsageState{Input: &tok},
		})
	}
	for i := 1; i <= 3; i++ {
		records = append(records, adapter.Record{
			"recordKey":  fmt.Sprintf("rec-new-%d", i),
			"occurredAt": "2026-10-20T00:00:00Z",
			"source":     adapter.ClaudeCodeJSONLSource,
		})
		updates = append(updates, progress.MessagePendingUpdate{
			MessageID: fmt.Sprintf("msg-new-%d", i),
			RecordKey: fmt.Sprintf("rec-new-%d", i),
			To:        &progress.MessageUsageState{Input: &tok},
		})
	}
	return cutoff, records, updates
}

// writeCutoffState creates a fresh synthetic state directory whose stored
// device cutoff governs (no HistoryFrom on the options, exercising the
// managed-consent/state fallback loads).
func writeCutoffState(t *testing.T, cutoff time.Time) string {
	t.Helper()
	dir := t.TempDir()
	if err := statedir.New(dir).Save(statedir.DeviceState{DeviceID: "dev-cutoff-cancel", HistoryFrom: &cutoff, HistoryDays: 7}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func cutoffOptions(dir string) adapter.Options {
	return adapter.Options{Source: adapter.ClaudeCodeJSONLSource, StateDir: dir}
}

// assertCutoffStateUntouched fails when a cancelled run left any
// half-applied trace: no pending filter journal, no quarantine entries, and
// no confirmed baseline for the skipped messages. This is the crash-recovery
// boundary made observable: cancellation before the last checkpoint never
// starts the journaled transaction, so there is nothing to recover.
func assertCutoffStateUntouched(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Stat(filtertxn.JournalPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("cancelled run must not leave a pending journal, stat err=%v", err)
	}
	entries, err := quarantine.New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("cancelled run must not quarantine anything, got %#v", entries)
	}
	messages, _, err := progress.New(dir).LoadMessageProgress()
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		key := adapter.ClaudeCodeJSONLSource + "\x00" + fmt.Sprintf("msg-old-%d", i)
		if entry, ok := messages[key]; ok && entry.Confirmed != nil {
			t.Fatalf("cancelled run must not confirm the msg-old-%d baseline, got %#v", i, entry)
		}
	}
}

// assertCutoffStateConverged fails when a completed run did not durably
// apply the whole transaction: the journal is removed and both halves
// (quarantine entries, confirmed baselines) are present.
func assertCutoffStateConverged(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Stat(filtertxn.JournalPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("completed transaction must remove its journal, stat err=%v", err)
	}
	entries, err := quarantine.New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("completed transaction must quarantine the three skipped records, got %#v", entries)
	}
	messages, _, err := progress.New(dir).LoadMessageProgress()
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		key := adapter.ClaudeCodeJSONLSource + "\x00" + fmt.Sprintf("msg-old-%d", i)
		entry, ok := messages[key]
		if !ok || entry.Confirmed == nil || entry.Confirmed.Input == nil || *entry.Confirmed.Input != 100 {
			t.Fatalf("completed transaction must confirm baseline msg-old-%d, got %#v", i, entry)
		}
	}
}

// TestFilterHistoryCutoffPreCancelledReturnsContextError pins the entry
// checkpoint: an already-cancelled scope fails before recovery runs and
// before any partitioning work, with no partial result and no state change.
func TestFilterHistoryCutoffPreCancelledReturnsContextError(t *testing.T) {
	cutoff, records, updates := cutoffFixture()
	dir := writeCutoffState(t, cutoff)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	opt := cutoffOptions(dir)
	opt.Context = ctx
	kept, keptUpdates, err := FilterHistoryCutoff(opt, records, updates)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled filter must surface context.Canceled, got err=%v", err)
	}
	if kept != nil || keptUpdates != nil {
		t.Fatalf("cancelled filter must not return a partial partition: %#v %#v", kept, keptUpdates)
	}
	assertCutoffStateUntouched(t, dir)
}

// TestFilterHistoryCutoffExpiredDeadlineSurfacesDeadlineExceeded pins the
// same entry checkpoint for deadline scopes.
func TestFilterHistoryCutoffExpiredDeadlineSurfacesDeadlineExceeded(t *testing.T) {
	cutoff, records, updates := cutoffFixture()
	dir := writeCutoffState(t, cutoff)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Minute))
	defer cancel()

	opt := cutoffOptions(dir)
	opt.Context = ctx
	kept, keptUpdates, err := FilterHistoryCutoff(opt, records, updates)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired deadline must surface context.DeadlineExceeded, got err=%v", err)
	}
	if kept != nil || keptUpdates != nil {
		t.Fatalf("expired deadline must not return a partial partition: %#v %#v", kept, keptUpdates)
	}
	assertCutoffStateUntouched(t, dir)
}

// TestFilterHistoryCutoffMidComputationCancellationDiscardsPartialResult
// cancels at EVERY checkpoint the pure-computation phases perform: a
// complete run with a never-cancelling counting scope measures the total
// number of checks, then each prefix length either completes with exactly
// the baseline partition and converged state, or fails with the context
// error, no partial partition, and completely untouched state — never a
// half-applied transaction. The final checkpoint before filtertxn.Commit
// is what enforces the atomicity boundary: once the journal starts, the
// transaction is deliberately not interruptible (crash recovery replays
// it), so cancellation must stop the run before Commit begins.
func TestFilterHistoryCutoffMidComputationCancellationDiscardsPartialResult(t *testing.T) {
	cutoff, records, updates := cutoffFixture()

	dir := writeCutoffState(t, cutoff)
	probe := &cancelAfterContext{Context: context.Background(), cancelAfter: math.MaxInt}
	opt := cutoffOptions(dir)
	opt.Context = probe
	baseKept, baseUpdates, err := FilterHistoryCutoff(opt, records, updates)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseKept) != 3 || adapter.StringField(baseKept[0], "recordKey") != "rec-new-1" {
		t.Fatalf("baseline partition must keep only the three post-cutoff records, got %#v", baseKept)
	}
	if len(baseUpdates) != 3 || baseUpdates[0].RecordKey != "rec-new-1" {
		t.Fatalf("baseline partition must keep only the three post-cutoff updates, got %#v", baseUpdates)
	}
	assertCutoffStateConverged(t, dir)

	total := probe.calls
	if total < 12 {
		t.Fatalf("synthetic fixture is too small to exercise mid-computation cancellation: %d checks", total)
	}

	for k := 1; k <= 2*total; k++ {
		dir := writeCutoffState(t, cutoff)
		opt := cutoffOptions(dir)
		opt.Context = &cancelAfterContext{Context: context.Background(), cancelAfter: k}
		kept, keptUpdates, err := FilterHistoryCutoff(opt, records, updates)
		switch {
		case err == nil:
			if !reflect.DeepEqual(kept, baseKept) || !reflect.DeepEqual(keptUpdates, baseUpdates) {
				t.Fatalf("uncancelled run (k=%d) must equal the baseline partition:\n%#v %#v\n%#v %#v", k, kept, keptUpdates, baseKept, baseUpdates)
			}
			assertCutoffStateConverged(t, dir)
		default:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled run must surface context.Canceled, got err=%v", err)
			}
			if kept != nil || keptUpdates != nil {
				t.Fatalf("cancelled run (k=%d) must not return a partial partition: %#v %#v", k, kept, keptUpdates)
			}
			assertCutoffStateUntouched(t, dir)
		}
	}
}

// TestFilterHistoryCutoffNilContextKeepsLegacyFilter pins nil
// compatibility: a nil Options.Context reproduces the historical
// uncancellable filter exactly (ContextOrBackground falls back to
// context.Background()).
func TestFilterHistoryCutoffNilContextKeepsLegacyFilter(t *testing.T) {
	cutoff, records, updates := cutoffFixture()

	dir := writeCutoffState(t, cutoff)
	legacyKept, legacyUpdates, err := FilterHistoryCutoff(cutoffOptions(dir), records, updates)
	if err != nil {
		t.Fatal(err)
	}
	if len(legacyKept) != 3 || len(legacyUpdates) != 3 {
		t.Fatalf("legacy filter must partition identically, got %#v %#v", legacyKept, legacyUpdates)
	}

	dir2 := writeCutoffState(t, cutoff)
	scoped := cutoffOptions(dir2)
	scoped.Context = context.Background()
	scopedKept, scopedUpdates, err := FilterHistoryCutoff(scoped, records, updates)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(legacyKept, scopedKept) || !reflect.DeepEqual(legacyUpdates, scopedUpdates) {
		t.Fatalf("nil Options.Context must reproduce the historical partition:\n%#v %#v\n%#v %#v", legacyKept, legacyUpdates, scopedKept, scopedUpdates)
	}
}

// TestFilterHistoryCutoffPreCancelledSkipsPendingJournalRecovery pins the
// entry-checkpoint ordering against crash recovery: a cancelled call must
// NOT replay a pending filter transaction (a cancelled call performs no
// state mutation at all), and the pending journal survives for the next
// non-cancelled call to converge — the same replay a real crash gets.
func TestFilterHistoryCutoffPreCancelledSkipsPendingJournalRecovery(t *testing.T) {
	cutoff, records, updates := cutoffFixture()
	dir := writeCutoffState(t, cutoff)

	// A half-applied transaction left by an earlier crash: the journal is
	// durable, its quarantine half has not been applied yet.
	writePendingFilterJournal(t, dir, filtertxn.Journal{
		Schema:     filtertxn.SchemaVersion,
		Source:     adapter.ClaudeCodeJSONLSource,
		Quarantine: []quarantine.Entry{{Source: adapter.ClaudeCodeJSONLSource, RecordKey: "rec-old-crash", Record: []byte(`{"recordKey":"rec-old-crash"}`), OriginBatchID: "crash-batch", Reason: quarantine.ReasonBeforeHistoryFrom, QuarantinedAt: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)}},
		Baselines:  []progress.MessagePendingUpdate{updates[0]},
		CreatedAt:  time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC),
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	opt := cutoffOptions(dir)
	opt.Context = ctx
	kept, keptUpdates, err := FilterHistoryCutoff(opt, records[3:], updates[3:])
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled filter must surface context.Canceled, got err=%v", err)
	}
	if kept != nil || keptUpdates != nil {
		t.Fatalf("cancelled filter must not return a partial partition: %#v %#v", kept, keptUpdates)
	}
	if _, statErr := os.Stat(filtertxn.JournalPath(dir)); statErr != nil {
		t.Fatalf("pending journal must survive a cancelled call, stat err=%v", statErr)
	}
	if entries, lerr := quarantine.New(dir).Load(); lerr != nil || len(entries) != 0 {
		t.Fatalf("cancelled call must not apply the pending journal, entries=%#v err=%v", entries, lerr)
	}

	// The next non-cancelled call replays the journal to completion even
	// though its own input has nothing to skip.
	kept, keptUpdates, err = FilterHistoryCutoff(cutoffOptions(dir), records[3:], updates[3:])
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 3 || len(keptUpdates) != 3 {
		t.Fatalf("post-recovery run must partition normally, got %#v %#v", kept, keptUpdates)
	}
	entries, err := quarantine.New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].RecordKey != "rec-old-crash" {
		t.Fatalf("recovery must apply the pending quarantine half, got %#v", entries)
	}
	messages, _, err := progress.New(dir).LoadMessageProgress()
	if err != nil {
		t.Fatal(err)
	}
	entry := messages[adapter.ClaudeCodeJSONLSource+"\x00msg-old-1"]
	if entry.Confirmed == nil || entry.Confirmed.Input == nil || *entry.Confirmed.Input != 100 {
		t.Fatalf("recovery must apply the pending baseline half, got %#v", entry)
	}
	if _, statErr := os.Stat(filtertxn.JournalPath(dir)); !os.IsNotExist(statErr) {
		t.Fatalf("recovered journal must be removed, stat err=%v", statErr)
	}
}
