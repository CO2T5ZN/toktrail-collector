package hermessqlite

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/source/adapter"
)

// cancelAfterContext is a synthetic cancellation scope for deterministic
// cancellation tests: it reports context.Canceled from the cancelAfter-th
// Err call onward, so a test can cancel at any chosen checkpoint of a
// filter pass without sleeping or racing a real timer. It mirrors the
// helper the JSONL loader packages use (see their cancellation_test.go)
// and also counts every Err call, which lets a test measure how many
// cancellation checks one complete filter performs and then cancel
// exactly at each of them.
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

// History-filter cancellation coverage: FilterForExport replays the
// immutable outbox and quarantine history (one file read per stored batch,
// one JSON decode per stored record) before partitioning fresh records, so
// a large history is a long loop that must honor Options.Context at coarse
// boundaries and never leak a partial fresh slice when the scope cancels.
// All state below is synthetic (t.TempDir + inline records); nothing reads
// a real collector state directory.

// writeHistoryFilterBatch registers one stored batch of records in the
// outbox ledger for the given source, standing in for previously exported
// history.
func writeHistoryFilterBatch(t *testing.T, stateDir, batchID, source string, records []adapter.Record) {
	t.Helper()
	body, err := json.Marshal(adapter.Batch{BatchID: batchID, Records: records})
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}
	path := filepath.Join(stateDir, batchID+".json")
	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		t.Fatalf("write batch file: %v", err)
	}
	ledger, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatalf("load outbox ledger: %v", err)
	}
	ledger.Batches = append(ledger.Batches, outbox.BatchEntry{
		BatchID: batchID,
		File:    path,
		Source:  source,
		Status:  outbox.StatusSynced,
	})
	if err := outbox.New(stateDir).Save(ledger); err != nil {
		t.Fatalf("save outbox ledger: %v", err)
	}
}

// appendHistoryFilterQuarantine stores one quarantined record for the
// given source.
func appendHistoryFilterQuarantine(t *testing.T, stateDir, source, key string, record adapter.Record) {
	t.Helper()
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	if err := quarantine.New(stateDir).Append([]quarantine.Entry{{
		Source:        source,
		RecordKey:     key,
		Record:        raw,
		OriginBatchID: "history-origin",
		Reason:        quarantine.ReasonToolNotAllowed,
	}}); err != nil {
		t.Fatalf("append quarantine entry: %v", err)
	}
}

// historyFilterFixture builds a synthetic history for one source: two
// stored outbox batches (two records each), one stored batch for an
// unrelated source, two quarantined records for this source plus one for
// the unrelated source, and a fresh scan mixing known and unknown records.
// The expected filter result drops every known record.
func historyFilterFixture(t *testing.T, source, otherSource string) (stateDir string, fresh []adapter.Record, expected []adapter.Record) {
	t.Helper()
	stateDir = t.TempDir()
	rec := func(key string) adapter.Record {
		return adapter.Record{"recordKey": key, "occurredAt": "2026-10-20T12:00:00Z", "source": source}
	}
	writeHistoryFilterBatch(t, stateDir, "hist-a", source, []adapter.Record{rec("known-batch-1"), rec("known-batch-2")})
	writeHistoryFilterBatch(t, stateDir, "hist-b", source, []adapter.Record{rec("known-batch-3"), rec("known-batch-4")})
	writeHistoryFilterBatch(t, stateDir, "hist-other", otherSource, []adapter.Record{rec("other-source-1")})
	appendHistoryFilterQuarantine(t, stateDir, source, "known-quarantine-1", rec("known-quarantine-1"))
	appendHistoryFilterQuarantine(t, stateDir, source, "known-quarantine-2", rec("known-quarantine-2"))
	appendHistoryFilterQuarantine(t, stateDir, otherSource, "other-quarantine-1", rec("other-quarantine-1"))
	fresh = []adapter.Record{rec("known-batch-1"), rec("known-quarantine-1"), rec("brand-new-1"), rec("brand-new-2")}
	expected = []adapter.Record{rec("brand-new-1"), rec("brand-new-2")}
	return stateDir, fresh, expected
}

// TestFilterForExportPreCancelledReturnsContextError pins the entry
// checkpoint: an already-cancelled scope fails the filter before any
// history is read, with no partial fresh slice.
func TestFilterForExportPreCancelledReturnsContextError(t *testing.T) {
	stateDir, fresh, _ := historyFilterFixture(t, adapter.HermesSQLiteSource, adapter.UsageJSONSource)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := Adapter().FilterForExport(adapter.Options{Source: adapter.HermesSQLiteSource, StateDir: stateDir, Context: ctx}, fresh)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled filter must surface context.Canceled, got err=%v", err)
	}
	if got != nil {
		t.Fatalf("cancelled filter must not return a partial result: %#v", got)
	}
}

// TestFilterForExportPreCancelledWithoutStateDirReturnsContextError pins
// the closure-level entry check: even the stateless fast path (no state
// directory, nothing to filter) honors a cancelled scope instead of
// silently returning the input.
func TestFilterForExportPreCancelledWithoutStateDirReturnsContextError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := Adapter().FilterForExport(adapter.Options{Source: adapter.HermesSQLiteSource, Context: ctx}, []adapter.Record{{"recordKey": "k"}})
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled stateless filter must surface context.Canceled, got err=%v", err)
	}
	if got != nil {
		t.Fatalf("cancelled stateless filter must not return records: %#v", got)
	}
}

// TestFilterForExportExpiredDeadlineSurfacesDeadlineExceeded pins the same
// entry checkpoint for deadline scopes.
func TestFilterForExportExpiredDeadlineSurfacesDeadlineExceeded(t *testing.T) {
	stateDir, fresh, _ := historyFilterFixture(t, adapter.HermesSQLiteSource, adapter.UsageJSONSource)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Minute))
	defer cancel()

	got, err := Adapter().FilterForExport(adapter.Options{Source: adapter.HermesSQLiteSource, StateDir: stateDir, Context: ctx}, fresh)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired deadline must surface context.DeadlineExceeded, got err=%v", err)
	}
	if got != nil {
		t.Fatalf("expired deadline must not return a partial result: %#v", got)
	}
}

// TestFilterForExportMidHistoryCancellationDiscardsPartialResult cancels at
// EVERY checkpoint the filter performs: a complete run with a
// never-cancelling counting scope measures the total number of checks, then
// each prefix length either completes with exactly the baseline result or
// fails with the context error and no records — never a prefix of the
// fresh slice.
func TestFilterForExportMidHistoryCancellationDiscardsPartialResult(t *testing.T) {
	stateDir, fresh, expected := historyFilterFixture(t, adapter.HermesSQLiteSource, adapter.UsageJSONSource)

	probe := &cancelAfterContext{Context: context.Background(), cancelAfter: math.MaxInt}
	baseline, err := Adapter().FilterForExport(adapter.Options{Source: adapter.HermesSQLiteSource, StateDir: stateDir, Context: probe}, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(baseline, expected) {
		t.Fatalf("synthetic baseline must drop every known record, got %#v", baseline)
	}
	total := probe.calls
	if total < 12 {
		t.Fatalf("synthetic history is too small to exercise mid-filter cancellation: %d checks", total)
	}

	for k := 1; k <= 2*total; k++ {
		got, err := Adapter().FilterForExport(
			adapter.Options{Source: adapter.HermesSQLiteSource, StateDir: stateDir, Context: &cancelAfterContext{Context: context.Background(), cancelAfter: k}},
			fresh)
		switch {
		case err == nil:
			if !reflect.DeepEqual(got, baseline) {
				t.Fatalf("uncancelled filter (k=%d) must equal the baseline result:\n%#v\n%#v", k, got, baseline)
			}
		default:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled filter must surface context.Canceled, got err=%v", err)
			}
			if got != nil {
				t.Fatalf("cancelled filter (k=%d) must not return a partial result: %#v", k, got)
			}
		}
	}
}

// TestFilterForExportNilContextKeepsLegacyFilter pins nil compatibility: a
// nil Options.Context reproduces the historical uncancellable filter
// exactly (ContextOrBackground falls back to context.Background()).
func TestFilterForExportNilContextKeepsLegacyFilter(t *testing.T) {
	stateDir, fresh, expected := historyFilterFixture(t, adapter.HermesSQLiteSource, adapter.UsageJSONSource)

	legacy, err := Adapter().FilterForExport(adapter.Options{Source: adapter.HermesSQLiteSource, StateDir: stateDir}, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(legacy, expected) {
		t.Fatalf("legacy filter must drop every known record, got %#v", legacy)
	}
	scoped, err := Adapter().FilterForExport(adapter.Options{Source: adapter.HermesSQLiteSource, StateDir: stateDir, Context: context.Background()}, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(legacy, scoped) {
		t.Fatalf("nil Options.Context must reproduce the historical filter:\n%#v\n%#v", legacy, scoped)
	}
}
