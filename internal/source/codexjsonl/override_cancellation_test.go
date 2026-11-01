package codexjsonl_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/overrides"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/codexjsonl"
)

// Override-ledger cancellation coverage: after replaying the stored
// history, FilterForExport folds the override ledger into its known-record
// baseline, and that fold honors Options.Context once per ledger record in
// both ledger scans (see internal/local/overrides.ApplyToBaselineContext).
// These tests pin the wiring from the adapter's scope through those scans:
// a scope cancelled inside the override application fails the whole filter
// with the context error and no partial result, and a nil Options.Context
// keeps the exact historical uncancellable behavior. All state is
// synthetic (t.TempDir + inline records); nothing reads a real collector
// state directory.

// overrideFilterFixture builds a synthetic codex history plus an override
// ledger (returned unsaved): one stored synced batch (known-1, known-2),
// a ledger with three confirmed codex entries (known-1 superseding the
// stored payload, plus the two ledger-only keys over-1 and over-2), one
// confirmed and one pending entry for another source (which must neither
// block nor apply), and a fresh scan carrying one ledger-only record and
// one unknown record. Without the ledger both fresh records pass
// (expectedWithout); with it, over-1 is already authoritative and drops
// (expected). The ledger is returned separately so a test can first
// measure the checkpoint total without it.
func overrideFilterFixture(t *testing.T) (stateDir string, fresh, expectedWithout, expected []adapter.Record, ledger overrides.Ledger) {
	t.Helper()
	stateDir = t.TempDir()
	if err := statedir.New(stateDir).Save(statedir.DeviceState{DeviceID: "device-a", DeviceSecret: strings.Repeat("a", 64), ServerURL: "http://srv"}); err != nil {
		t.Fatal(err)
	}
	rec := func(key, tokens string) adapter.Record {
		return adapter.Record{"recordKey": key, "inputTokens": tokens, "occurredAt": "2026-10-20T12:00:00Z", "source": adapter.CodexJSONLSource}
	}
	file := filepath.Join(stateDir, "hist.json")
	payload, err := json.Marshal(adapter.Batch{BatchID: "hist", Records: []adapter.Record{rec("codex:known-1", "10"), rec("codex:known-2", "10")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := outbox.New(stateDir).Save(outbox.Outbox{Batches: []outbox.BatchEntry{{BatchID: "hist", File: file, Source: adapter.CodexJSONLSource, Status: outbox.StatusSynced}}}); err != nil {
		t.Fatal(err)
	}
	canonical := func(key, tokens string) json.RawMessage {
		raw, err := overrides.CanonicalRecord(rec(key, tokens))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	at := time.Now().UTC()
	confirmed := func(key, source string) overrides.Entry {
		return overrides.Entry{RecordKey: key, Source: source, Record: canonical(key, "1"), AttemptID: "oa-" + key, Status: overrides.StatusConfirmed, UpdatedAt: at}
	}
	ledger = overrides.Ledger{Schema: overrides.Schema, DeviceID: "device-a", ServerURL: "http://srv", Entries: map[string]overrides.Entry{
		"codex:known-1": {RecordKey: "codex:known-1", Source: adapter.CodexJSONLSource, Record: canonical("codex:known-1", "11"), AttemptID: "oa-known-1", Status: overrides.StatusConfirmed, UpdatedAt: at},
		"codex:over-1":  confirmed("codex:over-1", adapter.CodexJSONLSource),
		"codex:over-2":  confirmed("codex:over-2", adapter.CodexJSONLSource),
		"dsh:d1":        confirmed("dsh:d1", adapter.DeepSeekHarnessSource),
		"dsh:dp":        {RecordKey: "dsh:dp", Source: adapter.DeepSeekHarnessSource, PendingRecord: canonical("dsh:dp", "5"), PendingAttemptID: "oa-dp", Status: overrides.StatusPending, PendingSince: &at, UpdatedAt: at},
	}}
	fresh = []adapter.Record{rec("codex:over-1", "1"), rec("codex:new-1", "1")}
	expectedWithout = []adapter.Record{rec("codex:over-1", "1"), rec("codex:new-1", "1")}
	expected = []adapter.Record{rec("codex:new-1", "1")}
	return stateDir, fresh, expectedWithout, expected, ledger
}

// TestFilterForExportOverrideLedgerMidCancellationDiscardsPartialResult
// proves the adapter's scope reaches the override ledger scans. A complete
// run without the ledger measures the checkpoint total; saving the ledger
// must add at least one check per record in EACH of the two per-record
// scans. Every checkpoint inside that added window then fails the filter
// with the context error and no records, and every other checkpoint either
// completes with exactly the baseline result or fails the same way — never
// a prefix of the scan. The ledger file on disk stays byte-identical
// throughout.
func TestFilterForExportOverrideLedgerMidCancellationDiscardsPartialResult(t *testing.T) {
	stateDir, fresh, expectedWithout, expected, ledger := overrideFilterFixture(t)

	// Baseline checkpoint count without the ledger (a missing ledger is a
	// no-op that still checks the scope at its entry).
	probe := &cancelAfterContext{Context: context.Background(), cancelAfter: math.MaxInt}
	got, err := codexjsonl.Adapter().FilterForExport(adapter.Options{Source: adapter.CodexJSONLSource, StateDir: stateDir, Context: probe}, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, expectedWithout) {
		t.Fatalf("without the ledger every fresh record must pass, got %#v", got)
	}
	totalWithout := probe.calls

	if err := overrides.New(stateDir).Save(ledger); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(overrides.New(stateDir).Path())
	if err != nil {
		t.Fatal(err)
	}

	probe = &cancelAfterContext{Context: context.Background(), cancelAfter: math.MaxInt}
	baseline, err := codexjsonl.Adapter().FilterForExport(adapter.Options{Source: adapter.CodexJSONLSource, StateDir: stateDir, Context: probe}, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(baseline, expected) {
		t.Fatalf("the override baseline must drop the ledger-only record, got %#v", baseline)
	}
	total := probe.calls
	entries := len(ledger.Entries)
	// The ledger's two per-record scans (pending-source and
	// confirmed-entry) must check the scope once per record each.
	if total < totalWithout+2*entries {
		t.Fatalf("the override ledger scans must check the scope per record: %d checks with the ledger < %d without + 2*%d", total, totalWithout, entries)
	}

	// The checkpoints the ledger scans added sit between the filter's
	// pre-override boundary check and the fresh-record loop: cancel at
	// every one of them and the filter must fail with the context error
	// and no partial result.
	windowStart := totalWithout - len(fresh) + 1
	windowEnd := windowStart + 2*entries - 1
	if windowStart < 1 || windowEnd > total-len(fresh) {
		t.Fatalf("ledger scan window (%d..%d) overruns the filter checkpoints (total %d, %d fresh)", windowStart, windowEnd, total, len(fresh))
	}
	for k := windowStart; k <= windowEnd; k++ {
		got, err := codexjsonl.Adapter().FilterForExport(
			adapter.Options{Source: adapter.CodexJSONLSource, StateDir: stateDir, Context: &cancelAfterContext{Context: context.Background(), cancelAfter: k}},
			fresh)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation inside the override ledger scans (k=%d) must surface context.Canceled, got err=%v result=%#v", k, err, got)
		}
		if got != nil {
			t.Fatalf("cancellation inside the override ledger scans (k=%d) must not return a partial result: %#v", k, got)
		}
	}

	// Umbrella invariant: cancel at EVERY checkpoint; each prefix length
	// either completes with exactly the baseline result or fails with the
	// context error and no records.
	for k := 1; k <= 2*total; k++ {
		got, err := codexjsonl.Adapter().FilterForExport(
			adapter.Options{Source: adapter.CodexJSONLSource, StateDir: stateDir, Context: &cancelAfterContext{Context: context.Background(), cancelAfter: k}},
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

	after, err := os.ReadFile(overrides.New(stateDir).Path())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("the filter must not write the override ledger or any other persistent state")
	}
}

// TestFilterForExportNilContextWithOverrideLedgerKeepsLegacyFilter pins
// nil compatibility on the override path: a nil Options.Context
// reproduces the historical uncancellable filter exactly (the override
// baseline still applies and drops the ledger-only record), matching an
// explicit context.Background().
func TestFilterForExportNilContextWithOverrideLedgerKeepsLegacyFilter(t *testing.T) {
	stateDir, fresh, _, expected, ledger := overrideFilterFixture(t)
	if err := overrides.New(stateDir).Save(ledger); err != nil {
		t.Fatal(err)
	}

	legacy, err := codexjsonl.Adapter().FilterForExport(adapter.Options{Source: adapter.CodexJSONLSource, StateDir: stateDir}, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(legacy, expected) {
		t.Fatalf("legacy filter must apply the override baseline and drop the ledger-only record, got %#v", legacy)
	}
	scoped, err := codexjsonl.Adapter().FilterForExport(adapter.Options{Source: adapter.CodexJSONLSource, StateDir: stateDir, Context: context.Background()}, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(legacy, scoped) {
		t.Fatalf("nil Options.Context must reproduce the historical filter:\n%#v\n%#v", legacy, scoped)
	}
}
