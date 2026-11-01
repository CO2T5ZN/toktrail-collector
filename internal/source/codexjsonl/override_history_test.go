package codexjsonl

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/overrides"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/adapter"
)

// TestCodexHistoryHonorsOverrideBaseline covers the override-ledger
// integration of the codex known-record filter: a confirmed override
// supersedes the stored payload (an identical fresh scan drops, a new
// drift fails closed), and a pending override blocks the whole scan.
func TestCodexHistoryHonorsOverrideBaseline(t *testing.T) {
	key := "codex-jsonl:abc:2"
	old := adapter.Record{"recordKey": key, "inputTokens": "10"}
	current := adapter.Record{"recordKey": key, "inputTokens": "11"}
	future := adapter.Record{"recordKey": key, "inputTokens": "12"}

	dir := t.TempDir()
	if err := statedir.New(dir).Save(statedir.DeviceState{DeviceID: "device-a", DeviceSecret: strings.Repeat("a", 64), ServerURL: "http://srv"}); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "old.json")
	payload, _ := json.Marshal(adapter.Batch{BatchID: "old", Records: []adapter.Record{old}})
	if err := os.WriteFile(file, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := outbox.New(dir).Save(outbox.Outbox{Batches: []outbox.BatchEntry{{BatchID: "old", File: file, Source: "codex-jsonl", Status: outbox.StatusSynced}}}); err != nil {
		t.Fatal(err)
	}
	if err := quarantine.New(dir).Append(nil); err != nil {
		t.Fatal(err)
	}
	canonicalCurrent, err := overrides.CanonicalRecord(current)
	if err != nil {
		t.Fatal(err)
	}
	canonicalFuture, err := overrides.CanonicalRecord(future)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	ledger := overrides.Ledger{
		Schema:    overrides.Schema,
		DeviceID:  "device-a",
		ServerURL: "http://srv",
		Entries: map[string]overrides.Entry{
			key: {RecordKey: key, Source: "codex-jsonl", Record: canonicalCurrent, AttemptID: "oa-1", Status: overrides.StatusConfirmed, UpdatedAt: at},
		},
	}
	if err := overrides.New(dir).Save(ledger); err != nil {
		t.Fatal(err)
	}

	// Confirmed override is the baseline: the CURRENT scan drops even
	// though it differs from the stored archived payload.
	got, err := filterKnownCodexRecordsContext(context.Background(), dir, []adapter.Record{current})
	if err != nil || len(got) != 0 {
		t.Fatalf("current scan must drop against the confirmed override: %v %v", got, err)
	}
	// The superseded archived payload is NOT "already synced" anymore.
	got, err = filterKnownCodexRecordsContext(context.Background(), dir, []adapter.Record{old})
	if err == nil || len(got) != 0 {
		t.Fatalf("the superseded archived payload must fail closed as a new drift, got %v %v", got, err)
	}
	// A further drift fails closed with the override pointer.
	if _, err := filterKnownCodexRecordsContext(context.Background(), dir, []adapter.Record{future}); err == nil || !strings.Contains(err.Error(), "replace-existing") {
		t.Fatalf("a drift past the override must point at the override pass: %v", err)
	}
	_ = canonicalFuture

	// A pending attempt blocks the whole scan fail-closed.
	pending := ledger.Entries[key]
	pending.Status = overrides.StatusPending
	pending.PendingRecord = canonicalFuture
	pending.PendingAttemptID = "oa-2"
	pending.PendingSince = &at
	ledger.Entries[key] = pending
	if err := overrides.New(dir).Save(ledger); err != nil {
		t.Fatal(err)
	}
	if _, err := filterKnownCodexRecordsContext(context.Background(), dir, []adapter.Record{current}); err == nil || !strings.Contains(err.Error(), "pending") {
		t.Fatalf("a pending override must block the scan: %v", err)
	}

	// A ledger bound to another device is never applied.
	bound := ledger.Entries[key]
	bound.Status = overrides.StatusConfirmed
	bound.PendingRecord = nil
	bound.PendingAttemptID = ""
	bound.PendingSince = nil
	ledger.Entries[key] = bound
	ledger.DeviceID = "device-b"
	if err := overrides.New(dir).Save(ledger); err != nil {
		t.Fatal(err)
	}
	if _, err := filterKnownCodexRecordsContext(context.Background(), dir, []adapter.Record{current}); err == nil || !strings.Contains(err.Error(), "device") {
		t.Fatalf("a foreign ledger binding must fail closed: %v", err)
	}
}
