package deepseekharness

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
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/adapter"
)

// TestDSHHistoryHonorsOverrideBaseline mirrors the codex override-baseline
// test for the deepseek-harness known-record filter: a confirmed override
// supersedes the stored payload and a pending override blocks the scan.
func TestDSHHistoryHonorsOverrideBaseline(t *testing.T) {
	key := "deepseek-harness:abc"
	old := adapter.Record{"recordKey": key, "inputTokens": "10"}
	current := adapter.Record{"recordKey": key, "inputTokens": "11"}

	dir := t.TempDir()
	if err := statedir.New(dir).Save(statedir.DeviceState{DeviceID: "device-a", DeviceSecret: strings.Repeat("a", 64), ServerURL: "http://srv"}); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "old.json")
	payload, _ := json.Marshal(adapter.Batch{BatchID: "old", Records: []adapter.Record{old}})
	if err := os.WriteFile(file, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := outbox.New(dir).Save(outbox.Outbox{Batches: []outbox.BatchEntry{{BatchID: "old", File: file, Source: adapter.DeepSeekHarnessSource, Status: outbox.StatusSynced}}}); err != nil {
		t.Fatal(err)
	}
	canonicalCurrent, err := overrides.CanonicalRecord(current)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	ledger := overrides.Ledger{
		Schema:    overrides.Schema,
		DeviceID:  "device-a",
		ServerURL: "http://srv",
		Entries: map[string]overrides.Entry{
			key: {RecordKey: key, Source: adapter.DeepSeekHarnessSource, Record: canonicalCurrent, AttemptID: "oa-1", Status: overrides.StatusConfirmed, UpdatedAt: at},
		},
	}
	if err := overrides.New(dir).Save(ledger); err != nil {
		t.Fatal(err)
	}
	got, err := filterKnownDSHRecordsContext(context.Background(), dir, []adapter.Record{current})
	if err != nil || len(got) != 0 {
		t.Fatalf("current scan must drop against the confirmed override: %v %v", got, err)
	}
	if _, err := filterKnownDSHRecordsContext(context.Background(), dir, []adapter.Record{old}); err == nil {
		t.Fatal("the superseded archived payload must fail closed as a new drift")
	}
	pending := ledger.Entries[key]
	pending.Status = overrides.StatusPending
	pending.PendingRecord = canonicalCurrent
	pending.PendingAttemptID = "oa-2"
	pending.PendingSince = &at
	ledger.Entries[key] = pending
	if err := overrides.New(dir).Save(ledger); err != nil {
		t.Fatal(err)
	}
	if _, err := filterKnownDSHRecordsContext(context.Background(), dir, []adapter.Record{current}); err == nil || !strings.Contains(err.Error(), "pending") {
		t.Fatalf("a pending override must block the dsh scan: %v", err)
	}
}
