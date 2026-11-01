package codexjsonl

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/source/adapter"
)

func TestCodexKnownHistoryAcrossPendingAckAndQuarantine(t *testing.T) {
	for _, status := range []string{outbox.StatusPending, outbox.StatusSynced, outbox.StatusReorganized, "quarantine"} {
		t.Run(status, func(t *testing.T) {
			dir := t.TempDir()
			old := adapter.Record{"recordKey": "codex-jsonl:abc:2", "inputTokens": "18446744073709551615"}
			fresh := adapter.Record{"recordKey": "codex-jsonl:abc:3", "inputTokens": "4"}
			raw, _ := json.Marshal(old)
			if status == "quarantine" {
				if err := quarantine.New(dir).Append([]quarantine.Entry{{Source: "codex-jsonl", RecordKey: old["recordKey"].(string), Record: raw, OriginBatchID: "old"}}); err != nil {
					t.Fatal(err)
				}
			} else {
				file := filepath.Join(dir, "old.json")
				payload, _ := json.Marshal(adapter.Batch{BatchID: "old", Records: []adapter.Record{old}})
				if err := os.WriteFile(file, payload, 0600); err != nil {
					t.Fatal(err)
				}
				if err := outbox.New(dir).Save(outbox.Outbox{Batches: []outbox.BatchEntry{{BatchID: "old", File: file, Source: "codex-jsonl", Status: status}}}); err != nil {
					t.Fatal(err)
				}
			}
			got, err := filterKnownCodexRecordsContext(context.Background(), dir, []adapter.Record{old, fresh})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0]["recordKey"] != fresh["recordKey"] {
				t.Fatalf("expected only appended line, got %v", got)
			}
			got, err = filterKnownCodexRecordsContext(context.Background(), dir, []adapter.Record{old})
			if err != nil || len(got) != 0 {
				t.Fatalf("repeat: %v %v", got, err)
			}
			changed := adapter.Record{"recordKey": old["recordKey"], "inputTokens": "1"}
			if _, err := filterKnownCodexRecordsContext(context.Background(), dir, []adapter.Record{changed}); err == nil {
				t.Fatal("mutated immutable line accepted")
			}
		})
	}
}
func TestCodexHistoryMissingBatchFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := outbox.New(dir).Save(outbox.Outbox{Batches: []outbox.BatchEntry{{BatchID: "lost", File: filepath.Join(dir, "missing"), Source: "codex-jsonl", Status: outbox.StatusSynced}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := filterKnownCodexRecordsContext(context.Background(), dir, nil); err == nil {
		t.Fatal("missing immutable history was ignored")
	}
}
