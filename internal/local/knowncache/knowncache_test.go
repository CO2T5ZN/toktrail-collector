package knowncache

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"toktrail-collector/internal/local/outbox"
)

// writeBatch writes one batch file and registers it in the outbox, the way an
// export commit leaves the state directory.
func writeBatch(t *testing.T, stateDir, batchID, source string, records []map[string]any) string {
	t.Helper()
	path := filepath.Join(stateDir, "batches", batchID+".json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"batchId": batchID, "records": records})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{
		BatchID: batchID, File: path, Source: source, RecordCount: len(records),
	}); err != nil {
		t.Fatal(err)
	}
	return path
}

func rec(key string) map[string]any {
	return map[string]any{"recordKey": key, "tool": "Codex", "input": "10", "output": "2"}
}

// The first load rebuilds from the batch files and persists a cache; the next
// load serves the same baseline without re-parsing the batch JSON.
func TestLoadBaselineRebuildsThenCaches(t *testing.T) {
	stateDir := t.TempDir()
	writeBatch(t, stateDir, "b1", "codex-jsonl", []map[string]any{rec("k1"), rec("k2")})

	first, err := LoadBaseline(context.Background(), stateDir, "codex-jsonl", "Codex")
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || len(first["k1"]) == 0 {
		t.Fatalf("baseline = %#v, want two records", first)
	}
	if _, err := os.Stat(New(stateDir).Path("codex-jsonl")); err != nil {
		t.Fatalf("the cache must be persisted after a rebuild: %v", err)
	}
	second, err := LoadBaseline(context.Background(), stateDir, "codex-jsonl", "Codex")
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 2 || string(second["k2"]) != string(first["k2"]) {
		t.Fatalf("the cached baseline must equal the rebuilt one")
	}
}

// A batch file edited out of band invalidates the cache: the digest proof
// fails, so the baseline is rebuilt from the current bytes instead of serving
// the stale cache.
func TestLoadBaselineDetectsTamperedBatch(t *testing.T) {
	stateDir := t.TempDir()
	path := writeBatch(t, stateDir, "b1", "codex-jsonl", []map[string]any{rec("k1")})
	if _, err := LoadBaseline(context.Background(), stateDir, "codex-jsonl", "Codex"); err != nil {
		t.Fatal(err)
	}
	// Same record count, different content.
	payload, err := json.Marshal(map[string]any{"batchId": "b1", "records": []map[string]any{
		{"recordKey": "k1", "tool": "Codex", "input": "99", "output": "2"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	baseline, err := LoadBaseline(context.Background(), stateDir, "codex-jsonl", "Codex")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(baseline["k1"]); got == "" || !contains(got, `"99"`) {
		t.Fatalf("the rebuilt baseline must reflect the current batch bytes, got %q", got)
	}
}

// A corrupt cache is not an error: it is discarded and rebuilt.
func TestLoadBaselineIgnoresCorruptCache(t *testing.T) {
	stateDir := t.TempDir()
	writeBatch(t, stateDir, "b1", "codex-jsonl", []map[string]any{rec("k1")})
	cachePath := New(stateDir).Path("codex-jsonl")
	if err := os.WriteFile(cachePath, []byte("{not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	baseline, err := LoadBaseline(context.Background(), stateDir, "codex-jsonl", "Codex")
	if err != nil {
		t.Fatalf("a corrupt cache must fall back to a rebuild, got %v", err)
	}
	if len(baseline) != 1 {
		t.Fatalf("baseline = %#v, want one record", baseline)
	}
}

// Appending a committed batch keeps the cache covering the ledger, so the
// next load is served from the cache.
func TestAppendCommittedBatchExtendsCache(t *testing.T) {
	stateDir := t.TempDir()
	writeBatch(t, stateDir, "b1", "codex-jsonl", []map[string]any{rec("k1")})
	if _, err := LoadBaseline(context.Background(), stateDir, "codex-jsonl", "Codex"); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"batchId": "b2", "records": []map[string]any{rec("k2")}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(stateDir, "batches", "b2.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{
		BatchID: "b2", File: path, Source: "codex-jsonl", RecordCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := AppendCommittedBatch(stateDir, "codex-jsonl", "b2", payload); err != nil {
		t.Fatal(err)
	}
	baseline, err := LoadBaseline(context.Background(), stateDir, "codex-jsonl", "Codex")
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline) != 2 {
		t.Fatalf("baseline after append = %#v, want both records", baseline)
	}
}

// A batch belonging to another source never enters this source's baseline.
func TestLoadBaselineIgnoresOtherSources(t *testing.T) {
	stateDir := t.TempDir()
	writeBatch(t, stateDir, "b1", "codex-jsonl", []map[string]any{rec("k1")})
	writeBatch(t, stateDir, "b2", "deepseek-harness", []map[string]any{rec("other")})
	baseline, err := LoadBaseline(context.Background(), stateDir, "codex-jsonl", "Codex")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := baseline["other"]; ok {
		t.Fatalf("a foreign source's record leaked into the baseline")
	}
	if len(baseline) != 1 {
		t.Fatalf("baseline = %#v, want only this source's record", baseline)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// benchState builds a state directory shaped like a real history: batches of
// 500 records, registered in the outbox.
func benchState(b *testing.B, batches, perBatch int) string {
	b.Helper()
	stateDir := b.TempDir()
	if err := os.MkdirAll(filepath.Join(stateDir, "batches"), 0o700); err != nil {
		b.Fatal(err)
	}
	store := outbox.New(stateDir)
	for i := 0; i < batches; i++ {
		records := make([]map[string]any, 0, perBatch)
		for j := 0; j < perBatch; j++ {
			records = append(records, map[string]any{
				"recordKey":      fmt.Sprintf("codex-jsonl:hash%d:%d", i, j),
				"kind":           "delta",
				"tool":           "Codex",
				"model":          "gpt-5-codex",
				"occurredAt":     "2026-10-20T01:00:00Z",
				"input":          "100",
				"cacheRead":      "50",
				"cacheWrite":     "5",
				"output":         "20",
				"adapterVersion": "codex-jsonl-v1",
				"sourceType":     "codex-jsonl",
			})
		}
		batchID := fmt.Sprintf("batch-%04d", i)
		path := filepath.Join(stateDir, "batches", batchID+".json")
		payload, err := json.Marshal(map[string]any{"batchId": batchID, "records": records})
		if err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			b.Fatal(err)
		}
		if _, err := store.AddPending(outbox.AddBatchOptions{BatchID: batchID, File: path, Source: "codex-jsonl", RecordCount: len(records)}); err != nil {
			b.Fatal(err)
		}
	}
	return stateDir
}

// BenchmarkLoadBaselineRebuild is the historical per-run cost: read and
// canonicalise every historical batch file.
func BenchmarkLoadBaselineRebuild(b *testing.B) {
	stateDir := benchState(b, 300, 500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Drop the cache each iteration so the rebuild path runs.
		_ = os.Remove(New(stateDir).Path("codex-jsonl"))
		if _, err := LoadBaseline(context.Background(), stateDir, "codex-jsonl", "Codex"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLoadBaselineCached is the new per-run cost: validate the cache
// against the batch digests and serve the stored baseline.
func BenchmarkLoadBaselineCached(b *testing.B) {
	stateDir := benchState(b, 300, 500)
	if _, err := LoadBaseline(context.Background(), stateDir, "codex-jsonl", "Codex"); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := LoadBaseline(context.Background(), stateDir, "codex-jsonl", "Codex"); err != nil {
			b.Fatal(err)
		}
	}
}

// A cache written by a different collector version is discarded, not trusted:
// the baseline is rebuilt from the batch files exactly as before.
func TestLoadBaselineIgnoresForeignCacheVersion(t *testing.T) {
	stateDir := t.TempDir()
	writeBatch(t, stateDir, "b1", "codex-jsonl", []map[string]any{rec("k1")})
	cachePath := New(stateDir).Path("codex-jsonl")
	if err := os.WriteFile(cachePath, []byte(`{"kind":"header","v":999}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	baseline, err := LoadBaseline(context.Background(), stateDir, "codex-jsonl", "Codex")
	if err != nil {
		t.Fatalf("a foreign cache version must fall back to a rebuild, got %v", err)
	}
	if len(baseline) != 1 {
		t.Fatalf("baseline = %#v, want one record", baseline)
	}
}
