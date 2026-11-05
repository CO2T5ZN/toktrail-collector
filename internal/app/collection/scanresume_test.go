package collection

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"toktrail-collector/internal/local/knowncache"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/scanledger"
	"toktrail-collector/internal/source/adapter"
)

// writeMonotonicCodexSession writes a Codex session JSONL: one turn context followed
// by `steps` monotonic token-count observations, which yield steps-1 delta
// records.
func writeMonotonicCodexSession(t *testing.T, dir, name string, steps int) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	base := time.Date(2026, 10, 20, 1, 0, 0, 0, time.UTC)
	var body []byte
	add := func(v any) {
		line, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		body = append(body, line...)
		body = append(body, '\n')
	}
	add(map[string]any{
		"timestamp": base.Format(time.RFC3339),
		"type":      "turn_context",
		"payload":   map[string]any{"model": "gpt-5-codex-collection"},
	})
	for step := 0; step < steps; step++ {
		add(map[string]any{
			"timestamp": base.Add(time.Duration(step) * time.Minute).Format(time.RFC3339),
			"type":      "event_msg",
			"payload": map[string]any{
				"type": "token_count",
				"info": map[string]any{"total_token_usage": map[string]any{
					"input_tokens":             2000 + 10*step,
					"cached_input_tokens":      200 + step,
					"cache_write_input_tokens": 20,
					"output_tokens":            900 + 5*step,
				}},
			},
		})
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The scan ledger may only be advanced once a source's records are safely
// committed. If the export commit fails, the file must stay "unexported" so
// the next run parses it again — otherwise its records would be skipped
// forever and silently lost.
func TestScanLedgerAdvancesOnlyAfterCommit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the failure is injected with POSIX directory permissions")
	}
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)
	sessions := filepath.Join(t.TempDir(), "sessions")
	sessionFile := writeMonotonicCodexSession(t, sessions, "a.jsonl", 4)
	enableGrant(t, stateDir, "codex-jsonl", sessions)

	// First run: two records exported, ledger records the committed content.
	res, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("first run failed: %v", err)
	}
	if res.ExportedRecords != 3 {
		t.Fatalf("first run exported %d records, want 3", res.ExportedRecords)
	}
	committed, existed, err := scanledger.New(stateDir).Load(adapter.CodexJSONLSource)
	if err != nil || !existed {
		t.Fatalf("the ledger must exist after a committed export (existed=%v err=%v)", existed, err)
	}
	firstDigest := committed[sessionFile].Digest
	if firstDigest == "" {
		t.Fatalf("the ledger must record the session file, got %#v", committed)
	}
	// The known-record cache exists after the commit, so the next scan does
	// not have to re-read and re-canonicalise the historical batch files.
	if _, statErr := os.Stat(knowncache.New(stateDir).Path(adapter.CodexJSONLSource)); statErr != nil {
		t.Fatalf("the known-record cache must exist after a committed export: %v", statErr)
	}

	// A second run over the unchanged history exports nothing and decides
	// no new work.
	quiet, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("second run failed: %v", err)
	}
	if quiet.ExportedRecords != 0 {
		t.Fatalf("an unchanged history must export nothing, got %d records", quiet.ExportedRecords)
	}

	// Append one observation, then make the batch directory unwritable so
	// the export commit fails after the scan.
	data, err := os.ReadFile(sessionFile)
	if err != nil {
		t.Fatal(err)
	}
	extra, err := json.Marshal(map[string]any{
		"timestamp": time.Date(2026, 10, 20, 1, 30, 0, 0, time.UTC).Format(time.RFC3339),
		"type":      "event_msg",
		"payload": map[string]any{
			"type": "token_count",
			"info": map[string]any{"total_token_usage": map[string]any{
				"input_tokens":             2040,
				"cached_input_tokens":      205,
				"cache_write_input_tokens": 20,
				"output_tokens":            925,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sessionFile, append(data, append(extra, '\n')...), 0o600); err != nil {
		t.Fatal(err)
	}
	batchesDir := filepath.Join(stateDir, "batches")
	if err := os.MkdirAll(batchesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(batchesDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(batchesDir, 0o700) })

	if _, err := Run(t.Context(), Options{StateDir: stateDir}); err == nil {
		t.Fatalf("a failed export commit must fail the run")
	}

	// The ledger must NOT have advanced to the new content.
	afterFailure, _, err := scanledger.New(stateDir).Load(adapter.CodexJSONLSource)
	if err != nil {
		t.Fatal(err)
	}
	if afterFailure[sessionFile].Digest != firstDigest {
		t.Fatalf("the ledger advanced despite a failed commit: digest %q -> %q",
			firstDigest, afterFailure[sessionFile].Digest)
	}

	// With the directory writable again the appended records export and the
	// ledger advances.
	if err := os.Chmod(batchesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	retried, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("retry run failed: %v", err)
	}
	// The failed commit left its export journal behind, so the retry first
	// replays that journal (completing the interrupted commit) and then
	// scans again. Either way the committed record set must be exactly the
	// four records of the file: nothing lost by the failure, nothing counted
	// twice by the replay.
	if total := committedRecordCount(t, stateDir, adapter.CodexJSONLSource); total != 4 {
		t.Fatalf("committed records = %d, want exactly 4 (retry exported %d)", total, retried.ExportedRecords)
	}
	final, _, err := scanledger.New(stateDir).Load(adapter.CodexJSONLSource)
	if err != nil {
		t.Fatal(err)
	}
	if final[sessionFile].Digest == firstDigest {
		t.Fatalf("the ledger must advance after the retried commit")
	}
}

// committedRecordCount sums the record counts of one source's batches in the
// outbox (pending and synced alike): the durable record set the ledger may
// claim was exported.
func committedRecordCount(t *testing.T, stateDir, source string) int {
	t.Helper()
	ledger, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, batch := range ledger.Batches {
		if batch.Source == source {
			total += batch.RecordCount
		}
	}
	return total
}
