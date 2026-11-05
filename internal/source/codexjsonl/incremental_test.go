package codexjsonl_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/local/scanledger"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/codexjsonl"
)

// incrementalFixtures writes one Codex session file: a turn context line
// followed by `steps` monotonic token-count observations, which the adapter
// turns into steps-1 delta records.
func incrementalFixtures(t *testing.T, dir, name string, steps int) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	base := time.Date(2026, 10, 20, 1, 0, 0, 0, time.UTC)
	var body []byte
	appendLine := func(v any) {
		payload, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		body = append(body, payload...)
		body = append(body, '\n')
	}
	appendLine(map[string]any{
		"timestamp": base.Format(time.RFC3339),
		"type":      "turn_context",
		"payload":   map[string]any{"model": "gpt-5-codex-test"},
	})
	for step := 0; step < steps; step++ {
		appendLine(map[string]any{
			"timestamp": base.Add(time.Duration(step) * time.Minute).Format(time.RFC3339),
			"type":      "event_msg",
			"payload": map[string]any{
				"type": "token_count",
				"info": map[string]any{"total_token_usage": map[string]any{
					"input_tokens":             1000 + 10*step,
					"cached_input_tokens":      100 + step,
					"cache_write_input_tokens": 10,
					"output_tokens":            500 + 5*step,
				}},
			},
		})
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func loadCodexResuming(t *testing.T, input, stateDir string) adapter.LoadResult {
	t.Helper()
	res, err := codexjsonl.Adapter().Load(adapter.Options{
		Source:   adapter.CodexJSONLSource,
		Input:    input,
		StateDir: stateDir,
	})
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	return res
}

func commitStates(t *testing.T, stateDir string, states map[string]scanledger.FileState) {
	t.Helper()
	if len(states) == 0 {
		return
	}
	if err := scanledger.New(stateDir).Save(adapter.CodexJSONLSource, states); err != nil {
		t.Fatal(err)
	}
}

// A first scan parses everything; once its states are committed (as the
// collection does after the export), an unchanged history yields no records
// at all — the run no longer JSON-decodes gigabytes of old sessions. A file
// appended to is parsed again, and only that file contributes.
func TestCodexResumesUnchangedFiles(t *testing.T) {
	input := filepath.Join(t.TempDir(), "sessions")
	stateDir := t.TempDir()
	fileA := incrementalFixtures(t, input, "a.jsonl", 4)
	incrementalFixtures(t, input, "b.jsonl", 3)

	first := loadCodexResuming(t, input, stateDir)
	if len(first.Records) != 3+2 {
		t.Fatalf("the first scan must parse both files, got %d records", len(first.Records))
	}
	if len(first.ScanStates) != 2 {
		t.Fatalf("the first scan must report both file states, got %#v", first.ScanStates)
	}
	commitStates(t, stateDir, first.ScanStates)

	second := loadCodexResuming(t, input, stateDir)
	if len(second.Records) != 0 {
		t.Fatalf("an unchanged history must yield no records, got %d", len(second.Records))
	}
	if len(second.ScanStates) != 2 {
		t.Fatalf("skipped files must still report their states, got %#v", second.ScanStates)
	}

	// Append one observation: only that file is parsed again.
	data, err := os.ReadFile(fileA)
	if err != nil {
		t.Fatal(err)
	}
	extra, err := json.Marshal(map[string]any{
		"timestamp": time.Date(2026, 10, 20, 1, 30, 0, 0, time.UTC).Format(time.RFC3339),
		"type":      "event_msg",
		"payload": map[string]any{
			"type": "token_count",
			"info": map[string]any{"total_token_usage": map[string]any{
				"input_tokens":             1040,
				"cached_input_tokens":      105,
				"cache_write_input_tokens": 10,
				"output_tokens":            520,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fileA, append(data, append(extra, '\n')...), 0o600); err != nil {
		t.Fatal(err)
	}
	third := loadCodexResuming(t, input, stateDir)
	if len(third.Records) != 4 {
		t.Fatalf("the appended file must be re-parsed in full, got %d records", len(third.Records))
	}
	// b.jsonl stayed skipped: its record keys never appear.
	for _, rec := range third.Records {
		if key := adapter.StringField(rec, "recordKey"); len(key) == 0 {
			t.Fatalf("record without a key: %#v", rec)
		}
	}
	if len(third.ScanStates) != 2 {
		t.Fatalf("both files must report states, got %#v", third.ScanStates)
	}
	if third.ScanStates[fileA].Digest == first.ScanStates[fileA].Digest {
		t.Fatalf("the appended file's digest must change")
	}
}

// A touched-but-identical file stays skipped: the modification time never
// decides a skip, only the content does.
func TestCodexSkipIgnoresModificationTime(t *testing.T) {
	input := filepath.Join(t.TempDir(), "sessions")
	stateDir := t.TempDir()
	fileA := incrementalFixtures(t, input, "a.jsonl", 3)

	first := loadCodexResuming(t, input, stateDir)
	commitStates(t, stateDir, first.ScanStates)

	later := time.Now().Add(3 * time.Hour)
	if err := os.Chtimes(fileA, later, later); err != nil {
		t.Fatal(err)
	}
	second := loadCodexResuming(t, input, stateDir)
	if len(second.Records) != 0 {
		t.Fatalf("an identical file with a new mtime must be skipped, got %d records", len(second.Records))
	}
}

// A same-size in-place rewrite is content change: it must be re-parsed, not
// skipped as unchanged.
func TestCodexSameSizeRewriteIsReparsed(t *testing.T) {
	input := filepath.Join(t.TempDir(), "sessions")
	stateDir := t.TempDir()
	fileA := incrementalFixtures(t, input, "a.jsonl", 3)

	first := loadCodexResuming(t, input, stateDir)
	commitStates(t, stateDir, first.ScanStates)
	before, err := os.Stat(fileA)
	if err != nil {
		t.Fatal(err)
	}

	// Rewrite in place with an identical byte length: the model name is
	// swapped for a same-length one, so only the content differs.
	data, err := os.ReadFile(fileA)
	if err != nil {
		t.Fatal(err)
	}
	rewritten := []byte(strings.ReplaceAll(string(data), "gpt-5-codex-test", "gpt-5-codex-tesu"))
	if bytesEqual(rewritten, data) {
		t.Fatal("the fixture must actually change")
	}
	if err := os.WriteFile(fileA, rewritten, 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(fileA)
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() != before.Size() {
		t.Fatalf("the fixture must keep the size (before %d, after %d)", before.Size(), after.Size())
	}

	second := loadCodexResuming(t, input, stateDir)
	if len(second.Records) == 0 {
		t.Fatalf("a same-size rewrite must be parsed again, got no records")
	}
	if second.ScanStates[fileA].Digest == first.ScanStates[fileA].Digest {
		t.Fatalf("the digest must change after a rewrite")
	}
}

// bytesEqual is a tiny helper so the fixture assertion reads clearly.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
