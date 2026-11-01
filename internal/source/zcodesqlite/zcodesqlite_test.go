package zcodesqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"toktrail-collector/internal/source/adapter"
)

func makeZcodeDB(t *testing.T, path string) { makeZcodeDBWithStatus(t, path, false) }

func makeZcodeDBWithStatus(t *testing.T, path string, withStatus bool) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	statusCol := ""
	if withStatus {
		statusCol = ", status TEXT"
	}
	_, err = db.Exec(`CREATE TABLE model_usage (
		id TEXT PRIMARY KEY,
		model_id TEXT,
		started_at INTEGER,
		input_tokens INTEGER,
		output_tokens INTEGER,
		cache_creation_input_tokens INTEGER,
		cache_read_input_tokens INTEGER` + statusCol + `
	)`)
	if err != nil {
		t.Fatal(err)
	}
}

func insertZcodeUsage(t *testing.T, path, id, model string, startedAt, input, output, cacheWrite, cacheRead int64) {
	insertZcodeUsageWithStatus(t, path, id, model, startedAt, input, output, cacheWrite, cacheRead, "")
}

func insertZcodeUsageWithStatus(t *testing.T, path, id, model string, startedAt, input, output, cacheWrite, cacheRead int64, status string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var hasStatus bool
	if err := db.QueryRow(`SELECT COUNT(*) > 0 FROM pragma_table_info('model_usage') WHERE name='status'`).Scan(&hasStatus); err != nil {
		t.Fatal(err)
	}
	if hasStatus {
		_, err = db.Exec(`INSERT INTO model_usage (id, model_id, started_at, input_tokens, output_tokens, cache_creation_input_tokens, cache_read_input_tokens, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, id, model, startedAt, input, output, cacheWrite, cacheRead, status)
	} else {
		_, err = db.Exec(`INSERT INTO model_usage (id, model_id, started_at, input_tokens, output_tokens, cache_creation_input_tokens, cache_read_input_tokens) VALUES (?, ?, ?, ?, ?, ?, ?)`, id, model, startedAt, input, output, cacheWrite, cacheRead)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestLoadRecordsParsesZCodeModelUsage(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "db.sqlite")
	makeZcodeDB(t, path)
	insertZcodeUsage(t, path, "row-1", "glm-5.2", 1790000001000, 100, 30, 5, 20)

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 0 || len(res.Issues) != 0 || len(res.Records) != 1 {
		t.Fatalf("unexpected result: %#v", res)
	}
	rec := res.Records[0]
	if rec["tool"] != "ZCode" || rec["sourceType"] != adapter.ZCodeSQLiteSource || rec["model"] != "glm-5.2" {
		t.Fatalf("unexpected identity: %#v", rec)
	}
	// ZCode input_tokens includes cache read/write, so TokTrail uploads net input.
	if rec["input"] != "75" || rec["cacheRead"] != "20" || rec["cacheWrite"] != "5" || rec["output"] != "30" {
		t.Fatalf("unexpected usage: %#v", rec)
	}
	if rec["occurredAt"] != "2026-09-21T14:13:21Z" {
		t.Fatalf("unexpected occurredAt: %#v", rec)
	}
	if !adapter.RecordIsUploadSafe(rec) {
		t.Fatalf("record is not upload safe: %#v", rec)
	}
	if err := adapter.ValidateRecord(rec); err != nil {
		t.Fatalf("record violates contract: %v", err)
	}
	raw, _ := json.Marshal(rec)
	if strings.Contains(string(raw), "row-1") || strings.Contains(string(raw), root) {
		t.Fatalf("record leaked private source data: %s", raw)
	}
}

func TestLoadRecordsReadsEverySqliteFileInDirectory(t *testing.T) {
	root := t.TempDir()
	pathA := filepath.Join(root, "db.sqlite")
	pathB := filepath.Join(root, "archive.sqlite")
	makeZcodeDB(t, pathA)
	makeZcodeDB(t, pathB)
	insertZcodeUsage(t, pathA, "row-a", "glm-5.2", 1790000001000, 100, 30, 5, 20)
	insertZcodeUsage(t, pathB, "row-b", "glm-5.2", 1790000002000, 200, 40, 10, 30)

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 2 {
		t.Fatalf("got %d records, want 2: %#v", len(res.Records), res.Records)
	}
}

func TestLoadRecordsFiltersIncompleteStatusWhenColumnExists(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "db.sqlite")
	makeZcodeDBWithStatus(t, path, true)
	insertZcodeUsageWithStatus(t, path, "row-running", "glm-5.2", 1790000000000, 100, 30, 5, 20, "running")
	insertZcodeUsageWithStatus(t, path, "row-error", "glm-5.2", 1790000000500, 100, 30, 5, 20, "error")
	insertZcodeUsageWithStatus(t, path, "row-completed", "glm-5.2", 1790000001000, 100, 30, 5, 20, "completed")

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 || res.Records[0]["recordKey"] == "" {
		t.Fatalf("only completed row should be counted: %#v", res)
	}
}

func TestLoadRecordsFallsBackToCacheWhenInputTokensZero(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "db.sqlite")
	makeZcodeDB(t, path)
	insertZcodeUsage(t, path, "row-1", "glm-5.2", 1790000001000, 0, 30, 5, 20)

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 {
		t.Fatalf("unexpected result: %#v", res)
	}
	rec := res.Records[0]
	if rec["input"] != "0" || rec["cacheRead"] != "20" || rec["cacheWrite"] != "5" || rec["output"] != "30" {
		t.Fatalf("unexpected fallback usage: %#v", rec)
	}
}

func TestLoadRecordsReportsUnknownModelWhenMissing(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "db.sqlite")
	makeZcodeDB(t, path)
	insertZcodeUsage(t, path, "row-1", "", 1790000001000, 100, 30, 5, 20)

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 || res.Records[0]["model"] != "unknown" {
		t.Fatalf("missing model should report unknown: %#v", res)
	}
}

func TestLoadRecordsRejectsCacheGreaterThanInput(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "db.sqlite")
	makeZcodeDB(t, path)
	insertZcodeUsage(t, path, "row-1", "glm-5.2", 1790000001000, 10, 30, 5, 20)

	_, err := LoadRecords(root)
	if err == nil || !strings.Contains(err.Error(), "cache tokens exceeding") {
		t.Fatalf("expected cache overflow error, got %v", err)
	}
}

func TestLoadRecordsRejectsMissingModelUsageTable(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "db.sqlite")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE other (id TEXT)`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()

	_, err = LoadRecords(root)
	if err == nil || !strings.Contains(err.Error(), "model_usage") {
		t.Fatalf("expected missing model_usage error, got %v", err)
	}
}

func TestAdapterLoadWithoutContextKeepsLegacyBehavior(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "db.sqlite")
	makeZcodeDB(t, path)
	insertZcodeUsage(t, path, "row-1", "glm-5.2", 1790000001000, 100, 30, 5, 20)

	res, err := Adapter().Load(adapter.Options{Input: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 || res.Records[0]["model"] != "glm-5.2" {
		t.Fatalf("nil Context must keep the uncancellable background scan: %#v", res)
	}
}

func TestAdapterLoadHonorsCancelledContext(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "db.sqlite")
	makeZcodeDB(t, path)
	insertZcodeUsage(t, path, "row-1", "glm-5.2", 1790000001000, 100, 30, 5, 20)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := Adapter().Load(adapter.Options{Input: root, Context: ctx})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if len(res.Records) != 0 || res.Quarantined != 0 || len(res.Issues) != 0 {
		t.Fatalf("cancelled load must fail without partial data: %#v", res)
	}
}

func TestAdapterLoadDeadlineMidScanFailsWithoutPartialData(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "db.sqlite")
	makeZcodeDB(t, path)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	insert, err := tx.Prepare(`INSERT INTO model_usage (id, model_id, started_at, input_tokens, output_tokens, cache_creation_input_tokens, cache_read_input_tokens) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		t.Fatal(err)
	}
	const rowCount = 20000
	for i := 0; i < rowCount; i++ {
		if _, err := insert.Exec(fmt.Sprintf("row-%d", i), "glm-5.2", int64(1790000001000+i), 100, 30, 5, 20); err != nil {
			t.Fatal(err)
		}
	}
	insert.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// The deadline lands mid-scan: the 20k-row query and row loop take far
	// longer than 5ms, so cancellation must abort the load (whichever check
	// fires first) and never return the rows scanned so far.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	res, err := Adapter().Load(adapter.Options{Input: root, Context: ctx})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
	if len(res.Records) != 0 || res.Quarantined != 0 || len(res.Issues) != 0 {
		t.Fatalf("deadline-exceeded load must fail without partial data: %#v", res)
	}
}
