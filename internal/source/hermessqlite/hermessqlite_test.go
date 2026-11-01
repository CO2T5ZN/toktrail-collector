package hermessqlite

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

func makeHermesDB(t *testing.T, path string, perModel bool) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE sessions (
		id TEXT PRIMARY KEY,
		model TEXT,
		started_at INTEGER,
		input_tokens INTEGER,
		output_tokens INTEGER,
		cache_read_tokens INTEGER,
		cache_write_tokens INTEGER
	)`); err != nil {
		t.Fatal(err)
	}
	if perModel {
		if _, err := db.Exec(`CREATE TABLE session_model_usage (
			session_id TEXT,
			model TEXT,
			input_tokens INTEGER,
			output_tokens INTEGER,
			cache_read_tokens INTEGER,
			cache_write_tokens INTEGER
		)`); err != nil {
			t.Fatal(err)
		}
	}
}

func insertHermesSession(t *testing.T, path, id, model string, startedAt, input, output, cacheRead, cacheWrite int64) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO sessions (id, model, started_at, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens) VALUES (?, ?, ?, ?, ?, ?, ?)`, id, model, startedAt, input, output, cacheRead, cacheWrite); err != nil {
		t.Fatal(err)
	}
}

func insertHermesModelUsage(t *testing.T, path, sessionID, model string, input, output, cacheRead, cacheWrite int64) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO session_model_usage (session_id, model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens) VALUES (?, ?, ?, ?, ?, ?)`, sessionID, model, input, output, cacheRead, cacheWrite); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRecordsPrefersSessionModelUsage(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "state.db")
	makeHermesDB(t, path, true)
	insertHermesSession(t, path, "sess-1", "summary-model", 1790000001000, 999, 999, 999, 999)
	insertHermesModelUsage(t, path, "sess-1", "nous-hermes", 100, 30, 20, 5)

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 0 || len(res.Issues) != 0 || len(res.Records) != 1 {
		t.Fatalf("unexpected result: %#v", res)
	}
	rec := res.Records[0]
	if rec["tool"] != "Hermes Agent" || rec["sourceType"] != adapter.HermesSQLiteSource || rec["model"] != "nous-hermes" {
		t.Fatalf("unexpected identity: %#v", rec)
	}
	if rec["kind"] != "cumulative" || rec["groupKey"] == nil || rec["resetKey"] != "hermes-sqlite-v1" {
		t.Fatalf("Hermes must export cumulative snapshots with stable group/reset keys: %#v", rec)
	}
	if rec["input"] != "100" || rec["cacheRead"] != "20" || rec["cacheWrite"] != "5" || rec["output"] != "30" {
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
	if strings.Contains(string(raw), "sess-1") || strings.Contains(string(raw), root) {
		t.Fatalf("record leaked private source data: %s", raw)
	}
}

func TestLoadRecordsFallsBackToSessionsTable(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "state.db")
	makeHermesDB(t, path, false)
	insertHermesSession(t, path, "sess-1", "summary-model", 1790000001000, 100, 30, 20, 5)

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 || res.Records[0]["model"] != "summary-model" {
		t.Fatalf("sessions fallback failed: %#v", res)
	}
}

func TestLoadRecordsReportsUnknownModelWhenMissing(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "state.db")
	makeHermesDB(t, path, false)
	insertHermesSession(t, path, "sess-1", "", 1790000001000, 100, 30, 20, 5)

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 || res.Records[0]["model"] != "unknown" {
		t.Fatalf("missing model should report unknown: %#v", res)
	}
}

func TestLoadRecordsSkipsZeroUsageRows(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "state.db")
	makeHermesDB(t, path, false)
	insertHermesSession(t, path, "sess-1", "summary-model", 1790000001000, 0, 0, 0, 0)

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 0 {
		t.Fatalf("zero usage rows should be ignored: %#v", res)
	}
}

func TestLoadRecordsRejectsMissingUsageTables(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "state.db")
	if err := os.MkdirAll(root, 0o755); err != nil {
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
	if err == nil || !strings.Contains(err.Error(), "sessions") {
		t.Fatalf("expected missing table error, got %v", err)
	}
}

func TestAdapterLoadHonorsCancelledContext(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "state.db")
	makeHermesDB(t, path, false)
	insertHermesSession(t, path, "sess-1", "summary-model", 1790000001000, 100, 30, 20, 5)

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
	path := filepath.Join(root, "state.db")
	makeHermesDB(t, path, false)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	insert, err := tx.Prepare(`INSERT INTO sessions (id, model, started_at, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		t.Fatal(err)
	}
	const rowCount = 20000
	for i := 0; i < rowCount; i++ {
		if _, err := insert.Exec(fmt.Sprintf("sess-%d", i), "summary-model", int64(1790000001000+i), 100, 30, 20, 5); err != nil {
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
