package openclawsqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"toktrail-collector/internal/source/adapter"
)

func makeOpenClawDB(t *testing.T, path string, compressed bool) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	extra := ""
	if compressed {
		extra = ", event_zstd BLOB, event_utf8_bytes INTEGER, navigation_json TEXT"
	}
	_, err = db.Exec(`CREATE TABLE transcript_events (
		session_id TEXT,
		seq INTEGER,
		event_json TEXT,
		created_at INTEGER` + extra + `
	)`)
	if err != nil {
		t.Fatal(err)
	}
}

func insertOpenClawEvent(t *testing.T, path, session string, seq int, createdAt int64, event string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`INSERT INTO transcript_events (session_id, seq, event_json, created_at) VALUES (?, ?, ?, ?)`, session, seq, event, createdAt)
	if err != nil {
		t.Fatal(err)
	}
}

func insertOpenClawCompressed(t *testing.T, path, session string, seq int, createdAt int64) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`INSERT INTO transcript_events (session_id, seq, event_json, created_at, event_zstd, event_utf8_bytes, navigation_json) VALUES (?, ?, NULL, ?, ?, ?, '{}')`, session, seq, createdAt, []byte{0x28, 0xb5, 0x2f, 0xfd}, 10)
	if err != nil {
		t.Fatal(err)
	}
}

func TestLoadRecordsParsesOpenClawUsageEvent(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "agents", "main", "agent", "openclaw-agent.sqlite")
	makeOpenClawDB(t, path, false)
	insertOpenClawEvent(t, path, "sess-1", 1, 1790000001000, `{"type":"message","id":"entry-1","timestamp":"2026-10-20T01:00:00Z","message":{"role":"assistant","model":"zhipu/glm-5.3-request","responseModel":"zhipu/glm-5.3-flash","timestamp":1790000000000,"usage":{"input":100,"output":30,"cacheRead":20,"cacheWrite":5,"totalTokens":155}}}`)

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 0 || len(res.Issues) != 0 || len(res.Records) != 1 {
		t.Fatalf("unexpected result: %#v", res)
	}
	rec := res.Records[0]
	if rec["tool"] != "OpenClaw" || rec["sourceType"] != adapter.OpenClawSQLiteSource || rec["model"] != "zhipu/glm-5.3-flash" {
		t.Fatalf("unexpected identity: %#v", rec)
	}
	if rec["input"] != "100" || rec["cacheRead"] != "20" || rec["cacheWrite"] != "5" || rec["output"] != "30" {
		t.Fatalf("unexpected usage: %#v", rec)
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

func TestLoadRecordsParsesNestedUsageAndFallbackTimestamp(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "openclaw-agent.sqlite")
	makeOpenClawDB(t, path, false)
	insertOpenClawEvent(t, path, "sess-1", 1, 1790000001000, `{"message":{"role":"assistant","model":"glm-5.3-request","responseModel":"glm-5.3","timestamp":1790000001000,"usage":{"input":100,"output":30,"cacheRead":20,"cacheWrite":5}}}`)

	res, err := LoadRecords(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 {
		t.Fatalf("unexpected result: %#v", res)
	}
	if res.Records[0]["occurredAt"] != "2026-09-21T14:13:21Z" || res.Records[0]["model"] != "glm-5.3" {
		t.Fatalf("fallback parse failed: %#v", res.Records[0])
	}
}

func TestLoadRecordsReportsCompressedRows(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "openclaw-agent.sqlite")
	makeOpenClawDB(t, path, true)
	insertOpenClawEvent(t, path, "sess-1", 1, 1790000001000, `{"timestamp":"2026-10-20T01:00:00Z","message":{"role":"assistant","model":"glm","usage":{"input":100,"output":30}}}`)
	insertOpenClawCompressed(t, path, "sess-1", 2, 1790000002000)

	res, err := LoadRecords(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 || res.Quarantined != 1 || len(res.Issues) != 1 || !strings.Contains(res.Issues[0].Reason, "compressed") {
		t.Fatalf("compressed rows should be reported while plain rows are read: %#v", res)
	}
}

func TestLoadRecordsRejectsMalformedUsage(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "openclaw-agent.sqlite")
	makeOpenClawDB(t, path, false)
	insertOpenClawEvent(t, path, "sess-1", 1, 1790000001000, `{"timestamp":"2026-10-20T01:00:00Z","message":{"role":"assistant","model":"glm","usage":{"input":-1,"output":30}}}`)

	_, err := LoadRecords(path)
	if err == nil || !strings.Contains(err.Error(), "invalid input") {
		t.Fatalf("expected invalid input error, got %v", err)
	}
}

func TestLoadRecordsRejectsMissingTranscriptEvents(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "openclaw-agent.sqlite")
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

	_, err = LoadRecords(path)
	if err == nil || !strings.Contains(err.Error(), "transcript_events") {
		t.Fatalf("expected missing transcript_events error, got %v", err)
	}
}

func TestAdapterLoadWithoutContextKeepsLegacyBehavior(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "openclaw-agent.sqlite")
	makeOpenClawDB(t, path, false)
	insertOpenClawEvent(t, path, "sess-1", 1, 1790000001000, `{"timestamp":"2026-10-20T01:00:00Z","message":{"role":"assistant","model":"glm","usage":{"input":100,"output":30,"cacheRead":20,"cacheWrite":5}}}`)

	res, err := Adapter().Load(adapter.Options{Input: path})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 || res.Records[0]["model"] != "glm" {
		t.Fatalf("nil Context must keep the uncancellable background scan: %#v", res)
	}
}

func TestAdapterLoadHonorsCancelledContext(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "openclaw-agent.sqlite")
	makeOpenClawDB(t, path, false)
	insertOpenClawEvent(t, path, "sess-1", 1, 1790000001000, `{"timestamp":"2026-10-20T01:00:00Z","message":{"role":"assistant","model":"glm","usage":{"input":100,"output":30,"cacheRead":20,"cacheWrite":5}}}`)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := Adapter().Load(adapter.Options{Input: path, Context: ctx})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if len(res.Records) != 0 || res.Quarantined != 0 || len(res.Issues) != 0 {
		t.Fatalf("cancelled load must fail without partial data: %#v", res)
	}
}

func TestAdapterLoadDeadlineMidScanFailsWithoutPartialData(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "openclaw-agent.sqlite")
	makeOpenClawDB(t, path, false)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	insert, err := tx.Prepare(`INSERT INTO transcript_events (session_id, seq, event_json, created_at) VALUES (?, ?, ?, ?)`)
	if err != nil {
		t.Fatal(err)
	}
	event := `{"timestamp":"2026-10-20T01:00:00Z","message":{"role":"assistant","model":"glm","usage":{"input":100,"output":30,"cacheRead":20,"cacheWrite":5}}}`
	const rowCount = 20000
	for i := 0; i < rowCount; i++ {
		if _, err := insert.Exec("sess-1", i+1, event, int64(1790000001000+i)); err != nil {
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
	res, err := Adapter().Load(adapter.Options{Input: path, Context: ctx})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
	if len(res.Records) != 0 || res.Quarantined != 0 || len(res.Issues) != 0 {
		t.Fatalf("deadline-exceeded load must fail without partial data: %#v", res)
	}
}
