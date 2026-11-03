package piwire

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toktrail-collector/internal/source/adapter"
)

func writePiJSONL(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRecordsParsesPiAssistantMessageUsage(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "--Users-demo-repo--", "2026-03-07T10-58-20-235Z_225c45fc-1111-4752-97dc-be57fd9a0001.jsonl")
	writePiJSONL(t, path,
		`{"type":"session","version":3,"id":"225c45fc-1111-4752-97dc-be57fd9a0001","timestamp":"2026-10-20T01:00:00Z","cwd":"/Users/demo/repo"}`,
		`{"type":"message","id":"e5f6a7b8","parentId":null,"timestamp":"2026-10-20T01:00:00Z","message":{"role":"user","content":[{"type":"text","text":"hi"}]}}`,
		`{"type":"message","id":"a1b2c3d4","parentId":"e5f6a7b8","timestamp":"2026-10-20T01:00:01Z","message":{"role":"assistant","model":"anthropic/claude-sonnet-4-6","timestamp":1790000001000,"usage":{"input":100,"output":30,"cacheRead":20,"cacheWrite":5,"totalTokens":155},"stopReason":"stop"}}`,
	)

	res, err := LoadRecords(root, PiConfig)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 0 || len(res.Issues) != 0 || len(res.Records) != 1 {
		t.Fatalf("unexpected result: %#v", res)
	}
	rec := res.Records[0]
	if rec["tool"] != "Pi" || rec["sourceType"] != adapter.PiJSONLSource || rec["model"] != "anthropic/claude-sonnet-4-6" {
		t.Fatalf("unexpected identity: %#v", rec)
	}
	// Pi follows the OpenAI convention: the four buckets are disjoint, so the
	// counters are uploaded verbatim without subtracting cache from input.
	if rec["input"] != "100" || rec["cacheRead"] != "20" || rec["cacheWrite"] != "5" || rec["output"] != "30" {
		t.Fatalf("unexpected usage: %#v", rec)
	}
	if rec["occurredAt"] != "2026-10-20T01:00:01Z" {
		t.Fatalf("unexpected occurredAt: %#v", rec)
	}
	if rec["kind"] != "delta" {
		t.Fatalf("per-request usage must be a delta: %#v", rec)
	}
	if !adapter.RecordIsUploadSafe(rec) {
		t.Fatalf("record is not upload safe: %#v", rec)
	}
	if err := adapter.ValidateRecord(rec); err != nil {
		t.Fatalf("record violates contract: %v", err)
	}
	raw, _ := json.Marshal(rec)
	if strings.Contains(string(raw), "/Users/demo") || strings.Contains(string(raw), "a1b2c3d4") || strings.Contains(string(raw), "225c45fc") || strings.Contains(string(raw), root) {
		t.Fatalf("record leaked private source data: %s", raw)
	}
}

func TestLoadRecordsParsesOMPModelUsageEntry(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "-demo-repo", "2026-10-20T01-00-00-000Z_0199aaaa-2222-7000-8000-000000000002.jsonl")
	writePiJSONL(t, path,
		`{"type":"session","version":3,"id":"0199aaaa-2222-7000-8000-000000000002","timestamp":"2026-10-20T01:00:00Z","cwd":"/Users/demo/repo","title":"A titled session"}`,
		`{"type":"title","id":"t0t0t0t0","parentId":null,"timestamp":"2026-10-20T01:00:00Z"}`,
		`{"type":"model_usage","id":"c1d2e3f4","parentId":null,"timestamp":"2026-10-20T01:00:05Z","model":"openai/gpt-5.6","usage":{"input":50,"output":10,"cacheRead":0,"cacheWrite":0,"reasoningTokens":3}}`,
	)

	res, err := LoadRecords(root, OMPConfig)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 0 || len(res.Issues) != 0 || len(res.Records) != 1 {
		t.Fatalf("unexpected result: %#v", res)
	}
	rec := res.Records[0]
	if rec["tool"] != "Oh My Pi" || rec["sourceType"] != adapter.OMPJSONLSource || rec["model"] != "openai/gpt-5.6" {
		t.Fatalf("unexpected identity: %#v", rec)
	}
	if rec["input"] != "50" || rec["cacheRead"] != "0" || rec["cacheWrite"] != "0" || rec["output"] != "10" {
		t.Fatalf("unexpected usage: %#v", rec)
	}
}

func TestLoadRecordsFallsBackToModelChangeForUsageEntries(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "--repo--", "2026-03-07T10-58-20-235Z_abc-def-0123.jsonl")
	writePiJSONL(t, path,
		`{"type":"session","version":3,"id":"abc-def-0123","timestamp":"2026-10-20T01:00:00Z"}`,
		`{"type":"model_change","id":"d1e2f3a4","parentId":null,"timestamp":"2026-10-20T01:00:00Z","provider":"anthropic","modelId":"claude-sonnet-4-6"}`,
		`{"type":"usage","id":"b2c3d4e5","parentId":null,"timestamp":"2026-10-20T01:00:02Z","usage":{"input":10,"output":4,"cacheRead":0,"cacheWrite":0}}`,
	)

	res, err := LoadRecords(root, PiConfig)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 0 || len(res.Issues) != 0 || len(res.Records) != 1 {
		t.Fatalf("unexpected result: %#v", res)
	}
	rec := res.Records[0]
	if rec["model"] != "claude-sonnet-4-6" {
		t.Fatalf("usage entry should inherit the model_change model: %#v", rec)
	}
}

func TestLoadRecordsDeduplicatesForkedEntriesBySessionAndEntryID(t *testing.T) {
	root := t.TempDir()
	entry := `{"type":"message","id":"a1b2c3d4","parentId":"e5f6a7b8","timestamp":"2026-10-20T01:00:01Z","message":{"role":"assistant","model":"claude-sonnet-4-6","usage":{"input":100,"output":30,"cacheRead":20,"cacheWrite":5}}}`
	writePiJSONL(t, filepath.Join(root, "--repo--", "t_aaa.jsonl"),
		`{"type":"session","version":3,"id":"sess-aaa","timestamp":"2026-10-20T01:00:00Z"}`,
		entry,
	)
	// A fork copies the entry under a different session id: both carry real
	// API usage, so both are kept. Two copies of the SAME session and entry id
	// (a re-read of one file copied elsewhere) collapse to one record.
	writePiJSONL(t, filepath.Join(root, "--repo--", "t_aaa-copy.jsonl"),
		`{"type":"session","version":3,"id":"sess-aaa","timestamp":"2026-10-20T01:00:00Z"}`,
		entry,
	)

	res, err := LoadRecords(root, PiConfig)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 0 || len(res.Issues) != 0 || len(res.Records) != 1 {
		t.Fatalf("identical session+entry duplicated across files should be counted once: %#v", res)
	}
}

func TestLoadRecordsReportsUnknownModelWithoutQuarantine(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "--repo--", "t_bbb.jsonl")
	writePiJSONL(t, path,
		`{"type":"session","version":3,"id":"sess-bbb","timestamp":"2026-10-20T01:00:00Z"}`,
		`{"type":"message","id":"a1b2c3d4","parentId":null,"timestamp":"2026-10-20T01:00:01Z","message":{"role":"assistant","usage":{"input":100,"output":30,"cacheRead":20,"cacheWrite":5}}}`,
	)

	res, err := LoadRecords(root, PiConfig)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 0 || len(res.Issues) != 1 || len(res.Records) != 1 {
		t.Fatalf("missing model should diagnose without quarantine: %#v", res)
	}
	if got := res.Records[0]["model"]; got != "unknown" {
		t.Fatalf("missing model must report unknown, got %#v", got)
	}
}

func TestLoadRecordsSkipsUnknownEntryTypesAndZeroUsage(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "--repo--", "t_ccc.jsonl")
	writePiJSONL(t, path,
		`{"type":"session","version":3,"id":"sess-ccc","timestamp":"2026-10-20T01:00:00Z"}`,
		`{"type":"thinking_level_change","id":"11111111","parentId":null,"timestamp":"2026-10-20T01:00:00Z","level":"high"}`,
		`{"type":"label","id":"22222222","parentId":null,"timestamp":"2026-10-20T01:00:00Z","label":"demo"}`,
		`{"type":"future_unknown_entry","id":"33333333","parentId":null,"timestamp":"2026-10-20T01:00:00Z","payload":{"anything":true}}`,
		`{"type":"message","id":"44444444","parentId":null,"timestamp":"2026-10-20T01:00:01Z","message":{"role":"assistant","model":"m","usage":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0}}}`,
	)

	res, err := LoadRecords(root, PiConfig)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 0 || len(res.Issues) != 0 || len(res.Records) != 0 {
		t.Fatalf("unknown entry types and zero usage should be ignored: %#v", res)
	}
}

func TestLoadRecordsQuarantinesMalformedUsage(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "--repo--", "t_ddd.jsonl")
	writePiJSONL(t, path,
		`{"type":"session","version":3,"id":"sess-ddd","timestamp":"2026-10-20T01:00:00Z"}`,
		`{"type":"message","id":"a1b2c3d4","parentId":null,"timestamp":"2026-10-20T01:00:01Z","message":{"role":"assistant","model":"m","usage":{"input":-1,"output":30}}}`,
	)

	res, err := LoadRecords(root, PiConfig)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 0 || res.Quarantined != 1 || len(res.Issues) != 1 {
		t.Fatalf("malformed usage should be quarantined: %#v", res)
	}
}
