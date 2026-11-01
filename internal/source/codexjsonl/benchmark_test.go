package codexjsonl_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/pipeline"
)

// BenchmarkCodexJSONLPipelineScan is the P0 baseline for the real Collector
// source-scan path: pipeline.Scan dispatches through the production registry
// into the codex-jsonl adapter, which walks, decodes, and converts JSONL
// session files into delta records. It is a file-scan-only baseline — no
// export, no outbox batches, no state directory, no network — and it depends
// on nothing outside testing.B.TempDir.
//
// The corpus is fully deterministic (no RNG): benchCodexFiles session files,
// each one turn_context line followed by benchCodexObservations token_count
// lines with monotonically increasing cumulative counters, so every file
// yields exactly benchCodexObservations-1 delta records with fixed
// per-interval deltas. The benchmark verifies the record count, validity,
// aggregate token totals, and tool distribution on every iteration so a
// regression that drops or duplicates records fails loudly instead of
// silently measuring the wrong corpus.
const (
	benchCodexFiles           = 25
	benchCodexObservations    = 401
	benchCodexModel           = "gpt-5-codex-bench"
	benchCodexInputDelta      = 37
	benchCodexCacheReadDelta  = 3
	benchCodexCacheWriteDelta = 1
	benchCodexOutputDelta     = 11
	benchCodexBaseInput       = 1000
	benchCodexBaseCacheRead   = 100
	benchCodexBaseCacheWrite  = 10
	benchCodexBaseOutput      = 500
)

func benchCodexLine(v any) []byte {
	payload, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return append(payload, '\n')
}

func benchCodexTurnContext(ts time.Time) []byte {
	return benchCodexLine(map[string]any{
		"timestamp": ts.Format(time.RFC3339),
		"type":      "turn_context",
		"payload":   map[string]any{"model": benchCodexModel},
	})
}

func benchCodexTokenCount(ts time.Time, step int) []byte {
	return benchCodexLine(map[string]any{
		"timestamp": ts.Format(time.RFC3339),
		"type":      "event_msg",
		"payload": map[string]any{
			"type": "token_count",
			"info": map[string]any{"total_token_usage": map[string]any{
				"input_tokens":             benchCodexBaseInput + benchCodexInputDelta*step,
				"cached_input_tokens":      benchCodexBaseCacheRead + benchCodexCacheReadDelta*step,
				"cache_write_input_tokens": benchCodexBaseCacheWrite + benchCodexCacheWriteDelta*step,
				"output_tokens":            benchCodexBaseOutput + benchCodexOutputDelta*step,
			}},
		},
	})
}

func BenchmarkCodexJSONLPipelineScan(b *testing.B) {
	input := filepath.Join(b.TempDir(), "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		b.Fatal(err)
	}
	base := time.Date(2026, 10, 20, 1, 0, 0, 0, time.UTC)
	var totalBytes, totalLines int
	for file := 0; file < benchCodexFiles; file++ {
		body := benchCodexTurnContext(base)
		for obs := 0; obs < benchCodexObservations; obs++ {
			body = append(body, benchCodexTokenCount(base.Add(time.Duration(obs+1)*time.Second), obs)...)
		}
		path := filepath.Join(input, fmt.Sprintf("rollout-bench-%02d.jsonl", file))
		if err := os.WriteFile(path, body, 0o600); err != nil {
			b.Fatal(err)
		}
		totalBytes += len(body)
		totalLines += 1 + benchCodexObservations
	}

	wantRecords := benchCodexFiles * (benchCodexObservations - 1)
	// The adapter records input net of cached tokens, so one interval
	// yields input 33, cacheRead 3, cacheWrite 1, output 11: include 48
	// per record, exclude 44 per record.
	netInputDelta := benchCodexInputDelta - benchCodexCacheReadDelta - benchCodexCacheWriteDelta
	wantInclude := uint64(wantRecords) * uint64(netInputDelta+benchCodexCacheReadDelta+benchCodexCacheWriteDelta+benchCodexOutputDelta)
	wantExclude := uint64(wantRecords) * uint64(netInputDelta+benchCodexOutputDelta)

	b.SetBytes(int64(totalBytes))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: input})
		if err != nil {
			b.Fatal(err)
		}
		if res.RecordCount != wantRecords || res.ValidRecords != wantRecords || res.InvalidRecords != 0 || res.Quarantined != 0 {
			b.Fatalf("scan counts: record=%d valid=%d invalid=%d quarantined=%d, want record=valid=%d invalid=0 quarantined=0", res.RecordCount, res.ValidRecords, res.InvalidRecords, res.Quarantined, wantRecords)
		}
		if res.KnownIncludeRecords != wantRecords || res.TokensInclude == nil || *res.TokensInclude != wantInclude {
			got := uint64(0)
			if res.TokensInclude != nil {
				got = *res.TokensInclude
			}
			b.Fatalf("include tokens: %d over %d records, want %d over %d", got, res.KnownIncludeRecords, wantInclude, wantRecords)
		}
		if res.KnownExcludeRecords != wantRecords || res.TokensExclude == nil || *res.TokensExclude != wantExclude {
			got := uint64(0)
			if res.TokensExclude != nil {
				got = *res.TokensExclude
			}
			b.Fatalf("exclude tokens: %d over %d records, want %d over %d", got, res.KnownExcludeRecords, wantExclude, wantRecords)
		}
		if res.Tools["Codex"] != wantRecords || len(res.Issues) != 0 {
			b.Fatalf("tool distribution: Codex=%d issues=%d, want Codex=%d issues=0", res.Tools["Codex"], len(res.Issues), wantRecords)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(wantRecords), "records/op")
	b.ReportMetric(float64(totalLines), "lines/op")
	b.ReportMetric(float64(totalBytes), "bytes/op")
}
