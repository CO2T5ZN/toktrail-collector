package usagejson

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"toktrail-collector/internal/source/adapter"
)

// LoadRecords reads one normalized usage JSON file. It keeps the historical
// uncancellable signature for direct callers; the adapter's Load passes its
// cancellation scope through loadRecordsContext.
func LoadRecords(path string) ([]adapter.Record, error) {
	return loadRecordsContext(context.Background(), path)
}

// loadRecordsContext reads with cancellation support: the context is checked
// before the input file is opened and once per extracted record. On
// cancellation it returns ctx.Err() (matchable with errors.Is(err,
// context.Canceled) or errors.Is(err, context.DeadlineExceeded)) and no
// partial result — records extracted so far are discarded, so a scan cut
// short never yields half of a fixture.
func loadRecordsContext(ctx context.Context, path string) ([]adapter.Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(b) {
		return nil, errors.New("invalid UTF-8 in JSON")
	}
	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	records, err := extractRecords(ctx, raw)
	if err != nil {
		return nil, err
	}
	// Free-form usage-json inputs may carry arbitrary keys; everything
	// outside the ingest whitelist is dropped here — before validation,
	// scan, preview, export, and outbox serialization — so sync can never
	// upload it. Already-pending outbox batch files are immutable and are
	// never rewritten by this projection.
	return adapter.SanitizeUsageJSONRecords(records), nil
}
func extractRecords(ctx context.Context, raw any) ([]adapter.Record, error) {
	switch v := raw.(type) {
	case []any:
		return extractRecordArray(ctx, v)
	case map[string]any:
		if arr, ok := v["records"].([]any); ok {
			return extractRecordArray(ctx, arr)
		}
		if rec, ok := v["record"].(map[string]any); ok {
			return []adapter.Record{adapter.Record(rec)}, nil
		}
		return []adapter.Record{adapter.Record(v)}, nil
	default:
		return nil, errors.New("input must be a record object, records array, batch object, or fixture array")
	}
}

func extractRecordArray(ctx context.Context, arr []any) ([]adapter.Record, error) {
	records := make([]adapter.Record, 0, len(arr))
	for idx, item := range arr {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		obj, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("item %d is not an object", idx)
		}
		if rec, ok := obj["record"].(map[string]any); ok {
			records = append(records, adapter.Record(rec))
			continue
		}
		records = append(records, adapter.Record(obj))
	}
	return records, nil
}

func Adapter() adapter.Adapter {
	return adapter.Adapter{Source: adapter.UsageJSONSource, Description: "Normalized usage JSON", Load: func(opt adapter.Options) (adapter.LoadResult, error) {
		records, err := loadRecordsContext(opt.ContextOrBackground(), opt.Input)
		return adapter.LoadResult{Records: records}, err
	}}
}
