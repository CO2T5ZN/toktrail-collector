package usagejson_test

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"testing"
	"time"

	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/usagejson"
)

// cancelAfterContext is a synthetic cancellation scope for deterministic
// cancellation tests: it reports context.Canceled from the cancelAfter-th
// Err call onward, so a test can cancel at any chosen point of a load
// without sleeping or racing a real timer. It also counts every Err call,
// which lets a test measure how many cancellation checks one complete load
// performs and then cancel exactly halfway through the next one.
type cancelAfterContext struct {
	context.Context
	cancelAfter int
	calls       int
	cancelled   bool
}

func (c *cancelAfterContext) Err() error {
	c.calls++
	if c.calls >= c.cancelAfter {
		c.cancelled = true
	}
	if c.cancelled {
		return context.Canceled
	}
	return nil
}

// usageCancellationInput writes a synthetic normalized-usage fixture array
// with eight records, so a cancelled load has real records to wrongly return
// if it ever leaked a partial result and enough per-record checks to cancel
// strictly between two of them.
func usageCancellationInput(t *testing.T) string {
	t.Helper()
	records := make([]map[string]any, 0, 8)
	for i := 0; i < 8; i++ {
		records = append(records, map[string]any{
			"recordKey":      fmt.Sprintf("fixture-%d", i),
			"groupKey":       nil,
			"resetKey":       nil,
			"kind":           "delta",
			"occurredAt":     fmt.Sprintf("2026-10-20T01:%02d:00Z", i),
			"tool":           "codex",
			"model":          nil,
			"input":          "10",
			"cacheRead":      "0",
			"cacheWrite":     "0",
			"output":         "5",
			"adapterVersion": "fixture-v1",
			"sourceType":     "fixture",
		})
	}
	return writeJSONFile(t, records)
}

func loadUsageWith(ctx context.Context, input string) (adapter.LoadResult, error) {
	return usagejson.Adapter().Load(adapter.Options{Source: adapter.UsageJSONSource, Input: input, Context: ctx})
}

func assertUsageContextCanceled(t *testing.T, err error) {
	t.Helper()
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled load must surface context.Canceled, got err=%v", err)
	}
}

func assertUsageNoPartialResult(t *testing.T, res adapter.LoadResult) {
	t.Helper()
	if len(res.Records) != 0 || len(res.Issues) != 0 || res.Quarantined != 0 || len(res.MessageUpdates) != 0 {
		t.Fatalf("cancelled load must not return a partial result: %#v", res)
	}
}

func TestUsageJSONLoadPreCancelledReturnsContextError(t *testing.T) {
	input := usageCancellationInput(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := loadUsageWith(ctx, input)
	assertUsageContextCanceled(t, err)
	assertUsageNoPartialResult(t, res)
}

func TestUsageJSONLoadExpiredDeadlineSurfacesDeadlineExceeded(t *testing.T) {
	input := usageCancellationInput(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Minute))
	defer cancel()

	res, err := loadUsageWith(ctx, input)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired deadline must surface context.DeadlineExceeded, got err=%v", err)
	}
	assertUsageNoPartialResult(t, res)
}

func TestUsageJSONLoadMidScanCancellationDiscardsPartialResult(t *testing.T) {
	input := usageCancellationInput(t)

	// One complete load with a never-cancelling counting scope measures how
	// many cancellation checks the loader performs end to end (one before
	// the file is read plus one per extracted record).
	probe := &cancelAfterContext{Context: context.Background(), cancelAfter: math.MaxInt}
	baseline, err := loadUsageWith(probe, input)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.Records) != 8 {
		t.Fatalf("synthetic baseline must hold eight records, got %d", len(baseline.Records))
	}
	total := probe.calls
	if total < 8 {
		t.Fatalf("synthetic load is too small to exercise mid-load cancellation: %d checks", total)
	}

	// Cancelling at any check the load performs must surface the context
	// error and discard every record extracted so far; a scope that flips
	// only after the last check (or never) must still return the complete
	// result, never a prefix of it.
	for k := 1; k <= 2*total; k++ {
		res, err := loadUsageWith(&cancelAfterContext{Context: context.Background(), cancelAfter: k}, input)
		switch {
		case err == nil:
			if !reflect.DeepEqual(res.Records, baseline.Records) {
				t.Fatalf("uncancelled load (k=%d) must equal the baseline result:\n%#v\n%#v", k, res.Records, baseline.Records)
			}
		default:
			assertUsageContextCanceled(t, err)
			assertUsageNoPartialResult(t, res)
		}
	}

	// The halfway check lands after extraction has started, proving a
	// cancellation arriving between two records never leaks a half-built
	// result.
	mid := &cancelAfterContext{Context: context.Background(), cancelAfter: total / 2}
	res, err := loadUsageWith(mid, input)
	assertUsageContextCanceled(t, err)
	assertUsageNoPartialResult(t, res)
}

func TestUsageJSONAdapterNilContextKeepsLegacyScan(t *testing.T) {
	input := usageCancellationInput(t)

	// The historical entry point keeps its exact signature and behavior:
	// the same records the adapter path loads, uncancellable.
	legacyRecords, err := usagejson.LoadRecords(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(legacyRecords) != 8 {
		t.Fatalf("legacy load must keep returning every record, got %d", len(legacyRecords))
	}

	// A nil Options.Context must reproduce the historical uncancellable
	// load exactly (ContextOrBackground falls back to context.Background).
	res, err := loadUsageWith(nil, input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Records, legacyRecords) {
		t.Fatalf("nil Options.Context must reproduce the legacy records:\n%#v\n%#v", res.Records, legacyRecords)
	}
}
