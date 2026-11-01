package qwenjsonl

import (
	"context"
	"errors"
	"math"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"toktrail-collector/internal/source/adapter"
)

// cancelAfterContext is a synthetic cancellation scope for deterministic
// cancellation tests: it reports context.Canceled from the cancelAfter-th
// Err call onward, so a test can cancel at any chosen point of a scan
// without sleeping or racing a real timer. It also counts every Err call,
// which lets a test measure how many cancellation checks one complete scan
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

// qwenCancellationRoot writes a synthetic Qwen input with two session files
// across two directories. Each file mixes valid api_response telemetry with
// an invalid JSON line, so a cancelled scan has real records, issues, and
// quarantine counts to wrongly return if it ever leaked a partial result,
// and the per-line quarantine path stays active so a cancellation can never
// hide inside it.
func qwenCancellationRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeQwenJSONL(t, filepath.Join(root, "alpha", "s1.jsonl"),
		apiLine("resp-1", "qwen-code", "1001", "21", "300", "7", "1022"),
		apiLine("resp-2", "qwen-code", "50", "5", "0", "0", "55"),
		`{"not json`,
	)
	writeQwenJSONL(t, filepath.Join(root, "beta", "s2.jsonl"),
		apiLine("resp-3", "qwen-max", "70", "9", "10", "0", "79"),
		apiLine("resp-4", "qwen-code", "11", "2", "0", "0", "13"),
		`{"also not json`,
	)
	return root
}

func sameLoadResult(a, b adapter.LoadResult) bool {
	return a.Quarantined == b.Quarantined &&
		len(a.MessageUpdates) == len(b.MessageUpdates) &&
		reflect.DeepEqual(a.Issues, b.Issues) &&
		reflect.DeepEqual(a.Records, b.Records) &&
		reflect.DeepEqual(a.MessageUpdates, b.MessageUpdates)
}

func assertNoPartialResult(t *testing.T, res adapter.LoadResult) {
	t.Helper()
	if len(res.Records) != 0 || len(res.Issues) != 0 || res.Quarantined != 0 || len(res.MessageUpdates) != 0 {
		t.Fatalf("cancelled scan must not return a partial result: %#v", res)
	}
}

func assertContextCanceled(t *testing.T, err error) {
	t.Helper()
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled scan must surface context.Canceled, got err=%v", err)
	}
}

func TestLoadRecordsContextPreCancelledReturnsContextError(t *testing.T) {
	root := qwenCancellationRoot(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := loadRecordsContext(ctx, root)
	assertContextCanceled(t, err)
	assertNoPartialResult(t, res)

	// The adapter entry point must forward Options.Context into the same
	// cancellation-aware path.
	adapterRes, err := Adapter().Load(adapter.Options{Source: adapter.QwenJSONLSource, Input: root, Context: ctx})
	assertContextCanceled(t, err)
	assertNoPartialResult(t, adapterRes)
}

func TestLoadRecordsContextExpiredDeadlineSurfacesDeadlineExceeded(t *testing.T) {
	root := qwenCancellationRoot(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Minute))
	defer cancel()

	res, err := loadRecordsContext(ctx, root)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired deadline must surface context.DeadlineExceeded, got err=%v", err)
	}
	assertNoPartialResult(t, res)
}

func TestLoadRecordsContextMidScanCancellationDiscardsPartialResult(t *testing.T) {
	root := qwenCancellationRoot(t)

	// One complete scan with a never-cancelling counting scope measures how
	// many cancellation checks the loader performs end to end.
	probe := &cancelAfterContext{Context: context.Background(), cancelAfter: math.MaxInt}
	baseline, err := loadRecordsContext(probe, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.Records) != 4 {
		t.Fatalf("synthetic baseline must hold four records, got %d", len(baseline.Records))
	}
	if baseline.Quarantined != 2 || len(baseline.Issues) != 2 {
		t.Fatalf("synthetic baseline must keep the quarantine machinery active: %#v", baseline)
	}
	total := probe.calls
	if total < 8 {
		t.Fatalf("synthetic scan is too small to exercise mid-scan cancellation: %d checks", total)
	}

	// Cancelling at any check the scan performs must surface the context
	// error and discard everything accumulated so far; a scope that flips
	// only after the last check (or never) must still return the complete
	// result, never a prefix of it.
	for k := 1; k <= 2*total; k++ {
		res, err := loadRecordsContext(&cancelAfterContext{Context: context.Background(), cancelAfter: k}, root)
		switch {
		case err == nil:
			if !sameLoadResult(res, baseline) {
				t.Fatalf("uncancelled scan (k=%d) must equal the baseline result:\n%#v\n%#v", k, res, baseline)
			}
		default:
			assertContextCanceled(t, err)
			assertNoPartialResult(t, res)
		}
	}

	// The halfway check lands after the scan has started (mid-file for this
	// input), proving a cancellation arriving while a session file is being
	// folded still never leaks a half-built result.
	mid := &cancelAfterContext{Context: context.Background(), cancelAfter: total / 2}
	res, err := loadRecordsContext(mid, root)
	assertContextCanceled(t, err)
	assertNoPartialResult(t, res)
}

func TestAdapterNilContextKeepsLegacyScan(t *testing.T) {
	root := qwenCancellationRoot(t)

	legacy, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(legacy.Records) != 4 {
		t.Fatalf("legacy scan must keep returning every record, got %d", len(legacy.Records))
	}

	// A nil Options.Context must reproduce the historical uncancellable
	// scan exactly (ContextOrBackground falls back to context.Background).
	res, err := Adapter().Load(adapter.Options{Source: adapter.QwenJSONLSource, Input: root})
	if err != nil {
		t.Fatal(err)
	}
	if !sameLoadResult(res, legacy) {
		t.Fatalf("nil Options.Context must reproduce the historical scan:\n%#v\n%#v", res, legacy)
	}
}
