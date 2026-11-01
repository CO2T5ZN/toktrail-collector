package codexjsonl_test

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/codexjsonl"
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

// codexCancellationInput writes a synthetic Codex input with two session
// files. The first file mixes an attributable interval with an
// unattributable one (a turn_context without a recorded model), so a
// cancelled scan has real records and model diagnostics to wrongly return
// if it ever leaked a partial result.
func codexCancellationInput(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	input := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSONLFile(t, filepath.Join(input, "session-a.jsonl"), []map[string]any{
		codexTurn("2026-10-20T01:00:00Z", "gpt-4o"),
		codexCount("2026-10-20T01:01:00Z", 100, 0, 0, 10),
		codexCount("2026-10-20T01:02:00Z", 150, 0, 0, 20),
		codexTurn("2026-10-20T01:03:00Z", nil),
		codexCount("2026-10-20T01:04:00Z", 220, 0, 0, 30),
	})
	writeJSONLFile(t, filepath.Join(input, "session-b.jsonl"), []map[string]any{
		codexTurn("2026-10-20T02:00:00Z", "gpt-5"),
		codexCount("2026-10-20T02:01:00Z", 10, 0, 0, 1),
		codexCount("2026-10-20T02:02:00Z", 30, 0, 0, 4),
	})
	return input
}

func loadCodexWith(ctx context.Context, input string) (adapter.LoadResult, error) {
	return codexjsonl.Adapter().Load(adapter.Options{Source: adapter.CodexJSONLSource, Input: input, Context: ctx})
}

func assertCodexContextCanceled(t *testing.T, err error) {
	t.Helper()
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled scan must surface context.Canceled, got err=%v", err)
	}
}

func assertCodexNoPartialResult(t *testing.T, res adapter.LoadResult) {
	t.Helper()
	if len(res.Records) != 0 || len(res.Issues) != 0 || res.Quarantined != 0 || len(res.MessageUpdates) != 0 {
		t.Fatalf("cancelled scan must not return a partial result: %#v", res)
	}
}

func TestCodexJSONLLoadPreCancelledReturnsContextError(t *testing.T) {
	input := codexCancellationInput(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := loadCodexWith(ctx, input)
	assertCodexContextCanceled(t, err)
	assertCodexNoPartialResult(t, res)
}

func TestCodexJSONLLoadExpiredDeadlineSurfacesDeadlineExceeded(t *testing.T) {
	input := codexCancellationInput(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Minute))
	defer cancel()

	res, err := loadCodexWith(ctx, input)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired deadline must surface context.DeadlineExceeded, got err=%v", err)
	}
	assertCodexNoPartialResult(t, res)
}

func TestCodexJSONLLoadMidScanCancellationDiscardsPartialResult(t *testing.T) {
	input := codexCancellationInput(t)

	// One complete scan with a never-cancelling counting scope measures how
	// many cancellation checks the loader performs end to end.
	probe := &cancelAfterContext{Context: context.Background(), cancelAfter: math.MaxInt}
	baseline, err := loadCodexWith(probe, input)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.Records) != 3 {
		t.Fatalf("synthetic baseline must hold three delta records, got %d", len(baseline.Records))
	}
	if len(baseline.Issues) != 1 {
		t.Fatalf("synthetic baseline must keep the model diagnostics active: %#v", baseline.Issues)
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
		res, err := loadCodexWith(&cancelAfterContext{Context: context.Background(), cancelAfter: k}, input)
		switch {
		case err == nil:
			if res.Quarantined != baseline.Quarantined ||
				len(res.MessageUpdates) != len(baseline.MessageUpdates) ||
				!reflect.DeepEqual(res.Issues, baseline.Issues) ||
				!reflect.DeepEqual(res.Records, baseline.Records) {
				t.Fatalf("uncancelled scan (k=%d) must equal the baseline result:\n%#v\n%#v", k, res, baseline)
			}
		default:
			assertCodexContextCanceled(t, err)
			assertCodexNoPartialResult(t, res)
		}
	}

	// The halfway check lands after the scan has started (mid-file for this
	// input), proving a cancellation arriving while a session file is being
	// folded still never leaks a half-built result.
	mid := &cancelAfterContext{Context: context.Background(), cancelAfter: total / 2}
	res, err := loadCodexWith(mid, input)
	assertCodexContextCanceled(t, err)
	assertCodexNoPartialResult(t, res)
}

func TestCodexJSONLAdapterNilContextKeepsLegacyScan(t *testing.T) {
	input := codexCancellationInput(t)

	// The historical records-only entry point keeps its exact signature and
	// behavior: the same records the adapter path loads, uncancellable.
	legacyRecords, err := codexjsonl.LoadRecords(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(legacyRecords) != 3 {
		t.Fatalf("legacy scan must keep returning every record, got %d", len(legacyRecords))
	}

	// A nil Options.Context must reproduce the historical uncancellable
	// scan exactly (ContextOrBackground falls back to context.Background),
	// diagnostics included.
	res, err := loadCodexWith(nil, input)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 3 || len(res.Issues) != 1 {
		t.Fatalf("nil Options.Context must reproduce the historical scan: %#v", res)
	}
	if !reflect.DeepEqual(res.Records, legacyRecords) {
		t.Fatalf("nil Options.Context must reproduce the legacy records:\n%#v\n%#v", res.Records, legacyRecords)
	}
}
