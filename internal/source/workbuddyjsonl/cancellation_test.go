package workbuddyjsonl

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

// workbuddyCancellationRoot writes a synthetic WorkBuddy input with two
// session files across two directories. Each file mixes two valid request
// usage records with an invalid JSON line, so a cancelled scan has real
// records, issues, and quarantine counts to wrongly return if it ever
// leaked a partial result, and the per-line quarantine path stays active so
// a cancellation can never hide inside it.
func workbuddyCancellationRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeJSONL(t, filepath.Join(root, "alpha", "session.jsonl"),
		wbRecord("call-1", "msg-1", `{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120,"prompt_cache_hit_tokens":40,"cache_creation_input_tokens":0}`),
		wbRecord("call-2", "msg-2", `{"prompt_tokens":110,"completion_tokens":21,"total_tokens":131,"prompt_cache_hit_tokens":41,"cache_creation_input_tokens":1}`),
		`{"not json`,
	)
	writeJSONL(t, filepath.Join(root, "beta", "session.jsonl"),
		wbRecord("call-3", "msg-3", `{"prompt_tokens":120,"completion_tokens":22,"total_tokens":142,"prompt_cache_hit_tokens":42,"cache_creation_input_tokens":2}`),
		wbRecord("call-4", "msg-4", `{"prompt_tokens":130,"completion_tokens":23,"total_tokens":153,"prompt_cache_hit_tokens":43,"cache_creation_input_tokens":3}`),
		`{"also not json`,
	)
	return root
}

func sameWorkBuddyLoadResult(a, b adapter.LoadResult) bool {
	return a.Quarantined == b.Quarantined &&
		len(a.MessageUpdates) == len(b.MessageUpdates) &&
		reflect.DeepEqual(a.Issues, b.Issues) &&
		reflect.DeepEqual(a.Records, b.Records) &&
		reflect.DeepEqual(a.MessageUpdates, b.MessageUpdates)
}

func assertWorkBuddyNoPartialResult(t *testing.T, res adapter.LoadResult) {
	t.Helper()
	if len(res.Records) != 0 || len(res.Issues) != 0 || res.Quarantined != 0 || len(res.MessageUpdates) != 0 {
		t.Fatalf("cancelled scan must not return a partial result: %#v", res)
	}
}

func assertWorkBuddyContextCanceled(t *testing.T, err error) {
	t.Helper()
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled scan must surface context.Canceled, got err=%v", err)
	}
}

func TestWorkBuddyLoadRecordsContextPreCancelledReturnsContextError(t *testing.T) {
	root := workbuddyCancellationRoot(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := loadRecordsContext(ctx, root)
	assertWorkBuddyContextCanceled(t, err)
	assertWorkBuddyNoPartialResult(t, res)

	// The adapter entry point must forward Options.Context into the same
	// cancellation-aware path.
	adapterRes, err := Adapter().Load(adapter.Options{Source: adapter.WorkBuddyJSONLSource, Input: root, Context: ctx})
	assertWorkBuddyContextCanceled(t, err)
	assertWorkBuddyNoPartialResult(t, adapterRes)
}

func TestWorkBuddyLoadRecordsContextExpiredDeadlineSurfacesDeadlineExceeded(t *testing.T) {
	root := workbuddyCancellationRoot(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Minute))
	defer cancel()

	res, err := loadRecordsContext(ctx, root)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired deadline must surface context.DeadlineExceeded, got err=%v", err)
	}
	assertWorkBuddyNoPartialResult(t, res)
}

func TestWorkBuddyLoadRecordsContextMidScanCancellationDiscardsPartialResult(t *testing.T) {
	root := workbuddyCancellationRoot(t)

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
	// result, never a prefix of it. This covers cancellations that arrive
	// between individual lines of the custom torn-tail-aware reader, so the
	// per-line check can never let a half-folded session leak.
	for k := 1; k <= 2*total; k++ {
		res, err := loadRecordsContext(&cancelAfterContext{Context: context.Background(), cancelAfter: k}, root)
		switch {
		case err == nil:
			if !sameWorkBuddyLoadResult(res, baseline) {
				t.Fatalf("uncancelled scan (k=%d) must equal the baseline result:\n%#v\n%#v", k, res, baseline)
			}
		default:
			assertWorkBuddyContextCanceled(t, err)
			assertWorkBuddyNoPartialResult(t, res)
		}
	}

	// The halfway check lands after the scan has started and before it
	// completes, proving a cancellation arriving while a session file is
	// being folded still never leaks a half-built result.
	mid := &cancelAfterContext{Context: context.Background(), cancelAfter: total / 2}
	res, err := loadRecordsContext(mid, root)
	assertWorkBuddyContextCanceled(t, err)
	assertWorkBuddyNoPartialResult(t, res)
}

func TestWorkBuddyAdapterNilContextKeepsLegacyScan(t *testing.T) {
	root := workbuddyCancellationRoot(t)

	legacy, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(legacy.Records) != 4 {
		t.Fatalf("legacy scan must keep returning every record, got %d", len(legacy.Records))
	}

	// A nil Options.Context must reproduce the historical uncancellable
	// scan exactly (ContextOrBackground falls back to context.Background).
	res, err := Adapter().Load(adapter.Options{Source: adapter.WorkBuddyJSONLSource, Input: root})
	if err != nil {
		t.Fatal(err)
	}
	if !sameWorkBuddyLoadResult(res, legacy) {
		t.Fatalf("nil Options.Context must reproduce the historical scan:\n%#v\n%#v", res, legacy)
	}
}
