package deepseekharness_test

import (
	"context"
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/deepseekharness"
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

// dshCancellationRoot writes a synthetic DSH sessions root with two session
// directories. Each session log holds two complete turns separated by a
// malformed JSON line, so a cancelled scan has real records, issues, and
// quarantine counts to wrongly return if it ever leaked a partial result.
func dshCancellationRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	f1 := newFixture("dsh-cancel-a", false)
	f1.messageTurn(0, usageC700, "deepseek-chat")
	f1.push(`{"not json`)
	f1.messageTurn(1, usageC800, "deepseek-chat")
	writePlain(t, sessionFile(root, "proj-a", "sess-a", "session.jsonl"), f1.Lines())

	f2 := newFixture("dsh-cancel-b", false)
	f2.messageTurn(0, usageW333, "deepseek-chat")
	f2.push(`{"also not json`)
	f2.messageTurn(1, usageW444, "deepseek-chat")
	writePlain(t, sessionFile(root, "proj-b", "sess-b", "session.jsonl"), f2.Lines())
	return root
}

func loadDSHWith(ctx context.Context, root string) (adapter.LoadResult, error) {
	return deepseekharness.Adapter().Load(adapter.Options{Source: adapter.DeepSeekHarnessSource, Input: root, Context: ctx})
}

func assertDSHContextCanceled(t *testing.T, err error) {
	t.Helper()
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled scan must surface context.Canceled, got err=%v", err)
	}
}

func assertDSHNoPartialResult(t *testing.T, res adapter.LoadResult) {
	t.Helper()
	if len(res.Records) != 0 || len(res.Issues) != 0 || res.Quarantined != 0 || len(res.MessageUpdates) != 0 {
		t.Fatalf("cancelled scan must not return a partial result: %#v", res)
	}
}

func assertDSHSameResult(t *testing.T, got, want adapter.LoadResult, k int) {
	t.Helper()
	if got.Quarantined != want.Quarantined ||
		len(got.MessageUpdates) != len(want.MessageUpdates) ||
		!reflect.DeepEqual(got.Issues, want.Issues) ||
		!reflect.DeepEqual(got.Records, want.Records) ||
		!reflect.DeepEqual(got.MessageUpdates, want.MessageUpdates) {
		t.Fatalf("scan (k=%d) must equal the baseline result:\n%#v\n%#v", k, got, want)
	}
}

func TestDeepSeekHarnessLoadPreCancelledReturnsContextError(t *testing.T) {
	root := dshCancellationRoot(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := loadDSHWith(ctx, root)
	assertDSHContextCanceled(t, err)
	assertDSHNoPartialResult(t, res)
}

func TestDeepSeekHarnessLoadExpiredDeadlineSurfacesDeadlineExceeded(t *testing.T) {
	root := dshCancellationRoot(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Minute))
	defer cancel()

	res, err := loadDSHWith(ctx, root)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired deadline must surface context.DeadlineExceeded, got err=%v", err)
	}
	assertDSHNoPartialResult(t, res)
}

func TestDeepSeekHarnessLoadMidScanCancellationDiscardsPartialResult(t *testing.T) {
	root := dshCancellationRoot(t)

	// One complete scan with a never-cancelling counting scope measures how
	// many cancellation checks the loader performs end to end.
	probe := &cancelAfterContext{Context: context.Background(), cancelAfter: math.MaxInt}
	baseline, err := loadDSHWith(probe, root)
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
	// between individual session events, so a turn folded so far can never
	// be half-exported.
	for k := 1; k <= 2*total; k++ {
		res, err := loadDSHWith(&cancelAfterContext{Context: context.Background(), cancelAfter: k}, root)
		switch {
		case err == nil:
			assertDSHSameResult(t, res, baseline, k)
		default:
			assertDSHContextCanceled(t, err)
			assertDSHNoPartialResult(t, res)
		}
	}

	// The halfway check lands after the scan has started and before it
	// completes, proving a cancellation arriving while a session file is
	// being folded still never leaks a half-built result.
	mid := &cancelAfterContext{Context: context.Background(), cancelAfter: total / 2}
	res, err := loadDSHWith(mid, root)
	assertDSHContextCanceled(t, err)
	assertDSHNoPartialResult(t, res)
}

func TestDeepSeekHarnessAdapterNilContextKeepsLegacyScan(t *testing.T) {
	root := dshCancellationRoot(t)

	// The historical entry point keeps its exact signature and behavior:
	// the same result the adapter path loads, uncancellable.
	legacy, err := deepseekharness.LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(legacy.Records) != 4 {
		t.Fatalf("legacy scan must keep returning every record, got %d", len(legacy.Records))
	}

	// A nil Options.Context must reproduce the historical uncancellable
	// scan exactly (ContextOrBackground falls back to context.Background),
	// issues and quarantine counts included.
	res, err := loadDSHWith(nil, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 4 || res.Quarantined != 2 || len(res.Issues) != 2 {
		t.Fatalf("nil Options.Context must reproduce the historical scan: %#v", res)
	}
	assertDSHSameResult(t, res, legacy, 0)
}
