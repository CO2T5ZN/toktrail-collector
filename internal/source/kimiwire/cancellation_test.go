package kimiwire

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

// kimiCancellationRoot writes a synthetic Kimi input with two session files
// across two groups. Each file mixes a valid StatusUpdate (whose legacy
// layout records no model, keeping the missing-model diagnostic machinery
// active) with an invalid JSON line, so a cancelled scan has real records,
// issues, and quarantine counts to wrongly return if it ever leaked a
// partial result.
func kimiCancellationRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeWire(t, filepath.Join(root, "group-a", "session-a", "wire.jsonl"),
		`{"timestamp":1772857971,"message":{"type":"StatusUpdate","payload":{"message_id":"msg-1","token_usage":{"input_other":100,"input_cache_read":20,"input_cache_creation":5,"output":30}}}}`,
		`{"not json`,
	)
	writeWire(t, filepath.Join(root, "group-b", "session-b", "wire.jsonl"),
		`{"timestamp":1772858971,"message":{"type":"StatusUpdate","payload":{"message_id":"msg-2","token_usage":{"input_other":70,"input_cache_read":9,"input_cache_creation":4,"output":11}}}}`,
		`{"also not json`,
	)
	return root
}

func sameKimiLoadResult(a, b adapter.LoadResult) bool {
	return a.Quarantined == b.Quarantined &&
		len(a.MessageUpdates) == len(b.MessageUpdates) &&
		reflect.DeepEqual(a.Issues, b.Issues) &&
		reflect.DeepEqual(a.Records, b.Records) &&
		reflect.DeepEqual(a.MessageUpdates, b.MessageUpdates)
}

func assertKimiNoPartialResult(t *testing.T, res adapter.LoadResult) {
	t.Helper()
	if len(res.Records) != 0 || len(res.Issues) != 0 || res.Quarantined != 0 || len(res.MessageUpdates) != 0 {
		t.Fatalf("cancelled scan must not return a partial result: %#v", res)
	}
}

func assertKimiContextCanceled(t *testing.T, err error) {
	t.Helper()
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled scan must surface context.Canceled, got err=%v", err)
	}
}

func TestKimiWireLoadRecordsContextPreCancelledReturnsContextError(t *testing.T) {
	root := kimiCancellationRoot(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := loadRecordsContext(ctx, root, KimiCLIConfig)
	assertKimiContextCanceled(t, err)
	assertKimiNoPartialResult(t, res)

	// The adapter entry point must forward Options.Context into the same
	// cancellation-aware path.
	adapterRes, err := Adapter(KimiCLIConfig).Load(adapter.Options{Source: adapter.KimiCLIJSONLSource, Input: root, Context: ctx})
	assertKimiContextCanceled(t, err)
	assertKimiNoPartialResult(t, adapterRes)
}

func TestKimiWireLoadRecordsContextExpiredDeadlineSurfacesDeadlineExceeded(t *testing.T) {
	root := kimiCancellationRoot(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Minute))
	defer cancel()

	res, err := loadRecordsContext(ctx, root, KimiCLIConfig)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired deadline must surface context.DeadlineExceeded, got err=%v", err)
	}
	assertKimiNoPartialResult(t, res)
}

func TestKimiWireLoadRecordsContextMidScanCancellationDiscardsPartialResult(t *testing.T) {
	root := kimiCancellationRoot(t)

	// One complete scan with a never-cancelling counting scope measures how
	// many cancellation checks the loader performs end to end.
	probe := &cancelAfterContext{Context: context.Background(), cancelAfter: math.MaxInt}
	baseline, err := loadRecordsContext(probe, root, KimiCLIConfig)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.Records) != 2 {
		t.Fatalf("synthetic baseline must hold two records, got %d", len(baseline.Records))
	}
	if baseline.Quarantined != 2 || len(baseline.Issues) != 4 {
		t.Fatalf("synthetic baseline must keep the quarantine and missing-model machinery active: %#v", baseline)
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
		res, err := loadRecordsContext(&cancelAfterContext{Context: context.Background(), cancelAfter: k}, root, KimiCLIConfig)
		switch {
		case err == nil:
			if !sameKimiLoadResult(res, baseline) {
				t.Fatalf("uncancelled scan (k=%d) must equal the baseline result:\n%#v\n%#v", k, res, baseline)
			}
		default:
			assertKimiContextCanceled(t, err)
			assertKimiNoPartialResult(t, res)
		}
	}

	// The halfway check lands after the scan has started and before it
	// completes; the exhaustive loop above already covers cancellations
	// that arrive between individual wire.jsonl lines, proving a
	// cancellation arriving while a session file is being folded still
	// never leaks a half-built result.
	mid := &cancelAfterContext{Context: context.Background(), cancelAfter: total / 2}
	res, err := loadRecordsContext(mid, root, KimiCLIConfig)
	assertKimiContextCanceled(t, err)
	assertKimiNoPartialResult(t, res)
}

func TestKimiWireAdapterNilContextKeepsLegacyScan(t *testing.T) {
	root := kimiCancellationRoot(t)

	legacy, err := LoadRecords(root, KimiCLIConfig)
	if err != nil {
		t.Fatal(err)
	}
	if len(legacy.Records) != 2 {
		t.Fatalf("legacy scan must keep returning every record, got %d", len(legacy.Records))
	}

	// A nil Options.Context must reproduce the historical uncancellable
	// scan exactly (ContextOrBackground falls back to context.Background).
	res, err := Adapter(KimiCLIConfig).Load(adapter.Options{Source: adapter.KimiCLIJSONLSource, Input: root})
	if err != nil {
		t.Fatal(err)
	}
	if !sameKimiLoadResult(res, legacy) {
		t.Fatalf("nil Options.Context must reproduce the historical scan:\n%#v\n%#v", res, legacy)
	}
}
