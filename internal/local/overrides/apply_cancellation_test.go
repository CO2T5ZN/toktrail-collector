package overrides

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Cancellation coverage for ApplyToBaselineContext: the two per-record
// ledger scans (the pending-source scan and the confirmed-entry scan)
// must honor the caller's scope at every record, and a cancelled pass
// must leave the caller's known map exactly as it was — supersessions
// are staged and applied in one shot, never record by record. The
// single-file ledger load and binding check stay non-interruptible at
// their file boundaries, and nothing is ever written back. All state is
// synthetic (t.TempDir + inline records); nothing reads a real collector
// state directory.

// cancelAfterContext is a synthetic cancellation scope for deterministic
// cancellation tests: it reports context.Canceled from the cancelAfter-th
// Err call onward, so a test can cancel at any chosen checkpoint of the
// ledger scans without sleeping or racing a real timer. It also counts
// every Err call, which lets a test measure how many cancellation checks
// one complete application performs and then cancel at each one.
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

// cancellationFixture builds a bound state directory whose ledger mixes:
// four confirmed codex entries (one superseding a stored payload, three
// ledger-only), two confirmed deepseek entries, and one pending deepseek
// attempt (which must not block the codex scan). The caller's original
// known map carries one stored payload a confirmed entry supersedes plus
// one key no entry touches; expected is the map after a complete codex
// application.
func cancellationFixture(t *testing.T) (dir string, orig, expected map[string][]byte, entries int) {
	t.Helper()
	dir = t.TempDir()
	boundState(t, dir, "device-a", "http://srv")
	at := time.Now().UTC()
	confirmed := func(key, source, tokens string) Entry {
		return Entry{RecordKey: key, Source: source, Record: record(key, tokens), AttemptID: "oa-" + key, Status: StatusConfirmed, UpdatedAt: at}
	}
	ledger := Ledger{Schema: Schema, DeviceID: "device-a", ServerURL: "http://srv", Entries: map[string]Entry{
		"codex:c1": confirmed("codex:c1", CodexSource, "99"),
		"codex:c2": confirmed("codex:c2", CodexSource, "1"),
		"codex:c3": confirmed("codex:c3", CodexSource, "2"),
		"codex:c4": confirmed("codex:c4", CodexSource, "3"),
		"dsh:d1":   confirmed("dsh:d1", DeepSeekSource, "1"),
		"dsh:d2":   confirmed("dsh:d2", DeepSeekSource, "2"),
		"dsh:dp":   {RecordKey: "dsh:dp", Source: DeepSeekSource, PendingRecord: record("dsh:dp", "5"), PendingAttemptID: "oa-dp", Status: StatusPending, PendingSince: &at, UpdatedAt: at},
	}}
	if err := New(dir).Save(ledger); err != nil {
		t.Fatal(err)
	}
	orig = map[string][]byte{
		"codex:c1":     record("codex:c1", "10"),
		"codex:stored": record("codex:stored", "10"),
	}
	expected = map[string][]byte{
		"codex:c1":     record("codex:c1", "99"),
		"codex:stored": record("codex:stored", "10"),
		"codex:c2":     record("codex:c2", "1"),
		"codex:c3":     record("codex:c3", "2"),
		"codex:c4":     record("codex:c4", "3"),
	}
	return dir, orig, expected, len(ledger.Entries)
}

func cloneKnown(m map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(m))
	for k, v := range m {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

// TestApplyToBaselineContextAppliesBaseline pins the live-scope behavior:
// a complete pass folds every confirmed codex entry into the caller's
// known map (superseding the stored payload and adding ledger-only keys)
// and never applies other sources' entries or pending content.
func TestApplyToBaselineContextAppliesBaseline(t *testing.T) {
	dir, orig, expected, _ := cancellationFixture(t)
	if err := ApplyToBaselineContext(context.Background(), dir, CodexSource, orig); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(orig, expected) {
		t.Fatalf("live scope must apply the full baseline:\n%#v\n%#v", orig, expected)
	}
}

// TestApplyToBaselineContextPreCancelledLeavesKnownUntouched pins the
// entry checkpoint: an already-dead scope fails before the ledger is
// loaded or the known map is mutated, for both cancel and deadline
// scopes.
func TestApplyToBaselineContextPreCancelledLeavesKnownUntouched(t *testing.T) {
	dir, orig, _, _ := cancellationFixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	known := cloneKnown(orig)
	if err := ApplyToBaselineContext(ctx, dir, CodexSource, known); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled scope must surface context.Canceled, got %v", err)
	}
	if !reflect.DeepEqual(known, orig) {
		t.Fatalf("pre-cancelled scope must not touch the known map:\n%#v\n%#v", known, orig)
	}

	deadline, dcancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Minute))
	defer dcancel()
	known = cloneKnown(orig)
	if err := ApplyToBaselineContext(deadline, dir, CodexSource, known); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired deadline must surface context.DeadlineExceeded, got %v", err)
	}
	if !reflect.DeepEqual(known, orig) {
		t.Fatalf("expired deadline must not touch the known map:\n%#v\n%#v", known, orig)
	}
}

// TestApplyToBaselineContextMidScanCancellationNeverPollutesKnown cancels
// at EVERY checkpoint the application performs: a complete run with a
// never-cancelling counting scope measures the total number of checks,
// then each prefix length either completes with exactly the full baseline
// or fails with the context error and a byte-identical known map — never
// a half-applied baseline. The ledger file on disk must stay
// byte-identical throughout: the application performs no persistent
// writes.
func TestApplyToBaselineContextMidScanCancellationNeverPollutesKnown(t *testing.T) {
	dir, orig, expected, entries := cancellationFixture(t)
	before, err := os.ReadFile(New(dir).Path())
	if err != nil {
		t.Fatal(err)
	}

	probe := &cancelAfterContext{Context: context.Background(), cancelAfter: math.MaxInt}
	if err := ApplyToBaselineContext(probe, dir, CodexSource, cloneKnown(orig)); err != nil {
		t.Fatal(err)
	}
	total := probe.calls
	// The entry check plus one check per record in each of the two scans.
	if minChecks := 1 + 2*entries; total < minChecks {
		t.Fatalf("synthetic ledger is too small to exercise mid-scan cancellation: %d checks < %d", total, minChecks)
	}

	for k := 1; k <= 2*total; k++ {
		known := cloneKnown(orig)
		err := ApplyToBaselineContext(&cancelAfterContext{Context: context.Background(), cancelAfter: k}, dir, CodexSource, known)
		switch {
		case err == nil:
			if !reflect.DeepEqual(known, expected) {
				t.Fatalf("uncancelled application (k=%d) must apply the full baseline:\n%#v\n%#v", k, known, expected)
			}
		default:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled application must surface context.Canceled, got err=%v", err)
			}
			if !reflect.DeepEqual(known, orig) {
				t.Fatalf("cancelled application (k=%d) must leave the known map untouched:\n%#v\n%#v", k, known, orig)
			}
		}
	}

	after, err := os.ReadFile(New(dir).Path())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("the application must not write the ledger or any other persistent state")
	}
}

// TestApplyToBaselineContextPendingScanHonorsScope pins that the pending
// scan itself observes the scope per record: with a pending codex attempt
// in the ledger, a scope cancelled inside the scan fails with the context
// error and an untouched known map, while a live scope still fails closed
// with the pending-override blocking error.
func TestApplyToBaselineContextPendingScanHonorsScope(t *testing.T) {
	dir := t.TempDir()
	boundState(t, dir, "device-a", "http://srv")
	at := time.Now().UTC()
	ledger := Ledger{Schema: Schema, DeviceID: "device-a", ServerURL: "http://srv", Entries: map[string]Entry{
		"codex:p": {RecordKey: "codex:p", Source: CodexSource, PendingRecord: record("codex:p", "5"), PendingAttemptID: "oa-p", Status: StatusPending, PendingSince: &at, UpdatedAt: at},
		"codex:c": {RecordKey: "codex:c", Source: CodexSource, Record: record("codex:c", "1"), AttemptID: "oa-c", Status: StatusConfirmed, UpdatedAt: at},
	}}
	if err := New(dir).Save(ledger); err != nil {
		t.Fatal(err)
	}
	orig := map[string][]byte{"codex:c": record("codex:c", "0")}

	// Live scope: the pending attempt blocks the source fail-closed
	// without touching the known map.
	blocked := cloneKnown(orig)
	if err := ApplyToBaselineContext(context.Background(), dir, CodexSource, blocked); err == nil || !strings.Contains(err.Error(), "pending") {
		t.Fatalf("a pending override must block the scan, got %v", err)
	}
	if !reflect.DeepEqual(blocked, orig) {
		t.Fatalf("a blocked scan must not touch the known map:\n%#v\n%#v", blocked, orig)
	}

	// Cancelled inside the pending scan: the entry check is checkpoint 1
	// and the first pending-scan record check is checkpoint 2, so the
	// scope error wins before the blocking decision is reached.
	cancelled := cloneKnown(orig)
	if err := ApplyToBaselineContext(&cancelAfterContext{Context: context.Background(), cancelAfter: 2}, dir, CodexSource, cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation inside the pending scan must surface context.Canceled, got %v", err)
	}
	if !reflect.DeepEqual(cancelled, orig) {
		t.Fatalf("cancellation inside the pending scan must leave the known map untouched:\n%#v\n%#v", cancelled, orig)
	}
}

// TestApplyToBaselineLegacyMatchesContext pins the legacy entry point's
// compatibility: ApplyToBaseline keeps the exact pre-context behavior —
// the same full baseline as ApplyToBaselineContext(context.Background())
// on the same ledger.
func TestApplyToBaselineLegacyMatchesContext(t *testing.T) {
	dir, orig, expected, _ := cancellationFixture(t)

	legacy := cloneKnown(orig)
	if err := ApplyToBaseline(dir, CodexSource, legacy); err != nil {
		t.Fatal(err)
	}
	scoped := cloneKnown(orig)
	if err := ApplyToBaselineContext(context.Background(), dir, CodexSource, scoped); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(legacy, expected) || !reflect.DeepEqual(scoped, expected) {
		t.Fatalf("legacy and scoped application must both apply the full baseline:\n%#v\n%#v\n%#v", legacy, scoped, expected)
	}
}
