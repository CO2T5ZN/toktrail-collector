package claudecodejsonl_test

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
	"toktrail-collector/internal/source/claudecodejsonl"
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

// claudeModelAssistantLine builds an assistant line that records a model
// identifier, so the synthetic baseline's diagnostics stay limited to the
// one deliberately quarantined line (missing-model diagnostics are emitted
// in per-message map order and would make the baseline unordered).
func claudeModelAssistantLine(timestamp, session, msgID, model string, usage map[string]any) map[string]any {
	line := claudeAssistantLine(timestamp, session, msgID, usage)
	line["message"].(map[string]any)["model"] = model
	return line
}

// claudeCancellationInput writes a synthetic Claude Code input with two
// session files. Streaming snapshots of one message, a quarantined invalid
// line, and fresh messages keep the dedup, quarantine, and interval
// machinery active, so a cancelled scan has real records, issues, and
// pending updates to wrongly return if it ever leaked a partial result.
func claudeCancellationInput(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	input := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSONLFile(t, filepath.Join(input, "session-a.jsonl"), []map[string]any{
		claudeModelAssistantLine("2026-10-20T01:00:00Z", "s1", "msg_1", "claude-sonnet-4-5", claudeUsage(10, 0, 0, 5)),
		claudeModelAssistantLine("2026-10-20T01:00:01Z", "s1", "msg_1", "claude-sonnet-4-5", claudeUsage(12, 2, 3, 8)),
		map[string]any{"type": "assistant", "timestamp": "2026-10-20T01:00:30Z", "message": map[string]any{"id": "msg_bad", "usage": "not-an-object"}},
		claudeModelAssistantLine("2026-10-20T01:01:00Z", "s1", "msg_2", "claude-opus-4-6", claudeUsage(7, 1, 0, 4)),
	})
	writeJSONLFile(t, filepath.Join(input, "session-b.jsonl"), []map[string]any{
		claudeModelAssistantLine("2026-10-20T02:00:00Z", "s2", "msg_3", "claude-sonnet-4-5", claudeUsage(3, 0, 0, 2)),
		claudeModelAssistantLine("2026-10-20T02:01:00Z", "s2", "msg_4", "claude-haiku-4-5", claudeUsage(5, 0, 0, 6)),
	})
	return input
}

func loadClaudeWith(ctx context.Context, input string) (adapter.LoadResult, error) {
	return claudecodejsonl.Load(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input, Context: ctx})
}

func assertClaudeContextCanceled(t *testing.T, err error) {
	t.Helper()
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled scan must surface context.Canceled, got err=%v", err)
	}
}

func assertClaudeNoPartialResult(t *testing.T, res adapter.LoadResult) {
	t.Helper()
	if len(res.Records) != 0 || len(res.Issues) != 0 || res.Quarantined != 0 || len(res.MessageUpdates) != 0 {
		t.Fatalf("cancelled scan must not return a partial result: %#v", res)
	}
}

func assertClaudeSameResult(t *testing.T, got, want adapter.LoadResult, k int) {
	t.Helper()
	if got.Quarantined != want.Quarantined ||
		len(got.MessageUpdates) != len(want.MessageUpdates) ||
		!reflect.DeepEqual(got.Issues, want.Issues) ||
		!reflect.DeepEqual(got.Records, want.Records) ||
		!reflect.DeepEqual(got.MessageUpdates, want.MessageUpdates) {
		t.Fatalf("scan (k=%d) must equal the baseline result:\n%#v\n%#v", k, got, want)
	}
}

func TestClaudeCodeJSONLLoadPreCancelledReturnsContextError(t *testing.T) {
	input := claudeCancellationInput(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := loadClaudeWith(ctx, input)
	assertClaudeContextCanceled(t, err)
	assertClaudeNoPartialResult(t, res)
}

func TestClaudeCodeJSONLLoadExpiredDeadlineSurfacesDeadlineExceeded(t *testing.T) {
	input := claudeCancellationInput(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Minute))
	defer cancel()

	res, err := loadClaudeWith(ctx, input)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired deadline must surface context.DeadlineExceeded, got err=%v", err)
	}
	assertClaudeNoPartialResult(t, res)
}

func TestClaudeCodeJSONLLoadMidScanCancellationDiscardsPartialResult(t *testing.T) {
	input := claudeCancellationInput(t)

	// One complete scan with a never-cancelling counting scope measures how
	// many cancellation checks the loader performs end to end.
	probe := &cancelAfterContext{Context: context.Background(), cancelAfter: math.MaxInt}
	baseline, err := loadClaudeWith(probe, input)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.Records) != 4 {
		t.Fatalf("synthetic baseline must hold four stateless records, got %d", len(baseline.Records))
	}
	if baseline.Quarantined != 1 || len(baseline.Issues) != 1 {
		t.Fatalf("synthetic baseline must keep the quarantine machinery active: %#v", baseline)
	}
	total := probe.calls
	if total < 8 {
		t.Fatalf("synthetic scan is too small to exercise mid-scan cancellation: %d checks", total)
	}

	// Cancelling at any check the scan performs must surface the context
	// error and discard everything accumulated so far — records, issues,
	// quarantine counts, and pending message updates alike; a scope that
	// flips only after the last check (or never) must still return the
	// complete result, never a prefix of it.
	for k := 1; k <= 2*total; k++ {
		res, err := loadClaudeWith(&cancelAfterContext{Context: context.Background(), cancelAfter: k}, input)
		switch {
		case err == nil:
			assertClaudeSameResult(t, res, baseline, k)
		default:
			assertClaudeContextCanceled(t, err)
			assertClaudeNoPartialResult(t, res)
		}
	}

	// The halfway check lands after the scan has started (mid-file for this
	// input), proving a cancellation arriving while a session file is being
	// folded still never leaks a half-built result — in particular no
	// pending message updates, so a cancelled scan never advances baselines.
	mid := &cancelAfterContext{Context: context.Background(), cancelAfter: total / 2}
	res, err := loadClaudeWith(mid, input)
	assertClaudeContextCanceled(t, err)
	assertClaudeNoPartialResult(t, res)
}

func TestClaudeCodeJSONLAdapterNilContextKeepsLegacyScan(t *testing.T) {
	input := claudeCancellationInput(t)

	// A nil Options.Context must reproduce the historical uncancellable
	// scan exactly (ContextOrBackground falls back to context.Background).
	res, err := loadClaudeWith(nil, input)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 4 || res.Quarantined != 1 {
		t.Fatalf("nil Options.Context must reproduce the historical scan: %#v", res)
	}

	explicit, err := loadClaudeWith(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	assertClaudeSameResult(t, res, explicit, 0)
}
