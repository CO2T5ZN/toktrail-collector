package resync

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/overrides"
	"toktrail-collector/internal/local/statedir"
)

// ---------------------------------------------------------------------------
// Cancellation of the override current-scan: RunOverride(ctx) must thread
// ctx through planOverrideContext → classifyOverrideScanContext →
// registry.LoadRecordsForSource (adapter.Options.Context), so a cancelled
// or expired scope stops the scan, fails the whole pass closed with an
// errors.Is-matchable error, and never degrades into a per-grant skip.
// Every fixture here is synthetic: temp directories, fake sessions, a
// local fake remote, and counting cancellation scopes — no real state, no
// real network, no external sources.
// ---------------------------------------------------------------------------

// cancelAfterScope is a synthetic cancellation scope for deterministic
// cancellation tests: it reports context.Canceled from the cancelAfter-th
// Err call onward, so a test can cancel at any chosen check point of a
// scan without sleeping or racing a real timer. It also counts every Err
// call, which lets a test measure how many cancellation checks one
// complete planning pass performs and then cancel exactly inside the next
// one.
type cancelAfterScope struct {
	context.Context
	cancelAfter int
	calls       int
	cancelled   bool
}

func (c *cancelAfterScope) Err() error {
	c.calls++
	if c.calls >= c.cancelAfter {
		c.cancelled = true
	}
	if c.cancelled {
		return context.Canceled
	}
	return nil
}

// overrideCancellationGrants builds a state directory with TWO granted
// codex-jsonl inputs, each holding several session files, so one
// planning pass performs many cancellation checks spread across both
// grants (the loader checks per file and per line, and the classifier
// checks per grant and per record). Cancelling early therefore proves the
// pass stopped inside the FIRST grant instead of skipping it and
// continuing with the second.
func overrideCancellationGrants(t *testing.T) (string, statedir.DeviceState) {
	t.Helper()
	dir := t.TempDir()
	st := statedir.DeviceState{DeviceID: "device-resync", DeviceSecret: strings.Repeat("a", 64), ServerURL: "http://srv"}
	if err := statedir.New(dir).Save(st); err != nil {
		t.Fatal(err)
	}
	for idx, name := range []string{"alpha", "beta"} {
		input := filepath.Join(dir, "sessions", name)
		if err := os.MkdirAll(input, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := grants.New(dir).Enable("codex-jsonl", input); err != nil {
			t.Fatalf("create synthetic source grant: %v", err)
		}
		for file := 0; file < 2; file++ {
			writeCodexSession(t, filepath.Join(input, fmt.Sprintf("rollout-%s-%d.jsonl", name, file)),
				[4]uint64{100 + uint64(idx), 20, 5, 40 + uint64(file)})
		}
	}
	return dir, st
}

// snapshotTree records every file (relative path + size) under a state
// directory so a test can prove a cancelled pass wrote nothing at all.
func snapshotTree(t *testing.T, root string) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		out[rel] = info.Size()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func assertNoStateChange(t *testing.T, before, after map[string]int64) {
	t.Helper()
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("a cancelled override pass must not touch the state directory:\nbefore=%v\nafter=%v", before, after)
	}
}

// TestOverrideScanPreCancelledStopsPassBeforeAnything proves the fixed
// ctx chain end to end: a pass whose scope is already cancelled fails
// during planning — before the dry-run/confirmation gates — with an error
// matching errors.Is(err, context.Canceled), the confirmation callback is
// never invoked, zero HTTP requests of any kind are made, and the state
// directory (the override ledger included) is byte-for-byte untouched.
func TestOverrideScanPreCancelledStopsPassBeforeAnything(t *testing.T) {
	remote, server := newOverrideRemote(t)
	dir, _ := overrideCancellationGrants(t)
	before := snapshotTree(t, dir)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	confirmed := false

	_, err := RunOverride(ctx, OverrideOptions{
		StateDir: dir, ServerURL: server.URL,
		Confirm: func(OverridePlan) error { confirmed = true; return nil },
	})
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled scope must fail the override pass with context.Canceled, got %v", err)
	}
	if confirmed {
		t.Fatal("a cancelled pass must never reach the confirmation callback")
	}
	if got := remote.requestCount(); got != 0 {
		t.Fatalf("a cancelled pass must make zero HTTP requests, got %d", got)
	}
	assertNoStateChange(t, before, snapshotTree(t, dir))
	if _, statErr := os.Stat(overrides.New(dir).Path()); !os.IsNotExist(statErr) {
		t.Fatal("a cancelled pass must not write the override ledger")
	}
}

// TestOverrideScanExpiredDeadlineSurfacesDeadlineExceeded proves an
// expired deadline flows through the same chain and stays matchable with
// errors.Is(err, context.DeadlineExceeded), again with zero network
// traffic and zero state writes.
func TestOverrideScanExpiredDeadlineSurfacesDeadlineExceeded(t *testing.T) {
	remote, server := newOverrideRemote(t)
	dir, _ := overrideCancellationGrants(t)
	before := snapshotTree(t, dir)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Minute))
	defer cancel()

	_, err := RunOverride(ctx, OverrideOptions{
		StateDir: dir, ServerURL: server.URL,
		Confirm: autoConfirmOverride(nil),
	})
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired deadline must surface context.DeadlineExceeded, got %v", err)
	}
	if got := remote.requestCount(); got != 0 {
		t.Fatalf("an expired pass must make zero HTTP requests, got %d", got)
	}
	assertNoStateChange(t, before, snapshotTree(t, dir))
}

// TestOverrideScanMidScanCancellationNeverPartial cancels the planning
// pass at EVERY check point it performs (measured with a counting scope
// first) and asserts the invariant: the pass either completes with
// exactly the baseline plan and delta, or fails with an error matching
// errors.Is(err, context.Canceled) and an empty delta — never a partial
// plan. Because the checks span both granted inputs, a cancellation
// landing in the first grant's scan must terminate the whole pass; the
// error propagating (instead of a per-grant skip that would let the
// second grant scan anyway) is exactly what the loop asserts.
func TestOverrideScanMidScanCancellationNeverPartial(t *testing.T) {
	dir, st := overrideCancellationGrants(t)
	ledger := overrides.Ledger{}

	// One complete never-cancelling pass measures the total number of
	// cancellation checks the planning performs (per grant, per file,
	// per line inside the loader, per record in the classifier).
	probe := &cancelAfterScope{Context: context.Background(), cancelAfter: math.MaxInt}
	basePlan, baseDelta, err := planOverrideContext(probe, dir, st, "http://srv", ledger)
	if err != nil {
		t.Fatal(err)
	}
	total := probe.calls
	if total < 8 {
		t.Fatalf("synthetic planning is too small to exercise mid-scan cancellation: %d checks", total)
	}
	if len(basePlan.Sources) != 2 || len(baseDelta) == 0 {
		t.Fatalf("baseline plan must cover both grants with a non-empty delta: %#v", basePlan.Sources)
	}

	// Cancelling at any check the pass performs must fail the WHOLE pass
	// closed; a scope that flips only after the last check (or never)
	// must still return the complete result, never a prefix of it.
	for k := 1; k <= 2*total; k++ {
		scope := &cancelAfterScope{Context: context.Background(), cancelAfter: k}
		plan, delta, err := planOverrideContext(scope, dir, st, "http://srv", ledger)
		switch {
		case err == nil:
			if !reflect.DeepEqual(plan, basePlan) || !reflect.DeepEqual(delta, baseDelta) {
				t.Fatalf("uncancelled planning (k=%d) must equal the baseline plan and delta:\n%#v\n%#v", k, plan, basePlan)
			}
		default:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled planning (k=%d) must surface context.Canceled, got %v", k, err)
			}
			if len(delta) != 0 {
				t.Fatalf("cancelled planning (k=%d) must not leak a partial delta: %d record(s)", k, len(delta))
			}
			for _, sp := range plan.Sources {
				if sp.Scanned == 0 {
					t.Fatalf("cancelled planning (k=%d) must not append an empty per-source summary: %#v", k, sp)
				}
			}
		}
	}

	// The halfway check lands mid-scan of the first grant (well before
	// the second grant's per-grant check), proving a cancellation inside
	// one grant's scan stops the pass outright instead of skipping that
	// grant and scanning the rest.
	mid := &cancelAfterScope{Context: context.Background(), cancelAfter: total / 2}
	plan, delta, err := planOverrideContext(mid, dir, st, "http://srv", ledger)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-scan cancellation must fail the pass with context.Canceled, got %v", err)
	}
	if len(delta) != 0 {
		t.Fatalf("mid-scan cancellation must not leak a partial delta: %d record(s)", len(delta))
	}
	if len(plan.Sources) != 0 {
		t.Fatalf("mid-scan cancellation must stop before any grant is summarized, got %d source summary(ies)", len(plan.Sources))
	}
}

// TestOverrideScanCancelledNotSwallowedAsPerGrantSkip pins the
// not-swallowed property directly: with two granted inputs and a scope
// that dies at the very first check (the first grant's boundary), the
// pass returns an error naming that grant, the second grant is never
// scanned (its check point is never reached), and a full RunOverride on
// top never reaches confirmation or the network.
func TestOverrideScanCancelledNotSwallowedAsPerGrantSkip(t *testing.T) {
	remote, server := newOverrideRemote(t)
	dir, _ := overrideCancellationGrants(t)
	granted, err := overrideGrants(dir, &OverridePlan{})
	if err != nil {
		t.Fatal(err)
	}
	if len(granted) != 2 {
		t.Fatalf("fixture must hold two granted inputs, got %d", len(granted))
	}
	sort.Slice(granted, func(i, j int) bool { return granted[i].Input < granted[j].Input })

	// The scope dies at the very first Err call — the per-grant check of
	// the first (lexicographically smaller) granted input.
	scope := &cancelAfterScope{Context: context.Background(), cancelAfter: 1}
	_, err = classifyOverrideScanContext(scope, dir, granted, overrides.Ledger{}, &OverridePlan{})
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation at the first grant boundary must fail closed, got %v", err)
	}
	if !strings.Contains(err.Error(), granted[0].Input) {
		t.Fatalf("the cancellation error must name the grant it stopped at: %v", err)
	}
	if scope.calls != 1 {
		t.Fatalf("a swallowed cancellation would have kept checking (grant 2 included); expected exactly 1 check, got %d", scope.calls)
	}

	// End to end: the same first-check cancellation inside RunOverride
	// must stop the pass before confirmation, network, or any write.
	before := snapshotTree(t, dir)
	confirmed := false
	_, runErr := RunOverride(&cancelAfterScope{Context: context.Background(), cancelAfter: 1}, OverrideOptions{
		StateDir: dir, ServerURL: server.URL,
		Confirm: func(OverridePlan) error { confirmed = true; return nil },
	})
	if runErr == nil || !errors.Is(runErr, context.Canceled) {
		t.Fatalf("RunOverride must propagate the scan cancellation, got %v", runErr)
	}
	if confirmed || remote.requestCount() != 0 {
		t.Fatalf("cancelled pass must not confirm or talk to the network: confirmed=%t requests=%d", confirmed, remote.requestCount())
	}
	assertNoStateChange(t, before, snapshotTree(t, dir))
}

// TestOverridePlanContextVariantMatchesLegacy proves the context variant
// is behaviorally identical to the historical no-ctx offline planning
// entry point when the scope is alive: identical plan, identical delta.
// The legacy signature itself stays uncancellable (context.Background
// fallback), which the existing multi-input planning tests keep covering.
func TestOverridePlanContextVariantMatchesLegacy(t *testing.T) {
	dir, st := overrideCancellationGrants(t)
	ledger := overrides.Ledger{}

	legacyPlan, legacyDelta, err := planOverride(dir, st, "http://srv", ledger)
	if err != nil {
		t.Fatal(err)
	}
	scopedPlan, scopedDelta, err := planOverrideContext(context.Background(), dir, st, "http://srv", ledger)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(legacyPlan, scopedPlan) {
		t.Fatalf("live scope must plan identically to the legacy entry point:\n%#v\n%#v", scopedPlan, legacyPlan)
	}
	if !reflect.DeepEqual(legacyDelta, scopedDelta) {
		t.Fatalf("live scope must derive the identical delta:\n%#v\n%#v", scopedDelta, legacyDelta)
	}

	// The legacy classifier entry point also keeps producing the full
	// result under the very same fixture.
	granted, err := overrideGrants(dir, &OverridePlan{})
	if err != nil {
		t.Fatal(err)
	}
	legacyScan, err := classifyOverrideScan(dir, granted, ledger, &OverridePlan{})
	if err != nil {
		t.Fatal(err)
	}
	if len(legacyScan) != len(legacyDelta) {
		t.Fatalf("legacy classifyOverrideScan must keep planning every record: %d vs %d", len(legacyScan), len(legacyDelta))
	}
}
