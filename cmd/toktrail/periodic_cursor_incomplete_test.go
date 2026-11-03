package main

// §6.5 coverage for the periodic CLI entry's account-queue incompleteness
// judgment (periodicCursorIncomplete): a successful (nil-error) periodic
// run whose account cursor round failed, drifted or paused with work
// queued must exit non-zero with a reason, while the authorization
// verdicts (no permit, scope withheld before any work), the normal
// bounded stops of an explicit --max-batches and an in-round fence
// recovery stay exit zero. The judgment is asserted end to end through
// the real flag parsing, budget plan and result rendering.
//
// Everything is synthetic: tempdir state directories (never the real
// TOKTRAIL_HOME), an httptest fake for the ingest server, seeded pending
// batches and — through the periodicCursorOptions test seam — synthetic
// cursor auth/verify/pull providers. No test reads real tool state, real
// Cursor credentials, or performs any network access beyond the fake
// server.

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/cursor/api"
	"toktrail-collector/internal/cursor/identity"
	"toktrail-collector/internal/local/cursorsource"
)

// capturePeriodicStdoutAndStderr runs fn with os.Stdout and os.Stderr
// redirected to pipes and returns everything the command printed on
// each stream (progress-json events go to stderr). Both pipes are
// drained concurrently while fn runs: reading only after fn returned
// would deadlock any output larger than the OS pipe buffer (see
// pipe_capture_test.go).
func capturePeriodicStdoutAndStderr(t *testing.T, fn func() error) (string, string, error) {
	t.Helper()
	return captureStdoutStderrPiped(t, fn)
}

// armPeriodicCursorOnlyFixture prepares a cursor-only device (no local
// file grants) with an active permit, the fake providers and the armed
// account source, so the run's account queue is the only work.
func armPeriodicCursorOnlyFixture(t *testing.T, server *periodicDrainFakeServer, pull *periodicFakePull) string {
	t.Helper()
	stateDir := t.TempDir()
	armPeriodicCursorSource(server)
	bindPeriodicCLIDevice(t, stateDir, server.URL)
	writePeriodicDrainCursorPermit(t, stateDir)
	armPeriodicCursorFakes(t, pull)
	return stateDir
}

// writePeriodicCursorPermitWithStatus seeds a local Cursor permit in the
// given status (the shared fixture always writes an active one).
func writePeriodicCursorPermitWithStatus(t *testing.T, stateDir string, status cursorsource.Status) {
	t.Helper()
	license := cursorsource.License{
		SourceInstanceID: "cursor-src-drain-1",
		SourceType:       cursorsource.SourceType,
		Status:           status,
		ConfirmedAt:      time.Date(2026, 10, 30, 3, 0, 0, 0, time.UTC),
		ConsentRevision:  40,
		FenceVersion:     3,
		NextRevision:     7,
		AccountMatchID:   identity.MatchAccount("user_draintest01"),
	}
	if err := cursorsource.New(stateDir).Save(license); err != nil {
		t.Fatal(err)
	}
}

// TestRunPeriodicCursorPullFailureIsIncomplete pins the actual-failure
// leg: a cursor round whose upstream pull fails makes the otherwise
// clean run report itself incomplete and exit non-zero with the failure
// reason, and — with --progress-json — emit no "complete" progress
// event for the run.
func TestRunPeriodicCursorPullFailureIsIncomplete(t *testing.T) {
	server := newPeriodicDrainFakeServer(t)
	pull := &periodicFakePull{err: errors.New("synthetic upstream outage")}
	stateDir := armPeriodicCursorOnlyFixture(t, server, pull)

	args := []string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--sync-timeout", "30s",
		"--progress-json",
		"--verbose",
	}
	out, stderr, err := capturePeriodicStdoutAndStderr(t, func() error { return runPeriodic(args) })
	if err == nil {
		t.Fatalf("a failed account pull must exit non-zero, stdout:\n%s", out)
	}
	if !strings.Contains(err.Error(), "periodic incomplete: the account cursor source failed:") ||
		!strings.Contains(err.Error(), "cursor usage pull failed") {
		t.Fatalf("the incomplete exit must name the failed account pull, got %v", err)
	}
	// The verbose human line carries the STRUCTURED reason only (the
	// raw pull diagnostic is withheld as untrusted free text); the
	// returned error chain above keeps the full historical text.
	if !strings.Contains(out, "incomplete: the account cursor source failed this run; remaining work stays pending") {
		t.Fatalf("expected the failed-pull incomplete report, stdout:\n%s", out)
	}
	if !strings.Contains(out, "cursor sync: outcome=error pending=0") {
		t.Fatalf("the error outcome must be named explicitly, stdout:\n%s", out)
	}
	if pull.calls != 1 {
		t.Fatalf("the upstream must be pulled exactly once, got %d", pull.calls)
	}
	if strings.Contains(stderr, `"stage":"complete"`) {
		t.Fatalf("an incomplete run must not emit a complete progress event, stderr:\n%s", stderr)
	}
}

// TestRunPeriodicCursorRetryExhaustedIsIncomplete pins the retry
// exhaustion leg through the REAL policy the CLI builds (full jitter,
// run deadline pinned to --sync-timeout): in the legacy unbudgeted shape
// (explicit --max-batches, no shared total — nil budget, no rotation) a
// source-batch ingest that keeps answering 503 exhausts the retry
// budget, the round fails, and the run exits non-zero with the
// exhaustion reason while the batch stays pending and the upstream is
// never pulled. The jittered backoffs are real time (at most ~7s).
func TestRunPeriodicCursorRetryExhaustedIsIncomplete(t *testing.T) {
	server := newPeriodicDrainFakeServer(t)
	server.setSrcIngestStatus(http.StatusServiceUnavailable)
	pull := &periodicFakePull{}
	stateDir := armPeriodicCursorOnlyFixture(t, server, pull)
	seedPeriodicCursorBatch(t, stateDir, "cursor-retry-cli-1", 1)

	args := []string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--max-batches", "5",
		"--sync-timeout", "30s",
		"--verbose",
	}
	out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
	if err == nil {
		t.Fatalf("an exhausted account retry must exit non-zero, stdout:\n%s", out)
	}
	if !strings.Contains(err.Error(), "periodic incomplete: the account cursor source failed:") ||
		!strings.Contains(err.Error(), "giving up after 4 attempts") {
		t.Fatalf("the incomplete exit must name the retry exhaustion, got %v", err)
	}
	if !strings.Contains(out, "cursor sync: outcome=error pending=1") {
		t.Fatalf("the error outcome must be named explicitly, stdout:\n%s", out)
	}
	if got := server.srcIngest.Load(); got != 4 {
		t.Fatalf("the policy must make exactly four attempts, got %d", got)
	}
	if pull.calls != 0 {
		t.Fatalf("a failed drain-first must never read the credential or pull, pulls=%d", pull.calls)
	}
	if n := periodicCursorPending(t, stateDir); n != 1 {
		t.Fatalf("the failed batch must stay pending, got %d", n)
	}
}

// TestRunPeriodicCursorFenceFlipIsIncomplete pins the fence-drift leg:
// when the server moves the account source fence after the pull phase,
// the rotation's cursor step skips with the fence-change reason and the
// run exits non-zero as an authorization drift, preserving the queued
// batch.
func TestRunPeriodicCursorFenceFlipIsIncomplete(t *testing.T) {
	server := newPeriodicDrainFakeServer(t)
	pull := &periodicFakePull{}
	stateDir := armPeriodicCursorOnlyFixture(t, server, pull)
	seedPeriodicCursorBatch(t, stateDir, "cursor-fence-cli-1", 1)
	seedPeriodicCursorBatch(t, stateDir, "cursor-fence-cli-2", 1)
	// Self requests: 1 grant sync, 2 cursor pull phase, 3+ fence flipped.
	server.setFenceFromSelf(3, 4)

	args := []string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--sync-timeout", "30s",
		"--verbose",
	}
	out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
	if err == nil {
		t.Fatalf("a moved account fence must exit non-zero, stdout:\n%s", out)
	}
	if !strings.Contains(err.Error(), "periodic incomplete: the account cursor source stopped by an authorization or source-state change: cursor source fence changed; a full sync is required to recover pending history") {
		t.Fatalf("the incomplete exit must name the fence change, got %v", err)
	}
	if !strings.Contains(out, "cursor sync: outcome=fence_stop pending=1") {
		t.Fatalf("the fence-stop outcome must be named explicitly, stdout:\n%s", out)
	}
	if !strings.Contains(out, "cursor sync: stopped by an authorization or source-state change") {
		t.Fatalf("the skip state must stay visible (closed-set phrase), stdout:\n%s", out)
	}
	if n := periodicCursorPending(t, stateDir); n != 1 {
		t.Fatalf("the skipped batch must stay pending, got %d", n)
	}
}

// TestRunPeriodicCursorScopeExclusionVerdicts pins the §6.5 distinction
// between an INITIAL authorization exclusion (a verdict: exit zero, even
// with batches the authorization withholds queued) and a MID-RUN scope
// narrowing (a drift after work already ran: exit non-zero).
func TestRunPeriodicCursorScopeExclusionVerdicts(t *testing.T) {
	t.Run("initial_exclusion_is_a_verdict", func(t *testing.T) {
		server := newPeriodicDrainFakeServer(t)
		pull := &periodicFakePull{}
		stateDir := armPeriodicCursorOnlyFixture(t, server, pull)
		seedPeriodicCursorBatch(t, stateDir, "cursor-withheld-cli-1", 1)
		seedPeriodicCursorBatch(t, stateDir, "cursor-withheld-cli-2", 1)
		// The very first self view (the grant sync) already excludes the
		// cursor tool: no work of this round was ever allowed.
		server.setCursorDisallowedFromSelf(1)

		args := []string{
			"--state-dir", stateDir,
			"--server", server.URL,
			"--sync-timeout", "30s",
			"--verbose",
		}
		out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
		if err != nil {
			t.Fatalf("an authorization verdict must keep the historical exit zero: %v\nstdout:\n%s", err, out)
		}
		if strings.Contains(out, "incomplete:") {
			t.Fatalf("an authorization verdict must not report incompleteness, stdout:\n%s", out)
		}
		if !strings.Contains(out, "cursor sync: outcome=auth_withheld pending=2") {
			t.Fatalf("the withheld verdict must be named explicitly with its queued backlog, stdout:\n%s", out)
		}
		if pull.calls != 0 {
			t.Fatalf("an excluded account source must never be pulled, pulls=%d", pull.calls)
		}
		if n := periodicCursorPending(t, stateDir); n != 2 {
			t.Fatalf("the withheld batches stay queued, got %d", n)
		}
	})

	t.Run("mid_run_narrowing_is_drift", func(t *testing.T) {
		server := newPeriodicDrainFakeServer(t)
		pull := &periodicFakePull{}
		stateDir := armPeriodicCursorOnlyFixture(t, server, pull)
		seedPeriodicCursorBatch(t, stateDir, "cursor-narrow-cli-1", 1)
		seedPeriodicCursorBatch(t, stateDir, "cursor-narrow-cli-2", 1)
		// Self requests: 1 grant sync (cursor allowed), 2 cursor pull
		// phase (uploads one batch), 3+ scope narrowed to exclude
		// cursor — work already ran under the wider scope.
		server.setCursorDisallowedFromSelf(3)

		args := []string{
			"--state-dir", stateDir,
			"--server", server.URL,
			"--sync-timeout", "30s",
			"--verbose",
		}
		out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
		if err == nil {
			t.Fatalf("a mid-run scope narrowing after uploads must exit non-zero, stdout:\n%s", out)
		}
		if !strings.Contains(err.Error(), "periodic incomplete: the account cursor source stopped by an authorization or source-state change: cursor is not allowed by the effective server grant scope for this device") {
			t.Fatalf("the incomplete exit must name the mid-run narrowing, got %v", err)
		}
		if !strings.Contains(out, "cursor sync: outcome=fence_stop pending=1") {
			t.Fatalf("the narrowing must be classified as a drift, stdout:\n%s", out)
		}
		if got := server.srcIngest.Load(); got != 1 {
			t.Fatalf("exactly the pull phase's batch may upload before the narrowing, got %d", got)
		}
		if n := periodicCursorPending(t, stateDir); n != 1 {
			t.Fatalf("the narrowed-out batch must stay pending, got %d", n)
		}
	})
}

// TestRunPeriodicCursorNoPermitAndPausedPermitStayClean pins the
// no-false-positive legs: a device with no cursor permit at all, and one
// whose permit is paused (login expired) with batches still queued, both
// keep the historical exit zero — no permit and an unauthorized-disabled
// permit are verdicts, not partial completions.
func TestRunPeriodicCursorNoPermitAndPausedPermitStayClean(t *testing.T) {
	t.Run("no_permit", func(t *testing.T) {
		server := newPeriodicDrainFakeServer(t)
		stateDir := t.TempDir()
		bindPeriodicCLIDevice(t, stateDir, server.URL)
		writePeriodicDrainPendingBatch(t, stateDir, "batch-nopermit-cli-1", 1)

		args := []string{
			"--state-dir", stateDir,
			"--server", server.URL,
			"--sync-timeout", "30s",
			"--verbose",
		}
		out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
		if err != nil {
			t.Fatalf("a run without a cursor permit must exit zero: %v\nstdout:\n%s", err, out)
		}
		if strings.Contains(out, "incomplete:") {
			t.Fatalf("a run without a cursor permit must not report incompleteness, stdout:\n%s", out)
		}
		if !strings.Contains(out, "cursor sync: outcome=no_permit pending=0") {
			t.Fatalf("the absent permit must be named explicitly, stdout:\n%s", out)
		}
		// The closed-set skip phrase prints for a no-permit round too
		// (the permit was never loaded, so the Status gate would have
		// hidden it); the raw skip text never does.
		if !strings.Contains(out, "cursor sync: no local permit") {
			t.Fatalf("the no-permit closed phrase must print, stdout:\n%s", out)
		}
		if !strings.Contains(out, "syncedBatches=1 syncedRecords=1") {
			t.Fatalf("the device queue must still drain, stdout:\n%s", out)
		}
	})

	t.Run("paused_permit_with_pending", func(t *testing.T) {
		server := newPeriodicDrainFakeServer(t)
		pull := &periodicFakePull{}
		stateDir := armPeriodicCursorOnlyFixture(t, server, pull)
		// Replace the active permit with a login-expired one: the
		// authorization withholds the account source before any work.
		writePeriodicCursorPermitWithStatus(t, stateDir, cursorsource.StatusLoginExpired)
		seedPeriodicCursorBatch(t, stateDir, "cursor-expired-cli-1", 1)
		seedPeriodicCursorBatch(t, stateDir, "cursor-expired-cli-2", 1)

		args := []string{
			"--state-dir", stateDir,
			"--server", server.URL,
			"--sync-timeout", "30s",
			"--verbose",
		}
		out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
		if err != nil {
			t.Fatalf("a login-expired permit is an authorization verdict, not a run failure: %v\nstdout:\n%s", err, out)
		}
		if strings.Contains(out, "incomplete:") {
			t.Fatalf("a withheld permit must not report incompleteness, stdout:\n%s", out)
		}
		if !strings.Contains(out, "cursor sync: outcome=auth_withheld pending=2") {
			t.Fatalf("the withheld permit must be named explicitly with its queued backlog, stdout:\n%s", out)
		}
		if pull.calls != 0 {
			t.Fatalf("a paused permit must never be pulled, pulls=%d", pull.calls)
		}
	})
}

// TestRunPeriodicCursorBoundedPendingStaysClean pins the legacy
// bounded-pending compatibility: an explicit --max-batches leaves cursor
// batches queued at the per-run bound in both drain shapes (the
// unbudgeted legacy shape and the fair rotation with a per-queue bound)
// and the run stays exit zero with the bounded outcome named.
func TestRunPeriodicCursorBoundedPendingStaysClean(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"legacy_shape", []string{"--max-batches", "1"}},
		{"fair_shape_with_bound", []string{"--max-batches", "1", "--max-total-batches", "10"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newPeriodicDrainFakeServer(t)
			pull := &periodicFakePull{}
			stateDir := armPeriodicCursorOnlyFixture(t, server, pull)
			seedPeriodicCursorBatch(t, stateDir, "cursor-bound-cli-1", 1)
			seedPeriodicCursorBatch(t, stateDir, "cursor-bound-cli-2", 1)
			seedPeriodicCursorBatch(t, stateDir, "cursor-bound-cli-3", 1)

			args := append([]string{
				"--state-dir", stateDir,
				"--server", server.URL,
				"--sync-timeout", "30s",
				"--verbose",
			}, tc.args...)
			out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
			if err != nil {
				t.Fatalf("a normal bounded stop must keep the historical exit zero: %v\nstdout:\n%s", err, out)
			}
			if strings.Contains(out, "incomplete:") {
				t.Fatalf("a normal bounded stop must not report incompleteness, stdout:\n%s", out)
			}
			if !strings.Contains(out, "cursor sync: outcome=bounded pending=2") {
				t.Fatalf("the bounded outcome must be named explicitly, stdout:\n%s", out)
			}
			if !strings.Contains(out, "cursor sync: exportedBatches=0 syncedBatches=1 syncedRecords=1 pendingRemaining=2") {
				t.Fatalf("exactly one bounded batch may upload, stdout:\n%s", out)
			}
			if n := periodicCursorPending(t, stateDir); n != 2 {
				t.Fatalf("two batches must remain queued at the bound, got %d", n)
			}
		})
	}
}

// TestRunPeriodicCursorFenceRecoveryStaysClean pins the false-positive
// protection for an in-round fence RECOVERY: when the fence moved before
// the pull phase, Sync fences the stale batches out, resets the event
// ledger and re-pulls under the new fence in the SAME round — a fully
// recovered round stays exit zero despite the fence-change notes.
func TestRunPeriodicCursorFenceRecoveryStaysClean(t *testing.T) {
	server := newPeriodicDrainFakeServer(t)
	pull := &periodicFakePull{events: periodicCursorFixtureEvents()}
	stateDir := armPeriodicCursorOnlyFixture(t, server, pull)
	seedPeriodicCursorBatch(t, stateDir, "cursor-recover-cli-1", 1)
	seedPeriodicCursorBatch(t, stateDir, "cursor-recover-cli-2", 1)
	// The fence has already moved (3 -> 4) when the pull phase starts:
	// Sync recovers in-round instead of stopping.
	server.setFenceFromSelf(1, 4)

	args := []string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--sync-timeout", "30s",
		"--verbose",
	}
	out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
	if err != nil {
		t.Fatalf("an in-round fence recovery is a complete round: %v\nstdout:\n%s", err, out)
	}
	if strings.Contains(out, "incomplete:") || strings.Contains(out, "outcome=") {
		t.Fatalf("a recovered round must report neither incompleteness nor a stop outcome, stdout:\n%s", out)
	}
	// The fenced-out count lives only in the round's free-text note,
	// which verbose withholds by design; the recovery itself is proven
	// below by the clean exit, the re-pulled counts and the drained
	// queue state.
	if !strings.Contains(out, "cursor sync: note present (details withheld)") {
		t.Fatalf("the recovery note renders the withheld marker, stdout:\n%s", out)
	}
	if !strings.Contains(out, "cursor sync: exportedBatches=1 syncedBatches=1 syncedRecords=2 pendingRemaining=0") {
		t.Fatalf("the re-pulled history must upload, stdout:\n%s", out)
	}
	if n := periodicCursorPending(t, stateDir); n != 0 {
		t.Fatalf("nothing may remain queued after the recovery, got %d", n)
	}
}

// TestRunPeriodicCursorNoStableIDIsIncomplete pins the dropped-data leg:
// a pull whose events include rows without a stable upstream id leaves
// those events uncounted, and even an otherwise clean, fully drained
// round reports itself incomplete with the skipped count.
func TestRunPeriodicCursorNoStableIDIsIncomplete(t *testing.T) {
	server := newPeriodicDrainFakeServer(t)
	zero := int64(0)
	events := []api.UsageEvent{
		{
			// No UsageEventID: skipped by normalization, never counted.
			TimestampMS:     time.Now().Add(-2 * time.Hour).UnixMilli(),
			Model:           "cursor-claude-4.5",
			InputTokens:     &zero,
			OutputTokens:    &zero,
			CacheReadTokens: &zero,
		},
		{
			UsageEventID:     "usage-event-periodic-nostable-1",
			ConversationID:   "conv-usage-event-periodic-nostable-1",
			TimestampMS:      time.Now().Add(-90 * time.Minute).UnixMilli(),
			Model:            "cursor-claude-4.5",
			InputTokens:      &zero,
			OutputTokens:     &zero,
			CacheReadTokens:  &zero,
			CacheWriteTokens: &zero,
		},
	}
	pull := &periodicFakePull{events: events}
	stateDir := armPeriodicCursorOnlyFixture(t, server, pull)

	args := []string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--sync-timeout", "30s",
		"--verbose",
	}
	out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
	if err == nil {
		t.Fatalf("a round that dropped stable-id-less events must exit non-zero, stdout:\n%s", out)
	}
	if !strings.Contains(err.Error(), "periodic incomplete: the account cursor source skipped 1 usage event(s) without a stable upstream id") {
		t.Fatalf("the incomplete exit must name the dropped events, got %v", err)
	}
	if !strings.Contains(out, "cursor sync: pulledEvents=2 new=1 replaced=0 unchanged=0 noStableId=1") {
		t.Fatalf("the dropped event must be visible in the round summary, stdout:\n%s", out)
	}
	if !strings.Contains(out, "incomplete: the account cursor source skipped 1 usage event(s) without a stable upstream id (those events are not counted); remaining work stays pending") {
		t.Fatalf("expected the dropped-events incomplete report, stdout:\n%s", out)
	}
	if n := periodicCursorPending(t, stateDir); n != 0 {
		t.Fatalf("the counted records must fully drain, got %d pending", n)
	}
}

// TestRunPeriodicCursorLegacyPausedBacklogIsIncomplete pins the legacy
// (non-fair, explicit --max-batches) paused regression: when the cursor
// round is skipped because the device is paused while its queue still
// holds a backlog, the skip exit recounts the queue, so the run reports
// the paused account source with its real pending count and exits
// non-zero — an uncounted backlog must never let the run read as a
// clean paused no-op.
func TestRunPeriodicCursorLegacyPausedBacklogIsIncomplete(t *testing.T) {
	server := newPeriodicDrainFakeServer(t)
	pull := &periodicFakePull{}
	stateDir := armPeriodicCursorOnlyFixture(t, server, pull)
	seedPeriodicCursorBatch(t, stateDir, "cursor-legacy-pause-1", 1)
	seedPeriodicCursorBatch(t, stateDir, "cursor-legacy-pause-2", 1)
	// Self requests: 1 grant sync (clean), 2 cursor pull phase (paused
	// from there on). The legacy shape runs no rotation, so the pull
	// phase's skip exit is the run's final account-queue word.
	server.setPauseFromSelf(2)

	args := []string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--max-batches", "5",
		"--sync-timeout", "30s",
		"--verbose",
	}
	out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
	if err == nil {
		t.Fatalf("a paused account queue with a legacy backlog must exit non-zero, stdout:\n%s", out)
	}
	if !strings.Contains(err.Error(), "periodic incomplete: the account cursor source is paused with 2 batch(es) still pending") {
		t.Fatalf("the incomplete exit must name the paused backlog, got %v", err)
	}
	if !strings.Contains(out, "cursor sync: outcome=paused pending=2") {
		t.Fatalf("the paused skip must carry its recounted backlog, stdout:\n%s", out)
	}
	if !strings.Contains(out, "cursor sync: paused") {
		t.Fatalf("the paused skip state must stay visible (closed-set phrase), stdout:\n%s", out)
	}
	if got := server.srcIngest.Load(); got != 0 {
		t.Fatalf("a paused account queue must upload nothing, got %d", got)
	}
	if n := periodicCursorPending(t, stateDir); n != 2 {
		t.Fatalf("both batches must stay queued, got %d", n)
	}
}

// TestRunPeriodicCursorAccountSwitchAfterWorkIsDrift pins the work vs
// verdict split of the account-switch exit: a desktop login that
// switched accounts is a pre-work authorization verdict when nothing
// was sent this round (exit zero), but a mid-round drift when the
// drain-first already uploaded batches under the recorded account (exit
// non-zero) — in both the legacy and the fair drain shape.
func TestRunPeriodicCursorAccountSwitchAfterWorkIsDrift(t *testing.T) {
	const switchedAccount = "user_switchedtest01"

	t.Run("legacy_with_uploads_is_drift", func(t *testing.T) {
		server := newPeriodicDrainFakeServer(t)
		pull := &periodicFakePull{}
		stateDir := armPeriodicCursorOnlyFixture(t, server, pull)
		armPeriodicCursorFakesForAccount(t, pull, switchedAccount)
		seedPeriodicCursorBatch(t, stateDir, "cursor-switch-legacy-1", 1)

		args := []string{
			"--state-dir", stateDir,
			"--server", server.URL,
			"--max-batches", "5",
			"--sync-timeout", "30s",
			"--verbose",
		}
		out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
		if err == nil {
			t.Fatalf("an account switch after this round uploaded must exit non-zero, stdout:\n%s", out)
		}
		if !strings.Contains(err.Error(), "periodic incomplete: the account cursor source stopped by an authorization or source-state change: the desktop login switched to a different Cursor account") {
			t.Fatalf("the incomplete exit must name the mid-round account switch, got %v", err)
		}
		// Proof the drift classification rests on actual work: exactly
		// one batch left under the recorded account before the switch.
		if !strings.Contains(out, "cursor sync: exportedBatches=0 syncedBatches=1 syncedRecords=1") {
			t.Fatalf("the drain-first upload must be visible as the work that happened, stdout:\n%s", out)
		}
		if !strings.Contains(out, "cursor sync: outcome=fence_stop pending=0") {
			t.Fatalf("the post-upload switch must classify as a drift, stdout:\n%s", out)
		}
		if pull.calls != 0 {
			t.Fatalf("the switched round must never pull, pulls=%d", pull.calls)
		}
		if n := periodicCursorPending(t, stateDir); n != 0 {
			t.Fatalf("the uploaded batch is settled, got %d pending", n)
		}
	})

	t.Run("legacy_without_uploads_is_verdict", func(t *testing.T) {
		server := newPeriodicDrainFakeServer(t)
		pull := &periodicFakePull{}
		stateDir := armPeriodicCursorOnlyFixture(t, server, pull)
		armPeriodicCursorFakesForAccount(t, pull, switchedAccount)

		args := []string{
			"--state-dir", stateDir,
			"--server", server.URL,
			"--max-batches", "5",
			"--sync-timeout", "30s",
			"--verbose",
		}
		out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
		if err != nil {
			t.Fatalf("an account switch before any work is a verdict, not a run failure: %v\nstdout:\n%s", err, out)
		}
		if strings.Contains(out, "incomplete:") {
			t.Fatalf("a pre-work account switch must not report incompleteness, stdout:\n%s", out)
		}
		if !strings.Contains(out, "cursor sync: outcome=auth_withheld pending=0") {
			t.Fatalf("the pre-work switch must stay a withheld verdict, stdout:\n%s", out)
		}
		if !strings.Contains(out, "cursor sync: withheld by the current authorization") {
			t.Fatalf("the switch state must stay visible (closed-set phrase), stdout:\n%s", out)
		}
		if pull.calls != 0 {
			t.Fatalf("the switched round must never pull, pulls=%d", pull.calls)
		}
	})

	t.Run("fair_with_uploads_is_drift", func(t *testing.T) {
		server := newPeriodicDrainFakeServer(t)
		pull := &periodicFakePull{}
		stateDir := armPeriodicCursorOnlyFixture(t, server, pull)
		armPeriodicCursorFakesForAccount(t, pull, switchedAccount)
		seedPeriodicCursorBatch(t, stateDir, "cursor-switch-fair-1", 1)
		seedPeriodicCursorBatch(t, stateDir, "cursor-switch-fair-2", 1)

		args := []string{
			"--state-dir", stateDir,
			"--server", server.URL,
			"--sync-timeout", "30s",
			"--verbose",
		}
		out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
		if err == nil {
			t.Fatalf("an account switch after the pull phase uploaded must exit non-zero, stdout:\n%s", out)
		}
		if !strings.Contains(err.Error(), "periodic incomplete: the account cursor source stopped by an authorization or source-state change: the desktop login switched to a different Cursor account") {
			t.Fatalf("the incomplete exit must name the mid-round account switch, got %v", err)
		}
		if !strings.Contains(out, "cursor sync: outcome=fence_stop pending=1") {
			t.Fatalf("the post-upload switch must classify as a drift with its queued remainder, stdout:\n%s", out)
		}
		if got := server.srcIngest.Load(); got != 1 {
			t.Fatalf("exactly the pull phase's batch may upload before the switch, got %d", got)
		}
		if n := periodicCursorPending(t, stateDir); n != 1 {
			t.Fatalf("the second batch must stay queued, got %d", n)
		}
	})
}

// TestPeriodicCursorIncompleteMatrix unit-pins the CLI judgment table
// itself: which structured outcomes (plus the pending and stable-id
// facts) turn a successful run non-zero, and which stay clean.
func TestPeriodicCursorIncompleteMatrix(t *testing.T) {
	cases := []struct {
		name       string
		cursor     cursorsync.Result
		incomplete bool
		reason     string
	}{
		{name: "absent", cursor: cursorsync.Result{Outcome: cursorsync.RoundAbsent}},
		{name: "ran", cursor: cursorsync.Result{Outcome: cursorsync.RoundRan}},
		{name: "ran_with_pending_is_not_judged", cursor: cursorsync.Result{Outcome: cursorsync.RoundRan, PendingRemaining: 3}},
		{name: "bounded_with_pending", cursor: cursorsync.Result{Outcome: cursorsync.RoundBounded, PendingRemaining: 3}},
		{name: "no_permit_with_pending", cursor: cursorsync.Result{Outcome: cursorsync.RoundNoPermit, PendingRemaining: 3}},
		{name: "auth_withheld_with_pending", cursor: cursorsync.Result{Outcome: cursorsync.RoundAuthWithheld, PendingRemaining: 3}},
		{
			name:       "paused_without_pending",
			cursor:     cursorsync.Result{Outcome: cursorsync.RoundPaused},
			incomplete: false,
		},
		{
			name:       "paused_with_pending",
			cursor:     cursorsync.Result{Outcome: cursorsync.RoundPaused, PendingRemaining: 2},
			incomplete: true,
			reason:     "is paused with 2 batch(es) still pending",
		},
		{
			name:       "fence_stop",
			cursor:     cursorsync.Result{Outcome: cursorsync.RoundFenceStop},
			incomplete: true,
			reason:     "stopped by an authorization or source-state change: the round did not complete",
		},
		{
			name:       "error",
			cursor:     cursorsync.Result{Outcome: cursorsync.RoundError, Skipped: "cursor usage pull failed"},
			incomplete: true,
			reason:     "failed: cursor usage pull failed",
		},
		{
			name:       "no_stable_id_overrides_clean_round",
			cursor:     cursorsync.Result{Outcome: cursorsync.RoundRan, SkippedNoStableID: 2},
			incomplete: true,
			reason:     "skipped 2 usage event(s) without a stable upstream id (those events are not counted)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason, incomplete := periodicCursorIncomplete(tc.cursor)
			if incomplete != tc.incomplete {
				t.Fatalf("incomplete = %t, want %t (reason %q)", incomplete, tc.incomplete, reason)
			}
			if tc.reason != "" && reason != tc.reason {
				t.Fatalf("reason = %q, want %q", reason, tc.reason)
			}
		})
	}
}

// TestPeriodicCursorDiagnosticPrefersSkipReason unit-pins the display
// helper: the skip reason wins, the first note segment is the fallback,
// and a bare round gets a generic phrase.
func TestPeriodicCursorDiagnosticPrefersSkipReason(t *testing.T) {
	if got := cursorDiagnostic(cursorsync.Result{Skipped: "the reason", Note: "a; b"}); got != "the reason" {
		t.Fatalf("skip reason must win, got %q", got)
	}
	if got := cursorDiagnostic(cursorsync.Result{Note: "first; second"}); got != "first" {
		t.Fatalf("the first note segment is the fallback, got %q", got)
	}
	if got := cursorDiagnostic(cursorsync.Result{Note: "only"}); got != "only" {
		t.Fatalf("a single note is used whole, got %q", got)
	}
	if got := cursorDiagnostic(cursorsync.Result{}); got != "the round did not complete" {
		t.Fatalf("a bare round gets the generic phrase, got %q", got)
	}
}
