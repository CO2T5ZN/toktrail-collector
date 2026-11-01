package collection

// Injection tests for the §6.5 structured stop codes: every high-risk
// stop path of a collection run must record its closed DrainStopCode /
// GrantSkipCode at the same site as the historical human message, so
// the stable summary classifies from structure and never matches text.
// Everything is synthetic (tempdir state, fake servers, no real
// credentials, no real Cursor state); these tests only ADD assertions
// on the new codes — the human messages and exit semantics stay pinned
// by the pre-existing tests.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/syncbudget"
)

// TestStopCodeBoundedDrain pins the legacy per-queue bound stop: an
// explicit MaxBatches reached with batches still pending records
// DrainStopBounded — the exit-zero bounded shape, never a budget code.
func TestStopCodeBoundedDrain(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)
	writePendingBatch(t, stateDir, "batch-code-bounded-1")
	writePendingBatch(t, stateDir, "batch-code-bounded-2")
	writePendingBatch(t, stateDir, "batch-code-bounded-3")

	res, err := Run(context.Background(), Options{StateDir: stateDir, MaxBatches: 2})
	if err != nil {
		t.Fatalf("a bounded stop keeps the historical nil error: %v", err)
	}
	if res.PendingRemaining != 1 || res.DrainStopped == "" {
		t.Fatalf("expected the bounded remainder and message, got %+v", res)
	}
	if res.DrainStop != DrainStopBounded {
		t.Fatalf("bounded stop must record DrainStopBounded, got %q (message %q)", res.DrainStop, res.DrainStopped)
	}
}

// newFailingUploadServer answers the device self preflight but fails
// every ingest upload with a server error (the same shape
// TestRunStopsDrainOnUploadFailure uses).
func newFailingUploadServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			writeJSONForTest(w, http.StatusOK, map[string]any{"device": map[string]any{
				"deviceId": "dev-1", "applicationId": "app-1", "externalSubjectId": "sub-1",
				"deviceName": "collector", "platform": "darwin", "consentRevision": 7,
				"uploadAuthorized": true, "publicAuthorized": false, "revoked": false,
				"checkedAt": "2026-10-21T04:00:00Z",
			}})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	return server
}

// TestStopCodeUploadFailure pins the failed-upload stop: a server error
// on the ingest POST records DrainStopFailed alongside the error.
func TestStopCodeUploadFailure(t *testing.T) {
	stateDir := t.TempDir()
	server := newFailingUploadServer(t)
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)
	writePendingBatch(t, stateDir, "batch-code-fail-1")
	writePendingBatch(t, stateDir, "batch-code-fail-2")

	res, err := Run(context.Background(), Options{StateDir: stateDir})
	if err == nil {
		t.Fatal("expected the upload failure to surface")
	}
	if res.PendingRemaining < 1 || res.DrainStopped == "" {
		t.Fatalf("expected the failure remainder and message, got %+v", res)
	}
	if res.DrainStop != DrainStopFailed {
		t.Fatalf("upload failure must record DrainStopFailed, got %q (message %q)", res.DrainStop, res.DrainStopped)
	}
}

// TestStopCodeBudgetDecline pins the shared-budget stop: a decline of
// the run's POST budget before an ingest records DrainStopBudget (the
// declined batch was never POSTed and stays pending).
func TestStopCodeBudgetDecline(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)
	writePendingBatch(t, stateDir, "batch-code-budget-1")
	writePendingBatch(t, stateDir, "batch-code-budget-2")

	budget := syncbudget.New(syncbudget.WithTotal(1))
	res, err := Run(context.Background(), Options{StateDir: stateDir, Budget: budget})
	if err == nil || !errors.Is(err, syncbudget.ErrTotalExhausted) {
		t.Fatalf("expected the budget decline to fail the run, got %v", err)
	}
	if res.PendingRemaining != 1 || res.DrainStopped == "" {
		t.Fatalf("expected the declined remainder and message, got %+v", res)
	}
	if res.DrainStop != DrainStopBudget {
		t.Fatalf("budget decline must record DrainStopBudget, got %q (message %q)", res.DrainStop, res.DrainStopped)
	}
}

// TestStopCodePauseMidDrain pins the server-pause stop: a pause that
// lands between the grant sync and an upload records DrainStopPaused
// and keeps the nil error (pause is a state, not a run failure).
func TestStopCodePauseMidDrain(t *testing.T) {
	stateDir := t.TempDir()
	server := startBudgetFakeServer(t)
	bindCursorDevice(t, stateDir, server.URL)
	writeCursorPermit(t, stateDir)
	budgetGrantSession(t, stateDir)
	seedCursorPendingBatch(t, stateDir, "cursor-code-pause-1", 1)
	writePendingBatch(t, stateDir, "device-code-pause-1")
	// Self requests: 1 grant sync, 2 cursor round, 3 device preflight —
	// the third and later answer the paused view.
	server.setPauseFromSelfRequest(3)

	budget := syncbudget.New(syncbudget.WithTotal(5))
	pull := &fakeCursorPull{}
	res, _, err := runBudgetPeriodic(t, stateDir, server.URL, server, budget, pull)
	if err != nil {
		t.Fatalf("a mid-run pause must keep the historical nil error: %v", err)
	}
	if res.PendingRemaining != 1 || res.DrainStopped == "" {
		t.Fatalf("expected the paused remainder and message, got %+v", res)
	}
	if res.DrainStop != DrainStopPaused {
		t.Fatalf("pause must record DrainStopPaused, got %q (message %q)", res.DrainStop, res.DrainStopped)
	}
}

// TestStopCodeScopeDriftDuringBacklogDrain pins the authorization-drift
// stop of a drain-only round with grant refreshes (connect's backlog
// shape): a consent revision that moves between the round's two grant
// refreshes records DrainStopScope.
func TestStopCodeScopeDriftDuringBacklogDrain(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 11)
	// The first grant-ack switches the served view to a newer revision,
	// so the round's second grant refresh observes a different revision
	// than the first (without failing the ack itself).
	server.advanceOnAck = &grantView{paused: false, tools: []string{"Claude Code"}, revision: 12}
	bindDevice(t, stateDir, server.URL)
	writePendingBatch(t, stateDir, "batch-code-scope-1")

	lock, err := runlock.Acquire(stateDir)
	if err != nil {
		t.Fatalf("acquire state lock: %v", err)
	}
	defer lock.Close()
	res, err := DrainPendingLocked(context.Background(), Options{
		StateDir:           stateDir,
		RefreshDrainGrants: true,
	}, lock)
	if err != nil {
		t.Fatalf("the drifted backlog drain keeps the historical nil error: %v", err)
	}
	if res.DrainStopped == "" {
		t.Fatalf("expected the drift message, got %+v", res)
	}
	if res.DrainStop != DrainStopScope {
		t.Fatalf("authorization drift must record DrainStopScope, got %q (message %q)", res.DrainStop, res.DrainStopped)
	}
}

// TestStopCodeSkipDeviceDrainNotRun pins the count-only pass: a drain
// round that deliberately never attempts the device queue records
// DrainStopNotRun while reporting the honest pending count.
func TestStopCodeSkipDeviceDrainNotRun(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)
	writePendingBatch(t, stateDir, "batch-code-notrun-1")

	lock, err := runlock.Acquire(stateDir)
	if err != nil {
		t.Fatalf("acquire state lock: %v", err)
	}
	defer lock.Close()
	res, err := DrainPendingLocked(context.Background(), Options{
		StateDir:           stateDir,
		SkipDeviceDrain:    true,
		RefreshDrainGrants: true,
	}, lock)
	if err != nil {
		t.Fatalf("the count-only pass keeps the historical nil error: %v", err)
	}
	if res.PendingRemaining != 1 {
		t.Fatalf("the count-only pass must report the pending count, got %+v", res)
	}
	if res.DrainStop != DrainStopNotRun {
		t.Fatalf("count-only pass must record DrainStopNotRun, got %q", res.DrainStop)
	}
}

// TestStopCodeGrantOutcomeCodes pins the GrantSkipCode twins of the
// per-grant skip messages: exported, no_new_records (a second run over
// an unchanged source), not_allowed (the server scope excludes the
// source), input_inaccessible (the granted directory vanished), and
// export_failed (the granted input no longer reads).
func TestStopCodeGrantOutcomeCodes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 000 does not reliably make files unreadable to the current user on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses permission-based unreadable inputs")
	}
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 11)
	bindDevice(t, stateDir, server.URL)

	// exported: a healthy Claude session under the allowed scope.
	claude := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, claude, "s.jsonl",
		claudeLine(t, "2026-10-26T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))
	enableGrant(t, stateDir, "claude-code-jsonl", claude)
	// not_allowed: a codex grant the served scope excludes.
	codex := filepath.Join(t.TempDir(), "codex")
	writeCodexSession(t, codex, "rollout-a.jsonl",
		codexTokenCount("2026-10-26T04:00:00Z", 100, 0, 0, 50))
	enableGrant(t, stateDir, "codex-jsonl", codex)
	// input_inaccessible: a grant whose directory is removed after the
	// grant was recorded (the store validates existence at enable time).
	vanished := filepath.Join(t.TempDir(), "vanished")
	if err := os.MkdirAll(vanished, 0o700); err != nil {
		t.Fatal(err)
	}
	enableGrant(t, stateDir, "claude-code-jsonl", vanished)
	if err := os.RemoveAll(vanished); err != nil {
		t.Fatal(err)
	}
	// export_failed: an existing directory whose file cannot be read.
	unreadable := filepath.Join(t.TempDir(), "unreadable")
	input := writeClaudeSession(t, unreadable, "u.jsonl",
		claudeLine(t, "2026-10-26T04:00:00Z", "u1", "msg_1", claudeUsage(10, 0, 0, 5)))
	enableGrant(t, stateDir, "claude-code-jsonl", unreadable)
	if err := os.Chmod(input, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(input, 0o600) })

	res, err := Run(context.Background(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]GrantSkipCode{}
	for _, outcome := range res.GrantOutcomes {
		codes[outcome.Input] = outcome.Code
	}
	if got := codes[claude]; got != GrantExported {
		t.Fatalf("the healthy grant must record GrantExported, got %q (outcomes %+v)", got, res.GrantOutcomes)
	}
	if got := codes[codex]; got != GrantNotAllowed {
		t.Fatalf("the scope-excluded grant must record GrantNotAllowed, got %q (outcomes %+v)", got, res.GrantOutcomes)
	}
	if got := codes[vanished]; got != GrantInputInaccessible {
		t.Fatalf("the vanished grant must record GrantInputInaccessible, got %q (outcomes %+v)", got, res.GrantOutcomes)
	}
	if got := codes[unreadable]; got != GrantExportFailed {
		t.Fatalf("the unreadable grant must record GrantExportFailed, got %q (outcomes %+v)", got, res.GrantOutcomes)
	}

	// no_new_records: an unchanged source on the next run.
	res2, err := Run(context.Background(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	for _, outcome := range res2.GrantOutcomes {
		if outcome.Input == claude && outcome.Code != GrantNoNewRecords {
			t.Fatalf("the unchanged grant must record GrantNoNewRecords, got %q (outcomes %+v)", outcome.Code, res2.GrantOutcomes)
		}
	}
}

// TestStopCodePauseDuringBacklogDrainIsNotScope pins the paused/scope
// split of the second authorization check (review item A): a pause
// that lands mid-drain records DrainStopPaused — never the scope code
// — while an actual revision drift (the sibling test above) keeps
// DrainStopScope.
func TestStopCodePauseDuringBacklogDrainIsNotScope(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 11)
	// The first grant-ack switches the served view to PAUSED, so the
	// round's second grant refresh observes a pause (not a revision
	// drift).
	server.advanceOnAck = &grantView{paused: true, tools: []string{"Claude Code"}, revision: 11}
	bindDevice(t, stateDir, server.URL)
	writePendingBatch(t, stateDir, "batch-code-pause-mid-1")

	lock, err := runlock.Acquire(stateDir)
	if err != nil {
		t.Fatalf("acquire state lock: %v", err)
	}
	defer lock.Close()
	res, err := DrainPendingLocked(context.Background(), Options{
		StateDir:           stateDir,
		RefreshDrainGrants: true,
	}, lock)
	if err != nil {
		t.Fatalf("the paused backlog drain keeps the historical nil error: %v", err)
	}
	if res.DrainStopped == "" {
		t.Fatalf("expected the pause message, got %+v", res)
	}
	if res.DrainStop != DrainStopPaused {
		t.Fatalf("a mid-drain pause must record DrainStopPaused, got %q (message %q)", res.DrainStop, res.DrainStopped)
	}
	if !res.PendingCounted {
		t.Fatalf("the drain already measured the queue before the pause: %+v", res)
	}
}

// TestProgressCompleteSuppressedAfterDrift pins review item A's
// progress contract: a drain-only round whose second authorization
// refresh observes a drift emits NO "complete" progress event — the
// run did not finish cleanly, so it may never claim completion.
func TestProgressCompleteSuppressedAfterDrift(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 11)
	server.advanceOnAck = &grantView{paused: false, tools: []string{"Claude Code"}, revision: 12}
	bindDevice(t, stateDir, server.URL)
	writePendingBatch(t, stateDir, "batch-progress-drift-1")

	var events []ProgressEvent
	lock, err := runlock.Acquire(stateDir)
	if err != nil {
		t.Fatalf("acquire state lock: %v", err)
	}
	defer lock.Close()
	_, err = DrainPendingLocked(context.Background(), Options{
		StateDir:           stateDir,
		RefreshDrainGrants: true,
		Progress: func(e ProgressEvent) {
			events = append(events, e)
		},
	}, lock)
	if err != nil {
		t.Fatalf("the drifted drain keeps the historical nil error: %v", err)
	}
	for _, e := range events {
		if e.Kind == ProgressCount && e.Stage == "complete" {
			t.Fatalf("a drifted round must not emit the complete event: %+v", events)
		}
	}
	// The same round without the drift (a fresh state) still emits it.
	stateDir2 := t.TempDir()
	server.setView(t, false, []string{"Claude Code"}, 11)
	bindDevice(t, stateDir2, server.URL)
	writePendingBatch(t, stateDir2, "batch-progress-clean-1")
	var events2 []ProgressEvent
	lock2, err := runlock.Acquire(stateDir2)
	if err != nil {
		t.Fatalf("acquire state lock: %v", err)
	}
	defer lock2.Close()
	if _, err := DrainPendingLocked(context.Background(), Options{
		StateDir:           stateDir2,
		RefreshDrainGrants: true,
		Progress: func(e ProgressEvent) {
			events2 = append(events2, e)
		},
	}, lock2); err != nil {
		t.Fatalf("the clean drain must succeed: %v", err)
	}
	found := false
	for _, e := range events2 {
		if e.Kind == ProgressCount && e.Stage == "complete" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a clean round must still emit the complete event: %+v", events2)
	}
}
