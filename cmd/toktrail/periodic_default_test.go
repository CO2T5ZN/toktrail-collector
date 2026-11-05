package main

// §6.2 default-profile coverage for the periodic CLI entry
// (runPeriodic), exercised through the real flag parsing, budget plan,
// result rendering and collection wiring like a user invocation:
//
//   - the default (no explicit --max-batches / --max-total-batches)
//     drains a device backlog far beyond the historical per-queue bound
//     of 5 in ONE run, exit zero (drain-only included);
//   - the default runs the §6.2 fair rotation over BOTH queues: with a
//     granted scannable source and an armed account source, the run
//     scans once, pulls once, and uploads strictly alternating device
//     and cursor batches until both queues are empty;
//   - an explicit --max-batches 200 is never truncated by the default
//     shared total of 100 (the historical unbudgeted shape);
//   - an explicit --max-total-batches caps the run's total POSTs and
//     exits non-zero (incomplete) with work left; the default 100-POST
//     budget does the same when the backlog exceeds it; an empty-queue
//     default run exits zero;
//   - a mid-run pause keeps the SKIPPED queue's known pending count
//     (never zeroed) and stops the rotation without spinning (a bounded
//     number of server preflights);
//   - periodicUploadPlan arms 100 POSTs inside a deadline of exactly
//     the effective --sync-timeout window (20 minutes by default; an
//     explicit 5m / 30s widens or narrows it), keeps the explicit
//     legacy bound unbudgeted, and combines explicit totals with the
//     fair rotation.
//
// Everything is synthetic: tempdir state directories (never the real
// TOKTRAIL_HOME, which the explicit --state-dir flag overrides), an
// httptest fake for the ingest server, seeded pending batches, and —
// through the periodicCursorOptions test seam — synthetic cursor
// auth/verify/pull providers. No test reads real tool state, real
// Cursor credentials, or performs any network access beyond the fake
// server.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/cursor/api"
	"toktrail-collector/internal/cursor/auth"
	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/cursor/usage"
	"toktrail-collector/internal/local/cursoroutbox"
	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncbudget"
)

// bindPeriodicCLIDevice writes a bound device state pointing at the fake
// server so the run uses the injected HTTP transport without any
// implicit rebind. The application/subject ids mirror the fake server's
// self view so the cursor round's subject namespace derives cleanly.
func bindPeriodicCLIDevice(t *testing.T, stateDir, serverURL string) {
	t.Helper()
	if err := statedir.New(stateDir).Save(statedir.DeviceState{
		ServerURL:         serverURL,
		DeviceID:          "dev-drain-1",
		DeviceSecret:      periodicDrainSecret,
		ApplicationID:     "app-drain-1",
		ExternalSubjectID: "sub-drain-1",
	}); err != nil {
		t.Fatal(err)
	}
}

// enablePeriodicCLIGrant records a claude-code-jsonl grant over the
// given session directory.
func enablePeriodicCLIGrant(t *testing.T, stateDir, sessions string) {
	t.Helper()
	if err := os.MkdirAll(sessions, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := grants.New(stateDir).Enable("claude-code-jsonl", sessions); err != nil {
		t.Fatal(err)
	}
}

// Obvious synthetic cursor fixtures; never real credentials. The
// account id matches writePeriodicDrainCursorPermit's recorded
// AccountMatchID so the armed permit collects for this fake login.
const (
	periodicCursorAccountID   = "user_draintest01"
	periodicCursorAccessToken = "synthetic-periodic-access-token-not-real"
	periodicCursorSessionTok  = "synthetic-periodic-session-token-not-real"
)

// periodicFakeAuth hands out a synthetic credential and counts reads.
type periodicFakeAuth struct{ fetches int }

func (f *periodicFakeAuth) Fetch(ctx context.Context) (auth.Credential, error) {
	f.fetches++
	return auth.Credential{
		AccessToken: periodicCursorAccessToken,
		AccountHint: periodicCursorAccountID,
		Source:      "periodic-test-fixture",
	}, nil
}

// periodicFakeVerify validates the synthetic credential without
// touching Cursor.
func periodicFakeVerify(ctx context.Context, accessToken string) (api.VerifyResult, error) {
	if accessToken != periodicCursorAccessToken {
		return api.VerifyResult{}, fmt.Errorf("unexpected credential handed to verify: %d bytes", len(accessToken))
	}
	return api.VerifyResult{
		AccountID:    periodicCursorAccountID,
		SessionToken: periodicCursorSessionTok,
	}, nil
}

// periodicFakePull serves synthetic events inside the requested window
// and counts calls so a test can prove the upstream was pulled once. A
// non-nil err makes every pull fail with it (the upstream-outage shape).
type periodicFakePull struct {
	events []api.UsageEvent
	calls  int
	err    error
}

func (f *periodicFakePull) Pull(ctx context.Context, sessionToken string, from, to time.Time) ([]api.UsageEvent, error) {
	if sessionToken != periodicCursorSessionTok {
		return nil, fmt.Errorf("pull called with an unverified session token")
	}
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	var out []api.UsageEvent
	for _, ev := range f.events {
		ts := time.UnixMilli(ev.TimestampMS)
		if (from.IsZero() || !ts.Before(from)) && ts.Before(to) {
			out = append(out, ev)
		}
	}
	return out, nil
}

// periodicCursorFixtureEvents returns two synthetic events well inside
// any realistic pull window.
func periodicCursorFixtureEvents() []api.UsageEvent {
	mk := func(id string, age time.Duration, in, out int64) api.UsageEvent {
		zero := int64(0)
		return api.UsageEvent{
			UsageEventID:     id,
			ConversationID:   "conv-" + id,
			TimestampMS:      time.Now().Add(-age).UnixMilli(),
			Model:            "cursor-claude-4.5",
			InputTokens:      &in,
			OutputTokens:     &out,
			CacheReadTokens:  &zero,
			CacheWriteTokens: &zero,
		}
	}
	return []api.UsageEvent{
		mk("usage-event-periodic-alpha", 2*time.Hour, 120, 30),
		mk("usage-event-periodic-beta", 90*time.Minute, 80, 20),
	}
}

// armPeriodicCursorFakes swaps the periodic cursor wiring for synthetic
// providers (the production wiring would read the real desktop
// credential; these tests must never do that).
func armPeriodicCursorFakes(t *testing.T, pull *periodicFakePull) *periodicFakeAuth {
	return armPeriodicCursorFakesForAccount(t, pull, periodicCursorAccountID)
}

// armPeriodicCursorFakesForAccount is armPeriodicCursorFakes with the
// verified account id overridable, so a test can model a desktop login
// that switched to a different Cursor account than the permit recorded.
func armPeriodicCursorFakesForAccount(t *testing.T, pull *periodicFakePull, accountID string) *periodicFakeAuth {
	t.Helper()
	authFake := &periodicFakeAuth{}
	old := periodicCursorOptions
	periodicCursorOptions = func(stateDir, serverURL string, httpClient *http.Client) (*cursorsync.Options, error) {
		return &cursorsync.Options{
			StateDir:   stateDir,
			ServerURL:  serverURL,
			HTTPClient: httpClient,
			Auth:       authFake,
			Verify: func(ctx context.Context, accessToken string) (api.VerifyResult, error) {
				if accessToken != periodicCursorAccessToken {
					return api.VerifyResult{}, fmt.Errorf("unexpected credential handed to verify: %d bytes", len(accessToken))
				}
				return api.VerifyResult{
					AccountID:    accountID,
					SessionToken: periodicCursorSessionTok,
				}, nil
			},
			Pull: pull.Pull,
		}, nil
	}
	t.Cleanup(func() { periodicCursorOptions = old })
	return authFake
}

// armPeriodicCursorSource arms the fake server's self view with the
// permit's account source so the cursor round finds its executor
// designation.
func armPeriodicCursorSource(s *periodicDrainFakeServer) {
	s.setAccountSources([]protocol.Source{{
		SourceInstanceID: "cursor-src-drain-1",
		SourceType:       protocol.SourceType,
		State:            "active",
		FenceVersion:     3,
		NextRevision:     7,
	}})
}

// seedPeriodicCursorBatch persists a hand-built pending cursor batch
// for the armed account source (fence 3, valid event revisions).
func seedPeriodicCursorBatch(t *testing.T, stateDir, batchID string, n int) {
	t.Helper()
	records := make([]protocol.Event, 0, n)
	for i := 0; i < n; i++ {
		records = append(records, protocol.Event{
			EventKey:       protocol.EventKeyPrefix + strings.Repeat("0", 63) + strconv.Itoa(i+1),
			Revision:       7,
			Kind:           "event",
			OccurredAt:     "2026-10-30T03:00:00Z",
			Tool:           protocol.Tool,
			AdapterVersion: usage.AdapterVersion,
			SourceType:     protocol.SourceType,
		})
	}
	batch := protocol.Batch{BatchID: batchID, SourceInstanceID: "cursor-src-drain-1", Records: records}
	encoded, err := protocol.EncodeBatch(batch)
	if err != nil {
		t.Fatalf("encode seed cursor batch: %v", err)
	}
	if _, err := cursoroutbox.New(stateDir).AddBatch(batch, 3, encoded); err != nil {
		t.Fatalf("seed pending cursor batch: %v", err)
	}
}

// periodicCursorPending counts the pending cursor batches.
func periodicCursorPending(t *testing.T, stateDir string) int {
	t.Helper()
	n, err := cursoroutbox.New(stateDir).CountPending()
	if err != nil {
		t.Fatalf("count pending cursor batches: %v", err)
	}
	return n
}

// assertPeriodicAlternation fails unless consecutive recorded uploads
// come from different queues.
func assertPeriodicAlternation(t *testing.T, order []periodicUpload) {
	t.Helper()
	if len(order) == 0 {
		t.Fatal("expected at least one recorded upload")
	}
	for i := 1; i < len(order); i++ {
		if order[i].Queue == order[i-1].Queue {
			t.Fatalf("uploads %d and %d came from the same queue (%s) — the rotation is not fair: %+v", i-1, i, order[i].Queue, order)
		}
	}
}

// TestRunPeriodicDefaultDrainsBeyondLegacyBound pins the §6.2 default:
// with NO explicit bounds a periodic run drains a seven-batch device
// backlog in one pass (the historical per-queue default bound of 5 must
// not stop it), exit zero, with no incomplete report. The drain-only
// entry behaves the same and never touches the account source.
func TestRunPeriodicDefaultDrainsBeyondLegacyBound(t *testing.T) {
	t.Run("full_mode", func(t *testing.T) {
		stateDir, server := budgetCLIFixture(t)
		// budgetCLIFixture seeds three batches; add four more.
		writePeriodicDrainPendingBatch(t, stateDir, "batch-default-4", 1)
		writePeriodicDrainPendingBatch(t, stateDir, "batch-default-5", 1)
		writePeriodicDrainPendingBatch(t, stateDir, "batch-default-6", 1)
		writePeriodicDrainPendingBatch(t, stateDir, "batch-default-7", 1)

		args := []string{
			"--state-dir", stateDir,
			"--server", server.URL,
			"--sync-timeout", "30s",
			"--verbose",
		}
		out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
		if err != nil {
			t.Fatalf("the default run must drain the whole backlog: %v\nstdout:\n%s", err, out)
		}
		if !strings.Contains(out, "syncedBatches=7 syncedRecords=7") {
			t.Fatalf("expected all seven batches to drain in one default run, stdout:\n%s", out)
		}
		for _, forbidden := range []string{"pendingRemaining=", "incomplete:"} {
			if strings.Contains(out, forbidden) {
				t.Fatalf("a fully drained default run must not report %q, stdout:\n%s", forbidden, out)
			}
		}
		if got := server.ingest.Load(); got != 7 {
			t.Fatalf("expected exactly seven ingest uploads, got %d", got)
		}
	})

	t.Run("drain_only", func(t *testing.T) {
		stateDir := t.TempDir()
		server := newPeriodicDrainFakeServer(t)
		bindPeriodicCLIDevice(t, stateDir, server.URL)
		for i := 1; i <= 7; i++ {
			writePeriodicDrainPendingBatch(t, stateDir, fmt.Sprintf("batch-drain-default-%d", i), 1)
		}
		// An armed account source must stay untouched: drain-only is
		// device-only by construction.
		writePeriodicDrainCursorPermit(t, stateDir)
		armPeriodicCursorSource(server)

		args := []string{
			"--state-dir", stateDir,
			"--server", server.URL,
			"--drain-only",
			"--sync-timeout", "30s",
			"--verbose",
		}
		out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
		if err != nil {
			t.Fatalf("the default drain-only run must drain the whole backlog: %v\nstdout:\n%s", err, out)
		}
		if !strings.Contains(out, "syncedBatches=7 syncedRecords=7") {
			t.Fatalf("expected all seven batches to drain, stdout:\n%s", out)
		}
		if got := server.ingest.Load(); got != 7 {
			t.Fatalf("expected exactly seven ingest uploads, got %d", got)
		}
		if got := server.srcIngest.Load(); got != 0 {
			t.Fatalf("drain-only must never touch the account queue, got %d source-batch POSTs", got)
		}
	})
}

// TestRunPeriodicDefaultFairRotationDualQueue pins the §6.2 rotation and
// the once-only scan/pull at the CLI level: with a granted scannable
// session, an armed account source, and two pending batches in each
// queue, the default run scans the grant exactly once (one exported
// batch), pulls the account upstream exactly once (one new cursor
// batch), and uploads all six batches in strict device/cursor
// alternation until both queues are empty.
func TestRunPeriodicDefaultFairRotationDualQueue(t *testing.T) {
	stateDir := t.TempDir()
	server := newPeriodicDrainFakeServer(t)
	armPeriodicCursorSource(server)
	bindPeriodicCLIDevice(t, stateDir, server.URL)
	writePeriodicDrainCursorPermit(t, stateDir)
	pull := &periodicFakePull{events: periodicCursorFixtureEvents()}
	authFake := armPeriodicCursorFakes(t, pull)

	sessions := filepath.Join(t.TempDir(), "sessions")
	writePeriodicDrainClaudeSession(t, sessions)
	enablePeriodicCLIGrant(t, stateDir, sessions)
	writePeriodicDrainPendingBatch(t, stateDir, "batch-fair-cli-d1", 1)
	writePeriodicDrainPendingBatch(t, stateDir, "batch-fair-cli-d2", 1)
	seedPeriodicCursorBatch(t, stateDir, "cursor-fair-cli-1", 1)
	seedPeriodicCursorBatch(t, stateDir, "cursor-fair-cli-2", 1)

	args := []string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--sync-timeout", "30s",
		"--verbose",
	}
	out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
	if err != nil {
		t.Fatalf("the default dual-queue run must finish: %v\nstdout:\n%s", err, out)
	}
	if pull.calls != 1 || authFake.fetches != 1 {
		t.Fatalf("the account upstream must be pulled exactly once (pull=%d credential reads=%d)", pull.calls, authFake.fetches)
	}
	if !strings.Contains(out, "exportedBatches=1 exportedRecords=2") {
		t.Fatalf("the scan must export exactly one batch of two records, stdout:\n%s", out)
	}
	if !strings.Contains(out, "cursor sync: pulledEvents=2 new=2") {
		t.Fatalf("the pull must surface its two events, stdout:\n%s", out)
	}
	if !strings.Contains(out, "syncedBatches=3 syncedRecords=4") {
		t.Fatalf("device queue: 2 seeded + 1 scanned batches (4 records), stdout:\n%s", out)
	}
	if !strings.Contains(out, "cursor sync: exportedBatches=1 syncedBatches=3 syncedRecords=4 pendingRemaining=0") {
		t.Fatalf("cursor queue: 2 seeded + 1 pulled batches (4 records), stdout:\n%s", out)
	}
	for _, forbidden := range []string{"pendingRemaining=2", "pendingRemaining=1", "incomplete:"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("a fully drained default run must not report %q, stdout:\n%s", forbidden, out)
		}
	}
	order := server.uploadOrder()
	if len(order) != 6 {
		t.Fatalf("expected six recorded uploads (3 device + 3 cursor), got %+v", order)
	}
	assertPeriodicAlternation(t, order)
	if order[0].Queue != "cursor" {
		t.Fatalf("the pull phase's capped drain-first uploads the first cursor batch, got %+v", order)
	}
	if n := periodicCursorPending(t, stateDir); n != 0 {
		t.Fatalf("no cursor batch may remain, got %d", n)
	}
	if got := server.unexpected.Load(); got != 0 {
		t.Fatalf("the run hit unexpected endpoints %d time(s)", got)
	}
}

// TestRunPeriodicExplicitMaxBatchesNotTruncatedByDefaultTotal pins the
// legacy compatibility: an explicit --max-batches 200 with 120 pending
// batches uploads all 120 in one run — the default shared total of 100
// must never truncate an explicitly bounded legacy run (no budget exists
// in that shape), and the bounded stop stays exit zero.
func TestRunPeriodicExplicitMaxBatchesNotTruncatedByDefaultTotal(t *testing.T) {
	stateDir := t.TempDir()
	server := newPeriodicDrainFakeServer(t)
	bindPeriodicCLIDevice(t, stateDir, server.URL)
	for i := 1; i <= 120; i++ {
		writePeriodicDrainPendingBatch(t, stateDir, fmt.Sprintf("batch-legacy-200-%d", i), 1)
	}

	args := []string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--max-batches", "200",
		"--verbose",
	}
	out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
	if err != nil {
		t.Fatalf("the legacy bounded run must drain all 120 batches: %v\nstdout:\n%s", err, out)
	}
	if !strings.Contains(out, "syncedBatches=120 syncedRecords=120") {
		t.Fatalf("all 120 batches must upload (never truncated at the default 100), stdout:\n%s", out)
	}
	for _, forbidden := range []string{"pendingRemaining=", "incomplete:"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("a fully drained legacy run must not report %q, stdout:\n%s", forbidden, out)
		}
	}
	if got := server.ingest.Load(); got != 120 {
		t.Fatalf("expected exactly 120 ingest uploads, got %d", got)
	}
}

// TestRunPeriodicTotalBudgetExhaustionAndEmptyQueues pins the total
// bound in both fair shapes and the clean empty-queue default run.
func TestRunPeriodicTotalBudgetExhaustionAndEmptyQueues(t *testing.T) {
	t.Run("explicit_total_stops_incomplete", func(t *testing.T) {
		stateDir, server := budgetCLIFixture(t)
		writePeriodicDrainPendingBatch(t, stateDir, "batch-total-4", 1)
		writePeriodicDrainPendingBatch(t, stateDir, "batch-total-5", 1)

		args := []string{
			"--state-dir", stateDir,
			"--server", server.URL,
			"--max-total-batches", "3",
			"--sync-timeout", "30s",
			"--verbose",
		}
		out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
		if err == nil {
			t.Fatalf("an exhausted explicit total must exit non-zero, stdout:\n%s", out)
		}
		if !errors.Is(err, syncbudget.ErrTotalExhausted) || !strings.Contains(err.Error(), "periodic incomplete") {
			t.Fatalf("the stop must surface the budget sentinel as an incomplete run, got %v", err)
		}
		if !strings.Contains(out, "syncedBatches=3 syncedRecords=3") {
			t.Fatalf("expected exactly the three budgeted uploads, stdout:\n%s", out)
		}
		if !strings.Contains(out, "pendingRemaining=2") || !strings.Contains(out, "stopped by the shared upload budget") {
			t.Fatalf("expected the budget-stopped remainder report, stdout:\n%s", out)
		}
		if !strings.Contains(out, "incomplete: the --max-total-batches 3 shared upload budget is exhausted (devicePending=2 cursorPending=0)") {
			t.Fatalf("expected the explicit-total incomplete report, stdout:\n%s", out)
		}
		if got := server.ingest.Load(); got != 3 {
			t.Fatalf("expected exactly three ingest uploads, got %d", got)
		}

		// A follow-up default run drains the remainder.
		args2 := []string{
			"--state-dir", stateDir,
			"--server", server.URL,
			"--sync-timeout", "30s",
			"--verbose",
		}
		out2, err := capturePeriodicStdout(t, func() error { return runPeriodic(args2) })
		if err != nil {
			t.Fatalf("the follow-up run must finish: %v\nstdout:\n%s", err, out2)
		}
		if !strings.Contains(out2, "syncedBatches=2 syncedRecords=2") {
			t.Fatalf("the remaining two batches must drain, stdout:\n%s", out2)
		}
		if strings.Contains(out2, "pendingRemaining=") || strings.Contains(out2, "incomplete:") {
			t.Fatalf("the finished run must report neither a remainder nor incompleteness, stdout:\n%s", out2)
		}
	})

	t.Run("default_total_exhaustion_stops_incomplete", func(t *testing.T) {
		stateDir := t.TempDir()
		server := newPeriodicDrainFakeServer(t)
		bindPeriodicCLIDevice(t, stateDir, server.URL)
		for i := 1; i <= 101; i++ {
			writePeriodicDrainPendingBatch(t, stateDir, fmt.Sprintf("batch-default-total-%d", i), 1)
		}

		args := []string{
			"--state-dir", stateDir,
			"--server", server.URL,
			"--sync-timeout", "30s",
			"--verbose",
		}
		out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
		if err == nil {
			t.Fatalf("the exhausted default budget must exit non-zero, stdout:\n%s", out)
		}
		if !errors.Is(err, syncbudget.ErrTotalExhausted) || !strings.Contains(err.Error(), "periodic incomplete") {
			t.Fatalf("the stop must surface the budget sentinel as an incomplete run, got %v", err)
		}
		if !strings.Contains(out, "syncedBatches=100 syncedRecords=100") {
			t.Fatalf("expected exactly the 100 budgeted uploads, stdout:\n%s", out)
		}
		if !strings.Contains(out, "pendingRemaining=1") {
			t.Fatalf("expected the budget-stopped remainder report, stdout:\n%s", out)
		}
		if !strings.Contains(out, fmt.Sprintf("incomplete: the default shared upload budget (%d POSTs / %s) is exhausted (devicePending=1 cursorPending=0)",
			collection.DefaultSharedPOSTBudget, 30*time.Second)) {
			t.Fatalf("expected the default-budget incomplete report, stdout:\n%s", out)
		}
		if got := server.ingest.Load(); got != 100 {
			t.Fatalf("expected exactly 100 ingest uploads, got %d", got)
		}
	})

	t.Run("empty_queues_default_run_is_clean", func(t *testing.T) {
		freshDir := t.TempDir()
		freshServer := newPeriodicDrainFakeServer(t)
		bindPeriodicCLIDevice(t, freshDir, freshServer.URL)
		sessions := filepath.Join(t.TempDir(), "sessions")
		enablePeriodicCLIGrant(t, freshDir, sessions)

		args := []string{
			"--state-dir", freshDir,
			"--server", freshServer.URL,
			"--sync-timeout", "30s",
			"--verbose",
		}
		out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
		if err != nil {
			t.Fatalf("an empty-queue default run must exit zero: %v\nstdout:\n%s", err, out)
		}
		if !strings.Contains(out, "no new records") {
			t.Fatalf("the idle grant must report its empty scan, stdout:\n%s", out)
		}
		if strings.Contains(out, "incomplete:") || strings.Contains(out, "pendingRemaining=") {
			t.Fatalf("an empty-queue run must not report incompleteness, stdout:\n%s", out)
		}
		if got := freshServer.ingest.Load(); got != 0 {
			t.Fatalf("an empty queue must upload nothing, got %d", got)
		}
	})
}

// TestRunPeriodicPausedQueueKeepsPendingNoSpin pins the §6.5 contract at
// the periodic entry: when the server pauses the device after the cursor
// pull phase, the device queue keeps its real pending count and its
// historical remainder report (pause is a queued state for the DEVICE
// queue), but the account cursor round — an active permit whose queue
// still holds a batch it could not upload — makes the run report itself
// incomplete and exit non-zero with the paused reason, and no "complete"
// progress event claims success. The rotation still stops after one
// bounded turn (the total number of server preflights stays exact,
// proving no hot spin). A follow-up run once the pause lifts drains both
// queues and exits zero.
func TestRunPeriodicPausedQueueKeepsPendingNoSpin(t *testing.T) {
	stateDir := t.TempDir()
	server := newPeriodicDrainFakeServer(t)
	armPeriodicCursorSource(server)
	bindPeriodicCLIDevice(t, stateDir, server.URL)
	writePeriodicDrainCursorPermit(t, stateDir)
	pull := &periodicFakePull{}
	armPeriodicCursorFakes(t, pull)
	writePeriodicDrainPendingBatch(t, stateDir, "batch-pause-cli-d1", 1)
	writePeriodicDrainPendingBatch(t, stateDir, "batch-pause-cli-d2", 1)
	seedPeriodicCursorBatch(t, stateDir, "cursor-pause-cli-1", 1)
	seedPeriodicCursorBatch(t, stateDir, "cursor-pause-cli-2", 1)
	// Self requests: 1 grant sync, 2 cursor pull phase, 3+ paused.
	server.setPauseFromSelf(3)

	args := []string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--sync-timeout", "30s",
		"--verbose",
	}
	out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
	if err == nil {
		t.Fatalf("a paused account queue with a pending batch must exit non-zero, stdout:\n%s", out)
	}
	if !strings.Contains(err.Error(), "periodic incomplete") || !strings.Contains(err.Error(), "paused with 1 batch(es) still pending") {
		t.Fatalf("the incomplete exit must name the paused account queue, got %v", err)
	}
	if !strings.Contains(out, "incomplete: the account cursor source is paused with 1 batch(es) still pending; remaining work stays pending") {
		t.Fatalf("expected the paused-account incomplete report, stdout:\n%s", out)
	}
	if !strings.Contains(out, "cursor sync: outcome=paused pending=1") {
		t.Fatalf("the paused outcome must be named explicitly, stdout:\n%s", out)
	}
	if !strings.Contains(out, "syncedBatches=0 syncedRecords=0") {
		t.Fatalf("the paused device queue must upload nothing, stdout:\n%s", out)
	}
	if !strings.Contains(out, "pendingRemaining=2 (the run stopped before the queues were empty; remaining work stays pending)") {
		t.Fatalf("the device pending must be preserved with the fair-mode remainder report, stdout:\n%s", out)
	}
	if !strings.Contains(out, "cursor sync: exportedBatches=0 syncedBatches=1 syncedRecords=1 pendingRemaining=1") {
		t.Fatalf("the skipped cursor queue must keep its real pending count (1), stdout:\n%s", out)
	}
	if n := periodicCursorPending(t, stateDir); n != 1 {
		t.Fatalf("one cursor batch must remain pending, got %d", n)
	}
	// Bounded work: exactly four preflights — grant sync, cursor pull
	// phase, the rotation's paused device step, the rotation's skipped
	// cursor step. A hot-spinning rotation would burn many more.
	if got := server.self.Load(); got != 4 {
		t.Fatalf("expected exactly four self preflights (no rotation spin), got %d", got)
	}
	if got := server.ingest.Load(); got != 0 {
		t.Fatalf("no device batch may upload under pause, got %d", got)
	}
	if got := server.srcIngest.Load(); got != 1 {
		t.Fatalf("only the pull phase's cursor batch may upload, got %d", got)
	}

	// The pause lifts: the next default run drains both queues.
	server.setPauseFromSelf(0)
	out2, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
	if err != nil {
		t.Fatalf("the resumed run must finish: %v\nstdout:\n%s", err, out2)
	}
	if !strings.Contains(out2, "syncedBatches=2 syncedRecords=2") {
		t.Fatalf("the retained device batches must drain, stdout:\n%s", out2)
	}
	if !strings.Contains(out2, "cursor sync: exportedBatches=0 syncedBatches=1 syncedRecords=1 pendingRemaining=0") {
		t.Fatalf("the retained cursor batch must drain, stdout:\n%s", out2)
	}
	// Run 2's six preflights: grant sync, the cursor pull phase, the
	// two device uploads, the rotation's queue-empty cursor step, and
	// the fully-drained cursor success receipt — plus run 1's four.
	if got := server.self.Load(); got != 10 {
		t.Fatalf("expected exactly ten self preflights across both runs, got %d", got)
	}
}

// TestPeriodicUploadPlanMatrix pins the flag-to-budget decision table
// and the §6.2 default window: the default profile arms exactly 100
// shared POSTs inside a deadline of the effective --sync-timeout (20
// minutes by default — an explicit 5m or 30s value moves the deadline
// with it), the explicit legacy bound alone stays unbudgeted, and an
// explicit total arms the fair rotation in both shapes.
func TestPeriodicUploadPlanMatrix(t *testing.T) {
	t.Run("default_arms_100_posts_and_default_window", func(t *testing.T) {
		cur := time.Date(2026, 10, 31, 4, 0, 0, 0, time.UTC)
		now := func() time.Time { return cur }
		budget, fair := periodicUploadPlan(now, false, 0, collection.DefaultSharedPOSTWindow)
		if !fair || budget == nil {
			t.Fatalf("the default profile must arm the fair drain with a budget, fair=%t budget=%v", fair, budget)
		}
		if n, ok := budget.Remaining(); !ok || n != collection.DefaultSharedPOSTBudget {
			t.Fatalf("the default profile arms %d POSTs, got n=%d ok=%t", collection.DefaultSharedPOSTBudget, n, ok)
		}
		ctx := context.Background()
		// Just inside the window: reserves are granted.
		cur = time.Date(2026, 10, 31, 4, 19, 59, 0, time.UTC)
		if err := budget.Reserve(ctx, "device"); err != nil {
			t.Fatalf("a reserve inside the default window must be granted, got %v", err)
		}
		// At and past the window: the deadline declines.
		cur = time.Date(2026, 10, 31, 4, 20, 0, 0, time.UTC)
		if err := budget.Reserve(ctx, "device"); !errors.Is(err, syncbudget.ErrDeadlineExceeded) {
			t.Fatalf("a reserve at the elapsed window must decline with the deadline sentinel, got %v", err)
		}

		// The count bound: 100 granted reserves exhaust the total.
		budget2, _ := periodicUploadPlan(now, false, 0, collection.DefaultSharedPOSTWindow)
		for i := 0; i < collection.DefaultSharedPOSTBudget; i++ {
			if err := budget2.Reserve(ctx, "device"); err != nil {
				t.Fatalf("reserve %d inside the window must be granted, got %v", i, err)
			}
		}
		if err := budget2.Reserve(ctx, "device"); !errors.Is(err, syncbudget.ErrTotalExhausted) {
			t.Fatalf("the 101st reserve must decline with the total sentinel, got %v", err)
		}
	})

	t.Run("explicit_sync_timeout_moves_the_window", func(t *testing.T) {
		ctx := context.Background()
		for _, tc := range []struct {
			timeout time.Duration
			granted time.Duration
		}{
			{timeout: 5 * time.Minute, granted: 4 * time.Minute},
			{timeout: 30 * time.Second, granted: 29 * time.Second},
		} {
			base := time.Date(2026, 10, 31, 4, 0, 0, 0, time.UTC)
			cur := base
			now := func() time.Time { return cur }
			budget, fair := periodicUploadPlan(now, false, 0, tc.timeout)
			if !fair || budget == nil {
				t.Fatalf("an explicit --sync-timeout must still arm the fair drain with a budget, fair=%t", fair)
			}
			cur = base.Add(tc.granted)
			if err := budget.Reserve(ctx, "device"); err != nil {
				t.Fatalf("a reserve inside the explicit %s window must be granted, got %v", tc.timeout, err)
			}
			cur = base.Add(tc.timeout)
			if err := budget.Reserve(ctx, "device"); !errors.Is(err, syncbudget.ErrDeadlineExceeded) {
				t.Fatalf("a reserve at the elapsed explicit %s window must decline with the deadline sentinel, got %v", tc.timeout, err)
			}
		}
	})

	t.Run("explicit_legacy_bound_alone_stays_unbudgeted", func(t *testing.T) {
		budget, fair := periodicUploadPlan(time.Now, true, 0, collection.DefaultSharedPOSTWindow)
		if fair || budget != nil {
			t.Fatalf("an explicit --max-batches without a total must keep the unbudgeted legacy shape, fair=%t budget=%v", fair, budget)
		}
	})

	t.Run("explicit_total_arms_fair_rotation", func(t *testing.T) {
		budget, fair := periodicUploadPlan(time.Now, false, 7, collection.DefaultSharedPOSTWindow)
		if !fair {
			t.Fatal("an explicit total without --max-batches must use the fair rotation")
		}
		if n, ok := budget.Remaining(); !ok || n != 7 {
			t.Fatalf("expected the explicit total of 7, got n=%d ok=%t", n, ok)
		}
	})

	t.Run("explicit_total_plus_legacy_bound_both_apply", func(t *testing.T) {
		budget, fair := periodicUploadPlan(time.Now, true, 7, collection.DefaultSharedPOSTWindow)
		if !fair {
			t.Fatal("an explicit total plus --max-batches must use the fair rotation with the per-queue bound")
		}
		if n, ok := budget.Remaining(); !ok || n != 7 {
			t.Fatalf("expected the explicit total of 7, got n=%d ok=%t", n, ok)
		}
	})
}
