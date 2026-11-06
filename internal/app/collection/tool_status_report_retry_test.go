package collection

// Retry wiring coverage for the tool-status metadata reports of a
// collection run: collection.Options.Retry must reach every
// synccmd.ReportToolStatuses Options site (the per-batch "synced"
// receipt after a confirmed upload, the cursor receipts and the
// grant-restriction report), so a transient tool-status 503 is retried
// under the run's bounded policy instead of failing the run. The
// confirmed usage batch itself is never re-uploaded by that retry —
// the metadata attempt rides the policy, not the ingest path — and
// metadata attempts never consume the shared ingest Budget.
//
// Everything is synthetic: tempdir state, the budgetFakeServer protocol
// fake (its tool-status endpoint scripted to answer one transient 503
// before accepting), and a fake-clock retry policy so nothing sleeps.
// No real credentials are read and no real endpoint is contacted.

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"toktrail-collector/internal/syncbudget"
	"toktrail-collector/internal/syncretry"
)

// TestRunToolStatusTransient503RetriedUnderPolicy drives one granted
// source through the legacy bounded drain with Options.Retry set: the
// batch upload is CONFIRMED exactly once, the per-batch "synced"
// tool-status report that follows hits a transient 503, and the wired
// policy retries it to success — so the run finishes cleanly, the
// report is delivered exactly once, and the ingest budget still counts
// only the real device POST.
func TestRunToolStatusTransient503RetriedUnderPolicy(t *testing.T) {
	stateDir := t.TempDir()
	server := startBudgetFakeServer(t)
	bindDevice(t, stateDir, server.URL)
	sessions := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, sessions, "session-ts-retry.jsonl",
		claudeLine(t, "2026-10-28T09:00:00Z", "s-ts-retry", "msg_ts_retry_1", claudeUsage(8, 0, 0, 4)),
	)
	enableGrant(t, stateDir, "claude-code-jsonl", sessions)
	// Script the transient blip: the FIRST tool-status POST answers a
	// 503 with no server error code — the same unclassified shape a
	// real blip produces — and every later POST is accepted.
	server.setFailToolStatusFirst(1)

	// A tight budget proves the metadata retry stays outside the ingest
	// accounting: only the confirmed device POST may reserve it.
	budget := syncbudget.New(syncbudget.WithTotal(5))
	policy := syncretry.New(syncretry.WithClock(frozenRetryClock{now: time.Now()}), syncretry.WithBaseDelay(0))
	res, err := Run(context.Background(), Options{
		StateDir:   stateDir,
		ServerURL:  server.URL,
		HTTPClient: server.Client(),
		HomeDir:    t.TempDir(),
		Now:        func() time.Time { return cursorTestNow },
		Budget:     budget,
		Retry:      policy,
	})
	if err != nil {
		t.Fatalf("a transient tool-status 503 must be retried to success under the wired policy, got %v", err)
	}
	if res.SyncedBatches != 1 || res.SyncedRecords != 1 || res.PendingRemaining != 0 {
		t.Fatalf("the run must finish cleanly with the batch synced once: synced=%d records=%d pending=%d",
			res.SyncedBatches, res.SyncedRecords, res.PendingRemaining)
	}
	if res.DrainStop != "" {
		t.Fatalf("the retried report must never stop the drain, got %q", res.DrainStopped)
	}
	selfRequests, _, devicePosts, toolStatusPosts, _ := server.counters()
	// The confirmed usage batch was uploaded exactly once: the retry
	// covers the metadata report, never the ingest POST.
	if devicePosts != 1 {
		t.Fatalf("the confirmed usage batch must be uploaded exactly once, got %d device POSTs", devicePosts)
	}
	// The report needed exactly two attempts (503, then accepted) and
	// was delivered exactly once.
	if attempts := server.toolStatusAttemptCount(); attempts != 2 {
		t.Fatalf("the tool-status report must be attempted exactly twice (transient 503 then success), got %d", attempts)
	}
	if toolStatusPosts != 1 {
		t.Fatalf("the tool-status report must be delivered exactly once, got %d", toolStatusPosts)
	}
	// Each attempt re-ran the authorization preflight (fresh auth), on
	// top of the grant sync's and the upload's own preflights.
	if selfRequests < 2 {
		t.Fatalf("the retried report must re-run its authorization preflight per attempt, got %d self requests", selfRequests)
	}
	// The metadata attempts stayed outside the ingest budget: only the
	// one real device POST reserved it.
	if used := budget.Used(); used != 1 {
		t.Fatalf("metadata retries must not consume the ingest budget, used=%d", used)
	}
	if n := devicePendingCount(t, stateDir); n != 0 {
		t.Fatalf("nothing may remain pending after the retried report, got %d", n)
	}
}

// TestRunToolStatusPersistent503StillFailsWithPolicy pins the other
// side of the wiring: a retry policy is not a license to swallow a
// persistently failing report. With the 503 armed for every POST, the
// bounded policy exhausts its attempts and the run still fails through
// the ErrToolStatusReport sentinel with the confirmed upload kept —
// the same contract the nil-Retry failure tests pin.
func TestRunToolStatusPersistent503StillFailsWithPolicy(t *testing.T) {
	stateDir := t.TempDir()
	server := startBudgetFakeServer(t)
	bindDevice(t, stateDir, server.URL)
	sessions := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, sessions, "session-ts-persist.jsonl",
		claudeLine(t, "2026-10-28T09:00:00Z", "s-ts-persist", "msg_ts_persist_1", claudeUsage(7, 0, 0, 3)),
	)
	enableGrant(t, stateDir, "claude-code-jsonl", sessions)
	server.setFailToolStatus(true)

	policy := syncretry.New(syncretry.WithClock(frozenRetryClock{now: time.Now()}), syncretry.WithBaseDelay(0))
	res, err := Run(context.Background(), Options{
		StateDir:   stateDir,
		ServerURL:  server.URL,
		HTTPClient: server.Client(),
		HomeDir:    t.TempDir(),
		Now:        func() time.Time { return cursorTestNow },
		Retry:      policy,
	})
	if err == nil {
		t.Fatalf("a persistently failing tool-status report must still fail the run under the policy, got %+v", res)
	}
	if !errors.Is(err, ErrToolStatusReport) {
		t.Fatalf("the persistent failure must keep the ErrToolStatusReport sentinel, got %v", err)
	}
	if res.SyncedBatches != 1 || res.SyncedRecords != 1 {
		t.Fatalf("the confirmed upload must stay counted: synced=%d records=%d", res.SyncedBatches, res.SyncedRecords)
	}
	_, _, devicePosts, toolStatusPosts, _ := server.counters()
	if devicePosts != 1 {
		t.Fatalf("the confirmed usage batch must be uploaded exactly once, got %d device POSTs", devicePosts)
	}
	if toolStatusPosts != 0 {
		t.Fatalf("no tool-status report may be counted as delivered, got %d", toolStatusPosts)
	}
	if attempts := server.toolStatusAttemptCount(); attempts < 2 {
		t.Fatalf("the policy must have retried the persistent failure at least once, got %d attempts", attempts)
	}
}
