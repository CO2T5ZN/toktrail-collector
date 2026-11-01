// Optional bounded retry (Options.Retry) for the cursor source-batch
// uploads: transient failures retry with the same batch id and immutable
// bytes under the same authorization boundary; every retry re-reads the
// device self view and stops conservatively on any drift; each real POST
// reserves the shared budget and persists its own MarkAttempt; a full
// acknowledgment is written at most once. Everything here is synthetic:
// a local fake TokTrail server with scripted ingest answers, a fake
// clock driving the retry policy (no real sleeping except the one
// client-timeout test), fake credential, verify and pull — no real user
// state is ever touched.
package cursorsync_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/local/cursoroutbox"
	"toktrail-collector/internal/syncbudget"
	"toktrail-collector/internal/syncretry"
)

// retryPolicy builds a policy over the harness fake clock: backoff waits
// advance fake time instead of sleeping. Extra options (run deadlines)
// append after the standard ones.
func retryPolicy(clock *fakeClock, maxRetries int, opts ...syncretry.Option) *syncretry.Policy {
	return syncretry.New(append([]syncretry.Option{
		syncretry.WithMaxRetries(maxRetries),
		syncretry.WithClock(clock),
	}, opts...)...)
}

// outboxEntry loads one outbox entry by batch id.
func outboxEntry(t *testing.T, dir, batchID string) cursoroutbox.Entry {
	t.Helper()
	entries, err := cursoroutbox.New(dir).Load()
	if err != nil {
		t.Fatalf("load outbox: %v", err)
	}
	for _, e := range entries {
		if e.BatchID == batchID {
			return e
		}
	}
	t.Fatalf("outbox entry %s not found", batchID)
	return cursoroutbox.Entry{}
}

// sourceWithFence is the default source under a different fence version.
func sourceWithFence(fence int64) protocol.Source {
	s := defaultSource()
	s.FenceVersion = fence
	return s
}

// TestSyncNilRetryPolicyKeepsSingleAttemptBehavior is the nil-retry
// contract end to end: without Options.Retry a transient-looking failure
// (codeless 503) still produces exactly one POST, one MarkAttempt, no
// retry marker and the historical hard error with the batch kept pending.
func TestSyncNilRetryPolicyKeepsSingleAttemptBehavior(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-nil-retry-1", 1)
	h.srv.setIngestScript(scriptedIngest{status: http.StatusServiceUnavailable})

	budget := syncbudget.New()
	opt := h.options()
	opt.Budget = budget
	res, err := cursorsync.Sync(context.Background(), opt, syncGate())
	if err == nil {
		t.Fatal("the single failed attempt must surface as an upload failure")
	}
	if res.Outcome != cursorsync.RoundError {
		t.Fatalf("the nil-policy failure must classify as an error outcome, got %q", res.Outcome)
	}
	if syncretry.IsRetryable(err) {
		t.Fatalf("a nil policy must never surface a retry marker: %v", err)
	}
	if !strings.Contains(err.Error(), `HTTP 503`) {
		t.Fatalf("unexpected failure: %v", err)
	}
	if _, _, ingest, _, _ := h.srv.stats(); ingest != 1 {
		t.Fatalf("exactly one POST may happen without a policy, ingest=%d", ingest)
	}
	if n := pendingCount(t, h.dir); n != 1 {
		t.Fatalf("the failed batch must stay pending, pending=%d", n)
	}
	if budget.Used() != 1 || budget.QueueUsed("cursor") != 1 {
		t.Fatalf("only the one real POST may be reserved: used=%d cursor=%d", budget.Used(), budget.QueueUsed("cursor"))
	}
	if at := outboxEntry(t, h.dir, "cursor-nil-retry-1").LastAttemptAt; !at.Equal(baseTime) {
		t.Fatalf("the single attempt must persist its MarkAttempt at %v, got %v", baseTime, at)
	}
}

// TestDrainRetryTransientFailuresRetriedWithSameBytesAndSingleAck is the
// core opt-in table, including the internal_error 500/503 regressions the
// server review asked for: one transient scripted failure, then success.
// Every retry re-sends the exact same bytes under the same batch id, each
// real POST reserves the shared budget, MarkAttempt persists per attempt
// (the fake clock advances across the backoff), and the batch is
// acknowledged exactly once.
func TestDrainRetryTransientFailuresRetriedWithSameBytesAndSingleAck(t *testing.T) {
	cases := []struct {
		name       string
		first      scriptedIngest
		wantWaits  []time.Duration
		wantLastAt time.Time
	}{
		{
			name:       "503 codeless",
			first:      scriptedIngest{status: http.StatusServiceUnavailable},
			wantWaits:  []time.Duration{time.Second},
			wantLastAt: baseTime.Add(time.Second),
		},
		{
			name:       "500 internal_error",
			first:      scriptedIngest{status: http.StatusInternalServerError, code: "internal_error"},
			wantWaits:  []time.Duration{time.Second},
			wantLastAt: baseTime.Add(time.Second),
		},
		{
			name:       "503 internal_error",
			first:      scriptedIngest{status: http.StatusServiceUnavailable, code: "internal_error"},
			wantWaits:  []time.Duration{time.Second},
			wantLastAt: baseTime.Add(time.Second),
		},
		{
			name:       "503 service_unavailable code",
			first:      scriptedIngest{status: http.StatusServiceUnavailable, code: "service_unavailable"},
			wantWaits:  []time.Duration{time.Second},
			wantLastAt: baseTime.Add(time.Second),
		},
		{
			name:       "429 rate_limited with Retry-After floor",
			first:      scriptedIngest{status: http.StatusTooManyRequests, code: "rate_limited", retryAfter: "2"},
			wantWaits:  []time.Duration{2 * time.Second},
			wantLastAt: baseTime.Add(2 * time.Second),
		},
		{
			name:       "503 raw proxy body",
			first:      scriptedIngest{status: http.StatusServiceUnavailable, rawBody: "Service Unavailable"},
			wantWaits:  []time.Duration{time.Second},
			wantLastAt: baseTime.Add(time.Second),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.srv.setSource(defaultSource())
			h.writeLicense(t, activeLicenseForA())
			seedPendingBatch(t, h.dir, "cursor-retry-transient-1", 1)
			h.srv.setIngestScript(tc.first)

			budget := syncbudget.New()
			opt := h.options()
			opt.Budget = budget
			opt.Retry = retryPolicy(h.clock, 2)
			res, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
			if err != nil {
				t.Fatalf("the retried drain must succeed: %v", err)
			}
			if !res.Ran || res.SyncedBatches != 1 || res.SyncedRecords != 1 || res.PendingRemaining != 0 {
				t.Fatalf("the batch must be acknowledged exactly once: %+v", res)
			}
			if _, _, ingest, _, batches := h.srv.stats(); ingest != 2 || len(batches) != 1 {
				t.Fatalf("exactly two real POSTs of one batch: ingest=%d stored=%d", ingest, len(batches))
			}
			if budget.Used() != 2 || budget.QueueUsed("cursor") != 2 {
				t.Fatalf("each real POST must reserve: used=%d cursor=%d", budget.Used(), budget.QueueUsed("cursor"))
			}
			bodies := h.srv.ingestBodyLog()
			if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
				t.Fatalf("retries must re-send the identical immutable bytes, got %d bodies", len(bodies))
			}
			var received protocol.Batch
			if err := json.Unmarshal(bodies[0], &received); err != nil {
				t.Fatalf("decode posted body: %v", err)
			}
			if received.BatchID != "cursor-retry-transient-1" {
				t.Fatalf("unexpected batch id %q", received.BatchID)
			}
			if waits := h.clock.waitLog(); len(waits) != len(tc.wantWaits) || waits[0] != tc.wantWaits[0] {
				t.Fatalf("policy waits = %v, want %v", waits, tc.wantWaits)
			}
			entry := outboxEntry(t, h.dir, "cursor-retry-transient-1")
			if entry.Status != cursoroutbox.StatusSynced {
				t.Fatalf("the batch must be marked synced once, status=%q", entry.Status)
			}
			if !entry.LastAttemptAt.Equal(tc.wantLastAt) {
				t.Fatalf("every attempt must persist MarkAttempt: last=%v want %v", entry.LastAttemptAt, tc.wantLastAt)
			}
		})
	}
}

// TestDrainRetryTwoFailuresThenSuccess proves MarkAttempt persists on
// EVERY attempt (the timestamp advances across both backoffs) and the
// round bound still counts the batch once.
func TestDrainRetryTwoFailuresThenSuccess(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-retry-2fail-1", 1)
	h.srv.setIngestScript(
		scriptedIngest{status: http.StatusBadGateway},
		scriptedIngest{status: http.StatusServiceUnavailable, code: "service_unavailable"},
	)

	budget := syncbudget.New()
	opt := h.options()
	opt.Budget = budget
	opt.Retry = retryPolicy(h.clock, 2)
	res, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
	if err != nil {
		t.Fatalf("the twice-retried drain must succeed: %v", err)
	}
	if res.SyncedBatches != 1 || res.PendingRemaining != 0 {
		t.Fatalf("the batch must be acknowledged once: %+v", res)
	}
	if _, _, ingest, _, _ := h.srv.stats(); ingest != 3 {
		t.Fatalf("three real POSTs must happen, ingest=%d", ingest)
	}
	if budget.Used() != 3 {
		t.Fatalf("each real POST must reserve, used=%d", budget.Used())
	}
	// Backoffs 1s and 2s: the last MarkAttempt lands at baseTime+3s.
	if at := outboxEntry(t, h.dir, "cursor-retry-2fail-1").LastAttemptAt; !at.Equal(baseTime.Add(3 * time.Second)) {
		t.Fatalf("MarkAttempt must persist per attempt (last=%v)", at)
	}
}

// TestDrainRetryExhaustedKeepsBatchPending: when the transient failure
// outlives the retry budget, the exhaustion error surfaces (wrapping the
// last failure) and the batch stays pending, never dropped.
func TestDrainRetryExhaustedKeepsBatchPending(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-retry-exhaust-1", 1)
	h.srv.setIngestScript(
		scriptedIngest{status: http.StatusServiceUnavailable},
		scriptedIngest{status: http.StatusServiceUnavailable},
	)

	opt := h.options()
	opt.Retry = retryPolicy(h.clock, 1)
	res, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
	if err == nil {
		t.Fatal("exhausted retries must surface as an upload failure")
	}
	if res.Outcome != cursorsync.RoundError {
		t.Fatalf("retry exhaustion must classify as an error outcome, got %q", res.Outcome)
	}
	if res.PendingRemaining != 1 {
		t.Fatalf("the exhausted round must keep its honest pending count: %+v", res)
	}
	if !strings.Contains(err.Error(), "giving up after 2 attempts") {
		t.Fatalf("the exhaustion must be reported: %v", err)
	}
	if _, _, ingest, _, _ := h.srv.stats(); ingest != 2 {
		t.Fatalf("exactly one retry may happen, ingest=%d", ingest)
	}
	if n := pendingCount(t, h.dir); n != 1 {
		t.Fatalf("the failed batch must stay pending, pending=%d", n)
	}
}

// TestDrainRetryBudgetDeclineOnRetryIsFinal: the retry's own POST is
// declined by the spent shared budget — a decline is final (no waiting,
// no further attempts), nothing new is acknowledged and the batch stays
// pending for the next run's fresh budget.
func TestDrainRetryBudgetDeclineOnRetryIsFinal(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-retry-budget-1", 1)
	h.srv.setIngestScript(scriptedIngest{status: http.StatusServiceUnavailable})

	budget := syncbudget.New(syncbudget.WithTotal(1))
	opt := h.options()
	opt.Budget = budget
	opt.Retry = retryPolicy(h.clock, 2)
	res, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
	if !errors.Is(err, syncbudget.ErrTotalExhausted) {
		t.Fatalf("the retry's budget decline must stop the round: %v", err)
	}
	if res.Outcome != cursorsync.RoundError {
		t.Fatalf("a budget decline must classify as an error outcome, got %q", res.Outcome)
	}
	if res.SyncedBatches != 0 || res.PendingRemaining != 1 {
		t.Fatalf("nothing new may be acknowledged: %+v", res)
	}
	if _, _, ingest, _, _ := h.srv.stats(); ingest != 1 {
		t.Fatalf("the declined retry must not POST, ingest=%d", ingest)
	}
	if budget.Used() != 1 {
		t.Fatalf("only the first POST was reserved, used=%d", budget.Used())
	}
}

// TestDrainRetryRetryAfterPastDeadlineStops: a server Retry-After floor
// that would start the next attempt past the policy's run deadline fails
// fast without a second POST, surfacing the syncretry sentinel.
func TestDrainRetryRetryAfterPastDeadlineStops(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-retry-deadline-1", 1)
	h.srv.setIngestScript(scriptedIngest{
		status:     http.StatusTooManyRequests,
		code:       "rate_limited",
		retryAfter: "3600",
	})

	opt := h.options()
	opt.Retry = retryPolicy(h.clock, 2, syncretry.WithRunDeadline(baseTime.Add(30*time.Minute)))
	_, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
	if !errors.Is(err, syncretry.ErrRetryPastDeadline) {
		t.Fatalf("the past-deadline retry must fail fast: %v", err)
	}
	if _, _, ingest, _, _ := h.srv.stats(); ingest != 1 {
		t.Fatalf("no second POST may start past the deadline, ingest=%d", ingest)
	}
	if n := pendingCount(t, h.dir); n != 1 {
		t.Fatalf("the batch must stay pending, pending=%d", n)
	}
	if waits := h.clock.waitLog(); len(waits) != 0 {
		t.Fatalf("a past-deadline retry must not wait, waits=%v", waits)
	}
}

// TestDrainRetryParentContextCanceledStops: canceling the run context
// during the first POST ends the round without any retry, and the
// cancellation stays observable through errors.Is.
func TestDrainRetryParentContextCanceledStops(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-retry-cancel-1", 1)
	h.srv.setIngestScript(scriptedIngest{status: http.StatusServiceUnavailable})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.srv.setIngestHook(cancel)

	opt := h.options()
	opt.Retry = retryPolicy(h.clock, 2)
	res, err := cursorsync.DrainPending(ctx, opt, syncGate())
	if err == nil {
		t.Fatal("the canceled round must surface an error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("the cancellation must stay observable: %v", err)
	}
	if res.Outcome != cursorsync.RoundError {
		t.Fatalf("a canceled round must classify as an error outcome, got %q", res.Outcome)
	}
	if _, _, ingest, _, _ := h.srv.stats(); ingest != 1 {
		t.Fatalf("no retry may start after the parent context is canceled, ingest=%d", ingest)
	}
	if n := pendingCount(t, h.dir); n != 1 {
		t.Fatalf("the batch must stay pending, pending=%d", n)
	}
}

// TestDrainRetryPreflightFetchCanceledPropagatesCancellation pins the
// cancellation contract of the retry preflight's boundary
// re-verification: when the run context is cancelled exactly while the
// preflight re-fetches the device self view, the cancellation
// propagates UNCHANGED (an error outcome, errors.Is-observable) instead
// of being wrapped as an authorization boundary change — a wrapped
// cancellation would read as a clean drift stop and hide the real
// reason the round ended.
func TestDrainRetryPreflightFetchCanceledPropagatesCancellation(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-retry-preflight-cancel-1", 1)
	h.srv.setIngestScript(scriptedIngest{status: http.StatusServiceUnavailable})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Self views: 1 = the round-start preflight (must succeed so the
	// round runs), 2 = the retry preflight's re-fetch — cancel the run
	// exactly there, before the view is served.
	selfViews := 0
	h.srv.setSelfHook(func() {
		selfViews++
		if selfViews == 2 {
			cancel()
		}
	})

	opt := h.options()
	opt.Retry = retryPolicy(h.clock, 2)
	res, err := cursorsync.DrainPending(ctx, opt, syncGate())
	if err == nil {
		t.Fatal("the preflight-cancelled round must surface an error, not a clean drift stop")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("the cancellation must stay observable through the preflight: %v", err)
	}
	if res.Outcome != cursorsync.RoundError {
		t.Fatalf("a preflight-cancelled round must classify as an error outcome, got %q", res.Outcome)
	}
	if res.SyncedBatches != 0 {
		t.Fatalf("nothing may be acknowledged, got %+v", res)
	}
	if _, _, ingest, _, _ := h.srv.stats(); ingest != 1 {
		t.Fatalf("exactly the first POST may happen, ingest=%d", ingest)
	}
	if n := pendingCount(t, h.dir); n != 1 {
		t.Fatalf("the batch must stay pending, pending=%d", n)
	}
}

// TestDrainRetryBoundaryDriftStopsConservatively is the authorization
// matrix: the retry preflight re-reads the device self view before every
// retry, and ANY drift — fence, consent, source state, source
// designation, device pause, scope narrowing, or a self view that cannot
// be re-fetched — stops the round conservatively (no second POST, batch
// pending, stopped note) instead of retrying under a moved boundary.
func TestDrainRetryBoundaryDriftStopsConservatively(t *testing.T) {
	cases := []struct {
		name        string
		wantOutcome cursorsync.RoundOutcome
		arm         func(h *harness)
	}{
		{"fence moved", cursorsync.RoundFenceStop, func(h *harness) {
			h.srv.setIngestHook(func() { h.srv.setSource(sourceWithFence(2)) })
		}},
		{"consent revision advanced", cursorsync.RoundFenceStop, func(h *harness) {
			h.srv.setIngestHook(func() { h.srv.setConsentRevision(6) })
		}},
		{"source paused server-side", cursorsync.RoundPaused, func(h *harness) {
			h.srv.setIngestHook(func() {
				paused := defaultSource()
				paused.State = "paused"
				h.srv.setSource(paused)
			})
		}},
		{"source dropped server-side", cursorsync.RoundFenceStop, func(h *harness) {
			h.srv.setIngestHook(func() { h.srv.dropSource() })
		}},
		{"device paused server-side", cursorsync.RoundFenceStop, func(h *harness) {
			h.srv.setIngestHook(func() { h.srv.setPaused(true) })
		}},
		{"effective scope narrowed", cursorsync.RoundFenceStop, func(h *harness) {
			h.srv.setIngestHook(func() { h.srv.setAllowedTools([]string{"Codex"}) })
		}},
		{"self view unavailable", cursorsync.RoundFenceStop, func(h *harness) {
			h.srv.setSelfFailAfter(1)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.srv.setSource(defaultSource())
			h.writeLicense(t, activeLicenseForA())
			seedPendingBatch(t, h.dir, "cursor-retry-drift-1", 1)
			h.srv.setIngestScript(scriptedIngest{status: http.StatusServiceUnavailable})
			tc.arm(h)

			opt := h.options()
			opt.Retry = retryPolicy(h.clock, 2)
			res, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
			if err != nil {
				t.Fatalf("a boundary drift must stop the round, not fail it: %v", err)
			}
			if !res.Ran {
				t.Fatalf("the round ran: %+v", res)
			}
			if res.Outcome != tc.wantOutcome {
				t.Fatalf("drift outcome %q, want %q", res.Outcome, tc.wantOutcome)
			}
			if !strings.Contains(res.Skipped, "stopped") {
				t.Fatalf("the stop must be reported: %+v", res)
			}
			if res.SyncedBatches != 0 || res.PendingRemaining != 1 {
				t.Fatalf("nothing may be acknowledged on a drifted boundary: %+v", res)
			}
			if _, _, ingest, _, _ := h.srv.stats(); ingest != 1 {
				t.Fatalf("no retry POST may happen after the drift, ingest=%d", ingest)
			}
			if n := pendingCount(t, h.dir); n != 1 {
				t.Fatalf("the batch must stay pending, pending=%d", n)
			}
			if res.Note == "" {
				t.Fatal("the drift must leave a diagnostic note")
			}
		})
	}
}

// TestDrainRetryCrossStatusBusinessCodesAtAppLevel mirrors the
// sourcebatch cross table through the drain: a 429 carrying scope_changed
// stops like a consent drift (never retried), and a 503 carrying an
// unknown code is a final failure (never retried).
func TestDrainRetryCrossStatusBusinessCodesAtAppLevel(t *testing.T) {
	t.Run("429 scope_changed stops the round", func(t *testing.T) {
		h := newHarness(t)
		h.srv.setSource(defaultSource())
		h.writeLicense(t, activeLicenseForA())
		seedPendingBatch(t, h.dir, "cursor-retry-cross-1", 1)
		h.srv.setIngestScript(scriptedIngest{status: http.StatusTooManyRequests, code: "scope_changed"})

		opt := h.options()
		opt.Retry = retryPolicy(h.clock, 2)
		res, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
		if err != nil {
			t.Fatalf("a scope drift must stop the round, not fail it: %v", err)
		}
		if !strings.Contains(res.Skipped, "stopped") || res.SyncedBatches != 0 || res.PendingRemaining != 1 {
			t.Fatalf("unexpected result: %+v", res)
		}
		if _, _, ingest, _, _ := h.srv.stats(); ingest != 1 {
			t.Fatalf("a terminal business code must never retry, ingest=%d", ingest)
		}
	})

	t.Run("503 unknown code is a final failure", func(t *testing.T) {
		h := newHarness(t)
		h.srv.setSource(defaultSource())
		h.writeLicense(t, activeLicenseForA())
		seedPendingBatch(t, h.dir, "cursor-retry-cross-2", 1)
		h.srv.setIngestScript(scriptedIngest{status: http.StatusServiceUnavailable, code: "outside_scope"})

		opt := h.options()
		opt.Retry = retryPolicy(h.clock, 2)
		_, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
		if err == nil || !strings.Contains(err.Error(), `code="unknown"`) {
			t.Fatalf("the unknown code must surface as a final failure under the fixed unknown label: %v", err)
		}
		if strings.Contains(err.Error(), "outside_scope") {
			t.Fatalf("an unrecognized business code is untrusted server text and must not be reflected: %v", err)
		}
		if _, _, ingest, _, _ := h.srv.stats(); ingest != 1 {
			t.Fatalf("an unknown business code must never retry, ingest=%d", ingest)
		}
		if n := pendingCount(t, h.dir); n != 1 {
			t.Fatalf("the batch must stay pending, pending=%d", n)
		}
	})
}

// TestDrainRetryPartialReceiptDoesNotRetry: a partial_error receipt is a
// complete protocol answer — the retry policy must not repeat it; the
// batch surfaces its rejected record and stays pending.
func TestDrainRetryPartialReceiptDoesNotRetry(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-retry-partial-1", 2)
	h.srv.setIngestPartialRejection(0, "stale_revision")

	opt := h.options()
	opt.Retry = retryPolicy(h.clock, 2)
	_, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("the partial receipt must surface: %v", err)
	}
	if _, _, ingest, _, _ := h.srv.stats(); ingest != 1 {
		t.Fatalf("a partial receipt must never retry, ingest=%d", ingest)
	}
	if n := pendingCount(t, h.dir); n != 1 {
		t.Fatalf("the partially rejected batch must stay pending, pending=%d", n)
	}
}

// TestDrainRetryReceiptLostAfterServerPersistReplaysOnce is the
// response-loss end-to-end contract: the first POST is durably stored
// server-side, but its 2xx receipt is cut off mid-stream, so the client
// can never see or validate it. The retry re-sends the SAME batch id and
// immutable bytes; the server answers the stored receipt with
// replay=true; that replay receipt is the one and only acknowledgment
// (the outbox is marked synced exactly once, the server counts the batch
// exactly once, each real POST reserves the shared budget once), and the
// next round re-sends nothing.
func TestDrainRetryReceiptLostAfterServerPersistReplaysOnce(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-retry-lost-1", 1)
	// First POST: durably stored server-side, receipt truncated in
	// transit (a retryable 2xx receipt loss).
	h.srv.setIngestScript(scriptedIngest{status: http.StatusAccepted, truncated2xx: true})

	budget := syncbudget.New()
	opt := h.options()
	opt.Budget = budget
	opt.Retry = retryPolicy(h.clock, 2)
	res, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
	if err != nil {
		t.Fatalf("the lost receipt must be proven by a re-send that succeeds: %v", err)
	}
	if !res.Ran || res.SyncedBatches != 1 || res.SyncedRecords != 1 || res.PendingRemaining != 0 {
		t.Fatalf("the replay receipt must acknowledge the batch exactly once: %+v", res)
	}
	// Two real POSTs of one batch, stored exactly once server-side.
	if _, _, ingest, _, batches := h.srv.stats(); ingest != 2 || len(batches) != 1 {
		t.Fatalf("two POSTs of one stored batch: ingest=%d stored=%d", ingest, len(batches))
	}
	// The re-send was answered with the stored receipt (replay=true).
	if n := h.srv.replayAnswerCount(); n != 1 {
		t.Fatalf("exactly the re-send may be answered as a replay, got %d", n)
	}
	// The re-send carried the identical immutable bytes.
	bodies := h.srv.ingestBodyLog()
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatalf("the re-send must carry the identical bytes, got %d bodies", len(bodies))
	}
	// Every retry re-reads the device self view (round start + preflight).
	if self, _, _, _, _ := h.srv.stats(); self != 2 {
		t.Fatalf("the retry preflight must re-read the self view, self=%d", self)
	}
	// Each real POST reserved the shared budget on its own.
	if budget.Used() != 2 || budget.QueueUsed("cursor") != 2 {
		t.Fatalf("each real POST must reserve: used=%d cursor=%d", budget.Used(), budget.QueueUsed("cursor"))
	}
	// One backoff before the re-send.
	if waits := h.clock.waitLog(); len(waits) != 1 || waits[0] != time.Second {
		t.Fatalf("one backoff before the re-send, got %v", waits)
	}
	// MarkAttempt persisted per attempt (the re-send lands at +1s), and
	// the replay receipt marked the batch synced exactly once.
	entry := outboxEntry(t, h.dir, "cursor-retry-lost-1")
	if entry.Status != cursoroutbox.StatusSynced {
		t.Fatalf("the batch must be marked synced, status=%q", entry.Status)
	}
	if entry.ReceiptStatus != "accepted" || entry.AcceptedRecords != 1 || entry.RejectedRecords != 0 {
		t.Fatalf("the stored receipt must count one accepted record: %+v", entry)
	}
	if !entry.LastAttemptAt.Equal(baseTime.Add(time.Second)) {
		t.Fatalf("every attempt must persist MarkAttempt: last=%v", entry.LastAttemptAt)
	}

	// The next round (fresh budget, same policy) re-sends nothing: the
	// batch is fully acknowledged and no longer pending.
	opt2 := h.options()
	opt2.Budget = syncbudget.New()
	opt2.Retry = retryPolicy(h.clock, 2)
	res2, err := cursorsync.DrainPending(context.Background(), opt2, syncGate())
	if err != nil {
		t.Fatalf("the settled round must succeed: %v", err)
	}
	if !res2.Ran || res2.SyncedBatches != 0 || res2.PendingRemaining != 0 {
		t.Fatalf("a settled batch must not re-send: %+v", res2)
	}
	if _, _, ingest, _, batches := h.srv.stats(); ingest != 2 || len(batches) != 1 {
		t.Fatalf("no third POST may happen: ingest=%d stored=%d", ingest, len(batches))
	}
	if n := pendingCount(t, h.dir); n != 0 {
		t.Fatalf("nothing may stay pending, pending=%d", n)
	}
}

// TestSyncRetryPolicyWiringThroughFullRound runs the retry through the
// full Sync round (preflight, drain, credential read, pull, second
// drain): a 500 internal_error on the first POST retries once and the
// round completes successfully.
func TestSyncRetryPolicyWiringThroughFullRound(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-retry-sync-1", 1)
	h.srv.setIngestScript(scriptedIngest{status: http.StatusInternalServerError, code: "internal_error"})

	budget := syncbudget.New()
	opt := h.options()
	opt.Budget = budget
	opt.Retry = retryPolicy(h.clock, 2)
	res, err := cursorsync.Sync(context.Background(), opt, syncGate())
	if err != nil {
		t.Fatalf("the retried round must succeed: %v", err)
	}
	if !res.Ran || res.SyncedBatches != 1 || res.SyncedRecords != 1 || res.PendingRemaining != 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if _, _, ingest, _, batches := h.srv.stats(); ingest != 2 || len(batches) != 1 {
		t.Fatalf("one batch over two POSTs: ingest=%d stored=%d", ingest, len(batches))
	}
	if budget.Used() != 2 || budget.QueueUsed("cursor") != 2 {
		t.Fatalf("each real POST must reserve: used=%d cursor=%d", budget.Used(), budget.QueueUsed("cursor"))
	}
}

// TestDrainRetryClientTimeoutWithLiveParentContextRetries: a slow server
// that outlives the http.Client timeout fails the first POST with a
// client timeout — the parent context is still live, so the policy
// retries and the second POST succeeds. (This is the one test with a
// real-time delay, matching the client timeout's own nature.)
func TestDrainRetryClientTimeoutWithLiveParentContextRetries(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-retry-timeout-1", 1)
	h.srv.setIngestScript(scriptedIngest{status: http.StatusServiceUnavailable, delay: 150 * time.Millisecond})

	budget := syncbudget.New()
	opt := h.options()
	opt.Budget = budget
	opt.HTTPClient = &http.Client{Timeout: 60 * time.Millisecond}
	opt.Retry = retryPolicy(h.clock, 2)
	res, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
	if err != nil {
		t.Fatalf("the timed-out first POST must retry to success: %v", err)
	}
	if res.SyncedBatches != 1 || res.PendingRemaining != 0 {
		t.Fatalf("the batch must upload on the retry: %+v", res)
	}
	if _, _, ingest, _, _ := h.srv.stats(); ingest != 2 {
		t.Fatalf("the client timeout must be retried, ingest=%d", ingest)
	}
	if budget.Used() != 2 {
		t.Fatalf("each real POST must reserve, used=%d", budget.Used())
	}
}
