// Optional per-batch progress events (Options.Progress) for the cursor
// account-source uploads: every real POST attempt, the retry preflight
// and inter-attempt spacing of retried batches, and exactly one sealed
// terminal outcome per uploaded batch — closed, sanitized facts only
// (no URLs, paths, credentials, identifiers or raw errors), with
// receipt counts only after strict validation. Timing goes through the
// independent observation clock (Options.ProgressClock), never the
// business Options.Now: the tests wire the fake business clock as the
// observation source, so policy waits measure exactly and real I/O
// measures zero. Everything here is synthetic: a local fake TokTrail
// server, a fake credential, verify and pull, a temporary state
// directory — no real user state is ever touched.
package cursorsync_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/local/cursoroutbox"
	"toktrail-collector/internal/syncbudget"
)

// progressLog is a synchronized BatchProgress collector.
type progressLog struct {
	mu     sync.Mutex
	events []cursorsync.BatchProgress
}

func (p *progressLog) record(e cursorsync.BatchProgress) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, e)
}

func (p *progressLog) snapshot() []cursorsync.BatchProgress {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]cursorsync.BatchProgress(nil), p.events...)
}

// phaseResult renders the event stream compactly for failure messages
// and sequence assertions: "http:ok wait:ok preflight:ok ...".
func phaseResult(events []cursorsync.BatchProgress) string {
	parts := make([]string, 0, len(events))
	for _, e := range events {
		parts = append(parts, string(e.Phase)+":"+string(e.Result))
	}
	return strings.Join(parts, " ")
}

// wantSequence asserts the exact phase:result sequence.
func wantSequence(t *testing.T, events []cursorsync.BatchProgress, want ...string) {
	t.Helper()
	got := make([]string, 0, len(events))
	for _, e := range events {
		got = append(got, string(e.Phase)+":"+string(e.Result))
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("event sequence = %q, want %q", strings.Join(got, " "), strings.Join(want, " "))
	}
}

// findEvent returns the index-th event with the given phase.
func findEvent(t *testing.T, events []cursorsync.BatchProgress, phase cursorsync.BatchPhase, index int) cursorsync.BatchProgress {
	t.Helper()
	seen := 0
	for _, e := range events {
		if e.Phase != phase {
			continue
		}
		if seen == index {
			return e
		}
		seen++
	}
	t.Fatalf("event %s #%d not found in %q", phase, index, phaseResult(events))
	return cursorsync.BatchProgress{}
}

// seededBatchBytes returns the immutable encoded size of a seeded
// pending batch — the planned/attempted volume its events must report.
func seededBatchBytes(t *testing.T, dir, batchID string) int {
	t.Helper()
	entry := outboxEntry(t, dir, batchID)
	batch, err := cursoroutbox.New(dir).LoadBatchBytes(entry)
	if err != nil {
		t.Fatalf("load seeded batch: %v", err)
	}
	encoded, err := protocol.EncodeBatch(batch)
	if err != nil {
		t.Fatalf("encode seeded batch: %v", err)
	}
	return len(encoded)
}

// countingClock counts its reads so a test can prove a nil Progress
// never touches any clock.
type countingClock struct {
	mu    sync.Mutex
	reads int
}

func (c *countingClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	return time.Now()
}

func (c *countingClock) readCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads
}

// advancingClock is an observation clock a test advances from server
// handler hooks, proving durations measure the OBSERVATION clock rather
// than the business one.
type advancingClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *advancingClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *advancingClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// TestProgressNilCallbackReadsNoClockAndKeepsBehavior: with Progress
// nil the round runs its historical path and reads NO clock — even a
// wired ProgressClock stays untouched; with Progress set and no
// ProgressClock, the default real clock produces sane (non-negative)
// durations.
func TestProgressNilCallbackReadsNoClockAndKeepsBehavior(t *testing.T) {
	t.Run("nil progress reads no clock", func(t *testing.T) {
		h := newHarness(t)
		h.srv.setSource(defaultSource())
		h.writeLicense(t, activeLicenseForA())
		seedPendingBatch(t, h.dir, "cursor-progress-nil-1", 1)

		clock := &countingClock{}
		opt := h.options()
		opt.ProgressClock = clock.now
		res, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
		if err != nil {
			t.Fatalf("drain: %v", err)
		}
		if !res.Ran || res.SyncedBatches != 1 || res.PendingRemaining != 0 {
			t.Fatalf("the historical round result must be unchanged: %+v", res)
		}
		if n := clock.readCount(); n != 0 {
			t.Fatalf("a nil Progress must read no clock at all, reads=%d", n)
		}
	})

	t.Run("default real observation clock", func(t *testing.T) {
		h := newHarness(t)
		h.srv.setSource(defaultSource())
		h.writeLicense(t, activeLicenseForA())
		seedPendingBatch(t, h.dir, "cursor-progress-defaultclock-1", 1)

		log := &progressLog{}
		opt := h.options()
		opt.Progress = log.record
		res, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
		if err != nil {
			t.Fatalf("drain: %v", err)
		}
		if !res.Ran || res.SyncedBatches != 1 {
			t.Fatalf("unexpected round: %+v", res)
		}
		wantSequence(t, log.snapshot(), "http:ok", "outcome:acknowledged")
		for _, e := range log.snapshot() {
			if e.Duration < 0 {
				t.Fatalf("durations must be non-negative on the real clock: %+v", e)
			}
		}
	})
}

// TestProgressHappyPathDrainReportsAttemptAndAck: one seeded batch, one
// real POST, one durable acknowledgment — exactly two events, both
// carrying the trusted receipt counts and the planned payload size, and
// durations of zero under the frozen observation source (the fake
// business clock does not advance during real I/O).
func TestProgressHappyPathDrainReportsAttemptAndAck(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-progress-happy-1", 1)
	wantBytes := seededBatchBytes(t, h.dir, "cursor-progress-happy-1")

	log := &progressLog{}
	opt := h.options()
	opt.Progress = log.record
	opt.ProgressClock = h.clock.Now
	res, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if !res.Ran || res.SyncedBatches != 1 || res.SyncedRecords != 1 || res.PendingRemaining != 0 {
		t.Fatalf("unexpected round: %+v", res)
	}
	events := log.snapshot()
	wantSequence(t, events, "http:ok", "outcome:acknowledged")

	httpEv := findEvent(t, events, cursorsync.BatchPhaseHTTP, 0)
	if httpEv.Attempt != 1 || !httpEv.ReceiptKnown || httpEv.AcceptedRecords != 1 || httpEv.RejectedRecords != 0 || httpEv.Replay {
		t.Fatalf("the http event must carry the trusted receipt counts: %+v", httpEv)
	}
	if httpEv.PayloadBytes != wantBytes {
		t.Fatalf("payload bytes = %d, want the planned batch size %d", httpEv.PayloadBytes, wantBytes)
	}
	if httpEv.Duration != 0 {
		t.Fatalf("a frozen observation clock measures zero for real I/O, got %v", httpEv.Duration)
	}
	if httpEv.InterAttemptDelay != 0 {
		t.Fatalf("the initial attempt carries no inter-attempt delay: %+v", httpEv)
	}

	outcomeEv := findEvent(t, events, cursorsync.BatchPhaseOutcome, 0)
	if !outcomeEv.ReceiptKnown || outcomeEv.AcceptedRecords != 1 || outcomeEv.PayloadBytes != wantBytes || outcomeEv.Attempt != 0 {
		t.Fatalf("the acknowledged terminal must carry the counts and payload size: %+v", outcomeEv)
	}
	if outcomeEv.Duration != 0 {
		t.Fatalf("the durable acknowledgment measures zero under the frozen clock, got %v", outcomeEv.Duration)
	}
	if _, _, ingest, _, _ := h.srv.stats(); ingest != 1 {
		t.Fatalf("http events must match the real POSTs one to one, ingest=%d", ingest)
	}
}

// TestProgressFullSyncRoundReportsEveryBatch: through the whole Sync
// round (preflight, first drain, pull, second drain) every uploaded
// batch — the seeded backlog one and the one this round produced —
// reports its own attempt and exactly one terminal each.
func TestProgressFullSyncRoundReportsEveryBatch(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-progress-sync-1", 1)
	h.pull.setEvents(ev("evt-progress-sync-1", baseTime.Add(-30*time.Minute), 100, 0, 0, 50))

	log := &progressLog{}
	opt := h.options()
	opt.Progress = log.record
	opt.ProgressClock = h.clock.Now
	res, err := cursorsync.Sync(context.Background(), opt, syncGate())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if !res.Ran || res.SyncedBatches != 2 || res.PendingRemaining != 0 || res.NewRecords != 1 {
		t.Fatalf("unexpected round: %+v", res)
	}
	events := log.snapshot()
	wantSequence(t, events, "http:ok", "outcome:acknowledged", "http:ok", "outcome:acknowledged")
	_, _, ingest, _, _ := h.srv.stats()
	if ingest != 2 {
		t.Fatalf("two batches over two POSTs, ingest=%d", ingest)
	}
	terminals := 0
	for _, e := range events {
		if e.Phase == cursorsync.BatchPhaseOutcome {
			terminals++
			if e.Result != cursorsync.BatchResultAcknowledged || !e.ReceiptKnown || e.PayloadBytes <= 0 {
				t.Fatalf("every terminal must be a trusted acknowledgment: %+v", e)
			}
		}
	}
	if terminals != 2 {
		t.Fatalf("exactly one terminal per uploaded batch, got %d", terminals)
	}
}

// TestProgressRetrySequenceReportsWaitPreflightAndAttempts: one
// transient failure then success — the http failure (unknown counts),
// the wait (the exact policy spacing on the observation clock), the
// retry preflight, the successful re-send and the single
// acknowledgment.
func TestProgressRetrySequenceReportsWaitPreflightAndAttempts(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-progress-retry-1", 1)
	h.srv.setIngestScript(scriptedIngest{status: http.StatusServiceUnavailable})

	log := &progressLog{}
	opt := h.options()
	opt.Progress = log.record
	opt.ProgressClock = h.clock.Now
	opt.Retry = retryPolicy(h.clock, 2)
	res, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
	if err != nil {
		t.Fatalf("the retried drain must succeed: %v", err)
	}
	if res.SyncedBatches != 1 || res.PendingRemaining != 0 {
		t.Fatalf("unexpected round: %+v", res)
	}
	events := log.snapshot()
	wantSequence(t, events, "http:failed", "wait:ok", "preflight:ok", "http:ok", "outcome:acknowledged")

	first := findEvent(t, events, cursorsync.BatchPhaseHTTP, 0)
	if first.Attempt != 1 || first.ReceiptKnown || first.AcceptedRecords != 0 || first.RejectedRecords != 0 {
		t.Fatalf("the failed attempt carries no receipt facts: %+v", first)
	}
	wait := findEvent(t, events, cursorsync.BatchPhaseWait, 0)
	if wait.Attempt != 2 || wait.InterAttemptDelay != time.Second {
		t.Fatalf("the wait must report the exact policy spacing of the fake clock: %+v", wait)
	}
	preflight := findEvent(t, events, cursorsync.BatchPhasePreflight, 0)
	if preflight.Attempt != 2 || preflight.Duration != 0 {
		t.Fatalf("the preflight spans the boundary re-verification on the observation clock: %+v", preflight)
	}
	second := findEvent(t, events, cursorsync.BatchPhaseHTTP, 1)
	if second.Attempt != 2 || !second.ReceiptKnown || second.AcceptedRecords != 1 {
		t.Fatalf("the re-send carries the trusted receipt: %+v", second)
	}
	if _, _, ingest, _, _ := h.srv.stats(); ingest != 2 {
		t.Fatalf("http events must match the real POSTs one to one, ingest=%d", ingest)
	}
}

// TestProgressLostReceiptReplayIsTheFirstLocalAck: the first POST is
// stored server-side but its receipt is lost in transit; the re-send is
// answered with a replay receipt, which the events report batch-level —
// and which is the batch's FIRST and only local acknowledgment.
func TestProgressLostReceiptReplayIsTheFirstLocalAck(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-progress-replay-1", 1)
	h.srv.setIngestScript(scriptedIngest{status: http.StatusAccepted, truncated2xx: true})

	log := &progressLog{}
	opt := h.options()
	opt.Progress = log.record
	opt.ProgressClock = h.clock.Now
	opt.Retry = retryPolicy(h.clock, 2)
	res, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
	if err != nil {
		t.Fatalf("the lost receipt must be proven by a re-send: %v", err)
	}
	if res.SyncedBatches != 1 || res.PendingRemaining != 0 {
		t.Fatalf("unexpected round: %+v", res)
	}
	events := log.snapshot()
	wantSequence(t, events, "http:failed", "wait:ok", "preflight:ok", "http:ok", "outcome:acknowledged")

	retry := findEvent(t, events, cursorsync.BatchPhaseHTTP, 1)
	if !retry.ReceiptKnown || !retry.Replay || retry.AcceptedRecords != 1 {
		t.Fatalf("the re-send must report the replay receipt: %+v", retry)
	}
	terminal := findEvent(t, events, cursorsync.BatchPhaseOutcome, 0)
	if terminal.Result != cursorsync.BatchResultAcknowledged || !terminal.Replay || !terminal.ReceiptKnown {
		t.Fatalf("the replay receipt is the first local acknowledgment: %+v", terminal)
	}
	// Locally acknowledged exactly once; the server answered exactly one
	// replay and counted the batch exactly once.
	entry := outboxEntry(t, h.dir, "cursor-progress-replay-1")
	if entry.Status != cursoroutbox.StatusSynced {
		t.Fatalf("the batch must be marked synced once, status=%q", entry.Status)
	}
	if n := h.srv.replayAnswerCount(); n != 1 {
		t.Fatalf("exactly one replay answer, got %d", n)
	}
	if _, _, ingest, _, batches := h.srv.stats(); ingest != 2 || len(batches) != 1 {
		t.Fatalf("two POSTs of one stored batch: ingest=%d stored=%d", ingest, len(batches))
	}
}

// TestProgressBoundaryDriftStopsAfterPreflight: a drift armed during
// the first POST is detected by the retry preflight — the preflight
// event classifies it (stopped for boundary drifts, paused for a
// paused source) and the round ends with the matching terminal, no
// second POST.
func TestProgressBoundaryDriftStopsAfterPreflight(t *testing.T) {
	cases := []struct {
		name string
		arm  func(h *harness)
		want cursorsync.BatchResult
	}{
		{"fence moved", func(h *harness) {
			h.srv.setIngestHook(func() { h.srv.setSource(sourceWithFence(2)) })
		}, cursorsync.BatchResultStopped},
		{"source paused server-side", func(h *harness) {
			h.srv.setIngestHook(func() {
				paused := defaultSource()
				paused.State = "paused"
				h.srv.setSource(paused)
			})
		}, cursorsync.BatchResultPaused},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.srv.setSource(defaultSource())
			h.writeLicense(t, activeLicenseForA())
			seedPendingBatch(t, h.dir, "cursor-progress-drift-1", 1)
			h.srv.setIngestScript(scriptedIngest{status: http.StatusServiceUnavailable})
			tc.arm(h)

			log := &progressLog{}
			opt := h.options()
			opt.Progress = log.record
			opt.ProgressClock = h.clock.Now
			opt.Retry = retryPolicy(h.clock, 2)
			res, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
			if err != nil {
				t.Fatalf("a drift must stop the round, not fail it: %v", err)
			}
			if res.SyncedBatches != 0 || res.PendingRemaining != 1 {
				t.Fatalf("nothing may be acknowledged on a drifted boundary: %+v", res)
			}
			events := log.snapshot()
			wantSequence(t, events, "http:failed", "wait:ok", "preflight:"+string(tc.want), "outcome:"+string(tc.want))
			preflight := findEvent(t, events, cursorsync.BatchPhasePreflight, 0)
			if preflight.ReceiptKnown || preflight.PayloadBytes != 0 {
				t.Fatalf("a preflight event carries no receipt or payload facts: %+v", preflight)
			}
			terminal := findEvent(t, events, cursorsync.BatchPhaseOutcome, 0)
			if terminal.ReceiptKnown || terminal.PayloadBytes <= 0 {
				t.Fatalf("a stopped terminal knows no receipt but the planned payload: %+v", terminal)
			}
			if _, _, ingest, _, _ := h.srv.stats(); ingest != 1 {
				t.Fatalf("no retry POST may happen after the drift, ingest=%d", ingest)
			}
		})
	}
}

// TestProgressBudgetDeclineEmitsNoHTTPEvent: a declined shared budget
// prevents the POST entirely — the batch surfaces one failed terminal
// with the planned payload size, NO http event (no request was handed
// to the transport) and unknown receipt counts.
func TestProgressBudgetDeclineEmitsNoHTTPEvent(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-progress-budget-1", 1)
	wantBytes := seededBatchBytes(t, h.dir, "cursor-progress-budget-1")

	log := &progressLog{}
	opt := h.options()
	opt.Progress = log.record
	opt.ProgressClock = h.clock.Now
	opt.Budget = syncbudget.New(syncbudget.WithTotal(0))
	opt.Retry = retryPolicy(h.clock, 2)
	_, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
	if err == nil {
		t.Fatal("the declined budget must fail the round")
	}
	events := log.snapshot()
	wantSequence(t, events, "outcome:failed")
	terminal := findEvent(t, events, cursorsync.BatchPhaseOutcome, 0)
	if terminal.ReceiptKnown || terminal.AcceptedRecords != 0 || terminal.PayloadBytes != wantBytes {
		t.Fatalf("the declined terminal knows the planned payload but no receipt: %+v", terminal)
	}
	if _, _, ingest, _, _ := h.srv.stats(); ingest != 0 {
		t.Fatalf("no POST may happen, ingest=%d", ingest)
	}
	if n := pendingCount(t, h.dir); n != 1 {
		t.Fatalf("the batch must stay pending, pending=%d", n)
	}
}

// TestProgressPartialRejectionTerminal: a valid receipt with a rejected
// record is a complete protocol answer — the http event reports the
// trusted split counts and the terminal classifies the batch as
// rejected (it stays pending).
func TestProgressPartialRejectionTerminal(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-progress-partial-1", 2)
	h.srv.setIngestPartialRejection(0, "stale_revision")

	log := &progressLog{}
	opt := h.options()
	opt.Progress = log.record
	opt.ProgressClock = h.clock.Now
	opt.Retry = retryPolicy(h.clock, 2)
	_, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("the partial receipt must surface: %v", err)
	}
	events := log.snapshot()
	wantSequence(t, events, "http:ok", "outcome:rejected")
	httpEv := findEvent(t, events, cursorsync.BatchPhaseHTTP, 0)
	if !httpEv.ReceiptKnown || httpEv.AcceptedRecords != 1 || httpEv.RejectedRecords != 1 {
		t.Fatalf("the split counts are trusted after strict validation: %+v", httpEv)
	}
	terminal := findEvent(t, events, cursorsync.BatchPhaseOutcome, 0)
	if !terminal.ReceiptKnown || terminal.AcceptedRecords != 1 || terminal.RejectedRecords != 1 {
		t.Fatalf("the rejected terminal carries the trusted counts: %+v", terminal)
	}
	if _, _, ingest, _, _ := h.srv.stats(); ingest != 1 {
		t.Fatalf("a partial receipt never retries, ingest=%d", ingest)
	}
	if n := pendingCount(t, h.dir); n != 1 {
		t.Fatalf("the rejected batch stays pending, pending=%d", n)
	}
}

// TestProgressRetryExhaustedKeepsAttemptTruth: when the transient
// failure outlives the retry budget, both attempts report honestly and
// the single terminal is a failure with unknown counts.
func TestProgressRetryExhaustedKeepsAttemptTruth(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-progress-exhaust-1", 1)
	h.srv.setIngestScript(
		scriptedIngest{status: http.StatusServiceUnavailable},
		scriptedIngest{status: http.StatusServiceUnavailable},
	)

	log := &progressLog{}
	opt := h.options()
	opt.Progress = log.record
	opt.ProgressClock = h.clock.Now
	opt.Retry = retryPolicy(h.clock, 1)
	_, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
	if err == nil {
		t.Fatal("retry exhaustion must fail the round")
	}
	events := log.snapshot()
	wantSequence(t, events, "http:failed", "wait:ok", "preflight:ok", "http:failed", "outcome:failed")
	for _, i := range []int{0, 1} {
		httpEv := findEvent(t, events, cursorsync.BatchPhaseHTTP, i)
		if httpEv.Attempt != i+1 || httpEv.ReceiptKnown || httpEv.PayloadBytes <= 0 {
			t.Fatalf("attempt %d must report unknown counts and the planned payload: %+v", i+1, httpEv)
		}
	}
	waits := 0
	for _, e := range events {
		if e.Phase == cursorsync.BatchPhaseWait {
			waits++
		}
	}
	if waits != 1 || findEvent(t, events, cursorsync.BatchPhaseWait, 0).InterAttemptDelay != time.Second {
		t.Fatalf("exactly one wait with the exact spacing, got %d", waits)
	}
	if _, _, ingest, _, _ := h.srv.stats(); ingest != 2 {
		t.Fatalf("two real POSTs, ingest=%d", ingest)
	}
}

// TestProgressNilRetrySingleFailure: without a retry policy a transient
// failure is one attempt and one failed terminal — nothing else.
func TestProgressNilRetrySingleFailure(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-progress-nilretry-1", 1)
	h.srv.setIngestScript(scriptedIngest{status: http.StatusServiceUnavailable})

	log := &progressLog{}
	opt := h.options()
	opt.Progress = log.record
	opt.ProgressClock = h.clock.Now
	_, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
	if err == nil {
		t.Fatal("the single failed attempt must surface")
	}
	wantSequence(t, log.snapshot(), "http:failed", "outcome:failed")
	if _, _, ingest, _, _ := h.srv.stats(); ingest != 1 {
		t.Fatalf("exactly one POST, ingest=%d", ingest)
	}
}

// TestProgressSealedEnumsAndNoIdentifiers: the event stream stays
// closed and sanitized — every phase and result is one of the sealed
// constants, and the marshaled events carry no identifier, credential,
// account, source instance, server URL or raw error text whatsoever.
func TestProgressSealedEnumsAndNoIdentifiers(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-progress-privacy-1", 1)
	h.srv.setIngestScript(scriptedIngest{status: http.StatusServiceUnavailable})

	log := &progressLog{}
	opt := h.options()
	opt.Progress = log.record
	opt.ProgressClock = h.clock.Now
	opt.Retry = retryPolicy(h.clock, 2)
	if _, err := cursorsync.DrainPending(context.Background(), opt, syncGate()); err != nil {
		t.Fatalf("the retried drain must succeed: %v", err)
	}
	events := log.snapshot()
	if len(events) == 0 {
		t.Fatal("events must have been reported")
	}
	phases := map[cursorsync.BatchPhase]bool{
		cursorsync.BatchPhasePreflight: true,
		cursorsync.BatchPhaseWait:      true,
		cursorsync.BatchPhaseHTTP:      true,
		cursorsync.BatchPhaseOutcome:   true,
	}
	results := map[cursorsync.BatchResult]bool{
		cursorsync.BatchResultOK:           true,
		cursorsync.BatchResultFailed:       true,
		cursorsync.BatchResultStopped:      true,
		cursorsync.BatchResultPaused:       true,
		cursorsync.BatchResultAcknowledged: true,
		cursorsync.BatchResultRejected:     true,
	}
	terminals := 0
	for _, e := range events {
		if !phases[e.Phase] {
			t.Fatalf("unsealed phase %q", e.Phase)
		}
		if !results[e.Result] {
			t.Fatalf("unsealed result %q", e.Result)
		}
		if e.Phase == cursorsync.BatchPhaseOutcome {
			terminals++
		}
	}
	if terminals != 1 {
		t.Fatalf("exactly one terminal per batch, got %d", terminals)
	}
	// The marshaled stream must not carry any identifier, credential,
	// account, source instance, host or raw error text — and its schema
	// must stay exactly the closed field set (no status, error or
	// identifier field can sneak in unnoticed).
	blob, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("marshal events: %v", err)
	}
	text := string(blob)
	for _, forbidden := range []string{
		"cursor-progress-privacy-1", // batch id
		testDeviceID,                // device id
		testDeviceSecret,            // device credential
		accountA,                    // account identity
		"src_inst_1",                // source instance id
		h.srv.url(),                 // server URL
		"127.0.0.1",                 // host
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("the event stream must not carry %q: %s", forbidden, text)
		}
	}
	var probe []map[string]any
	if err := json.Unmarshal(blob, &probe); err != nil {
		t.Fatalf("unmarshal events: %v", err)
	}
	allowedKeys := map[string]bool{
		"Phase": true, "Result": true, "Attempt": true, "Duration": true,
		"InterAttemptDelay": true, "PayloadBytes": true, "ReceiptKnown": true,
		"AcceptedRecords": true, "RejectedRecords": true, "Replay": true,
	}
	for i, ev := range probe {
		for key := range ev {
			if !allowedKeys[key] {
				t.Fatalf("event %d carries the non-closed field %q", i, key)
			}
		}
	}
}

// TestProgressDurationsMeasureTheObservationClockNotBusinessNow: an
// observation clock advanced from the server handler measures the http
// duration, while the business clock (watermarks, attempt stamps)
// stays untouched — proving progress timing never rides Options.Now.
func TestProgressDurationsMeasureTheObservationClockNotBusinessNow(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-progress-obs-1", 1)

	obs := &advancingClock{t: baseTime}
	h.srv.setIngestHook(func() { obs.advance(5 * time.Millisecond) })

	log := &progressLog{}
	opt := h.options()
	opt.Progress = log.record
	opt.ProgressClock = obs.now
	res, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if !res.Ran || res.SyncedBatches != 1 {
		t.Fatalf("unexpected round: %+v", res)
	}
	events := log.snapshot()
	wantSequence(t, events, "http:ok", "outcome:acknowledged")
	httpEv := findEvent(t, events, cursorsync.BatchPhaseHTTP, 0)
	if httpEv.Duration != 5*time.Millisecond {
		t.Fatalf("the http duration must measure the observation clock, got %v", httpEv.Duration)
	}
	// The business clock kept its historical role alone: the durable
	// attempt stamp is the frozen fake time, not the advanced observer.
	if at := outboxEntry(t, h.dir, "cursor-progress-obs-1").LastAttemptAt; !at.Equal(baseTime) {
		t.Fatalf("the attempt stamp must keep using the business clock, got %v", at)
	}
}
