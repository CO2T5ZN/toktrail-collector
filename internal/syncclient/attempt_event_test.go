package syncclient

// Tests for the optional per-attempt progress events (Options.Progress /
// AttemptEvent). Everything here is synthetic: temporary directories,
// httptest servers, scripted failures, and fake retry clocks. No test
// touches real state, credentials, or network endpoints, and nothing is
// deployed or committed.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/syncbudget"
	"toktrail-collector/internal/syncretry"
)

// eventRecorder is the mutex-guarded Progress sink every test uses; the
// race detector watches the handoff between Run's goroutine and the test
// goroutine reading the snapshot.
type eventRecorder struct {
	mu     sync.Mutex
	events []AttemptEvent
}

func (r *eventRecorder) record(ev AttemptEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *eventRecorder) snapshot() []AttemptEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]AttemptEvent(nil), r.events...)
}

// singleFixtureRecord is the privacy-gate-clean record every batch here
// carries.
func singleFixtureRecord() map[string]any {
	return map[string]any{
		"recordKey":      "record-1",
		"kind":           "delta",
		"occurredAt":     "2026-10-20T10:00:00Z",
		"tool":           "usage-json",
		"input":          "10",
		"cacheRead":      "0",
		"cacheWrite":     "0",
		"output":         "5",
		"adapterVersion": "test-adapter-1",
		"sourceType":     "fixture",
	}
}

func TestAttemptEventSingleAttemptSuccess(t *testing.T) {
	stateDir, store, _ := setupPendingRetryBatch(t, "batch-event-1")
	server, rec := scriptedIngestServer(t, nil)
	defer server.Close()

	events := &eventRecorder{}
	res, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, Progress: events.record})
	if err != nil {
		t.Fatal(err)
	}
	if res.Receipt.AcceptedRecords != 1 {
		t.Fatalf("unexpected result: %#v", res)
	}
	evs := events.snapshot()
	if len(evs) != 1 {
		t.Fatalf("events = %d, want exactly one per attempt", len(evs))
	}
	ev := evs[0]
	if ev.Attempt != 1 {
		t.Fatalf("attempt = %d, want 1", ev.Attempt)
	}
	if ev.Stage != StageAck || ev.Result != ResultAcked {
		t.Fatalf("stage/result = %s/%s, want ack/acked", ev.Stage, ev.Result)
	}
	wantObserved := ObservedPrepare | ObservedSelfCheck | ObservedHTTP | ObservedACK | ObservedPayloadBytes
	if ev.Observed != wantObserved {
		t.Fatalf("observed = %s, want %s (no inter-attempt on the first attempt)", ev.Observed, wantObserved)
	}
	if ev.InterAttemptDelay != 0 {
		t.Fatalf("inter-attempt delay = %s, want 0 on the first attempt", ev.InterAttemptDelay)
	}
	if ev.PrepareDuration <= 0 || ev.SelfCheckDuration <= 0 || ev.HTTPDuration <= 0 || ev.ACKDuration <= 0 {
		t.Fatalf("all reached stage durations must be positive: %#v", ev)
	}
	if ev.PrepareDuration < ev.SelfCheckDuration {
		t.Fatalf("prepare (%s) must include the self check (%s)", ev.PrepareDuration, ev.SelfCheckDuration)
	}
	if !ev.ReceiptKnown || ev.Accepted != 1 || ev.Rejected != 0 || ev.BatchReplay {
		t.Fatalf("receipt fields not reported: %#v", ev)
	}
	bodies := rec.postBodies()
	if len(bodies) != 1 {
		t.Fatalf("posts = %d, want 1", len(bodies))
	}
	if ev.PayloadBytes != int64(len(bodies[0])) {
		t.Fatalf("payload bytes = %d, want the planned body size %d", ev.PayloadBytes, len(bodies[0]))
	}
}

func TestAttemptEventRetryableFailureThenAckedOnRetry(t *testing.T) {
	const batchID = "batch-event-retry-1"
	stateDir, store, _ := setupPendingRetryBatch(t, batchID)
	// A success status whose receipt dies mid-JSON: retryable, and no
	// receipt was ever seen to validate.
	truncated := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"batch":{"batchId":"` + batchID + `","status":"accep`))
	}
	server, rec := scriptedIngestServer(t, []func(w http.ResponseWriter){truncated})
	defer server.Close()

	budget := syncbudget.New(syncbudget.WithTotal(2))
	clock := newFakeRetryClock(time.Now())
	// The policy wait really sleeps so the measured inter-attempt delay
	// is deterministically observable with the monotonic clock.
	clock.wait = func(ctx context.Context, d time.Duration) error {
		time.Sleep(2 * time.Millisecond)
		return nil
	}
	policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(0))
	events := &eventRecorder{}
	if _, err := Run(t.Context(), store, Options{
		ServerURL:   server.URL,
		StateDir:    stateDir,
		Budget:      budget,
		BudgetQueue: "device",
		Retry:       policy,
		Progress:    events.record,
	}); err != nil {
		t.Fatal(err)
	}
	evs := events.snapshot()
	if len(evs) != 2 {
		t.Fatalf("events = %d, want one per attempt (2 attempts)", len(evs))
	}
	first, second := evs[0], evs[1]
	if first.Attempt != 1 || second.Attempt != 2 {
		t.Fatalf("attempt order broken: %d then %d", first.Attempt, second.Attempt)
	}
	if first.Stage != StageUpload || first.Result != ResultRetryableFailure {
		t.Fatalf("first event stage/result = %s/%s, want upload/retryable_failure", first.Stage, first.Result)
	}
	wantFirst := ObservedPrepare | ObservedSelfCheck | ObservedHTTP | ObservedPayloadBytes
	if first.Observed != wantFirst {
		t.Fatalf("first observed = %s, want %s", first.Observed, wantFirst)
	}
	if first.ReceiptKnown || first.Accepted != 0 || first.Rejected != 0 || first.BatchReplay {
		t.Fatalf("a lost body must leave the receipt unknown: %#v", first)
	}
	if first.HTTPDuration <= 0 || first.PrepareDuration <= 0 || first.SelfCheckDuration <= 0 {
		t.Fatalf("reached durations must be positive: %#v", first)
	}
	if second.Stage != StageAck || second.Result != ResultAcked {
		t.Fatalf("second event stage/result = %s/%s, want ack/acked", second.Stage, second.Result)
	}
	wantSecond := wantFirst | ObservedACK | ObservedInterAttempt
	if second.Observed != wantSecond {
		t.Fatalf("second observed = %s, want %s", second.Observed, wantSecond)
	}
	if second.InterAttemptDelay < 2*time.Millisecond {
		t.Fatalf("inter-attempt delay = %s, want at least the slept policy wait", second.InterAttemptDelay)
	}
	if !second.ReceiptKnown || second.Accepted != 1 || second.Rejected != 0 {
		t.Fatalf("receipt not reported on the acked retry: %#v", second)
	}
	if first.PayloadBytes == 0 || first.PayloadBytes != second.PayloadBytes {
		t.Fatalf("payload bytes must be known and identical across attempts: %d vs %d", first.PayloadBytes, second.PayloadBytes)
	}
	bodies := rec.postBodies()
	if len(bodies) != 2 || first.PayloadBytes != int64(len(bodies[0])) {
		t.Fatalf("payload bytes must equal the planned body size; posts = %d", len(bodies))
	}
	if got := budget.Used(); got != 2 {
		t.Fatalf("budget used = %d, want one reservation per POST", got)
	}
}

func TestAttemptEventRetryExhaustionReportsEveryAttemptOnly(t *testing.T) {
	stateDir, store, _ := setupPendingRetryBatch(t, "batch-event-exhaust-1")
	server, rec := scriptedIngestServer(t, []func(w http.ResponseWriter){
		failWith(http.StatusServiceUnavailable, ""),
		failWith(http.StatusServiceUnavailable, ""),
	})
	defer server.Close()

	policy := syncretry.New(
		syncretry.WithClock(newFakeRetryClock(time.Now())),
		syncretry.WithMaxRetries(1),
		syncretry.WithBaseDelay(0),
	)
	events := &eventRecorder{}
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, Retry: policy, Progress: events.record})
	if err == nil || !errors.Is(err, syncretry.ErrRetryExhausted) {
		t.Fatalf("expected retry exhaustion, got %v", err)
	}
	evs := events.snapshot()
	if len(evs) != 2 {
		t.Fatalf("events = %d, want exactly one per real attempt (no fabricated stop event)", len(evs))
	}
	for i, ev := range evs {
		if ev.Attempt != i+1 || ev.Stage != StageUpload || ev.Result != ResultRetryableFailure {
			t.Fatalf("event %d = attempt %d %s/%s, want a retryable upload failure", i, ev.Attempt, ev.Stage, ev.Result)
		}
		if ev.ReceiptKnown {
			t.Fatalf("event %d must not claim receipt knowledge: %#v", i, ev)
		}
	}
	if !evs[1].Observed.Has(ObservedInterAttempt) {
		t.Fatal("the retry must report the inter-attempt delay")
	}
	if got := rec.posts.Load(); got != 2 {
		t.Fatalf("posts = %d, want 2", got)
	}
}

func TestAttemptEventPausedStopsInPrepare(t *testing.T) {
	stateDir, store, _ := setupPendingRetryBatch(t, "batch-event-paused-1")
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			writeJSON(w, http.StatusOK, map[string]any{"device": map[string]any{
				"deviceId":             "dev-1",
				"consentRevision":      7,
				"uploadAuthorized":     true,
				"revoked":              false,
				"paused":               true,
				"grantProtocolVersion": 1,
			}})
			return
		}
		posts.Add(1)
		t.Errorf("paused device must not be uploaded, saw %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	events := &eventRecorder{}
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, Progress: events.record})
	if !errors.Is(err, ErrDevicePaused) {
		t.Fatalf("expected ErrDevicePaused, got %v", err)
	}
	if posts.Load() != 0 {
		t.Fatalf("posts = %d, want 0", posts.Load())
	}
	evs := events.snapshot()
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	ev := evs[0]
	if ev.Stage != StagePrepare || ev.Result != ResultFinalFailure {
		t.Fatalf("stage/result = %s/%s, want prepare/final_failure", ev.Stage, ev.Result)
	}
	wantObserved := ObservedPrepare | ObservedSelfCheck
	if ev.Observed != wantObserved {
		t.Fatalf("observed = %s, want %s (self check ran, no POST, no frozen payload)", ev.Observed, wantObserved)
	}
	if ev.ReceiptKnown || ev.PayloadBytes != 0 {
		t.Fatalf("nothing beyond the self check may be known: %#v", ev)
	}
}

func TestAttemptEventPreflightAccountingHookFailureStopsBeforeSelfCheck(t *testing.T) {
	_, store, _ := setupBoundState(t)
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": "batch-event-hook-1",
		"records": []map[string]any{singleFixtureRecord()},
	})
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		t.Errorf("a failed accounting hook must produce zero HTTP traffic, saw %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	events := &eventRecorder{}
	_, err := Run(t.Context(), store, Options{
		ServerURL: server.URL,
		BatchFile: batchFile,
		PreflightAccounting: func(time.Time) error {
			return errors.New("journal unavailable")
		},
		Progress: events.record,
	})
	if !errors.Is(err, ErrPreflightAccounting) {
		t.Fatalf("expected ErrPreflightAccounting, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("HTTP hits = %d, want 0", hits.Load())
	}
	evs := events.snapshot()
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	ev := evs[0]
	if ev.Stage != StagePrepare || ev.Result != ResultFinalFailure {
		t.Fatalf("stage/result = %s/%s, want prepare/final_failure", ev.Stage, ev.Result)
	}
	// The hook failed before preflightSelf was invoked, so not even the
	// self check may claim to have been observed.
	if ev.Observed != ObservedPrepare {
		t.Fatalf("observed = %s, want %s only", ev.Observed, ObservedPrepare)
	}
	if ev.SelfCheckDuration != 0 || ev.ReceiptKnown || ev.PayloadBytes != 0 {
		t.Fatalf("only the (partial) prepare duration may be known: %#v", ev)
	}
}

func TestAttemptEventBudgetDeclineKnowsFrozenPayloadWithoutPosting(t *testing.T) {
	stateDir, store, batchFile := setupPendingRetryBatch(t, "batch-event-budget-1")
	server, rec := scriptedIngestServer(t, nil)
	defer server.Close()

	// The planned payload is fully deterministic: the batch file
	// re-marshaled through the same struct the run freezes.
	raw, err := os.ReadFile(batchFile)
	if err != nil {
		t.Fatal(err)
	}
	var submitted BatchRequest
	if err := json.Unmarshal(raw, &submitted); err != nil {
		t.Fatal(err)
	}
	wantPayload, err := json.Marshal(submitted)
	if err != nil {
		t.Fatal(err)
	}

	events := &eventRecorder{}
	budget := syncbudget.New(syncbudget.WithTotal(0))
	_, err = Run(t.Context(), store, Options{
		ServerURL:   server.URL,
		StateDir:    stateDir,
		Budget:      budget,
		BudgetQueue: "device",
		Progress:    events.record,
	})
	if err == nil || !errors.Is(err, syncbudget.ErrTotalExhausted) {
		t.Fatalf("expected a budget decline, got %v", err)
	}
	if got := rec.posts.Load(); got != 0 {
		t.Fatalf("posts = %d, want 0 after a decline", got)
	}
	if got := rec.gets.Load(); got != 1 {
		t.Fatalf("self preflights = %d, want 1 (the decline is post-preflight)", got)
	}
	evs := events.snapshot()
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	ev := evs[0]
	if ev.Stage != StagePrepare || ev.Result != ResultFinalFailure {
		t.Fatalf("stage/result = %s/%s, want prepare/final_failure", ev.Stage, ev.Result)
	}
	wantObserved := ObservedPrepare | ObservedSelfCheck | ObservedPayloadBytes
	if ev.Observed != wantObserved {
		t.Fatalf("observed = %s, want %s (marshal ran, no POST)", ev.Observed, wantObserved)
	}
	if ev.PayloadBytes != int64(len(wantPayload)) {
		t.Fatalf("payload bytes = %d, want the frozen planned size %d", ev.PayloadBytes, len(wantPayload))
	}
	if ev.HTTPDuration != 0 || ev.ReceiptKnown {
		t.Fatalf("no POST happened, nothing upload-side may be known: %#v", ev)
	}
}

func TestAttemptEventReceiptMismatchKeepsReceiptUnknown(t *testing.T) {
	stateDir, store, _ := setupPendingRetryBatch(t, "batch-event-mismatch-1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelf(t, w, r, 7) {
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId":         "batch-event-other-1",
			"status":          "accepted",
			"acceptedRecords": 1,
			"rejectedRecords": 0,
			"replay":          false,
			"receivedAt":      "2026-10-20T10:12:00Z",
		}})
	}))
	defer server.Close()

	events := &eventRecorder{}
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, Progress: events.record})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected the receipt mismatch to surface, got %v", err)
	}
	evs := events.snapshot()
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	ev := evs[0]
	if ev.Stage != StageUpload || ev.Result != ResultFinalFailure {
		t.Fatalf("stage/result = %s/%s, want upload/final_failure", ev.Stage, ev.Result)
	}
	// The receipt decoded but failed validation, so its counts must NOT
	// be reported as known server decisions.
	if ev.ReceiptKnown || ev.Accepted != 0 || ev.Rejected != 0 || ev.BatchReplay {
		t.Fatalf("an unvalidated receipt must stay unknown: %#v", ev)
	}
	if !ev.Observed.Has(ObservedHTTP) || !ev.Observed.Has(ObservedPayloadBytes) {
		t.Fatalf("the POST happened and must be observed: %#v", ev)
	}
	assertBatchPending(t, stateDir, "batch-event-mismatch-1")
}

func TestAttemptEventACKFailureKeepsValidatedReceipt(t *testing.T) {
	stateDir, store, _ := setupPendingRetryBatch(t, "batch-event-ackfail-1")
	// Deterministic, permission-free ACK fault injection: occupy the ACK
	// journal's atomic-write temp path with a directory, so commitSyncACK
	// fails with EISDIR after reconcileReceipt already validated the
	// receipt. No chmod, no OS permission semantics involved.
	if err := os.Mkdir(filepath.Join(stateDir, syncACKJournalFileName+".tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	server, rec := scriptedIngestServer(t, nil)
	defer server.Close()

	events := &eventRecorder{}
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, Progress: events.record})
	if err == nil {
		t.Fatal("expected the ACK commit to fail")
	}
	if got := rec.posts.Load(); got != 1 {
		t.Fatalf("posts = %d, want 1", got)
	}
	evs := events.snapshot()
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	ev := evs[0]
	if ev.Stage != StageAck || ev.Result != ResultFinalFailure {
		t.Fatalf("stage/result = %s/%s, want ack/final_failure", ev.Stage, ev.Result)
	}
	// The receipt was fully validated before the ACK failed, so its
	// decisions stay known even though the attempt failed.
	if !ev.ReceiptKnown || ev.Accepted != 1 || ev.Rejected != 0 || ev.BatchReplay {
		t.Fatalf("the validated receipt must stay known through an ACK failure: %#v", ev)
	}
	if !ev.Observed.Has(ObservedACK) || ev.ACKDuration <= 0 {
		t.Fatalf("the ACK ran and must be observed: %#v", ev)
	}
	assertBatchPending(t, stateDir, "batch-event-ackfail-1")
}

func TestAttemptEventWholeBatchReplayReceipt(t *testing.T) {
	stateDir, store, _ := setupPendingRetryBatch(t, "batch-event-replay-1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelf(t, w, r, 7) {
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId":         "batch-event-replay-1",
			"status":          "accepted",
			"acceptedRecords": 1,
			"rejectedRecords": 0,
			"replay":          true,
			"receivedAt":      "2026-10-20T10:12:00Z",
		}})
	}))
	defer server.Close()

	events := &eventRecorder{}
	if _, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, Progress: events.record}); err != nil {
		t.Fatal(err)
	}
	evs := events.snapshot()
	if len(evs) != 1 || evs[0].Result != ResultAcked {
		t.Fatalf("events = %#v, want one acked event", evs)
	}
	ev := evs[0]
	if !ev.ReceiptKnown || !ev.BatchReplay {
		t.Fatalf("the whole-batch replay flag must be mirrored: %#v", ev)
	}
	if ev.Accepted != 1 || ev.Rejected != 0 {
		t.Fatalf("replayed receipt counts must be reported as stored: %#v", ev)
	}
	// A replayed receipt does not exclude a first local ACK: this run
	// synced the outbox exactly once.
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Batches) != 1 || out.Batches[0].Status != outbox.StatusSynced {
		t.Fatalf("expected exactly one local ACK: %#v", out.Batches)
	}
}

func TestAttemptEventRedaction(t *testing.T) {
	_, store, secret := setupBoundState(t)
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": "batch-event-redact-1",
		"records": []map[string]any{singleFixtureRecord()},
	})
	collect := &eventRecorder{}

	// Scenario 1: an acked send of a --file batch (no state dir).
	ackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelf(t, w, r, 7) {
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId":         "batch-event-redact-1",
			"status":          "accepted",
			"acceptedRecords": 1,
			"rejectedRecords": 0,
			"replay":          false,
			"receivedAt":      "2026-10-20T10:12:00Z",
		}})
	}))
	if _, err := Run(t.Context(), store, Options{
		ServerURL:           ackServer.URL,
		BatchFile:           batchFile,
		PreflightAccounting: func(time.Time) error { return nil },
		Progress:            collect.record,
	}); err != nil {
		t.Fatal(err)
	}
	ackServer.Close()

	// Scenario 2: a paused device stops in prepare.
	pausedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"device": map[string]any{
			"deviceId": "dev-1", "consentRevision": 7, "uploadAuthorized": true,
			"revoked": false, "paused": true, "grantProtocolVersion": 1,
		}})
	}))
	pausedState, pausedStore, _ := setupPendingRetryBatch(t, "batch-event-redact-2")
	if _, err := Run(t.Context(), pausedStore, Options{ServerURL: pausedServer.URL, StateDir: pausedState, Progress: collect.record}); !errors.Is(err, ErrDevicePaused) {
		t.Fatal(err)
	}
	pausedServer.Close()

	// Scenario 3: a receipt mismatch fails in upload.
	mismatchState, mismatchStore, _ := setupPendingRetryBatch(t, "batch-event-redact-3")
	mismatchServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelf(t, w, r, 7) {
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId": "batch-event-redact-other", "status": "accepted",
			"acceptedRecords": 1, "rejectedRecords": 0, "replay": false,
			"receivedAt": "2026-10-20T10:12:00Z",
		}})
	}))
	if _, err := Run(t.Context(), mismatchStore, Options{ServerURL: mismatchServer.URL, StateDir: mismatchState, Progress: collect.record}); err == nil {
		t.Fatal("expected the mismatch failure")
	}
	mismatchServer.Close()

	events := collect.snapshot()
	if len(events) != 3 {
		t.Fatalf("events = %d, want 3 across the scenarios", len(events))
	}
	forbidden := []string{
		"batch-event-redact-1", "batch-event-redact-2", "batch-event-redact-3",
		"batch-event-redact-other", "dev-1", secret, "record-1",
		"127.0.0.1", "batchId", "recordKey", "device", "paused",
		"does not match", "status", "URL", "secret",
	}
	wantKeys := []string{
		"attempt", "stage", "result", "observed", "interAttemptDelay",
		"prepareDuration", "selfCheckDuration", "httpDuration", "ackDuration",
		"payloadBytes", "receiptKnown", "accepted", "rejected", "batchReplay",
	}
	for i, ev := range events {
		b, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		text := string(b)
		for _, leak := range forbidden {
			if strings.Contains(text, leak) {
				t.Fatalf("event %d leaks %q: %s", i, leak, text)
			}
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		if len(m) != len(wantKeys) {
			t.Fatalf("event %d has %d keys, want exactly %d", i, len(m), len(wantKeys))
		}
		for _, key := range wantKeys {
			if _, ok := m[key]; !ok {
				t.Fatalf("event %d is missing key %q: %s", i, key, text)
			}
		}
		// The string renderings are fixed identifiers, never data.
		for _, rendered := range []string{ev.Stage.String(), ev.Result.String(), ev.Observed.String()} {
			for _, leak := range forbidden {
				if strings.Contains(rendered, leak) {
					t.Fatalf("event %d enum rendering leaks %q: %s", i, leak, rendered)
				}
			}
		}
	}
}

func TestAttemptEventNilProgressChangesNothing(t *testing.T) {
	// runOnce executes the identical scripted scenario — a 503 that a
	// single retry then overcomes — with or without a Progress callback,
	// on fresh but identically-shaped state, and returns everything the
	// run touched that must not differ.
	type runStats struct {
		posts, gets    int32
		bodies         [][]byte
		budgetUsed     int
		preflightCount int
		outboxStatus   string
		receiptStatus  string
		accepted       int
		stateBatch     string
		stateStatus    string
		stateAccepted  int
		stateRejected  int
		events         int
	}
	runOnce := func(withProgress bool) runStats {
		stateDir, store, _ := setupPendingRetryBatch(t, "batch-event-parity-1")
		server, rec := scriptedIngestServer(t, []func(w http.ResponseWriter){
			failWith(http.StatusServiceUnavailable, ""),
		})
		defer server.Close()
		budget := syncbudget.New(syncbudget.WithTotal(2))
		policy := syncretry.New(syncretry.WithClock(newFakeRetryClock(time.Now())), syncretry.WithBaseDelay(0))
		opt := Options{
			ServerURL:   server.URL,
			StateDir:    stateDir,
			Budget:      budget,
			BudgetQueue: "device",
			Retry:       policy,
		}
		collect := &eventRecorder{}
		if withProgress {
			opt.Progress = collect.record
		}
		res, err := Run(t.Context(), store, opt)
		if err != nil {
			t.Fatalf("run with progress=%t: %v", withProgress, err)
		}
		preflight, err := outbox.New(stateDir).LoadPreflightAttempts()
		if err != nil {
			t.Fatal(err)
		}
		out, err := outbox.New(stateDir).Load()
		if err != nil {
			t.Fatal(err)
		}
		st, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		return runStats{
			posts:          rec.posts.Load(),
			gets:           rec.gets.Load(),
			bodies:         rec.postBodies(),
			budgetUsed:     budget.Used(),
			preflightCount: preflight.Count,
			outboxStatus:   out.Batches[0].Status,
			receiptStatus:  out.Batches[0].ReceiptStatus,
			accepted:       res.Receipt.AcceptedRecords,
			stateBatch:     st.LastSyncBatchID,
			stateStatus:    st.LastSyncStatus,
			stateAccepted:  st.LastSyncAcceptedRecords,
			stateRejected:  st.LastSyncRejectedRecords,
			events:         len(collect.snapshot()),
		}
	}
	without, with := runOnce(false), runOnce(true)
	if without.posts != 2 || without.gets != 2 || without.budgetUsed != 2 || without.preflightCount != 2 {
		t.Fatalf("baseline run misbehaved: %#v", without)
	}
	if without.posts != with.posts || without.gets != with.gets || without.budgetUsed != with.budgetUsed || without.preflightCount != with.preflightCount {
		t.Fatalf("HTTP/accounting drift: nil %#v vs progress %#v", without, with)
	}
	if len(without.bodies) != len(with.bodies) {
		t.Fatalf("post count drift: %d vs %d", len(without.bodies), len(with.bodies))
	}
	for i := range without.bodies {
		if string(without.bodies[i]) != string(with.bodies[i]) {
			t.Fatalf("post body %d drifted between nil and progress runs", i)
		}
	}
	if without.outboxStatus != with.outboxStatus || without.receiptStatus != with.receiptStatus ||
		without.accepted != with.accepted || without.stateBatch != with.stateBatch ||
		without.stateStatus != with.stateStatus || without.stateAccepted != with.stateAccepted ||
		without.stateRejected != with.stateRejected {
		t.Fatalf("outcome drift: nil %#v vs progress %#v", without, with)
	}
	if with.events != 2 {
		t.Fatalf("progress events = %d, want one per attempt", with.events)
	}
}

func TestAttemptEventNotEmittedOutsideBatchAttempts(t *testing.T) {
	// The events cover per-batch send attempts only: FetchDeviceSelf —
	// a bare authorization snapshot read — must stay silent even with a
	// Progress callback wired.
	_, store, _ := setupBoundState(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveSelf(t, w, r, 7)
	}))
	defer server.Close()
	collect := &eventRecorder{}
	if _, err := FetchDeviceSelf(t.Context(), store, Options{ServerURL: server.URL, Progress: collect.record}); err != nil {
		t.Fatal(err)
	}
	if got := len(collect.snapshot()); got != 0 {
		t.Fatalf("FetchDeviceSelf emitted %d events, want 0", got)
	}
}

func TestAttemptEventInterAttemptDelayExcludesSlowCallback(t *testing.T) {
	// Regression for the delay-capture point: prevAttemptEnd is taken
	// AFTER the Progress callback returns, so a slow consumer must not
	// inflate the measured inter-attempt gap. The policy wait really
	// sleeps 2ms while the callback sleeps 25ms; the reported delay must
	// include the former and exclude the latter. With the timestamp
	// taken before the callback, the delay would reach the 25ms
	// callback time and this test fails.
	const batchID = "batch-event-slowcb-1"
	stateDir, store, _ := setupPendingRetryBatch(t, batchID)
	truncated := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"batch":{"batchId":"` + batchID + `","status":"accep`))
	}
	server, _ := scriptedIngestServer(t, []func(w http.ResponseWriter){truncated})
	defer server.Close()

	clock := newFakeRetryClock(time.Now())
	clock.wait = func(ctx context.Context, d time.Duration) error {
		time.Sleep(2 * time.Millisecond) // the policy wait, really slept
		return nil
	}
	policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(0))
	collect := &eventRecorder{}
	slow := func(ev AttemptEvent) {
		time.Sleep(25 * time.Millisecond) // a slow consumer
		collect.record(ev)
	}
	if _, err := Run(t.Context(), store, Options{
		ServerURL: server.URL,
		StateDir:  stateDir,
		Retry:     policy,
		Progress:  slow,
	}); err != nil {
		t.Fatal(err)
	}
	evs := collect.snapshot()
	if len(evs) != 2 || evs[1].Attempt != 2 {
		t.Fatalf("events = %#v, want two ordered events", evs)
	}
	delay := evs[1].InterAttemptDelay
	if !evs[1].Observed.Has(ObservedInterAttempt) || delay < 2*time.Millisecond {
		t.Fatalf("inter-attempt delay = %s, must include the slept policy wait", delay)
	}
	if delay >= 25*time.Millisecond {
		t.Fatalf("inter-attempt delay = %s, must exclude the 25ms callback time", delay)
	}
}

func TestAttemptEventNilProgressNeverReadsInstrumentationClock(t *testing.T) {
	// The nil-Progress contract, verified directly rather than through
	// HTTP outcomes: with no callback wired, the instrumentation clock
	// (attemptNow) must never be read — no tracker, no stage timing, no
	// prevAttemptEnd bookkeeping. With a callback wired, the reads are
	// exactly the documented stage boundaries.
	orig := attemptNow
	defer func() { attemptNow = orig }()
	var reads int
	installCountingClock := func() {
		reads = 0
		attemptNow = func() time.Time {
			reads++
			return orig()
		}
	}

	// Nil Progress: a full successful send must read the clock zero
	// times.
	nilState, nilStore, _ := setupPendingRetryBatch(t, "batch-event-clock-nil-1")
	nilServer, nilRec := scriptedIngestServer(t, nil)
	defer nilServer.Close()
	installCountingClock()
	if _, err := Run(t.Context(), nilStore, Options{ServerURL: nilServer.URL, StateDir: nilState}); err != nil {
		t.Fatal(err)
	}
	if reads != 0 {
		t.Fatalf("nil Progress read the instrumentation clock %d times, want 0", reads)
	}
	if got := nilRec.posts.Load(); got != 1 {
		t.Fatalf("posts = %d, want the run itself to behave normally", got)
	}

	// Progress wired: a single successful attempt reads the clock at
	// exactly the nine stage boundaries — attempt start, self check
	// start and done, POST issue, POST done, ACK start and done, the
	// wrapper's prevAttemptEnd, and finish's conclusion read.
	progState, progStore, _ := setupPendingRetryBatch(t, "batch-event-clock-prog-1")
	progServer, _ := scriptedIngestServer(t, nil)
	defer progServer.Close()
	installCountingClock()
	collect := &eventRecorder{}
	if _, err := Run(t.Context(), progStore, Options{ServerURL: progServer.URL, StateDir: progState, Progress: collect.record}); err != nil {
		t.Fatal(err)
	}
	if reads != 9 {
		t.Fatalf("progress run read the instrumentation clock %d times, want 9 (the documented stage boundaries)", reads)
	}
	if evs := collect.snapshot(); len(evs) != 1 || evs[0].Result != ResultAcked {
		t.Fatalf("events = %#v, want one acked event", evs)
	}
}

func TestAttemptProgressNilReceiverMarksAllocateNothing(t *testing.T) {
	// The nil tracker's marks must be true no-ops: no panic, no clock
	// read, and zero heap allocations per run — this is what makes the
	// nil-Progress path instrument nothing rather than instrument
	// silently.
	var tr *attemptProgress
	allocs := testing.AllocsPerRun(200, func() {
		tr.markSelfStart()
		tr.markSelfDone()
		tr.noteFrozenPayload(42)
		tr.markPostIssued()
		tr.markPostDone()
		tr.setReceipt(BatchReceipt{AcceptedRecords: 1, RejectedRecords: 0, Replay: true})
		tr.markAckStart()
		tr.markAckDone()
	})
	if allocs != 0 {
		t.Fatalf("nil-receiver marks allocated %v per run, want 0", allocs)
	}
}

func TestAttemptProgressTrackerSemantics(t *testing.T) {
	// First attempt: no predecessor, so no inter-attempt delay exists.
	first := startAttemptProgress(1, time.Time{})
	if first.interAttempt {
		t.Fatal("the first attempt must not claim an inter-attempt delay")
	}
	ev := first.finish(errors.New("boom"))
	if ev.Result != ResultFinalFailure || ev.Stage != StagePrepare {
		t.Fatalf("plain failure classified as %s/%s", ev.Stage, ev.Result)
	}
	if ev.Observed != ObservedPrepare || ev.PrepareDuration < 0 {
		t.Fatalf("only the (partial) prepare duration may be known: %#v", ev)
	}

	// A retry with a synthetic 25ms gap behind it.
	prevEnd := time.Now().Add(-25 * time.Millisecond)
	retry := startAttemptProgress(2, prevEnd)
	ev = retry.finish(syncretry.Retryable(errors.New("transient")))
	if ev.Result != ResultRetryableFailure {
		t.Fatalf("retry-marked failure classified as %s", ev.Result)
	}
	if !ev.Observed.Has(ObservedInterAttempt) || ev.InterAttemptDelay < 25*time.Millisecond {
		t.Fatalf("inter-attempt delay = %s, want at least the synthetic 25ms gap", ev.InterAttemptDelay)
	}

	// A fully successful attempt walks every mark.
	full := startAttemptProgress(2, time.Now().Add(-time.Millisecond))
	full.markSelfStart()
	full.markSelfDone()
	full.noteFrozenPayload(1234)
	full.markPostIssued()
	full.markPostDone()
	full.setReceipt(BatchReceipt{AcceptedRecords: 2, RejectedRecords: 1, Replay: true})
	full.markAckStart()
	full.markAckDone()
	ev = full.finish(nil)
	if ev.Result != ResultAcked || ev.Stage != StageAck {
		t.Fatalf("success classified as %s/%s", ev.Stage, ev.Result)
	}
	wantAll := ObservedPrepare | ObservedSelfCheck | ObservedHTTP | ObservedACK | ObservedInterAttempt | ObservedPayloadBytes
	if ev.Observed != wantAll {
		t.Fatalf("observed = %s, want %s", ev.Observed, wantAll)
	}
	if ev.PayloadBytes != 1234 || !ev.ReceiptKnown || ev.Accepted != 2 || ev.Rejected != 1 || !ev.BatchReplay {
		t.Fatalf("marked values not reported: %#v", ev)
	}
	if ev.PrepareDuration < ev.SelfCheckDuration {
		t.Fatalf("prepare must contain the self check: %#v", ev)
	}

	// Enum renderings are stable, closed identifiers.
	for _, tc := range []struct {
		got, want string
	}{
		{StagePrepare.String(), "prepare"},
		{StageUpload.String(), "upload"},
		{StageAck.String(), "ack"},
		{ResultAcked.String(), "acked"},
		{ResultRetryableFailure.String(), "retryable_failure"},
		{ResultFinalFailure.String(), "final_failure"},
		{AttemptObserved(0).String(), "none"},
		{wantAll.String(), "prepare|self_check|http|ack|inter_attempt|payload_bytes"},
	} {
		if tc.got != tc.want {
			t.Fatalf("enum rendering = %q, want %q", tc.got, tc.want)
		}
	}
	// Has requires every requested bit.
	if (ObservedPrepare | ObservedHTTP).Has(ObservedACK) {
		t.Fatal("Has must require every requested bit")
	}
	if !(ObservedPrepare | ObservedHTTP).Has(ObservedHTTP) {
		t.Fatal("Has must find a set bit")
	}
}
