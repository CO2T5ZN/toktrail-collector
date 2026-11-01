package syncclient

// PreflightAccounting coverage for the StateDir-less send path (the
// history retransmission): the caller-supplied hook must fire
// immediately before EVERY device self GET — the first attempt's and
// every retry's — and a hook failure must stop the run with zero HTTP
// traffic as a final (never retried) error wrapping
// ErrPreflightAccounting.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncbudget"
	"toktrail-collector/internal/syncretry"
)

// outboxLedgerPreflightCount reads the durable preflight-attempt
// accounting a StateDir-carrying run maintains.
func outboxLedgerPreflightCount(stateDir string) (int, error) {
	attempts, err := outbox.New(stateDir).LoadPreflightAttempts()
	if err != nil {
		return 0, err
	}
	return attempts.Count, nil
}

// countedHook records every invocation timestamp.
type countedHook struct {
	mu    sync.Mutex
	calls []time.Time
	fail  func(n int) error // 1-based call number decides an injected failure
}

func (h *countedHook) record(at time.Time) error {
	h.mu.Lock()
	n := len(h.calls) + 1
	h.calls = append(h.calls, at)
	fail := h.fail
	h.mu.Unlock()
	if fail != nil {
		return fail(n)
	}
	return nil
}

func (h *countedHook) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.calls)
}

// setupFileOnlyBatch wires a bound device plus an explicitly selected
// batch FILE with NO StateDir on the sync options — the history
// retransmission shape. (The device state still lives in the temp
// directory setupBoundState builds; only the send options omit StateDir.)
func setupFileOnlyBatch(t *testing.T, batchID string) (statedir.Store, string) {
	t.Helper()
	_, store, _ := setupBoundState(t)
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": batchID,
		"records": []map[string]any{{
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
		}},
	})
	return store, batchFile
}

// TestPreflightAccountingHookFiresBeforeEverySelfGet drives a 503→200
// retry over a BatchFile-only run and asserts the hook fires exactly once
// per self GET (two attempts, two GETs, two records), the two POSTs are
// byte-identical under the same batch ID, and the budget reserved once
// per real POST.
func TestPreflightAccountingHookFiresBeforeEverySelfGet(t *testing.T) {
	const batchID = "batch-preflight-hook-1"
	store, batchFile := setupFileOnlyBatch(t, batchID)
	server, rec := scriptedIngestServer(t, []func(w http.ResponseWriter){
		failWith(http.StatusServiceUnavailable, ""),
	})
	defer server.Close()

	hook := &countedHook{}
	budget := syncbudget.New(syncbudget.WithTotal(4))
	clock := newFakeRetryClock(time.Now())
	policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(0))
	res, err := Run(t.Context(), store, Options{
		ServerURL:           server.URL,
		BatchFile:           batchFile,
		BatchID:             batchID,
		Budget:              budget,
		BudgetQueue:         "history",
		Retry:               policy,
		PreflightAccounting: hook.record,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := rec.posts.Load(); got != 2 {
		t.Fatalf("posts = %d, want 2 (503 then accepted)", got)
	}
	if got := rec.gets.Load(); got != 2 {
		t.Fatalf("self GETs = %d, want 2 (one per attempt)", got)
	}
	if got := hook.count(); got != 2 {
		t.Fatalf("preflight accounting records = %d, want exactly one per self GET (2)", got)
	}
	if got := budget.Used(); got != 2 {
		t.Fatalf("budget used = %d, want one reservation per real POST", got)
	}
	bodies := rec.postBodies()
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("the retry must resend byte-identical payloads")
	}
	var sent BatchRequest
	if err := json.Unmarshal(bodies[0], &sent); err != nil {
		t.Fatal(err)
	}
	if sent.BatchID != batchID || res.Receipt.BatchID != batchID {
		t.Fatalf("batch ID drifted: sent %q receipt %q", sent.BatchID, res.Receipt.BatchID)
	}
}

// TestPreflightAccountingHookFailureFailsClosedBeforeAnyHTTP pins the
// fail-closed contract: a hook failure on the FIRST attempt performs zero
// self GETs and zero POSTs, surfaces ErrPreflightAccounting, and never
// waits (the error is final, not retryable).
func TestPreflightAccountingHookFailureFailsClosedBeforeAnyHTTP(t *testing.T) {
	const batchID = "batch-preflight-fail-1"
	store, batchFile := setupFileOnlyBatch(t, batchID)
	server, rec := scriptedIngestServer(t, nil)
	defer server.Close()

	hook := &countedHook{fail: func(n int) error {
		return errors.New("disk full: cannot persist preflight accounting")
	}}
	clock := newFakeRetryClock(time.Now())
	policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(0))
	_, err := Run(t.Context(), store, Options{
		ServerURL:           server.URL,
		BatchFile:           batchFile,
		BatchID:             batchID,
		Retry:               policy,
		PreflightAccounting: hook.record,
	})
	if err == nil || !errors.Is(err, ErrPreflightAccounting) {
		t.Fatalf("expected ErrPreflightAccounting to surface, got %v", err)
	}
	if got := rec.gets.Load(); got != 0 {
		t.Fatalf("self GETs = %d, want zero: the hook must gate the GET", got)
	}
	if got := rec.posts.Load(); got != 0 {
		t.Fatalf("posts = %d, want zero: failure means no send", got)
	}
	if waits := clock.recordedWaits(); len(waits) != 0 {
		t.Fatalf("a hook failure is final and must never wait, waited %v", waits)
	}
}

// TestPreflightAccountingHookFailureOnRetryStopsTheLoop pins the same
// contract mid-retry: the first attempt ran (one GET, one 503 POST), the
// retry's hook fails, and the loop stops without a second POST.
func TestPreflightAccountingHookFailureOnRetryStopsTheLoop(t *testing.T) {
	const batchID = "batch-preflight-fail-2"
	store, batchFile := setupFileOnlyBatch(t, batchID)
	server, rec := scriptedIngestServer(t, []func(w http.ResponseWriter){
		failWith(http.StatusServiceUnavailable, ""),
	})
	defer server.Close()

	hook := &countedHook{fail: func(n int) error {
		if n >= 2 {
			return errors.New("disk full: cannot persist preflight accounting")
		}
		return nil
	}}
	clock := newFakeRetryClock(time.Now())
	policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(0))
	_, err := Run(t.Context(), store, Options{
		ServerURL:           server.URL,
		BatchFile:           batchFile,
		BatchID:             batchID,
		Retry:               policy,
		PreflightAccounting: hook.record,
	})
	if err == nil || !errors.Is(err, ErrPreflightAccounting) {
		t.Fatalf("expected ErrPreflightAccounting to surface, got %v", err)
	}
	if got := rec.gets.Load(); got != 1 {
		t.Fatalf("self GETs = %d, want 1 (only the first attempt's)", got)
	}
	if got := rec.posts.Load(); got != 1 {
		t.Fatalf("posts = %d, want 1 (the 503); the retry must not POST", got)
	}
	// Exactly the one backoff between the two attempts was waited; the
	// hook failure itself is final, so no further wait may follow it.
	if waits := clock.recordedWaits(); len(waits) != 1 {
		t.Fatalf("expected exactly the one inter-attempt backoff, waited %v", waits)
	}
}

// TestPreflightAccountingIgnoredWithStateDir pins that a run WITH a
// StateDir keeps the built-in ledger accounting and never calls the
// caller hook (the field serves only the StateDir-less history path).
func TestPreflightAccountingIgnoredWithStateDir(t *testing.T) {
	const batchID = "batch-preflight-statedir-1"
	stateDir, store, _ := setupPendingRetryBatch(t, batchID)
	server, rec := scriptedIngestServer(t, []func(w http.ResponseWriter){
		failWith(http.StatusServiceUnavailable, ""),
	})
	defer server.Close()

	hook := &countedHook{}
	clock := newFakeRetryClock(time.Now())
	policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(0))
	if _, err := Run(t.Context(), store, Options{
		ServerURL:           server.URL,
		StateDir:            stateDir,
		Budget:              syncbudget.New(syncbudget.WithTotal(4)),
		BudgetQueue:         "device",
		Retry:               policy,
		PreflightAccounting: hook.record,
	}); err != nil {
		t.Fatal(err)
	}
	if got := hook.count(); got != 0 {
		t.Fatalf("the hook must stay silent when a StateDir is set, got %d calls", got)
	}
	// The built-in ledger accounting covered both attempts instead.
	attempts, err := outboxLedgerPreflightCount(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("ledger preflight records = %d, want one per self GET (2)", attempts)
	}
	if got := rec.gets.Load(); got != 2 {
		t.Fatalf("self GETs = %d, want 2", got)
	}
}
