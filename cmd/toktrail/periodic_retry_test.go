package main

// Entry-level retry wiring coverage for the periodic CLI entry
// (runPeriodic), which builds its own production policy internally —
// full jitter, run deadline pinned to the --sync-timeout ctx deadline —
// so these tests exercise the REAL construction (only the jittered
// first-retry wait up to ~1s is real time; everything else is synthetic
// tempdir state and an httptest fake).
//
// Covered:
//   - 503→200: the retried batch is resent byte-identically under the
//     same batch ID and ACKed exactly once (one synced outbox entry).
//   - Budget exhaustion mid-retry: with --max-total-batches 1 the failed
//     first POST's reservation is real, the retry is declined BEFORE its
//     POST, and the run exits non-zero with the budget sentinel.
//   - Retry-After past the run deadline: the policy refuses the wait
//     without sleeping, exactly one POST happens.
//   - Authorization change between attempts: the retry's preflight is
//     refused and the run stops without a second POST; nothing commits.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncbudget"
)

// periodicRetryServer fakes the ingest server for the retry wiring: a
// self endpoint whose Nth GET can flip to a 401 device_revoked, and an
// ingest endpoint whose first POST comes from a script (retryable 503 or
// a Retry-After floor) before accepting everything, capturing raw POST
// bodies.
type periodicRetryServer struct {
	*httptest.Server
	self   atomic.Int64
	posts  atomic.Int64
	mu     sync.Mutex
	bodies [][]byte
	// script holds the scripted first response (status + optional
	// Retry-After); nil means accept immediately.
	script *periodicRetryScript
	// unauthorizedFromSelf makes every self GET at or beyond this 1-based
	// count answer 401 device_revoked (0=never).
	unauthorizedFromSelf int64
}

type periodicRetryScript struct {
	status     int
	retryAfter string
}

func newPeriodicRetryServer(t *testing.T, script *periodicRetryScript) *periodicRetryServer {
	t.Helper()
	s := &periodicRetryServer{script: script}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self":
			n := s.self.Add(1)
			if s.unauthorizedFromSelf > 0 && n >= s.unauthorizedFromSelf {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "device_revoked", "message": "synthetic revocation"}})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"device": map[string]any{
				"deviceId":          "dev-retry-1",
				"applicationId":     "app-retry-1",
				"externalSubjectId": "sub-retry-1",
				"deviceName":        "collector-retry-test",
				"platform":          "darwin",
				"consentRevision":   7,
				"uploadAuthorized":  true,
				"publicAuthorized":  false,
				"revoked":           false,
				"checkedAt":         "2026-10-30T04:00:00Z",
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/batches":
			s.posts.Add(1)
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read ingest body: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			s.mu.Lock()
			s.bodies = append(s.bodies, append([]byte(nil), body...))
			script := s.script
			s.script = nil
			s.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if script != nil {
				if script.retryAfter != "" {
					w.Header().Set("Retry-After", script.retryAfter)
				}
				w.WriteHeader(script.status)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "service_unavailable", "message": "synthetic transient failure"}})
				return
			}
			var batch struct {
				BatchID string `json:"batchId"`
				Records []struct {
					RecordKey string `json:"recordKey"`
				} `json:"records"`
			}
			_ = json.Unmarshal(body, &batch)
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]any{"batch": map[string]any{
				"batchId":         batch.BatchID,
				"status":          "accepted",
				"acceptedRecords": len(batch.Records),
				"rejectedRecords": 0,
				"replay":          false,
				"receivedAt":      "2026-10-30T04:01:00Z",
				"recordErrors":    []map[string]any{},
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/devices/tool-status":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]any{"accepted": true})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *periodicRetryServer) postBodies() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, len(s.bodies))
	copy(out, s.bodies)
	return out
}

// periodicRetryFixture prepares a bound device with one pending device
// batch and a granted (record-empty) claude-code-jsonl session directory,
// so a full periodic run scans the grant, finds no new records, and
// drains only the seeded batch.
func periodicRetryFixture(t *testing.T, server *periodicRetryServer) string {
	t.Helper()
	stateDir := t.TempDir()
	if err := statedir.New(stateDir).Save(statedir.DeviceState{
		ServerURL:    server.URL,
		DeviceID:     "dev-retry-1",
		DeviceSecret: periodicDrainSecret,
	}); err != nil {
		t.Fatal(err)
	}
	writePeriodicDrainPendingBatch(t, stateDir, "batch-periodic-retry-1", 1)
	sessions := filepath.Join(t.TempDir(), "sessions")
	if err := os.MkdirAll(sessions, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := grants.New(stateDir).Enable("claude-code-jsonl", sessions); err != nil {
		t.Fatal(err)
	}
	return stateDir
}

// TestRunPeriodicRetriesTransientIngestFailure drives the production
// policy the entry builds: a retryable 503 on the batch's first POST is
// retried (the jittered wait is at most ~1s), the resend is
// byte-identical under the same batch ID, and the run completes with the
// batch ACKed exactly once.
func TestRunPeriodicRetriesTransientIngestFailure(t *testing.T) {
	server := newPeriodicRetryServer(t, &periodicRetryScript{status: http.StatusServiceUnavailable})
	stateDir := periodicRetryFixture(t, server)

	args := []string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--sync-timeout", "30s",
	}
	out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
	if err != nil {
		t.Fatalf("the retried periodic run must succeed, got %v\nstdout:\n%s", err, out)
	}
	if got := server.posts.Load(); got != 2 {
		t.Fatalf("posts = %d, want 2 (503 then accepted)", got)
	}
	bodies := server.postBodies()
	if len(bodies) != 2 || string(bodies[0]) != string(bodies[1]) {
		t.Fatal("the retry must resend byte-identical payloads under the same batch ID")
	}
	var sent struct {
		BatchID string `json:"batchId"`
	}
	if err := json.Unmarshal(bodies[0], &sent); err != nil {
		t.Fatal(err)
	}
	if sent.BatchID != "batch-periodic-retry-1" {
		t.Fatalf("batch ID drifted across attempts: %q", sent.BatchID)
	}
	if !strings.Contains(out, "syncedBatches=1 syncedRecords=1") {
		t.Fatalf("expected the single batch synced, stdout:\n%s", out)
	}
	final, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(final.Batches) != 1 || final.Batches[0].Status != outbox.StatusSynced {
		t.Fatalf("expected the batch ACKed exactly once, got %#v", final.Batches)
	}
}

// TestRunPeriodicBudgetDeclineStopsTheRetry pins the budget consistency
// under retry: with --max-total-batches 1 the failed first POST consumes
// the only unit and the retry is declined BEFORE its POST — the run
// exits non-zero with the budget sentinel and the batch stays pending.
func TestRunPeriodicBudgetDeclineStopsTheRetry(t *testing.T) {
	server := newPeriodicRetryServer(t, &periodicRetryScript{status: http.StatusServiceUnavailable})
	stateDir := periodicRetryFixture(t, server)

	args := []string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--max-total-batches", "1",
		"--sync-timeout", "30s",
	}
	out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
	if err == nil {
		t.Fatalf("the budget-exhausted retry run must exit non-zero, stdout:\n%s", out)
	}
	if !errors.Is(err, syncbudget.ErrTotalExhausted) {
		t.Fatalf("expected the budget sentinel, got %v", err)
	}
	if got := server.posts.Load(); got != 1 {
		t.Fatalf("posts = %d, want exactly 1: the retry was declined before its POST", got)
	}
	final, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if final.Batches[0].Status != outbox.StatusPending {
		t.Fatalf("the declined batch must stay pending, got %#v", final.Batches[0])
	}
}

// TestRunPeriodicRetryAfterPastRunDeadlineStops pins the deadline stop
// through the real policy construction: a server Retry-After of one hour
// against a 5-second run window is refused WITHOUT waiting, exactly one
// POST happens, and nothing commits (the batch stays pending, the run
// exits non-zero).
func TestRunPeriodicRetryAfterPastRunDeadlineStops(t *testing.T) {
	server := newPeriodicRetryServer(t, &periodicRetryScript{status: http.StatusTooManyRequests, retryAfter: "3600"})
	stateDir := periodicRetryFixture(t, server)

	args := []string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--sync-timeout", "5s",
	}
	start := time.Now()
	out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("the Retry-After past the run deadline must stop the run, stdout:\n%s", out)
	}
	if !strings.Contains(err.Error(), "run deadline") {
		t.Fatalf("expected the run-deadline refusal to surface, got %v", err)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("the deadline check must fail fast instead of waiting out the Retry-After, took %s", elapsed)
	}
	if got := server.posts.Load(); got != 1 {
		t.Fatalf("posts = %d, want exactly 1: the retry must not start past the deadline", got)
	}
	final, err2 := outbox.New(stateDir).Load()
	if err2 != nil {
		t.Fatal(err2)
	}
	if final.Batches[0].Status != outbox.StatusPending {
		t.Fatalf("the stopped batch must stay pending, got %#v", final.Batches[0])
	}
}

// TestRunPeriodicAuthorizationChangeStopsTheRetry pins the authorization
// stop: when the live self view turns unauthorized between the first
// attempt and the retry's preflight, the retry stops for good — one POST,
// nothing committed.
func TestRunPeriodicAuthorizationChangeStopsTheRetry(t *testing.T) {
	server := newPeriodicRetryServer(t, &periodicRetryScript{status: http.StatusServiceUnavailable})
	// Self GET #1 is the grant sync, #2 the first attempt's preflight;
	// #3 (the retry's preflight) is unauthorized from there on.
	server.unauthorizedFromSelf = 3
	stateDir := periodicRetryFixture(t, server)

	args := []string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--sync-timeout", "30s",
	}
	out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
	if err == nil {
		t.Fatalf("the authorization change must stop the run, stdout:\n%s", out)
	}
	if !strings.Contains(err.Error(), "device_revoked") {
		t.Fatalf("expected the authorization stop to surface, got %v", err)
	}
	if got := server.posts.Load(); got != 1 {
		t.Fatalf("posts = %d, want exactly 1: the retry's preflight refused the resend", got)
	}
	final, err2 := outbox.New(stateDir).Load()
	if err2 != nil {
		t.Fatal(err2)
	}
	if final.Batches[0].Status != outbox.StatusPending {
		t.Fatalf("the stopped batch must stay pending, got %#v", final.Batches[0])
	}
}
