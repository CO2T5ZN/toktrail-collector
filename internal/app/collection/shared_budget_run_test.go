package collection

// Shared run-budget coverage for the full periodic Run: one
// syncbudget pool wired through Options.Budget (device outbox queue) and
// Options.Cursor.Budget (account cursor queue), exactly like the CLI's
// --max-total-batches. A decline stops the attempt BEFORE its ingest
// POST — the declined batch was never sent, acknowledged or dropped, so
// it stays pending — and the run must surface the decline as an
// incomplete failure instead of reporting success:
//
//   - a mixed device+cursor run shares ONE total across both queues;
//   - a cursor-only device (the historical swallow path) fails with the
//     sentinel instead of exit-zero "nothing else to do";
//   - a decline with an idle device queue still fails the run;
//   - a NON-budget cursor failure (network) keeps the historical
//     non-fatal recording — only budget declines fail the run;
//   - a mid-run authorization pause stays a queued state, never a
//     budget-incomplete failure.
//
// Everything is synthetic: tempdir state, an httptest fake speaking the
// device self / grant-ack / tool-status / device-batch / source-batch
// protocol, and injected auth/verify/pull fakes. No test reads the real
// Cursor desktop state, calls the Cursor API, or touches real
// credentials.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/cursor/usage"
	"toktrail-collector/internal/local/cursoroutbox"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/syncbudget"
)

// budgetFakeServer speaks the whole periodic protocol against synthetic
// fixtures: the grant-protocol self view (unrestricted scope, the
// permit's account source), grant-ack, tool-status reports, device batch
// ingest (correct receipts) and cursor source-batch ingest (correct
// receipts). Unexpected endpoints fail the test.
type budgetFakeServer struct {
	*httptest.Server

	mu sync.Mutex
	// pauseFromSelfRequest makes every /v1/devices/self request at or
	// beyond this 1-based count answer the paused grant view (0=never).
	pauseFromSelfRequest int
	selfRequests         int
	srcPosts             int
	devicePosts          int
	toolStatusPosts      int
	grantAcks            int
	// order records every real ingest POST (device and cursor queue)
	// in arrival order, so fair-rotation tests can assert alternation.
	order []fairUpload
	// rejectRecords, when set, maps a device ingest body's records onto
	// per-index rejection codes (nil = accept everything), mirroring
	// fakeCollectorServer's partial-receipt hook.
	rejectRecords func(records []map[string]any) map[int]string
	// failToolStatus, when true, answers every tool-status POST with a
	// synthetic transient 503 (no server error code), so tests can
	// exercise the per-batch receipt path's failure handling after a
	// confirmed upload. Failed attempts are not counted in
	// toolStatusPosts.
	failToolStatus bool
}

// fairUpload is one recorded real ingest POST: which queue made it and
// which batch it carried.
type fairUpload struct {
	Queue   string
	BatchID string
}

// recordUpload appends one ingest POST to the ordered upload log.
func (s *budgetFakeServer) recordUpload(queue, batchID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.order = append(s.order, fairUpload{Queue: queue, BatchID: batchID})
}

// uploadOrder returns a copy of the ordered upload log.
func (s *budgetFakeServer) uploadOrder() []fairUpload {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]fairUpload(nil), s.order...)
}

func startBudgetFakeServer(t *testing.T) *budgetFakeServer {
	t.Helper()
	s := &budgetFakeServer{}
	writeJSON := func(w http.ResponseWriter, status int, body any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self":
			s.mu.Lock()
			s.selfRequests++
			paused := s.pauseFromSelfRequest > 0 && s.selfRequests >= s.pauseFromSelfRequest
			s.mu.Unlock()
			device := map[string]any{
				"deviceId":             "dev-1",
				"consentRevision":      41,
				"uploadAuthorized":     true,
				"revoked":              false,
				"paused":               paused,
				"grantProtocolVersion": 1,
				"deviceGrantManaged":   true,
				"accountSources": []protocol.Source{{
					SourceInstanceID: cursorPermitSourceID,
					SourceType:       protocol.SourceType,
					State:            "active",
					FenceVersion:     3,
					NextRevision:     7,
				}},
			}
			if paused {
				device["allowedTools"] = []string{"__toktrail_paused__"}
			}
			writeJSON(w, http.StatusOK, map[string]any{"device": device})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/devices/grant-ack":
			var body struct {
				ConsentRevision int64  `json:"consentRevision"`
				ApplyState      string `json:"applyState"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("invalid grant-ack body: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			s.mu.Lock()
			s.grantAcks++
			s.mu.Unlock()
			echoed := body.ApplyState
			if echoed == "" {
				echoed = "applied"
			}
			writeJSON(w, http.StatusOK, map[string]any{"grantAck": map[string]any{
				"consentRevision":        body.ConsentRevision,
				"currentConsentRevision": body.ConsentRevision,
				"ackedState":             echoed,
				"ackedAt":                cursorTestNow.Format(time.RFC3339),
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/devices/tool-status":
			var body struct {
				Statuses []toolStatusReport `json:"statuses"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("invalid tool-status body: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if len(body.Statuses) == 0 {
				t.Errorf("tool-status POST must carry at least one statuses[] entry")
			}
			s.mu.Lock()
			failed := s.failToolStatus
			if !failed {
				s.toolStatusPosts++
			}
			s.mu.Unlock()
			if failed {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{})
				return
			}
			writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/batches":
			var body struct {
				BatchID string           `json:"batchId"`
				Records []map[string]any `json:"records"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("invalid ingest body: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			s.mu.Lock()
			s.devicePosts++
			s.mu.Unlock()
			s.recordUpload("device", body.BatchID)
			var rejected map[int]string
			if s.rejectRecords != nil {
				rejected = s.rejectRecords(body.Records)
			}
			writeJSON(w, http.StatusAccepted, ingestReceiptForTest(body.BatchID, body.Records, rejected))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/source-batches":
			var batch struct {
				BatchID string            `json:"batchId"`
				Records []json.RawMessage `json:"records"`
			}
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				t.Errorf("invalid source-batch body: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			s.mu.Lock()
			s.srcPosts++
			s.mu.Unlock()
			s.recordUpload("cursor", batch.BatchID)
			writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
				"batchId":         batch.BatchID,
				"status":          "accepted",
				"acceptedRecords": len(batch.Records),
				"rejectedRecords": 0,
				"replay":          false,
				"receivedAt":      cursorTestNow.Format(time.RFC3339),
			}})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Server.Close)
	return s
}

// setPauseFromSelfRequest arms the mid-run pause flip: the given 1-based
// self request and every later one answer the paused grant view.
func (s *budgetFakeServer) setPauseFromSelfRequest(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pauseFromSelfRequest = n
}

// setFailToolStatus arms or clears the synthetic transient tool-status
// failure (503 with no server error code) for every tool-status POST.
func (s *budgetFakeServer) setFailToolStatus(fail bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failToolStatus = fail
}

func (s *budgetFakeServer) counters() (selfRequests, srcPosts, devicePosts, toolStatusPosts, grantAcks int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.selfRequests, s.srcPosts, s.devicePosts, s.toolStatusPosts, s.grantAcks
}

// seedCursorPendingBatch persists a hand-built pending cursor batch for
// the collection cursor fixtures (source cursorPermitSourceID, fence 3,
// valid event revisions), mirroring the cursorsync drain fixtures.
func seedCursorPendingBatch(t *testing.T, stateDir, batchID string, n int) {
	t.Helper()
	records := make([]protocol.Event, 0, n)
	for i := 0; i < n; i++ {
		records = append(records, protocol.Event{
			EventKey:       protocol.EventKeyPrefix + strings.Repeat("0", 63) + strconv.Itoa(i+1),
			Revision:       7,
			Kind:           "event",
			OccurredAt:     cursorTestNow.Add(-time.Hour).Format(time.RFC3339Nano),
			Tool:           protocol.Tool,
			AdapterVersion: usage.AdapterVersion,
			SourceType:     protocol.SourceType,
		})
	}
	batch := protocol.Batch{BatchID: batchID, SourceInstanceID: cursorPermitSourceID, Records: records}
	encoded, err := protocol.EncodeBatch(batch)
	if err != nil {
		t.Fatalf("encode seed cursor batch: %v", err)
	}
	if _, err := cursoroutbox.New(stateDir).AddBatch(batch, 3, encoded); err != nil {
		t.Fatalf("seed pending cursor batch: %v", err)
	}
}

func cursorPendingCount(t *testing.T, stateDir string) int {
	t.Helper()
	n, err := cursoroutbox.New(stateDir).CountPending()
	if err != nil {
		t.Fatalf("count pending cursor batches: %v", err)
	}
	return n
}

// runBudgetPeriodic executes one periodic Run with the cursor wiring and
// ONE shared budget threaded through both queues, exactly like the CLI's
// --max-total-batches. It returns the run result and the credential
// fake so tests can prove the budget stop precedes the credential read.
func runBudgetPeriodic(t *testing.T, stateDir, serverURL string, server *budgetFakeServer, budget *syncbudget.Budget, pull *fakeCursorPull) (Result, *fakeCursorAuth, error) {
	t.Helper()
	authFake := &fakeCursorAuth{}
	res, err := Run(context.Background(), Options{
		StateDir:   stateDir,
		ServerURL:  serverURL,
		HTTPClient: server.Client(),
		HomeDir:    t.TempDir(),
		Now:        func() time.Time { return cursorTestNow },
		Budget:     budget,
		Cursor: &cursorsync.Options{
			StateDir:   stateDir,
			ServerURL:  serverURL,
			HTTPClient: server.Client(),
			Auth:       authFake,
			Verify:     fakeCursorVerify,
			Pull:       pull.Pull,
			Now:        func() time.Time { return cursorTestNow },
			Budget:     budget,
		},
	})
	return res, authFake, err
}

// budgetGrantSession enables a claude-code-jsonl grant over an empty
// session directory so the device side of the run has a granted source
// whose scan finds no new records (the drain path still runs).
func budgetGrantSession(t *testing.T, stateDir string) {
	t.Helper()
	sessions := filepath.Join(t.TempDir(), "sessions")
	if err := os.MkdirAll(sessions, 0o700); err != nil {
		t.Fatal(err)
	}
	enableGrant(t, stateDir, "claude-code-jsonl", sessions)
}

// TestRunSharedBudgetCapsDeviceAndCursorPostsTogether verifies the mixed
// queue accounting: with one shared total and both queues holding pending
// batches, the cursor round consumes the pool first, the device drain's
// next attempt is declined BEFORE its ingest POST, and the run fails
// with the budget sentinel while both queues keep their pending batches.
// A follow-up run under its own fresh budget drains everything.
func TestRunSharedBudgetCapsDeviceAndCursorPostsTogether(t *testing.T) {
	stateDir := t.TempDir()
	server := startBudgetFakeServer(t)
	bindCursorDevice(t, stateDir, server.URL)
	writeCursorPermit(t, stateDir)
	budgetGrantSession(t, stateDir)
	seedCursorPendingBatch(t, stateDir, "cursor-budget-mixed-1", 1)
	seedCursorPendingBatch(t, stateDir, "cursor-budget-mixed-2", 1)
	writePendingBatch(t, stateDir, "device-budget-mixed-1")
	writePendingBatch(t, stateDir, "device-budget-mixed-2")

	budget := syncbudget.New(syncbudget.WithTotal(1))
	pull := &fakeCursorPull{}
	res, authFake, err := runBudgetPeriodic(t, stateDir, server.URL, server, budget, pull)
	if err == nil {
		t.Fatalf("the exhausted shared budget must fail the mixed run, got %+v", res)
	}
	if !errors.Is(err, syncbudget.ErrTotalExhausted) {
		t.Fatalf("the stop must surface the budget sentinel, got %v", err)
	}
	// Exactly one POST happened (the cursor queue drains first); the
	// device attempt was declined before its POST.
	if budget.Used() != 1 || budget.QueueUsed("cursor") != 1 || budget.QueueUsed("device") != 0 {
		t.Fatalf("actual POST attempts exceed the budget: used=%d cursor=%d device=%d",
			budget.Used(), budget.QueueUsed("cursor"), budget.QueueUsed("device"))
	}
	_, srcPosts, devicePosts, _, _ := server.counters()
	if srcPosts != 1 || devicePosts != 0 {
		t.Fatalf("expected one source-batch POST and no device POST, got src=%d device=%d", srcPosts, devicePosts)
	}
	// The budget stop precedes the credential read and the pull.
	if authFake.fetches != 0 || pull.calls != 0 {
		t.Fatalf("a budget-stopped round must not read the credential or pull, got %d reads / %d pulls", authFake.fetches, pull.calls)
	}
	// The cursor round synced one batch and kept one pending; the
	// decline is surfaced on the cursor result, never as success.
	if res.Cursor.SyncedBatches != 1 || res.Cursor.PendingRemaining != 1 {
		t.Fatalf("cursor queue must hold one synced and one pending batch: %+v", res.Cursor)
	}
	if !strings.Contains(res.Cursor.Skipped, "budget") {
		t.Fatalf("the cursor decline must be surfaced on the cursor result, got %q", res.Cursor.Skipped)
	}
	// The device queue kept both batches pending and reports the
	// budget stop (never a failed upload).
	if res.SyncedBatches != 0 || res.PendingRemaining != 2 {
		t.Fatalf("device queue must keep both batches pending: %+v", res)
	}
	if !strings.Contains(res.DrainStopped, "shared upload budget") {
		t.Fatalf("the drain stop must name the budget, got %q", res.DrainStopped)
	}
	if cursorPendingCount(t, stateDir) != 1 {
		t.Fatalf("the declined cursor batch must stay pending, got %d", cursorPendingCount(t, stateDir))
	}

	// Follow-up run with its own fresh budget drains both queues.
	budget2 := syncbudget.New(syncbudget.WithTotal(10))
	res2, _, err := runBudgetPeriodic(t, stateDir, server.URL, server, budget2, pull)
	if err != nil {
		t.Fatalf("the resumed run must finish: %v", err)
	}
	if res2.Cursor.SyncedBatches != 1 || res2.Cursor.PendingRemaining != 0 {
		t.Fatalf("the retained cursor batch must drain: %+v", res2.Cursor)
	}
	if res2.SyncedBatches != 2 || res2.PendingRemaining != 0 {
		t.Fatalf("both device batches must drain: %+v", res2)
	}
	if budget2.Used() != 3 || budget2.QueueUsed("cursor") != 1 || budget2.QueueUsed("device") != 2 {
		t.Fatalf("the resumed run must spend exactly its three uploads: used=%d cursor=%d device=%d",
			budget2.Used(), budget2.QueueUsed("cursor"), budget2.QueueUsed("device"))
	}
	_, srcPosts, devicePosts, _, _ = server.counters()
	if srcPosts != 2 || devicePosts != 2 {
		t.Fatalf("expected two source-batch and two device POSTs in total, got src=%d device=%d", srcPosts, devicePosts)
	}
}

// TestRunCursorOnlyBudgetExhaustionSurfacesIncomplete verifies the
// cursor-only swallow fix: a device with NO local grants whose cursor
// round stops on the shared budget must fail the run with the sentinel —
// never an exit-zero "cursor ran, nothing else to do" — while the
// declined batch stays pending and the next run resumes it.
func TestRunCursorOnlyBudgetExhaustionSurfacesIncomplete(t *testing.T) {
	stateDir := t.TempDir()
	server := startBudgetFakeServer(t)
	bindCursorDevice(t, stateDir, server.URL)
	writeCursorPermit(t, stateDir)
	// No local grants: the historical code path returned nil here.
	seedCursorPendingBatch(t, stateDir, "cursor-budget-only-1", 1)
	seedCursorPendingBatch(t, stateDir, "cursor-budget-only-2", 1)

	budget := syncbudget.New(syncbudget.WithTotal(1))
	pull := &fakeCursorPull{}
	res, authFake, err := runBudgetPeriodic(t, stateDir, server.URL, server, budget, pull)
	if err == nil {
		t.Fatalf("a cursor-only budget decline must not be swallowed into success, got %+v", res)
	}
	if !errors.Is(err, syncbudget.ErrTotalExhausted) {
		t.Fatalf("the cursor-only stop must surface the budget sentinel, got %v", err)
	}
	if res.Cursor.SyncedBatches != 1 || res.Cursor.PendingRemaining != 1 {
		t.Fatalf("one cursor batch must sync and one must stay pending: %+v", res.Cursor)
	}
	if res.SyncedBatches != 0 || res.PendingRemaining != 0 {
		t.Fatalf("a cursor-only device must not drain device batches: %+v", res)
	}
	if res.NoGrants || res.Skipped != "" {
		t.Fatalf("a ran cursor round must not read as a no-op, got NoGrants=%t Skipped=%q", res.NoGrants, res.Skipped)
	}
	if budget.Used() != 1 || budget.QueueUsed("cursor") != 1 {
		t.Fatalf("actual POST attempts exceed the budget: used=%d cursor=%d", budget.Used(), budget.QueueUsed("cursor"))
	}
	_, srcPosts, devicePosts, _, _ := server.counters()
	if srcPosts != 1 || devicePosts != 0 {
		t.Fatalf("expected one source-batch POST and no device traffic, got src=%d device=%d", srcPosts, devicePosts)
	}
	if authFake.fetches != 0 || pull.calls != 0 {
		t.Fatalf("a budget-stopped round must not read the credential or pull, got %d reads / %d pulls", authFake.fetches, pull.calls)
	}
	if n := cursorPendingCount(t, stateDir); n != 1 {
		t.Fatalf("the declined cursor batch must stay pending, got %d", n)
	}

	// The next run, under its own fresh budget, resumes the backlog.
	resume, _, err := runBudgetPeriodic(t, stateDir, server.URL, server, syncbudget.New(syncbudget.WithTotal(5)), pull)
	if err != nil {
		t.Fatalf("the resumed cursor-only run must finish: %v", err)
	}
	if resume.Cursor.SyncedBatches != 1 || resume.Cursor.PendingRemaining != 0 {
		t.Fatalf("the retained cursor batch must drain: %+v", resume.Cursor)
	}
	if n := cursorPendingCount(t, stateDir); n != 0 {
		t.Fatalf("nothing may remain after the resumed run, got %d pending", n)
	}
}

// TestRunCursorBudgetExhaustionWithIdleDeviceQueueStillIncomplete
// verifies the other propagation path: when the cursor round declines
// but the device queue is empty and every grant scan finishes cleanly,
// the run must still fail with the sentinel instead of reporting a
// complete cycle.
func TestRunCursorBudgetExhaustionWithIdleDeviceQueueStillIncomplete(t *testing.T) {
	stateDir := t.TempDir()
	server := startBudgetFakeServer(t)
	bindCursorDevice(t, stateDir, server.URL)
	writeCursorPermit(t, stateDir)
	budgetGrantSession(t, stateDir)
	seedCursorPendingBatch(t, stateDir, "cursor-budget-idle-1", 1)
	seedCursorPendingBatch(t, stateDir, "cursor-budget-idle-2", 1)
	// No pending device batches: the drain has nothing to do.

	budget := syncbudget.New(syncbudget.WithTotal(1))
	pull := &fakeCursorPull{}
	res, _, err := runBudgetPeriodic(t, stateDir, server.URL, server, budget, pull)
	if err == nil {
		t.Fatalf("an exhausted cursor budget must fail the run even with an idle device queue, got %+v", res)
	}
	if !errors.Is(err, syncbudget.ErrTotalExhausted) {
		t.Fatalf("the stop must surface the budget sentinel, got %v", err)
	}
	if res.Cursor.SyncedBatches != 1 || res.Cursor.PendingRemaining != 1 {
		t.Fatalf("one cursor batch must sync and one must stay pending: %+v", res.Cursor)
	}
	if res.SyncedBatches != 0 || res.PendingRemaining != 0 || res.DrainStopped != "" {
		t.Fatalf("the idle device queue must stay clean: %+v", res)
	}
	if budget.Used() != 1 {
		t.Fatalf("actual POST attempts exceed the budget: used=%d", budget.Used())
	}
	if n := cursorPendingCount(t, stateDir); n != 1 {
		t.Fatalf("the declined cursor batch must stay pending, got %d", n)
	}
}

// TestRunCursorNetworkFailureStaysNonFatalUnderBudget pins the boundary
// between budget declines and ordinary cursor failures: a pull failure
// (a network problem, not a budget decline) keeps the historical
// non-fatal recording — the run succeeds, the device queue drains, and
// nothing is reported incomplete.
func TestRunCursorNetworkFailureStaysNonFatalUnderBudget(t *testing.T) {
	stateDir := t.TempDir()
	server := startBudgetFakeServer(t)
	bindCursorDevice(t, stateDir, server.URL)
	writeCursorPermit(t, stateDir)
	budgetGrantSession(t, stateDir)
	writePendingBatch(t, stateDir, "device-budget-netfail-1")

	budget := syncbudget.New(syncbudget.WithTotal(5))
	pull := &fakeCursorPull{err: errors.New("synthetic cursor pull failure")}
	res, _, err := runBudgetPeriodic(t, stateDir, server.URL, server, budget, pull)
	if err != nil {
		t.Fatalf("an ordinary cursor failure must stay non-fatal for the run, got %v", err)
	}
	if !strings.Contains(res.Cursor.Skipped, "cursor usage pull failed") {
		t.Fatalf("the pull failure must surface on the cursor result, got %q", res.Cursor.Skipped)
	}
	if res.SyncedBatches != 1 || res.PendingRemaining != 0 {
		t.Fatalf("the device queue must drain normally: %+v", res)
	}
	if budget.Used() != 1 || budget.QueueUsed("device") != 1 {
		t.Fatalf("only the device upload may spend budget: used=%d device=%d", budget.Used(), budget.QueueUsed("device"))
	}
	_, srcPosts, devicePosts, _, _ := server.counters()
	if srcPosts != 0 || devicePosts != 1 {
		t.Fatalf("expected no cursor POST and one device POST, got src=%d device=%d", srcPosts, devicePosts)
	}
}

// TestRunSharedBudgetPauseMidDrainIsNotIncomplete pins the authorization
// boundary: when the server pauses the device MID-run (after the grant
// sync and the cursor round, at the first device upload preflight), the
// drain keeps every batch queued and the run succeeds — an
// authorization pause is a state, never a budget-incomplete failure,
// even with a shared budget armed.
func TestRunSharedBudgetPauseMidDrainIsNotIncomplete(t *testing.T) {
	stateDir := t.TempDir()
	server := startBudgetFakeServer(t)
	bindCursorDevice(t, stateDir, server.URL)
	writeCursorPermit(t, stateDir)
	budgetGrantSession(t, stateDir)
	seedCursorPendingBatch(t, stateDir, "cursor-budget-pause-1", 1)
	writePendingBatch(t, stateDir, "device-budget-pause-1")
	// Self requests: 1 grant sync, 2 cursor round, 3 device preflight.
	// The third and later answer the paused view.
	server.setPauseFromSelfRequest(3)

	budget := syncbudget.New(syncbudget.WithTotal(5))
	pull := &fakeCursorPull{}
	res, _, err := runBudgetPeriodic(t, stateDir, server.URL, server, budget, pull)
	if err != nil {
		t.Fatalf("a mid-run pause must not fail the run (and must not read as a budget stop), got %v", err)
	}
	if res.Cursor.SyncedBatches != 1 || res.Cursor.PendingRemaining != 0 {
		t.Fatalf("the cursor round must finish before the pause: %+v", res.Cursor)
	}
	if res.SyncedBatches != 0 || res.PendingRemaining != 1 {
		t.Fatalf("the paused device batch must stay queued: %+v", res)
	}
	if !strings.Contains(res.DrainStopped, "paused") {
		t.Fatalf("the drain stop must name the pause, got %q", res.DrainStopped)
	}
	if budget.Used() != 1 || budget.QueueUsed("cursor") != 1 {
		t.Fatalf("only the cursor upload may spend budget: used=%d cursor=%d", budget.Used(), budget.QueueUsed("cursor"))
	}
	_, srcPosts, devicePosts, _, _ := server.counters()
	if srcPosts != 1 || devicePosts != 0 {
		t.Fatalf("expected one cursor POST and no device POST, got src=%d device=%d", srcPosts, devicePosts)
	}
	if n := devicePendingCount(t, stateDir); n != 1 {
		t.Fatalf("the paused device batch must stay pending, got %d", n)
	}
}

// devicePendingCount counts the pending device outbox batches through
// the package's own drain accounting.
func devicePendingCount(t *testing.T, stateDir string) int {
	t.Helper()
	n, err := countPending(outbox.New(stateDir))
	if err != nil {
		t.Fatalf("count pending device batches: %v", err)
	}
	return n
}
