package collection

// End-to-end wiring tests for the unified progress stream through the
// real collection entry points: the event sequence of a full run,
// heartbeats during an in-flight POST, the business clock's call count
// and the durable end state being independent of progress, the bounded
// IO budget (no per-batch full-queue rescan), split-child origins, the
// two-queue fair rotation's real events, and the account round's
// conservative origin. Everything is synthetic (tempdir state, httptest
// fakes, injected tick channels and counting hooks); no real collector
// state, credentials or network is ever touched.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncbudget"
)

// progressRecorder captures the unified stream for assertions.
type progressRecorder struct {
	mu     sync.Mutex
	events []ProgressEvent
}

func (r *progressRecorder) record(ev ProgressEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *progressRecorder) snapshot() []ProgressEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ProgressEvent(nil), r.events...)
}

func (r *progressRecorder) ofKind(kind string) []ProgressEvent {
	var out []ProgressEvent
	for _, ev := range r.snapshot() {
		if ev.Kind == kind {
			out = append(out, ev)
		}
	}
	return out
}

func (r *progressRecorder) batches(queue string) []ProgressEvent {
	var out []ProgressEvent
	for _, ev := range r.ofKind(ProgressBatch) {
		if ev.Queue == queue {
			out = append(out, ev)
		}
	}
	return out
}

func (r *progressRecorder) queues(queue string) []ProgressEvent {
	var out []ProgressEvent
	for _, ev := range r.ofKind(ProgressQueue) {
		if ev.Queue == queue {
			out = append(out, ev)
		}
	}
	return out
}

// One full periodic run over two pending batches: stage events, bounded
// queue snapshots at the drain boundaries, per-attempt batch events and
// the final heartbeat with the folded drain counters.
func TestRunEmitsUnifiedProgressEvents(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)
	writePendingBatch(t, stateDir, "progress-run-1")
	writePendingBatch(t, stateDir, "progress-run-2")

	rec := &progressRecorder{}
	res, err := Run(context.Background(), Options{
		StateDir:      stateDir,
		ServerURL:     server.URL,
		Progress:      rec.record,
		progressTicks: make(chan time.Time),
	})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if res.SyncedBatches != 2 || res.PendingRemaining != 0 {
		t.Fatalf("both batches must drain: %+v", res)
	}

	var sawDrainStart, sawDrainEnd bool
	for _, ev := range rec.ofKind(ProgressStageStart) {
		if ev.Stage == "drain" {
			sawDrainStart = true
		}
	}
	for _, ev := range rec.ofKind(ProgressStageEnd) {
		if ev.Stage == "drain" {
			sawDrainEnd = true
		}
	}
	if !sawDrainStart || !sawDrainEnd {
		t.Fatalf("the drain phase must be marked: start=%v end=%v", sawDrainStart, sawDrainEnd)
	}

	queues := rec.queues(ProgressQueueDevice)
	if len(queues) < 3 {
		t.Fatalf("expected start, per-batch and end queue events, got %d", len(queues))
	}
	first := queues[0]
	if !first.Counted || !first.RecordsCounted || first.PendingBatches != 2 || first.PendingRecords != 2 {
		t.Fatalf("the drain-start snapshot must count both batches: %+v", first)
	}
	last := queues[len(queues)-1]
	if !last.Counted || last.PendingBatches != 0 {
		t.Fatalf("the drain-end snapshot must observe the empty queue: %+v", last)
	}

	batches := rec.batches(ProgressQueueDevice)
	if len(batches) != 2 {
		t.Fatalf("expected two device batch events, got %+v", batches)
	}
	for _, ev := range batches {
		if ev.Result != "acked" || ev.AttemptStage != "ack" {
			t.Fatalf("a successful drain step must report an acked attempt: %+v", ev)
		}
		if !ev.PrepareMeasured || !ev.SelfCheckMeasured || !ev.HTTPMeasured || !ev.ACKMeasured {
			t.Fatalf("the attempt's phases must be measured: %+v", ev)
		}
		if !ev.ReceiptObserved || ev.AcceptedRecords != 1 || ev.BatchReplay {
			t.Fatalf("the receipt must be observed: %+v", ev)
		}
		if !ev.PayloadBytesKnown || ev.PayloadBytes <= 0 {
			t.Fatalf("the planned payload size must be known: %+v", ev)
		}
		if ev.FirstBatchConfirmation != FirstBatchConfirmationYes {
			t.Fatalf("a drained pending batch's ACK is its first local confirmation: %+v", ev)
		}
		if ev.Origin != OriginUnknown {
			t.Fatalf("a plain selected entry may have been split: %+v", ev)
		}
	}

	hb := rec.ofKind(ProgressHeartbeat)
	if len(hb) == 0 {
		t.Fatalf("the run must emit a final heartbeat")
	}
	final := hb[len(hb)-1]
	if final.Samples != 2 || final.FirstBatchConfirmedBatches != 2 {
		t.Fatalf("the final heartbeat must fold both outcomes: %+v", final)
	}
	if final.ProcessingRateRecPerSec <= 0 {
		t.Fatalf("a sampled drain carries a processing rate: %+v", final)
	}
}

// A heartbeat fires during a single in-flight POST: the run goroutine is
// blocked inside the upload while the ticker reports the attempt.
func TestRunHeartbeatDuringInFlightAttempt(t *testing.T) {
	stateDir := t.TempDir()
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self":
			writeJSONForTest(w, http.StatusOK, map[string]any{"device": map[string]any{
				"deviceId": "dev-1", "consentRevision": 7,
				"uploadAuthorized": true, "revoked": false,
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/batches":
			close(entered)
			<-release
			var body struct {
				BatchID string           `json:"batchId"`
				Records []map[string]any `json:"records"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			writeJSONForTest(w, http.StatusAccepted, ingestReceiptForTest(body.BatchID, body.Records, nil))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)
	writePendingBatch(t, stateDir, "progress-blocked-1")

	events := make(chan ProgressEvent, 64)
	ticks := make(chan time.Time)
	runDone := make(chan error, 1)
	go func() {
		_, err := Run(context.Background(), Options{
			StateDir:      stateDir,
			ServerURL:     server.URL,
			Progress:      func(ev ProgressEvent) { events <- ev },
			progressTicks: ticks,
		})
		runDone <- err
	}()

	<-entered
	ticks <- time.Now()
	var inFlight *ProgressEvent
	deadline := time.After(5 * time.Second)
	for inFlight == nil {
		select {
		case ev := <-events:
			if ev.Kind == ProgressHeartbeat && ev.AttemptInFlight {
				cp := ev
				inFlight = &cp
			}
		case <-deadline:
			t.Fatalf("no in-flight heartbeat during the blocked POST")
		}
	}
	if inFlight.Queue != ProgressQueueDevice || inFlight.Stage != "drain" {
		t.Fatalf("the in-flight heartbeat must name the drain's device attempt: %+v", inFlight)
	}
	close(release)
	if err := <-runDone; err != nil {
		t.Fatalf("run failed: %v", err)
	}
}

// countingServer wraps the standard fake shapes and counts every
// request, so the identity test can prove progress adds zero HTTP.
type countingServer struct {
	*httptest.Server
	self   atomic.Int64
	ingest atomic.Int64
	status atomic.Int64
}

func newCountingServer(t *testing.T) *countingServer {
	t.Helper()
	s := &countingServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self":
			s.self.Add(1)
			writeJSONForTest(w, http.StatusOK, map[string]any{"device": map[string]any{
				"deviceId": "dev-1", "consentRevision": 7,
				"uploadAuthorized": true, "revoked": false,
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/batches":
			s.ingest.Add(1)
			var body struct {
				BatchID string           `json:"batchId"`
				Records []map[string]any `json:"records"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			writeJSONForTest(w, http.StatusAccepted, ingestReceiptForTest(body.BatchID, body.Records, nil))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/devices/tool-status":
			s.status.Add(1)
			var body struct {
				Statuses []toolStatusReport `json:"statuses"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			writeJSONForTest(w, http.StatusAccepted, map[string]any{"accepted": true})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Server.Close)
	return s
}

// durableEndState captures every durable outcome the run leaves behind
// that progress must not perturb: the outbox ledger, the preflight
// attempt accounting, the quarantine store and the device state's sync
// markers.
type durableEndState struct {
	outbox     []outbox.BatchEntry
	preflight  int
	quarantine int
	lastSync   statedir.DeviceState
}

func captureDurableEndState(t *testing.T, stateDir string) durableEndState {
	t.Helper()
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	attempts, err := outbox.New(stateDir).LoadPreflightAttempts()
	if err != nil {
		t.Fatal(err)
	}
	qEntries, err := quarantine.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	st, err := statedir.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	// Normalize the fields the two runs may legitimately differ in by
	// wall-clock jitter alone (none today: the fake receipt fixes
	// ReceivedAt); keep everything else byte-comparable.
	return durableEndState{outbox: out.Batches, preflight: attempts.Count, quarantine: len(qEntries), lastSync: st}
}

// Enabling progress must not change anything the run does: the business
// clock's call count, the HTTP traffic and the entire durable end state
// (outbox ledger, preflight accounting, quarantine, device sync
// markers) are identical with and without the stream.
func TestRunProgressLeavesBusinessStateIdentical(t *testing.T) {
	runOnce := func(withProgress bool) (int, durableEndState, int64, int64) {
		stateDir := t.TempDir()
		server := newCountingServer(t)
		bindDevice(t, stateDir, server.URL)
		enableIdleGrant(t, stateDir)
		writePendingBatch(t, stateDir, "progress-identity-1")
		writePendingBatch(t, stateDir, "progress-identity-2")
		calls := 0
		opt := Options{
			StateDir:  stateDir,
			ServerURL: server.URL,
			Now:       func() time.Time { calls++; return cursorTestNow },
		}
		if withProgress {
			rec := &progressRecorder{}
			opt.Progress = rec.record
			opt.progressTicks = make(chan time.Time)
		}
		if _, err := Run(context.Background(), opt); err != nil {
			t.Fatalf("run failed: %v", err)
		}
		return calls, captureDurableEndState(t, stateDir), server.self.Load(), server.ingest.Load()
	}
	callsA, stateA, selfA, ingestA := runOnce(false)
	callsB, stateB, selfB, ingestB := runOnce(true)
	if callsA == 0 || callsA != callsB {
		t.Fatalf("the business Now call count must be identical: nil=%d enabled=%d", callsA, callsB)
	}
	if selfA != selfB || ingestA != ingestB {
		t.Fatalf("HTTP traffic must be identical: self %d/%d ingest %d/%d", selfA, selfB, ingestA, ingestB)
	}
	if normalizeOutboxForCompare(stateA.outbox) != normalizeOutboxForCompare(stateB.outbox) {
		t.Fatalf("the outbox end state must be identical:\n%s\n%s",
			normalizeOutboxForCompare(stateA.outbox), normalizeOutboxForCompare(stateB.outbox))
	}
	if stateA.preflight != stateB.preflight || stateA.quarantine != stateB.quarantine {
		t.Fatalf("preflight/quarantine accounting must be identical: %+v vs %+v", stateA, stateB)
	}
	if stateA.lastSync.LastSyncBatchID != stateB.lastSync.LastSyncBatchID ||
		stateA.lastSync.LastSyncAcceptedRecords != stateB.lastSync.LastSyncAcceptedRecords ||
		stateA.lastSync.LastSyncedAt != stateB.lastSync.LastSyncedAt {
		t.Fatalf("the device sync markers must be identical: %+v vs %+v", stateA.lastSync, stateB.lastSync)
	}
}

// normalizeOutboxForCompare strips the fields two identical runs may
// differ in by tempdir spelling or wall-clock jitter alone (paths,
// creation and attempt stamps); every durable semantic field — status,
// counts, receipt outcome, reorg linkage, origin revision — stays in.
func normalizeOutboxForCompare(batches []outbox.BatchEntry) string {
	type row struct {
		BatchID, Status       string
		RecordCount           int
		SyncedAt              time.Time
		ReceiptStatus         string
		Accepted, Rejected    int
		ReorganizedInto       string
		OriginConsentRevision int64
	}
	rows := make([]row, 0, len(batches))
	for _, b := range batches {
		rows = append(rows, row{
			BatchID: b.BatchID, Status: b.Status, RecordCount: b.RecordCount,
			SyncedAt: b.SyncedAt, ReceiptStatus: b.ReceiptStatus,
			Accepted: b.AcceptedRecords, Rejected: b.RejectedRecords,
			ReorganizedInto: b.ReorganizedInto, OriginConsentRevision: b.OriginConsentRevision,
		})
	}
	return fmt.Sprintf("%+v", rows)
}

// The progress layer's IO budget: with progress enabled over N pending
// batches, the ledger is read only at the bounded boundaries (a fixed
// small number, independent of N) and exactly one guarded stat runs per
// drained batch — O(N) total, never a per-batch full-queue rescan.
func TestRunProgressIOBudgetIsBoundedPerBatch(t *testing.T) {
	const n = 12
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)
	for i := 1; i <= n; i++ {
		writePendingBatch(t, stateDir, fmt.Sprintf("progress-io-%d", i))
	}

	var queueReads, fileStats atomic.Int64
	progressQueueReadHook = func(string) { queueReads.Add(1) }
	progressFileStatHook = func() { fileStats.Add(1) }
	defer func() {
		progressQueueReadHook = nil
		progressFileStatHook = nil
	}()

	rec := &progressRecorder{}
	res, err := Run(context.Background(), Options{
		StateDir:      stateDir,
		ServerURL:     server.URL,
		MaxBatches:    n,
		Progress:      rec.record,
		progressTicks: make(chan time.Time),
	})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if res.SyncedBatches != n {
		t.Fatalf("all %d batches must drain: %+v", n, res)
	}
	reads := queueReads.Load()
	stats := fileStats.Load()
	// Bounded ledger reads: the drain's start and end snapshots only —
	// a constant, independent of the batch count.
	if reads != 2 {
		t.Fatalf("the ledger must be read only at the bounded boundaries, got %d reads for %d batches", reads, n)
	}
	// One guarded stat per pending file at the start snapshot plus one
	// per drained batch: linear in N, never quadratic.
	if stats > int64(2*n) {
		t.Fatalf("file stats must stay O(N), got %d stats for %d batches", stats, n)
	}
	if stats < int64(n) {
		t.Fatalf("the start snapshot alone must stat every pending file, got %d stats for %d batches", stats, n)
	}
}

// An oversize parent (>MaxBatchRecords) is split before its POST: the
// first attempt's events describe the child, so a plain parent's origin
// stays unknown; the leftover child, selected directly on the next
// step, is provably reorg-shaped.
func TestRunOversizeSplitBatchEvents(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)
	writePendingBatchRecords(t, stateDir, "progress-oversize-1", 501)

	rec := &progressRecorder{}
	res, err := Run(context.Background(), Options{
		StateDir:      stateDir,
		ServerURL:     server.URL,
		Progress:      rec.record,
		progressTicks: make(chan time.Time),
	})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if res.SyncedBatches != 2 || res.PendingRemaining != 0 {
		t.Fatalf("both split children must drain: %+v", res)
	}
	batches := rec.batches(ProgressQueueDevice)
	if len(batches) != 2 {
		t.Fatalf("expected two attempt events (one per child), got %+v", batches)
	}
	// The oversize-split journal inherits the plain parent's revision
	// (zero) for its children, so neither event can prove a reorg shape:
	// both stay conservatively unknown — never a guess.
	for _, ev := range batches {
		if ev.Origin != OriginUnknown {
			t.Fatalf("an oversize child of a plain parent keeps the origin unknown: %+v", ev)
		}
		if ev.FirstBatchConfirmation != FirstBatchConfirmationYes {
			t.Fatalf("each drained child's ACK is its first local confirmation: %+v", ev)
		}
	}
	queues := rec.queues(ProgressQueueDevice)
	if len(queues) < 2 {
		t.Fatalf("expected per-batch and boundary queue events, got %d", len(queues))
	}
	if queues[1].Counted {
		t.Fatalf("a split child's effect on the queue is not provable incrementally: %+v", queues[1])
	}
	last := queues[len(queues)-1]
	if !last.Counted || last.PendingBatches != 0 {
		t.Fatalf("the drain-end re-sample must restore the queue: %+v", last)
	}
}

// The first attempt's consent-scope gate splits a mixed-scope batch
// before its POST: the in-scope child is acked under a new batch ID.
func TestRunScopeGateSplitBatchEvents(t *testing.T) {
	stateDir := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self":
			writeJSONForTest(w, http.StatusOK, map[string]any{"device": map[string]any{
				"deviceId": "dev-1", "consentRevision": 7,
				"uploadAuthorized": true, "revoked": false,
				"historyFrom": "2026-10-21T12:00:00Z",
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/batches":
			var body struct {
				BatchID string           `json:"batchId"`
				Records []map[string]any `json:"records"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			writeJSONForTest(w, http.StatusAccepted, ingestReceiptForTest(body.BatchID, body.Records, nil))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)
	writePendingMixedScopeBatch(t, stateDir, "progress-scope-1")

	rec := &progressRecorder{}
	res, err := Run(context.Background(), Options{
		StateDir:      stateDir,
		ServerURL:     server.URL,
		Progress:      rec.record,
		progressTicks: make(chan time.Time),
	})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if res.SyncedBatches != 1 {
		t.Fatalf("the in-scope child must drain: %+v", res)
	}
	batches := rec.batches(ProgressQueueDevice)
	if len(batches) != 1 {
		t.Fatalf("expected one attempt event for the scoped child, got %+v", batches)
	}
	if batches[0].Origin != OriginUnknown {
		t.Fatalf("a plain parent replaced by a scope child keeps the origin unknown: %+v", batches[0])
	}
	if batches[0].FirstBatchConfirmation != FirstBatchConfirmationYes || !batches[0].ReceiptObserved {
		t.Fatalf("the scoped child's ACK is its first local confirmation: %+v", batches[0])
	}
}

// A reorg-shaped selected entry (a scope-reorganization child or a
// quarantine-recovery re-pend) is provably reorg_child — whichever
// batch the step actually sends.
func TestRunReorgShapedParentOrigin(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)
	writePendingBatch(t, stateDir, "progress-reorg-1")
	path := filepath.Join(stateDir, "batches", "progress-reorg-1.json")
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{
		BatchID:               "progress-reorg-1",
		File:                  path,
		Source:                "usage-json",
		Input:                 path,
		RecordCount:           1,
		OriginConsentRevision: 9,
	}); err != nil {
		t.Fatal(err)
	}

	rec := &progressRecorder{}
	if _, err := Run(context.Background(), Options{
		StateDir:      stateDir,
		ServerURL:     server.URL,
		Progress:      rec.record,
		progressTicks: make(chan time.Time),
	}); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	batches := rec.batches(ProgressQueueDevice)
	if len(batches) != 1 || batches[0].Origin != OriginReorgChild {
		t.Fatalf("a reorg-shaped selected entry is provably reorg_child: %+v", batches)
	}
}

// The two-queue fair rotation emits real events for BOTH queues in one
// run: per-attempt device events, per-phase account events, both
// queues' snapshots and the shared counters.
func TestRunFairDrainTwoQueueProgressEvents(t *testing.T) {
	stateDir := t.TempDir()
	server := startBudgetFakeServer(t)
	bindCursorDevice(t, stateDir, server.URL)
	writeCursorPermit(t, stateDir)
	budgetGrantSession(t, stateDir)
	seedCursorPendingBatch(t, stateDir, "progress-fair-cursor-1", 1)
	seedCursorPendingBatch(t, stateDir, "progress-fair-cursor-2", 1)
	writePendingBatch(t, stateDir, "progress-fair-device-1")
	writePendingBatch(t, stateDir, "progress-fair-device-2")

	rec := &progressRecorder{}
	budget := syncbudget.New(syncbudget.WithTotal(10))
	res, err := Run(context.Background(), Options{
		StateDir:   stateDir,
		ServerURL:  server.URL,
		HTTPClient: server.Client(),
		HomeDir:    t.TempDir(),
		Now:        func() time.Time { return cursorTestNow },
		Budget:     budget,
		FairDrain:  true,
		Cursor: &cursorsync.Options{
			StateDir:   stateDir,
			ServerURL:  server.URL,
			HTTPClient: server.Client(),
			Auth:       &fakeCursorAuth{},
			Verify:     fakeCursorVerify,
			Pull:       (&fakeCursorPull{}).Pull,
			Now:        func() time.Time { return cursorTestNow },
			Budget:     budget,
		},
		Progress:      rec.record,
		progressTicks: make(chan time.Time),
	})
	if err != nil {
		t.Fatalf("fair run failed: %v", err)
	}
	if res.SyncedBatches != 2 || res.Cursor.SyncedBatches != 2 {
		t.Fatalf("both queues must drain: device=%+v cursor=%+v", res, res.Cursor)
	}

	deviceBatches := rec.batches(ProgressQueueDevice)
	cursorBatches := rec.batches(ProgressQueueCursor)
	if len(deviceBatches) != 2 {
		t.Fatalf("expected two device attempt events, got %+v", deviceBatches)
	}
	if len(cursorBatches) < 2 {
		t.Fatalf("expected the account queue's per-phase events, got %+v", cursorBatches)
	}
	var acknowledgedCursor int
	for _, ev := range cursorBatches {
		if ev.Phase == "outcome" && ev.Result == "acknowledged" {
			acknowledgedCursor++
			if ev.FirstBatchConfirmation != FirstBatchConfirmationYes {
				t.Fatalf("the acknowledged terminal proves the first local confirmation: %+v", ev)
			}
		}
	}
	if acknowledgedCursor != 2 {
		t.Fatalf("both cursor batches must reach the acknowledged terminal, got %d", acknowledgedCursor)
	}
	// Both queues' snapshots exist and end empty.
	for _, queue := range []string{ProgressQueueDevice, ProgressQueueCursor} {
		qs := rec.queues(queue)
		if len(qs) == 0 {
			t.Fatalf("the %s queue must emit snapshots", queue)
		}
		last := qs[len(qs)-1]
		if !last.Counted || last.PendingBatches != 0 {
			t.Fatalf("the %s queue must end empty: %+v", queue, last)
		}
	}
	// The final heartbeat folds both queues' outcomes.
	hb := rec.ofKind(ProgressHeartbeat)
	if len(hb) == 0 {
		t.Fatalf("the run must emit a final heartbeat")
	}
	final := hb[len(hb)-1]
	if final.Samples != 4 || final.FirstBatchConfirmedBatches != 4 {
		t.Fatalf("the final heartbeat must fold both queues' outcomes: %+v", final)
	}
}

// The account round through the real collection entry: a drain-only
// round over purely pre-run backlog is provably backlog and its
// acknowledged terminal proves the first batch confirmation; a pull
// round is mixed by construction (unknown).
func TestRunCursorRoundOriginsThroughEntry(t *testing.T) {
	stateDir := t.TempDir()
	server := startBudgetFakeServer(t)
	bindCursorDevice(t, stateDir, server.URL)
	writeCursorPermit(t, stateDir)
	seedCursorPendingBatch(t, stateDir, "progress-cursor-pre-1", 1)

	rec := &progressRecorder{}
	res, err := Run(context.Background(), Options{
		StateDir:   stateDir,
		ServerURL:  server.URL,
		HTTPClient: server.Client(),
		HomeDir:    t.TempDir(),
		Now:        func() time.Time { return cursorTestNow },
		Cursor: &cursorsync.Options{
			StateDir:   stateDir,
			ServerURL:  server.URL,
			HTTPClient: server.Client(),
			Auth:       &fakeCursorAuth{},
			Verify:     fakeCursorVerify,
			Pull:       (&fakeCursorPull{}).Pull,
			Now:        func() time.Time { return cursorTestNow },
		},
		CursorDrainOnly: true,
		Progress:        rec.record,
		progressTicks:   make(chan time.Time),
	})
	if err != nil {
		t.Fatalf("drain-only run failed: %v", err)
	}
	if res.Cursor.SyncedBatches != 1 {
		t.Fatalf("the pre-run cursor batch must drain: %+v", res.Cursor)
	}
	cursorBatches := rec.batches(ProgressQueueCursor)
	if len(cursorBatches) == 0 {
		t.Fatalf("the cursor drain must emit batch events")
	}
	var acknowledged *ProgressEvent
	for _, ev := range cursorBatches {
		if ev.Origin != OriginPendingBacklog {
			t.Fatalf("a drain-only round over pre-run backlog is provably backlog: %+v", ev)
		}
		if ev.Phase == "outcome" && ev.Result == "acknowledged" {
			cp := ev
			acknowledged = &cp
		}
	}
	if acknowledged == nil {
		t.Fatalf("the drained cursor batch must reach the acknowledged terminal: %+v", cursorBatches)
	}
	if acknowledged.FirstBatchConfirmation != FirstBatchConfirmationYes || !acknowledged.ReceiptObserved {
		t.Fatalf("the acknowledged terminal proves the first local confirmation: %+v", acknowledged)
	}

	// A pull round over the same fixture shape is mixed: unknown.
	stateDir2 := t.TempDir()
	server2 := startBudgetFakeServer(t)
	bindCursorDevice(t, stateDir2, server2.URL)
	writeCursorPermit(t, stateDir2)
	seedCursorPendingBatch(t, stateDir2, "progress-cursor-mixed-1", 1)
	rec2 := &progressRecorder{}
	pull := &fakeCursorPull{events: cursorFixtureEvents()}
	res2, err := Run(context.Background(), Options{
		StateDir:   stateDir2,
		ServerURL:  server2.URL,
		HTTPClient: server2.Client(),
		HomeDir:    t.TempDir(),
		Now:        func() time.Time { return cursorTestNow },
		Cursor: &cursorsync.Options{
			StateDir:   stateDir2,
			ServerURL:  server2.URL,
			HTTPClient: server2.Client(),
			Auth:       &fakeCursorAuth{},
			Verify:     fakeCursorVerify,
			Pull:       pull.Pull,
			Now:        func() time.Time { return cursorTestNow },
		},
		Progress:      rec2.record,
		progressTicks: make(chan time.Time),
	})
	if err != nil {
		t.Fatalf("pull round failed: %v", err)
	}
	_ = res2
	for _, ev := range rec2.batches(ProgressQueueCursor) {
		if ev.Origin != OriginUnknown {
			t.Fatalf("a pull round is mixed by construction: %+v", ev)
		}
	}
}

// writePendingMixedScopeBatch seeds a pending batch whose records straddle
// a consent history cutoff (half before, half after).
func writePendingMixedScopeBatch(t *testing.T, stateDir, batchID string) {
	t.Helper()
	batchesDir := filepath.Join(stateDir, "batches")
	if err := os.MkdirAll(batchesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(batchesDir, batchID+".json")
	records := make([]map[string]any, 0, 4)
	timestamps := []string{"2026-10-21T04:00:00Z", "2026-10-22T04:00:00Z"}
	for i := 1; i <= 4; i++ {
		records = append(records, map[string]any{
			"recordKey":      fmt.Sprintf("%s-record-%d", batchID, i),
			"kind":           "delta",
			"occurredAt":     timestamps[i%2],
			"tool":           "usage-json",
			"input":          "10",
			"cacheRead":      "0",
			"cacheWrite":     "0",
			"output":         "5",
			"adapterVersion": "collection-test-1",
			"sourceType":     "fixture",
		})
	}
	payload := map[string]any{"batchId": batchID, "records": records}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{
		BatchID:     batchID,
		File:        path,
		Source:      "usage-json",
		Input:       path,
		RecordCount: 4,
	}); err != nil {
		t.Fatal(err)
	}
}

// A scope_changed rejection has the syncclient complete a durable
// reorganization BEFORE the error surfaces as a failed upload: the held
// queue snapshot must be conservatively invalidated on that failure
// path (never a short-window stale value), and the drain's closing
// bounded re-sample must restore it. Concurrent ticks run throughout —
// under -race this pins the failure path against the heartbeat.
func TestRunScopeChangedFailureInvalidatesAndResamples(t *testing.T) {
	stateDir := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self":
			writeJSONForTest(w, http.StatusOK, map[string]any{"device": map[string]any{
				"deviceId": "dev-1", "consentRevision": 7,
				"uploadAuthorized": true, "revoked": false,
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/batches":
			// The server rejects the batch with a scope change; the
			// syncclient reorganizes durably (a fresh self GET, a new
			// pending child, quarantine for nothing here) and returns
			// the scope error.
			writeJSONForTest(w, http.StatusConflict, map[string]any{"error": map[string]any{
				"code":    "scope_changed",
				"message": "synthetic scope change",
			}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)
	writePendingBatch(t, stateDir, "progress-scope-fail-1")

	rec := &progressRecorder{}
	ticks := make(chan time.Time)
	// Drive concurrent ticks throughout the run: any race between the
	// failure path's invalidation and the heartbeat shows under -race.
	stopTicks := make(chan struct{})
	ticksDone := make(chan struct{})
	go func() {
		defer close(ticksDone)
		for {
			select {
			case <-stopTicks:
				return
			case ticks <- time.Now():
			}
		}
	}()
	res, err := Run(context.Background(), Options{
		StateDir:      stateDir,
		ServerURL:     server.URL,
		Progress:      rec.record,
		progressTicks: ticks,
	})
	close(stopTicks)
	<-ticksDone
	if err == nil {
		t.Fatalf("the scope-changed upload must fail the run: %+v", res)
	}
	if res.DrainStop != DrainStopFailed {
		t.Fatalf("the failure semantics stay exactly as before: %+v", res)
	}
	// The parent batch settled through the reorganization; the drain's
	// closing bounded re-sample must observe the resulting queue.
	queues := rec.queues(ProgressQueueDevice)
	if len(queues) == 0 {
		t.Fatalf("the drain must emit queue snapshots")
	}
	last := queues[len(queues)-1]
	if !last.Counted {
		t.Fatalf("the closing re-sample must restore the queue: %+v", last)
	}
	if last.PendingBatches != 1 {
		// The reorganized child stays pending for the next run.
		t.Fatalf("the reorganization's child must be the observed remainder: %+v", last)
	}
	// The batch event of the failed attempt reports the scope-shaped
	// final failure conservatively.
	for _, ev := range rec.batches(ProgressQueueDevice) {
		if ev.Result != "final_failure" {
			t.Fatalf("a scope rejection is a final failure on the device vocabulary: %+v", ev)
		}
		if ev.Origin != OriginUnknown {
			t.Fatalf("a plain parent possibly replaced by the reorg stays unknown: %+v", ev)
		}
	}
}
