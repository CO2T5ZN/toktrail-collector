package main

// Synthetic end-to-end happy-path coverage for the `toktrail periodic
// --drain-only` CLI entry (runPeriodic), exercised through the real flag
// parsing and result rendering like a user invocation.
//
// Everything is synthetic: a tempdir state directory (never the real
// TOKTRAIL_HOME, which the explicit --state-dir flag overrides), an
// httptest fake for the ingest server, seeded pending outbox batches, a
// claude-code-jsonl source grant over a synthetic session directory with
// scannable records (so any regression that makes drain-only scan sources
// would export and upload extra batches), and an active local Cursor
// permit (so any regression that makes drain-only run the account-level
// cursor source would consume it). No test reads real tool state, real
// credentials, or performs any network access beyond the fake server.
//
// Covered behavior:
//   - --drain-only uploads only already-pending device outbox batches.
//   - --max-total-batches bounds the drain through the shared POST
//     budget: the run stops when the budget declines the next attempt
//     (before its POST), reports itself incomplete and returns a
//     non-zero exit; a follow-up run continues and finishes the queue.
//   - No source scanning (no export, no extra ingest, no new outbox
//     batch from the granted session directory) and no account pull (no
//     cursor round; the local permit stays byte-identical).

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/cursor/identity"
	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/local/cursorsource"
	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncbudget"
)

// periodicDrainSecret is an obvious synthetic device secret; never real.
const periodicDrainSecret = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

// periodicUpload records one real ingest POST (device or cursor queue) in
// arrival order, so fair-rotation tests can assert alternation.
type periodicUpload struct {
	Queue   string
	BatchID string
}

// periodicDrainFakeServer stands in for the ingest server: it answers the
// device self preflight and accepts every batch upload while counting
// per-endpoint traffic so the test can assert exactly what the CLI sent.
// Any other endpoint is recorded as unexpected and fails the test.
type periodicDrainFakeServer struct {
	*httptest.Server
	self       atomic.Int64
	ingest     atomic.Int64
	srcIngest  atomic.Int64
	tooling    atomic.Int64
	unexpected atomic.Int64
	// pauseFromSelf makes every /v1/devices/self request at or beyond
	// this 1-based count answer the paused device view (0=never).
	pauseFromSelf atomic.Int64
	// fenceFromSelf makes every /v1/devices/self request at or beyond
	// this 1-based count serve the account sources with
	// fenceVersionOverride instead of their recorded fence (0=never).
	fenceFromSelf          atomic.Int64
	fenceVersionOverridden atomic.Int64
	// cursorDisallowedFromSelf makes every /v1/devices/self request at
	// or beyond this 1-based count answer with an allowedTools list that
	// excludes the cursor tool (0=never; the default view stays
	// unrestricted).
	cursorDisallowedFromSelf atomic.Int64
	// srcIngestStatus, when non-zero, makes every source-batch ingest
	// POST answer this HTTP status with a codeless body (0=accept).
	srcIngestStatus atomic.Int64
	// deviceIngestStatus, when non-zero, makes every device-batch
	// ingest POST answer this HTTP status with a codeless body
	// (0=accept) — the transient-failure shape for retry tests.
	deviceIngestStatus atomic.Int64
	// accountSources, when non-empty, is served in the self view so the
	// cursor round finds its designated source.
	accountSources []protocol.Source

	mu    sync.Mutex
	order []periodicUpload
}

func newPeriodicDrainFakeServer(t *testing.T) *periodicDrainFakeServer {
	t.Helper()
	s := &periodicDrainFakeServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self":
			n := s.self.Add(1)
			paused := s.pauseFromSelf.Load() > 0 && n >= s.pauseFromSelf.Load()
			device := map[string]any{
				"deviceId":          "dev-drain-1",
				"applicationId":     "app-drain-1",
				"externalSubjectId": "sub-drain-1",
				"deviceName":        "collector-drain-test",
				"platform":          "darwin",
				"consentRevision":   7,
				"uploadAuthorized":  true,
				"publicAuthorized":  false,
				"revoked":           false,
				"checkedAt":         "2026-10-30T04:00:00Z",
			}
			if paused {
				// The grant-protocol marker is required for the
				// syncclient to honor the pause (checkNotPaused ignores
				// old-protocol snapshots), mirroring the real server's
				// paused grant view.
				device["paused"] = true
				device["grantProtocolVersion"] = 1
				device["deviceGrantManaged"] = true
				device["allowedTools"] = []string{"__toktrail_paused__"}
			}
			if ff := s.fenceFromSelf.Load(); ff > 0 && n >= ff {
				if sources := s.accountSourcesSnapshot(); len(sources) > 0 {
					flipped := make([]protocol.Source, 0, len(sources))
					for _, src := range sources {
						src.FenceVersion = s.fenceVersionOverridden.Load()
						flipped = append(flipped, src)
					}
					device["accountSources"] = flipped
				}
			} else if sources := s.accountSourcesSnapshot(); len(sources) > 0 {
				device["accountSources"] = sources
			}
			if cd := s.cursorDisallowedFromSelf.Load(); cd > 0 && n >= cd {
				device["allowedTools"] = []string{"codex"}
			}
			writePeriodicDrainJSON(w, http.StatusOK, map[string]any{"device": device})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/batches":
			s.ingest.Add(1)
			var body struct {
				BatchID string           `json:"batchId"`
				Records []map[string]any `json:"records"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("invalid ingest body: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if status := s.deviceIngestStatus.Load(); status != 0 {
				writePeriodicDrainJSON(w, int(status), map[string]any{"error": map[string]any{
					"code":    "service_unavailable",
					"message": "synthetic device-batch failure",
				}})
				return
			}
			s.recordUpload("device", body.BatchID)
			writePeriodicDrainJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
				"batchId":         body.BatchID,
				"status":          "accepted",
				"acceptedRecords": len(body.Records),
				"rejectedRecords": 0,
				"replay":          false,
				"receivedAt":      "2026-10-30T04:01:00Z",
				"recordErrors":    []map[string]any{},
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/source-batches":
			s.srcIngest.Add(1)
			var batch struct {
				BatchID string            `json:"batchId"`
				Records []json.RawMessage `json:"records"`
			}
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				t.Errorf("invalid source-batch body: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if status := s.srcIngestStatus.Load(); status != 0 {
				writePeriodicDrainJSON(w, int(status), map[string]any{"error": map[string]any{
					"code":    "service_unavailable",
					"message": "synthetic source-batch failure",
				}})
				return
			}
			s.recordUpload("cursor", batch.BatchID)
			writePeriodicDrainJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
				"batchId":         batch.BatchID,
				"status":          "accepted",
				"acceptedRecords": len(batch.Records),
				"rejectedRecords": 0,
				"replay":          false,
				"receivedAt":      "2026-10-30T04:01:00Z",
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/devices/tool-status":
			s.tooling.Add(1)
			writePeriodicDrainJSON(w, http.StatusAccepted, map[string]any{"accepted": true})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/devices/grant-ack":
			// A managed (paused or restricted) grant view is still
			// acknowledged; the envelope echoes the applied revision.
			var body struct {
				ConsentRevision int64 `json:"consentRevision"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			writePeriodicDrainJSON(w, http.StatusOK, map[string]any{"grantAck": map[string]any{
				"consentRevision": body.ConsentRevision, "currentConsentRevision": body.ConsentRevision,
				"ackedState": "applied", "ackedAt": "2026-10-30T04:00:00Z",
			}})
		default:
			s.unexpected.Add(1)
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Server.Close)
	return s
}

// setPauseFromSelf arms (n>0) or clears (n=0) the mid-run pause flip.
func (s *periodicDrainFakeServer) setPauseFromSelf(n int64) { s.pauseFromSelf.Store(n) }

// setFenceFromSelf arms (n>0) the mid-run fence flip: every self view at
// or beyond n serves the account sources under the given fence version.
func (s *periodicDrainFakeServer) setFenceFromSelf(n, fence int64) {
	s.fenceFromSelf.Store(n)
	s.fenceVersionOverridden.Store(fence)
}

// setCursorDisallowedFromSelf arms (n>0) the scope narrowing that
// excludes the cursor tool from the self view's allowedTools at or
// beyond n.
func (s *periodicDrainFakeServer) setCursorDisallowedFromSelf(n int64) {
	s.cursorDisallowedFromSelf.Store(n)
}

// setSrcIngestStatus makes every source-batch ingest POST answer the
// given HTTP status with a codeless body (0=accept).
func (s *periodicDrainFakeServer) setSrcIngestStatus(status int64) {
	s.srcIngestStatus.Store(status)
}

// setDeviceIngestStatus makes every device-batch ingest POST answer
// this HTTP status (0=accept).
func (s *periodicDrainFakeServer) setDeviceIngestStatus(status int64) {
	s.deviceIngestStatus.Store(status)
}

// setAccountSources arms the self view's accountSources list.
func (s *periodicDrainFakeServer) setAccountSources(sources []protocol.Source) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accountSources = sources
}

func (s *periodicDrainFakeServer) accountSourcesSnapshot() []protocol.Source {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accountSources
}

func (s *periodicDrainFakeServer) recordUpload(queue, batchID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.order = append(s.order, periodicUpload{Queue: queue, BatchID: batchID})
}

// uploadOrder returns a copy of the ordered upload log.
func (s *periodicDrainFakeServer) uploadOrder() []periodicUpload {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]periodicUpload(nil), s.order...)
}

func writePeriodicDrainJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writePeriodicDrainPendingBatch seeds the outbox with a pending batch
// file carrying n synthetic records, mirroring the collection test
// fixture: no export round is needed to exercise the drain.
func writePeriodicDrainPendingBatch(t *testing.T, stateDir, batchID string, n int) {
	t.Helper()
	batchesDir := filepath.Join(stateDir, "batches")
	if err := os.MkdirAll(batchesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(batchesDir, batchID+".json")
	records := make([]map[string]any, 0, n)
	for i := 1; i <= n; i++ {
		records = append(records, map[string]any{
			"recordKey":      fmt.Sprintf("%s-record-%d", batchID, i),
			"kind":           "delta",
			"occurredAt":     "2026-10-30T04:00:00Z",
			"tool":           "usage-json",
			"input":          "10",
			"cacheRead":      "0",
			"cacheWrite":     "0",
			"output":         "5",
			"adapterVersion": "periodic-drain-test-1",
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
		RecordCount: n,
	}); err != nil {
		t.Fatal(err)
	}
}

// writePeriodicDrainClaudeSession writes a synthetic Claude Code session
// directory holding two scannable assistant messages. The file lives
// outside the state directory; a drain-only run must never read it.
func writePeriodicDrainClaudeSession(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	lines := make([]string, 0, 2)
	for i, ts := range []string{"2026-10-30T04:00:00Z", "2026-10-30T04:01:00Z"} {
		line := map[string]any{
			"type":      "assistant",
			"timestamp": ts,
			"message": map[string]any{"id": fmt.Sprintf("msg_drain_%d", i+1), "usage": map[string]any{
				"input_tokens":                10,
				"cache_read_input_tokens":     0,
				"cache_creation_input_tokens": 0,
				"output_tokens":               5,
			}},
			"sessionId": "s-drain",
		}
		b, err := json.Marshal(line)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(b))
	}
	path := filepath.Join(dir, "session-drain.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// writePeriodicDrainCursorPermit seeds an active local Cursor permit so
// the account-level source is armed: a full periodic run would attempt
// the cursor round, while a drain-only run must leave it untouched.
func writePeriodicDrainCursorPermit(t *testing.T, stateDir string) {
	t.Helper()
	license := cursorsource.License{
		SourceInstanceID: "cursor-src-drain-1",
		SourceType:       cursorsource.SourceType,
		Status:           cursorsource.StatusActive,
		ConfirmedAt:      time.Date(2026, 10, 30, 3, 0, 0, 0, time.UTC),
		ConsentRevision:  40,
		FenceVersion:     3,
		NextRevision:     7,
		AccountMatchID:   identity.MatchAccount("user_draintest01"),
	}
	if err := cursorsource.New(stateDir).Save(license); err != nil {
		t.Fatal(err)
	}
}

// capturePeriodicStdout runs fn with os.Stdout redirected to a pipe and
// returns everything the command printed. The pipe is drained
// concurrently (see pipe_capture_test.go): a verbose periodic run
// writes far more than the OS pipe buffer, so a capture that only
// started reading after fn returned would deadlock mid-write.
func capturePeriodicStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	return captureStdoutPiped(t, fn)
}

func TestRunPeriodicDrainOnlySyntheticEndToEnd(t *testing.T) {
	stateDir := t.TempDir() // never the real state directory
	server := newPeriodicDrainFakeServer(t)

	// Bound device pointing at the fake server: draining requires an
	// existing binding and never re-binds.
	if err := statedir.New(stateDir).Save(statedir.DeviceState{
		ServerURL:    server.URL,
		DeviceID:     "dev-drain-1",
		DeviceSecret: periodicDrainSecret,
	}); err != nil {
		t.Fatal(err)
	}

	// Three already-pending batches: the drain-only run must upload only
	// these, bounded by the flags below.
	writePeriodicDrainPendingBatch(t, stateDir, "batch-drain-cli-1", 1)
	writePeriodicDrainPendingBatch(t, stateDir, "batch-drain-cli-2", 1)
	writePeriodicDrainPendingBatch(t, stateDir, "batch-drain-cli-3", 1)

	// An enabled source grant over a synthetic session directory with
	// scannable records: a full periodic run would export and upload a
	// new batch from it, so it proves drain-only performs no source scan.
	sessions := filepath.Join(t.TempDir(), "sessions")
	sessionFile := writePeriodicDrainClaudeSession(t, sessions)
	if _, err := grants.New(stateDir).Enable("claude-code-jsonl", sessions); err != nil {
		t.Fatal(err)
	}
	sessionBefore, err := os.ReadFile(sessionFile)
	if err != nil {
		t.Fatal(err)
	}

	// An active Cursor permit proves drain-only performs no account pull.
	writePeriodicDrainCursorPermit(t, stateDir)
	permitBefore, err := os.ReadFile(cursorsource.New(stateDir).Path())
	if err != nil {
		t.Fatal(err)
	}

	// Run 1: the shared budget (2) is below the per-queue bound (5), so
	// the drain must stop when the budget declines the third attempt —
	// before its ingest POST — and report the run as incomplete with a
	// non-zero exit.
	args := []string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--drain-only",
		"--max-batches", "5",
		"--max-total-batches", "2",
		"--sync-timeout", "30s",
		"--verbose",
	}
	out1, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
	if err == nil {
		t.Fatalf("a budget-exhausted drain with pending batches must exit non-zero, stdout:\n%s", out1)
	}
	if !errors.Is(err, syncbudget.ErrTotalExhausted) || !strings.Contains(err.Error(), "periodic incomplete") {
		t.Fatalf("the stop must surface the budget sentinel as an incomplete run, got %v", err)
	}

	// Incomplete accounting: nothing exported (no source scan), exactly
	// the budgeted two batches synced, one batch left for the next run.
	if !strings.Contains(out1, "exportedBatches=0 exportedRecords=0") {
		t.Fatalf("drain-only run must not export anything, stdout:\n%s", out1)
	}
	if !strings.Contains(out1, "syncedBatches=2 syncedRecords=2") {
		t.Fatalf("expected exactly two drained batches with two records, stdout:\n%s", out1)
	}
	if !strings.Contains(out1, "pendingRemaining=1") || !strings.Contains(out1, "stopped by the shared upload budget") {
		t.Fatalf("expected the budget-stopped remainder report, stdout:\n%s", out1)
	}
	if !strings.Contains(out1, "incomplete: the --max-total-batches 2 shared upload budget is exhausted") {
		t.Fatalf("expected the incomplete report, stdout:\n%s", out1)
	}
	for _, forbidden := range []string{"grant ", "grantSync:", "cursor sync:"} {
		if strings.Contains(out1, forbidden) {
			t.Fatalf("drain-only run must not scan sources or pull accounts (%q found), stdout:\n%s", forbidden, out1)
		}
	}

	// Network: one self preflight per upload plus one for the declined
	// attempt (the budget reserve sits right before the ingest POST, so
	// the declined batch still ran its preflight) and nothing else — no
	// grant-sync fetch, no scan-driven extra ingest, no account traffic.
	if got := server.self.Load(); got != 3 {
		t.Fatalf("expected three self preflights (2 uploads + 1 declined attempt), got %d", got)
	}
	if got := server.ingest.Load(); got != 2 {
		t.Fatalf("expected exactly two ingest uploads, got %d", got)
	}
	if got := server.tooling.Load(); got != 0 {
		t.Fatalf("drain-only run must not report tool statuses, got %d", got)
	}
	if got := server.unexpected.Load(); got != 0 {
		t.Fatalf("drain-only run hit unexpected endpoints %d time(s)", got)
	}

	// State: the outbox still holds exactly the three seeded batches —
	// two synced, one pending — and no scan-exported batch appeared.
	outboxState, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	pending, synced := 0, 0
	for _, batch := range outboxState.Batches {
		switch batch.Status {
		case outbox.StatusPending:
			pending++
		case outbox.StatusSynced:
			synced++
		default:
			t.Fatalf("unexpected outbox status %q for batch %s", batch.Status, batch.BatchID)
		}
	}
	if len(outboxState.Batches) != 3 || pending != 1 || synced != 2 {
		t.Fatalf("expected 3 seeded batches (1 pending, 2 synced), got %d total, %d pending, %d synced",
			len(outboxState.Batches), pending, synced)
	}

	// No source scan and no account pull: the granted session file and
	// the local Cursor permit stay byte-identical.
	sessionAfter, err := os.ReadFile(sessionFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sessionBefore, sessionAfter) {
		t.Fatal("drain-only run must not modify the granted input")
	}
	permitAfter, err := os.ReadFile(cursorsource.New(stateDir).Path())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(permitBefore, permitAfter) {
		t.Fatal("drain-only run must not touch the local cursor permit (no account pull)")
	}

	// The device stays bound to the same fake server (no implicit rebind).
	st, err := statedir.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.DeviceID != "dev-drain-1" || st.ServerURL != server.URL {
		t.Fatalf("drain-only run must keep the existing binding, got device %q server %q", st.DeviceID, st.ServerURL)
	}

	// Run 2: without the total bound the next run continues the drain and
	// finishes the queue, proving the reported remainder was real.
	args2 := []string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--drain-only",
		"--max-batches", "5",
		"--sync-timeout", "30s",
		"--verbose",
	}
	out2, err := capturePeriodicStdout(t, func() error { return runPeriodic(args2) })
	if err != nil {
		t.Fatalf("follow-up drain failed: %v\nstdout:\n%s", err, out2)
	}
	if !strings.Contains(out2, "exportedBatches=0 exportedRecords=0") {
		t.Fatalf("follow-up drain must not export anything, stdout:\n%s", out2)
	}
	if !strings.Contains(out2, "syncedBatches=1 syncedRecords=1") {
		t.Fatalf("expected the remaining batch to drain, stdout:\n%s", out2)
	}
	if strings.Contains(out2, "pendingRemaining=") {
		t.Fatalf("the finished drain must report no remainder, stdout:\n%s", out2)
	}
	if got := server.ingest.Load(); got != 3 {
		t.Fatalf("expected exactly the 3 seeded batches uploaded across both runs, got %d", got)
	}
	if got := server.self.Load(); got != 4 {
		t.Fatalf("expected exactly four self preflights across both runs (2 uploads + 1 declined + 1 upload), got %d", got)
	}
	if got := server.unexpected.Load(); got != 0 {
		t.Fatalf("drain-only runs hit unexpected endpoints %d time(s)", got)
	}

	final, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, batch := range final.Batches {
		if batch.Status != outbox.StatusSynced {
			t.Fatalf("expected every seeded batch synced after the follow-up run, got %s for %s", batch.Status, batch.BatchID)
		}
	}
}

// TestRunPeriodicNoGrantsStillDrainsAndReportsCounts pins the §6.1 CLI
// surface: a periodic run with NO enabled local file grants still drains
// its pending device batches, and the summary shows the synced counts —
// the historical "nothing to collect" skip line only appears for a run
// whose sendable queue is actually empty.
func TestRunPeriodicNoGrantsStillDrainsAndReportsCounts(t *testing.T) {
	stateDir := t.TempDir()
	server := newPeriodicDrainFakeServer(t)
	if err := statedir.New(stateDir).Save(statedir.DeviceState{
		ServerURL:    server.URL,
		DeviceID:     "dev-drain-1",
		DeviceSecret: periodicDrainSecret,
	}); err != nil {
		t.Fatal(err)
	}
	writePeriodicDrainPendingBatch(t, stateDir, "nogrants-drain-1", 2)

	args := []string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--max-batches", "5",
		"--sync-timeout", "30s",
		"--verbose",
	}
	out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
	if err != nil {
		t.Fatalf("the grant-less run must succeed while draining its queue: %v\nstdout:\n%s", err, out)
	}
	if !strings.Contains(out, "syncedBatches=1 syncedRecords=2") {
		t.Fatalf("the drained counts must be reported for a grant-less run, stdout:\n%s", out)
	}
	if strings.Contains(out, "nothing to collect") {
		t.Fatalf("a run that drained its queue must not print the no-op skip line, stdout:\n%s", out)
	}

	// The paired no-op shape: no grants AND an empty queue keeps the
	// historical skip line.
	emptyDir := t.TempDir()
	emptyServer := newPeriodicDrainFakeServer(t)
	if err := statedir.New(emptyDir).Save(statedir.DeviceState{
		ServerURL:    emptyServer.URL,
		DeviceID:     "dev-drain-1",
		DeviceSecret: periodicDrainSecret,
	}); err != nil {
		t.Fatal(err)
	}
	args2 := []string{
		"--state-dir", emptyDir,
		"--server", emptyServer.URL,
		"--max-batches", "5",
		"--sync-timeout", "30s",
		"--verbose",
	}
	out2, err := capturePeriodicStdout(t, func() error { return runPeriodic(args2) })
	if err != nil {
		t.Fatalf("the empty grant-less run must succeed: %v\nstdout:\n%s", err, out2)
	}
	if !strings.Contains(out2, "no enabled source grants; nothing to collect") {
		t.Fatalf("an actually-empty queue keeps the historical skip line, stdout:\n%s", out2)
	}
}
