package collection

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/local/statedir"
)

// ---------------------------------------------------------------------------
// test helpers
// ---------------------------------------------------------------------------

const testSecret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// toolStatusReport mirrors one entry of the POST /v1/devices/tool-status
// body the collector sends.
type toolStatusReport struct {
	Tool   string `json:"tool"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// fakeCollectorServer stands in for the ingest server: it answers the device
// self preflight, accepts every batch upload, and accepts tool-status reports
// while recording per-endpoint traffic so tests can assert exactly what the
// collector sent. Only synthetic fixtures are ever sent.
type fakeCollectorServer struct {
	*httptest.Server
	total   atomic.Int64
	self    atomic.Int64
	ingest  atomic.Int64
	tooling atomic.Int64 // POST /v1/devices/tool-status

	// failIngestOnce, when set, makes the next ingest upload fail with a 500
	// exactly once. Set by fakeServerWithFlake only.
	failIngestOnce *atomic.Bool

	// rejectRecords, when set, decides per ingest upload which submitted
	// record indexes the server rejects, mapped to a stable rejection
	// code. It lets tests exercise partial and fully rejected receipts;
	// nil accepts every record (the historical default).
	rejectRecords func(records []map[string]any) map[int]string

	mu      sync.Mutex
	reports []toolStatusReport
	// posts holds the statuses[] payload of each tool-status POST, in order.
	posts [][]toolStatusReport
}

func (s *fakeCollectorServer) totalRequests() int64      { return s.total.Load() }
func (s *fakeCollectorServer) selfRequests() int64       { return s.self.Load() }
func (s *fakeCollectorServer) ingestRequests() int64     { return s.ingest.Load() }
func (s *fakeCollectorServer) toolStatusRequests() int64 { return s.tooling.Load() }

// toolStatusReports returns every recorded statuses[] entry in arrival order.
func (s *fakeCollectorServer) toolStatusReports() []toolStatusReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]toolStatusReport, len(s.reports))
	copy(out, s.reports)
	return out
}

// lastToolStatusReports returns the statuses[] entries of the most recent
// tool-status POST, or nil when none was received yet.
func (s *fakeCollectorServer) lastToolStatusReports() []toolStatusReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.posts) == 0 {
		return nil
	}
	last := s.posts[len(s.posts)-1]
	out := make([]toolStatusReport, len(last))
	copy(out, last)
	return out
}

func (s *fakeCollectorServer) handle(t *testing.T, w http.ResponseWriter, r *http.Request) {
	s.total.Add(1)
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self":
		s.self.Add(1)
		writeJSONForTest(w, http.StatusOK, map[string]any{"device": map[string]any{
			"deviceId":          "dev-1",
			"applicationId":     "app-1",
			"externalSubjectId": "sub-1",
			"deviceName":        "collector",
			"platform":          "darwin",
			"consentRevision":   7,
			"uploadAuthorized":  true,
			"publicAuthorized":  false,
			"revoked":           false,
			"checkedAt":         "2026-10-21T04:00:00Z",
		}})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/batches":
		s.ingest.Add(1)
		if s.failIngestOnce != nil && s.failIngestOnce.CompareAndSwap(true, false) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var body struct {
			BatchID string           `json:"batchId"`
			Records []map[string]any `json:"records"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("invalid ingest body: %v", err)
		}
		var rejected map[int]string
		if s.rejectRecords != nil {
			rejected = s.rejectRecords(body.Records)
		}
		writeJSONForTest(w, http.StatusAccepted, ingestReceiptForTest(body.BatchID, body.Records, rejected))
	case r.Method == http.MethodPost && r.URL.Path == "/v1/devices/tool-status":
		s.tooling.Add(1)
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
		s.reports = append(s.reports, body.Statuses...)
		s.posts = append(s.posts, body.Statuses)
		s.mu.Unlock()
		writeJSONForTest(w, http.StatusAccepted, map[string]any{"accepted": true})
	default:
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

// fakeServer starts a fakeCollectorServer and registers its cleanup.
func fakeServer(t *testing.T) *fakeCollectorServer {
	t.Helper()
	s := &fakeCollectorServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handle(t, w, r)
	}))
	t.Cleanup(s.Server.Close)
	return s
}

func writeJSONForTest(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// ingestReceiptForTest builds the batch receipt for one accepted ingest
// upload. rejected maps submitted record indexes to a stable rejection
// code; the accepted count, the receipt status (accepted / partial_error /
// rejected) and the per-record errors derive from it exactly like the real
// server, so the collector's receipt reconciliation accepts the result.
func ingestReceiptForTest(batchID string, records []map[string]any, rejected map[int]string) map[string]any {
	accepted := len(records) - len(rejected)
	recordErrors := make([]map[string]any, 0, len(rejected))
	indexes := make([]int, 0, len(rejected))
	for idx := range rejected {
		indexes = append(indexes, idx)
	}
	sort.Ints(indexes)
	for _, idx := range indexes {
		recordErrors = append(recordErrors, map[string]any{
			"index":     idx,
			"recordKey": records[idx]["recordKey"],
			"code":      rejected[idx],
			"message":   "synthetic rejection for tests",
		})
	}
	status := "accepted"
	switch {
	case len(rejected) > 0 && accepted == 0:
		status = "rejected"
	case len(rejected) > 0:
		status = "partial_error"
	}
	return map[string]any{"batch": map[string]any{
		"batchId":         batchID,
		"status":          status,
		"acceptedRecords": accepted,
		"rejectedRecords": len(rejected),
		"replay":          false,
		"receivedAt":      "2026-10-21T04:01:00Z",
		"recordErrors":    recordErrors,
	}}
}

// bindDevice writes a bound device state pointing at the fake server so the
// drain uses the injected HTTP transport without any implicit rebind.
func bindDevice(t *testing.T, stateDir, serverURL string) {
	t.Helper()
	if err := statedir.New(stateDir).Save(statedir.DeviceState{
		ServerURL:    serverURL,
		DeviceID:     "dev-1",
		DeviceSecret: testSecret,
	}); err != nil {
		t.Fatal(err)
	}
}

// writeClaudeSession writes a synthetic Claude Code session directory with
// two assistant messages. No real user logs are ever read by these tests.
func writeClaudeSession(t *testing.T, dir, name string, lines ...string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func claudeLine(t *testing.T, timestamp, session, msgID string, usage map[string]any) string {
	line := map[string]any{
		"type":      "assistant",
		"timestamp": timestamp,
		"message":   map[string]any{"id": msgID, "usage": usage},
		"sessionId": session,
	}
	b, err := json.Marshal(line)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func claudeUsage(input, cacheRead, cacheWrite, output any) map[string]any {
	return map[string]any{
		"input_tokens":                input,
		"cache_read_input_tokens":     cacheRead,
		"cache_creation_input_tokens": cacheWrite,
		"output_tokens":               output,
	}
}

// enableGrant records an explicit source grant for the periodic entry.
func enableGrant(t *testing.T, stateDir, source, input string) {
	t.Helper()
	if _, err := grants.New(stateDir).Enable(source, input); err != nil {
		t.Fatal(err)
	}
}

// writePendingBatch seeds the outbox with a minimal valid one-record batch
// file, used to exercise the bounded drain without going through export.
func writePendingBatch(t *testing.T, stateDir, batchID string) {
	t.Helper()
	writePendingBatchRecords(t, stateDir, batchID, 1)
}

// writePendingBatchRecords seeds the outbox with a pending batch file
// carrying n synthetic records, for drain tests whose receipts must mix
// accepted and rejected records inside one batch.
func writePendingBatchRecords(t *testing.T, stateDir, batchID string, n int) {
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
			"occurredAt":     "2026-10-21T04:00:00Z",
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
		RecordCount: n,
	}); err != nil {
		t.Fatal(err)
	}
}

// enableIdleGrant enables a grant over an empty session directory so the
// collection phase is a no-op and the drain can be exercised in isolation.
func enableIdleGrant(t *testing.T, stateDir string) {
	t.Helper()
	sessions := filepath.Join(t.TempDir(), "sessions")
	if err := os.MkdirAll(sessions, 0o700); err != nil {
		t.Fatal(err)
	}
	enableGrant(t, stateDir, "claude-code-jsonl", sessions)
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// A second concurrent run must fail fast with the lock error and must not
// touch the network even though a granted input and pending batches exist.
func TestRunRefusesConcurrentRunWithoutNetwork(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)
	input := writeClaudeSession(t, filepath.Join(t.TempDir(), "sessions"), "s.jsonl",
		claudeLine(t, "2026-10-21T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))
	enableGrant(t, stateDir, "claude-code-jsonl", filepath.Dir(input))
	writePendingBatch(t, stateDir, "batch-pending-lock-1")

	lock, err := runlock.Acquire(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()

	_, err = Run(t.Context(), Options{StateDir: stateDir})
	if !errors.Is(err, runlock.ErrBusy) {
		t.Fatalf("expected ErrBusy, got %v", err)
	}
	if n := server.totalRequests(); n != 0 {
		t.Fatalf("concurrent run must not touch the network, got %d requests", n)
	}
}

// No enabled grants (§6.1): the scan reads nothing (the no-grants
// semantics), but the device outbox drain still runs — an already-pending
// batch keeps uploading under the live server consent preflight instead
// of hiding behind PendingRemaining=0. The run reports the NoGrants fact
// WITH the drained counts; Skipped stays empty because work was
// attempted, so no caller can mistake the drained queue for a no-op.
func TestRunWithNoGrantsStillDrainsPendingBatches(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)
	writePendingBatch(t, stateDir, "batch-pending-nogrants-1")

	res, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if !res.NoGrants || res.Grants != 0 {
		t.Fatalf("the no-grants fact must be reported, got %#v", res)
	}
	if res.Skipped != "" {
		t.Fatalf("a run that drained work must not carry the no-op skip wording, got %q", res.Skipped)
	}
	if res.SyncedBatches != 1 || res.SyncedRecords != 1 || res.PendingRemaining != 0 {
		t.Fatalf("the pending batch must drain, got %+v", res)
	}
	if res.GrantSync.Active {
		t.Fatalf("old-protocol server must not activate the grant sync, got %#v", res.GrantSync)
	}
	if got := server.ingestRequests(); got != 1 {
		t.Fatalf("the grant-less run must upload the pending batch, got %d ingest requests", got)
	}
	if got := server.selfRequests(); got != 2 {
		t.Fatalf("expected the grant-sync self fetch plus the upload preflight, got %d", got)
	}
}

// A grant-less run whose sendable queue is actually EMPTY keeps the
// historical no-op shape: the only network traffic is the grant-sync self
// fetch (a bound device always refreshes its authorization view so the
// server can re-enable tools), and the skip wording is reported.
func TestRunWithNoGrantsAndEmptyQueueStaysNoOp(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)

	res, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if !res.NoGrants || res.Grants != 0 {
		t.Fatalf("expected no-grants no-op, got %#v", res)
	}
	if res.Skipped == "" {
		t.Fatal("expected a skip reason for the no-op run")
	}
	if res.SyncedBatches != 0 || res.PendingRemaining != 0 {
		t.Fatalf("an empty queue must drain nothing, got %+v", res)
	}
	if res.GrantSync.Active {
		t.Fatalf("old-protocol server must not activate the grant sync, got %#v", res.GrantSync)
	}
	if n := server.totalRequests(); n != 1 {
		t.Fatalf("no-grants empty run must only perform the grant-sync self fetch, got %d requests", n)
	}
	if got := server.selfRequests(); got != 1 {
		t.Fatalf("expected exactly the grant-sync self request, got %d", got)
	}
}

func TestRunEmitsProgressEventsForScanAndDrain(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)
	writePendingBatch(t, stateDir, "batch-pending-progress-1")

	var events []ProgressEvent
	res, err := Run(t.Context(), Options{
		StateDir: stateDir,
		Progress: func(event ProgressEvent) {
			events = append(events, event)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.SyncedBatches != 1 || res.PendingRemaining != 0 {
		t.Fatalf("expected one drained batch, got %+v", res)
	}
	wantEnds := []string{"grant_sync", "source_scan", "drain"}
	for _, want := range wantEnds {
		found := false
		for _, event := range events {
			if event.Kind == ProgressStageEnd && event.Stage == want {
				found = true
				if event.EndedAt.IsZero() || event.Duration < 0 {
					t.Fatalf("event %s missing timing data: %+v", want, event)
				}
			}
		}
		if !found {
			t.Fatalf("missing %s end event in %#v", want, events)
		}
	}
	foundComplete := false
	for _, event := range events {
		if event.Kind == ProgressCount && event.Stage == "complete" {
			foundComplete = true
			if event.SyncedBatches != 1 || event.PendingRemaining != 0 {
				t.Fatalf("unexpected complete counts: %+v", event)
			}
		}
	}
	if !foundComplete {
		t.Fatalf("missing complete count event in %#v", events)
	}
}

// A granted input that disappeared after the grant was recorded is skipped
// without failing the run and without upload or tool-status traffic: a
// missing input is a local validation failure, never a tool-status report.
// The grant-sync self fetch still happens (bound device, before scanning).
func TestRunSkipsMissingGrantedInputWithoutNetwork(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)

	sessions := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, sessions, "s.jsonl",
		claudeLine(t, "2026-10-21T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))
	enableGrant(t, stateDir, "claude-code-jsonl", sessions)
	// Remove the whole granted directory so the grant points at a genuinely
	// missing input. Removing only the session file would leave an existing
	// (empty) directory behind, which counts as an accessible-but-idle input.
	if err := os.RemoveAll(sessions); err != nil {
		t.Fatal(err)
	}

	res, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExportedBatches != 0 || res.SyncedBatches != 0 {
		t.Fatalf("nothing must be collected for a missing input: %#v", res)
	}
	if len(res.GrantOutcomes) != 1 || res.GrantOutcomes[0].Skipped == "" {
		t.Fatalf("expected one skipped grant outcome, got %#v", res.GrantOutcomes)
	}
	if !strings.Contains(res.GrantOutcomes[0].Skipped, "not accessible") {
		t.Fatalf("expected the missing input to be reported as inaccessible, got %#v", res.GrantOutcomes)
	}
	if n := server.totalRequests(); n != 1 {
		t.Fatalf("run with only a missing input must only perform the grant-sync self fetch, got %d requests", n)
	}
}

// End to end: one periodic run exports the new observations from a granted
// input through the exportcommit WAL, drains the batch through syncclient
// with the server's fresh-consent preflight intact, and reports a synced
// receipt. A second run over the unchanged input exports nothing, replays no
// ingest, and only reports the empty-scan status.
func TestRunCollectsExportsAndSyncsEndToEnd(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)

	sessions := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, sessions, "session-a.jsonl",
		claudeLine(t, "2026-10-21T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)),
		claudeLine(t, "2026-10-21T04:01:00Z", "s1", "msg_2", claudeUsage(7, 1, 0, 4)))
	enableGrant(t, stateDir, "claude-code-jsonl", sessions)

	res, err := Run(t.Context(), Options{StateDir: stateDir, Now: func() time.Time {
		return time.Date(2026, 10, 21, 4, 2, 0, 0, time.UTC)
	}})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExportedBatches != 1 || res.SyncedBatches != 1 {
		t.Fatalf("expected one exported and one synced batch, got %#v", res)
	}
	if res.PendingRemaining != 0 || res.DrainStopped != "" {
		t.Fatalf("outbox must be fully drained, got %#v", res)
	}
	if len(res.GrantOutcomes) != 1 || !res.GrantOutcomes[0].Exported {
		t.Fatalf("expected the grant to be exported: %#v", res.GrantOutcomes)
	}
	// First run network: grant-sync self fetch, drain preflight + upload,
	// then the synced receipt (self preflight + tool-status POST).
	if got := server.ingestRequests(); got != 1 {
		t.Fatalf("first run must upload exactly one batch, got %d", got)
	}
	if got := server.selfRequests(); got != 3 {
		t.Fatalf("expected grant-sync, drain and receipt preflights, got %d self requests", got)
	}
	if got := server.toolStatusRequests(); got != 1 {
		t.Fatalf("first run must send exactly one synced receipt, got %d tool-status POSTs", got)
	}
	if reports := server.toolStatusReports(); len(reports) != 1 ||
		reports[0] != (toolStatusReport{Tool: "Claude Code", Status: "synced"}) {
		t.Fatalf("expected a single Claude Code synced receipt, got %#v", reports)
	}

	// Second run: no new observations and an empty outbox. The only network
	// traffic is the grant-sync self fetch plus the empty-scan status report
	// (self preflight + tool-status POST), and strictly no ingest replay.
	before, ingestBefore := server.totalRequests(), server.ingestRequests()
	res2, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if res2.ExportedBatches != 0 || res2.SyncedBatches != 0 || res2.PendingRemaining != 0 {
		t.Fatalf("second run over unchanged input must be a no-op, got %#v", res2)
	}
	if len(res2.GrantOutcomes) != 1 || res2.GrantOutcomes[0].Skipped == "" {
		t.Fatalf("expected a skip reason for the unchanged input: %#v", res2.GrantOutcomes)
	}
	if got := server.ingestRequests(); got != ingestBefore {
		t.Fatalf("second run must not replay any ingest upload: %d -> %d", ingestBefore, got)
	}
	if n := server.totalRequests(); n != before+3 {
		t.Fatalf("second run must only add the grant-sync fetch and the empty-scan status report: %d -> %d requests", before, n)
	}
	if got := server.toolStatusRequests(); got != 2 {
		t.Fatalf("second run must add exactly one tool-status POST, got %d total", got)
	}
	if reports := server.toolStatusReports(); len(reports) != 2 ||
		reports[1] != (toolStatusReport{
			Tool:   "Claude Code",
			Status: "no_new_records",
			Detail: "no new records since last confirmed baseline",
		}) {
		t.Fatalf("expected a Claude Code no_new_records status after the receipt, got %#v", reports)
	}
}

// The drain is bounded: with more pending batches than the batch limit the
// run stops after the limit and reports the remainder for the next run.
func TestDrainPendingUploadsOutboxWithoutSourceScanOrGrants(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)
	writePendingBatch(t, stateDir, "batch-drain-only-1")
	writePendingBatch(t, stateDir, "batch-drain-only-2")

	var events []ProgressEvent
	res, err := DrainPending(t.Context(), Options{
		StateDir:   stateDir,
		MaxBatches: 10,
		Progress: func(event ProgressEvent) {
			events = append(events, event)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExportedBatches != 0 || len(res.GrantOutcomes) != 0 || res.Grants != 0 || res.NoGrants {
		t.Fatalf("drain-only run must not scan grants or export, got %+v", res)
	}
	if res.SyncedBatches != 2 || res.PendingRemaining != 0 || res.DrainStopped != "" {
		t.Fatalf("expected two pending batches drained, got %+v", res)
	}
	if got := server.ingestRequests(); got != 2 {
		t.Fatalf("expected exactly two ingest uploads, got %d", got)
	}
	for _, event := range events {
		if event.Stage == "source_scan" || event.Stage == "grant_sync" {
			t.Fatalf("drain-only run emitted scan/grant event: %#v", events)
		}
	}
	foundDrain := false
	foundComplete := false
	for _, event := range events {
		switch {
		case event.Kind == ProgressStageEnd && event.Stage == "drain":
			foundDrain = true
			if event.SyncedBatches != 2 || event.PendingRemaining != 0 {
				t.Fatalf("unexpected drain counts: %+v", event)
			}
		case event.Kind == ProgressCount && event.Stage == "complete":
			foundComplete = true
		}
	}
	if !foundDrain || !foundComplete {
		t.Fatalf("missing drain/complete progress events: %#v", events)
	}
}

func TestRunDrainIsBounded(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)
	writePendingBatch(t, stateDir, "batch-bounded-1")
	writePendingBatch(t, stateDir, "batch-bounded-2")
	writePendingBatch(t, stateDir, "batch-bounded-3")

	res, err := Run(t.Context(), Options{StateDir: stateDir, MaxBatches: 2})
	if err != nil {
		t.Fatal(err)
	}
	if res.SyncedBatches != 2 {
		t.Fatalf("expected exactly the bounded 2 batches synced, got %#v", res)
	}
	if res.PendingRemaining != 1 || res.DrainStopped == "" {
		t.Fatalf("expected one remaining batch and a stop reason, got %#v", res)
	}
	if n := server.totalRequests(); n != 5 { // grant-sync self + 2 batches x (preflight + upload)
		t.Fatalf("unexpected network requests: %d", n)
	}
	// The incomplete drain must suppress the empty-scan status report: the
	// pending remainder proves the run is not settled yet.
	if got := server.toolStatusRequests(); got != 0 {
		t.Fatalf("an unfinished drain must not report tool status, got %d tool-status POSTs", got)
	}

	// The next run continues the drain and finishes the outbox, then reports
	// the idle grant's empty scan in the same run.
	res2, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if res2.SyncedBatches != 1 || res2.PendingRemaining != 0 || res2.DrainStopped != "" {
		t.Fatalf("expected the remaining batch to drain, got %#v", res2)
	}
	if got := server.ingestRequests(); got != 3 {
		t.Fatalf("expected exactly the 3 seeded batches to be uploaded, got %d", got)
	}
	if got := server.toolStatusRequests(); got != 1 {
		t.Fatalf("the finished drain must add exactly one tool-status POST, got %d", got)
	}
	if reports := server.lastToolStatusReports(); len(reports) != 1 ||
		reports[0] != (toolStatusReport{
			Tool:   "Claude Code",
			Status: "no_new_records",
			Detail: "no new records since last confirmed baseline",
		}) {
		t.Fatalf("expected a Claude Code no_new_records status after the drain, got %#v", reports)
	}
	if n := server.totalRequests(); n != 10 { // run 1: 5; run 2: grant-sync + 2 drain + self + status
		t.Fatalf("unexpected total network requests: %d", n)
	}
}

// A failed upload stops the drain without losing the pending batch: it
// stays in the outbox for the next scheduled run.
func TestRunStopsDrainOnUploadFailure(t *testing.T) {
	stateDir := t.TempDir()
	var requests atomic.Int64
	// The server answers the preflight but rejects every upload with a
	// server error.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			writeJSONForTest(w, http.StatusOK, map[string]any{"device": map[string]any{
				"deviceId": "dev-1", "applicationId": "app-1", "externalSubjectId": "sub-1",
				"deviceName": "collector", "platform": "darwin", "consentRevision": 7,
				"uploadAuthorized": true, "publicAuthorized": false, "revoked": false,
				"checkedAt": "2026-10-21T04:00:00Z",
			}})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)
	writePendingBatch(t, stateDir, "batch-fail-1")
	writePendingBatch(t, stateDir, "batch-fail-2")

	res, err := Run(t.Context(), Options{StateDir: stateDir})
	if err == nil {
		t.Fatal("expected the upload failure to surface")
	}
	if res.SyncedBatches != 0 {
		t.Fatalf("nothing must be counted as synced, got %#v", res)
	}
	if res.PendingRemaining < 1 || res.DrainStopped == "" {
		t.Fatalf("expected pending remainder and a drain-stop reason, got %#v", res)
	}
	// The failed batch must still be recorded as pending, not lost.
	ledger := outbox.New(stateDir)
	remaining, err := countPending(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if remaining < 2 {
		t.Fatalf("both batches must remain pending after the failure, got %d", remaining)
	}
}

// A partial receipt — the server accepted some records of a batch and
// rejected the rest — must never read as full sync success. The
// syncclient has already reconciled the receipt (accepted records
// confirmed, batch marked synced), so the run keeps the accepted part
// counted and still reports the tool as synced, but it fails with
// ErrRecordsRejected and explicit rejected counts instead of returning
// nil.
func TestRunPartialReceiptIsNotFullSyncSuccess(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	// Every batch's first record is accepted; the rest are rejected with
	// a stable code.
	server.rejectRecords = func(records []map[string]any) map[int]string {
		rejected := map[int]string{}
		for idx := 1; idx < len(records); idx++ {
			rejected[idx] = "invalid_record"
		}
		return rejected
	}
	bindDevice(t, stateDir, server.URL)

	sessions := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, sessions, "session.jsonl",
		claudeLine(t, "2026-10-21T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)),
		claudeLine(t, "2026-10-21T04:01:00Z", "s1", "msg_2", claudeUsage(7, 1, 0, 4)))
	enableGrant(t, stateDir, "claude-code-jsonl", sessions)

	res, err := Run(t.Context(), Options{StateDir: stateDir, Now: func() time.Time {
		return time.Date(2026, 10, 21, 4, 2, 0, 0, time.UTC)
	}})
	if !errors.Is(err, ErrRecordsRejected) {
		t.Fatalf("expected ErrRecordsRejected, got %v", err)
	}
	if !strings.Contains(err.Error(), "1 record(s)") || !strings.Contains(err.Error(), "1 drained batch") {
		t.Fatalf("the rejection error must carry the explicit counts, got %v", err)
	}
	// The accepted record is not lost: it stays counted and reported.
	if res.SyncedBatches != 1 || res.SyncedRecords != 1 {
		t.Fatalf("the accepted record must stay counted, got %#v", res)
	}
	if res.RejectedBatches != 1 || res.RejectedRecords != 1 {
		t.Fatalf("the rejected record must be counted explicitly, got %#v", res)
	}
	if res.PendingRemaining != 0 || res.DrainStopped != "" {
		t.Fatalf("the settled batch must leave nothing pending, got %#v", res)
	}
	if got := server.toolStatusRequests(); got != 1 {
		t.Fatalf("the accepted part must still produce one synced receipt, got %d tool-status POSTs", got)
	}
	if reports := server.toolStatusReports(); len(reports) != 1 ||
		reports[0] != (toolStatusReport{Tool: "Claude Code", Status: "synced"}) {
		t.Fatalf("expected a single Claude Code synced receipt, got %#v", reports)
	}
	// The batch is settled in the outbox with both counts recorded — the
	// syncclient's reconciliation is preserved, nothing is retried.
	out, loadErr := outbox.New(stateDir).Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(out.Batches) != 1 {
		t.Fatalf("expected exactly the exported batch in the outbox, got %#v", out.Batches)
	}
	batch := out.Batches[0]
	if batch.Status != outbox.StatusSynced || batch.AcceptedRecords != 1 || batch.RejectedRecords != 1 {
		t.Fatalf("expected the settled batch to record accepted=1 rejected=1, got %#v", batch)
	}
}

// A fully rejected receipt — the server accepted nothing — is the
// strongest form of a partial outcome. The run must fail with
// ErrRecordsRejected, count every rejected record, and send no tool
// status at all: no synced receipt (nothing was accepted) and no
// no_new_records empty-scan report either, because the run is not a
// clean success.
func TestRunFullyRejectedReceiptIsNotFullSyncSuccess(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	server.rejectRecords = func(records []map[string]any) map[int]string {
		rejected := map[int]string{}
		for idx := range records {
			rejected[idx] = "invalid_record"
		}
		return rejected
	}
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)
	writePendingBatch(t, stateDir, "batch-rejected-all-1")

	res, err := Run(t.Context(), Options{StateDir: stateDir})
	if !errors.Is(err, ErrRecordsRejected) {
		t.Fatalf("expected ErrRecordsRejected, got %v", err)
	}
	if !strings.Contains(err.Error(), "batch-rejected-all-1") {
		t.Fatalf("the rejection error must name the rejected batch, got %v", err)
	}
	if res.SyncedRecords != 0 {
		t.Fatalf("nothing must be counted as accepted, got %#v", res)
	}
	if res.SyncedBatches != 1 || res.RejectedBatches != 1 || res.RejectedRecords != 1 {
		t.Fatalf("expected the settled batch and its rejected record counted, got %#v", res)
	}
	if res.PendingRemaining != 0 {
		t.Fatalf("the settled batch must not stay pending, got %#v", res)
	}
	// Neither a synced receipt nor the empty-scan status may dress the
	// run up as success.
	if got := server.toolStatusRequests(); got != 0 {
		t.Fatalf("a fully rejected run must send no tool status, got %d tool-status POSTs", got)
	}
	// The syncclient's reconciliation stands: the batch is terminal with
	// the rejected count recorded, not queued for a blind resend.
	out, loadErr := outbox.New(stateDir).Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(out.Batches) != 1 {
		t.Fatalf("expected exactly the seeded batch in the outbox, got %#v", out.Batches)
	}
	batch := out.Batches[0]
	if batch.Status != outbox.StatusSynced || batch.AcceptedRecords != 0 || batch.RejectedRecords != 1 {
		t.Fatalf("expected the settled batch to record accepted=0 rejected=1, got %#v", batch)
	}
}

// A partial rejection must not block the rest of the drain: later pending
// batches still upload and their accepted records stay counted alongside
// the rejected ones, while the run still fails overall.
func TestRunDrainContinuesAfterPartialRejection(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	var uploads atomic.Int64
	server.rejectRecords = func(records []map[string]any) map[int]string {
		if uploads.Add(1) == 1 {
			// First batch: two records, the second one rejected.
			return map[int]string{1: "invalid_record"}
		}
		return nil // Later batches: accept everything.
	}
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)
	writePendingBatchRecords(t, stateDir, "batch-partial-first", 2)
	writePendingBatch(t, stateDir, "batch-partial-second")

	res, err := Run(t.Context(), Options{StateDir: stateDir})
	if !errors.Is(err, ErrRecordsRejected) {
		t.Fatalf("expected ErrRecordsRejected, got %v", err)
	}
	if got := server.ingestRequests(); got != 2 {
		t.Fatalf("the drain must upload both batches despite the partial rejection, got %d ingest POSTs", got)
	}
	if res.SyncedBatches != 2 || res.SyncedRecords != 2 {
		t.Fatalf("the second batch's accepted record must not be lost, got %#v", res)
	}
	if res.RejectedBatches != 1 || res.RejectedRecords != 1 {
		t.Fatalf("only the first batch's rejection must be counted, got %#v", res)
	}
	if res.PendingRemaining != 0 {
		t.Fatalf("both settled batches must leave nothing pending, got %#v", res)
	}
}

// An empty state directory must fail closed before any work: the required
// state dir is validated up front.
func TestRunRequiresStateDir(t *testing.T) {
	if _, err := Run(t.Context(), Options{}); err == nil {
		t.Fatal("expected an error for a missing state dir")
	}
	if _, err := Run(t.Context(), Options{StateDir: "   "}); err == nil {
		t.Fatal("expected an error for a blank state dir")
	}
}

// The scheduled drain only works against an already-bound device: an
// unbound state with pending batches must not attempt any network call and
// must report the missing binding.
func TestRunDrainRequiresBoundDevice(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	// No bindDevice call: the state directory has no bound device.
	enableIdleGrant(t, stateDir)
	writePendingBatch(t, stateDir, "batch-unbound-1")

	res, err := Run(t.Context(), Options{StateDir: stateDir})
	if err == nil {
		t.Fatal("expected an error because no device is bound")
	}
	if res.PendingRemaining < 1 {
		t.Fatalf("the pending batch must stay in the outbox, got %#v", res)
	}
	if n := server.totalRequests(); n != 0 {
		t.Fatalf("unbound drain must not touch the network, got %d requests", n)
	}
}

// A completely idle run over enabled Claude Code and Codex grants with no new
// records reports a single deduplicated no_new_records tool-status POST that
// covers both tools: one self preflight plus one POST, and no ingest upload.
func TestRunReportsBatchedEmptyScanStatusForClaudeAndCodex(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)

	claudeSessions := filepath.Join(t.TempDir(), "claude-sessions")
	if err := os.MkdirAll(claudeSessions, 0o700); err != nil {
		t.Fatal(err)
	}
	enableGrant(t, stateDir, "claude-code-jsonl", claudeSessions)

	codexSessions := filepath.Join(t.TempDir(), "codex-sessions")
	if err := os.MkdirAll(codexSessions, 0o700); err != nil {
		t.Fatal(err)
	}
	enableGrant(t, stateDir, "codex-jsonl", codexSessions)

	res, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExportedBatches != 0 || res.SyncedBatches != 0 || res.PendingRemaining != 0 {
		t.Fatalf("idle run must collect and sync nothing, got %#v", res)
	}
	if got := server.ingestRequests(); got != 0 {
		t.Fatalf("an idle run must not upload anything, got %d ingest POSTs", got)
	}
	if got := server.selfRequests(); got != 2 {
		t.Fatalf("expected the grant-sync fetch plus one status preflight, got %d", got)
	}
	if got := server.toolStatusRequests(); got != 1 {
		t.Fatalf("both tools must share one deduplicated tool-status POST, got %d", got)
	}

	reports := server.lastToolStatusReports()
	want := map[string]bool{"Claude Code": false, "Codex": false}
	for _, r := range reports {
		if r.Status != "no_new_records" {
			t.Fatalf("expected no_new_records for %s, got %#v", r.Tool, r)
		}
		if r.Detail != "no new records since last confirmed baseline" {
			t.Fatalf("expected the baseline detail for %s, got %#v", r.Tool, r)
		}
		seen, known := want[r.Tool]
		if !known {
			t.Fatalf("unexpected tool %q in status report", r.Tool)
		}
		if seen {
			t.Fatalf("tool %q reported more than once in the same POST", r.Tool)
		}
		want[r.Tool] = true
	}
	for tool, seen := range want {
		if !seen {
			t.Fatalf("tool %q missing from the status report: %#v", tool, reports)
		}
	}
	if len(reports) != 2 {
		t.Fatalf("expected exactly two statuses[] entries, got %#v", reports)
	}
	if n := server.totalRequests(); n != 3 {
		t.Fatalf("idle scan must only send the grant-sync fetch, the preflight and the status POST, got %d requests", n)
	}
}

// When two grants share one tool and only one of them produced records, the
// synced receipt wins for that tool: the same-run no_new_records status from
// the idle grant must be suppressed so a synced tool is never overwritten
// with "no new records".
func TestRunSyncedToolSuppressesNoNewRecordsFromSameToolGrants(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)

	busySessions := filepath.Join(t.TempDir(), "claude-busy")
	writeClaudeSession(t, busySessions, "session.jsonl",
		claudeLine(t, "2026-10-21T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))
	enableGrant(t, stateDir, "claude-code-jsonl", busySessions)

	idleSessions := filepath.Join(t.TempDir(), "claude-idle")
	if err := os.MkdirAll(idleSessions, 0o700); err != nil {
		t.Fatal(err)
	}
	enableGrant(t, stateDir, "claude-code-jsonl", idleSessions)

	res, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExportedBatches != 1 || res.SyncedBatches != 1 || res.PendingRemaining != 0 {
		t.Fatalf("expected exactly one exported and synced batch, got %#v", res)
	}
	if got := server.ingestRequests(); got != 1 {
		t.Fatalf("expected exactly one ingest upload, got %d", got)
	}
	if got := server.toolStatusRequests(); got != 1 {
		t.Fatalf("only the synced receipt must be reported, got %d tool-status POSTs", got)
	}
	reports := server.lastToolStatusReports()
	want := []toolStatusReport{{Tool: "Claude Code", Status: "synced", Detail: ""}}
	if len(reports) != len(want) {
		t.Fatalf("expected only the synced receipt status, got %#v", reports)
	}
	for i, r := range reports {
		if r != want[i] {
			t.Fatalf("status entry %d must stay the synced receipt without being overwritten, got %#v want %#v", i, r, want[i])
		}
	}
	if n := server.totalRequests(); n != 5 { // grant-sync + drain self + ingest + receipt self + receipt POST
		t.Fatalf("expected exactly the sync traffic with no empty-scan POST, got %d requests", n)
	}
}

// A granted input that exists but cannot be read (permission denied) fails
// the export preparation locally: the run reports the read failure as a skip
// and never touches the network for it.
func TestRunSkipsUnreadableGrantedInputWithoutNetwork(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 000 does not reliably make files unreadable to the current user on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses permission-based unreadable inputs")
	}
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)

	sessions := filepath.Join(t.TempDir(), "sessions")
	input := writeClaudeSession(t, sessions, "s.jsonl",
		claudeLine(t, "2026-10-21T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))
	enableGrant(t, stateDir, "claude-code-jsonl", sessions)
	if err := os.Chmod(input, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(input, 0o600) })

	res, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExportedBatches != 0 || res.SyncedBatches != 0 {
		t.Fatalf("nothing must be collected for an unreadable input: %#v", res)
	}
	if len(res.GrantOutcomes) != 1 || res.GrantOutcomes[0].Skipped == "" {
		t.Fatalf("expected one skipped grant outcome, got %#v", res.GrantOutcomes)
	}
	if !strings.Contains(res.GrantOutcomes[0].Skipped, "export preparation failed") {
		t.Fatalf("expected the unreadable input to fail export preparation, got %#v", res.GrantOutcomes)
	}
	if n := server.totalRequests(); n != 1 {
		t.Fatalf("run with only an unreadable input must only perform the grant-sync self fetch, got %d requests", n)
	}
}

// TestRunLockedRunsUnderCallerHeldLock pins the already-held-lock entry
// point connect uses to bridge its setup lock into the initial
// collection round: a valid handed-over lock runs the identical round
// without acquiring (the caller keeps holding it throughout — an in-round
// probe must observe ErrBusy — and still owns the release afterwards),
// while a foreign or closed handle fails closed before any work.
func TestRunLockedRunsUnderCallerHeldLock(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)
	writePendingBatch(t, stateDir, "batch-runlocked-1")

	lock, err := runlock.Acquire(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	// A foreign live lock and a closed handle both fail closed before
	// any local-state or network work.
	foreign, err := runlock.Acquire(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RunLocked(t.Context(), Options{StateDir: stateDir}, foreign); err == nil {
		t.Fatal("a foreign lock must fail closed")
	}
	_ = foreign.Close()
	if _, err := RunLocked(t.Context(), Options{StateDir: stateDir}, foreign); err == nil {
		t.Fatal("a closed lock must fail closed")
	}
	if n := server.totalRequests(); n != 0 {
		t.Fatalf("a rejected handoff must perform no work, got %d requests", n)
	}

	// The valid handoff runs the round under the caller's lock: the
	// in-round probe (drain stage start) must see the lock as held.
	inRoundBusy := false
	res, err := RunLocked(t.Context(), Options{
		StateDir: stateDir,
		Progress: func(event ProgressEvent) {
			if event.Kind == ProgressStageStart && event.Stage == "drain" {
				if _, aErr := runlock.Acquire(stateDir); errors.Is(aErr, runlock.ErrBusy) {
					inRoundBusy = true
				}
			}
		},
	}, lock)
	if err != nil {
		t.Fatal(err)
	}
	if res.SyncedBatches != 1 || res.PendingRemaining != 0 {
		t.Fatalf("the handed-over round must drain the pending batch, got %+v", res)
	}
	if !inRoundBusy {
		t.Fatal("the caller's lock must still be held inside the round")
	}
	// RunLocked must not release the caller's lock.
	if _, aErr := runlock.Acquire(stateDir); !errors.Is(aErr, runlock.ErrBusy) {
		t.Fatalf("the caller must still hold the lock after RunLocked returns, got %v", aErr)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	fresh, err := runlock.Acquire(stateDir)
	if err != nil {
		t.Fatalf("the released lock must be acquirable again: %v", err)
	}
	_ = fresh.Close()
}
