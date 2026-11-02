package connect

// Sync orchestration tests: the post-authorization flow connect runs
// after its setup (initial collection → exclusive-lock history
// retransmission → backlog drain), its honesty rules, the ownership
// fail-closed checks, the confirmation ordering the resync CLI relies
// on, and the lock-race handling around the just-installed scheduled
// task. Everything is synthetic: tempdir state, httptest mock servers,
// hand-seeded outbox ledgers. No real tool state, no real credentials.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/app/resync"
	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/local/statedir"
)

var syncTestNow = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

// syncToktrailMock fakes the TokTrail server for a full connect + sync
// run: bind, device self, device-batch ingest, tool-status and the
// grant-ack endpoint (whose failures are non-fatal by protocol, so the
// lenient {} answer is fine).
type syncToktrailMock struct {
	*httptest.Server

	mu             sync.Mutex
	bindDeviceID   string
	bindCalls      int
	paused         bool
	withProtocol   bool
	allowedTools   []string
	failIngest     string
	historyDays    int   // server-side consent window; 0 = unrestricted
	revision       int64 // consent revision the self endpoint serves; 0 = 1
	ingestBatchIDs []string
	ingestRecords  int
	ingestKeys     map[string]bool
	selfCalls      int
	// flakeFirstIngest fails the FIRST ingest POST with a retryable 503
	// (allowlisted transient code) so retry-wiring tests can observe a
	// 503→200 resend through the full connect orchestration.
	flakeFirstIngest bool
	// ingestBodies captures the raw body of every ingest POST in order
	// (failed and accepted alike), so retry tests can assert total POST
	// counts and byte-identity.
	ingestBodies [][]byte
	// ingestTotal counts every ingest POST, failed and accepted alike.
	// ingestBatchIDs below keeps its historical meaning: only POSTs the
	// mock accepted.
	ingestTotal int
}

func startSyncToktrailMock(t *testing.T, deviceID string) *syncToktrailMock {
	t.Helper()
	m := &syncToktrailMock{bindDeviceID: deviceID, ingestKeys: map[string]bool{}, revision: 1}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/devices/bind":
			m.mu.Lock()
			m.bindCalls++
			id := m.bindDeviceID
			m.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device": map[string]any{
					"deviceId":          id,
					"applicationId":     "app-sync",
					"externalSubjectId": "sub-sync",
					"deviceName":        "collector",
					"platform":          "test",
					"consentRevision":   1,
					"boundAt":           syncTestNow.Format(time.RFC3339),
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self":
			m.mu.Lock()
			m.selfCalls++
			paused, withProtocol, allowed := m.paused, m.withProtocol, m.allowedTools
			id := m.bindDeviceID
			revision := m.revision
			m.mu.Unlock()
			if revision <= 0 {
				revision = 1
			}
			device := map[string]any{
				"deviceId":         id,
				"consentRevision":  revision,
				"uploadAuthorized": true,
				"revoked":          false,
			}
			if withProtocol {
				v := 1
				device["grantProtocolVersion"] = v
				device["allowedTools"] = allowed
				device["paused"] = paused
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"device": device})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/batches":
			raw, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				t.Errorf("invalid ingest body: %v", readErr)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var batch struct {
				BatchID string           `json:"batchId"`
				Records []map[string]any `json:"records"`
			}
			if err := json.Unmarshal(raw, &batch); err != nil {
				t.Errorf("invalid ingest body: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			m.mu.Lock()
			fail := m.failIngest
			days := m.historyDays
			flake := m.flakeFirstIngest && len(m.ingestBodies) == 0
			m.ingestTotal++
			m.ingestBodies = append(m.ingestBodies, append([]byte(nil), raw...))
			m.mu.Unlock()
			if flake {
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "service_unavailable", "message": "synthetic transient failure"}})
				return
			}
			if fail != "" && batch.BatchID == fail {
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "temporarily_unavailable", "message": "synthetic failure"}})
				return
			}
			// The real server enforces the live consent window and
			// answers 403 outside_scope; the client then quarantines the
			// records recoverably. The mock mirrors that contract so the
			// tests observe true server-side receipts: keys are recorded
			// only for batches the server actually accepted.
			if days > 0 {
				windowFrom := syncTestNow.AddDate(0, 0, -days)
				for _, rec := range batch.Records {
					occurred, _ := rec["occurredAt"].(string)
					at, perr := time.Parse(time.RFC3339, strings.TrimSpace(occurred))
					if perr != nil || at.Before(windowFrom) {
						w.WriteHeader(http.StatusForbidden)
						_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "outside_scope", "message": "record falls before the authorized history window"}})
						return
					}
				}
			}
			m.mu.Lock()
			m.ingestBatchIDs = append(m.ingestBatchIDs, batch.BatchID)
			seen := false
			for _, rec := range batch.Records {
				if key, _ := rec["recordKey"].(string); key != "" {
					if m.ingestKeys[key] {
						seen = true
					}
					m.ingestKeys[key] = true
				}
			}
			m.ingestRecords += len(batch.Records)
			m.mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]any{"batch": map[string]any{
				"batchId":         batch.BatchID,
				"status":          "accepted",
				"acceptedRecords": len(batch.Records),
				"rejectedRecords": 0,
				"replay":          seen,
				"receivedAt":      syncTestNow.Format(time.RFC3339),
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/devices/tool-status":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"accepted": true})
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
	t.Cleanup(m.Close)
	return m
}

func (m *syncToktrailMock) setFailIngest(batchID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failIngest = batchID
}

// setFlakeFirstIngest arms the retryable one-shot 503 on the first ingest
// POST (see flakeFirstIngest).
func (m *syncToktrailMock) setFlakeFirstIngest() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flakeFirstIngest = true
}

// ingestRawBodies returns a copy of the captured raw ingest POST bodies.
func (m *syncToktrailMock) ingestRawBodies() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]byte, len(m.ingestBodies))
	copy(out, m.ingestBodies)
	return out
}

// ingestTotalCount reports every ingest POST the mock saw, failed and
// accepted alike.
func (m *syncToktrailMock) ingestTotalCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ingestTotal
}

// setRevision swaps the consent revision the self endpoint serves,
// modeling a server-side authorization change between runs.
func (m *syncToktrailMock) setRevision(revision int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revision = revision
}

func (m *syncToktrailMock) setHistoryDays(days int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.historyDays = days
}

func (m *syncToktrailMock) ingestCount(batchID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, id := range m.ingestBatchIDs {
		if id == batchID {
			n++
		}
	}
	return n
}

func (m *syncToktrailMock) receivedKey(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ingestKeys[key]
}

func (m *syncToktrailMock) totalIngests() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.ingestBatchIDs)
}

func (m *syncToktrailMock) bindCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bindCalls
}

func (m *syncToktrailMock) selfCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.selfCalls
}

// syncConfigMock serves the connect config endpoint with mutable days.
type syncConfigMock struct {
	*httptest.Server
	mu    sync.Mutex
	days  *int
	tools []string
}

func startSyncConfigMock(t *testing.T, serverURL string, tools []string, days *int) *syncConfigMock {
	t.Helper()
	c := &syncConfigMock{days: days, tools: tools}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		days, tools := c.days, c.tools
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Config{
			SchemaVersion: 1,
			ServerURL:     serverURL,
			ApplicationID: "app-sync",
			SubjectID:     "sub-sync",
			Tools:         tools,
			Days:          days,
			ExpiresAt:     syncTestNow.Add(24 * time.Hour).Format(time.RFC3339),
		})
	}))
	t.Cleanup(c.Close)
	return c
}

func (c *syncConfigMock) setDays(d int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d == 0 {
		c.days = nil
		return
	}
	c.days = &d
}

// syncCodexInput is the local directory connect maps the Codex tool to.
func syncCodexInput(homeDir string) string {
	return filepath.Join(homeDir, ".codex", "sessions")
}

// syncRecord builds one record that passes both the drain's upload gates
// and resync's offline validation (upload whitelist, recordKey,
// occurredAt inside the test's history windows).
func syncRecord(key, occurredAt string) map[string]any {
	return map[string]any{
		"recordKey":      key,
		"kind":           "delta",
		"tool":           "Codex",
		"model":          "gpt-5.4",
		"occurredAt":     occurredAt,
		"input":          "100",
		"output":         "50",
		"cacheRead":      "20",
		"cacheWrite":     "5",
		"adapterVersion": "synthetic",
		"sourceType":     "fixture",
	}
}

// seedBatch writes a batch file and registers it in the outbox with the
// given status, attributed to the codex grant connect will enable.
func seedBatch(t *testing.T, stateDir, homeDir, batchID, status string, records ...map[string]any) {
	t.Helper()
	batchesDir := filepath.Join(stateDir, "batches")
	if err := os.MkdirAll(batchesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(batchesDir, batchID+".json")
	raw, err := json.Marshal(map[string]any{"batchId": batchID, "records": records})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	input := syncCodexInput(homeDir)
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	out.Batches = append(out.Batches, outbox.BatchEntry{
		BatchID:     batchID,
		File:        path,
		Source:      "codex-jsonl",
		Input:       input,
		Status:      status,
		RecordCount: len(records),
		CreatedAt:   syncTestNow.Add(-time.Duration(len(out.Batches)+1) * time.Minute),
	})
	if err := outbox.New(stateDir).Save(out); err != nil {
		t.Fatal(err)
	}
}

// seedBoundState writes a bound device state matching the connect
// authorization the mocks serve, so connect rebinds (or skips) without
// tripping the identity checks.
func seedBoundState(t *testing.T, stateDir, serverURL, deviceID string) {
	t.Helper()
	if err := statedir.New(stateDir).Save(statedir.DeviceState{
		DeviceID:          deviceID,
		DeviceSecret:      strings.Repeat("a", 64),
		ServerURL:         serverURL,
		ApplicationID:     "app-sync",
		ExternalSubjectID: "sub-sync",
		ConsentRevision:   1,
		UploadAuthorized:  true,
	}); err != nil {
		t.Fatal(err)
	}
}

// seedCodexGrant enables the grant connect would have enabled, for tests
// that drive Sync directly on a hand-seeded state.
func seedCodexGrant(t *testing.T, stateDir, homeDir string) {
	t.Helper()
	input := syncCodexInput(homeDir)
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := grants.New(stateDir).Enable("codex-jsonl", input); err != nil {
		t.Fatal(err)
	}
}

// runSyncConnect executes one full connect.Run against the mocks.
func runSyncConnect(t *testing.T, cfg *syncConfigMock, stateDir, homeDir, ticket string) (Result, error) {
	t.Helper()
	return runSyncConnectWithOptions(t, cfg, stateDir, homeDir, ticket, Options{})
}

// runCursorConnectWithOptionsOut is runSyncConnectWithOptions with the
// run's output captured into the caller's writer for assertions.
func runCursorConnectWithOptionsOut(t *testing.T, cfg *syncConfigMock, stateDir, homeDir, ticket string, extra Options, out io.Writer) (Result, error) {
	t.Helper()
	opt := Options{
		URL:             fmt.Sprintf("%s/api/collector/connect#%s", cfg.URL, ticket),
		StateDir:        stateDir,
		HomeDir:         homeDir,
		BinaryPath:      fakeCollectorBinary(t),
		HTTPClient:      cfg.Client(),
		SchedulerRunner: &mockRunner{},
		Now:             func() time.Time { return syncTestNow },
		Out:             out,
	}
	if extra.MaxTotalBatches != 0 {
		opt.MaxTotalBatches = extra.MaxTotalBatches
	}
	if extra.Cursor != nil {
		opt.Cursor = extra.Cursor
	}
	if extra.CursorConfirm != nil {
		opt.CursorConfirm = extra.CursorConfirm
	}
	return Run(context.Background(), opt)
}

func runSyncConnectWithOptions(t *testing.T, cfg *syncConfigMock, stateDir, homeDir, ticket string, extra Options) (Result, error) {
	t.Helper()
	res, err, _ := runSyncConnectWithOutput(t, cfg, stateDir, homeDir, ticket, extra)
	return res, err
}

// runSyncConnectWithOutput is runSyncConnectWithOptions's twin that
// also returns the captured human output (the display-layer regression
// tests read it).
func runSyncConnectWithOutput(t *testing.T, cfg *syncConfigMock, stateDir, homeDir, ticket string, extra Options) (Result, error, string) {
	t.Helper()
	out := &strings.Builder{}
	opt := Options{
		URL:             fmt.Sprintf("%s/api/collector/connect#%s", cfg.URL, ticket),
		StateDir:        stateDir,
		HomeDir:         homeDir,
		BinaryPath:      fakeCollectorBinary(t),
		HTTPClient:      cfg.Client(),
		SchedulerRunner: &mockRunner{},
		Now:             func() time.Time { return syncTestNow },
		Out:             out,
	}
	if extra.MaxTotalBatches != 0 {
		opt.MaxTotalBatches = extra.MaxTotalBatches
	}
	if extra.Cursor != nil {
		opt.Cursor = extra.Cursor
	}
	if extra.CursorConfirm != nil {
		opt.CursorConfirm = extra.CursorConfirm
	}
	if extra.Retry != nil {
		opt.Retry = extra.Retry
	}
	if extra.Verbose {
		opt.Verbose = true
	}
	if extra.DryRun {
		opt.DryRun = true
	}
	if extra.SchedulerRunner != nil {
		opt.SchedulerRunner = extra.SchedulerRunner
	}
	res, err := Run(context.Background(), opt)
	return res, err, out.String()
}

func journalExists(stateDir string) bool {
	_, err := os.Stat(filepath.Join(stateDir, "resync-journal.json"))
	return err == nil
}

// journalBatchIDs reads the resync job journal's planned batch ids. The
// connect package cannot use resync's private journal types, so the file
// is parsed as plain JSON.
func journalBatchIDs(t *testing.T, stateDir string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(stateDir, "resync-journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	var jb struct {
		Batches []struct {
			BatchID string `json:"batchId"`
		} `json:"batches"`
	}
	if err := json.Unmarshal(raw, &jb); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(jb.Batches))
	for _, b := range jb.Batches {
		ids = append(ids, b.BatchID)
	}
	return ids
}

func pendingCount(t *testing.T, stateDir string) int {
	t.Helper()
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, b := range out.Batches {
		if b.Status == outbox.StatusPending {
			n++
		}
	}
	return n
}

// TestSyncFirstInstallDoesNotReplayFreshBatches verifies the first-install
// path under the connect snapshot: pending batches drain through the
// initial collection, and because the snapshot captured under the setup
// lock was empty (nothing was synced before this connect), the
// retransmission phase replays NOTHING — the batches this run just
// uploaded are not immediately re-sent. The pass still completes (an
// empty restricted job), leaving a journal, with no incompleteness.
func TestSyncFirstInstallDoesNotReplayFreshBatches(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startSyncToktrailMock(t, "dev-first-1")
	cfg := startSyncConfigMock(t, mock.URL, []string{"Codex"}, intPtr(30))

	seedBatch(t, stateDir, homeDir, "first-pending-1", outbox.StatusPending,
		syncRecord("first-key-1", syncTestNow.Add(-time.Hour).Format(time.RFC3339)))
	seedBatch(t, stateDir, homeDir, "first-pending-2", outbox.StatusPending,
		syncRecord("first-key-2", syncTestNow.Add(-2*time.Hour).Format(time.RFC3339)))
	seedBatch(t, stateDir, homeDir, "first-pending-3", outbox.StatusPending,
		syncRecord("first-key-3", syncTestNow.Add(-3*time.Hour).Format(time.RFC3339)))

	res, err := runSyncConnect(t, cfg, stateDir, homeDir, strings.Repeat("1", 64))
	if err != nil {
		t.Fatalf("first-install connect failed: %v", err)
	}
	if len(res.Sync.Incomplete) != 0 {
		t.Fatalf("first install must be complete, got incompleteness: %v", res.Sync.Incomplete)
	}
	if !res.Sync.Resync.Completed || res.Sync.Resync.Uploads != 0 || res.Sync.Resync.ReplayReceipts != 0 {
		t.Fatalf("a first install must not replay the freshly synced batches, got %+v", res.Sync.Resync)
	}
	if res.Sync.Resync.ExcludedAfterSnapshot != 3 {
		t.Fatalf("the 3 batches synced during this run must be reported as excluded by the snapshot, got %+v", res.Sync.Resync)
	}
	if res.Sync.Backlog.Passes != 0 || res.Sync.Backlog.PendingRemaining != 0 {
		t.Fatalf("3 pending batches drain within the initial bound, got %+v", res.Sync.Backlog)
	}
	if !journalExists(stateDir) {
		t.Fatalf("the completed empty resync job must leave a journal")
	}
	if ids := journalBatchIDs(t, stateDir); len(ids) != 0 {
		t.Fatalf("the restricted first-install job must plan no batch, got %v", ids)
	}
	for _, id := range []string{"first-pending-1", "first-pending-2", "first-pending-3"} {
		if got := mock.ingestCount(id); got != 1 {
			t.Fatalf("batch %s must be uploaded exactly once by the drain and never replayed, got %d posts", id, got)
		}
	}
}

// TestSyncReconnectRetransmitsPriorHistory verifies the reconnect path:
// already-synced history (from before this connect) is retransmitted to
// the currently bound server under the exclusive lock, the ownership
// guard is recorded, and the run completes with no incompleteness.
func TestSyncReconnectRetransmitsPriorHistory(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startSyncToktrailMock(t, "dev-rc-1")
	cfg := startSyncConfigMock(t, mock.URL, []string{"Codex"}, intPtr(30))

	seedBoundState(t, stateDir, mock.URL, "dev-rc-1")
	seedBatch(t, stateDir, homeDir, "rc-synced-1", outbox.StatusSynced,
		syncRecord("rc-key-1", syncTestNow.Add(-time.Hour).Format(time.RFC3339)),
		syncRecord("rc-key-2", syncTestNow.Add(-90*time.Minute).Format(time.RFC3339)))
	seedBatch(t, stateDir, homeDir, "rc-synced-2", outbox.StatusSynced,
		syncRecord("rc-key-3", syncTestNow.Add(-2*time.Hour).Format(time.RFC3339)))

	res, err := runSyncConnect(t, cfg, stateDir, homeDir, strings.Repeat("2", 64))
	if err != nil {
		t.Fatalf("reconnect connect failed: %v", err)
	}
	if len(res.Sync.Incomplete) != 0 {
		t.Fatalf("reconnect must be complete, got incompleteness: %v", res.Sync.Incomplete)
	}
	if !res.Sync.Resync.Completed || res.Sync.Resync.Uploads != 2 || res.Sync.Resync.UploadedRecords != 3 {
		t.Fatalf("retransmission must cover the 2 prior batches (3 records), got %+v", res.Sync.Resync)
	}
	if res.Sync.Resync.Remaining != 0 || res.Sync.Resync.Blocked != 0 {
		t.Fatalf("nothing may remain or be withheld on a clean reconnect, got %+v", res.Sync.Resync)
	}
	for _, key := range []string{"rc-key-1", "rc-key-2", "rc-key-3"} {
		if !mock.receivedKey(key) {
			t.Fatalf("the server must have received retransmitted record %s", key)
		}
	}
	own, has, err := loadOwnership(stateDir)
	if err != nil || !has || own.DeviceID != "dev-rc-1" {
		t.Fatalf("the ownership guard must record the bound device, got (%+v, %v, %v)", own, has, err)
	}
}

// TestSyncRetransmissionFailureReportedHonestlyAndResumes verifies the
// honesty and resume rules: a failed retransmission upload fails the
// whole run with a clear error while the scheduled service stays
// installed and the initial collection outcome is still reported, and
// re-running the same connect link resumes the frozen job to completion.
func TestSyncRetransmissionFailureReportedHonestlyAndResumes(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startSyncToktrailMock(t, "dev-rf-1")
	cfg := startSyncConfigMock(t, mock.URL, []string{"Codex"}, intPtr(30))

	seedBoundState(t, stateDir, mock.URL, "dev-rf-1")
	seedBatch(t, stateDir, homeDir, "rf-synced-1", outbox.StatusSynced,
		syncRecord("rf-key-1", syncTestNow.Add(-time.Hour).Format(time.RFC3339)))
	seedBatch(t, stateDir, homeDir, "rf-synced-2", outbox.StatusSynced,
		syncRecord("rf-key-2", syncTestNow.Add(-2*time.Hour).Format(time.RFC3339)))

	mock.setFailIngest("rf-synced-1")
	ticket := strings.Repeat("3", 64)
	res, err := runSyncConnect(t, cfg, stateDir, homeDir, ticket)
	if err == nil || !strings.Contains(err.Error(), "history retransmission failed") {
		t.Fatalf("a failed retransmission must fail the run honestly, got: %v", err)
	}
	// resync's error path stops before populating Remaining; the stopped
	// job is reported through Completed=false + Stopped.
	if res.Sync.Resync.Completed || res.Sync.Resync.Stopped == "" || res.Sync.Resync.Err == "" {
		t.Fatalf("the failure must report the unfinished job, got %+v", res.Sync.Resync)
	}
	if !strings.Contains(res.Sync.Resync.Stopped, "upload failed") {
		t.Fatalf("the stop reason must name the failed upload, got %+v", res.Sync.Resync)
	}
	if !journalExists(stateDir) {
		t.Fatalf("the incomplete job must stay resumable via its journal")
	}
	if res.PeriodicResult.Grants != 1 {
		t.Fatalf("the initial collection outcome must still be reported, got %+v", res.PeriodicResult)
	}

	// Re-running the same link (same receipt) resumes the job; the
	// previously failed batch is retried and the job completes.
	mock.setFailIngest("")
	res2, err := runSyncConnect(t, cfg, stateDir, homeDir, ticket)
	if err != nil {
		t.Fatalf("the resume run must complete: %v", err)
	}
	if !res2.Sync.Resync.Resumed || !res2.Sync.Resync.Completed {
		t.Fatalf("the second run must resume and complete the job, got %+v", res2.Sync.Resync)
	}
	if len(res2.Sync.Incomplete) != 0 {
		t.Fatalf("the resumed run must be complete, got %v", res2.Sync.Incomplete)
	}
	if !mock.receivedKey("rf-key-1") || !mock.receivedKey("rf-key-2") {
		t.Fatalf("both records must have reached the server after the resume")
	}
}

// TestSyncDrainsBacklogBeyondInitialBound verifies that a reconnect
// backlog larger than one bounded drain is fully drained by extra
// passes (the 5-batch bound is never presented as success). The
// retransmission stays empty: every batch was pending when connect
// captured its snapshot, so each is uploaded once by the drain itself
// and never re-sent.
func TestSyncDrainsBacklogBeyondInitialBound(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startSyncToktrailMock(t, "dev-bl-1")
	cfg := startSyncConfigMock(t, mock.URL, []string{"Codex"}, intPtr(30))

	for i := 1; i <= 7; i++ {
		id := fmt.Sprintf("bl-pending-%d", i)
		seedBatch(t, stateDir, homeDir, id, outbox.StatusPending,
			syncRecord(fmt.Sprintf("bl-key-%d", i), syncTestNow.Add(-time.Duration(i)*time.Hour).Format(time.RFC3339)))
	}

	res, err := runSyncConnect(t, cfg, stateDir, homeDir, strings.Repeat("4", 64))
	if err != nil {
		t.Fatalf("backlog drain failed: %v", err)
	}
	if res.Sync.Collection.PendingRemaining != 2 {
		t.Fatalf("the initial bound leaves 2 of 7 pending, got %d", res.Sync.Collection.PendingRemaining)
	}
	if res.Sync.Backlog.Passes != 1 || res.Sync.Backlog.PendingRemaining != 0 {
		t.Fatalf("one backlog pass must drain the remainder, got %+v", res.Sync.Backlog)
	}
	if len(res.Sync.Incomplete) != 0 {
		t.Fatalf("a fully drained backlog is complete, got %v", res.Sync.Incomplete)
	}
	if res.Sync.Backlog.Result.ExportedBatches != 0 || len(res.Sync.Backlog.Result.GrantOutcomes) != 0 {
		t.Fatalf("device-only backlog must not rescan sources: %+v", res.Sync.Backlog.Result)
	}
	if pendingCount(t, stateDir) != 0 {
		t.Fatalf("the outbox must be fully drained, got %d pending", pendingCount(t, stateDir))
	}
	// 7 drain uploads; the history phase (which runs after the backlog
	// drain) replays nothing because the connect snapshot (captured
	// before the collection) covered no synced batch — the initial pass
	// synced 5 and the backlog pass 2, and by plan time all 7 exist as
	// synced batches that postdate the snapshot.
	if got := mock.totalIngests(); got != 7 {
		t.Fatalf("expected 7 drain uploads and no replay, got %d", got)
	}
	if res.Sync.Resync.Uploads != 0 || res.Sync.Resync.ExcludedAfterSnapshot != 7 {
		t.Fatalf("the plan must report all 7 batches the drain synced as after-snapshot exclusions, got %+v", res.Sync.Resync)
	}
	if res.Sync.Resync.ExcludedPending != 0 {
		t.Fatalf("the backlog drain empties the outbox before the history phase plans, got %+v", res.Sync.Resync)
	}
}

// TestSyncMaxTotalBatchesBoundsInitialAndBacklogUploads verifies the
// shared-budget semantics of --max-total-batches: the cap counts every
// real ingest POST of the run (device, account and history queues), the
// run stops honestly at the cap, and nothing is presented as success.
func TestSyncMaxTotalBatchesBoundsInitialAndBacklogUploads(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startSyncToktrailMock(t, "dev-budget-1")
	cfg := startSyncConfigMock(t, mock.URL, []string{"Codex"}, intPtr(30))

	for i := 1; i <= 7; i++ {
		id := fmt.Sprintf("budget-pending-%d", i)
		seedBatch(t, stateDir, homeDir, id, outbox.StatusPending,
			syncRecord(fmt.Sprintf("budget-key-%d", i), syncTestNow.Add(-time.Duration(i)*time.Hour).Format(time.RFC3339)))
	}

	res, err := runSyncConnectWithOptions(t, cfg, stateDir, homeDir, strings.Repeat("5", 64), Options{MaxTotalBatches: 6})
	if err == nil || !errors.Is(err, ErrSyncIncomplete) {
		t.Fatalf("expected incomplete sync after budget bound, got res=%+v err=%v", res.Sync, err)
	}
	if res.Sync.Collection.SyncedBatches != 5 {
		t.Fatalf("initial collection should use the first 5 budget slots, got %+v", res.Sync.Collection)
	}
	if res.Sync.Backlog.Passes != 1 || res.Sync.Backlog.Result.SyncedBatches != 1 || res.Sync.Backlog.PendingRemaining != 1 {
		t.Fatalf("backlog should drain exactly one remaining budget slot, got %+v", res.Sync.Backlog)
	}
	if !strings.Contains(res.Sync.Backlog.Stopped, backlogBudgetStopped) || !res.Sync.BudgetExhausted {
		t.Fatalf("expected the shared budget stop reason and flag, got %+v", res.Sync.Backlog)
	}
	if pending := pendingCount(t, stateDir); pending != 1 {
		t.Fatalf("expected one pending batch after budget bound, got %d", pending)
	}
	// Six fresh drain uploads only: the shared budget caps every queue's
	// real POSTs, and the history retransmission has nothing to replay —
	// the snapshot captured no synced batch before this run's collection
	// started (it still runs and completes as an empty restricted pass).
	if got := mock.totalIngests(); got != 6 {
		t.Fatalf("expected 6 drain uploads and no replay, got %d", got)
	}
	if res.Sync.Resync.Uploads != 0 || !res.Sync.Resync.Completed {
		t.Fatalf("the empty-snapshot retransmission must still complete, got %+v", res.Sync.Resync)
	}
	if !containsReason(res.Sync.Incomplete, "shared sync POST budget") {
		t.Fatalf("the budget stop must be named as an incompleteness, got %v", res.Sync.Incomplete)
	}
}

func TestSyncPausedDeviceIsIncompleteNotSuccess(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startSyncToktrailMock(t, "dev-paused-1")
	mock.mu.Lock()
	mock.paused = true
	mock.withProtocol = true
	mock.allowedTools = []string{"Codex"}
	mock.mu.Unlock()
	cfg := startSyncConfigMock(t, mock.URL, []string{"Codex"}, intPtr(30))

	seedBoundState(t, stateDir, mock.URL, "dev-paused-1")
	seedBatch(t, stateDir, homeDir, "paused-pending-1", outbox.StatusPending,
		syncRecord("paused-key-1", syncTestNow.Add(-time.Hour).Format(time.RFC3339)))

	res, err := runSyncConnect(t, cfg, stateDir, homeDir, strings.Repeat("5", 64))
	if !errors.Is(err, ErrSyncIncomplete) {
		t.Fatalf("a paused device must not look like success, got: %v", err)
	}
	if !strings.Contains(err.Error(), "paused") {
		t.Fatalf("the incompleteness must name the pause, got: %v", err)
	}
	if res.Sync.Resync.Skipped == "" {
		t.Fatalf("the retransmission phase must record why it declined, got %+v", res.Sync.Resync)
	}
	if res.Sync.Resync.Ran {
		t.Fatalf("a paused device must not retransmit, got %+v", res.Sync.Resync)
	}
	if pendingCount(t, stateDir) != 1 {
		t.Fatalf("the pending batch must stay queued for the next run, got %d", pendingCount(t, stateDir))
	}
}

// TestSyncRestrictedSourceIsIncomplete verifies the collection failure
// outcomes connect must not swallow: a grant the server's live scope
// disallows is reported through GrantOutcomes.Skipped, and connect turns
// that into an explicit incompleteness (while the empty-ledger
// retransmission completes normally — no synced batches exist).
func TestSyncRestrictedSourceIsIncomplete(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startSyncToktrailMock(t, "dev-restricted-1")
	mock.mu.Lock()
	mock.withProtocol = true
	mock.allowedTools = []string{"Cursor"}
	mock.mu.Unlock()
	cfg := startSyncConfigMock(t, mock.URL, []string{"Codex"}, intPtr(30))
	if err := os.MkdirAll(syncCodexInput(homeDir), 0o700); err != nil {
		t.Fatal(err)
	}

	res, err := runSyncConnect(t, cfg, stateDir, homeDir, strings.Repeat("6", 64))
	if !errors.Is(err, ErrSyncIncomplete) {
		t.Fatalf("a restricted authorized source must not look like success, got: %v", err)
	}
	if !strings.Contains(err.Error(), "codex-jsonl") || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("the incompleteness must name the restricted source and reason, got: %v", err)
	}
	if len(res.Sync.Collection.GrantOutcomes) != 1 || res.Sync.Collection.GrantOutcomes[0].Skipped == "" {
		t.Fatalf("the grant outcome must carry the restriction, got %+v", res.Sync.Collection.GrantOutcomes)
	}
	if !res.Sync.Resync.Completed {
		t.Fatalf("the empty-ledger retransmission completes (nothing to retransmit), got %+v", res.Sync.Resync)
	}
}

// TestSyncHistoryWindowFollowsAuthorizationEndToEnd verifies across TWO
// real connect runs that the history window the current authorization
// pins governs what the server actually receives: narrowing 30→7 stops
// older records from being uploaded, and 7→30 lets them through again.
//
// Not covered here (deliberately): recovery of records already
// quarantined by a narrower window when the window later widens —
// quarantine recovery lives in collection/syncclient (a separate
// in-flight change) and requires a strictly newer consent revision.
func TestSyncHistoryWindowFollowsAuthorizationEndToEnd(t *testing.T) {
	// A 20-day-old record: outside the 7-day window, inside the 30-day
	// one. A 3-hour-old record sits inside both.
	outsideNarrow := syncTestNow.Add(-20 * 24 * time.Hour).Format(time.RFC3339)
	insideBoth := syncTestNow.Add(-3 * time.Hour).Format(time.RFC3339)

	t.Run("narrows_30_to_7", func(t *testing.T) {
		stateDir := t.TempDir()
		homeDir := t.TempDir()
		mock := startSyncToktrailMock(t, "dev-cut-1")
		mock.setHistoryDays(30)
		cfg := startSyncConfigMock(t, mock.URL, []string{"Codex"}, intPtr(30))

		// First connect under a 30-day window: the 20-day-old record is
		// inside and the server receives it.
		seedBatch(t, stateDir, homeDir, "cut-30-in", outbox.StatusPending, syncRecord("cut-key-30", outsideNarrow))
		if _, err := runSyncConnect(t, cfg, stateDir, homeDir, strings.Repeat("7", 64)); err != nil {
			t.Fatalf("30-day connect failed: %v", err)
		}
		if !mock.receivedKey("cut-key-30") {
			t.Fatalf("the server must receive the in-window record under the 30-day authorization")
		}

		// Second connect under a 7-day window (new receipt → rebind): an
		// equally old record now falls before the cutoff. The server
		// enforces the live window (403 outside_scope → recoverable
		// quarantine), so nothing reaches it. A user narrowing the
		// collection window is a normal success, not an incompleteness;
		// the withheld history is reported through the resync summary
		// instead.
		mock.setHistoryDays(7)
		cfg.setDays(7)
		seedBatch(t, stateDir, homeDir, "cut-7-out", outbox.StatusPending, syncRecord("cut-key-7", outsideNarrow))
		res, err := runSyncConnect(t, cfg, stateDir, homeDir, strings.Repeat("8", 64))
		if err != nil {
			t.Fatalf("a narrowed window is a normal successful connect, got: %v", err)
		}
		if mock.receivedKey("cut-key-7") {
			t.Fatalf("the server must NOT receive the out-of-window record under the 7-day authorization")
		}
		st, lerr := statedir.New(stateDir).Load()
		if lerr != nil {
			t.Fatal(lerr)
		}
		want := syncTestNow.AddDate(0, 0, -7)
		if st.HistoryFrom == nil || !st.HistoryFrom.Equal(want) {
			t.Fatalf("the narrowed window must be pinned, got %v", st.HistoryFrom)
		}
		if res.Sync.Resync.Blocked == 0 && res.Sync.Resync.SkippedOutOfScopeRecords == 0 {
			t.Fatalf("the withheld history must be visible in the resync summary, got %+v", res.Sync.Resync)
		}
		if len(res.Sync.Incomplete) != 0 {
			t.Fatalf("scope-excluded history must not be judged incomplete, got %v", res.Sync.Incomplete)
		}
	})

	t.Run("widens_7_to_30", func(t *testing.T) {
		stateDir := t.TempDir()
		homeDir := t.TempDir()
		mock := startSyncToktrailMock(t, "dev-cut-2")
		mock.setHistoryDays(7)
		cfg := startSyncConfigMock(t, mock.URL, []string{"Codex"}, intPtr(7))

		// First connect under a 7-day window: only the recent record is
		// uploaded.
		seedBatch(t, stateDir, homeDir, "cut-7-in", outbox.StatusPending, syncRecord("cut-key-near", insideBoth))
		if _, err := runSyncConnect(t, cfg, stateDir, homeDir, strings.Repeat("9", 64)); err != nil {
			t.Fatalf("7-day connect failed: %v", err)
		}
		if !mock.receivedKey("cut-key-near") {
			t.Fatalf("the server must receive the in-window record under the 7-day authorization")
		}

		// Second connect under a 30-day window: a 20-day-old record —
		// which the 7-day window excluded — is uploaded.
		mock.setHistoryDays(30)
		cfg.setDays(30)
		seedBatch(t, stateDir, homeDir, "cut-30-late", outbox.StatusPending, syncRecord("cut-key-late", outsideNarrow))
		if _, err := runSyncConnect(t, cfg, stateDir, homeDir, strings.Repeat("a", 64)); err != nil {
			t.Fatalf("30-day connect failed: %v", err)
		}
		if !mock.receivedKey("cut-key-late") {
			t.Fatalf("the server must receive the older record once the authorization widens to 30 days")
		}
		st, lerr := statedir.New(stateDir).Load()
		if lerr != nil {
			t.Fatal(lerr)
		}
		want := syncTestNow.AddDate(0, 0, -30)
		if st.HistoryFrom == nil || !st.HistoryFrom.Equal(want) {
			t.Fatalf("the widened window must be pinned, got %v", st.HistoryFrom)
		}
	})
}

// TestConnectFailsClosedOnIdentityMismatch verifies that a state
// directory already bound to a different server/application/subject is
// never re-pointed: the run fails closed before any bind, telling the
// user to use a separate state directory.
func TestConnectFailsClosedOnIdentityMismatch(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startSyncToktrailMock(t, "dev-id-1")
	cfg := startSyncConfigMock(t, mock.URL, []string{"Codex"}, intPtr(30))

	// Bound to a different server (and subject) with synced history.
	seedBoundState(t, stateDir, "http://127.0.0.1:1", "dev-other-1")
	statedir.New(stateDir).Save(statedir.DeviceState{
		DeviceID:          "dev-other-1",
		DeviceSecret:      strings.Repeat("a", 64),
		ServerURL:         "http://127.0.0.1:1",
		ApplicationID:     "app-other",
		ExternalSubjectID: "sub-other",
		ConsentRevision:   1,
	})
	seedBatch(t, stateDir, homeDir, "id-synced-1", outbox.StatusSynced,
		syncRecord("id-key-1", syncTestNow.Add(-time.Hour).Format(time.RFC3339)))

	_, err := runSyncConnect(t, cfg, stateDir, homeDir, strings.Repeat("b", 64))
	if err == nil || !strings.Contains(err.Error(), "already bound to a different authorization") {
		t.Fatalf("an identity mismatch must fail closed, got: %v", err)
	}
	if !strings.Contains(err.Error(), "separate --state-dir") {
		t.Fatalf("the error must tell the user to use a separate state directory, got: %v", err)
	}
	if mock.bindCount() != 0 {
		t.Fatalf("no bind may happen on a mismatch, got %d calls", mock.bindCount())
	}
	if mock.totalIngests() != 0 {
		t.Fatalf("nothing may be uploaded on a mismatch, got %d posts", mock.totalIngests())
	}
}

// TestConnectFailsClosedOnDeviceChangeRebind verifies that a rebind
// which changes the device identity over existing synced history fails
// closed (nothing is retransmitted, avoiding double counting), and that
// the ownership guard keeps the refusal durable across retries of the
// same link.
func TestConnectFailsClosedOnDeviceChangeRebind(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startSyncToktrailMock(t, "dev-new-1") // the rebind returns a DIFFERENT device
	cfg := startSyncConfigMock(t, mock.URL, []string{"Codex"}, intPtr(30))

	seedBoundState(t, stateDir, mock.URL, "dev-old-1")
	seedBatch(t, stateDir, homeDir, "dc-synced-1", outbox.StatusSynced,
		syncRecord("dc-key-1", syncTestNow.Add(-time.Hour).Format(time.RFC3339)))

	ticket := strings.Repeat("c", 64)
	_, err := runSyncConnect(t, cfg, stateDir, homeDir, ticket)
	if err == nil || !strings.Contains(err.Error(), "changed the device identity") {
		t.Fatalf("a device-changing rebind over history must fail closed, got: %v", err)
	}
	if !strings.Contains(err.Error(), "double count") {
		t.Fatalf("the error must explain the double-counting risk, got: %v", err)
	}
	if mock.totalIngests() != 0 {
		t.Fatalf("nothing may be retransmitted on a device change, got %d posts", mock.totalIngests())
	}
	own, has, lerr := loadOwnership(stateDir)
	if lerr != nil || !has || own.DeviceID != "dev-old-1" {
		t.Fatalf("the guard must pin the old device, got (%+v, %v, %v)", own, has, lerr)
	}

	// Retrying the same link must stay refused: the state is now bound
	// as the new device while the history belongs to the old one.
	_, err = runSyncConnect(t, cfg, stateDir, homeDir, ticket)
	if err == nil || !strings.Contains(err.Error(), "belongs to device dev-old-1") {
		t.Fatalf("the retry must be blocked by the ownership guard, got: %v", err)
	}
	if mock.totalIngests() != 0 {
		t.Fatalf("the retry must not retransmit anything, got %d posts", mock.totalIngests())
	}
}

// TestConnectFailsClosedOnUnboundSyncedHistory verifies that a state
// directory holding synced history but no bound device cannot be bound
// over: the history's owner cannot be attributed, so connect refuses.
func TestConnectFailsClosedOnUnboundSyncedHistory(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startSyncToktrailMock(t, "dev-fresh-1")
	cfg := startSyncConfigMock(t, mock.URL, []string{"Codex"}, intPtr(30))

	seedBatch(t, stateDir, homeDir, "ub-synced-1", outbox.StatusSynced,
		syncRecord("ub-key-1", syncTestNow.Add(-time.Hour).Format(time.RFC3339)))

	_, err := runSyncConnect(t, cfg, stateDir, homeDir, strings.Repeat("d", 64))
	if err == nil || !strings.Contains(err.Error(), "no bound device") {
		t.Fatalf("unbound synced history must fail closed, got: %v", err)
	}
	if mock.bindCount() != 0 {
		t.Fatalf("no bind may run over unattributable history, got %d calls", mock.bindCount())
	}
}

// TestSyncConfirmRunsBeforeAnyCollectionOrUpload pins the CLI
// confirmation ordering: when a caller provides ResyncConfirm, Sync
// invokes it with a read-only plan BEFORE any collection round or upload
// happens (no self fetch, no ingest, no state mutation), and an abort
// leaves the state directory untouched.
func TestSyncConfirmRunsBeforeAnyCollectionOrUpload(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startSyncToktrailMock(t, "dev-confirm-1")

	seedBoundState(t, stateDir, mock.URL, "dev-confirm-1")
	seedCodexGrant(t, stateDir, homeDir)
	seedBatch(t, stateDir, homeDir, "cf-synced-1", outbox.StatusSynced,
		syncRecord("cf-key-1", syncTestNow.Add(-time.Hour).Format(time.RFC3339)))
	seedBatch(t, stateDir, homeDir, "cf-pending-1", outbox.StatusPending,
		syncRecord("cf-key-2", syncTestNow.Add(-2*time.Hour).Format(time.RFC3339)))

	out := &strings.Builder{}

	confirmCalls := 0
	_, err := Sync(context.Background(), SyncOptions{
		StateDir:   stateDir,
		ServerURL:  mock.URL,
		HTTPClient: mock.Client(),
		Now:        func() time.Time { return syncTestNow },
		Out:        out,
		ResyncConfirm: func(plan resync.Plan) error {
			confirmCalls++
			if mock.selfCount() != 0 || mock.totalIngests() != 0 {
				return fmt.Errorf("confirmation must precede any collection or upload (self=%d ingests=%d)", mock.selfCount(), mock.totalIngests())
			}
			if len(plan.Batches) != 1 || plan.Batches[0].BatchID != "cf-synced-1" {
				return fmt.Errorf("the pre-run plan must list the already-synced archive, got %+v", plan.Batches)
			}
			return errors.New("declined by test")
		},
	})
	if err == nil || !strings.Contains(err.Error(), "aborted before any collection or upload") {
		t.Fatalf("a declined confirmation must abort before any work, got: %v", err)
	}
	if confirmCalls != 1 {
		t.Fatalf("the confirmation hook must run exactly once, got %d", confirmCalls)
	}
	if mock.selfCount() != 0 || mock.totalIngests() != 0 {
		t.Fatalf("the abort must leave the server untouched (self=%d ingests=%d)", mock.selfCount(), mock.totalIngests())
	}
	if pendingCount(t, stateDir) != 1 || journalExists(stateDir) {
		t.Fatalf("the abort must leave the state directory untouched")
	}
	if _, err := os.Stat(filepath.Join(stateDir, ".collector.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the abort must not even create the lock file, got %v", err)
	}

	// With the confirmation granted, the same call runs the full flow.
	out.Reset()
	res, err := Sync(context.Background(), SyncOptions{
		StateDir:   stateDir,
		ServerURL:  mock.URL,
		HTTPClient: mock.Client(),
		Now:        func() time.Time { return syncTestNow },
		Out:        out,
		ResyncConfirm: func(plan resync.Plan) error {
			confirmCalls++
			return nil
		},
	})
	if err != nil {
		t.Fatalf("the confirmed run must complete: %v", err)
	}
	if !res.Resync.Completed || !mock.receivedKey("cf-key-1") {
		t.Fatalf("the confirmed run must retransmit the history, got %+v", res.Resync)
	}
	if pendingCount(t, stateDir) != 0 || !mock.receivedKey("cf-key-2") {
		t.Fatalf("the confirmed run must also drain the pending backlog")
	}
	if confirmCalls != 2 {
		t.Fatalf("expected one hook call per Sync run, got %d", confirmCalls)
	}
}

// TestSyncDryRunIsOfflinePlanOnly verifies the dry-run limitations: no
// collection phase, no state lock, no journal write, no network.
func TestSyncDryRunIsOfflinePlanOnly(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startSyncToktrailMock(t, "dev-dry-1")

	seedBoundState(t, stateDir, mock.URL, "dev-dry-1")
	seedCodexGrant(t, stateDir, homeDir)
	seedBatch(t, stateDir, homeDir, "dry-synced-1", outbox.StatusSynced,
		syncRecord("dry-key-1", syncTestNow.Add(-time.Hour).Format(time.RFC3339)))
	seedBatch(t, stateDir, homeDir, "dry-pending-1", outbox.StatusPending,
		syncRecord("dry-key-2", syncTestNow.Add(-2*time.Hour).Format(time.RFC3339)))

	res, err := Sync(context.Background(), SyncOptions{
		StateDir:     stateDir,
		ServerURL:    mock.URL,
		HTTPClient:   mock.Client(),
		Now:          func() time.Time { return syncTestNow },
		ResyncDryRun: true,
	})
	if err != nil {
		t.Fatalf("dry run failed: %v", err)
	}
	if !res.Resync.DryRun || !res.Resync.Ran || res.Resync.Completed {
		t.Fatalf("the dry run must report a plan only, got %+v", res.Resync)
	}
	if mock.selfCount() != 0 || mock.totalIngests() != 0 {
		t.Fatalf("a dry run must perform no network access (self=%d ingests=%d)", mock.selfCount(), mock.totalIngests())
	}
	if journalExists(stateDir) {
		t.Fatalf("a dry run must not write the journal")
	}
	if pendingCount(t, stateDir) != 1 {
		t.Fatalf("a dry run must not drain anything")
	}
	if _, err := os.Stat(filepath.Join(stateDir, ".collector.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a dry run must not create the lock file, got %v", err)
	}
}

// TestSyncBlockedByOwnershipGuard verifies the guard at the Sync level
// (the path the resync CLI shares): history owned by another device is
// never retransmitted, even when connect's own checks were bypassed.
func TestSyncBlockedByOwnershipGuard(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startSyncToktrailMock(t, "dev-guard-1")

	seedBoundState(t, stateDir, mock.URL, "dev-guard-new")
	seedCodexGrant(t, stateDir, homeDir)
	seedBatch(t, stateDir, homeDir, "guard-synced-1", outbox.StatusSynced,
		syncRecord("guard-key-1", syncTestNow.Add(-time.Hour).Format(time.RFC3339)))
	if err := saveOwnership(stateDir, "dev-guard-old", syncTestNow); err != nil {
		t.Fatal(err)
	}

	_, err := Sync(context.Background(), SyncOptions{
		StateDir:   stateDir,
		ServerURL:  mock.URL,
		HTTPClient: mock.Client(),
		Now:        func() time.Time { return syncTestNow },
	})
	if err == nil || !strings.Contains(err.Error(), "history retransmission blocked") {
		t.Fatalf("the ownership guard must block the retransmission, got: %v", err)
	}
	if !strings.Contains(err.Error(), "dev-guard-old") {
		t.Fatalf("the error must name the owning device, got: %v", err)
	}
	if mock.totalIngests() != 0 {
		t.Fatalf("nothing may be retransmitted, got %d posts", mock.totalIngests())
	}
}

// TestAcquireStateLockRetrySemantics verifies the bounded busy retry the
// post-install phases use: a held lock is retried until the budget runs
// out, and a lock released mid-budget is acquired.
func TestAcquireStateLockRetrySemantics(t *testing.T) {
	withLockRetry(t, 400*time.Millisecond, 20*time.Millisecond)

	t.Run("busy_after_budget", func(t *testing.T) {
		dir := t.TempDir()
		held, err := runlock.Acquire(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer held.Close()
		start := time.Now()
		if _, err := acquireStateLock(context.Background(), dir); !errors.Is(err, runlock.ErrBusy) {
			t.Fatalf("expected ErrBusy after the retry budget, got %v", err)
		}
		if elapsed := time.Since(start); elapsed < 300*time.Millisecond {
			t.Fatalf("the retry must honor the budget, gave up after %s", elapsed)
		}
	})

	t.Run("acquires_once_released", func(t *testing.T) {
		dir := t.TempDir()
		held, err := runlock.Acquire(dir)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			time.Sleep(80 * time.Millisecond)
			held.Close()
		}()
		lock, err := acquireStateLock(context.Background(), dir)
		if err != nil {
			t.Fatalf("expected the retry to win the lock after release, got %v", err)
		}
		lock.Close()
	})

	t.Run("collection_pass_reports_busy", func(t *testing.T) {
		dir := t.TempDir()
		held, err := runlock.Acquire(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer held.Close()
		_, err = runCollectionPass(context.Background(), collectionOptionsFor(dir))
		if !errors.Is(err, runlock.ErrBusy) {
			t.Fatalf("a busy collection pass must surface ErrBusy, got %v", err)
		}
	})
}

// TestSyncResyncPhaseSkipsWhenStateBusy verifies the lock-contention
// path: when the scheduled task holds the state directory past the retry
// budget, the retransmission phase declines (recorded as Skipped) rather
// than sending anything, and the completeness evaluation turns that into
// an incomplete result.
func TestSyncResyncPhaseSkipsWhenStateBusy(t *testing.T) {
	withLockRetry(t, 300*time.Millisecond, 20*time.Millisecond)

	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startSyncToktrailMock(t, "dev-busy-1")

	seedBoundState(t, stateDir, mock.URL, "dev-busy-1")
	seedCodexGrant(t, stateDir, homeDir)
	seedBatch(t, stateDir, homeDir, "busy-synced-1", outbox.StatusSynced,
		syncRecord("busy-key-1", syncTestNow.Add(-time.Hour).Format(time.RFC3339)))

	held, err := runlock.Acquire(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	out := &strings.Builder{}
	summary, phaseErr, budgetStopped := runResyncPhase(context.Background(), stateDir, SyncOptions{
		StateDir:   stateDir,
		ServerURL:  mock.URL,
		HTTPClient: mock.Client(),
		Now:        func() time.Time { return syncTestNow },
	}, nil, newDisplay(out, false), func() time.Time { return syncTestNow }, nil)
	if phaseErr != nil {
		t.Fatalf("a busy lock is a recorded skip, not a hard error, got %v", phaseErr)
	}
	if budgetStopped {
		t.Fatalf("a busy lock is not a budget stop, got %+v", summary)
	}
	if summary.Skipped == "" || !strings.Contains(summary.Skipped, "busy") {
		t.Fatalf("the skip reason must name the busy state, got %+v", summary)
	}
	if summary.Ran || mock.totalIngests() != 0 {
		t.Fatalf("nothing may be retransmitted while the state is busy, got %+v", summary)
	}
	// The Skipped → incomplete reporting path this feeds is covered by
	// the paused-device test (the same evaluate rule); a Sync-level busy
	// scenario cannot be driven deterministically here because the
	// collection phase shares the lock and fails first — itself the
	// honest behavior for a state directory held the whole time.
}

// TestErrResyncNothingEligibleClassification pins the wording match that
// separates an authorization verdict (nothing eligible under the current
// grants) from a hard failure (unreadable or corrupt grant state).
func TestErrResyncNothingEligibleClassification(t *testing.T) {
	verdicts := []string{
		"none of the 3 synced batch(es) match a currently enabled local source grant (excluded: a, b); enable the sources you want to recover with `toktrail sources enable --source <source> --input <absolute-path>` and re-run resync",
		"no local source grants are configured (grants.json is absent): resync denies retransmission by default so residual archives cannot bypass local permission; enable the sources you want to recover with `toktrail sources enable --source <source> --input <absolute-path>` and re-run resync",
	}
	for _, msg := range verdicts {
		if !errResyncNothingEligible(errors.New(msg)) {
			t.Fatalf("an authorization verdict must be classified benign: %s", msg)
		}
	}
	hard := []string{
		"cannot read the local source grants; resync refuses to retransmit without current local authorization: open grants.json: permission denied",
		"resync cannot plan: 2 synced batch file(s) are missing or invalid; nothing was retransmitted and no job was started",
	}
	for _, msg := range hard {
		if errResyncNothingEligible(errors.New(msg)) {
			t.Fatalf("a hard failure must not be classified benign: %s", msg)
		}
	}
}

// withLockRetry shrinks the lock-retry budget for a test.
func withLockRetry(t *testing.T, total, delay time.Duration) {
	t.Helper()
	oldTotal, oldDelay := stateLockRetryTotal, stateLockRetryDelay
	stateLockRetryTotal, stateLockRetryDelay = total, delay
	t.Cleanup(func() { stateLockRetryTotal, stateLockRetryDelay = oldTotal, oldDelay })
}

// collectionOptionsFor builds a minimal collection.Options for the
// lock-contention unit test.
func collectionOptionsFor(stateDir string) collection.Options {
	return collection.Options{StateDir: stateDir, ServerURL: "http://127.0.0.1:1"}
}

// TestSyncInitialLockReleasedOnEarlyValidationFailure pins the handoff
// safety net's placement: a caller that handed its state lock in gets it
// back released on EVERY exit — including the early parameter failures
// that happen before any phase runs (an empty state directory, a
// negative total). A leak here would leave every later process seeing
// ErrBusy.
func TestSyncInitialLockReleasedOnEarlyValidationFailure(t *testing.T) {
	t.Run("empty state dir", func(t *testing.T) {
		lockDir := t.TempDir()
		lock, err := runlock.Acquire(lockDir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Sync(context.Background(), SyncOptions{StateDir: "", InitialLock: lock}); err == nil {
			t.Fatal("an empty state directory must fail validation")
		}
		// The handoff must have been released by the safety net.
		fresh, aErr := runlock.Acquire(lockDir)
		if aErr != nil {
			t.Fatalf("the handed-over lock must be released after an early validation failure, got %v", aErr)
		}
		_ = fresh.Close()
	})
	t.Run("negative total", func(t *testing.T) {
		stateDir := t.TempDir()
		lock, err := runlock.Acquire(stateDir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Sync(context.Background(), SyncOptions{StateDir: stateDir, MaxTotalBatches: -1, InitialLock: lock}); err == nil {
			t.Fatal("a negative max total must fail validation")
		}
		fresh, aErr := runlock.Acquire(stateDir)
		if aErr != nil {
			t.Fatalf("the handed-over lock must be released after an early validation failure, got %v", aErr)
		}
		_ = fresh.Close()
	})
	t.Run("dry run never leaks the handoff", func(t *testing.T) {
		dir := t.TempDir()
		homeDir := t.TempDir()
		mock := startSyncToktrailMock(t, "dev-dry-handoff-1")
		seedBoundState(t, dir, mock.URL, "dev-dry-handoff-1")
		lock, err := runlock.Acquire(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Sync(context.Background(), SyncOptions{
			StateDir: dir, ServerURL: mock.URL, HomeDir: homeDir,
			ResyncDryRun: true, InitialLock: lock,
			Now: func() time.Time { return syncTestNow },
		}); err != nil {
			t.Fatalf("the dry run must plan cleanly, got %v", err)
		}
		fresh, aErr := runlock.Acquire(dir)
		if aErr != nil {
			t.Fatalf("the dry-run branch must release the handoff, got %v", aErr)
		}
		_ = fresh.Close()
	})
}
