package collection

// Cursor periodic regressions for the account-level Cursor source inside
// the periodic collection run.
//
// Everything is synthetic: tempdir state, an httptest fake for the
// TokTrail device/grant endpoints, and injected auth/verify/pull fakes.
// No test ever reads the real Cursor desktop state, calls the Cursor API,
// or touches real credentials.
//
// Covered regressions:
//   - A cursor-only device (Cursor source permitted, zero local file
//     grants) still syncs: the round pulls, persists and uploads its
//     source batch, and the run is NOT reported as NoGrants/nothing to
//     collect.
//   - Without a local permit the cursor round is a clean skip that never
//     reads the Cursor credential and never pulls.
//   - A server-paused device runs no cursor authentication or pull at
//     all.
//   - When Cursor is outside the fresh server grant scope, the cursor
//     round skips before any credential read or pull, leaving the permit
//     untouched.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/cursor/api"
	"toktrail-collector/internal/cursor/auth"
	"toktrail-collector/internal/cursor/identity"
	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/local/cursoroutbox"
	"toktrail-collector/internal/local/cursorsource"
	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/managedconsent"
	"toktrail-collector/internal/local/statedir"
)

// Obvious synthetic fixtures; never real credentials.
const (
	cursorTestAccountID   = "user_testaccount01"
	cursorTestAccessToken = "synthetic-access-token-not-a-real-credential"
	cursorTestSessionTok  = "synthetic-session-token-not-a-real-credential"
	cursorPermitSourceID  = "cursor-src-per-1"
)

var cursorTestNow = time.Date(2026, 10, 28, 10, 0, 0, 0, time.UTC)

// fakeCursorAuth hands out a synthetic credential and counts reads so a
// test can prove the Cursor credential was never touched.
type fakeCursorAuth struct{ fetches int }

func (f *fakeCursorAuth) Fetch(ctx context.Context) (auth.Credential, error) {
	f.fetches++
	return auth.Credential{
		AccessToken: cursorTestAccessToken,
		AccountHint: cursorTestAccountID,
		Source:      "test-fixture",
	}, nil
}

// fakeCursorVerify validates the synthetic credential without touching
// Cursor.
func fakeCursorVerify(ctx context.Context, accessToken string) (api.VerifyResult, error) {
	if accessToken != cursorTestAccessToken {
		return api.VerifyResult{}, fmt.Errorf("unexpected credential handed to verify: %d bytes", len(accessToken))
	}
	return api.VerifyResult{
		AccountID:    cursorTestAccountID,
		SessionToken: cursorTestSessionTok,
	}, nil
}

// fakeCursorPull serves synthetic events inside the requested window and
// counts calls. A non-nil err makes every pull fail.
type fakeCursorPull struct {
	events []api.UsageEvent
	err    error
	calls  int
}

func (f *fakeCursorPull) Pull(ctx context.Context, sessionToken string, from, to time.Time) ([]api.UsageEvent, error) {
	if sessionToken != cursorTestSessionTok {
		return nil, fmt.Errorf("pull called with an unverified session token")
	}
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	var out []api.UsageEvent
	for _, ev := range f.events {
		ts := time.UnixMilli(ev.TimestampMS)
		if (from.IsZero() || !ts.Before(from)) && ts.Before(to) {
			out = append(out, ev)
		}
	}
	return out, nil
}

// cursorFixtureEvents returns two synthetic events inside the fixed test
// clock: a first pull from the zero time sees both.
func cursorFixtureEvents() []api.UsageEvent {
	mk := func(id string, age time.Duration, in, out int64) api.UsageEvent {
		zero := int64(0)
		return api.UsageEvent{
			UsageEventID:     id,
			ConversationID:   "conv-" + id,
			TimestampMS:      cursorTestNow.Add(-age).UnixMilli(),
			Model:            "cursor-claude-4.5",
			InputTokens:      &in,
			OutputTokens:     &out,
			CacheReadTokens:  &zero,
			CacheWriteTokens: &zero,
		}
	}
	return []api.UsageEvent{
		mk("usage-event-alpha", 2*time.Hour, 120, 30),
		mk("usage-event-beta", 90*time.Minute, 80, 20),
	}
}

// cursorFakeView is one served device grant view.
type cursorFakeView struct {
	paused   bool
	tools    []string
	revision int64
}

// cursorFakeServer speaks the device self / grant-ack / tool-status
// protocol plus the cursor source-batch ingest endpoint. It serves the
// permit's account source in self.accountSources. Unexpected endpoints
// fail the test so accidental traffic (e.g. cursor records on the device
// batch endpoint) is caught.
type cursorFakeServer struct {
	*httptest.Server

	mu          sync.Mutex
	view        cursorFakeView
	enablePosts int
	srcPosts    int
	srcRecords  int
	devicePosts int
	// fenceFailSourceBatches makes every source-batch upload answer the
	// server's fence-changed error code (stopping the drain).
	fenceFailSourceBatches bool
	// toolStatuses records every statuses[] entry of the tool-status
	// POSTs in arrival order.
	toolStatuses []toolStatusReport
}

func startCursorFakeServer(t *testing.T) *cursorFakeServer {
	t.Helper()
	s := &cursorFakeServer{
		view: cursorFakeView{tools: []string{"Cursor"}, revision: 41},
	}
	writeJSON := func(w http.ResponseWriter, status int, body any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self":
			s.mu.Lock()
			view := s.view
			s.mu.Unlock()
			device := map[string]any{
				"deviceId":             "dev-1",
				"consentRevision":      view.revision,
				"uploadAuthorized":     true,
				"revoked":              false,
				"paused":               view.paused,
				"allowedTools":         view.tools,
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
			s.mu.Lock()
			s.toolStatuses = append(s.toolStatuses, body.Statuses...)
			s.mu.Unlock()
			writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/source-batches":
			s.mu.Lock()
			fenceFail := s.fenceFailSourceBatches
			s.mu.Unlock()
			if fenceFail {
				writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]any{
					"code":    "source_fence_changed",
					"message": "simulated fence move",
				}})
				return
			}
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
			s.srcRecords += len(batch.Records)
			s.mu.Unlock()
			writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
				"batchId":         batch.BatchID,
				"status":          "accepted",
				"acceptedRecords": len(batch.Records),
				"rejectedRecords": 0,
				"replay":          false,
				"receivedAt":      cursorTestNow.Format(time.RFC3339),
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/account-sources/enable":
			// The periodic run must never enable an account source;
			// count it so tests can fail on the accidental call.
			s.mu.Lock()
			s.enablePosts++
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"source": protocol.Source{
				SourceInstanceID: cursorPermitSourceID,
				SourceType:       protocol.SourceType,
				State:            "active",
				FenceVersion:     3,
				NextRevision:     7,
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/batches":
			// Cursor records must never ride the device batch path;
			// count it so tests can fail on the accidental call. The
			// receipt is valid so a legitimate device backlog (a
			// cursor-only device still drains its device outbox, §6.1)
			// can be exercised through this server.
			var body struct {
				BatchID string            `json:"batchId"`
				Records []json.RawMessage `json:"records"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			s.mu.Lock()
			s.devicePosts++
			s.mu.Unlock()
			writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
				"batchId":         body.BatchID,
				"status":          "accepted",
				"acceptedRecords": len(body.Records),
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

func (s *cursorFakeServer) setView(t *testing.T, view cursorFakeView) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.view = view
}

// setFenceFail toggles the source-fence-changed failure on uploads.
func (s *cursorFakeServer) setFenceFail(t *testing.T, on bool) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fenceFailSourceBatches = on
}

func (s *cursorFakeServer) counters() (enablePosts, srcPosts, srcRecords, devicePosts int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enablePosts, s.srcPosts, s.srcRecords, s.devicePosts
}

func (s *cursorFakeServer) reportedToolStatuses() []toolStatusReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]toolStatusReport, len(s.toolStatuses))
	copy(out, s.toolStatuses)
	return out
}

// bindCursorDevice binds a device whose subject namespace is usable by
// the cursor event identity derivation: identity.SubjectNamespace needs
// both the application id and the external subject id of a real bound
// state (the shared bindDevice helper writes neither).
func bindCursorDevice(t *testing.T, stateDir, serverURL string) {
	t.Helper()
	if err := statedir.New(stateDir).Save(statedir.DeviceState{
		ServerURL:         serverURL,
		DeviceID:          "dev-1",
		DeviceSecret:      testSecret,
		ApplicationID:     "app-1",
		ExternalSubjectID: "sub-1",
	}); err != nil {
		t.Fatal(err)
	}
}

// writeCursorPermit seeds an active local cursor permit matching the
// source the fake server serves in self.accountSources.
func writeCursorPermit(t *testing.T, stateDir string) {
	t.Helper()
	license := cursorsource.License{
		SourceInstanceID: cursorPermitSourceID,
		SourceType:       cursorsource.SourceType,
		Status:           cursorsource.StatusActive,
		ConfirmedAt:      cursorTestNow.Add(-time.Hour),
		ConsentRevision:  40,
		FenceVersion:     3,
		NextRevision:     7,
		AccountMatchID:   identity.MatchAccount(cursorTestAccountID),
	}
	if err := cursorsource.New(stateDir).Save(license); err != nil {
		t.Fatal(err)
	}
}

// runCursorPeriodic executes one periodic Run with the cursor wiring and
// the given pull fake.
func runCursorPeriodic(t *testing.T, stateDir, serverURL string, server *cursorFakeServer, pull *fakeCursorPull) (Result, *fakeCursorAuth) {
	t.Helper()
	authFake := &fakeCursorAuth{}
	res, err := Run(t.Context(), Options{
		StateDir:   stateDir,
		ServerURL:  serverURL,
		HTTPClient: server.Client(),
		HomeDir:    t.TempDir(),
		Now:        func() time.Time { return cursorTestNow },
		Cursor: &cursorsync.Options{
			StateDir:   stateDir,
			ServerURL:  serverURL,
			HTTPClient: server.Client(),
			Auth:       authFake,
			Verify:     fakeCursorVerify,
			Pull:       pull.Pull,
			Now:        func() time.Time { return cursorTestNow },
		},
	})
	if err != nil {
		t.Fatalf("periodic Run failed: %v", err)
	}
	return res, authFake
}

// TestPeriodicCursorOnlyDeviceSyncs verifies that a cursor-only device —
// a permitted Cursor account source and zero local file grants — still
// syncs through the periodic run: the round pulls the synthetic usage,
// persists a source batch and uploads it through the source-batch
// endpoint. The run must not be reported as NoGrants/"nothing to
// collect", and no local grant may be fabricated for the account source.
func TestPeriodicCursorOnlyDeviceSyncs(t *testing.T) {
	stateDir := t.TempDir()
	server := startCursorFakeServer(t)
	server.setView(t, cursorFakeView{tools: []string{"Cursor"}, revision: 41})
	bindCursorDevice(t, stateDir, server.URL)
	writeCursorPermit(t, stateDir)

	pull := &fakeCursorPull{events: cursorFixtureEvents()}
	res, authFake := runCursorPeriodic(t, stateDir, server.URL, server, pull)

	if !res.GrantSync.Active || res.GrantSync.Paused {
		t.Fatalf("unexpected grant sync result: %+v", res.GrantSync)
	}
	// The cursor round ran to completion.
	if !res.Cursor.Ran || res.Cursor.Skipped != "" {
		t.Fatalf("cursor round must run on a cursor-only device, got %+v", res.Cursor)
	}
	if res.Cursor.PulledEvents != 2 || res.Cursor.NewRecords != 2 {
		t.Fatalf("cursor pull/normalize = %d/%d, want 2/2", res.Cursor.PulledEvents, res.Cursor.NewRecords)
	}
	if res.Cursor.SyncedBatches != 1 || res.Cursor.SyncedRecords != 2 || res.Cursor.PendingRemaining != 0 {
		t.Fatalf("cursor upload = %d batches / %d records / %d pending, want 1/2/0: %+v",
			res.Cursor.SyncedBatches, res.Cursor.SyncedRecords, res.Cursor.PendingRemaining, res.Cursor)
	}
	if authFake.fetches != 1 || pull.calls != 1 {
		t.Fatalf("credential reads = %d, pulls = %d; want exactly 1 each", authFake.fetches, pull.calls)
	}
	// Cursor records travel only through the source-batch endpoint; the
	// periodic run never enables an account source by itself.
	enablePosts, srcPosts, srcRecords, devicePosts := server.counters()
	if enablePosts != 0 {
		t.Fatalf("the periodic run must never call account-source enable, got %d", enablePosts)
	}
	if srcPosts != 1 || srcRecords != 2 {
		t.Fatalf("source-batch uploads = %d posts / %d records, want 1/2", srcPosts, srcRecords)
	}
	if devicePosts != 0 {
		t.Fatalf("cursor records must never ride the device batch endpoint, got %d posts", devicePosts)
	}
	// A cursor-only device is NOT a no-op run.
	if res.NoGrants || res.Skipped != "" {
		t.Fatalf("a synced cursor-only device must not report NoGrants/skip, got NoGrants=%t Skipped=%q", res.NoGrants, res.Skipped)
	}
	if res.Grants != 0 {
		t.Fatalf("cursor-only device must have zero local grants, got %d", res.Grants)
	}
	// No local grant was fabricated for the account source.
	cfg, err := grants.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Grants) != 0 {
		t.Fatalf("the cursor source must never create local file grants, got %#v", cfg.Grants)
	}
	// The permit advanced: watermark set, next revision bumped, still
	// active.
	license, ok, err := cursorsource.New(stateDir).Load()
	if err != nil || !ok {
		t.Fatalf("permit must survive the round, ok=%v err=%v", ok, err)
	}
	if license.Status != cursorsource.StatusActive || license.PullWatermark == nil || license.NextRevision != 8 {
		t.Fatalf("permit must advance (active, watermark set, nextRevision 8), got %+v", license)
	}
	// The successful round reports the tool-status receipt a cursor-only
	// device would otherwise never produce: exactly one "synced" report
	// for Cursor, in the fixed vocabulary.
	if got := server.reportedToolStatuses(); len(got) != 1 || got[0] != (toolStatusReport{Tool: "Cursor", Status: "synced"}) {
		t.Fatalf("tool-status receipts = %#v, want exactly [Cursor synced]", got)
	}
}

// TestPeriodicCursorNoPermitSkipsWithoutCredentialRead verifies that
// without a local permit the cursor round is a clean skip: the Cursor
// credential is never read, nothing is pulled or uploaded, and — with no
// local grants either — the run honestly reports NoGrants.
func TestPeriodicCursorNoPermitSkipsWithoutCredentialRead(t *testing.T) {
	stateDir := t.TempDir()
	server := startCursorFakeServer(t)
	server.setView(t, cursorFakeView{tools: []string{"Cursor"}, revision: 41})
	bindCursorDevice(t, stateDir, server.URL)
	// No cursor permit, no local grants.

	pull := &fakeCursorPull{events: cursorFixtureEvents()}
	res, authFake := runCursorPeriodic(t, stateDir, server.URL, server, pull)

	if res.Cursor.Ran {
		t.Fatalf("cursor round must not run without a permit, got %+v", res.Cursor)
	}
	if !strings.Contains(res.Cursor.Skipped, "no local cursor permit") {
		t.Fatalf("cursor skip reason = %q, want the no-permit reason", res.Cursor.Skipped)
	}
	if authFake.fetches != 0 || pull.calls != 0 {
		t.Fatalf("no permit means no credential read and no pull, got %d reads / %d pulls", authFake.fetches, pull.calls)
	}
	enablePosts, srcPosts, _, devicePosts := server.counters()
	if enablePosts != 0 || srcPosts != 0 || devicePosts != 0 {
		t.Fatalf("no permit means no cursor traffic, got enables=%d sourceBatches=%d deviceBatches=%d", enablePosts, srcPosts, devicePosts)
	}
	if !res.NoGrants || !strings.Contains(res.Skipped, "nothing to collect") {
		t.Fatalf("no permit and no grants must report the honest no-op, got NoGrants=%t Skipped=%q", res.NoGrants, res.Skipped)
	}
	if got := server.reportedToolStatuses(); len(got) != 0 {
		t.Fatalf("a skipped cursor round must not report a tool-status receipt, got %#v", got)
	}
}

// TestPeriodicPausedDeviceRunsNoCursorAuth verifies that a server-paused
// device performs no cursor authentication and no pull: the run stops at
// the applied pause before the cursor sync starts.
func TestPeriodicPausedDeviceRunsNoCursorAuth(t *testing.T) {
	stateDir := t.TempDir()
	server := startCursorFakeServer(t)
	server.setView(t, cursorFakeView{paused: true, tools: []string{"__toktrail_paused__"}, revision: 42})
	bindCursorDevice(t, stateDir, server.URL)
	writeCursorPermit(t, stateDir)

	pull := &fakeCursorPull{events: cursorFixtureEvents()}
	res, authFake := runCursorPeriodic(t, stateDir, server.URL, server, pull)

	if !res.GrantSync.Paused {
		t.Fatalf("the paused view must be applied, got %+v", res.GrantSync)
	}
	if res.Cursor.Ran || res.Cursor.Status != "" {
		t.Fatalf("a paused run must not start a cursor round, got %+v", res.Cursor)
	}
	if res.Skipped == "" || !strings.Contains(res.Skipped, "paused") {
		t.Fatalf("paused run must carry the pause skip reason, got %q", res.Skipped)
	}
	if authFake.fetches != 0 || pull.calls != 0 {
		t.Fatalf("a paused device must not read the credential or pull, got %d reads / %d pulls", authFake.fetches, pull.calls)
	}
	enablePosts, srcPosts, _, devicePosts := server.counters()
	if enablePosts != 0 || srcPosts != 0 || devicePosts != 0 {
		t.Fatalf("a paused device must not produce cursor traffic, got enables=%d sourceBatches=%d deviceBatches=%d", enablePosts, srcPosts, devicePosts)
	}
	// The permit is untouched.
	license, ok, err := cursorsource.New(stateDir).Load()
	if err != nil || !ok {
		t.Fatal(err)
	}
	if license.PullWatermark != nil || license.NextRevision != 7 {
		t.Fatalf("a paused run must not advance the permit, got %+v", license)
	}
	if got := server.reportedToolStatuses(); len(got) != 0 {
		t.Fatalf("a paused run must not report a tool-status receipt, got %#v", got)
	}
}

// TestPeriodicCursorOutsideFreshScopeSkipsAuthAndPull verifies that when
// the fresh server grant scope does not include Cursor, the cursor round
// skips before any credential read or pull. The permit stays intact (and
// keeps the run off the NoGrants/"nothing to collect" path), and the run
// itself succeeds.
func TestPeriodicCursorOutsideFreshScopeSkipsAuthAndPull(t *testing.T) {
	stateDir := t.TempDir()
	server := startCursorFakeServer(t)
	server.setView(t, cursorFakeView{tools: []string{"Codex"}, revision: 43})
	bindCursorDevice(t, stateDir, server.URL)
	writeCursorPermit(t, stateDir)

	pull := &fakeCursorPull{events: cursorFixtureEvents()}
	res, authFake := runCursorPeriodic(t, stateDir, server.URL, server, pull)

	if res.Cursor.Ran {
		t.Fatalf("cursor round must not run outside the fresh scope, got %+v", res.Cursor)
	}
	if !strings.Contains(res.Cursor.Skipped, "not allowed by the effective server grant scope") {
		t.Fatalf("cursor skip reason = %q, want the scope reason", res.Cursor.Skipped)
	}
	if authFake.fetches != 0 || pull.calls != 0 {
		t.Fatalf("out-of-scope cursor must not read the credential or pull, got %d reads / %d pulls", authFake.fetches, pull.calls)
	}
	enablePosts, srcPosts, _, devicePosts := server.counters()
	if enablePosts != 0 || srcPosts != 0 || devicePosts != 0 {
		t.Fatalf("out-of-scope cursor must not produce cursor traffic, got enables=%d sourceBatches=%d deviceBatches=%d", enablePosts, srcPosts, devicePosts)
	}
	// The permit survives untouched and still counts as an active source
	// for the run's reporting.
	if res.Cursor.Status != cursorsource.StatusActive {
		t.Fatalf("permit status must stay active, got %q", res.Cursor.Status)
	}
	if res.NoGrants || strings.Contains(res.Skipped, "nothing to collect") {
		t.Fatalf("a permitted cursor source must not be reported as nothing-to-collect, got NoGrants=%t Skipped=%q", res.NoGrants, res.Skipped)
	}
	license, ok, err := cursorsource.New(stateDir).Load()
	if err != nil || !ok {
		t.Fatal(err)
	}
	if license.PullWatermark != nil || license.NextRevision != 7 || license.Status != cursorsource.StatusActive {
		t.Fatalf("an out-of-scope skip must not mutate the permit, got %+v", license)
	}
	// The applied overlay still reflects the server's scope.
	o, seen, err := managedconsent.New(stateDir).Load()
	if err != nil || !seen {
		t.Fatalf("expected the managed-consent overlay, seen=%v err=%v", seen, err)
	}
	if len(o.AllowedTools) != 1 || o.AllowedTools[0] != "Codex" {
		t.Fatalf("applied scope = %#v, want [Codex]", o.AllowedTools)
	}
	// The Codex restriction is reported, but never a Cursor success: a
	// skipped cursor round must not masquerade as synced.
	for _, report := range server.reportedToolStatuses() {
		if report.Tool == "Cursor" {
			t.Fatalf("an out-of-scope cursor round must not report a Cursor receipt, got %#v", report)
		}
	}
}

// TestPeriodicCursorOnlyEmptyScanReportsNoNewRecords verifies the empty
// scan receipt: a fully successful cursor round with no new events (and
// nothing pending) reports Cursor as no_new_records — the honest
// "connected, nothing new" signal a cursor-only device needs — while the
// permit still advances its watermark.
func TestPeriodicCursorOnlyEmptyScanReportsNoNewRecords(t *testing.T) {
	stateDir := t.TempDir()
	server := startCursorFakeServer(t)
	server.setView(t, cursorFakeView{tools: []string{"Cursor"}, revision: 41})
	bindCursorDevice(t, stateDir, server.URL)
	writeCursorPermit(t, stateDir)

	// The pull completes successfully but returns no events at all.
	pull := &fakeCursorPull{}
	res, authFake := runCursorPeriodic(t, stateDir, server.URL, server, pull)

	if !res.Cursor.Ran || res.Cursor.Skipped != "" || res.Cursor.Note != "" {
		t.Fatalf("the empty scan must be a fully successful round, got %+v", res.Cursor)
	}
	if res.Cursor.PulledEvents != 0 || res.Cursor.NewRecords != 0 || res.Cursor.SyncedBatches != 0 || res.Cursor.PendingRemaining != 0 {
		t.Fatalf("empty scan counters wrong: %+v", res.Cursor)
	}
	if authFake.fetches != 1 || pull.calls != 1 {
		t.Fatalf("the empty scan still reads the credential and pulls once, got %d reads / %d pulls", authFake.fetches, pull.calls)
	}
	if res.NoGrants || res.Skipped != "" {
		t.Fatalf("an empty cursor scan is not a no-op run, got NoGrants=%t Skipped=%q", res.NoGrants, res.Skipped)
	}
	if got := server.reportedToolStatuses(); len(got) != 1 || got[0] != (toolStatusReport{
		Tool:   "Cursor",
		Status: "no_new_records",
		Detail: "no new records since last confirmed baseline",
	}) {
		t.Fatalf("tool-status receipts = %#v, want exactly [Cursor no_new_records]", got)
	}
	// The watermark still advances: the pull window was covered.
	license, ok, err := cursorsource.New(stateDir).Load()
	if err != nil || !ok {
		t.Fatal(err)
	}
	if license.PullWatermark == nil {
		t.Fatalf("the empty scan must still advance the watermark, got %+v", license)
	}
}

// TestPeriodicCursorPullFailureNotReportedAsSuccess verifies that a
// failed cursor round (pull error) never produces a success receipt: no
// Cursor tool-status post at all, the failure surfaces on the cursor
// result, the permit keeps its watermark, and the run itself stays
// non-fatal.
func TestPeriodicCursorPullFailureNotReportedAsSuccess(t *testing.T) {
	stateDir := t.TempDir()
	server := startCursorFakeServer(t)
	server.setView(t, cursorFakeView{tools: []string{"Cursor"}, revision: 41})
	bindCursorDevice(t, stateDir, server.URL)
	writeCursorPermit(t, stateDir)

	pull := &fakeCursorPull{err: errors.New("synthetic cursor pull failure")}
	res, authFake := runCursorPeriodic(t, stateDir, server.URL, server, pull)

	if authFake.fetches != 1 || pull.calls != 1 {
		t.Fatalf("the round reads the credential and attempts the pull, got %d reads / %d pulls", authFake.fetches, pull.calls)
	}
	if res.Cursor.Skipped == "" || !strings.Contains(res.Cursor.Skipped, "cursor usage pull failed") {
		t.Fatalf("the pull failure must surface on the cursor result, got %q", res.Cursor.Skipped)
	}
	if got := server.reportedToolStatuses(); len(got) != 0 {
		t.Fatalf("a failed cursor round must not report a tool-status receipt, got %#v", got)
	}
	_, srcPosts, _, devicePosts := server.counters()
	if srcPosts != 0 || devicePosts != 0 {
		t.Fatalf("a failed pull must not upload anything, got sourceBatches=%d deviceBatches=%d", srcPosts, devicePosts)
	}
	// The watermark is not advanced and the run is not a no-op report.
	license, ok, err := cursorsource.New(stateDir).Load()
	if err != nil || !ok {
		t.Fatal(err)
	}
	if license.PullWatermark != nil || license.NextRevision != 7 {
		t.Fatalf("a failed pull must not advance the permit, got %+v", license)
	}
	if res.NoGrants {
		t.Fatalf("a permitted cursor source keeps the run off the NoGrants path even on failure")
	}
}

// TestPeriodicCursorFenceStopNotReportedAsSuccess verifies that a round
// whose upload drain is stopped by a server-side fence move reports no
// success: the batch stays pending, the stop is noted, and no Cursor
// tool-status receipt is sent.
func TestPeriodicCursorFenceStopNotReportedAsSuccess(t *testing.T) {
	stateDir := t.TempDir()
	server := startCursorFakeServer(t)
	server.setView(t, cursorFakeView{tools: []string{"Cursor"}, revision: 41})
	bindCursorDevice(t, stateDir, server.URL)
	writeCursorPermit(t, stateDir)
	// The pull succeeds and persists a batch; the upload is rejected with
	// the server's fence-changed code, stopping the drain.
	server.setFenceFail(t, true)

	pull := &fakeCursorPull{events: cursorFixtureEvents()}
	res, _ := runCursorPeriodic(t, stateDir, server.URL, server, pull)

	if !res.Cursor.Ran {
		t.Fatalf("the round ran (pull completed) before the fence stop, got %+v", res.Cursor)
	}
	if res.Cursor.PendingRemaining != 1 {
		t.Fatalf("the fence-stopped batch must stay pending, got %+v", res.Cursor)
	}
	if res.Cursor.Note == "" || !strings.Contains(res.Cursor.Note, "stopped") {
		t.Fatalf("the fence stop must be noted, got %q", res.Cursor.Note)
	}
	if got := server.reportedToolStatuses(); len(got) != 0 {
		t.Fatalf("a fence-stopped round must not report a tool-status receipt, got %#v", got)
	}
	pending, err := cursoroutbox.New(stateDir).CountPending()
	if err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Fatalf("the cursor outbox must hold the fenced batch, got %d pending", pending)
	}
	// The produced records are durable: the next round retries them.
	if res.Cursor.NewRecords != 2 {
		t.Fatalf("the pull still produced its records, got %+v", res.Cursor)
	}
	if res.NoGrants {
		t.Fatalf("a permitted cursor source keeps the run off the NoGrants path even when stopped")
	}
}

// TestPeriodicCursorDrainOnlyRoundNeverPulls verifies the drain-only
// cursor round (Options.CursorDrainOnly): with an active permit and a
// pending cursor batch, the round still executes under the same runlock
// and server preflight and uploads the persisted batch, but it never
// reads the Cursor credential and never pulls upstream usage — the round
// shape connect's first-enable flow uses for its initial collection
// round, so the enable's first sync stays the only upstream pull.
func TestPeriodicCursorDrainOnlyRoundNeverPulls(t *testing.T) {
	stateDir := t.TempDir()
	server := startCursorFakeServer(t)
	bindCursorDevice(t, stateDir, server.URL)
	writeCursorPermit(t, stateDir)
	seedCursorPendingBatch(t, stateDir, "cursor-drainonly-1", 2)

	pull := &fakeCursorPull{events: cursorFixtureEvents()}
	authFake := &fakeCursorAuth{}
	res, err := Run(t.Context(), Options{
		StateDir:        stateDir,
		ServerURL:       server.URL,
		HTTPClient:      server.Client(),
		HomeDir:         t.TempDir(),
		Now:             func() time.Time { return cursorTestNow },
		CursorDrainOnly: true,
		Cursor: &cursorsync.Options{
			StateDir:   stateDir,
			ServerURL:  server.URL,
			HTTPClient: server.Client(),
			Auth:       authFake,
			Verify:     fakeCursorVerify,
			Pull:       pull.Pull,
			Now:        func() time.Time { return cursorTestNow },
		},
	})
	if err != nil {
		t.Fatalf("a fully drained drain-only round must succeed, got %v", err)
	}
	// The round ran and drained the persisted queue honestly.
	if !res.Cursor.Ran || res.Cursor.Skipped != "" || res.Cursor.Note != "" {
		t.Fatalf("the drain-only round must run cleanly, got %+v", res.Cursor)
	}
	if res.Cursor.SyncedBatches != 1 || res.Cursor.SyncedRecords != 2 || res.Cursor.PendingRemaining != 0 {
		t.Fatalf("the pending cursor batch must drain, got %+v", res.Cursor)
	}
	// No credential read and no upstream pull — the two operations that
	// distinguish the drain-only round from the full round.
	if pull.calls != 0 {
		t.Fatalf("a drain-only round must never pull upstream usage, got %d pulls", pull.calls)
	}
	if authFake.fetches != 0 {
		t.Fatalf("a drain-only round must never read the cursor credential, got %d reads", authFake.fetches)
	}
	enablePosts, srcPosts, srcRecords, devicePosts := server.counters()
	if enablePosts != 0 || srcPosts != 1 || srcRecords != 2 || devicePosts != 0 {
		t.Fatalf("exactly the persisted batch may upload (and never via the device path), got enable=%d src=%d records=%d device=%d",
			enablePosts, srcPosts, srcRecords, devicePosts)
	}
	if n := cursorPendingCount(t, stateDir); n != 0 {
		t.Fatalf("nothing may stay pending, got %d", n)
	}
	// A fully drained round still reports the honest tool-status receipt.
	if got := server.reportedToolStatuses(); len(got) != 1 || got[0] != (toolStatusReport{Tool: "Cursor", Status: "synced"}) {
		t.Fatalf("tool-status receipts = %#v, want exactly [Cursor synced]", got)
	}
}

// TestPeriodicCursorOnlyDeviceStillDrainsDeviceBacklog pins the §6.1
// cursor-only arm: a device with an active cursor permit and NO local
// file grants still drains its pending DEVICE outbox batches (they are
// the current authorization's already-materialized queue, and sending
// stays gated by the live server consent preflight). The run reports the
// drained counts — never a NoGrants no-op hiding PendingRemaining=0 —
// while the cursor round proceeds as usual.
func TestPeriodicCursorOnlyDeviceStillDrainsDeviceBacklog(t *testing.T) {
	stateDir := t.TempDir()
	server := startCursorFakeServer(t)
	// Unrestricted scope: the pending device batch's tool is allowed by
	// the live authorization, so the §6.1 drain may legitimately upload
	// it (a scope that withholds it would quarantine it honestly — a
	// different, already-covered behavior).
	server.setView(t, cursorFakeView{tools: nil, revision: 41})
	bindCursorDevice(t, stateDir, server.URL)
	writeCursorPermit(t, stateDir)
	writePendingBatch(t, stateDir, "cursor-only-device-pending-1")

	pull := &fakeCursorPull{}
	authFake := &fakeCursorAuth{}
	res, err := Run(t.Context(), Options{
		StateDir:   stateDir,
		ServerURL:  server.URL,
		HTTPClient: server.Client(),
		HomeDir:    t.TempDir(),
		Now:        func() time.Time { return cursorTestNow },
		Cursor: &cursorsync.Options{
			StateDir:   stateDir,
			ServerURL:  server.URL,
			HTTPClient: server.Client(),
			Auth:       authFake,
			Verify:     fakeCursorVerify,
			Pull:       pull.Pull,
			Now:        func() time.Time { return cursorTestNow },
		},
	})
	if err != nil {
		t.Fatalf("the cursor-only run must succeed, got %v", err)
	}
	if res.NoGrants {
		t.Fatalf("a cursor-only device with a live permit must not report NoGrants, got %+v", res)
	}
	if res.Skipped != "" {
		t.Fatalf("a run that drained work must not read as a no-op, got %q", res.Skipped)
	}
	if res.SyncedBatches != 1 || res.SyncedRecords != 1 || res.PendingRemaining != 0 {
		t.Fatalf("the pending device batch must drain, got %+v", res)
	}
	// The cursor round ran as usual (one pull of the overlap window, no
	// cursor batches pending), and the device batch rode the device
	// endpoint exactly once.
	if !res.Cursor.Ran || res.Cursor.Skipped != "" {
		t.Fatalf("the cursor round must run cleanly, got %+v", res.Cursor)
	}
	enablePosts, srcPosts, _, devicePosts := server.counters()
	if enablePosts != 0 || srcPosts != 0 || devicePosts != 1 {
		t.Fatalf("exactly one device upload and no cursor traffic expected, got enable=%d src=%d device=%d",
			enablePosts, srcPosts, devicePosts)
	}
}
