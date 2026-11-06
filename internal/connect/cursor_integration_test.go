package connect

// Cursor integration regressions for the connect orchestration.
//
// These tests exercise the account-level Cursor source wiring through the
// full connect.Run flow with everything synthetic: tempdir state, httptest
// mock servers for the TokTrail endpoints, and injected
// auth/verify/pull/confirm fakes. No test ever touches the real Cursor
// desktop state, the Cursor API, or any real credential; the only tokens
// that exist are obvious synthetic fixtures.
//
// Covered regressions:
//   - Selecting Cursor in the connect authorization enables the source
//     directly through the injected confirmation + authentication (no
//     separate `toktrail cursor login` step), never fabricates a local
//     file grant, and completes the first sync (pull + source-batch
//     upload).
//   - A declined first-time confirmation is a clean skip: the Cursor
//     credential is never read, no permit is written, the server enable
//     is never called, and the other authorized tools keep their full
//     connect setup (grants, scheduler, initial collection).

import (
	"bytes"
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
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/console"
	"toktrail-collector/internal/cursor/api"
	"toktrail-collector/internal/cursor/auth"
	autherr "toktrail-collector/internal/cursor/auth"
	"toktrail-collector/internal/cursor/identity"
	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/local/cursorsource"
	"toktrail-collector/internal/local/grants"
)

// Obvious synthetic fixtures: never real credentials, never valid against
// the real Cursor API.
const (
	cursorTestAccountID   = "user_testaccount01"
	cursorTestAccessToken = "synthetic-access-token-not-a-real-credential"
	cursorTestSessionTok  = "synthetic-session-token-not-a-real-credential"
	cursorTestSourceID    = "cursor-src-test-1"
	cursorTestDeviceID    = "dev-cursor-1"
	cursorTestSubjectID   = "sub-cursor-1"
)

var cursorTestNow = time.Date(2026, 10, 28, 10, 0, 0, 0, time.UTC)

// fakeCursorAuth is an auth.Provider that never touches the Cursor
// desktop state: it hands out a synthetic credential and counts reads so
// tests can prove the credential was NOT read on a declined first-time
// confirmation.
type fakeCursorAuth struct{ fetches atomic.Int64 }

func (f *fakeCursorAuth) Fetch(ctx context.Context) (auth.Credential, error) {
	f.fetches.Add(1)
	return auth.Credential{
		AccessToken: cursorTestAccessToken,
		AccountHint: cursorTestAccountID,
		Source:      "test-fixture",
	}, nil
}

// fakeCursorVerify validates the synthetic credential with zero network
// access to Cursor and derives the canonical account identity.
func fakeCursorVerify(ctx context.Context, accessToken string) (api.VerifyResult, error) {
	if accessToken != cursorTestAccessToken {
		return api.VerifyResult{}, fmt.Errorf("unexpected credential handed to verify: %d bytes", len(accessToken))
	}
	return api.VerifyResult{
		AccountID:    cursorTestAccountID,
		SessionToken: cursorTestSessionTok,
	}, nil
}

// fakeCursorPull serves synthetic usage events that fall inside the
// requested [from, to) window, counting calls.
type fakeCursorPull struct {
	events []api.UsageEvent
	calls  atomic.Int64
}

func (f *fakeCursorPull) Pull(ctx context.Context, sessionToken string, from, to time.Time) ([]api.UsageEvent, error) {
	if sessionToken != cursorTestSessionTok {
		return nil, fmt.Errorf("pull called with an unverified session token")
	}
	f.calls.Add(1)
	var out []api.UsageEvent
	for _, ev := range f.events {
		ts := time.UnixMilli(ev.TimestampMS)
		if (from.IsZero() || !ts.Before(from)) && ts.Before(to) {
			out = append(out, ev)
		}
	}
	return out, nil
}

// cursorFixtureEvents returns two synthetic usage events well inside the
// test's fixed clock so the first pull (from the zero time) sees both and
// the post-enable overlap re-pull (watermark minus one hour) sees none.
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

// cursorToktrailMock fakes the TokTrail server side that a cursor-wired
// connect run talks to: device bind, the device self view, the
// account-source enable call, cursor source-batch ingest, device batch
// ingest and tool-status reports. Only synthetic fixtures are served.
type cursorToktrailMock struct {
	*httptest.Server

	mu sync.Mutex
	// enabledSource is served in self.accountSources once the enable
	// endpoint has been called.
	enabledSource *protocol.Source
	bindSecret    string

	bindCalls     int
	enableCalls   int
	selfCalls     int
	srcBatchPosts int
	srcRecords    int
	devicePosts   int
	enableAuth    []string
	enableBodies  []string
	// flakeFirstSrcBatch fails the FIRST cursor source-batch POST with a
	// retryable 503 (allowlisted transient code) so retry-wiring tests
	// can observe a 503→200 resend through the first-enable round.
	flakeFirstSrcBatch bool
	// srcBatchBodies captures the raw body of every source-batch POST.
	srcBatchBodies [][]byte
}

func startCursorToktrailMock(t *testing.T) *cursorToktrailMock {
	t.Helper()
	m := &cursorToktrailMock{}
	writeJSON := func(w http.ResponseWriter, status int, body any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/devices/bind":
			m.mu.Lock()
			m.bindCalls++
			m.mu.Unlock()
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("invalid bind body: %v", err)
			}
			m.mu.Lock()
			if s, _ := req["deviceSecret"].(string); s != "" {
				m.bindSecret = s
			}
			m.mu.Unlock()
			writeJSON(w, http.StatusCreated, map[string]any{
				"device": map[string]any{
					"deviceId":          cursorTestDeviceID,
					"applicationId":     "app-cursor-1",
					"externalSubjectId": cursorTestSubjectID,
					"deviceName":        "collector",
					"platform":          "test",
					"consentRevision":   1,
					"boundAt":           cursorTestNow.Format(time.RFC3339),
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self":
			m.mu.Lock()
			m.selfCalls++
			src := m.enabledSource
			m.mu.Unlock()
			device := map[string]any{
				"deviceId":          cursorTestDeviceID,
				"applicationId":     "app-cursor-1",
				"externalSubjectId": cursorTestSubjectID,
				"consentRevision":   1,
				"uploadAuthorized":  true,
				"publicAuthorized":  false,
				"revoked":           false,
			}
			if src != nil {
				device["accountSources"] = []protocol.Source{*src}
			}
			writeJSON(w, http.StatusOK, map[string]any{"device": device})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/account-sources/enable":
			body, _ := io.ReadAll(r.Body)
			m.mu.Lock()
			m.enableCalls++
			m.enableAuth = append(m.enableAuth, r.Header.Get("Authorization"))
			m.enableBodies = append(m.enableBodies, string(body))
			m.mu.Unlock()
			src := protocol.Source{
				SourceInstanceID: cursorTestSourceID,
				SourceType:       protocol.SourceType,
				State:            "active",
				FenceVersion:     1,
				NextRevision:     1,
			}
			m.mu.Lock()
			m.enabledSource = &src
			m.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"source": src})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/source-batches":
			raw, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				t.Errorf("invalid source-batch body: %v", readErr)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var batch struct {
				BatchID string            `json:"batchId"`
				Records []json.RawMessage `json:"records"`
			}
			if err := json.Unmarshal(raw, &batch); err != nil {
				t.Errorf("invalid source-batch body: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			m.mu.Lock()
			flake := m.flakeFirstSrcBatch && len(m.srcBatchBodies) == 0
			m.srcBatchPosts++
			m.srcBatchBodies = append(m.srcBatchBodies, append([]byte(nil), raw...))
			if !flake {
				m.srcRecords += len(batch.Records)
			}
			m.mu.Unlock()
			if flake {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]any{"code": "service_unavailable", "message": "synthetic transient failure"}})
				return
			}
			writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
				"batchId":         batch.BatchID,
				"status":          "accepted",
				"acceptedRecords": len(batch.Records),
				"rejectedRecords": 0,
				"replay":          false,
				"receivedAt":      cursorTestNow.Format(time.RFC3339),
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/batches":
			m.mu.Lock()
			m.devicePosts++
			m.mu.Unlock()
			var body struct {
				BatchID string           `json:"batchId"`
				Records []map[string]any `json:"records"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
				"batchId":         body.BatchID,
				"status":          "accepted",
				"acceptedRecords": len(body.Records),
				"rejectedRecords": 0,
				"replay":          false,
				"receivedAt":      cursorTestNow.Format(time.RFC3339),
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/devices/tool-status":
			writeJSON(w, http.StatusOK, map[string]any{"accepted": true})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/capabilities":
			// The account-source protocol gate Enable probes before
			// reading the cursor credential.
			writeJSON(w, http.StatusOK, map[string]any{
				"features": []string{"account-sources"},
			})
		default:
			writeJSON(w, http.StatusOK, map[string]any{})
		}
	}))
	t.Cleanup(m.Server.Close)
	return m
}

// startConnectConfigMock serves the leaderboard connect-config endpoint
// for one fixed Config payload.
func startConnectConfigMock(t *testing.T, cfg Config) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/collector/connect" {
			t.Errorf("unexpected config path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	}))
	t.Cleanup(s.Close)
	return s
}

// runCursorConnect executes one connect.Run with the cursor wiring and
// the given confirmation, returning the result, captured output, state
// directory and fakes for further assertions.
func runCursorConnect(t *testing.T, tools []string, confirm func(string, io.Writer) (bool, error)) (Result, string, string, *fakeCursorAuth, *fakeCursorPull, *cursorToktrailMock) {
	t.Helper()
	stateDir := t.TempDir()
	homeDir := t.TempDir()

	toktrail := startCursorToktrailMock(t)
	cfgServer := startConnectConfigMock(t, Config{
		SchemaVersion: 1,
		ServerURL:     toktrail.URL,
		ApplicationID: "app-cursor-1",
		SubjectID:     cursorTestSubjectID,
		Tools:         tools,
		Days:          intPtr(30),
		ExpiresAt:     cursorTestNow.Add(24 * time.Hour).Format(time.RFC3339),
	})

	authFake := &fakeCursorAuth{}
	pullFake := &fakeCursorPull{events: cursorFixtureEvents()}
	out := &bytes.Buffer{}

	res, err := Run(context.Background(), Options{
		URL:             fmt.Sprintf("%s/api/collector/connect#%s", cfgServer.URL, strings.Repeat("9", 64)),
		StateDir:        stateDir,
		HomeDir:         homeDir,
		BinaryPath:      fakeCollectorBinary(t),
		HTTPClient:      cfgServer.Client(),
		SchedulerRunner: &mockRunner{},
		Now:             func() time.Time { return cursorTestNow },
		Out:             out,
		Cursor: &cursorsync.Options{
			Auth:   authFake,
			Verify: fakeCursorVerify,
			Pull:   pullFake.Pull,
			Now:    func() time.Time { return cursorTestNow },
		},
		CursorConfirm: confirm,
	})
	if err != nil {
		t.Fatalf("connect Run failed: %v", err)
	}
	return res, out.String(), stateDir, authFake, pullFake, toktrail
}

// TestConnectCursorIntegratedEnable verifies that authorizing Cursor
// through connect enables the account source directly — the injected
// first-time confirmation plus the injected authentication cover the
// whole flow, with no independent login step — while never creating a
// local file grant for it, and that the first sync pulls and uploads.
func TestConnectCursorIntegratedEnable(t *testing.T) {
	confirmCalls := 0
	confirm := func(notice string, w io.Writer) (bool, error) {
		confirmCalls++
		if notice != cursorsync.EnableNotice {
			t.Errorf("confirmation notice = %q, want cursorsync.EnableNotice", notice)
		}
		return true, nil
	}

	res, out, stateDir, authFake, pullFake, toktrail := runCursorConnect(t, []string{"Cursor"}, confirm)

	// The connect run itself succeeded and authorized exactly Cursor.
	if len(res.AuthorizedTools) != 1 || res.AuthorizedTools[0] != "Cursor" {
		t.Fatalf("authorized tools = %#v, want [Cursor]\nrun output:\n%s", res.AuthorizedTools, out)
	}
	if res.DeviceID != cursorTestDeviceID || res.SkippedBind {
		t.Fatalf("unexpected bind outcome: %+v", res)
	}
	// The website grant authorizes the first enable: no second local question.
	if confirmCalls != 0 {
		t.Fatalf("first-time confirmation calls = %d, want 0 (the website grant is the authorization)", confirmCalls)
	}
	if !strings.Contains(out, cursorsync.EnableNotice) {
		t.Fatalf("the consent notice must still be printed, output:\n%s", out)
	}

	// Direct enable: exactly one server enable call for the cursor
	// source type, authenticated with the bound device credentials.
	toktrail.mu.Lock()
	enableCalls, enableAuth, enableBody, srcPosts, srcRecords := toktrail.enableCalls, toktrail.enableAuth, toktrail.enableBodies, toktrail.srcBatchPosts, toktrail.srcRecords
	bindSecret := toktrail.bindSecret
	toktrail.mu.Unlock()
	if enableCalls != 1 {
		t.Fatalf("account-source enable calls = %d, want 1", enableCalls)
	}
	if len(enableAuth) != 1 || enableAuth[0] != "Bearer "+cursorTestDeviceID+"."+bindSecret {
		t.Fatalf("enable Authorization = %#v, want the bound device credentials", enableAuth)
	}
	if !strings.Contains(enableBody[0], protocol.SourceType) {
		t.Fatalf("enable body %q must name the cursor source type", enableBody[0])
	}

	// The permit exists and completed its first sync; it stores neither
	// the access token nor the account id (privacy invariant).
	license, ok, err := cursorsource.New(stateDir).Load()
	if err != nil || !ok {
		t.Fatalf("expected a cursor permit after the integrated enable, ok=%v err=%v", ok, err)
	}
	if license.SourceInstanceID != cursorTestSourceID {
		t.Fatalf("permit sourceInstanceId = %q, want %q", license.SourceInstanceID, cursorTestSourceID)
	}
	if license.Status != cursorsource.StatusActive {
		t.Fatalf("permit status = %q, want active after the first sync", license.Status)
	}
	if license.AccountMatchID != identity.MatchAccount(cursorTestAccountID) {
		t.Fatalf("permit accountMatchID = %q, want the digest of %q", license.AccountMatchID, cursorTestAccountID)
	}
	if license.PullWatermark == nil {
		t.Fatalf("permit must record the first pull watermark")
	}
	raw, rerr := os.ReadFile(cursorsource.New(stateDir).Path())
	if rerr != nil {
		t.Fatal(rerr)
	}
	for _, secret := range []string{cursorTestAccessToken, cursorTestAccountID, cursorTestSessionTok} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("cursor permit file leaked %q", secret)
		}
	}

	// The enable used the injected authentication (no separate login
	// step): the credential was read and verified through the fakes, and
	// the synthetic usage was pulled and uploaded as a source batch.
	// Exactly TWO credential reads, both inside the enable itself (the
	// pre-enable account verification and the first sync's verification);
	// the initial collection's cursor round runs drain-only over the
	// freshly enabled source (it refreshes the authorization and uploads
	// whatever the enable's bounded first sync left pending, but never
	// reads the credential and never pulls the upstream again), so the
	// enable's first sync is the run's ONLY upstream pull and only its
	// batch (2 records) is ever uploaded.
	if got := authFake.fetches.Load(); got != 2 {
		t.Fatalf("credential reads = %d, want exactly 2 (both inside the enable; the initial round is drain-only)", got)
	}
	if got := pullFake.calls.Load(); got != 1 {
		t.Fatalf("upstream pulls = %d, want exactly 1 (the enable's full-window first sync; the initial round is drain-only)", got)
	}
	if srcPosts != 1 || srcRecords != 2 {
		t.Fatalf("source-batch uploads = %d posts / %d records, want 1 post / 2 records (the enable's first sync only; no forced re-emission)", srcPosts, srcRecords)
	}
	if res.PeriodicResult.Cursor.ReemittedRecords != 0 {
		t.Fatalf("the initial cursor round must not re-emit after a fresh enable, got %+v", res.PeriodicResult.Cursor)
	}
	if res.PeriodicResult.Cursor.Skipped != "" || !res.PeriodicResult.Cursor.Ran {
		t.Fatalf("the initial cursor round completed and must not be skipped, got %+v", res.PeriodicResult.Cursor)
	}

	// No local grant is fabricated for the account-level source: the
	// grant store stays empty on a cursor-only authorization.
	cfg, err := grants.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Grants) != 0 {
		t.Fatalf("cursor must never create local file grants, got %#v", cfg.Grants)
	}

	// The initial collection reports the cursor round instead of the
	// misleading no-grants skip, and the run output never claims "no
	// sources active" for a cursor-only device.
	if res.PeriodicResult.NoGrants {
		t.Fatalf("a cursor-only device with a synced cursor source must not report NoGrants: %+v", res.PeriodicResult)
	}
	if !res.PeriodicResult.Cursor.Ran {
		t.Fatalf("the initial collection must run the cursor sync, got %+v", res.PeriodicResult.Cursor)
	}
	if !strings.Contains(out, "enabled (source configured, state=active)") {
		t.Fatalf("output must report the integrated enable, got:\n%s", out)
	}
	if !strings.Contains(out, "Cursor: the server confirmed 2 record(s).") {
		t.Fatalf("output must summarize the cursor round's confirmed records, got:\n%s", out)
	}
	if strings.Contains(out, "no tool directories detected locally; no sources active") {
		t.Fatalf("a cursor-only enable must not warn about inactive sources, got:\n%s", out)
	}
	if strings.Contains(out, "no enabled source grants; skipped") {
		t.Fatalf("a cursor-only enable must not print the no-grants skip, got:\n%s", out)
	}
}

// TestConnectCursorEnableFailureSkipsCursorAndKeepsOtherTools verifies that a
// FAILED first-time enable (here: the credential cannot be verified) is a
// clean, non-fatal skip for the OTHER tools while making the overall install
// explicitly incomplete: no permit and no server enable exist afterwards, and
// every other authorized tool keeps its full connect setup — grant, scheduler
// and initial collection. The run itself returns ErrSyncIncomplete naming the
// account source. No local confirmation is involved any more: the website grant
// authorizes the attempt, so a failure is reported as a failure.
func TestConnectCursorEnableFailureSkipsCursorAndKeepsOtherTools(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	// Codex exists locally (empty sessions directory); Cursor does not
	// map to any directory at all.
	codexDir := filepath.Join(homeDir, ".codex", "sessions")
	if err := os.MkdirAll(codexDir, 0o700); err != nil {
		t.Fatal(err)
	}

	toktrail := startCursorToktrailMock(t)
	cfgServer := startConnectConfigMock(t, Config{
		SchemaVersion: 1,
		ServerURL:     toktrail.URL,
		ApplicationID: "app-cursor-1",
		SubjectID:     cursorTestSubjectID,
		Tools:         []string{"Cursor", "Codex"},
		Days:          intPtr(30),
		ExpiresAt:     cursorTestNow.Add(24 * time.Hour).Format(time.RFC3339),
	})

	authFake := &fakeCursorAuth{}
	pullFake := &fakeCursorPull{events: cursorFixtureEvents()}
	out := &bytes.Buffer{}
	confirmCalls := 0

	runner := &mockRunner{}
	res, err := Run(context.Background(), Options{
		URL:             fmt.Sprintf("%s/api/collector/connect#%s", cfgServer.URL, strings.Repeat("8", 64)),
		StateDir:        stateDir,
		HomeDir:         homeDir,
		BinaryPath:      fakeCollectorBinary(t),
		HTTPClient:      cfgServer.Client(),
		SchedulerRunner: runner,
		Now:             func() time.Time { return cursorTestNow },
		Out:             out,
		Cursor: &cursorsync.Options{
			Auth: authFake,
			// Verification rejects the session, so the enable cannot finish.
			Verify: func(ctx context.Context, accessToken string) (api.VerifyResult, error) {
				return api.VerifyResult{}, errors.New("upstream rejected the session")
			},
			Pull: pullFake.Pull,
			Now:  func() time.Time { return cursorTestNow },
		},
		CursorConfirm: func(notice string, w io.Writer) (bool, error) {
			confirmCalls++
			return true, nil
		},
	})
	if err == nil {
		t.Fatalf("a failed cursor enable leaves the install explicitly incomplete; expected an error")
	}
	if !errors.Is(err, ErrSyncIncomplete) {
		t.Fatalf("the failure must surface as ErrSyncIncomplete, got: %v", err)
	}
	if !strings.Contains(err.Error(), "Cursor") {
		t.Fatalf("the incomplete error must name the account source: %v", err)
	}
	if confirmCalls != 0 {
		t.Fatalf("no local confirmation belongs on the first enable, got %d call(s)", confirmCalls)
	}

	// Nothing cursor-related reached the server or the usage API.
	if got := pullFake.calls.Load(); got != 0 {
		t.Fatalf("a failed enable must never pull usage, got %d pulls", got)
	}
	toktrail.mu.Lock()
	enableCalls, srcPosts := toktrail.enableCalls, toktrail.srcBatchPosts
	toktrail.mu.Unlock()
	if enableCalls != 0 || srcPosts != 0 {
		t.Fatalf("a declined confirmation must not enable or upload: enables=%d sourceBatches=%d", enableCalls, srcPosts)
	}
	if _, ok, lerr := cursorsource.New(stateDir).Load(); lerr != nil || ok {
		t.Fatalf("no cursor permit may exist after a decline, ok=%v err=%v", ok, lerr)
	}

	// The other tool keeps its full setup: authorized, granted,
	// scheduled, and collected by the initial run.
	if len(res.AuthorizedTools) != 1 || res.AuthorizedTools[0] != "Codex" {
		t.Fatalf("authorized tools = %#v, want [Codex]", res.AuthorizedTools)
	}
	cfg, err := grants.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Grants) != 1 || cfg.Grants[0].Source != "codex-jsonl" || filepath.Clean(cfg.Grants[0].Input) != filepath.Clean(codexDir) {
		t.Fatalf("the codex grant must survive the cursor decline, got %#v", cfg.Grants)
	}
	if len(runner.commands) == 0 {
		t.Fatalf("the scheduler must still be installed after a cursor decline")
	}
	if res.PeriodicResult.Grants != 1 || res.PeriodicResult.NoGrants {
		t.Fatalf("the initial collection must still run the codex grant, got %+v", res.PeriodicResult)
	}
	if res.PeriodicResult.Cursor.Ran {
		t.Fatalf("the cursor sync must not run after a decline, got %+v", res.PeriodicResult.Cursor)
	}
	if !strings.Contains(res.PeriodicResult.Cursor.Skipped, "no local cursor permit") {
		t.Fatalf("the cursor round must carry the no-permit skip reason, got %q", res.PeriodicResult.Cursor.Skipped)
	}
	if !strings.Contains(out.String(), "not enabled") {
		t.Fatalf("output must report the source as not enabled, got:\n%s", out)
	}
}

// TestConnectCursorFirstEnableIsHeadless pins the product rule the install flow
// depends on: the website's grant authorizes the first Cursor enable, so a run
// with NO terminal (the documented `curl | sh`, or any headless install) must
// complete instead of stopping to ask. A confirmer that would report a missing
// terminal is never consulted; the notice is still printed so the terminal
// states what is being read and uploaded.
func TestConnectCursorFirstEnableIsHeadless(t *testing.T) {
	confirmCalls := 0
	confirm := func(notice string, w io.Writer) (bool, error) {
		confirmCalls++
		return false, console.ErrNoInteractiveTerminal
	}

	stateDir := t.TempDir()
	homeDir := t.TempDir()
	toktrail := startCursorToktrailMock(t)
	cfgServer := startConnectConfigMock(t, Config{
		SchemaVersion: 1,
		ServerURL:     toktrail.URL,
		ApplicationID: "app-cursor-1",
		SubjectID:     cursorTestSubjectID,
		Tools:         []string{"Cursor"},
		Days:          intPtr(30),
		ExpiresAt:     cursorTestNow.Add(24 * time.Hour).Format(time.RFC3339),
	})
	authFake := &fakeCursorAuth{}
	pullFake := &fakeCursorPull{events: cursorFixtureEvents()}
	out := &bytes.Buffer{}
	_, err := Run(context.Background(), Options{
		URL:             fmt.Sprintf("%s/api/collector/connect#%s", cfgServer.URL, strings.Repeat("7", 64)),
		StateDir:        stateDir,
		HomeDir:         homeDir,
		BinaryPath:      fakeCollectorBinary(t),
		HTTPClient:      cfgServer.Client(),
		SchedulerRunner: &mockRunner{},
		Now:             func() time.Time { return cursorTestNow },
		Out:             out,
		Cursor: &cursorsync.Options{
			Auth:   authFake,
			Verify: fakeCursorVerify,
			Pull:   pullFake.Pull,
			Now:    func() time.Time { return cursorTestNow },
		},
		CursorConfirm: confirm,
	})
	if err != nil {
		t.Fatalf("a first enable must not need a terminal, got %v\n%s", err, out.String())
	}
	if confirmCalls != 0 {
		t.Fatalf("no local confirmation belongs on the first enable, got %d call(s)", confirmCalls)
	}
	outStr := out.String()
	if !strings.Contains(outStr, cursorsync.EnableNotice) {
		t.Fatalf("the consent notice must still be printed, got:\n%s", outStr)
	}
	if strings.Contains(outStr, "no interactive terminal was available") {
		t.Fatalf("a first enable must not report a missing terminal, got:\n%s", outStr)
	}
	// The enable really happened: a permit exists and usage was pulled.
	if _, ok, loadErr := cursorsource.New(stateDir).Load(); loadErr != nil || !ok {
		t.Fatalf("the permit must exist after a headless first enable (ok=%t err=%v)", ok, loadErr)
	}
	if pullFake.calls.Load() == 0 {
		t.Fatal("the first sync must run during a headless first enable")
	}
}

// A failed enable must say WHICH step stopped it. "The local enable did not
// complete" was all a Windows user saw while the actual cause (an unreadable
// Cursor login, a scope that excludes Cursor, a server refusal) was known to the
// code but not to them.
func TestConnectNamesTheCursorEnableFailureClass(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startCursorBacklogMock(t)
	cfg := startSyncConfigMock(t, mock.URL, []string{"Cursor"}, nil)
	ticket := strings.Repeat("7", 64)
	seedFirstEnableConnect(t, stateDir, mock, cfg, ticket)

	wiring := budgetCursorWiring(&cursorBacklogPull{events: cursorBulkEvents(1)}, 5)
	wiring.Verify = func(ctx context.Context, accessToken string) (api.VerifyResult, error) {
		// An unreadable login must not be mistaken for an absent tool.
		return api.VerifyResult{}, fmt.Errorf("verify: %w", autherr.ErrPermission)
	}
	out := &bytes.Buffer{}
	res, err := runCursorConnectWithOptionsOut(t, cfg, stateDir, homeDir, ticket, Options{
		Cursor: wiring,
	}, out)
	if err == nil || !isErrSyncIncomplete(err) {
		t.Fatalf("a credential failure must leave the run incomplete, got %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "Cursor login could not be used") {
		t.Fatalf("the failure class must be named, got:\n%s", text)
	}
	if !strings.Contains(text, "the Cursor state is not readable with the current permissions") {
		t.Fatalf("the closed-set credential reason must appear, got:\n%s", text)
	}
	if strings.Contains(text, "an unexpected error occurred") {
		t.Fatalf("a known cause must never read as an unexpected error, got:\n%s", text)
	}
	if res.Sync.Collection.Cursor.Outcome != cursorsync.RoundNoPermit {
		t.Fatalf("outcome = %q, want no_permit", res.Sync.Collection.Cursor.Outcome)
	}
}
