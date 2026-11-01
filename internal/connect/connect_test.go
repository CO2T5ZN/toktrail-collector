package connect

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
	"reflect"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncclient"
)

type mockRunner struct {
	commands []string
}

func (m *mockRunner) Run(name string, args ...string) error {
	m.commands = append(m.commands, name+" "+strings.Join(args, " "))
	return nil
}

// toolStatusPost records one POST to /v1/devices/tool-status for assertions.
type toolStatusPost struct {
	Auth     string
	Revision string
	Body     []byte
}

func (p toolStatusPost) statuses(t *testing.T) []syncclient.ToolStatus {
	t.Helper()
	var payload struct {
		Statuses []syncclient.ToolStatus `json:"statuses"`
	}
	if err := json.Unmarshal(p.Body, &payload); err != nil {
		t.Fatalf("decode tool-status payload: %v", err)
	}
	return payload.Statuses
}

// fakeCollectorBinary writes a dummy executable for scheduler installation.
func fakeCollectorBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "toktrail")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func intPtr(n int) *int { return &n }

func TestConnectHappyPathAndRetry(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()

	// Create local mock directories for tools
	codexDir := filepath.Join(homeDir, ".codex", "sessions")
	if err := os.MkdirAll(codexDir, 0o700); err != nil {
		t.Fatal(err)
	}

	validTicket := strings.Repeat("a", 64)

	// Mock toktrail-server for bind & collection
	var bindCalls int
	var bindSecret string
	var statusPosts []toolStatusPost
	toktrailServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/devices/bind":
			bindCalls++
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			if req["ticket"] == "" {
				t.Fatalf("missing ticket in bind req")
			}
			// The collector generates the device secret client-side and
			// submits it with the bind request; capture it to verify the
			// tool-status Authorization header.
			if s, _ := req["deviceSecret"].(string); s != "" {
				bindSecret = s
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device": map[string]any{
					"deviceId":          "dev-test-1",
					"applicationId":     req["applicationId"],
					"externalSubjectId": req["externalSubjectId"],
					"deviceName":        req["deviceName"],
					"platform":          req["platform"],
					"consentRevision":   1,
					"boundAt":           time.Now().UTC().Format(time.RFC3339),
				},
			})
		case "/v1/devices/self":
			// preflightSelf requires the device envelope under "device".
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device": map[string]any{
					"deviceId":         "dev-test-1",
					"consentRevision":  1,
					"uploadAuthorized": true,
					"publicAuthorized": true,
					"revoked":          false,
				},
			})
		case "/v1/devices/tool-status":
			body, _ := io.ReadAll(r.Body)
			statusPosts = append(statusPosts, toolStatusPost{
				Auth:     r.Header.Get("Authorization"),
				Revision: r.Header.Get("X-Consent-Revision"),
				Body:     body,
			})
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{})
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
	defer toktrailServer.Close()

	// Mock leaderboard connect endpoint
	leaderboardServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/collector/connect" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			t.Fatalf("unexpected Authorization header: %s", auth)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(Config{
			SchemaVersion: 1,
			ServerURL:     toktrailServer.URL,
			ApplicationID: "app-test",
			SubjectID:     "sub-test",
			Tools:         []string{"Codex", "Claude Code", "NonExistentTool"},
			Days:          intPtr(30),
			ExpiresAt:     time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		})
	}))
	defer leaderboardServer.Close()

	binDir := t.TempDir()
	fakeBinary := filepath.Join(binDir, "toktrail")
	if err := os.WriteFile(fakeBinary, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	runner := &mockRunner{}
	connectURL := fmt.Sprintf("%s/api/collector/connect#%s", leaderboardServer.URL, validTicket)

	// 1. First run: should bind device, authorize Codex (Claude Code doesn't exist locally), install service, run initial collection
	res, err := Run(context.Background(), Options{
		URL:             connectURL,
		StateDir:        stateDir,
		HomeDir:         homeDir,
		BinaryPath:      fakeBinary,
		HTTPClient:      leaderboardServer.Client(),
		SchedulerRunner: runner,
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if res.DeviceID != "dev-test-1" {
		t.Fatalf("expected deviceId dev-test-1, got %s", res.DeviceID)
	}
	if res.SkippedBind {
		t.Fatalf("expected first run to not skip bind")
	}
	if bindCalls != 1 {
		t.Fatalf("expected 1 bind call, got %d", bindCalls)
	}
	if len(res.AuthorizedTools) != 1 || res.AuthorizedTools[0] != "Codex" {
		t.Fatalf("expected only Codex authorized, got %#v", res.AuthorizedTools)
	}

	// Verify state in stateDir:
	store := statedir.New(stateDir)
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.ConnectReceiptHash == "" {
		t.Fatalf("expected ConnectReceiptHash to be saved")
	}
	if st.PendingConnectReceiptHash != "" {
		t.Fatalf("expected PendingConnectReceiptHash to be cleared")
	}

	// Verify grants in stateDir:
	grantStore := grants.New(stateDir)
	enabled, err := grantStore.Enabled()
	if err != nil {
		t.Fatal(err)
	}
	if len(enabled) != 1 || enabled[0].Source != "codex-jsonl" {
		t.Fatalf("expected only codex-jsonl grant enabled, got %#v", enabled)
	}

	// 2. Retry run with same connect URL: bind MUST be skipped!
	res2, err := Run(context.Background(), Options{
		URL:             connectURL,
		StateDir:        stateDir,
		HomeDir:         homeDir,
		BinaryPath:      fakeBinary,
		HTTPClient:      leaderboardServer.Client(),
		SchedulerRunner: runner,
	})
	if err != nil {
		t.Fatalf("retry Run failed: %v", err)
	}
	if !res2.SkippedBind {
		t.Fatalf("expected retry to skip bind, but SkippedBind was false")
	}
	if bindCalls != 1 {
		t.Fatalf("expected bindCalls to still be 1 after retry, got %d", bindCalls)
	}

	// 3. New connect with DIFFERENT ticket/URL: bind MUST NOT be skipped!
	differentTicket := strings.Repeat("f", 64)
	diffConnectURL := fmt.Sprintf("%s/api/collector/connect#%s", leaderboardServer.URL, differentTicket)
	res3, err := Run(context.Background(), Options{
		URL:             diffConnectURL,
		StateDir:        stateDir,
		HomeDir:         homeDir,
		BinaryPath:      fakeBinary,
		HTTPClient:      leaderboardServer.Client(),
		SchedulerRunner: runner,
	})
	if err != nil {
		t.Fatalf("run with different ticket failed: %v", err)
	}
	if res3.SkippedBind {
		t.Fatalf("expected different ticket to not skip bind")
	}
	if bindCalls != 2 {
		t.Fatalf("expected 2 bind calls, got %d", bindCalls)
	}

	// Tool-status reporting: connect reports probe-only statuses for tools
	// it could NOT activate — Claude Code (no default directory) and
	// NonExistentTool (unsupported). Codex is activated by connect, so it
	// is reported by the collection flow (synced / no_new_records), never
	// with a probe status.
	wantProbe := []syncclient.ToolStatus{
		{Tool: "Claude Code", Status: "not_detected", Detail: "default directory not found"},
		{Tool: "NonExistentTool", Status: "unsupported", Detail: "unsupported tool"},
	}
	if len(statusPosts) == 0 {
		t.Fatalf("expected tool-status POSTs, got none")
	}
	// The first POST of every run is connect's probe report (lockedWork
	// finishes before the initial collection starts).
	if got := statusPosts[0].statuses(t); !reflect.DeepEqual(got, wantProbe) {
		t.Fatalf("first tool-status POST = %#v, want exact probe payload %#v", got, wantProbe)
	}
	probeReports := 0
	for _, p := range statusPosts {
		if reflect.DeepEqual(p.statuses(t), wantProbe) {
			probeReports++
		}
		if p.Auth != "Bearer dev-test-1."+bindSecret {
			t.Fatalf("tool-status Authorization = %q, want Bearer dev-test-1.<bound device secret>", p.Auth)
		}
		if p.Revision != "1" {
			t.Fatalf("tool-status X-Consent-Revision = %q, want 1", p.Revision)
		}
		for _, s := range p.statuses(t) {
			if (s.Tool == "Claude Code" || s.Tool == "NonExistentTool") &&
				(s.Status == "synced" || s.Status == "no_new_records") {
				t.Fatalf("connect must never report collection statuses for probed tools: %#v", s)
			}
		}
	}
	if probeReports != 3 {
		t.Fatalf("expected exactly one probe report per run (3 runs), got %d of %d POSTs", probeReports, len(statusPosts))
	}
}

func TestConnectCrashRecovery(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()

	validTicket := strings.Repeat("b", 64)
	strippedURL := "http://127.0.0.1:9999/api/collector/connect"
	fingerprint := computeReceiptFingerprint(validTicket, strippedURL)

	// Simulate crash or failed bind: device has PendingConnectReceiptHash, but NO atomic proof.
	// shouldSkipBind MUST be false to prevent false skips on rerun!
	store := statedir.New(stateDir)
	if err := store.Save(statedir.DeviceState{
		DeviceID:                  "dev-crashed-1",
		ServerURL:                 "http://127.0.0.1:8888",
		ApplicationID:             "app-1",
		ExternalSubjectID:         "sub-1",
		ConsentRevision:           1,
		PendingConnectReceiptHash: fingerprint,
	}); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		SchemaVersion: 1,
		ServerURL:     "http://127.0.0.1:8888",
		ApplicationID: "app-1",
		SubjectID:     "sub-1",
		Tools:         []string{"Codex"},
		Days:          intPtr(30),
		ExpiresAt:     time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
	}

	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	bindFp := "some-bind-fp"
	if shouldSkipBind(st, fingerprint, bindFp, cfg) {
		t.Fatalf("shouldSkipBind should be false for pending receipt without atomic proof")
	}

	// Now set atomic proof via ConnectReceiptHash
	st.ConnectReceiptHash = fingerprint
	st.PendingConnectReceiptHash = ""
	if !shouldSkipBind(st, fingerprint, bindFp, cfg) {
		t.Fatalf("shouldSkipBind should be true when ConnectReceiptHash matches")
	}

	// Or atomic proof via LastBindFingerprint
	st.ConnectReceiptHash = ""
	st.LastBindFingerprint = bindFp
	if !shouldSkipBind(st, fingerprint, bindFp, cfg) {
		t.Fatalf("shouldSkipBind should be true when LastBindFingerprint matches")
	}
	_ = homeDir
}

func TestConnectHistoryCutoffFollowsCurrentAuthorization(t *testing.T) {
	fixedNow := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

	// setup builds one mock pair per scenario; the captured `days`
	// variable lets the connect config change between runs, exactly like
	// a reissued connect link with a different history window.
	setup := func(t *testing.T) (runTicket func(string) statedir.DeviceState, setDays func(int)) {
		t.Helper()
		stateDir := t.TempDir()
		homeDir := t.TempDir()
		codexDir := filepath.Join(homeDir, ".codex", "sessions")
		if err := os.MkdirAll(codexDir, 0o700); err != nil {
			t.Fatal(err)
		}

		days := 90
		toktrailServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/devices/bind":
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"device": map[string]any{
						"deviceId":          "dev-cutoff-1",
						"applicationId":     "app-1",
						"externalSubjectId": "sub-1",
						"deviceName":        "dev-name",
						"platform":          "test-platform",
						"consentRevision":   1,
						"boundAt":           fixedNow.Format(time.RFC3339),
					},
				})
			case "/v1/devices/self":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"device": map[string]any{
						"deviceId":         "dev-cutoff-1",
						"consentRevision":  1,
						"uploadAuthorized": true,
						"revoked":          false,
					},
				})
			default:
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{})
			}
		}))
		t.Cleanup(toktrailServer.Close)

		connectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			var requestedDays *int
			if days != 0 {
				requestedDays = intPtr(days)
			}
			_ = json.NewEncoder(w).Encode(Config{
				SchemaVersion: 1,
				ServerURL:     toktrailServer.URL,
				ApplicationID: "app-1",
				SubjectID:     "sub-1",
				Tools:         []string{"Codex"},
				Days:          requestedDays,
				ExpiresAt:     fixedNow.Add(24 * time.Hour).Format(time.RFC3339),
			})
		}))
		t.Cleanup(connectServer.Close)

		runTicket = func(ticket string) statedir.DeviceState {
			url := fmt.Sprintf("%s/api/collector/connect#%s", connectServer.URL, ticket)
			if _, err := Run(context.Background(), Options{
				URL:             url,
				StateDir:        stateDir,
				HomeDir:         homeDir,
				BinaryPath:      fakeCollectorBinary(t),
				HTTPClient:      connectServer.Client(),
				SchedulerRunner: &mockRunner{},
				Now:             func() time.Time { return fixedNow },
			}); err != nil {
				t.Fatalf("connect Run failed: %v", err)
			}
			st, err := statedir.New(stateDir).Load()
			if err != nil {
				t.Fatal(err)
			}
			return st
		}
		setDays = func(d int) { days = d }
		return runTicket, setDays
	}

	assertWindow := func(t *testing.T, st statedir.DeviceState, want time.Time, wantDays int) {
		t.Helper()
		if st.HistoryFrom == nil || !st.HistoryFrom.Equal(want) || st.HistoryDays != wantDays {
			t.Fatalf("history window = (HistoryFrom=%v, HistoryDays=%d), want (%v, %d)",
				st.HistoryFrom, st.HistoryDays, want, wantDays)
		}
	}

	t.Run("same_receipt_retry_keeps_pinned_cutoff", func(t *testing.T) {
		runTicket, setDays := setup(t)
		cutoff90 := fixedNow.AddDate(0, 0, -90)

		st := runTicket(strings.Repeat("a", 64))
		assertWindow(t, st, cutoff90, 90)

		// Server narrows the window on the SAME link: a retry is the same
		// authorization being re-presented, and re-deriving the now-based
		// cutoff on every retry would drift the window forward run by
		// run. The pinned cutoff stays fixed.
		setDays(7)
		st = runTicket(strings.Repeat("a", 64))
		assertWindow(t, st, cutoff90, 90)
	})

	t.Run("rebind_with_narrower_window_narrows", func(t *testing.T) {
		runTicket, setDays := setup(t)
		cutoff90 := fixedNow.AddDate(0, 0, -90)
		cutoff7 := fixedNow.AddDate(0, 0, -7)

		st := runTicket(strings.Repeat("a", 64))
		assertWindow(t, st, cutoff90, 90)

		// A new link (new receipt → rebind) carries the user's CURRENT
		// authorization: a narrower window replaces the wider one.
		// Records already collected that fall before the new cutoff are
		// quarantined by the pipeline (before_history_from), never
		// deleted.
		setDays(7)
		st = runTicket(strings.Repeat("b", 64)) // new ticket → rebind
		assertWindow(t, st, cutoff7, 7)
	})

	t.Run("same_receipt_unlimited_keeps_fixed_window", func(t *testing.T) {
		runTicket, setDays := setup(t)
		cutoff30 := fixedNow.AddDate(0, 0, -30)

		setDays(30)
		assertWindow(t, runTicket(strings.Repeat("a", 64)), cutoff30, 30)

		// An explicit null on the SAME receipt must not clear the pinned
		// window: same-receipt retries never re-derive the cutoff (see
		// same_receipt_retry_keeps_pinned_cutoff).
		setDays(0) // encode an explicit JSON null
		st := runTicket(strings.Repeat("a", 64))
		assertWindow(t, st, cutoff30, 30)
	})

	t.Run("new_receipt_unlimited_clears_window", func(t *testing.T) {
		runTicket, setDays := setup(t)
		cutoff30 := fixedNow.AddDate(0, 0, -30)

		setDays(30)
		assertWindow(t, runTicket(strings.Repeat("a", 64)), cutoff30, 30)

		setDays(0)                               // encode an explicit JSON null
		st := runTicket(strings.Repeat("b", 64)) // new receipt → rebind
		if st.HistoryFrom != nil || st.HistoryDays != 0 {
			t.Fatalf("expected unlimited history from the new authorization, got from=%v days=%d", st.HistoryFrom, st.HistoryDays)
		}
	})

	t.Run("rebind_with_wider_window_widens_cutoff", func(t *testing.T) {
		runTicket, setDays := setup(t)
		cutoff7 := fixedNow.AddDate(0, 0, -7)
		cutoff90 := fixedNow.AddDate(0, 0, -90)

		setDays(7)
		st := runTicket(strings.Repeat("a", 64))
		assertWindow(t, st, cutoff7, 7)

		setDays(90)
		st = runTicket(strings.Repeat("b", 64)) // new ticket → rebind
		assertWindow(t, st, cutoff90, 90)
	})
}

func TestApplyHistoryCutoffRules(t *testing.T) {
	day := func(offset int) *time.Time {
		tt := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC).AddDate(0, 0, offset)
		return &tt
	}

	// applyHistoryCutoff pins the window to THIS authorization: the
	// current cutoff replaces whatever was stored, narrowing included.
	// The same-receipt "keep fixed" behavior lives in Run's receipt
	// logic, not in this setter.

	t.Run("no_current_cutoff_adopts_any_cutoff", func(t *testing.T) {
		st := statedir.DeviceState{}
		applyHistoryCutoff(&st, day(-30), 30)
		if st.HistoryFrom == nil || !st.HistoryFrom.Equal(*day(-30)) || st.HistoryDays != 30 {
			t.Fatalf("got (HistoryFrom=%v, HistoryDays=%d)", st.HistoryFrom, st.HistoryDays)
		}
	})

	t.Run("zero_value_history_from_is_replaced", func(t *testing.T) {
		st := statedir.DeviceState{HistoryFrom: &time.Time{}, HistoryDays: 0}
		applyHistoryCutoff(&st, day(-7), 7)
		if st.HistoryFrom == nil || !st.HistoryFrom.Equal(*day(-7)) || st.HistoryDays != 7 {
			t.Fatalf("got (HistoryFrom=%v, HistoryDays=%d)", st.HistoryFrom, st.HistoryDays)
		}
	})

	t.Run("earlier_cutoff_widens", func(t *testing.T) {
		st := statedir.DeviceState{HistoryFrom: day(-7), HistoryDays: 7}
		applyHistoryCutoff(&st, day(-90), 90)
		if !st.HistoryFrom.Equal(*day(-90)) || st.HistoryDays != 90 {
			t.Fatalf("got (HistoryFrom=%v, HistoryDays=%d)", st.HistoryFrom, st.HistoryDays)
		}
	})

	t.Run("later_cutoff_narrows_to_current_authorization", func(t *testing.T) {
		// The user's current consent governs: a re-issued authorization
		// with a narrower window replaces the wider one.
		st := statedir.DeviceState{HistoryFrom: day(-90), HistoryDays: 90}
		applyHistoryCutoff(&st, day(-7), 7)
		if !st.HistoryFrom.Equal(*day(-7)) || st.HistoryDays != 7 {
			t.Fatalf("cutoff must follow the current authorization; got (HistoryFrom=%v, HistoryDays=%d)", st.HistoryFrom, st.HistoryDays)
		}
	})

	t.Run("equal_cutoff_keeps_days", func(t *testing.T) {
		st := statedir.DeviceState{HistoryFrom: day(-30), HistoryDays: 30}
		applyHistoryCutoff(&st, day(-30), 30)
		if !st.HistoryFrom.Equal(*day(-30)) || st.HistoryDays != 30 {
			t.Fatalf("got (HistoryFrom=%v, HistoryDays=%d)", st.HistoryFrom, st.HistoryDays)
		}
	})

	t.Run("nil_cutoff_means_unlimited", func(t *testing.T) {
		st := statedir.DeviceState{HistoryFrom: day(-30), HistoryDays: 30}
		applyHistoryCutoff(&st, nil, 0)
		if st.HistoryFrom != nil || st.HistoryDays != 0 {
			t.Fatalf("nil cutoff must clear the window; got (HistoryFrom=%v, HistoryDays=%d)", st.HistoryFrom, st.HistoryDays)
		}
	})

	t.Run("cutoff_and_days_replace_together", func(t *testing.T) {
		// Both fields always reflect the SAME authorization; there is no
		// widowed widest-days tracking anymore.
		st := statedir.DeviceState{HistoryFrom: day(-7), HistoryDays: 7}
		applyHistoryCutoff(&st, day(-3), 90)
		if !st.HistoryFrom.Equal(*day(-3)) || st.HistoryDays != 90 {
			t.Fatalf("got (HistoryFrom=%v, HistoryDays=%d)", st.HistoryFrom, st.HistoryDays)
		}
	})
}

func TestConnectSecurityAndValidation(t *testing.T) {
	validTicket := strings.Repeat("c", 64)
	validURL := "https://leaderboard.example.com/api/collector/connect#" + validTicket

	// Test URL parsing
	t.Run("missing_fragment", func(t *testing.T) {
		_, _, err := parseAndValidateConnectURL("https://example.com/connect")
		if err == nil || !strings.Contains(err.Error(), "missing connect ticket") {
			t.Fatalf("expected missing ticket error, got %v", err)
		}
	})

	t.Run("invalid_ticket_length", func(t *testing.T) {
		_, _, err := parseAndValidateConnectURL("https://example.com/connect#1234")
		if err == nil || !strings.Contains(err.Error(), "must be 64-character hex") {
			t.Fatalf("expected ticket length error, got %v", err)
		}
	})

	t.Run("non_hex_ticket", func(t *testing.T) {
		nonHex := strings.Repeat("z", 64)
		_, _, err := parseAndValidateConnectURL("https://example.com/connect#" + nonHex)
		if err == nil || !strings.Contains(err.Error(), "must be 64-character hex") {
			t.Fatalf("expected hex ticket error, got %v", err)
		}
	})

	t.Run("insecure_remote_http", func(t *testing.T) {
		_, _, err := parseAndValidateConnectURL("http://example.com/connect#" + validTicket)
		if err == nil || !strings.Contains(err.Error(), "only permitted for loopback") {
			t.Fatalf("expected loopback error for http, got %v", err)
		}
	})

	t.Run("loopback_http_allowed", func(t *testing.T) {
		for _, host := range []string{"127.0.0.1", "localhost", "::1"} {
			u, ticket, err := parseAndValidateConnectURL(fmt.Sprintf("http://%s:8080/connect#%s", host, validTicket))
			if err != nil {
				t.Fatalf("expected loopback http to succeed for %s, got %v", host, err)
			}
			if ticket != validTicket {
				t.Fatalf("unexpected ticket: %s", ticket)
			}
			if strings.Contains(u, "#") {
				t.Fatalf("stripped URL must not contain fragment: %s", u)
			}
		}
	})

	t.Run("userinfo_rejected", func(t *testing.T) {
		_, _, err := parseAndValidateConnectURL("https://user:pass@example.com/connect#" + validTicket)
		if err == nil || !strings.Contains(err.Error(), "userinfo") {
			t.Fatalf("expected userinfo rejection, got %v", err)
		}
	})

	t.Run("query_rejected", func(t *testing.T) {
		_, _, err := parseAndValidateConnectURL("https://example.com/connect?token=123#" + validTicket)
		if err == nil || !strings.Contains(err.Error(), "query parameters") {
			t.Fatalf("expected query rejection, got %v", err)
		}
	})

	t.Run("no_ticket_leak_in_errors", func(t *testing.T) {
		testErr := fmt.Errorf("connection to %s failed: secret is %s and %s", validURL, validTicket, strings.ToUpper(validTicket))
		sanitized := sanitizeError(testErr, validTicket)
		if strings.Contains(strings.ToLower(sanitized.Error()), strings.ToLower(validTicket)) {
			t.Fatalf("sanitized error leaked ticket in any case: %s", sanitized.Error())
		}
		if strings.Contains(sanitized.Error(), validURL) {
			t.Fatalf("sanitized error leaked the URL: %s", sanitized.Error())
		}
		if !errors.Is(sanitized, testErr) {
			t.Fatal("sanitized error lost the errors.Is chain")
		}
	})
}

func TestConnectConfigValidation(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	validTicket := strings.Repeat("d", 64)

	makeServer := func(handler http.HandlerFunc) *httptest.Server {
		return httptest.NewServer(handler)
	}

	t.Run("redirect_rejected", func(t *testing.T) {
		s := makeServer(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/other", http.StatusFound)
		})
		defer s.Close()
		_, err := fetchConnectConfig(context.Background(), s.Client(), s.URL, validTicket, now)
		if err == nil || !strings.Contains(err.Error(), "redirects are not allowed") {
			t.Fatalf("expected redirect error, got %v", err)
		}
	})

	t.Run("schema_version_mismatch", func(t *testing.T) {
		s := makeServer(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 2})
		})
		defer s.Close()
		_, err := fetchConnectConfig(context.Background(), s.Client(), s.URL, validTicket, now)
		if err == nil || !strings.Contains(err.Error(), "unsupported connect schemaVersion") {
			t.Fatalf("expected schemaVersion error, got %v", err)
		}
	})

	t.Run("expired_expiresAt", func(t *testing.T) {
		s := makeServer(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(Config{
				SchemaVersion: 1,
				ServerURL:     "http://localhost:8080",
				ApplicationID: "app-1",
				SubjectID:     "sub-1",
				Tools:         []string{"Codex"},
				Days:          intPtr(30),
				ExpiresAt:     now.Add(-1 * time.Hour).Format(time.RFC3339),
			})
		})
		defer s.Close()
		_, err := fetchConnectConfig(context.Background(), s.Client(), s.URL, validTicket, now)
		if err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("expected expired error, got %v", err)
		}
	})

	t.Run("null_days_all_history", func(t *testing.T) {
		s := makeServer(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(Config{
				SchemaVersion: 1,
				ServerURL:     "http://localhost:8080",
				ApplicationID: "app-1",
				SubjectID:     "sub-1",
				Tools:         []string{"Codex"},
				Days:          nil,
				ExpiresAt:     now.Add(1 * time.Hour).Format(time.RFC3339),
			})
		})
		defer s.Close()
		cfg, err := fetchConnectConfig(context.Background(), s.Client(), s.URL, validTicket, now)
		if err != nil {
			t.Fatalf("expected null days to be accepted, got %v", err)
		}
		if cfg.Days != nil {
			t.Fatalf("days should remain nil for unlimited history, got %v", *cfg.Days)
		}
	})

	t.Run("missing_days_rejected", func(t *testing.T) {
		s := makeServer(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 1, "serverUrl": "http://localhost:8080",
				"applicationId": "app-1", "subjectId": "sub-1",
				"tools": []string{"Codex"}, "expiresAt": now.Add(time.Hour).Format(time.RFC3339),
			})
		})
		defer s.Close()
		_, err := fetchConnectConfig(context.Background(), s.Client(), s.URL, validTicket, now)
		if err == nil || !strings.Contains(err.Error(), "missing days") {
			t.Fatalf("expected missing days error, got %v", err)
		}
	})

	t.Run("invalid_days", func(t *testing.T) {
		s := makeServer(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(Config{
				SchemaVersion: 1,
				ServerURL:     "http://localhost:8080",
				ApplicationID: "app-1",
				SubjectID:     "sub-1",
				Tools:         []string{"Codex"},
				Days:          intPtr(15), // must be 7, 30, or 90
				ExpiresAt:     now.Add(1 * time.Hour).Format(time.RFC3339),
			})
		})
		defer s.Close()
		_, err := fetchConnectConfig(context.Background(), s.Client(), s.URL, validTicket, now)
		if err == nil || !strings.Contains(err.Error(), "invalid days") {
			t.Fatalf("expected invalid days error, got %v", err)
		}
	})

	t.Run("insecure_server_url", func(t *testing.T) {
		s := makeServer(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(Config{
				SchemaVersion: 1,
				ServerURL:     "http://insecure-remote.example.com",
				ApplicationID: "app-1",
				SubjectID:     "sub-1",
				Tools:         []string{"Codex"},
				Days:          intPtr(7),
				ExpiresAt:     now.Add(1 * time.Hour).Format(time.RFC3339),
			})
		})
		defer s.Close()
		_, err := fetchConnectConfig(context.Background(), s.Client(), s.URL, validTicket, now)
		if err == nil || !strings.Contains(err.Error(), "serverUrl must use HTTPS") {
			t.Fatalf("expected insecure serverUrl error, got %v", err)
		}
	})
}

func TestConnectLockContention(t *testing.T) {
	stateDir := t.TempDir()
	validTicket := strings.Repeat("e", 64)

	leaderboardServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Config{
			SchemaVersion: 1,
			ServerURL:     "http://localhost:8080",
			ApplicationID: "app-1",
			SubjectID:     "sub-1",
			Tools:         []string{"Codex"},
			Days:          intPtr(7),
			ExpiresAt:     time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		})
	}))
	defer leaderboardServer.Close()

	// Acquire lock beforehand to simulate contention
	lock, err := runlock.Acquire(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()

	connectURL := fmt.Sprintf("%s/api/collector/connect#%s", leaderboardServer.URL, validTicket)
	_, err = Run(context.Background(), Options{
		URL:        connectURL,
		StateDir:   stateDir,
		HTTPClient: leaderboardServer.Client(),
	})
	if !errors.Is(err, runlock.ErrBusy) {
		t.Fatalf("expected runlock.ErrBusy on locked stateDir, got %v", err)
	}
}

func TestConnectToolStatusReportFailures(t *testing.T) {
	validTicket := strings.Repeat("d", 64)

	// run executes one full connect Run against a toktrail mock whose
	// tool-status endpoint delegates to toolStatusHandler. cfg.Tools
	// contains only an unsupported tool, so connect always has a probe
	// status to report.
	run := func(t *testing.T, toolStatusHandler http.HandlerFunc) error {
		t.Helper()
		stateDir := t.TempDir()
		homeDir := t.TempDir()

		mux := http.NewServeMux()
		mux.HandleFunc("/v1/devices/bind", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device": map[string]any{
					"deviceId":          "dev-status-1",
					"applicationId":     "app-1",
					"externalSubjectId": "sub-1",
					"deviceName":        "dev-name",
					"platform":          "test-platform",
					"consentRevision":   1,
					"boundAt":           time.Now().UTC().Format(time.RFC3339),
				},
			})
		})
		mux.HandleFunc("/v1/devices/self", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device": map[string]any{
					"deviceId":         "dev-status-1",
					"consentRevision":  1,
					"uploadAuthorized": true,
					"revoked":          false,
				},
			})
		})
		mux.Handle("/v1/devices/tool-status", toolStatusHandler)
		toktrailServer := httptest.NewServer(mux)
		t.Cleanup(toktrailServer.Close)

		connectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(Config{
				SchemaVersion: 1,
				ServerURL:     toktrailServer.URL,
				ApplicationID: "app-1",
				SubjectID:     "sub-1",
				Tools:         []string{"NonExistentTool"},
				Days:          intPtr(30),
				ExpiresAt:     time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
			})
		}))
		t.Cleanup(connectServer.Close)

		_, err := Run(context.Background(), Options{
			URL:             fmt.Sprintf("%s/api/collector/connect#%s", connectServer.URL, validTicket),
			StateDir:        stateDir,
			HomeDir:         homeDir,
			BinaryPath:      fakeCollectorBinary(t),
			HTTPClient:      connectServer.Client(),
			SchedulerRunner: &mockRunner{},
		})
		return err
	}

	t.Run("server_error_surfaces", func(t *testing.T) {
		var postSeen bool
		err := run(t, func(w http.ResponseWriter, r *http.Request) {
			postSeen = true
			w.WriteHeader(http.StatusInternalServerError)
			// The ticket embedded in the server error must never reach
			// the user-visible error message.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"code":    "internal_error",
					"message": "boom " + validTicket,
				},
			})
		})
		if !postSeen {
			t.Fatalf("expected a tool-status POST")
		}
		if err == nil {
			t.Fatalf("expected Run to fail when the tool-status report fails")
		}
		if !strings.Contains(err.Error(), "report tool statuses failed") {
			t.Fatalf("error should mention the failed report: %v", err)
		}
		if strings.Contains(err.Error(), validTicket) {
			t.Fatalf("error must redact the connect ticket: %v", err)
		}
		// The syncclient now strips untrusted server free text before it
		// reaches this layer, so the ticket is absent outright rather
		// than replaced with a marker; absence is the security property.
	})

	t.Run("undeployed_endpoint_404_tolerated", func(t *testing.T) {
		var postSeen bool
		err := run(t, func(w http.ResponseWriter, r *http.Request) {
			postSeen = true
			w.WriteHeader(http.StatusNotFound)
		})
		if !postSeen {
			t.Fatalf("expected a tool-status POST attempt")
		}
		if err != nil {
			t.Fatalf("404 from an older server must be tolerated, got: %v", err)
		}
	})

	t.Run("undeployed_endpoint_405_tolerated", func(t *testing.T) {
		var postSeen bool
		err := run(t, func(w http.ResponseWriter, r *http.Request) {
			postSeen = true
			w.WriteHeader(http.StatusMethodNotAllowed)
		})
		if !postSeen {
			t.Fatalf("expected a tool-status POST attempt")
		}
		if err != nil {
			t.Fatalf("405 from an older server must be tolerated, got: %v", err)
		}
	})
}
