package main

// CLI-level coverage for the §6.5 stable JSON result (--json on
// periodic and connect): stdout carries EXACTLY one JSON object on
// every exit path (including errors and usage failures), the human
// text and the interactive cursor confirmation move to stderr, exit
// semantics stay identical to the default (non---json) mode, and the
// default mode's stdout stays the historical human text with nothing
// on stderr. Everything is synthetic; no test reads real tool state,
// real Cursor credentials, or the real state directory.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/connect"
	"toktrail-collector/internal/cursor/api"
	"toktrail-collector/internal/cursor/auth"
	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/source/registry"
)

// refusingAuthProvider is a cursor credential provider that must never
// be asked for a credential: the declined first-time confirmation
// returns before the credential read.
type refusingAuthProvider struct{ reached *bool }

func (p refusingAuthProvider) Fetch(ctx context.Context) (auth.Credential, error) {
	*p.reached = true
	return auth.Credential{}, errors.New("never reached")
}

// decodeSingleJSONLine asserts that out is exactly one
// newline-terminated JSON object and decodes it.
func decodeSingleJSONLine(t *testing.T, out string) map[string]any {
	t.Helper()
	trimmed := strings.TrimSuffix(out, "\n")
	if trimmed == "" || strings.Contains(trimmed, "\n") {
		t.Fatalf("stdout must be exactly one JSON line, got %q", out)
	}
	if !strings.HasPrefix(trimmed, "{") {
		t.Fatalf("stdout must be a JSON object, got %q", out)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
		t.Fatalf("stdout is not valid JSON: %q: %v", out, err)
	}
	return decoded
}

// TestPeriodicJSONCompleteSingleObject: a fully drained default run
// emits exactly one JSON object on stdout with stop_reason=complete,
// while the historical human summary moves to stderr.
func TestPeriodicJSONCompleteSingleObject(t *testing.T) {
	stateDir, server := budgetCLIFixture(t)

	var stdout, stderr bytes.Buffer
	err := runPeriodicIO([]string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--sync-timeout", "30s",
		"--json",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("the drained run must keep the historical nil error: %v\nstderr:\n%s", err, stderr.String())
	}
	decoded := decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != string(collection.StopComplete) {
		t.Fatalf("stopReason = %v, want complete: %s", decoded["stop_reason"], stdout.String())
	}
	if decoded["schema"] != float64(collection.ResultSchema) || decoded["command"] != "periodic" {
		t.Fatalf("unexpected envelope: %s", stdout.String())
	}
	counts := decoded["counts"].(map[string]any)
	if counts["syncedBatches"] != float64(3) || counts["pendingBatches"] != float64(0) {
		t.Fatalf("unexpected counts: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "syncedBatches=3 syncedRecords=3") {
		t.Fatalf("the historical human summary must move to stderr, got:\n%s", stderr.String())
	}
}

// TestPeriodicJSONBudgetExhaustedIncomplete: a budget-stopped run
// still emits exactly one JSON object (never zero objects on error),
// verdict budget_exhausted, while the exit stays the historical
// non-zero contract.
func TestPeriodicJSONBudgetExhaustedIncomplete(t *testing.T) {
	stateDir, server := budgetCLIFixture(t)

	var stdout, stderr bytes.Buffer
	err := runPeriodicIO([]string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--sync-timeout", "30s",
		"--max-total-batches", "1",
		"--json",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("a budget-stopped run must keep the historical non-zero exit")
	}
	decoded := decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != string(collection.StopBudgetExhausted) {
		t.Fatalf("stopReason = %v, want budget_exhausted: %s", decoded["stop_reason"], stdout.String())
	}
	counts := decoded["counts"].(map[string]any)
	if counts["pendingBatches"] != float64(2) {
		t.Fatalf("the declined batches must be counted as pending: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "incomplete: the --max-total-batches 1 shared upload budget is exhausted") {
		t.Fatalf("the historical incomplete text must move to stderr, got:\n%s", stderr.String())
	}
}

// TestPeriodicJSONBusyVerdict: a busy state directory reports busy with
// a not_run drain section (never a fabricated drained queue).
func TestPeriodicJSONBusyVerdict(t *testing.T) {
	stateDir := t.TempDir()
	lock, err := runlock.Acquire(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()

	var stdout, stderr bytes.Buffer
	err = runPeriodicIO([]string{
		"--state-dir", stateDir,
		"--sync-timeout", "30s",
		"--json",
	}, &stdout, &stderr)
	if err == nil || !errors.Is(err, runlock.ErrBusy) {
		t.Fatalf("the busy run must keep the historical error: %v", err)
	}
	decoded := decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != string(collection.StopBusy) {
		t.Fatalf("stopReason = %v, want busy: %s", decoded["stop_reason"], stdout.String())
	}
	drain := decoded["drain"].(map[string]any)
	if drain["stop"] != string(collection.DrainStopNotRun) {
		t.Fatalf("a busy run must report a not_run drain, got %v", drain["stop"])
	}
}

// TestPeriodicJSONFlagErrorEmitsObject: a usage failure after --json
// still emits one result object (the best-effort raw-argument scan).
func TestPeriodicJSONFlagErrorEmitsObject(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := runPeriodicIO([]string{"--json", "--bogus-flag"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("an unknown flag must fail")
	}
	decoded := decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != string(collection.StopFatalError) {
		t.Fatalf("stopReason = %v, want fatal_error: %s", decoded["stop_reason"], stdout.String())
	}
	drain := decoded["drain"].(map[string]any)
	if drain["stop"] != string(collection.DrainStopNotRun) {
		t.Fatalf("a pre-run failure must report a not_run drain, got %v", drain["stop"])
	}
}

// TestPeriodicDefaultModeKeepsHumanStdout: without --json the human
// text stays on stdout (the historical behavior) and stderr stays
// empty.
func TestPeriodicDefaultModeKeepsHumanStdout(t *testing.T) {
	stateDir, server := budgetCLIFixture(t)

	var stdout, stderr bytes.Buffer
	err := runPeriodicIO([]string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--sync-timeout", "30s",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("the drained run must succeed: %v", err)
	}
	if !strings.Contains(stdout.String(), "syncedBatches=3 syncedRecords=3") {
		t.Fatalf("the default mode must keep the human summary on stdout, got:\n%s", stdout.String())
	}
	if strings.HasPrefix(stdout.String(), "{") {
		t.Fatalf("the default mode must not emit JSON on stdout: %s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("the default mode must keep stderr empty (no progress events requested), got:\n%s", stderr.String())
	}
}

// connectCLIServers builds the mock TokTrail + connect-config server
// pair the connect JSON tests drive, naming the given tools.
func connectCLIServers(t *testing.T, tools []string) (connectURL string) {
	t.Helper()
	toktrailServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/devices/bind":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device": map[string]any{
					"deviceId":          "dev-json-cli-1",
					"applicationId":     "app-cli",
					"externalSubjectId": "sub-cli",
					"deviceName":        "dev-name",
					"platform":          "test-platform",
					"consentRevision":   1,
					"boundAt":           time.Now().UTC().Format(time.RFC3339),
				},
			})
		case "/v1/devices/self":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device": map[string]any{
					"deviceId": "dev-json-cli-1", "consentRevision": 1,
					"uploadAuthorized": true, "publicAuthorized": true,
					"revoked": false, "paused": false,
					// The managed grant-protocol view: the named tools
					// drive the managed-grant merge (and its pending
					// map when a default input is missing).
					"allowedTools": tools, "grantProtocolVersion": 1,
					"deviceGrantManaged": true,
				},
			})
		case "/v1/devices/grant-ack":
			var body struct {
				ConsentRevision int64  `json:"consentRevision"`
				ApplyState      string `json:"applyState"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			// Echo the requested application state (see the periodic
			// fake above).
			echoed := body.ApplyState
			if echoed == "" {
				echoed = "applied"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"grantAck": map[string]any{
				"consentRevision": body.ConsentRevision, "currentConsentRevision": body.ConsentRevision,
				"ackedState": echoed, "ackedAt": time.Now().UTC().Format(time.RFC3339),
			}})
		case "/v1/ingest/batches":
			var batch struct {
				BatchID string `json:"batchId"`
			}
			_ = json.NewDecoder(r.Body).Decode(&batch)
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]any{"batch": map[string]any{
				"batchId": batch.BatchID, "status": "accepted",
				"acceptedRecords": 1, "rejectedRecords": 0, "replay": false,
				"receivedAt": time.Now().UTC().Format(time.RFC3339),
			}})
		case "/v1/devices/tool-status":
			_ = json.NewEncoder(w).Encode(map[string]any{"accepted": true})
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
	t.Cleanup(toktrailServer.Close)

	connectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(connect.Config{
			SchemaVersion: 1,
			ServerURL:     toktrailServer.URL,
			ApplicationID: "app-cli",
			SubjectID:     "sub-cli",
			Tools:         tools,
			ExpiresAt:     time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339),
		})
	}))
	t.Cleanup(connectServer.Close)
	return fmt.Sprintf("%s/api/collector/connect#%s", connectServer.URL, strings.Repeat("5", 64))
}

// TestConnectJSONCompleteRun: a clean connect emits exactly one JSON
// object on stdout with the binding and scheduler sections, while the
// progressive human setup log moves to stderr.
func TestConnectJSONCompleteRun(t *testing.T) {
	oldRunner := connectSchedulerRunner
	connectSchedulerRunner = mockSchedulerRunner{}
	defer func() { connectSchedulerRunner = oldRunner }()

	stateDir := t.TempDir()
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
	// A granted Codex directory with no sessions: the scan is healthy
	// and empty.
	if err := os.MkdirAll(filepath.Join(homeDir, ".codex", "sessions"), 0o700); err != nil {
		t.Fatal(err)
	}
	connectURL := connectCLIServers(t, []string{"Codex"})

	var stdout, stderr bytes.Buffer
	err := runConnectIO([]string{"--state-dir", stateDir, "--json", connectURL}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("the clean connect must keep the historical nil error: %v\nstderr:\n%s", err, stderr.String())
	}
	decoded := decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != string(collection.StopComplete) {
		t.Fatalf("stopReason = %v, want complete: %s", decoded["stop_reason"], stdout.String())
	}
	if decoded["command"] != "connect" || decoded["schema"] != float64(collection.ResultSchema) {
		t.Fatalf("unexpected envelope: %s", stdout.String())
	}
	binding := decoded["binding"].(map[string]any)
	if binding["status"] != string(connect.BindBound) {
		t.Fatalf("binding status = %v, want bound: %s", binding["status"], stdout.String())
	}
	scheduler := decoded["scheduler"].(map[string]any)
	if scheduler["installed"] != true {
		t.Fatalf("the scheduler section must report the installation: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "connected to") || !strings.Contains(stderr.String(), "bound device") {
		t.Fatalf("the human setup log must move to stderr, got:\n%s", stderr.String())
	}
	if strings.Contains(stdout.String(), "connected to") {
		t.Fatalf("stdout must carry only the JSON object: %s", stdout.String())
	}
}

// TestConnectJSONBudgetExhausted: connect's honest incomplete result
// still emits exactly one JSON object with verdict budget_exhausted
// and keeps the non-zero exit.
func TestConnectJSONBudgetExhausted(t *testing.T) {
	oldRunner := connectSchedulerRunner
	connectSchedulerRunner = mockSchedulerRunner{}
	defer func() { connectSchedulerRunner = oldRunner }()

	stateDir := t.TempDir()
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
	for i := 1; i <= 3; i++ {
		seedCLIDeviceBatch(t, stateDir, homeDir, fmt.Sprintf("json-budget-%d", i), fmt.Sprintf("json-budget-key-%d", i), time.Duration(i)*time.Hour)
	}
	connectURL := connectCLIServers(t, []string{"Codex"})

	var stdout, stderr bytes.Buffer
	err := runConnectIO([]string{"--state-dir", stateDir, "--max-total-batches", "2", "--json", connectURL}, &stdout, &stderr)
	if err == nil || !errors.Is(err, connect.ErrSyncIncomplete) {
		t.Fatalf("the budget-capped connect must keep the historical incomplete error, got %v", err)
	}
	decoded := decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != string(collection.StopBudgetExhausted) {
		t.Fatalf("stopReason = %v, want budget_exhausted: %s", decoded["stop_reason"], stdout.String())
	}
	counts := decoded["collection"].(map[string]any)["counts"].(map[string]any)
	if counts["syncedBatches"] != float64(2) || counts["pendingBatches"] != float64(1) {
		t.Fatalf("unexpected counts: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "incomplete:") {
		t.Fatalf("the human incompleteness report must move to stderr, got:\n%s", stderr.String())
	}
}

// TestConnectJSONFlagErrorEmitsObject: a connect usage failure after
// --json still emits one result object with an honest not_attempted
// binding.
func TestConnectJSONFlagErrorEmitsObject(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := runConnectIO([]string{"--json", "--invalid-flag", "http://localhost:8080/connect#abc"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("an unknown flag must fail")
	}
	decoded := decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != string(collection.StopFatalError) {
		t.Fatalf("stopReason = %v, want fatal_error: %s", decoded["stop_reason"], stdout.String())
	}
	binding := decoded["binding"].(map[string]any)
	if binding["status"] != string(connect.BindNotAttempted) {
		t.Fatalf("binding status = %v, want not_attempted: %s", binding["status"], stdout.String())
	}
}

// TestConnectJSONPromptStaysInteractiveAndOffStdout pins the
// interactive-prompt preservation under --json: the first-time Cursor
// confirmation still runs (it reads stdin and writes the human
// stream), a declined answer keeps the historical clean-skip handling,
// and the prompt text never lands on the JSON machine stream.
func TestConnectJSONPromptStaysInteractiveAndOffStdout(t *testing.T) {
	oldRunner := connectSchedulerRunner
	connectSchedulerRunner = mockSchedulerRunner{}
	defer func() { connectSchedulerRunner = oldRunner }()

	// Inject the cursor wiring through the CLI seam; the declined
	// confirmation returns before any credential read, so the provider
	// is never reached.
	oldCursor := connectCursorOptions
	authReached := false
	connectCursorOptions = func(stateDir, serverURL string, httpClient *http.Client) (*cursorsync.Options, error) {
		return &cursorsync.Options{
			StateDir:   stateDir,
			ServerURL:  serverURL,
			HTTPClient: httpClient,
			Auth:       refusingAuthProvider{&authReached},
			Verify: func(ctx context.Context, accessToken string) (api.VerifyResult, error) {
				authReached = true
				return api.VerifyResult{}, errors.New("never reached")
			},
			Pull: func(ctx context.Context, sessionToken string, from, to time.Time) ([]api.UsageEvent, error) {
				authReached = true
				return nil, errors.New("never reached")
			},
		}, nil
	}
	t.Cleanup(func() { connectCursorOptions = oldCursor })

	stateDir := t.TempDir()
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
	connectURL := connectCLIServers(t, []string{"Cursor"})

	// Answer the interactive confirmation with a decline. DefaultConfirm
	// reads os.Stdin; the swap feeds it one line (stdin only — every
	// output writer stays explicitly injected).
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	if _, err := w.WriteString("n\n"); err != nil {
		t.Fatal(err)
	}
	w.Close()
	defer func() { os.Stdin = oldStdin; r.Close() }()

	var stdout, stderr bytes.Buffer
	err = runConnectIO([]string{"--state-dir", stateDir, "--json", connectURL}, &stdout, &stderr)
	if err == nil {
		t.Fatalf("a declined account-source enable keeps the historical incomplete result (the authorization named the tool)")
	}
	if authReached {
		t.Fatal("a declined confirmation must precede any credential read")
	}
	decoded := decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != string(collection.StopFatalError) {
		t.Fatalf("stopReason = %v, want fatal_error: %s", decoded["stop_reason"], stdout.String())
	}
	// The prompt (and its decline) live on the human stream.
	if !strings.Contains(stderr.String(), "Cursor 桌面登录凭据") {
		t.Fatalf("the interactive confirmation notice must move to stderr, got:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "not enabled") {
		t.Fatalf("the decline guidance must move to stderr, got:\n%s", stderr.String())
	}
	if strings.Contains(stdout.String(), "Cursor 桌面登录凭据") || strings.Contains(stdout.String(), "not enabled") {
		t.Fatalf("stdout must carry only the JSON object: %s", stdout.String())
	}
}

// ---------------------------------------------------------------------------
// Review fixes F1-F5 and the flag-scan semantics, end to end.
// ---------------------------------------------------------------------------

// TestPeriodicJSONGrantFaultIsIncompleteNonZero pins F1 end to end: a
// granted source whose input cannot be read makes the periodic run a
// non-zero incomplete exit with stop_reason=fatal_error and the
// incomplete line on the human stream — while the source's skip is a
// local fault, not a scope verdict.
func TestPeriodicJSONGrantFaultIsIncompleteNonZero(t *testing.T) {
	stateDir, server := budgetCLIFixture(t)
	// Replace the healthy empty-session grant with an unreadable one.
	sessions := filepath.Join(t.TempDir(), "broken")
	input := filepath.Join(sessions, "s.jsonl")
	if err := os.MkdirAll(sessions, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, []byte("{}"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(input, 0o600) })
	if _, err := grants.New(stateDir).Enable("claude-code-jsonl", sessions); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err := runPeriodicIO([]string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--sync-timeout", "30s",
		"--json",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("a granted source that failed to read must exit non-zero")
	}
	decoded := decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != string(collection.StopFatalError) {
		t.Fatalf("stop_reason = %v, want fatal_error: %s", decoded["stop_reason"], stdout.String())
	}
	scan := decoded["scan"].(map[string]any)
	sources := scan["sources"].([]any)
	found := false
	for _, s := range sources {
		entry := s.(map[string]any)
		if entry["status"] == string(collection.GrantExportFailed) {
			found = true
		}
	}
	if !found {
		t.Fatalf("the faulting source must carry export_failed: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "incomplete:") {
		t.Fatalf("the human stream must carry the incomplete line: %s", stderr.String())
	}
}

// TestPeriodicJSONScopeExcludedSourceStaysComplete pins F1's other
// half: a source the server scope excludes is an authorization
// verdict — the run stays complete with exit zero.
func TestPeriodicJSONScopeExcludedSourceStaysComplete(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolCLIServer(t, []string{"Claude Code"})
	bindPeriodicCLIDevice(t, stateDir, server.URL)
	// An isolated HOME with the authorized tool's default directory
	// present (resolved through the registry, never the real home):
	// the managed grant applies cleanly. A codex grant the served
	// scope excludes completes the fixture.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	spec, ok := registry.LookupTool("Claude Code")
	if !ok {
		t.Fatal("Claude Code must be a registered tool")
	}
	if err := os.MkdirAll(spec.ResolveDefaultInput(home), 0o700); err != nil {
		t.Fatal(err)
	}
	codex := filepath.Join(t.TempDir(), "codex")
	if err := os.MkdirAll(codex, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := grants.New(stateDir).Enable("codex-jsonl", codex); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err := runPeriodicIO([]string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--sync-timeout", "30s",
		"--json",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("a scope-excluded source keeps the complete exit: %v\nstderr:\n%s", err, stderr.String())
	}
	decoded := decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != string(collection.StopComplete) {
		t.Fatalf("stop_reason = %v, want complete: %s", decoded["stop_reason"], stdout.String())
	}
	// The excluded source is reported as not_allowed, never as a fault.
	scan := decoded["scan"].(map[string]any)
	found := false
	for _, s := range scan["sources"].([]any) {
		entry := s.(map[string]any)
		if entry["source"] == "codex-jsonl" && entry["status"] == string(collection.GrantNotAllowed) {
			found = true
		}
	}
	if !found {
		t.Fatalf("the scope-excluded source must carry not_allowed: %s", stdout.String())
	}
}

// grantProtocolCLIServer is a minimal speak-the-grant-protocol server
// for CLI tests: the self view carries grantProtocolVersion and the
// given allowed tools, grant-ack echoes the revision, and the ingest
// endpoints accept.
func grantProtocolCLIServer(t *testing.T, tools []string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self":
			writePeriodicDrainJSON(w, http.StatusOK, map[string]any{"device": map[string]any{
				"deviceId": "dev-drain-1", "consentRevision": 11,
				"uploadAuthorized": true, "revoked": false, "paused": false,
				"allowedTools": tools, "grantProtocolVersion": 1,
				"deviceGrantManaged": true,
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/devices/grant-ack":
			var body struct {
				ConsentRevision int64  `json:"consentRevision"`
				ApplyState      string `json:"applyState"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			// Echo the requested application state: a restricted
			// (pending) application acks as "pending", exactly like the
			// real server and the collection test fake.
			echoed := body.ApplyState
			if echoed == "" {
				echoed = "applied"
			}
			writePeriodicDrainJSON(w, http.StatusOK, map[string]any{"grantAck": map[string]any{
				"consentRevision": body.ConsentRevision, "currentConsentRevision": body.ConsentRevision,
				"ackedState": echoed, "ackedAt": "2026-10-31T08:00:00Z",
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/batches":
			var body struct {
				BatchID string           `json:"batchId"`
				Records []map[string]any `json:"records"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			writePeriodicDrainJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
				"batchId": body.BatchID, "status": "accepted",
				"acceptedRecords": len(body.Records), "rejectedRecords": 0,
				"replay": false, "receivedAt": "2026-10-31T08:00:00Z",
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/devices/tool-status":
			writePeriodicDrainJSON(w, http.StatusAccepted, map[string]any{"accepted": true})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// TestPeriodicJSONPausedEarlyReportsNotRunUnobserved pins F4 end to
// end: a server pause detected before the drain leaves the drain
// not_run and every pending count unobserved (never a claimed empty
// queue), while the verdict stays paused with the historical exit
// zero.
func TestPeriodicJSONPausedEarlyReportsNotRunUnobserved(t *testing.T) {
	stateDir := t.TempDir()
	server := newPeriodicDrainFakeServer(t)
	server.setPauseFromSelf(1)
	bindPeriodicCLIDevice(t, stateDir, server.URL)
	writePeriodicDrainPendingBatch(t, stateDir, "batch-paused-early-1", 1)

	var stdout, stderr bytes.Buffer
	err := runPeriodicIO([]string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--sync-timeout", "30s",
		"--json",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("a paused run keeps the historical nil error: %v", err)
	}
	decoded := decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != string(collection.StopPaused) {
		t.Fatalf("stop_reason = %v, want paused: %s", decoded["stop_reason"], stdout.String())
	}
	drain := decoded["drain"].(map[string]any)
	if drain["stop"] != string(collection.DrainStopNotRun) {
		t.Fatalf("the pre-drain pause must leave the drain not_run, got %v", drain["stop"])
	}
	if drain["pendingObserved"] != false {
		t.Fatalf("the never-counted queue must stay unobserved: %s", stdout.String())
	}
	if decoded["counts"].(map[string]any)["pendingObserved"] != false {
		t.Fatalf("the totals must follow the unobserved queues: %s", stdout.String())
	}
}

// TestPeriodicJSONDrainOnlyPartialAndAccountUnobserved pins F5 end to
// end: the drain-only mode never reads the account source (no
// source-batch POST), reports the account queue unobserved, and a
// clean run keeps exit zero with stop_reason=partial — never a claim
// of global completion.
func TestPeriodicJSONDrainOnlyPartialAndAccountUnobserved(t *testing.T) {
	stateDir, server := budgetCLIFixture(t)
	armPeriodicCursorSource(server)
	pull := &periodicFakePull{}
	armPeriodicCursorFakes(t, pull)
	writePeriodicDrainCursorPermit(t, stateDir)
	seedPeriodicCursorBatch(t, stateDir, "cursor-drainonly-1", 1)

	var stdout, stderr bytes.Buffer
	err := runPeriodicIO([]string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--sync-timeout", "30s",
		"--drain-only",
		"--json",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("a clean drain-only run keeps the historical exit zero: %v\nstderr:\n%s", err, stderr.String())
	}
	decoded := decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != string(collection.StopPartial) {
		t.Fatalf("stop_reason = %v, want partial: %s", decoded["stop_reason"], stdout.String())
	}
	drain := decoded["drain"].(map[string]any)
	account := drain["account"].(map[string]any)
	if account["pendingObserved"] != false {
		t.Fatalf("the drain-only mode must leave the account queue unobserved: %s", stdout.String())
	}
	if drain["pendingObserved"] != true {
		t.Fatalf("the drained device queue must be observed: %s", stdout.String())
	}
	// The unrequested account source was never read.
	if pull.calls != 0 {
		t.Fatalf("drain-only must never pull the account upstream, got %d pulls", pull.calls)
	}
	if got := server.srcIngest.Load(); got != 0 {
		t.Fatalf("drain-only must never POST the account queue, got %d", got)
	}
}

// TestPeriodicJSONRetryExhaustedVerdict pins F2 end to end: transient
// ingest failures that outlive the retry policy classify as
// retry_exhausted (never budget_exhausted), with the batch pending.
func TestPeriodicJSONRetryExhaustedVerdict(t *testing.T) {
	stateDir := t.TempDir()
	server := newPeriodicDrainFakeServer(t)
	// Every device-batch ingest answers 503 (a retryable transient
	// failure), so the CLI's bounded retry policy spends all four
	// attempts and surfaces the exhaustion sentinel.
	server.setDeviceIngestStatus(http.StatusServiceUnavailable)
	bindPeriodicCLIDevice(t, stateDir, server.URL)
	writePeriodicDrainPendingBatch(t, stateDir, "batch-retry-exhausted-1", 1)

	var stdout, stderr bytes.Buffer
	err := runPeriodicIO([]string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--sync-timeout", "30s",
		"--json",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("an exhausted retry must exit non-zero")
	}
	decoded := decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != string(collection.StopRetryExhausted) {
		t.Fatalf("stop_reason = %v, want retry_exhausted: %s", decoded["stop_reason"], stdout.String())
	}
	drain := decoded["drain"].(map[string]any)
	if drain["pendingObserved"] != true || drain["pendingRemaining"] != float64(1) {
		t.Fatalf("the failed batch must stay pending and observed: %s", stdout.String())
	}
}

// testFlagSet builds a flag set with the periodic command's flag
// shapes (value-taking and boolean) for the scan tests.
func testFlagSet(t *testing.T) *flag.FlagSet {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("state-dir", "", "")
	fs.String("server", "", "")
	fs.Int("max-batches", 0, "")
	fs.Int("max-total-batches", 0, "")
	fs.Bool("drain-only", false, "")
	fs.Bool("json", false, "")
	return fs
}

// TestScanArgsWantsJSON pins the flag-portion scan: standard boolean
// truthy values, last-valid-assignment wins, only the leading flag
// portion parsed, the VALUES of known value-taking flags skipped (the
// review bug: --state-dir /tmp/x used to end the scan), and "json"
// fragments inside other arguments never triggering it.
func TestScanArgsWantsJSON(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"bare long", []string{"--json"}, true},
		{"bare short", []string{"-json"}, true},
		{"true", []string{"--json=true"}, true},
		{"one", []string{"--json=1"}, true},
		{"t", []string{"--json=t"}, true},
		{"TRUE", []string{"--json=TRUE"}, true},
		{"False", []string{"--json=false"}, false},
		{"zero", []string{"--json=0"}, false},
		{"F", []string{"--json=F"}, false},
		{"absent", []string{"--server", "http://x"}, false},
		{"last valid wins false", []string{"--json", "--json=false"}, false},
		{"last valid wins true", []string{"--json=false", "--json=1"}, true},
		{"unparseable keeps previous", []string{"--json=true", "--json=bogus"}, true},
		{"unparseable alone", []string{"--json=bogus"}, false},
		{"positional stops the scan", []string{"http://x/json", "--json"}, false},
		{"terminator stops the scan", []string{"--", "--json"}, false},
		{"url fragment is not a switch", []string{"--server", "http://x/api/json#ticket", "--bogus"}, false},
		{"other flag with json value", []string{"--server=json", "--bogus"}, false},
		{"similar flag name", []string{"--jsonx=true", "--bogus"}, false},
		{"dash alone is positional", []string{"-", "--json"}, false},
		// The review bug: a value-taking flag's VALUE must not end the
		// scan — the switch after it is still a flag.
		{"value flag then switch", []string{"--state-dir", "/tmp/x", "--json=true"}, true},
		{"value flag then bare switch", []string{"--state-dir", "/tmp/x", "--json"}, true},
		{"value flag then disabled", []string{"--state-dir", "/tmp/x", "--json=false"}, false},
		{"negative number value", []string{"--max-total-batches", "-1", "--json=1"}, true},
		{"value flag then unknown then switch", []string{"--state-dir", "/tmp/x", "--bogus", "--json=true"}, true},
		{"value flag without later switch", []string{"--state-dir", "/tmp/x", "--bogus"}, false},
		{"bool flag does not consume", []string{"--drain-only", "--json=1"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scanArgsWantsJSON(testFlagSet(t), tc.args); got != tc.want {
				t.Fatalf("scanArgsWantsJSON(%v) = %t, want %t", tc.args, got, tc.want)
			}
		})
	}
}

// TestJSONWantsEmissionPriority pins the parsed-state priority: a
// --json the flag package actually parsed before the failure wins
// (including an explicit false), and only a parse that stopped before
// reaching --json falls back to the raw scan.
func TestJSONWantsEmissionPriority(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		// The review case: --state-dir VALUE --json=true --bogus — the
		// parser consumed the value and the switch before failing.
		{"parsed switch after a value flag", []string{"--state-dir", "/tmp/x", "--json=true", "--bogus"}, true},
		{"parsed explicit false stays disabled", []string{"--json=false", "--bogus"}, false},
		{"repeated false overrides an earlier true", []string{"--json=true", "--json=false", "--bogus"}, false},
		{"repeated true after false", []string{"--json=false", "--json", "--bogus"}, true},
		{"value flag then repeated false", []string{"--state-dir", "/tmp/x", "--json", "--json=false", "--bogus"}, false},
		{"parsed explicit true", []string{"--json=1", "--bogus"}, true},
		{"parse stops before the switch", []string{"--bogus", "--json=true"}, true},
		{"no switch anywhere", []string{"--state-dir", "/tmp/x", "--bogus"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := testFlagSet(t)
			jsonOut := false
			err := fs.Parse(tc.args)
			if err == nil {
				t.Fatalf("the case must fail parsing: %v", tc.args)
			}
			if f := fs.Lookup("json"); f != nil {
				jsonOut = f.Value.String() == "true"
			}
			if got := jsonWantsEmission(fs, jsonOut, tc.args); got != tc.want {
				t.Fatalf("jsonWantsEmission(%v) = %t, want %t", tc.args, got, tc.want)
			}
		})
	}
}

// TestPeriodicAndConnectJSONFlagFailureTruthiness pins the flag-failure
// emission on both commands: --json=false stays disabled (no object on
// stdout) while --json=1 emits exactly one, and no argument text leaks
// into the emitted object.
func TestPeriodicAndConnectJSONFlagFailureTruthiness(t *testing.T) {
	// periodic, --json=false: nothing on stdout.
	var stdout, stderr bytes.Buffer
	err := runPeriodicIO([]string{"--json=false", "--bogus-flag"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("an unknown flag must fail")
	}
	if stdout.Len() != 0 {
		t.Fatalf("--json=false must not emit an object, got %q", stdout.String())
	}

	// periodic, --json=1: exactly one object, no argument echo.
	stdout.Reset()
	stderr.Reset()
	err = runPeriodicIO([]string{"--json=1", "--bogus-flag"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("an unknown flag must fail")
	}
	decoded := decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != string(collection.StopFatalError) {
		t.Fatalf("stop_reason = %v, want fatal_error: %s", decoded["stop_reason"], stdout.String())
	}
	if strings.Contains(stdout.String(), "bogus-flag") {
		t.Fatalf("the emitted object must not echo the failing argument: %s", stdout.String())
	}

	// The review case: a value-taking flag's value before the switch —
	// the parser already consumed both when it fails on the last flag,
	// so the parsed state must drive the emission.
	stdout.Reset()
	stderr.Reset()
	err = runPeriodicIO([]string{"--state-dir", t.TempDir(), "--json=true", "--bogus-flag"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("an unknown flag must fail")
	}
	decoded = decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != string(collection.StopFatalError) {
		t.Fatalf("stop_reason = %v, want fatal_error: %s", decoded["stop_reason"], stdout.String())
	}

	// connect, --json=false: nothing on stdout.
	stdout.Reset()
	stderr.Reset()
	err = runConnectIO([]string{"--json=false", "--invalid-flag", "http://localhost:8080/connect#abc"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("an unknown flag must fail")
	}
	if stdout.Len() != 0 {
		t.Fatalf("--json=false must not emit an object, got %q", stdout.String())
	}

	// connect, --json=1: exactly one object with an honest not-attempted
	// binding.
	stdout.Reset()
	stderr.Reset()
	err = runConnectIO([]string{"--json=1", "--invalid-flag", "http://localhost:8080/connect#abc"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("an unknown flag must fail")
	}
	decoded = decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != string(collection.StopFatalError) {
		t.Fatalf("stop_reason = %v, want fatal_error: %s", decoded["stop_reason"], stdout.String())
	}
	if decoded["binding"].(map[string]any)["status"] != string(connect.BindNotAttempted) {
		t.Fatalf("binding must report not_attempted: %s", stdout.String())
	}
}

// TestPeriodicJSONCountFailureStaysUnobserved pins F4's count-failure
// shape end to end: an unreadable device outbox makes the run fail
// without ever measuring the queue — pendingObserved=false everywhere,
// never a claimed empty queue.
func TestPeriodicJSONCountFailureStaysUnobserved(t *testing.T) {
	stateDir, server := budgetCLIFixture(t)
	// Corrupt the outbox ledger so every count (and the drain's first
	// read) fails.
	if err := os.WriteFile(filepath.Join(stateDir, "outbox.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err := runPeriodicIO([]string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--sync-timeout", "30s",
		"--json",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("an unreadable outbox must fail the run")
	}
	decoded := decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != string(collection.StopFatalError) {
		t.Fatalf("stop_reason = %v, want fatal_error: %s", decoded["stop_reason"], stdout.String())
	}
	drain := decoded["drain"].(map[string]any)
	if drain["pendingObserved"] != false {
		t.Fatalf("the never-counted queue must stay unobserved: %s", stdout.String())
	}
	if decoded["counts"].(map[string]any)["pendingObserved"] != false {
		t.Fatalf("the totals must follow the unobserved queue: %s", stdout.String())
	}
	if stop := drain["stop"]; stop != string(collection.DrainStopNotRun) && stop != string(collection.DrainStopUnknown) {
		t.Fatalf("an unmeasured drain must report not_run or unknown, got %v", stop)
	}
}

// TestPeriodicJSONNoPermitAccountUnobserved pins F4's account shape:
// a full-mode run whose account source has no local permit never read
// the account queue — observed=false, never a claimed empty queue —
// while the verdict stays complete (nothing was owed).
func TestPeriodicJSONNoPermitAccountUnobserved(t *testing.T) {
	stateDir, server := budgetCLIFixture(t)
	// Arm the account source and the fake providers, but write NO
	// local permit: the cursor round skips before any queue read.
	armPeriodicCursorSource(server)
	pull := &periodicFakePull{}
	armPeriodicCursorFakes(t, pull)

	// The explicit legacy bound keeps the unbudgeted shape: the cursor
	// round is ONE cursorsync.Sync call with no fair rotation, so the
	// no-permit skip never reads the account outbox (the rotation's
	// preservePending recount is what measures it in the fair shape).
	var stdout, stderr bytes.Buffer
	err := runPeriodicIO([]string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--sync-timeout", "30s",
		"--max-batches", "5",
		"--json",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("a no-permit account source keeps the complete exit: %v\nstderr:\n%s", err, stderr.String())
	}
	decoded := decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != string(collection.StopComplete) {
		t.Fatalf("stop_reason = %v, want complete: %s", decoded["stop_reason"], stdout.String())
	}
	account := decoded["drain"].(map[string]any)["account"].(map[string]any)
	if account["pendingObserved"] != false {
		t.Fatalf("a no-permit round never read the account queue: %s", stdout.String())
	}
	if pull.calls != 0 {
		t.Fatalf("a no-permit round must never pull the upstream, got %d pulls", pull.calls)
	}
}

// TestPeriodicJSONUncoveredAuthorizedSourceIsIncomplete pins the
// review fix end to end: an authorized tool whose default input is
// missing on this device makes the periodic run a NON-ZERO incomplete
// exit (never a quiet partial), with stop_reason=partial, the concern
// counted in the scope section, and a path-free incomplete line on
// the human stream.
func TestPeriodicJSONUncoveredAuthorizedSourceIsIncomplete(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolCLIServer(t, []string{"Claude Code"})
	bindPeriodicCLIDevice(t, stateDir, server.URL)
	// An isolated, EMPTY home: the managed grant for the authorized
	// tool cannot apply (its default directory is missing).
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	var stdout, stderr bytes.Buffer
	err := runPeriodicIO([]string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--sync-timeout", "30s",
		"--json",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("an uncovered authorized source must exit non-zero")
	}
	decoded := decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != string(collection.StopPartial) {
		t.Fatalf("stop_reason = %v, want partial: %s", decoded["stop_reason"], stdout.String())
	}
	scope := decoded["scope"].(map[string]any)
	if scope["pendingMissingInput"] != float64(1) {
		t.Fatalf("the uncovered source must be counted: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "incomplete: 1 authorized source(s) are not covered") {
		t.Fatalf("the human stream must carry the path-free incomplete line: %s", stderr.String())
	}
	// The NEW incomplete line itself is path-free (the historical
	// grantSync pending lines keep their full reason text by design).
	var incompleteLine string
	for _, line := range strings.Split(stderr.String(), "\n") {
		if strings.HasPrefix(line, "incomplete: 1 authorized source(s)") {
			incompleteLine = line
		}
	}
	if incompleteLine == "" {
		t.Fatalf("the incomplete line must exist: %s", stderr.String())
	}
	for _, forbidden := range []string{home, ".claude", "/"} {
		if strings.Contains(incompleteLine, forbidden) {
			t.Fatalf("the incomplete line must stay path-free, got %q", incompleteLine)
		}
	}
}

// TestPeriodicJSONUnsupportedAuthorizedToolStaysComplete pins the
// no-false-alarm half: an authorized tool this collector cannot
// collect (unsupported) is a no-concern pending state — the run stays
// complete with exit zero, counted but never flagged.
func TestPeriodicJSONUnsupportedAuthorizedToolStaysComplete(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolCLIServer(t, []string{"A Tool This Build Never Heard Of"})
	bindPeriodicCLIDevice(t, stateDir, server.URL)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	var stdout, stderr bytes.Buffer
	err := runPeriodicIO([]string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--sync-timeout", "30s",
		"--json",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("an unsupported authorized tool keeps the complete exit: %v\nstderr:\n%s", err, stderr.String())
	}
	decoded := decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != string(collection.StopComplete) {
		t.Fatalf("stop_reason = %v, want complete: %s", decoded["stop_reason"], stdout.String())
	}
	scope := decoded["scope"].(map[string]any)
	if scope["pendingUnsupported"] != float64(1) {
		t.Fatalf("the unsupported tool must be counted as no-concern: %s", stdout.String())
	}
}

// TestConnectJSONUncoveredAuthorizedSourceIsIncomplete pins the
// connect side: an authorization naming a tool whose default directory
// is missing on this device never reads as success — the run reports
// ErrSyncIncomplete with stop_reason=partial and the closed
// source_uncovered code, and the human stream carries the path-free
// incomplete line.
func TestConnectJSONUncoveredAuthorizedSourceIsIncomplete(t *testing.T) {
	oldRunner := connectSchedulerRunner
	connectSchedulerRunner = mockSchedulerRunner{}
	defer func() { connectSchedulerRunner = oldRunner }()

	stateDir := t.TempDir()
	home := t.TempDir() // empty: no default tool directories
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	connectURL := connectCLIServers(t, []string{"Claude Code"})

	var stdout, stderr bytes.Buffer
	err := runConnectIO([]string{"--state-dir", stateDir, "--json", connectURL}, &stdout, &stderr)
	if err == nil || !errors.Is(err, connect.ErrSyncIncomplete) {
		t.Fatalf("an uncovered authorized source must keep the honest incomplete error, got %v", err)
	}
	decoded := decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != string(collection.StopPartial) {
		t.Fatalf("stop_reason = %v, want partial: %s", decoded["stop_reason"], stdout.String())
	}
	found := false
	if codes, ok := decoded["incompleteCodes"].([]any); ok {
		for _, c := range codes {
			if c == "source_uncovered" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("the closed source_uncovered code must be reported: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "incomplete:") {
		t.Fatalf("the human stream must carry the incomplete line: %s", stderr.String())
	}
}

// TestEmitResultJSONMarshalFallback pins the never-happens net: a
// summary that cannot marshal still yields exactly one JSON object —
// with the stable stop_reason key, not the retired camelCase spelling
// — and no partial garbage.
func TestEmitResultJSONMarshalFallback(t *testing.T) {
	var stdout bytes.Buffer
	// A channel value cannot marshal: the injected failure shape.
	emitResultJSON(&stdout, map[string]any{"bad": make(chan int)})
	line := strings.TrimSuffix(stdout.String(), "\n")
	if line == "" || strings.Contains(line, "\n") {
		t.Fatalf("the fallback must be exactly one line, got %q", stdout.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(line), &decoded); err != nil {
		t.Fatalf("the fallback must be valid JSON, got %q: %v", line, err)
	}
	if decoded["stop_reason"] != string(collection.StopFatalError) {
		t.Fatalf("the fallback must carry stop_reason=fatal_error, got %s", line)
	}
	if _, ok := decoded["stopReason"]; ok {
		t.Fatalf("the retired camelCase key must not appear, got %s", line)
	}
	// The healthy path still emits the real object.
	stdout.Reset()
	emitResultJSON(&stdout, collection.SummarizeNotRun(nil, "periodic", 1))
	if !strings.Contains(stdout.String(), `"stop_reason":"partial"`) {
		t.Fatalf("the healthy path must emit the verdict, got %s", stdout.String())
	}
}
