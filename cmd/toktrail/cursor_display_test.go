package main

// C2 display-layer tests: a polluted old permit may carry arbitrary text
// (the device secret included) in its SourceInstanceID, and a malicious
// server may place attacker-chosen text in a source's State. Neither is
// ever printed verbatim — the source linkage displays as a fixed label
// and the state maps onto a fixed vocabulary. The state machine, permit
// handling and exit codes are untouched. Everything is synthetic
// (tempdir state, httptest fakes, synthetic secrets); no real state,
// credential or network is ever touched.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/local/cursorsource"
	"toktrail-collector/internal/local/statedir"
)

// The display vocabulary: known states pass through (trimmed), the empty
// state is a known "unspecified", and anything else — including
// attacker-chosen text — displays as "unknown".
func TestDisplaySourceStateVocabulary(t *testing.T) {
	cases := map[string]string{
		"active":                     "active",
		"pending":                    "pending",
		"paused":                     "paused",
		"  active  ":                 "active",
		"":                           "unspecified",
		"aGVsbG8tc2VjcmV0LXRva2Vu":   "unknown",
		"active; DROP TABLE permits": "unknown",
	}
	for in, want := range cases {
		if got := displaySourceState(in); got != want {
			t.Fatalf("displaySourceState(%q) = %q, want %q", in, got, want)
		}
	}
}

// The source linkage label never echoes the identifier.
func TestSourceConfiguredLabel(t *testing.T) {
	if got := sourceConfiguredLabel(""); got != "not configured" {
		t.Fatalf("an empty identifier is not configured, got %q", got)
	}
	if got := sourceConfiguredLabel("   "); got != "not configured" {
		t.Fatalf("a blank identifier is not configured, got %q", got)
	}
	if got := sourceConfiguredLabel("synthetic-device-secret-value"); got != "configured" {
		t.Fatalf("a non-empty identifier displays as configured, got %q", got)
	}
}

// A polluted permit whose SourceInstanceID carries the device secret:
// the status output must never echo it — the fixed "configured" label
// and the numeric counters stay readable, and the permit on disk is
// untouched. (The server here is clean: the display-layer leak under
// test is the permit's own field, and the hardened self protocol
// already fails closed on any server that would echo the secret back.)
func TestRunCursorStatusSanitizesPollutedPermit(t *testing.T) {
	const deviceSecret = "synthetic-status-device-secret-0123456789abcdef"

	stateDir := t.TempDir()
	if err := statedir.New(stateDir).Save(statedir.DeviceState{
		DeviceID:     "dev-display-1",
		DeviceSecret: deviceSecret,
	}); err != nil {
		t.Fatal(err)
	}
	writeCursorDisplayPermit(t, stateDir, deviceSecret, cursorsource.StatusActive)

	server := startCursorDisplayServer(t, "dev-display-1", protocol.Source{
		SourceInstanceID: "synthetic-clean-server-source-id",
		SourceType:       protocol.SourceType,
		State:            "active",
		FenceVersion:     2,
		NextRevision:     3,
	})
	defer server.Close()

	out := captureCursorDisplayStdout(t, func() error {
		return runCursorStatus([]string{"--state-dir", stateDir, "--server", server.URL})
	})
	if out.err != nil {
		t.Fatalf("cursor status failed: %v", out.err)
	}
	if strings.Contains(out.text, deviceSecret) {
		t.Fatalf("the status output must not echo the polluted permit identifier, got:\n%s", out.text)
	}
	if !strings.Contains(out.text, "source: configured (fenceVersion=4 nextRevision=9)") {
		t.Fatalf("the status output must keep the sanitized readable line, got:\n%s", out.text)
	}
	// The display change never touches the permit on disk.
	reread, ok, err := cursorsource.New(stateDir).Load()
	if err != nil || !ok || reread.SourceInstanceID != deviceSecret || reread.Status != cursorsource.StatusActive {
		t.Fatalf("the permit must be untouched by the display layer: ok=%v err=%v", ok, err)
	}
}

// A malicious server placing attacker-chosen text in a source's State:
// the matched server-source line maps the state onto the fixed
// vocabulary ("unknown"), never echoing the text. The attack text is a
// NON-credential arbitrary value by design: credential reflection has
// its own fail-closed security layer (covered separately below), and
// this test isolates the pure display-layer vocabulary.
func TestRunCursorStatusSanitizesServerSourceState(t *testing.T) {
	const attackerState = "synthetic-attacker-state-text-lNm3Xy"
	const sourceID = "synthetic-status-source-id"

	stateDir := t.TempDir()
	if err := statedir.New(stateDir).Save(statedir.DeviceState{
		DeviceID:     "dev-display-2",
		DeviceSecret: "synthetic-status-secret-2",
	}); err != nil {
		t.Fatal(err)
	}
	writeCursorDisplayPermit(t, stateDir, sourceID, cursorsource.StatusActive)

	server := startCursorDisplayServer(t, "dev-display-2", protocol.Source{
		SourceInstanceID: sourceID,
		SourceType:       protocol.SourceType,
		State:            attackerState,
		FenceVersion:     4,
		NextRevision:     9,
	})
	defer server.Close()

	out := captureCursorDisplayStdout(t, func() error {
		return runCursorStatus([]string{"--state-dir", stateDir, "--server", server.URL})
	})
	if out.err != nil {
		t.Fatalf("cursor status failed: %v", out.err)
	}
	if strings.Contains(out.text, attackerState) {
		t.Fatalf("the status output must not echo the server state text, got:\n%s", out.text)
	}
	if !strings.Contains(out.text, "server source: state=unknown fenceVersion=4 nextRevision=9") {
		t.Fatalf("the server source line must carry the fixed vocabulary, got:\n%s", out.text)
	}
	if strings.Contains(out.text, sourceID) {
		t.Fatalf("the source identifier must never be echoed, got:\n%s", out.text)
	}
}

// A server response carrying the ACTUAL device secret in a source
// field is rejected by the reflected-credential fail-closed layer
// (owned by the account-boundary work) — this test pins only the
// display side of that failure: the secret never appears in the status
// output, before or after the closed failure, while the local permit's
// sanitized line still prints.
func TestRunCursorStatusDoesNotLeakReflectedCredentialFailure(t *testing.T) {
	const deviceSecret = "synthetic-reflected-device-secret-Aa7Bb9Cc"

	stateDir := t.TempDir()
	if err := statedir.New(stateDir).Save(statedir.DeviceState{
		DeviceID:     "dev-display-3",
		DeviceSecret: deviceSecret,
	}); err != nil {
		t.Fatal(err)
	}
	// A clean local permit: the leak risk here is the SERVER echoing the
	// secret back inside its source fields.
	writeCursorDisplayPermit(t, stateDir, "synthetic-clean-permit-id", cursorsource.StatusActive)

	server := startCursorDisplayServer(t, "dev-display-3", protocol.Source{
		SourceInstanceID: deviceSecret, // the reflected credential
		SourceType:       protocol.SourceType,
		State:            "active",
		FenceVersion:     1,
		NextRevision:     1,
	})
	defer server.Close()

	out := captureCursorDisplayStdout(t, func() error {
		return runCursorStatus([]string{"--state-dir", stateDir, "--server", server.URL})
	})
	if out.err != nil {
		t.Fatalf("cursor status must report the closed failure, not fail: %v", out.err)
	}
	// The secret must never appear — not in the permit line, not in the
	// closed-failure server line.
	if strings.Contains(out.text, deviceSecret) {
		t.Fatalf("the status output must not echo the reflected device secret, got:\n%s", out.text)
	}
	if !strings.Contains(out.text, "source: configured (fenceVersion=4 nextRevision=9)") {
		t.Fatalf("the local permit's sanitized line must still print, got:\n%s", out.text)
	}
	if !strings.Contains(out.text, "server source: unavailable (") {
		t.Fatalf("the closed failure must surface as the unavailable server source, got:\n%s", out.text)
	}
}

// writeCursorDisplayPermit persists a synthetic permit with the given
// source identifier (the pollution carrier) into the tempdir state.
func writeCursorDisplayPermit(t *testing.T, stateDir, sourceInstanceID string, status cursorsource.Status) {
	t.Helper()
	permit := cursorsource.License{
		SchemaVersion:    1,
		SourceInstanceID: sourceInstanceID,
		SourceType:       protocol.SourceType,
		CredentialSource: "desktop",
		AccountMatchID:   "synthetic-match",
		Status:           status,
		ConfirmedAt:      time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC),
		ConsentRevision:  1,
		FenceVersion:     4,
		NextRevision:     9,
	}
	b, err := json.Marshal(permit)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cursorsource.New(stateDir).Path(), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// startCursorDisplayServer fakes the device self view with one account
// source (never any credential material in the response).
func startCursorDisplayServer(t *testing.T, deviceID string, src protocol.Source) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			writeCursorDisplayJSON(t, w, http.StatusOK, map[string]any{"device": map[string]any{
				"deviceId":         deviceID,
				"consentRevision":  1,
				"uploadAuthorized": true,
				"revoked":          false,
				"accountSources":   []protocol.Source{src},
			}})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

func writeCursorDisplayJSON(t *testing.T, w http.ResponseWriter, status int, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

type cursorDisplayOutput struct {
	text string
	err  error
}

func captureCursorDisplayStdout(t *testing.T, fn func() error) cursorDisplayOutput {
	t.Helper()
	// The pipe is drained concurrently while fn runs: reading only after
	// fn returned would deadlock any output larger than the OS pipe
	// buffer (see pipe_capture_test.go).
	text, fnErr := captureStdoutPiped(t, fn)
	return cursorDisplayOutput{text: text, err: fnErr}
}
