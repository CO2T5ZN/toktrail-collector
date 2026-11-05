package main

// The periodic concise-logging surface (the approved one-line default
// summary, --verbose, the ~30s human heartbeat and the safe error
// display), covered end-to-end through the real runPeriodicIO flag
// parsing and collection wiring, plus unit-level regressions for the
// sanitization and throttle logic:
//
//   - the default (no --verbose) run prints exactly the natural
//     English one-line summary (date-time, server-confirmed counts,
//     observable pending) and none of the historical detail lines;
//   - "no new records" is claimed ONLY when the scan provably ran
//     (a granted source returned the healthy empty-scan code, or the
//     account round pulled); drain-only, no-grants and never-scanned
//     runs keep the neutral "no records confirmed" wording;
//   - a backlog drain (nothing newly collected, NoGrants included)
//     always shows its confirmed counts and never reads as idle;
//   --verbose restores the detailed log with closed codes and counts;
//   - a real error surfaces exactly once (main's unified line via
//     displayErrorText) while the returned error keeps its chain,
//     text, exit-code semantics and the --json stop_reason;
//   - hostile strings (URLs with userinfo/query/fragment, absolute
//     paths, bearer tokens, raw session text) injected through error
//     text, flag values, environment defaults and free-text result
//     fields never reach the default or --verbose human output;
//   - the heartbeat throttle renders at most one line per interval,
//     drops machine events and honors the pending observation gates;
//   - --json keeps stdout to exactly one object and --progress-json
//     keeps the machine events on stderr with no human heartbeat.
//
// Everything is synthetic: tempdir state directories, a local httptest
// fake for the ingest server, seeded outbox batches and hand-built
// results. No test reads real tool state, real credentials or performs
// any network access beyond the fake server.

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
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncbudget"
)

// Hostile fixture strings for the leak regressions: a URL with
// userinfo, query and fragment, an absolute path, a bearer token and a
// raw session-like blob. None of these may ever reach the default or
// --verbose human output.
const (
	conciseHostileURL     = "https://user:pass%20word@evil.example.com/ingest?ticket=TICKET-SECRET-123#frag"
	conciseHostilePath    = "/Users/victim/Library/Application Support/secret-state"
	conciseHostileBearer  = "Bearer eyJhbGciOiJIUzI1NiJ9.SECRET-PAYLOAD.raw"
	conciseHostileSession = `{"session":"raw-session-SECRET","apiKey":"sk-live-SECRET"}`
)

// conciseLogServer is a minimal self-contained ingest fake: it answers
// the device self preflight and accepts every device-batch upload,
// counting traffic; any other endpoint fails the test.
type conciseLogServer struct {
	*httptest.Server
	self    atomic.Int64
	ingest  atomic.Int64
	tooling atomic.Int64
}

func newConciseLogServer(t *testing.T) *conciseLogServer {
	t.Helper()
	s := &conciseLogServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self":
			s.self.Add(1)
			writeJSON(w, http.StatusOK, map[string]any{"device": map[string]any{
				"deviceId":          "dev-concise-1",
				"applicationId":     "app-concise-1",
				"externalSubjectId": "sub-concise-1",
				"deviceName":        "collector-concise-test",
				"platform":          "darwin",
				"consentRevision":   7,
				"uploadAuthorized":  true,
				"publicAuthorized":  false,
				"revoked":           false,
				"checkedAt":         "2026-11-02T08:00:00Z",
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/devices/tool-status":
			// The scan reports per-tool no_new_records states and the
			// drain reports synced tools through this endpoint.
			s.tooling.Add(1)
			writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true})
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
			writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
				"batchId":         body.BatchID,
				"status":          "accepted",
				"acceptedRecords": len(body.Records),
				"rejectedRecords": 0,
				"replay":          false,
				"receivedAt":      "2026-11-02T08:01:00Z",
				"recordErrors":    []map[string]any{},
			}})
		default:
			t.Errorf("unexpected endpoint: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// conciseBindDevice writes a bound device state pointing at the fake
// server (the application/subject ids mirror its self view).
func conciseBindDevice(t *testing.T, stateDir, serverURL string) {
	t.Helper()
	if err := statedir.New(stateDir).Save(statedir.DeviceState{
		ServerURL:         serverURL,
		DeviceID:          "dev-concise-1",
		DeviceSecret:      strings.Repeat("c", 64),
		ApplicationID:     "app-concise-1",
		ExternalSubjectID: "sub-concise-1",
	}); err != nil {
		t.Fatal(err)
	}
}

// conciseSeedPending seeds n pending outbox batches of one record each.
func conciseSeedPending(t *testing.T, stateDir string, n int) {
	t.Helper()
	batchesDir := filepath.Join(stateDir, "batches")
	if err := os.MkdirAll(batchesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= n; i++ {
		batchID := fmt.Sprintf("batch-concise-%d", i)
		path := filepath.Join(batchesDir, batchID+".json")
		record := map[string]any{
			"recordKey":      batchID + "-record-1",
			"kind":           "delta",
			"occurredAt":     "2026-11-02T07:00:00Z",
			"tool":           "usage-json",
			"input":          "10",
			"cacheRead":      "0",
			"cacheWrite":     "0",
			"output":         "5",
			"adapterVersion": "concise-log-test-1",
			"sourceType":     "fixture",
		}
		b, err := json.Marshal(map[string]any{"batchId": batchID, "records": []map[string]any{record}})
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
			RecordCount: 1,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// conciseEnableEmptyGrant enables a claude-code-jsonl grant over an
// empty session directory, so the scan demonstrably runs and finds
// nothing new.
func conciseEnableEmptyGrant(t *testing.T, stateDir string) string {
	t.Helper()
	sessions := filepath.Join(t.TempDir(), "sessions")
	if err := os.MkdirAll(sessions, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := grants.New(stateDir).Enable("claude-code-jsonl", sessions); err != nil {
		t.Fatal(err)
	}
	return sessions
}

// conciseRun runs runPeriodicIO with buffer writers and returns
// (stdout, stderr, error).
func conciseRun(args ...string) (string, string, error) {
	var out, errBuf bytes.Buffer
	err := runPeriodicIO(args, &out, &errBuf)
	return out.String(), errBuf.String(), err
}

// conciseAssertNoDetailLines fails when the default (concise) output
// carries any of the historical verbose detail markers.
func conciseAssertNoDetailLines(t *testing.T, out string) {
	t.Helper()
	for _, marker := range []string{
		"grantSync:", "grant ", "cursor sync:", "exportedBatches=", "syncedBatches=", "pendingRemaining=", "incomplete:", "Still running",
	} {
		if strings.Contains(out, marker) {
			t.Fatalf("the concise default output must not carry the detail marker %q, got:\n%s", marker, out)
		}
	}
}

// TestPeriodicConciseDefaultDrainsBacklogWithConfirmedCounts pins the
// approved default: a backlog drain (no new collection at all — even
// with no enabled grants) prints exactly one natural English line that
// SHOWS the server-confirmed counts; it never reads as "no new
// records", and none of the historical detail lines appear. Exit zero.
func TestPeriodicConciseDefaultDrainsBacklogWithConfirmedCounts(t *testing.T) {
	stateDir := t.TempDir()
	server := newConciseLogServer(t)
	conciseBindDevice(t, stateDir, server.URL)
	conciseSeedPending(t, stateDir, 3)

	out, stderr, err := conciseRun("--state-dir", stateDir, "--server", server.URL, "--sync-timeout", "30s")
	if err != nil {
		t.Fatalf("the drained backlog run must exit zero: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}
	if strings.Contains(out, "no new records") {
		t.Fatalf("a backlog drain must never read as idle, got:\n%s", out)
	}
	if !strings.Contains(out, "Complete: 3 records confirmed in 3 batches") {
		t.Fatalf("the confirmed counts must show, got:\n%s", out)
	}
	if !strings.Contains(out, "nothing pending") {
		t.Fatalf("the drained queue must report nothing pending, got:\n%s", out)
	}
	conciseAssertNoDetailLines(t, out)
	if stderr != "" {
		t.Fatalf("the default run must keep stderr empty (no progress events requested), got:\n%s", stderr)
	}
	// Exactly one line: the concise summary.
	if n := strings.Count(strings.TrimRight(out, "\n"), "\n"); n != 0 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("the default output must be exactly one line, got %d newlines:\n%s", n, out)
	}
	if got := server.ingest.Load(); got != 3 {
		t.Fatalf("expected three ingest uploads, got %d", got)
	}
}

// TestPeriodicConciseIdleScanClaimsNoNewRecordsOnlyWhenProvable pins
// the idle wording: a run whose granted source demonstrably scanned
// and found nothing new says "no new records"; the drain-only mode
// (nothing scanned at all) and a no-grants run never claim it.
func TestPeriodicConciseIdleScanClaimsNoNewRecordsOnlyWhenProvable(t *testing.T) {
	t.Run("proven_empty_scan", func(t *testing.T) {
		stateDir := t.TempDir()
		server := newConciseLogServer(t)
		conciseBindDevice(t, stateDir, server.URL)
		conciseEnableEmptyGrant(t, stateDir)

		out, stderr, err := conciseRun("--state-dir", stateDir, "--server", server.URL, "--sync-timeout", "30s")
		if err != nil {
			t.Fatalf("the idle run must exit zero: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
		}
		if !strings.Contains(out, "Complete: no new records") {
			t.Fatalf("a provably empty scan reads as no new records, got:\n%s", out)
		}
		conciseAssertNoDetailLines(t, out)
	})

	t.Run("drain_only_never_claims_no_new_records", func(t *testing.T) {
		stateDir := t.TempDir()
		server := newConciseLogServer(t)
		conciseBindDevice(t, stateDir, server.URL)
		conciseSeedPending(t, stateDir, 1)

		out, _, err := conciseRun("--state-dir", stateDir, "--server", server.URL, "--drain-only", "--sync-timeout", "30s")
		if err != nil {
			t.Fatalf("the clean drain-only run must exit zero: %v\nstdout:\n%s", err, out)
		}
		if strings.Contains(out, "no new records") {
			t.Fatalf("drain-only never scanned and must not claim no new records, got:\n%s", out)
		}
		// One seeded batch means one confirmed record; the mode is
		// named in the pending clause. Either way the idle claim must
		// stay absent (checked above).
		if !strings.Contains(out, "1 record confirmed in 1 batch") {
			t.Fatalf("the drain-only summary must show its confirmed counts, got:\n%s", out)
		}
		if !strings.Contains(out, "drain-only") {
			t.Fatalf("the drain-only pending clause must name the mode, got:\n%s", out)
		}
		conciseAssertNoDetailLines(t, out)
	})

	t.Run("no_grants_never_claims_no_new_records", func(t *testing.T) {
		stateDir := t.TempDir()
		server := newConciseLogServer(t)
		conciseBindDevice(t, stateDir, server.URL)

		out, _, err := conciseRun("--state-dir", stateDir, "--server", server.URL, "--sync-timeout", "30s")
		if err != nil {
			t.Fatalf("the no-grants run must exit zero: %v\nstdout:\n%s", err, out)
		}
		if strings.Contains(out, "no new records") {
			t.Fatalf("a no-grants run never scanned and must not claim no new records, got:\n%s", out)
		}
		if !strings.Contains(out, "no records confirmed") {
			t.Fatalf("the no-grants run keeps the neutral wording, got:\n%s", out)
		}
		conciseAssertNoDetailLines(t, out)
	})
}

// TestPeriodicConciseBacklogPlusEmptyScanNamesBoth pins the combined
// shape: a granted empty scan over a drained backlog shows the
// confirmed counts AND the "no new records this scan" suffix — work
// happened, nothing new arrived.
func TestPeriodicConciseBacklogPlusEmptyScanNamesBoth(t *testing.T) {
	stateDir := t.TempDir()
	server := newConciseLogServer(t)
	conciseBindDevice(t, stateDir, server.URL)
	conciseEnableEmptyGrant(t, stateDir)
	conciseSeedPending(t, stateDir, 2)

	out, _, err := conciseRun("--state-dir", stateDir, "--server", server.URL, "--sync-timeout", "30s")
	if err != nil {
		t.Fatalf("the run must exit zero: %v\nstdout:\n%s", err, out)
	}
	if !strings.Contains(out, "2 records confirmed in 2 batches") || !strings.Contains(out, "no new records this scan") {
		t.Fatalf("the backlog-plus-empty-scan line must name both, got:\n%s", out)
	}
	conciseAssertNoDetailLines(t, out)
}

// TestPeriodicConciseBoundedStopKeepsExitZeroAndNaturalPhrase pins the
// bounded shape: an explicit --max-batches with work left keeps the
// historical exit zero and reads as "Stopped at the requested batch
// limit" with its pending count — never as failure, never as complete.
func TestPeriodicConciseBoundedStopKeepsExitZeroAndNaturalPhrase(t *testing.T) {
	stateDir := t.TempDir()
	server := newConciseLogServer(t)
	conciseBindDevice(t, stateDir, server.URL)
	conciseSeedPending(t, stateDir, 2)

	out, _, err := conciseRun("--state-dir", stateDir, "--server", server.URL, "--max-batches", "1", "--sync-timeout", "30s")
	if err != nil {
		t.Fatalf("the bounded stop keeps the historical exit zero: %v\nstdout:\n%s", err, out)
	}
	if !strings.Contains(out, "Stopped at the requested batch limit: 1 record confirmed in 1 batch") {
		t.Fatalf("the bounded stop phrase and counts must show, got:\n%s", out)
	}
	if !strings.Contains(out, "1 batch pending") {
		t.Fatalf("the bounded remainder must show, got:\n%s", out)
	}
	if strings.Contains(out, "Complete:") || strings.Contains(out, "Incomplete:") {
		t.Fatalf("a bounded stop is neither complete nor incomplete, got:\n%s", out)
	}
	conciseAssertNoDetailLines(t, out)
}

// TestPeriodicConciseBudgetStopSingleErrorSurface pins the error
// deduplication: a budget-stopped run prints its concise status line
// (counts only — no reason text) and exits non-zero with the wrapped
// error keeping chain, sentinel and historical text; displayErrorText
// (main's unified line) carries the safe reason exactly once with no
// raw inner error text.
func TestPeriodicConciseBudgetStopSingleErrorSurface(t *testing.T) {
	stateDir := t.TempDir()
	server := newConciseLogServer(t)
	conciseBindDevice(t, stateDir, server.URL)
	conciseSeedPending(t, stateDir, 3)

	out, stderr, err := conciseRun("--state-dir", stateDir, "--server", server.URL, "--max-total-batches", "2", "--sync-timeout", "30s")
	if err == nil {
		t.Fatalf("the exhausted budget must exit non-zero, stdout:\n%s", out)
	}
	if !errors.Is(err, syncbudget.ErrTotalExhausted) {
		t.Fatalf("the sentinel must survive the display wrapper, got %v", err)
	}
	if !strings.Contains(err.Error(), "periodic incomplete") || !strings.Contains(err.Error(), "--max-total-batches 2") {
		t.Fatalf("the returned error keeps its historical text, got %v", err)
	}
	if !strings.Contains(out, "Incomplete: 2 records confirmed in 2 batches") || !strings.Contains(out, "1 batch pending") {
		t.Fatalf("the concise line carries the counts, got:\n%s", out)
	}
	if strings.Contains(out, "incomplete:") {
		t.Fatalf("the concise mode must not duplicate the reason text, got:\n%s", out)
	}
	// main's unified line: the safe reason, once, without raw inner
	// error text (the underlying decline error never names endpoints).
	safe := displayErrorText(err)
	if !strings.Contains(safe, "periodic incomplete") || !strings.Contains(safe, "remaining work stays pending") {
		t.Fatalf("the safe display carries the curated reason, got %q", safe)
	}
	if strings.Contains(safe, conciseHostileURL) || strings.Contains(safe, conciseHostilePath) {
		t.Fatalf("the safe display must not carry raw inner text, got %q", safe)
	}
	if stderr != "" {
		t.Fatalf("the default run must keep stderr empty, got:\n%s", stderr)
	}
}

// TestPeriodicVerboseRestoresDetailLog pins --verbose: the historical
// detailed lines return (closed codes and counts), no concise summary
// line prints, and the collection semantics are unchanged.
func TestPeriodicVerboseRestoresDetailLog(t *testing.T) {
	stateDir := t.TempDir()
	server := newConciseLogServer(t)
	conciseBindDevice(t, stateDir, server.URL)
	conciseEnableEmptyGrant(t, stateDir)
	conciseSeedPending(t, stateDir, 2)

	out, stderr, err := conciseRun("--state-dir", stateDir, "--server", server.URL, "--verbose", "--sync-timeout", "30s")
	if err != nil {
		t.Fatalf("the verbose run must exit zero: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}
	if strings.Contains(out, "records confirmed in") || strings.Contains(out, "Stopped at") {
		t.Fatalf("the verbose mode must not print the concise summary line, got:\n%s", out)
	}
	for _, marker := range []string{
		"grant Claude Code: skipped (no new records since the last confirmed baselines)",
		"syncedBatches=2 syncedRecords=2",
		"exportedBatches=0 exportedRecords=0",
	} {
		if !strings.Contains(out, marker) {
			t.Fatalf("the verbose log must carry %q, got:\n%s", marker, out)
		}
	}
	if stderr != "" {
		t.Fatalf("verbose without --json keeps stderr empty, got:\n%s", stderr)
	}
}

// TestPeriodicConciseJSONAndProgressStreamsPreserved pins the machine
// contracts: --json keeps stdout to exactly one object with the
// stop_reason, the human line moves to stderr; --progress-json keeps
// the machine events on stderr (parseable, heartbeat kind present)
// with no human heartbeat line mixed in.
func TestPeriodicConciseJSONAndProgressStreamsPreserved(t *testing.T) {
	stateDir := t.TempDir()
	server := newConciseLogServer(t)
	conciseBindDevice(t, stateDir, server.URL)
	conciseSeedPending(t, stateDir, 2)

	out, stderr, err := conciseRun("--state-dir", stateDir, "--server", server.URL, "--json", "--sync-timeout", "30s")
	if err != nil {
		t.Fatalf("the drained run must exit zero: %v\nstderr:\n%s", err, stderr)
	}
	trimmed := strings.TrimSpace(out)
	if trimmed == "" || strings.Contains(trimmed, "\n") {
		t.Fatalf("stdout must be exactly one JSON object, got %q", out)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(trimmed), &result); err != nil {
		t.Fatalf("stdout must be one JSON object: %v", err)
	}
	if result["stop_reason"] != "complete" {
		t.Fatalf("the clean drain keeps stop_reason complete, got %#v", result["stop_reason"])
	}
	if !strings.Contains(stderr, "2 records confirmed in 2 batches") {
		t.Fatalf("the concise human line moves to stderr under --json, got:\n%s", stderr)
	}

	// --progress-json: machine events on stderr, no human heartbeat.
	stateDir2 := t.TempDir()
	conciseBindDevice(t, stateDir2, server.URL)
	conciseSeedPending(t, stateDir2, 2)
	out2, stderr2, err2 := conciseRun("--state-dir", stateDir2, "--server", server.URL, "--progress-json", "--sync-timeout", "30s")
	if err2 != nil {
		t.Fatalf("the progress run must exit zero: %v\nstderr:\n%s", err2, stderr2)
	}
	if strings.Contains(out2, "Still running") || strings.Contains(stderr2, "Still running") {
		t.Fatalf("the machine-event mode adds no human heartbeat, stdout:\n%s\nstderr:\n%s", out2, stderr2)
	}
	sawEvent, sawHeartbeat := false, false
	for _, line := range strings.Split(stderr2, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var probe map[string]any
		if err := json.Unmarshal([]byte(line), &probe); err != nil {
			t.Fatalf("every progress line must be JSON, got %q: %v", line, err)
		}
		if probe["type"] != "collection_progress" {
			t.Fatalf("every stderr line must be a progress event, got %q", line)
		}
		sawEvent = true
		if probe["kind"] == "heartbeat" {
			sawHeartbeat = true
		}
	}
	if !sawEvent || !sawHeartbeat {
		t.Fatalf("the machine events must include batch and heartbeat kinds (event=%v heartbeat=%v), stderr:\n%s", sawEvent, sawHeartbeat, stderr2)
	}
}

// TestPeriodicDisplayErrorHostileInjection is the display-helper
// security regression: hostile strings injected through error text
// (URLs with userinfo/query/fragment, absolute paths, bearer tokens,
// raw session text) never reach the displayed line in either
// verbosity, while errors.Is/As keep matching through the wrapper.
func TestPeriodicDisplayErrorHostileInjection(t *testing.T) {
	hostile := fmt.Errorf("post %s failed after reading %s with %s session=%s",
		conciseHostileURL, conciseHostilePath, conciseHostileBearer, conciseHostileSession)
	sentinel := runlock.ErrBusy
	wrapped := fmt.Errorf("outer: %w: %v", sentinel, hostile)

	displayed := displayErrorText(hostile)
	for _, leak := range []string{conciseHostileURL, conciseHostilePath, conciseHostileBearer, conciseHostileSession, "user:pass", "TICKET-SECRET", "sk-live-SECRET"} {
		if strings.Contains(displayed, leak) {
			t.Fatalf("an unclassified error must collapse to the fixed fallback, got %q", displayed)
		}
	}
	if displayed != displayErrorText(hostile) || !strings.Contains(displayed, "details withheld; review the configuration before another run") {
		t.Fatalf("the fallback is a fixed text, got %q", displayed)
	}

	safe := safeDisplayError(wrapped, "curated safe reason")
	if safe.Error() != wrapped.Error() {
		t.Fatalf("the wrapper delegates Error() verbatim, got %q", safe.Error())
	}
	if !errors.Is(safe, sentinel) {
		t.Fatal("errors.Is must survive the wrapper")
	}
	if got := displayErrorText(safe); got != "curated safe reason" {
		t.Fatalf("displayErrorText shows the curated text, got %q", got)
	}
}

// TestPeriodicFlagValueEchoNeverLeaks pins the parse-error surface: a
// flag VALUE carrying a bearer token, URL or path is never echoed to
// either stream (the flag package's spontaneous output is captured and
// discarded), while the returned error keeps the raw text in its chain
// for errors.Is and the fixed safe text renders instead.
func TestPeriodicFlagValueEchoNeverLeaks(t *testing.T) {
	hostileValue := "BearerSECRET-" + conciseHostileBearer + "@" + conciseHostileURL
	out, stderr, err := conciseRun("--sync-timeout", "30s", "--max-batches", hostileValue)
	if err == nil {
		t.Fatalf("the hostile value must fail flag parsing, stdout:\n%s", out)
	}
	if !strings.Contains(err.Error(), hostileValue) {
		t.Fatalf("the returned error keeps the raw flag text in its chain, got %v", err)
	}
	displayed := displayErrorText(err)
	for _, leak := range []string{hostileValue, conciseHostileBearer, conciseHostileURL} {
		if strings.Contains(displayed, leak) || strings.Contains(out, leak) || strings.Contains(stderr, leak) {
			t.Fatalf("the hostile flag value must never reach an output stream, display=%q stdout=%q stderr=%q", displayed, out, stderr)
		}
	}
	if !strings.Contains(displayed, "invalid flag or flag value") {
		t.Fatalf("the parse failure renders the fixed safe text, got %q", displayed)
	}
	if stderr != "" {
		t.Fatalf("the flag package's spontaneous output is discarded, got:\n%s", stderr)
	}
}

// TestPeriodicHelpNeverLeaksEnvDefaults pins the -h surface: the
// automatic usage re-emitted on ErrHelp never carries the environment
// defaults (TOKTRAIL_SERVER_URL may hold a URL with credentials,
// TOKTRAIL_HOME a local path), and the help request keeps its
// historical exit path.
func TestPeriodicHelpNeverLeaksEnvDefaults(t *testing.T) {
	t.Setenv("TOKTRAIL_SERVER_URL", conciseHostileURL)
	t.Setenv("TOKTRAIL_HOME", conciseHostilePath)

	out, stderr, err := conciseRun("-h")
	if err == nil || !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("the help request keeps its historical error return, got %v", err)
	}
	for _, stream := range []string{out, stderr} {
		for _, leak := range []string{conciseHostileURL, conciseHostilePath, "user:pass", "TICKET-SECRET"} {
			if strings.Contains(stream, leak) {
				t.Fatalf("the -h usage must never echo environment defaults, got:\n%s", stream)
			}
		}
	}
	if !strings.Contains(stderr, "Usage of periodic") && !strings.Contains(stderr, "--sync-timeout") {
		t.Fatalf("the -h usage itself still prints (the convention), got:\n%s", stderr)
	}
	if !strings.Contains(displayErrorText(err), "help requested") {
		t.Fatalf("the ErrHelp display stays the static flag text, got %q", displayErrorText(err))
	}
}

// TestPeriodicPreRunErrorSafeTextAndCleanStreams pins the pre-run
// failure surface: a wiring error carrying hostile text produces NO
// human output (nothing ran; main's unified line is the single reason)
// while the returned error keeps the hostile text in its chain and the
// safe display stays curated.
func TestPeriodicPreRunErrorSafeTextAndCleanStreams(t *testing.T) {
	stateDir := t.TempDir()
	server := newConciseLogServer(t)
	conciseBindDevice(t, stateDir, server.URL)

	hostile := fmt.Errorf("wiring failed reading %s via %s (%s)", conciseHostilePath, conciseHostileURL, conciseHostileBearer)
	old := periodicCursorOptions
	periodicCursorOptions = func(stateDir, serverURL string, httpClient *http.Client) (*cursorsync.Options, error) {
		return nil, hostile
	}
	t.Cleanup(func() { periodicCursorOptions = old })

	out, stderr, err := conciseRun("--state-dir", stateDir, "--server", server.URL, "--sync-timeout", "30s")
	if err == nil {
		t.Fatalf("the wiring failure must exit non-zero, stdout:\n%s", out)
	}
	if !strings.Contains(err.Error(), conciseHostileURL) {
		t.Fatalf("the returned error keeps the hostile text in its chain, got %v", err)
	}
	if out != "" || stderr != "" {
		t.Fatalf("a pre-run failure prints no human output (main's line is the single surface), stdout:\n%s\nstderr:\n%s", out, stderr)
	}
	safe := displayErrorText(err)
	if safe != "cannot initialize the account source (cursor) wiring" {
		t.Fatalf("the safe display stays curated, got %q", safe)
	}
	// --json still emits exactly one object with the not-run verdict.
	outJSON, stderrJSON, errJSON := conciseRun("--state-dir", stateDir, "--server", server.URL, "--json", "--sync-timeout", "30s")
	if errJSON == nil {
		t.Fatalf("the --json wiring failure exits non-zero, stdout:\n%s", outJSON)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(outJSON)), &result); err != nil {
		t.Fatalf("stdout must be one JSON object: %v\n%s", err, outJSON)
	}
	if result["stop_reason"] != "fatal_error" {
		t.Fatalf("an unclassified wiring failure stays fatal_error, got %#v", result["stop_reason"])
	}
	if strings.Contains(outJSON, conciseHostileURL) || strings.Contains(stderrJSON, conciseHostileURL) {
		t.Fatalf("the hostile wiring text must never reach an output stream, stdout:\n%s\nstderr:\n%s", outJSON, stderrJSON)
	}
}

// TestPeriodicVerboseSanitizesFreeTextFields is the verbose
// sanitization regression: hostile free text (notes, skip diagnostics,
// pending reasons, input paths) injected into a result never reaches
// the --verbose log; the closed codes, counts and authored non-error
// skip wording still do.
func TestPeriodicVerboseSanitizesFreeTextFields(t *testing.T) {
	hostileNote := "note leaked " + conciseHostileURL + " " + conciseHostileSession
	hostileSkipped := "input not accessible: " + conciseHostilePath + " token " + conciseHostileBearer
	result := collection.Result{
		GrantSync: collection.GrantSync{
			Active:  true,
			Acked:   true,
			Note:    hostileNote,
			Pending: map[string]string{"HostileTool": hostileSkipped, "Claude Code": hostileSkipped},
			AddedGrants: []string{
				"claude-code-jsonl " + conciseHostilePath,
			},
		},
		Cursor: cursorsync.Result{
			Ran:     true,
			Outcome: cursorsync.RoundError,
			Skipped: hostileSkipped,
			Note:    hostileNote,
			Status:  "active",
		},
		GrantOutcomes: []collection.GrantOutcome{{
			Source:  "claude-code-jsonl",
			Input:   conciseHostilePath,
			Skipped: hostileSkipped,
			Code:    collection.GrantInputInaccessible,
		}},
	}
	var buf bytes.Buffer
	printPeriodicResult(&buf, result)
	out := buf.String()
	for _, leak := range []string{conciseHostileURL, conciseHostilePath, conciseHostileBearer, conciseHostileSession, "user:pass", "TICKET-SECRET", "sk-live-SECRET", "HostileTool"} {
		if strings.Contains(out, leak) {
			t.Fatalf("the verbose log must never carry hostile free text %q, got:\n%s", leak, out)
		}
	}
	for _, want := range []string{
		"note present (details withheld)",
		"cursor sync: failed (raw diagnostics withheld)",
		"grant Claude Code: skipped (input not accessible (details withheld))",
		"pending Claude Code (restriction details withheld)",
		"grantSync: added managed grant Claude Code (input path withheld)",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the verbose log must carry the sanitized line %q, got:\n%s", want, out)
		}
	}

	// The authored non-error skip vocabulary stays recognizable...
	result.Cursor.Outcome = cursorsync.RoundPaused
	result.Cursor.Skipped = "device is not authorized to upload (paused=true revoked=false)"
	buf.Reset()
	printPeriodicResult(&buf, result)
	if !strings.Contains(buf.String(), "cursor sync: paused") {
		t.Fatalf("the paused state renders its closed-set phrase, got:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "run toktrail") || strings.Contains(buf.String(), "full sync") {
		t.Fatalf("the closed-set phrases carry no reconnect or resync guidance, got:\n%s", buf.String())
	}

	// A contaminated persisted permit status reaches Skipped through the
	// permit-status fallback ("permit status %q"): only the strict
	// authored vocabulary prints; the hostile text is withheld.
	result.Cursor.Skipped = fmt.Sprintf("permit status %q does not collect", conciseHostileBearer)
	buf.Reset()
	printPeriodicResult(&buf, result)
	if strings.Contains(buf.String(), conciseHostileBearer) || strings.Contains(buf.String(), "permit status") {
		t.Fatalf("a contaminated permit status must be withheld, got:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "cursor sync: paused") {
		t.Fatalf("the hostile skip renders the closed outcome phrase, got:\n%s", buf.String())
	}

	// A contaminated batch id from persisted state never echoes: only
	// the strict local identifier shape prints, anything else withholds.
	result.Cursor.Outcome = cursorsync.RoundError
	result.Cursor.Skipped = hostileSkipped
	// No mode echoes a stored batch id: even a plain 64-hex ticket (the
	// shape that defeats charset checks) never prints — the verbose
	// line carries the per-run ORDINAL instead.
	hexTicket := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	leaky := collection.Result{
		GrantOutcomes: []collection.GrantOutcome{
			{Source: "claude-code-jsonl", Exported: true, BatchID: "batch " + conciseHostileBearer + " " + conciseHostileURL, Records: 2, Code: collection.GrantExported},
			{Source: "codex-jsonl", Exported: true, BatchID: hexTicket, Records: 1, Code: collection.GrantExported},
		},
	}
	buf.Reset()
	printPeriodicResult(&buf, leaky)
	if strings.Contains(buf.String(), conciseHostileBearer) || strings.Contains(buf.String(), conciseHostileURL) || strings.Contains(buf.String(), hexTicket) {
		t.Fatalf("a stored batch id must never echo in any mode, got:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "grant Claude Code: exported batch #1 records=2") {
		t.Fatalf("the first export renders its ordinal, got:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "grant Codex: exported batch #2 records=1") {
		t.Fatalf("the run-wide ordinals stay unique per exported batch, got:\n%s", buf.String())
	}

	// An outcome value outside the closed vocabulary renders as
	// "unknown", never as the raw string; an uncounted queue renders
	// pending=unknown, never a zero.
	weird := collection.Result{Cursor: cursorsync.Result{Status: "active", Skipped: "x", Outcome: cursorsync.RoundOutcome("evil-" + conciseHostileSession), PendingRemaining: 1}}
	buf.Reset()
	printPeriodicResult(&buf, weird)
	if strings.Contains(buf.String(), conciseHostileSession) || strings.Contains(buf.String(), "evil-") {
		t.Fatalf("an unknown outcome value must never echo, got:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "cursor sync: outcome=unknown pending=unknown") {
		t.Fatalf("the unknown outcome and uncounted pending render as unknown, got:\n%s", buf.String())
	}

	// The cursor counts line honors the same observation gate: an
	// uncounted queue never reads as pendingRemaining=0.
	uncounted := collection.Result{Cursor: cursorsync.Result{
		Ran: true, Status: "active", Outcome: cursorsync.RoundRan,
		ExportedBatches: 1, SyncedBatches: 2, SyncedRecords: 3,
		PendingRemaining: 0, PendingCounted: false,
	}}
	buf.Reset()
	printPeriodicResult(&buf, uncounted)
	if !strings.Contains(buf.String(), "cursor sync: exportedBatches=1 syncedBatches=2 syncedRecords=3 pendingRemaining=unknown") {
		t.Fatalf("an uncounted queue renders pendingRemaining=unknown, got:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "pendingRemaining=0") {
		t.Fatalf("an uncounted queue must never read as zero pending, got:\n%s", buf.String())
	}
}

// TestCanonicalToolDisplayMapsSourceIDs pins the source→tool display
// mapping: internal source identifiers render as their operator-facing
// canonical tool names (Codex for the codex source, Claude Code for
// the claude-code source), tool names match directly, and unknown or
// hostile names stay "unknown" — the internal id never reaches the
// display.
func TestCanonicalToolDisplayMapsSourceIDs(t *testing.T) {
	cases := map[string]string{
		"codex-jsonl":                    "Codex",
		"claude-code-jsonl":              "Claude Code",
		"workbuddy-jsonl":                "WorkBuddy",
		"qwen-jsonl":                     "Qwen Code",
		"zcode-sqlite":                   "ZCode",
		"openclaw-sqlite":                "OpenClaw",
		"Claude Code":                    "Claude Code", // a tool name matches directly
		"codex":                          "Codex",       // an alias matches directly
		"Hostile" + conciseHostileBearer: "unknown",
		"":                               "unknown",
	}
	for in, want := range cases {
		if got := canonicalToolDisplay(in); got != want {
			t.Fatalf("canonicalToolDisplay(%q) = %q, want %q", in, got, want)
		}
	}
	// The verbose grant line renders the canonical tool name for a
	// Codex grant outcome.
	res := collection.Result{GrantOutcomes: []collection.GrantOutcome{{
		Source: "codex-jsonl", Exported: true, BatchID: "b-1", Records: 3, Code: collection.GrantExported,
	}}}
	var buf bytes.Buffer
	printPeriodicResult(&buf, res)
	if !strings.Contains(buf.String(), "grant Codex: exported batch #1 records=3") {
		t.Fatalf("a codex grant renders its canonical tool name, got:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "codex-jsonl") {
		t.Fatalf("the internal source id never reaches the display, got:\n%s", buf.String())
	}
}

// TestPeriodicConciseFaultedSourcesClosedAndCanonical pins the concise
// faulted-sources clause: canonical registry names plus closed fault
// phrases, at most three named with the remainder counted, hostile
// source names collapsed to unknown, and no input paths or free text.
func TestPeriodicConciseFaultedSourcesClosedAndCanonical(t *testing.T) {
	mkStatus := func(source string, status collection.GrantSkipCode) collection.GrantSourceStatus {
		return collection.GrantSourceStatus{Source: source, Status: status}
	}
	summary := collection.RunSummary{StopReason: collection.StopFatalError}
	summary.Phases.Scan.Sources = []collection.GrantSourceStatus{
		mkStatus("Hostile<script>"+conciseHostileBearer, collection.GrantInputInaccessible),
		mkStatus("claude-code-jsonl", collection.GrantInputInaccessible),
		mkStatus("codex-jsonl", collection.GrantExportFailed),
		mkStatus("workbuddy-jsonl", collection.GrantSplitFailed),
		mkStatus("qwen-jsonl", collection.GrantInputInaccessible),
	}
	var buf bytes.Buffer
	periodicConciseResult(&buf, summary, false, time.Now())
	out := buf.String()
	for _, leak := range []string{conciseHostileBearer, "<script>", "/Users"} {
		if strings.Contains(out, leak) {
			t.Fatalf("the faulted-sources clause must never echo hostile names, got:\n%s", out)
		}
	}
	for _, want := range []string{
		"5 source(s) did not complete:",
		"unknown (input not accessible)",
		"Claude Code (input not accessible)",
		"Codex (export preparation failed)",
		", and 2 more",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the faulted-sources clause must carry %q, got:\n%s", want, out)
		}
	}
	// Well-formed with no faults: no clause at all.
	clean := collection.RunSummary{StopReason: collection.StopComplete}
	clean.Phases.Scan.Sources = []collection.GrantSourceStatus{mkStatus("claude-code-jsonl", collection.GrantNoNewRecords)}
	buf.Reset()
	periodicConciseResult(&buf, clean, false, time.Now())
	if strings.Contains(buf.String(), "did not complete") {
		t.Fatalf("a healthy scan renders no fault clause, got:\n%s", buf.String())
	}
}

// TestPeriodicHumanHeartbeatThrottleAndGates pins the heartbeat
// filter: machine events are dropped, the first line waits out the
// interval, subsequent lines keep the cadence, and the pending counts
// honor the observation gates (an uncounted queue never reads as
// zero). The write goes through the serialized writer's
// WriteProgressLine so an open prompt line is completed first.
func TestPeriodicHumanHeartbeatThrottleAndGates(t *testing.T) {
	start := time.Date(2026, 11, 2, 8, 0, 0, 0, time.UTC)
	cur := start
	hb := &periodicHumanHeartbeat{
		out:      newSerializedWriter(&bytes.Buffer{}),
		started:  start,
		now:      func() time.Time { return cur },
		interval: 30 * time.Second,
	}

	// Machine events never render.
	hb.handle(collection.ProgressEvent{Kind: collection.ProgressBatch, Queue: "device"})
	hb.handle(collection.ProgressEvent{Kind: collection.ProgressQueue, Queue: "device"})
	// Heartbeats inside the first interval stay silent.
	for i := 0; i < 5; i++ {
		cur = start.Add(time.Duration(i+1) * 5 * time.Second)
		hb.handle(collection.ProgressEvent{Kind: collection.ProgressHeartbeat, Stage: "drain"})
	}
	buf := hb.out.(*serializedWriter).w.(*bytes.Buffer)
	if buf.Len() != 0 {
		t.Fatalf("no heartbeat line may render before the interval, got:\n%s", buf.String())
	}
	// At the interval: one line, gated pending unknown.
	cur = start.Add(30 * time.Second)
	hb.handle(collection.ProgressEvent{Kind: collection.ProgressHeartbeat, Stage: "drain"})
	first := buf.String()
	if !strings.Contains(first, "Still running: 30s elapsed") || !strings.Contains(first, "uploading pending batches") || !strings.Contains(first, "pending unknown") {
		t.Fatalf("the first heartbeat carries the closed-set stage phrase and gated pending, got:\n%s", first)
	}
	if strings.Contains(first, "stage ") || strings.Contains(first, "drain,") {
		t.Fatalf("the heartbeat never echoes the raw stage token, got:\n%s", first)
	}
	// Within the next interval: silent even with counted snapshots.
	cur = start.Add(45 * time.Second)
	hb.handle(collection.ProgressEvent{Kind: collection.ProgressHeartbeat, Stage: "drain", Counted: true, PendingBatches: 4, RecordsCounted: true, PendingRecords: 9})
	if buf.String() != first {
		t.Fatalf("the throttle keeps one line per interval, got:\n%s", buf.String())
	}
	// After the interval: the counted snapshot renders.
	cur = start.Add(61 * time.Second)
	hb.handle(collection.ProgressEvent{Kind: collection.ProgressHeartbeat, Stage: "drain", Counted: true, PendingBatches: 4, RecordsCounted: true, PendingRecords: 9, AttemptInFlightKnown: true, AttemptInFlight: true})
	second := strings.TrimPrefix(buf.String(), first)
	if !strings.Contains(second, "Still running: 1m01s elapsed") || !strings.Contains(second, "4 batches pending (9 records)") || !strings.Contains(second, "uploading a batch") {
		t.Fatalf("the counted heartbeat renders its gates, got:\n%s", second)
	}

	// A stage value outside the closed vocabulary (contaminated state,
	// a token) collapses to the fixed "working" and never echoes.
	cur = start.Add(91 * time.Second)
	hb.handle(collection.ProgressEvent{Kind: collection.ProgressHeartbeat, Stage: "evil-" + conciseHostileBearer, Counted: true, PendingBatches: 1, RecordsCounted: true, PendingRecords: 1})
	third := strings.TrimPrefix(buf.String(), first+second)
	if !strings.Contains(third, ", working,") {
		t.Fatalf("an unknown stage renders the fixed working phrase, got:\n%s", third)
	}
	if strings.Contains(third, conciseHostileBearer) || strings.Contains(third, "evil-") {
		t.Fatalf("a hostile stage value must never echo, got:\n%s", third)
	}
}

// TestPeriodicRunErrorSafeTextSentinels pins the closed-set sentinel
// mapping of the generic run-error display: permission and timeout
// sentinels render their fixed short reasons (no paths, URLs or free
// text), the known sentinels keep their curated wording, unknown
// errors collapse to the fixed fallback, and the JSON/stop_reason
// classification is unaffected (display-only).
func TestPeriodicRunErrorSafeTextSentinels(t *testing.T) {
	hostile := fmt.Errorf("open %s via %s failed: %s", conciseHostilePath, conciseHostileURL, conciseHostileSession)
	// Direct sentinel cases.
	if got := periodicRunErrorSafeText(fmt.Errorf("wrap: %w %v", os.ErrPermission, hostile), nil); got != "local access denied; check permissions" {
		t.Fatalf("a permission sentinel renders its fixed reason, got %q", got)
	}
	if got := periodicRunErrorSafeText(fmt.Errorf("wrap: %w %v", context.DeadlineExceeded, hostile), nil); got != "operation timed out" {
		t.Fatalf("a bare in-chain deadline renders the timeout reason, got %q", got)
	}
	if got := periodicRunErrorSafeText(fmt.Errorf("wrap: %w", os.ErrDeadlineExceeded), nil); got != "operation timed out" {
		t.Fatalf("the os deadline sentinel renders the timeout reason, got %q", got)
	}
	if got := periodicRunErrorSafeText(fmt.Errorf("wrap: %w", runlock.ErrBusy), nil); got != "another collector process holds the collector state lock; no work was performed" {
		t.Fatalf("the busy sentinel keeps its curated wording, got %q", got)
	}
	if got := periodicRunErrorSafeText(fmt.Errorf("wrap: %w", context.Canceled), nil); got != "the run was cancelled before it finished" {
		t.Fatalf("the cancel sentinel keeps its curated wording, got %q", got)
	}
	// Unknown hostile error: the fixed fallback, never the raw text.
	got := periodicRunErrorSafeText(hostile, nil)
	if got != "the collection round failed (details withheld; review the configuration before another run)" {
		t.Fatalf("an unknown error collapses to the fixed fallback, got %q", got)
	}
	for _, leak := range []string{conciseHostilePath, conciseHostileURL, conciseHostileSession} {
		if strings.Contains(got, leak) {
			t.Fatalf("the fallback never carries hostile text, got %q", got)
		}
	}
	// The display wrapper keeps the sentinel matchable (JSON verdicts
	// classify through it unchanged).
	wrapped := safeDisplayError(fmt.Errorf("outer: %w", os.ErrPermission), "curated")
	if !errors.Is(wrapped, os.ErrPermission) {
		t.Fatal("errors.Is must survive the display wrapper")
	}
	if displayErrorText(wrapped) != "curated" {
		t.Fatalf("the curated text renders, got %q", displayErrorText(wrapped))
	}
}

// TestPeriodicConcisePendingHonorsObservationGates pins the pending
// clause's honesty at the renderer level: an unobserved queue never
// reads as zero pending; the drain-only not-read shape and the counted
// shapes render their natural wording.
func TestPeriodicConcisePendingHonorsObservationGates(t *testing.T) {
	cases := []struct {
		name      string
		drain     collection.DrainSummary
		account   collection.AccountDrainSummary
		drainOnly bool
		want      string
	}{
		{
			name:    "both_observed_empty",
			drain:   collection.DrainSummary{PendingObserved: true},
			account: collection.AccountDrainSummary{PendingObserved: true},
			want:    "nothing pending",
		},
		{
			name:    "both_observed_remainder",
			drain:   collection.DrainSummary{PendingObserved: true, PendingRemaining: 2},
			account: collection.AccountDrainSummary{PendingObserved: true, PendingRemaining: 1},
			want:    "3 batches pending",
		},
		{
			name:      "drain_only_not_read",
			drain:     collection.DrainSummary{PendingObserved: true},
			account:   collection.AccountDrainSummary{Outcome: cursorsync.RoundAbsent},
			drainOnly: true,
			want:      "device queue empty, nothing was scanned and the account queue was not read (drain-only)",
		},
		{
			// RoundAbsent WITHOUT the drain-only flag: the mode is not
			// inferable from the outcome, so the wording stays neutral.
			name:    "absent_round_not_drain_only",
			drain:   collection.DrainSummary{PendingObserved: true},
			account: collection.AccountDrainSummary{Outcome: cursorsync.RoundAbsent},
			want:    "device queue empty; account queue not read",
		},
		{
			name:    "absent_round_not_drain_only_with_remainder",
			drain:   collection.DrainSummary{PendingObserved: true, PendingRemaining: 2},
			account: collection.AccountDrainSummary{Outcome: cursorsync.RoundAbsent},
			want:    "2 batches pending on the device queue; account queue not read",
		},
		{
			name:    "cursor_unobserved",
			drain:   collection.DrainSummary{PendingObserved: true, PendingRemaining: 2},
			account: collection.AccountDrainSummary{Outcome: cursorsync.RoundNoPermit},
			want:    "2 batches pending on the device queue; cursor pending unknown",
		},
		{
			// The account queue was measured empty while the device
			// queue was not: neutral, never a global claim.
			name:    "account_observed_empty_device_unobserved",
			drain:   collection.DrainSummary{},
			account: collection.AccountDrainSummary{PendingObserved: true},
			want:    "account queue empty; device pending unknown",
		},
		{
			// A KNOWN positive account queue is never swallowed by the
			// unknown device side.
			name:    "account_observed_positive_device_unobserved",
			drain:   collection.DrainSummary{},
			account: collection.AccountDrainSummary{PendingObserved: true, PendingRemaining: 2},
			want:    "2 account batches pending; device pending unknown",
		},
		{
			name:    "account_observed_one_device_unobserved",
			drain:   collection.DrainSummary{},
			account: collection.AccountDrainSummary{PendingObserved: true, PendingRemaining: 1},
			want:    "1 account batch pending; device pending unknown",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := periodicPendingClause(tc.drain, tc.account, tc.drainOnly); got != tc.want {
				t.Fatalf("pending clause mismatch:\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

// TestPeriodicConciseIdleClaimRequiresProof pins the "no new records"
// rule at the summary level: it needs a real scan verdict
// (GrantNoNewRecords/GrantExported) or an account pull, the clean
// exit-zero shapes, and nothing new anywhere; all-not-allowed grants,
// drain-only and no-grants shapes keep the neutral wording.
func TestPeriodicConciseIdleClaimRequiresProof(t *testing.T) {
	base := collection.RunSummary{
		Phases: collection.Phases{
			Scan: collection.ScanSummary{
				Grants: 2,
				Sources: []collection.GrantSourceStatus{
					{Source: "claude-code-jsonl", Status: collection.GrantNoNewRecords},
					{Source: "codex-jsonl", Status: collection.GrantNotAllowed},
				},
			},
		},
	}
	mk := func(mutate func(*collection.RunSummary)) collection.RunSummary {
		s := base
		mutate(&s)
		return s
	}
	complete := mk(func(s *collection.RunSummary) { s.StopReason = collection.StopComplete })
	var buf bytes.Buffer
	periodicConciseResult(&buf, complete, false, time.Now())
	if !strings.Contains(buf.String(), "no new records") {
		t.Fatalf("a proven empty scan claims no new records, got:\n%s", buf.String())
	}

	// All grants not-allowed: nothing was scanned → neutral.
	notAllowed := mk(func(s *collection.RunSummary) {
		s.StopReason = collection.StopComplete
		s.Phases.Scan.Sources = []collection.GrantSourceStatus{
			{Source: "claude-code-jsonl", Status: collection.GrantNotAllowed},
			{Source: "codex-jsonl", Status: collection.GrantNotAllowed},
		}
	})
	buf.Reset()
	periodicConciseResult(&buf, notAllowed, false, time.Now())
	if strings.Contains(buf.String(), "no new records") {
		t.Fatalf("an all-not-allowed scan proves nothing and stays neutral, got:\n%s", buf.String())
	}

	// No grants at all: neutral.
	noGrants := mk(func(s *collection.RunSummary) {
		s.StopReason = collection.StopComplete
		s.Phases.Scan.Grants = 0
		s.Phases.Scan.Sources = nil
	})
	buf.Reset()
	periodicConciseResult(&buf, noGrants, false, time.Now())
	if strings.Contains(buf.String(), "no new records") {
		t.Fatalf("a no-grants run stays neutral, got:\n%s", buf.String())
	}

	// An exported source: new records exist → never the idle claim.
	exported := mk(func(s *collection.RunSummary) {
		s.StopReason = collection.StopComplete
		s.Phases.Scan.Sources = []collection.GrantSourceStatus{
			{Source: "claude-code-jsonl", Status: collection.GrantExported},
		}
		s.Phases.Counts.ExportedRecords = 3
	})
	buf.Reset()
	periodicConciseResult(&buf, exported, false, time.Now())
	if strings.Contains(buf.String(), "no new records") {
		t.Fatalf("an exported scan never claims no new records, got:\n%s", buf.String())
	}

	// An incomplete status with an otherwise empty scan: neutral.
	incomplete := mk(func(s *collection.RunSummary) { s.StopReason = collection.StopFatalError })
	buf.Reset()
	periodicConciseResult(&buf, incomplete, false, time.Now())
	if strings.Contains(buf.String(), "no new records") {
		t.Fatalf("a non-clean status never claims no new records, got:\n%s", buf.String())
	}

	// A PARTIAL verdict with a proven empty scan never claims
	// "no new records" either: unexamined scope (an uncovered
	// authorized source) keeps the neutral wording.
	partial := mk(func(s *collection.RunSummary) { s.StopReason = collection.StopPartial })
	buf.Reset()
	periodicConciseResult(&buf, partial, false, time.Now())
	if strings.Contains(buf.String(), "no new records") {
		t.Fatalf("a partial verdict never claims no new records, got:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "no records confirmed") {
		t.Fatalf("a partial verdict keeps the neutral wording, got:\n%s", buf.String())
	}

	// The account pull alone also proves the scan ran.
	accountOnly := collection.RunSummary{StopReason: collection.StopComplete}
	accountOnly.Phases.Scan.Account.Ran = true
	buf.Reset()
	periodicConciseResult(&buf, accountOnly, false, time.Now())
	if !strings.Contains(buf.String(), "no new records") {
		t.Fatalf("an account pull with nothing new claims no new records, got:\n%s", buf.String())
	}
}
