package connect

// C2 display-layer tests for the connect enable line: a malicious
// server may place attacker-chosen text in a source's State (and in the
// identifier), and the line printed into the run's human output — the
// same stream that carries progress JSONL under --json — must map them
// onto the fixed display vocabulary instead of echoing them. The state
// machine, permit handling and exit codes are untouched. Everything is
// synthetic (tempdir state, httptest fakes, injected providers,
// synthetic secrets); no real credentials or state are ever touched.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/cursor/protocol"
)

// startMaliciousCursorMock fakes the TokTrail server for a cursor-wired
// connect run whose source fields carry attacker-chosen text: the
// enable response and the self view both report State (and an
// identifier) full of it. No credential material is ever reflected.
func startMaliciousCursorMock(t *testing.T, attackerID, attackerState string) *httptest.Server {
	t.Helper()
	src := func() protocol.Source {
		return protocol.Source{
			SourceInstanceID: attackerID,
			SourceType:       protocol.SourceType,
			State:            attackerState,
			FenceVersion:     1,
			NextRevision:     1,
		}
	}
	writeJSON := func(w http.ResponseWriter, status int, body any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/devices/bind":
			writeJSON(w, http.StatusCreated, map[string]any{"device": map[string]any{
				"deviceId":          cursorTestDeviceID,
				"applicationId":     "app-cursor-1",
				"externalSubjectId": cursorTestSubjectID,
				"deviceName":        "collector",
				"platform":          "test",
				"consentRevision":   1,
				"boundAt":           cursorTestNow.Format(time.RFC3339),
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self":
			writeJSON(w, http.StatusOK, map[string]any{"device": map[string]any{
				"deviceId":          cursorTestDeviceID,
				"applicationId":     "app-cursor-1",
				"externalSubjectId": cursorTestSubjectID,
				"consentRevision":   1,
				"uploadAuthorized":  true,
				"publicAuthorized":  false,
				"revoked":           false,
				"accountSources":    []protocol.Source{src()},
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/account-sources/enable":
			writeJSON(w, http.StatusOK, map[string]any{"source": src()})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/source-batches":
			var batch struct {
				BatchID string            `json:"batchId"`
				Records []json.RawMessage `json:"records"`
			}
			_ = json.NewDecoder(r.Body).Decode(&batch)
			writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
				"batchId":         batch.BatchID,
				"status":          "accepted",
				"acceptedRecords": len(batch.Records),
				"rejectedRecords": 0,
				"replay":          false,
				"receivedAt":      cursorTestNow.Format(time.RFC3339),
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/batches":
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
			writeJSON(w, http.StatusOK, map[string]any{"features": []string{"account-sources"}})
		default:
			writeJSON(w, http.StatusOK, map[string]any{})
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// serializedDisplayStream mirrors the CLI's mixed stderr stream: one
// mutex serializes the human output and the progress JSONL lines that
// share it under --json + --progress-json.
type serializedDisplayStream struct {
	mu sync.Mutex
	w  bytes.Buffer
}

func (s *serializedDisplayStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

func (s *serializedDisplayStream) writeProgressLine(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.w.WriteString(line + "\n")
}

func (s *serializedDisplayStream) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.String()
}

// The connect enable line over a malicious server: the attacker's State
// text (and identifier) never echo — the fixed vocabulary displays —
// while the run keeps its readable sync counts, and the progress JSONL
// sharing the same serialized stream stays per-line parseable.
func TestConnectCursorEnableDisplaySanitizesMaliciousServer(t *testing.T) {
	const attackerID = "synthetic-connect-attacker-id-Kk4"
	const attackerState = "synthetic-connect-attacker-state-Jj6"

	toktrail := startMaliciousCursorMock(t, attackerID, attackerState)
	cfgServer := startConnectConfigMock(t, Config{
		SchemaVersion: 1,
		ServerURL:     toktrail.URL,
		ApplicationID: "app-cursor-1",
		SubjectID:     cursorTestSubjectID,
		Tools:         []string{"Cursor"},
		Days:          intPtr(30),
		ExpiresAt:     cursorTestNow.Add(24 * time.Hour).Format(time.RFC3339),
	})

	stream := &serializedDisplayStream{}
	res, err := Run(context.Background(), Options{
		URL:             fmt.Sprintf("%s/api/collector/connect#%s", cfgServer.URL, strings.Repeat("9", 64)),
		StateDir:        t.TempDir(),
		HomeDir:         t.TempDir(),
		BinaryPath:      fakeCollectorBinary(t),
		HTTPClient:      cfgServer.Client(),
		SchedulerRunner: &mockRunner{},
		Now:             func() time.Time { return cursorTestNow },
		Out:             stream,
		Cursor: &cursorsync.Options{
			Auth:   &fakeCursorAuth{},
			Verify: fakeCursorVerify,
			Pull:   (&fakeCursorPull{events: cursorFixtureEvents()}).Pull,
			Now:    func() time.Time { return cursorTestNow },
		},
		CursorConfirm: func(string, io.Writer) (bool, error) { return true, nil },
		Progress: func(ev collection.ProgressEvent) {
			// Progress JSONL rides the same serialized stream, exactly
			// like the CLI's mixed stderr under --json + --progress-json.
			b, _ := json.Marshal(map[string]any{
				"type": "collection_progress", "kind": ev.Kind, "queue": ev.Queue,
			})
			stream.writeProgressLine(string(b))
		},
	})
	if err == nil {
		// A malicious state legitimately withholds collection: the run
		// must surface it (the state machine is untouched by the display
		// layer). The FAILURE itself must be sanitized too.
		t.Fatalf("the malicious server state must surface as a failed run, got %+v", res)
	}
	if strings.Contains(err.Error(), attackerID) || strings.Contains(err.Error(), attackerState) {
		t.Fatalf("the run error must not echo the attacker's source fields: %v", err)
	}

	out := stream.String()
	// Neither attacker-controlled value may echo anywhere in the stream.
	if strings.Contains(out, attackerID) || strings.Contains(out, attackerState) {
		t.Fatalf("the run output must not echo the attacker's source fields, got:\n%s", out)
	}
	// The enable line carries the fixed vocabulary and stays readable.
	if !strings.Contains(out, "enabled (source configured, state=unknown)") {
		t.Fatalf("the enable line must carry the sanitized labels, got:\n%s", out)
	}
	// The progress lines sharing the stream stay per-line parseable with
	// their type discriminator.
	progressLines := 0
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || !strings.HasPrefix(trimmed, "{") {
			continue
		}
		var probe map[string]any
		if err := json.Unmarshal([]byte(trimmed), &probe); err != nil {
			t.Fatalf("a JSON line in the mixed stream must stay parseable, got %q: %v", line, err)
		}
		if probe["type"] != "collection_progress" {
			t.Fatalf("a JSON line in the mixed stream must be a progress event: %q", line)
		}
		progressLines++
	}
	if progressLines == 0 {
		t.Fatalf("the progress events must share the mixed stream, got:\n%s", out)
	}
}

// The display vocabulary twin in this package matches the fixed set.
func TestConnectDisplaySourceStateVocabulary(t *testing.T) {
	cases := map[string]string{
		"active":   "active",
		"pending":  "pending",
		"paused":   "paused",
		"":         "unspecified",
		"attacker": "unknown",
	}
	for in, want := range cases {
		if got := displaySourceState(in); got != want {
			t.Fatalf("displaySourceState(%q) = %q, want %q", in, got, want)
		}
	}
	if got := sourceConfiguredLabel("anything-at-all"); got != "configured" {
		t.Fatalf("a non-empty identifier displays as configured, got %q", got)
	}
	if got := sourceConfiguredLabel(""); got != "not configured" {
		t.Fatalf("an empty identifier is not configured, got %q", got)
	}
}
