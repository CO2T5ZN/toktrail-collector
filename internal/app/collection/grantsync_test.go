package collection

import (
	"encoding/json"
	"errors"
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

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/managedconsent"
	"toktrail-collector/internal/local/statedir"
	synccmd "toktrail-collector/internal/syncclient"
)

// ---------------------------------------------------------------------------
// grant-protocol fake server
// ---------------------------------------------------------------------------

// grantAckPendingReasonBody mirrors one pendingReasons grant-ack entry.
type grantAckPendingReasonBody struct {
	Tool string `json:"tool"`
	Code string `json:"code"`
}

// grantAckBody mirrors the POST /v1/devices/grant-ack body.
type grantAckBody struct {
	ConsentRevision  int64                       `json:"consentRevision"`
	ApplyState       string                      `json:"applyState"`
	CollectorVersion string                      `json:"collectorVersion"`
	SupportedTools   []string                    `json:"supportedTools"`
	PendingReasons   []grantAckPendingReasonBody `json:"pendingReasons"`
}

// grantAckBody.carriesCapabilities reports whether the decoded body
// included the optional capability fields.
func (b grantAckBody) carriesCapabilities() bool {
	return len(b.SupportedTools) > 0 || len(b.PendingReasons) > 0
}

// grantView is one served device grant view.
type grantView struct {
	paused   bool
	tools    []string
	revision int64
}

// grantProtocolServer is a fake server that speaks the device grant
// protocol on GET /v1/devices/self and POST /v1/devices/grant-ack, while
// accepting ingest and tool-status traffic. Only synthetic fixtures are
// ever sent.
type grantProtocolServer struct {
	*httptest.Server

	mu                 sync.Mutex
	grantProtocol      *int // nil = old server without the grant protocol
	view               grantView
	historyFrom        *string
	revoked            bool
	deviceID           string     // deviceId served in the self view
	ackStatus          int        // HTTP status for grant-ack
	ackEchoOffset      int64      // added to the echoed revision (mismatch tests)
	ackCurrentBump     int64      // added to currentConsentRevision (stale tests)
	alwaysAdvancing    bool       // every ack reports a newer current revision AND advances the served view
	deviceGrantManaged *bool      // served deviceGrantManaged; nil omits the field
	advanceOnAck       *grantView // served view switches after the next ack
	failSelfWith       *int       // non-nil: self GET responds with this status and an empty JSON object
	garbageSelf        bool       // self GET responds 200 with an undecodable body
	dropProtocol       bool       // self GET omits grantProtocolVersion
	// rejectAckCapabilities emulates an old server that validates the
	// grant-ack body against a closed schema: any ack carrying the
	// optional supportedTools/pendingReasons fields is rejected with 400.
	rejectAckCapabilities bool

	total   atomic.Int64
	self    atomic.Int64
	ack     atomic.Int64
	ingest  atomic.Int64
	tooling atomic.Int64

	authSeen    []string
	ackBodies   []grantAckBody
	ackRaw      []string
	toolReports []toolStatusReport
}

func grantProtocolServerStart(t *testing.T) *grantProtocolServer {
	t.Helper()
	s := &grantProtocolServer{
		ackStatus: http.StatusOK,
		deviceID:  "dev-1",
		view:      grantView{revision: 11, tools: []string{"Claude Code"}},
	}
	proto := 1
	s.grantProtocol = &proto
	managed := true
	s.deviceGrantManaged = &managed
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.total.Add(1)
		if auth := r.Header.Get("Authorization"); auth != "" {
			s.mu.Lock()
			s.authSeen = append(s.authSeen, auth)
			s.mu.Unlock()
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self":
			s.self.Add(1)
			s.mu.Lock()
			failStatus, dropProtocol, garbage := s.failSelfWith, s.dropProtocol, s.garbageSelf
			view, proto, historyFrom, revoked, deviceID := s.view, s.grantProtocol, s.historyFrom, s.revoked, s.deviceID
			managed := s.deviceGrantManaged
			s.mu.Unlock()
			if garbage {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("this is not json"))
				return
			}
			if failStatus != nil {
				writeJSONForTest(w, *failStatus, map[string]any{})
				return
			}
			device := map[string]any{
				"deviceId":         deviceID,
				"consentRevision":  view.revision,
				"uploadAuthorized": !revoked,
				"revoked":          revoked,
				"paused":           view.paused,
				"allowedTools":     view.tools,
			}
			if !dropProtocol && proto != nil {
				device["grantProtocolVersion"] = *proto
			}
			if managed != nil {
				device["deviceGrantManaged"] = *managed
			}
			if historyFrom != nil {
				device["historyFrom"] = *historyFrom
			}
			writeJSONForTest(w, http.StatusOK, map[string]any{"device": device})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/devices/grant-ack":
			s.ack.Add(1)
			raw, rerr := io.ReadAll(r.Body)
			if rerr != nil {
				t.Errorf("cannot read grant-ack body: %v", rerr)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var body grantAckBody
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Errorf("invalid grant-ack body: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			s.mu.Lock()
			s.ackBodies = append(s.ackBodies, body)
			s.ackRaw = append(s.ackRaw, string(raw))
			rejectCapabilities := s.rejectAckCapabilities
			status, echoOffset, bump, advancing, advance := s.ackStatus, s.ackEchoOffset, s.ackCurrentBump, s.alwaysAdvancing, s.advanceOnAck
			s.ackCurrentBump = 0
			if advance != nil {
				s.view = *advance
				s.advanceOnAck = nil
			}
			s.mu.Unlock()
			if rejectCapabilities {
				// Strict closed-schema validation like an old server:
				// the unknown KEYS are rejected whatever their value,
				// including an explicit empty pendingReasons array.
				var keys map[string]json.RawMessage
				if err := json.Unmarshal(raw, &keys); err == nil {
					if _, ok := keys["supportedTools"]; ok {
						writeJSONForTest(w, http.StatusBadRequest, map[string]any{"error": map[string]any{
							"code": "invalid_request", "message": "unknown field supportedTools",
						}})
						return
					}
					if _, ok := keys["pendingReasons"]; ok {
						writeJSONForTest(w, http.StatusBadRequest, map[string]any{"error": map[string]any{
							"code": "invalid_request", "message": "unknown field pendingReasons",
						}})
						return
					}
				}
			}
			if status != http.StatusOK && status != http.StatusAccepted {
				// Real servers pair non-2xx statuses with a JSON error
				// body; the collector's classification reads it.
				writeJSONForTest(w, status, map[string]any{"error": map[string]any{
					"code":    "invalid_request",
					"message": "simulated grant-ack failure",
				}})
				return
			}
			current := body.ConsentRevision
			if advancing {
				current = body.ConsentRevision + 1
				s.view.revision = body.ConsentRevision + 1
			} else if bump > 0 {
				current = body.ConsentRevision + bump
			}
			echoedState := body.ApplyState
			if echoedState == "" {
				echoedState = "applied"
			}
			writeJSONForTest(w, status, map[string]any{"grantAck": map[string]any{
				"consentRevision":        body.ConsentRevision + echoOffset,
				"currentConsentRevision": current,
				"ackedState":             echoedState,
				"ackedAt":                "2026-10-27T08:00:00Z",
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/batches":
			s.ingest.Add(1)
			var body struct {
				BatchID string           `json:"batchId"`
				Records []map[string]any `json:"records"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("invalid ingest body: %v", err)
			}
			writeJSONForTest(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
				"batchId":         body.BatchID,
				"status":          "accepted",
				"acceptedRecords": len(body.Records),
				"rejectedRecords": 0,
				"replay":          false,
				"receivedAt":      "2026-10-27T08:01:00Z",
			}})
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
			s.mu.Lock()
			s.toolReports = append(s.toolReports, body.Statuses...)
			s.mu.Unlock()
			writeJSONForTest(w, http.StatusAccepted, map[string]any{"accepted": true})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Server.Close)
	return s
}

func (s *grantProtocolServer) setView(t *testing.T, paused bool, tools []string, revision int64) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.view = grantView{paused: paused, tools: tools, revision: revision}
}

func (s *grantProtocolServer) ackRequests() int64    { return s.ack.Load() }
func (s *grantProtocolServer) ingestRequests() int64 { return s.ingest.Load() }
func (s *grantProtocolServer) totalRequests() int64  { return s.total.Load() }

func (s *grantProtocolServer) lastAckBody() grantAckBody {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ackBodies) == 0 {
		return grantAckBody{}
	}
	return s.ackBodies[len(s.ackBodies)-1]
}

// allAckBodies returns every received grant-ack body, including those
// the (legacy-fake) server rejected.
func (s *grantProtocolServer) allAckBodies() []grantAckBody {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]grantAckBody, len(s.ackBodies))
	copy(out, s.ackBodies)
	return out
}

// allAckRawBodies returns every received grant-ack body as raw JSON.
func (s *grantProtocolServer) allAckRawBodies() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.ackRaw))
	copy(out, s.ackRaw)
	return out
}

func (s *grantProtocolServer) toolStatusReports() []toolStatusReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]toolStatusReport, len(s.toolReports))
	copy(out, s.toolReports)
	return out
}

func (s *grantProtocolServer) requireAuthBearer(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, auth := range s.authSeen {
		if auth != "Bearer dev-1."+testSecret {
			t.Fatalf("device credentials missing or wrong, got %q", auth)
		}
	}
	if len(s.authSeen) == 0 {
		t.Fatal("no authenticated request reached the server")
	}
}

func loadOverlayForTest(t *testing.T, stateDir string) managedconsent.Overlay {
	t.Helper()
	o, seen, err := managedconsent.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if !seen {
		t.Fatal("expected the managed-consent overlay to exist")
	}
	return o
}

// writeDSHSession writes a minimal synthetic DeepSeek Harness session under
// a DSH sessions root (layout <root>/<project>/<session>/session.jsonl).
func writeDSHSession(t *testing.T, root, sessionID string) {
	t.Helper()
	dir := filepath.Join(root, "--demo--", sessionID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	lines := []string{
		`{"type":"session","version":4,"id":"` + sessionID + `","createdAt":1698000000000,"isSeeded":false,"delegationDepth":0,"cwd":"/work/demo"}`,
		`{"type":"turn/start","seq":1,"time":1698000001000,"data":{"turn":1}}`,
		`{"type":"user/message","seq":2,"time":1698000002000,"data":{"turn":1,"message":{"role":"user","content":"synthetic"}}}`,
		`{"type":"step/start","seq":3,"time":1698000003000,"data":{"turn":1,"step":0}}`,
		`{"type":"assistant/message","seq":4,"time":1698000004000,"data":{"turn":1,"step":0,"usage":{"inputTokens":100,"outputTokens":40,"cacheReadTokens":10,"cacheWriteTokens":20,"totalTokens":170},"message":{"source":{"kind":"model","provider":"deepseek","model":"deepseek-chat"}}}}`,
		`{"type":"step/end","seq":5,"time":1698000005000,"data":{"turn":1,"step":0}}`,
		`{"type":"turn/end","seq":6,"time":1698000006000,"data":{"turn":1}}`,
	}
	if err := os.WriteFile(filepath.Join(dir, "session.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// grant sync behavior
// ---------------------------------------------------------------------------

// The grant sync narrows reading to the effective allowedTools intersection
// with the built-in registry, applies the view durably, and acknowledges
// the applied revision with the device credentials.
func TestGrantSyncAppliesScopeAndAcks(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 11)
	bindDevice(t, stateDir, server.URL)

	claude := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, claude, "s.jsonl",
		claudeLine(t, "2026-10-26T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))
	enableGrant(t, stateDir, "claude-code-jsonl", claude)
	codex := filepath.Join(t.TempDir(), "codex")
	writeCodexSession(t, codex, "rollout-a.jsonl",
		codexTokenCount("2026-10-26T04:00:00Z", 100, 0, 0, 50),
		codexTokenCount("2026-10-26T04:01:00Z", 160, 0, 0, 80))
	enableGrant(t, stateDir, "codex-jsonl", codex)

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir(), CollectorVersion: "v0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.GrantSync.Active || res.GrantSync.Paused || !res.GrantSync.Refreshed || !res.GrantSync.Acked {
		t.Fatalf("unexpected grant sync result: %#v", res.GrantSync)
	}
	if res.GrantSync.ConsentRevision != 11 {
		t.Errorf("applied revision = %d", res.GrantSync.ConsentRevision)
	}
	// Only the allowed tool was read and uploaded.
	if res.ExportedBatches != 1 || res.SyncedBatches != 1 {
		t.Fatalf("only the Claude grant must be collected, got %#v", res)
	}
	if len(res.GrantOutcomes) != 2 {
		t.Fatalf("both grant outcomes must be reported, got %#v", res.GrantOutcomes)
	}
	for _, outcome := range res.GrantOutcomes {
		if outcome.Source == "codex-jsonl" && outcome.Skipped == "" {
			t.Fatalf("the narrowed codex grant must be skipped, got %#v", res.GrantOutcomes)
		}
	}
	if got := server.ingestRequests(); got != 1 {
		t.Fatalf("only the allowed tool's batch may be uploaded, got %d", got)
	}
	// The overlay is durable and the ack used device credentials.
	o := loadOverlayForTest(t, stateDir)
	if o.ConsentRevision != 11 || o.Paused || len(o.Pending) != 0 || o.AckedRevision != 11 || o.AckedCollectorVersion != "v0.2.1" {
		t.Fatalf("unexpected overlay: %#v", o)
	}
	if got := server.ackRequests(); got != 1 {
		t.Fatalf("exactly one grant-ack POST expected, got %d", got)
	}
	if last := server.lastAckBody(); last.ConsentRevision != 11 || last.CollectorVersion != "v0.2.1" {
		t.Fatalf("unexpected ack body: %#v", last)
	}
	server.requireAuthBearer(t)

	// An unchanged revision and version on the next run does not re-ack.
	res2, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir(), CollectorVersion: "v0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if !res2.GrantSync.Acked {
		t.Fatalf("unchanged revision must stay acknowledged without a new ack: %#v", res2.GrantSync)
	}
	if got := server.ackRequests(); got != 1 {
		t.Fatalf("no second ack expected for the same revision and version, got %d", got)
	}
}

// A collector upgrade re-acks the same revision with the new version so the
// server's device view learns the actual running release; the same version
// afterwards does not re-ack.
func TestGrantSyncReAckOnCollectorVersionChange(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 12)
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)

	if _, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir(), CollectorVersion: "v0.2.1"}); err != nil {
		t.Fatal(err)
	}
	if got := server.ackRequests(); got != 1 {
		t.Fatalf("initial ack expected, got %d", got)
	}

	// Upgrade: same revision, new collector version -> re-ack.
	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir(), CollectorVersion: "v0.3.0"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.GrantSync.Acked {
		t.Fatalf("the version-change re-ack must be acknowledged, got %#v", res.GrantSync)
	}
	if got := server.ackRequests(); got != 2 {
		t.Fatalf("the version change must re-ack the same revision, got %d acks", got)
	}
	if last := server.lastAckBody(); last.ConsentRevision != 12 || last.CollectorVersion != "v0.3.0" {
		t.Fatalf("unexpected re-ack body: %#v", last)
	}
	o := loadOverlayForTest(t, stateDir)
	if o.AckedRevision != 12 || o.AckedCollectorVersion != "v0.3.0" {
		t.Fatalf("overlay must record the acked version, got %#v", o)
	}

	// Same version again: no further ack.
	if _, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir(), CollectorVersion: "v0.3.0"}); err != nil {
		t.Fatal(err)
	}
	if got := server.ackRequests(); got != 2 {
		t.Fatalf("unchanged version must not re-ack, got %d", got)
	}

	// A dev build (no valid version) acks once without the field and then
	// stays settled; it never fakes a release version.
	if _, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir(), CollectorVersion: "dev"}); err != nil {
		t.Fatal(err)
	}
	if got := server.ackRequests(); got != 3 {
		t.Fatalf("switching to a dev build must re-ack once without a version, got %d", got)
	}
	if last := server.lastAckBody(); last.CollectorVersion != "" {
		t.Fatalf("dev builds must omit collectorVersion, got %#v", last)
	}
}

// A restricted (pending) application never carries a previous ack forward:
// while restricted the overlay holds no ack, and clearing the restriction
// re-acks the same revision.
func TestGrantSyncPendingDoesNotCarryAckAcrossRuns(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Codex"}, 13)
	bindDevice(t, stateDir, server.URL)

	home := t.TempDir()
	codexDefault := filepath.Join(home, ".codex", "sessions")
	writeCodexSession(t, codexDefault, "rollout-a.jsonl",
		codexTokenCount("2026-10-26T04:00:00Z", 100, 0, 0, 50),
		codexTokenCount("2026-10-26T04:01:00Z", 130, 0, 0, 65))

	if _, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home}); err != nil {
		t.Fatal(err)
	}
	if got := server.ackRequests(); got != 1 {
		t.Fatalf("initial unrestricted run must ack, got %d", got)
	}

	// The user manually disables the managed default grant.
	if _, _, err := grants.New(stateDir).Disable("codex-jsonl", codexDefault); err != nil {
		t.Fatal(err)
	}
	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	// The restricted revision is acknowledged WITH its restriction stated
	// (applyState=pending), so the server UI cannot keep claiming a fully
	// applied state from the earlier ack.
	if !res.GrantSync.Acked {
		t.Fatalf("a restricted application must be acknowledged as pending, got %#v", res.GrantSync)
	}
	if got := server.ackRequests(); got != 2 {
		t.Fatalf("the restricted run must re-ack with the pending state, got %d acks", got)
	}
	if last := server.lastAckBody(); last.ConsentRevision != 13 || last.ApplyState != "pending" {
		t.Fatalf("expected a pending-state ack of revision 13, got %#v", last)
	}
	o := loadOverlayForTest(t, stateDir)
	if o.AckedRevision != 13 || o.AckedApplyState != "pending" {
		t.Fatalf("the overlay must record the pending ack state, got %#v", o)
	}

	// Clearing the restriction re-acks the same revision as applied.
	if _, err := grants.New(stateDir).Enable("codex-jsonl", codexDefault); err != nil {
		t.Fatal(err)
	}
	res2, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if !res2.GrantSync.Acked || len(res2.GrantSync.Pending) != 0 {
		t.Fatalf("clearing the restriction must re-ack as applied, got %#v", res2.GrantSync)
	}
	if got := server.ackRequests(); got != 3 {
		t.Fatalf("the state change must re-ack the same revision, got %d acks", got)
	}
	if last := server.lastAckBody(); last.ConsentRevision != 13 || last.ApplyState != "applied" {
		t.Fatalf("expected an applied-state ack of revision 13, got %#v", last)
	}
}

// Pause stops all local reading and the drain for the run, cleanly.
func TestGrantSyncPausedStopsReadingAndDrain(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, true, []string{"__toktrail_paused__"}, 14)
	bindDevice(t, stateDir, server.URL)

	claude := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, claude, "s.jsonl",
		claudeLine(t, "2026-10-26T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))
	enableGrant(t, stateDir, "claude-code-jsonl", claude)
	writePendingBatch(t, stateDir, "batch-paused-1")

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatalf("a paused run must be a clean skip, not an error: %v", err)
	}
	if !res.GrantSync.Paused {
		t.Fatalf("paused must surface in the result: %#v", res.GrantSync)
	}
	if res.ExportedBatches != 0 || res.SyncedBatches != 0 || res.NoGrants {
		t.Fatalf("paused run must read and upload nothing: %#v", res)
	}
	if res.Skipped == "" || !strings.Contains(res.Skipped, "paused") {
		t.Fatalf("paused run must carry an explicit skip reason, got %q", res.Skipped)
	}
	if got := server.ingestRequests(); got != 0 {
		t.Fatalf("paused run must not drain pending batches, got %d ingests", got)
	}
	o := loadOverlayForTest(t, stateDir)
	if !o.Paused || o.AckedRevision != 14 {
		t.Fatalf("paused overlay must be applied and acknowledged: %#v", o)
	}
	if got := server.ackRequests(); got != 1 {
		t.Fatalf("a fully applicable paused view must still be acknowledged, got %d", got)
	}
}

// Expansion: a device that initially only collected Codex gains the
// server-confirmed DeepSeek Harness tool; its built-in default directory
// exists, so a managed grant is added and read in the same run, and the
// device identity (id/secret) is untouched.
func TestGrantSyncExpansionAddsDSHAndPreservesIdentity(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	bindDevice(t, stateDir, server.URL)

	home := t.TempDir()
	codexDefault := filepath.Join(home, ".codex", "sessions")
	writeCodexSession(t, codexDefault, "rollout-a.jsonl",
		codexTokenCount("2026-10-26T04:00:00Z", 100, 0, 0, 50),
		codexTokenCount("2026-10-26T04:01:00Z", 160, 0, 0, 80))
	dshDefault := filepath.Join(home, ".dsh", "sessions")
	writeDSHSession(t, dshDefault, "11111111-0000-4000-8000-000000000001")

	// Initially only Codex is confirmed; the user granted nothing else.
	server.setView(t, false, []string{"Codex"}, 15)
	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExportedBatches != 1 || len(res.GrantSync.AddedGrants) != 1 {
		t.Fatalf("initial run must add and collect only codex, got %#v", res)
	}
	if got := server.ingestRequests(); got != 1 {
		t.Fatalf("initial run uploads, got %d", got)
	}

	// The server expands the device scope to include DeepSeek Harness.
	server.setView(t, false, []string{"Codex", "DeepSeek Harness"}, 16)
	res2, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.GrantSync.AddedGrants) != 1 || !strings.Contains(res2.GrantSync.AddedGrants[0], "deepseek-harness") {
		t.Fatalf("the expansion must add the DSH default grant, got %#v", res2.GrantSync.AddedGrants)
	}
	if res2.ExportedBatches != 1 || res2.SyncedBatches != 1 {
		t.Fatalf("the newly granted DSH source must be collected and uploaded, got %#v", res2)
	}
	cfg, err := grants.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Grants) != 2 {
		t.Fatalf("expected the codex and dsh managed grants, got %#v", cfg.Grants)
	}
	for _, g := range cfg.Grants {
		if !g.Managed {
			t.Fatalf("both grants must be managed-origin, got %#v", g)
		}
	}
	// The device identity is untouched: no re-bind happened.
	st, err := statedir.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.DeviceID != "dev-1" || st.DeviceSecret != testSecret {
		t.Fatalf("device identity must be unchanged, got id=%q", st.DeviceID)
	}
	if res2.GrantSync.ConsentRevision != 16 || !res2.GrantSync.Acked {
		t.Fatalf("the expanded revision must be applied and acked, got %#v", res2.GrantSync)
	}
	if last := server.lastAckBody(); last.ConsentRevision != 16 {
		t.Fatalf("ack revision = %d, want 16", last.ConsentRevision)
	}
}

// A self view that names a different device fails closed: another device's
// authorization is never applied to this one.
func TestGrantSyncRejectsForeignDeviceView(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 17)
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)

	server.mu.Lock()
	server.deviceID = "dev-someone-else"
	server.mu.Unlock()

	_, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "another device's authorization") {
		t.Fatalf("expected a foreign-device failure, got %v", err)
	}
	if _, seen, lerr := managedconsent.New(stateDir).Load(); lerr != nil || seen {
		t.Fatalf("no overlay may be written for a foreign device view, seen=%v err=%v", seen, lerr)
	}
}

// A terminal rejection (revoked device) stops local reading even on an
// old-protocol server that never spoke the grant protocol.
func TestGrantSyncRevokedDeviceStopsReadingWithoutProtocol(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 18)
	bindDevice(t, stateDir, server.URL)

	claude := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, claude, "s.jsonl",
		claudeLine(t, "2026-10-26T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))
	enableGrant(t, stateDir, "claude-code-jsonl", claude)

	// Old protocol + revoked.
	server.mu.Lock()
	server.grantProtocol = nil
	server.revoked = true
	server.mu.Unlock()

	_, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err == nil || !errors.Is(err, synccmd.ErrDeviceRevoked) {
		t.Fatalf("a revoked device must stop the run even without the grant protocol, got %v", err)
	}
	if got := countLocalBatches(t, stateDir); got != 0 {
		t.Fatalf("a revoked device must not read locally, got %d batches", got)
	}
}

// An unknown tool never becomes a grant and keeps the revision
// unacknowledged (pending), while the known tools are still collected.
func TestGrantSyncUnknownToolIsPendingWithoutAck(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Codex", "FutureTool"}, 19)
	bindDevice(t, stateDir, server.URL)

	home := t.TempDir()
	codexDefault := filepath.Join(home, ".codex", "sessions")
	writeCodexSession(t, codexDefault, "rollout-a.jsonl",
		codexTokenCount("2026-10-26T04:00:00Z", 100, 0, 0, 50),
		codexTokenCount("2026-10-26T04:01:00Z", 160, 0, 0, 80))

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.GrantSync.AddedGrants) != 1 || !strings.Contains(res.GrantSync.AddedGrants[0], "codex-jsonl") {
		t.Fatalf("expected one added managed codex grant, got %#v", res.GrantSync.AddedGrants)
	}
	if res.ExportedBatches != 1 || res.SyncedBatches != 1 {
		t.Fatalf("the known tool must still be collected, got %#v", res)
	}
	if len(res.GrantSync.Pending) != 1 || !strings.Contains(res.GrantSync.Pending["FutureTool"], "unknown tool") {
		t.Fatalf("expected FutureTool to be pending-unknown, got %#v", res.GrantSync.Pending)
	}
	if !res.GrantSync.Acked || server.ackRequests() != 1 {
		t.Fatalf("a restricted application must be acknowledged as pending, acks=%d", server.ackRequests())
	}
	if last := server.lastAckBody(); last.ApplyState != "pending" {
		t.Fatalf("expected a pending-state ack, got %#v", last)
	}
}

// A manually disabled default-directory grant is never silently restarted,
// and a missing default directory keeps the tool pending; both stay
// unacknowledged with clear diagnostics. The user's grants.json entries
// are never modified by the sync.
func TestGrantSyncRestrictedApplicationDoesNotAckOrRestart(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Codex", "Claude Code"}, 20)
	bindDevice(t, stateDir, server.URL)

	home := t.TempDir()
	codexDefault := filepath.Join(home, ".codex", "sessions")
	writeCodexSession(t, codexDefault, "rollout-a.jsonl",
		codexTokenCount("2026-10-26T04:00:00Z", 100, 0, 0, 50),
		codexTokenCount("2026-10-26T04:01:00Z", 130, 0, 0, 65))
	// User manually disabled the codex default grant.
	if _, err := grants.New(stateDir).Enable("codex-jsonl", codexDefault); err != nil {
		t.Fatal(err)
	}
	if _, _, err := grants.New(stateDir).Disable("codex-jsonl", codexDefault); err != nil {
		t.Fatal(err)
	}
	// Claude's default directory does not exist (only a custom path).
	customClaude := filepath.Join(t.TempDir(), "claude-custom")
	writeClaudeSession(t, customClaude, "s.jsonl",
		claudeLine(t, "2026-10-26T04:00:00Z", "s1", "msg_1", claudeUsage(7, 0, 0, 3)))
	enableGrant(t, stateDir, "claude-code-jsonl", customClaude)

	before, err := grants.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	// Restricted: acknowledged with applyState=pending, never as applied.
	if !res.GrantSync.Acked {
		t.Fatalf("restricted application must be acknowledged as pending, got %#v", res.GrantSync)
	}
	if last := server.lastAckBody(); last.ApplyState != "pending" {
		t.Fatalf("expected a pending-state ack, got %#v", last)
	}
	if len(res.GrantSync.Pending) != 1 || !strings.Contains(res.GrantSync.Pending["Codex"], "manually disabled") {
		t.Fatalf("expected the manually disabled codex default grant to be pending, got %#v", res.GrantSync.Pending)
	}
	// Claude is collected through the custom path: not restricted.
	if res.ExportedBatches != 1 || res.SyncedBatches != 1 {
		t.Fatalf("the custom claude grant must still be collected, got %#v", res)
	}
	// The grants config is untouched: same entries.
	after, err := grants.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Grants) != len(before.Grants) {
		t.Fatalf("the sync must not add or remove entries here: before=%#v after=%#v", before.Grants, after.Grants)
	}
	for i := range after.Grants {
		if after.Grants[i] != before.Grants[i] {
			t.Fatalf("grant entry %d changed: %#v -> %#v", i, before.Grants[i], after.Grants[i])
		}
	}
}

// Once the grant protocol has been active, a failed refresh stops local
// reading (fail closed) instead of continuing under the previous scope.
func TestGrantSyncFailClosedWhenRefreshFailsAfterProtocolSeen(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 21)
	bindDevice(t, stateDir, server.URL)

	claude := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, claude, "s.jsonl",
		claudeLine(t, "2026-10-26T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))
	enableGrant(t, stateDir, "claude-code-jsonl", claude)

	if _, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	batchesBefore := countLocalBatches(t, stateDir)

	// The server becomes unreachable.
	status := http.StatusServiceUnavailable
	server.mu.Lock()
	server.failSelfWith = &status
	server.mu.Unlock()

	// New data arrives while the refresh is broken.
	writeClaudeSession(t, claude, "s2.jsonl",
		claudeLine(t, "2026-10-26T05:00:00Z", "s2", "msg_2", claudeUsage(8, 0, 0, 2)))

	_, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "cannot refresh the server grant authorization") {
		t.Fatalf("expected a fail-closed refresh error, got %v", err)
	}
	if got := countLocalBatches(t, stateDir); got != batchesBefore {
		t.Fatalf("no local reading may happen under an unconfirmable authorization: batches %d -> %d", batchesBefore, got)
	}
}

// A server that stops advertising the grant protocol after it was active is
// treated as a downgrade: reading stops instead of silently widening.
func TestGrantSyncAntiDowngrade(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 22)
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)

	if _, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}

	server.mu.Lock()
	server.dropProtocol = true
	server.mu.Unlock()
	_, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "no longer advertises the grant protocol") {
		t.Fatalf("expected an anti-downgrade failure, got %v", err)
	}
}

// An unsupported protocol version fails closed with an upgrade hint.
func TestGrantSyncUnsupportedProtocolVersion(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	two := 2
	server.mu.Lock()
	server.grantProtocol = &two
	server.mu.Unlock()
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)

	_, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "unsupported grant protocol version 2") {
		t.Fatalf("expected an unsupported-version failure, got %v", err)
	}
	if _, seen, lerr := managedconsent.New(stateDir).Load(); lerr != nil || seen {
		t.Fatalf("no overlay may be written for an unsupported protocol, seen=%v err=%v", seen, lerr)
	}
}

// A failed ack is non-fatal: the applied view still governs reading and the
// ack is retried on the next run.
func TestGrantSyncAckFailureRetriedNextRun(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 23)
	bindDevice(t, stateDir, server.URL)

	claude := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, claude, "s.jsonl",
		claudeLine(t, "2026-10-26T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))
	enableGrant(t, stateDir, "claude-code-jsonl", claude)

	server.mu.Lock()
	server.ackStatus = http.StatusInternalServerError
	server.mu.Unlock()

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatalf("an ack failure must not fail the run: %v", err)
	}
	if res.GrantSync.Acked || server.ackRequests() != 1 {
		t.Fatalf("the failed ack must not count as acknowledged: %#v acks=%d", res.GrantSync, server.ackRequests())
	}
	if res.ExportedBatches != 1 || res.SyncedBatches != 1 {
		t.Fatalf("the applied view must still govern collection, got %#v", res)
	}
	if res.GrantSync.Note == "" || !strings.Contains(res.GrantSync.Note, "grant ack not confirmed") {
		t.Fatalf("the ack failure must be surfaced as a note, got %q", res.GrantSync.Note)
	}
	o := loadOverlayForTest(t, stateDir)
	if o.AckedRevision != 0 {
		t.Fatalf("overlay must not record an unconfirmed ack: %#v", o)
	}

	// Next run: the ack endpoint recovered; the same revision is acked.
	server.mu.Lock()
	server.ackStatus = http.StatusOK
	server.mu.Unlock()
	res2, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if !res2.GrantSync.Acked || server.ackRequests() != 2 {
		t.Fatalf("the ack must be retried and confirmed, got %#v acks=%d", res2.GrantSync, server.ackRequests())
	}
	if last := server.lastAckBody(); last.ConsentRevision != 23 {
		t.Fatalf("retried ack revision = %d, want 23", last.ConsentRevision)
	}
}

// An ack echo of a DIFFERENT (not newer) revision leaves the revision
// state unclear: the run conservatively stops local reading instead of
// trusting the applied view, and nothing is recorded as confirmed.
func TestGrantSyncAckEchoMismatchStopsConservatively(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 24)
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)

	server.mu.Lock()
	server.ackEchoOffset = -3 // server confirms an older revision
	server.mu.Unlock()

	_, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err == nil || !errors.Is(err, synccmd.ErrAckEchoMismatch) {
		t.Fatalf("an unclear ack echo must stop the run, got %v", err)
	}
	o, seen, lerr := managedconsent.New(stateDir).Load()
	if lerr != nil || !seen {
		t.Fatalf("the applied overlay must exist, seen=%v err=%v", seen, lerr)
	}
	if o.AckedRevision != 0 {
		t.Fatalf("overlay must not record an unconfirmed ack: %#v", o)
	}
}

// An ack that reports a newer current revision triggers one re-fetch and
// re-apply of the newer view; an always-advancing server stops the run
// instead of reading under a stale revision.
func TestGrantSyncStaleRevisionRefetchAndAlwaysAdvancingFails(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 25)
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)

	// The first ack reports the server moved to revision 26; the served
	// view then switches to 26 with the scope narrowed to Codex only.
	server.mu.Lock()
	server.advanceOnAck = &grantView{revision: 26, tools: []string{"Claude Code"}}
	server.ackCurrentBump = 1
	server.mu.Unlock()

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatalf("stale ack with a successful re-fetch must not fail: %v", err)
	}
	if got := server.self.Load(); got != 3 { // 2 grant-sync fetches + 1 empty-scan status preflight
		t.Fatalf("expected the stale ack to trigger a second grant-sync fetch, got %d self requests", got)
	}
	if res.GrantSync.ConsentRevision != 26 {
		t.Fatalf("the newer revision must be applied, got %#v", res.GrantSync)
	}
	if !res.GrantSync.Acked {
		t.Fatalf("the newer revision must be acknowledged, got %#v", res.GrantSync)
	}
	if last := server.lastAckBody(); last.ConsentRevision != 26 {
		t.Fatalf("the re-acked revision = %d, want 26", last.ConsentRevision)
	}

	// Always-advancing: a new revision whose ack always reports a newer
	// current revision fails closed instead of reading stale.
	server.mu.Lock()
	server.alwaysAdvancing = true
	server.view = grantView{revision: 27, tools: []string{"Claude Code"}}
	server.mu.Unlock()
	_, err = Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "keeps advancing") {
		t.Fatalf("expected the always-advancing failure, got %v", err)
	}
}

// The server-confirmed effective historyFrom governs new exports and can
// widen beyond the bind-time cutoff; it is applied in the same run as the
// ack (no stale bound history).
func TestGrantSyncServerEffectiveHistoryFromWidens(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	wide := "2026-10-01T00:00:00Z"
	server.mu.Lock()
	server.historyFrom = &wide
	server.mu.Unlock()
	bindDevice(t, stateDir, server.URL)

	// The bind-time cutoff is narrower than the server's effective one.
	narrow := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	st := statedir.DeviceState{
		ServerURL:    server.URL,
		DeviceID:     "dev-1",
		DeviceSecret: testSecret,
		HistoryFrom:  &narrow,
	}
	if err := statedir.New(stateDir).Save(st); err != nil {
		t.Fatal(err)
	}

	claude := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, claude, "s.jsonl",
		claudeLine(t, "2026-10-15T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))
	enableGrant(t, stateDir, "claude-code-jsonl", claude)

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExportedBatches != 1 || res.SyncedBatches != 1 {
		t.Fatalf("the server-effective wider cutoff must include the older record, got %#v", res)
	}
	if !res.GrantSync.Acked {
		t.Fatalf("expected the applied view to be acknowledged, got %#v", res.GrantSync)
	}
}

// An unbound device performs no network traffic and keeps legacy behavior.
func TestGrantSyncUnboundDeviceNoNetwork(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 27)

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if res.GrantSync.Active {
		t.Fatalf("unbound device must keep legacy behavior, got %#v", res.GrantSync)
	}
	if got := server.totalRequests(); got != 0 {
		t.Fatalf("unbound run must not touch the network, got %d requests", got)
	}
	if _, seen, err := managedconsent.New(stateDir).Load(); err != nil || seen {
		t.Fatalf("no overlay expected for an unbound device, seen=%v err=%v", seen, err)
	}
}

// countLocalBatches counts the exported batch files in the state directory.
func countLocalBatches(t *testing.T, stateDir string) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(stateDir, "batches"))
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// An authentication failure on the self fetch stops local reading even on
// a server that never spoke the grant protocol: rejected credentials are
// never a transient network failure to fall back from.
func TestGrantSyncAuthFailureStopsWithoutProtocolSeen(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 28)
	bindDevice(t, stateDir, server.URL)

	claude := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, claude, "s.jsonl",
		claudeLine(t, "2026-10-26T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))
	enableGrant(t, stateDir, "claude-code-jsonl", claude)

	// Old protocol + credentials rejected.
	unauthorized := http.StatusUnauthorized
	server.mu.Lock()
	server.grantProtocol = nil
	server.failSelfWith = &unauthorized
	server.mu.Unlock()

	_, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err == nil || !errors.Is(err, synccmd.ErrDeviceUnauthorized) {
		t.Fatalf("rejected credentials must stop the run, got %v", err)
	}
	if got := countLocalBatches(t, stateDir); got != 0 {
		t.Fatalf("no local reading may happen after an auth failure, got %d batches", got)
	}
	if _, seen, lerr := managedconsent.New(stateDir).Load(); lerr != nil || seen {
		t.Fatalf("no overlay expected, seen=%v err=%v", seen, lerr)
	}
}

// A structurally invalid self response (HTTP 200 with an undecodable body)
// stops local reading even on first contact.
func TestGrantSyncMalformedSelfStopsWithoutProtocolSeen(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 29)
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)

	server.mu.Lock()
	server.garbageSelf = true
	server.mu.Unlock()

	_, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err == nil || !errors.Is(err, synccmd.ErrSelfProtocol) {
		t.Fatalf("a malformed self response must stop the run, got %v", err)
	}
	if got := countLocalBatches(t, stateDir); got != 0 {
		t.Fatalf("no local reading may happen after a protocol anomaly, got %d batches", got)
	}
}

// Documented compatibility: a transport-level failure on a server that
// never spoke the grant protocol keeps the legacy behavior — local reading
// continues under the user's grants and the drain reports the network
// failure. (Once the protocol has been seen, the same failure stops
// reading; see TestGrantSyncFailClosedWhenRefreshFailsAfterProtocolSeen.)
func TestGrantSyncOfflineNeverSeenKeepsLegacyReading(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 30)
	bindDevice(t, stateDir, server.URL)

	claude := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, claude, "s.jsonl",
		claudeLine(t, "2026-10-26T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))
	enableGrant(t, stateDir, "claude-code-jsonl", claude)

	// The server becomes unreachable before the first successful fetch.
	server.Close()

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err == nil {
		t.Fatal("the drain must surface the network failure")
	}
	// The drain's network failure surfaces as the syncclient's sanitized
	// transport wording: the raw network error text (endpoint, runtime
	// detail) is withheld by design, so the fixed "transport failure"
	// phrase is the observable classification.
	if !strings.Contains(err.Error(), "transport failure") {
		t.Fatalf("expected the drain's network failure, got %v", err)
	}
	// Reading DID happen under the legacy local grants before the drain
	// failed: exactly one exported batch sits in the outbox.
	if res.ExportedBatches != 1 || res.SyncedBatches != 0 {
		t.Fatalf("legacy offline behavior must still export locally, got %#v", res)
	}
	if res.GrantSync.Active {
		t.Fatalf("the grant sync must stay inactive without a successful fetch, got %#v", res.GrantSync)
	}
	if got := countLocalBatches(t, stateDir); got != 1 {
		t.Fatalf("expected the exported batch to be preserved for the next run, got %d", got)
	}
	if _, seen, lerr := managedconsent.New(stateDir).Load(); lerr != nil || seen {
		t.Fatalf("no overlay expected without a successful fetch, seen=%v err=%v", seen, lerr)
	}
}

// Legacy over-authorization regression: a device the server has NOT
// explicitly authorized for grant management (deviceGrantManaged=false)
// never gains default-directory grants, even though the subject-level scope
// lists the tool and the directory exists. The sync only filters existing
// local grants, which fully applies and may be acknowledged.
func TestGrantSyncLegacySubjectScopeDoesNotAutoAdd(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Codex", "DeepSeek Harness"}, 31)
	bindDevice(t, stateDir, server.URL)

	home := t.TempDir()
	// Both default directories exist locally...
	codexDefault := filepath.Join(home, ".codex", "sessions")
	writeCodexSession(t, codexDefault, "rollout-a.jsonl",
		codexTokenCount("2026-10-26T04:00:00Z", 100, 0, 0, 50),
		codexTokenCount("2026-10-26T04:01:00Z", 160, 0, 0, 80))
	dshDefault := filepath.Join(home, ".dsh", "sessions")
	writeDSHSession(t, dshDefault, "11111111-0000-4000-8000-000000000002")
	// ...but the user only ever granted Codex.
	enableGrant(t, stateDir, "codex-jsonl", codexDefault)

	unmanaged := false
	server.mu.Lock()
	server.deviceGrantManaged = &unmanaged
	server.mu.Unlock()

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.GrantSync.AddedGrants) != 0 {
		t.Fatalf("an unmanaged device must never gain grants, got %#v", res.GrantSync.AddedGrants)
	}
	cfg, err := grants.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Grants) != 1 || cfg.Grants[0].Managed {
		t.Fatalf("the user's codex grant must be the only, unmanaged entry, got %#v", cfg.Grants)
	}
	// Filter-only application is complete: the revision is acknowledged.
	if !res.GrantSync.Acked {
		t.Fatalf("a fully applied filter-only view must be acknowledged, got %#v", res.GrantSync)
	}
	if res.ExportedBatches != 1 || res.SyncedBatches != 1 {
		t.Fatalf("the existing codex grant must still be collected, got %#v", res)
	}
	o := loadOverlayForTest(t, stateDir)
	if o.DeviceGrantManaged {
		t.Fatalf("overlay must record the unmanaged state, got %#v", o)
	}

	// After the device explicitly confirms its grants on the server
	// (managed=true), the same scope may add the DSH default grant.
	managed := true
	server.mu.Lock()
	server.deviceGrantManaged = &managed
	server.mu.Unlock()
	server.setView(t, false, []string{"Codex", "DeepSeek Harness"}, 32)
	res2, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.GrantSync.AddedGrants) != 1 || !strings.Contains(res2.GrantSync.AddedGrants[0], "deepseek-harness") {
		t.Fatalf("a managed device may add the confirmed DSH default grant, got %#v", res2.GrantSync.AddedGrants)
	}
}

// A new-protocol server that omits deviceGrantManaged entirely is treated
// as unmanaged: no automatic grants, with an explicit note.
func TestGrantSyncMissingManagedFlagMeansUnmanaged(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Codex"}, 33)
	bindDevice(t, stateDir, server.URL)

	home := t.TempDir()
	codexDefault := filepath.Join(home, ".codex", "sessions")
	writeCodexSession(t, codexDefault, "rollout-a.jsonl",
		codexTokenCount("2026-10-26T04:00:00Z", 100, 0, 0, 50),
		codexTokenCount("2026-10-26T04:01:00Z", 160, 0, 0, 80))

	server.mu.Lock()
	server.deviceGrantManaged = nil // field omitted
	server.mu.Unlock()

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.GrantSync.AddedGrants) != 0 {
		t.Fatalf("a missing managed flag must not add grants, got %#v", res.GrantSync.AddedGrants)
	}
	if res.GrantSync.Note == "" || !strings.Contains(res.GrantSync.Note, "deviceGrantManaged") {
		t.Fatalf("the omission must be surfaced, got %q", res.GrantSync.Note)
	}
	if !res.GrantSync.Acked {
		t.Fatalf("filter-only application is complete and may be acknowledged, got %#v", res.GrantSync)
	}
}

// A device identity change (re-bind to another device) never reuses the
// previous overlay's ack or its managed grants: they are disabled until
// the new device confirms them.
func TestGrantSyncIdentityChangeResetsAckAndDisablesManagedGrants(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Codex"}, 34)
	bindDevice(t, stateDir, server.URL)

	home := t.TempDir()
	codexDefault := filepath.Join(home, ".codex", "sessions")
	writeCodexSession(t, codexDefault, "rollout-a.jsonl",
		codexTokenCount("2026-10-26T04:00:00Z", 100, 0, 0, 50),
		codexTokenCount("2026-10-26T04:01:00Z", 160, 0, 0, 80))

	if _, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home}); err != nil {
		t.Fatal(err)
	}
	if got := server.ackRequests(); got != 1 {
		t.Fatalf("initial ack expected, got %d", got)
	}

	// The user re-binds to a different device on the same state directory.
	if err := statedir.New(stateDir).Save(statedir.DeviceState{
		ServerURL:    server.URL,
		DeviceID:     "dev-2",
		DeviceSecret: testSecret,
	}); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	server.deviceID = "dev-2"
	server.mu.Unlock()

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	// ...the previous ack was not reused (a new ack for dev-2's revision)...
	if !res.GrantSync.Acked {
		t.Fatalf("the new device's view must be acknowledged on its own, got %#v", res.GrantSync)
	}
	o := loadOverlayForTest(t, stateDir)
	if o.DeviceID != "dev-2" {
		t.Fatalf("overlay must be rebound to the new device, got %#v", o)
	}
	// ...and because dev-2 explicitly authorizes Codex (managed), the
	// system-disabled managed grant is RESTORED and collected — not stuck
	// pending. A user-disabled grant would stay pending instead.
	cfg, err := grants.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Grants) != 1 || !cfg.Grants[0].Enabled || !cfg.Grants[0].Managed || cfg.Grants[0].SystemDisabled {
		t.Fatalf("the system-disabled managed grant must be restored under the new device's authorization, got %#v", cfg.Grants)
	}
	if len(res.GrantSync.Pending) != 0 {
		t.Fatalf("no restriction expected after the restore, got %#v", res.GrantSync.Pending)
	}
	if len(res.GrantSync.AddedGrants) != 1 || !strings.Contains(res.GrantSync.AddedGrants[0], "restored after device change") {
		t.Fatalf("the restore must be reported, got %#v", res.GrantSync.AddedGrants)
	}
}

// A pause that arrives between the grant sync and the drain stops all
// sending: pending batches stay queued (never quarantined) and the run
// ends cleanly.
func TestGrantSyncPausedMidRunStopsDrain(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 35)
	bindDevice(t, stateDir, server.URL)

	claude := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, claude, "s.jsonl",
		claudeLine(t, "2026-10-26T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))
	enableGrant(t, stateDir, "claude-code-jsonl", claude)

	// Pause the device right after the grant-sync fetch succeeds: the
	// drain's own preflight must then refuse to POST.
	var grantSyncDone atomic.Bool
	wrapped := server.Server.Config.Handler
	server.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped.ServeHTTP(w, r)
		if r.Method == http.MethodPost && r.URL.Path == "/v1/devices/grant-ack" && grantSyncDone.CompareAndSwap(false, true) {
			server.mu.Lock()
			server.view = grantView{paused: true, tools: []string{"__toktrail_paused__"}, revision: 35}
			server.mu.Unlock()
		}
	})

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatalf("a mid-run pause must be a clean stop, got %v", err)
	}
	if res.ExportedBatches != 1 || res.SyncedBatches != 0 {
		t.Fatalf("the export happens before the pause, the upload must not, got %#v", res)
	}
	if res.PendingRemaining != 1 || res.DrainStopped == "" || !strings.Contains(res.DrainStopped, "paused") {
		t.Fatalf("pending batches must stay queued with a pause reason, got %#v", res)
	}
	if got := server.ingestRequests(); got != 0 {
		t.Fatalf("a paused device must not upload, got %d ingests", got)
	}
	if got := server.tooling.Load(); got != 0 {
		t.Fatalf("a paused device must not report tool statuses either, got %d", got)
	}
}

// Restricted tools are reported per-tool through the tool-status channel so
// the server can show why the current revision is not fully applied.
func TestGrantSyncReportsPendingToolStatuses(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Codex", "FutureTool"}, 36)
	bindDevice(t, stateDir, server.URL)

	home := t.TempDir()
	codexDefault := filepath.Join(home, ".codex", "sessions")
	writeCodexSession(t, codexDefault, "rollout-a.jsonl",
		codexTokenCount("2026-10-26T04:00:00Z", 100, 0, 0, 50),
		codexTokenCount("2026-10-26T04:01:00Z", 160, 0, 0, 80))
	// The user disabled the managed codex default grant.
	if _, err := grants.New(stateDir).Enable("codex-jsonl", codexDefault); err != nil {
		t.Fatal(err)
	}
	if _, _, err := grants.New(stateDir).Disable("codex-jsonl", codexDefault); err != nil {
		t.Fatal(err)
	}

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	_ = res
	reports := server.toolStatusReports()
	byTool := map[string]toolStatusReport{}
	for _, r := range reports {
		byTool[r.Tool] = r
	}
	if r, ok := byTool["FutureTool"]; !ok || r.Status != "unsupported" || r.Detail != "unsupported tool" {
		t.Fatalf("unknown tool must be reported unsupported, got %#v", r)
	}
	if r, ok := byTool["Codex"]; !ok || r.Status != "not_detected" || r.Detail != "default directory grant disabled" {
		t.Fatalf("the disabled default grant must be reported, got %#v", r)
	}
}

// Under the grant protocol, an explicit server historyFrom of nil means
// unlimited: records before the bind-time cutoff are included again (the
// legacy fallback must not clamp them).
func TestGrantSyncNilServerHistoryMeansUnlimited(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	// No historyFrom in the served view.
	bindDevice(t, stateDir, server.URL)

	narrow := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	if err := statedir.New(stateDir).Save(statedir.DeviceState{
		ServerURL:    server.URL,
		DeviceID:     "dev-1",
		DeviceSecret: testSecret,
		HistoryFrom:  &narrow,
	}); err != nil {
		t.Fatal(err)
	}

	claude := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, claude, "s.jsonl",
		claudeLine(t, "2026-10-15T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))
	enableGrant(t, stateDir, "claude-code-jsonl", claude)

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExportedBatches != 1 || res.SyncedBatches != 1 {
		t.Fatalf("an explicit server nil cutoff must include pre-bind records, got %#v", res)
	}
}
