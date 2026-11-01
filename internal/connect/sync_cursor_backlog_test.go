package connect

// Cursor regressions for the shared Sync orchestration (the flow the
// resync CLI drives with a nil AccountTools list):
//
//   - backlog drain passes never repeat the forced cursor round
//     (ForceResync is a one-round recovery semantic; repeating it would
//     re-pull and re-emit the whole history every pass and a large
//     cursor backlog could never converge);
//   - a failed cursor round is never swallowed when no explicit account
//     tool list names it;
//   - a permit that exists in ANY status (login_expired included) under
//     a grant that allows Cursor owes completion;
//   - a cursor the server never authorized, or a device with no permit,
//     skipping normally is NOT an incompleteness;
//   - a round that skipped rows without a stable upstream event id left
//     usage uncounted and is never a complete success.
//
// Everything is synthetic: tempdir state, one httptest TokTrail double
// and injected cursor auth/verify/pull fakes. No real Cursor state,
// credential or account is ever read.
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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/app/resync"
	"toktrail-collector/internal/cursor/api"
	"toktrail-collector/internal/cursor/auth"
	"toktrail-collector/internal/cursor/identity"
	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/cursor/usage"
	"toktrail-collector/internal/local/cursoroutbox"
	"toktrail-collector/internal/local/cursorsource"
	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncbudget"
)

const (
	cursorBacklogAccount = "user_backlogtest"
	cursorBacklogToken   = "synthetic-backlog-access-token"
	cursorBacklogSession = "synthetic-backlog-session-token"
	cursorBacklogSource  = "cursor-src-backlog-1"
	cursorBacklogDevice  = "dev-backlog-1"
)

var cursorBacklogNow = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

// cursorBacklogMock fakes the TokTrail server a cursor-wired Sync run
// talks to: the device self view (grant protocol + account sources),
// cursor source-batch ingest, device batch ingest, tool-status reports
// and the capability probe. Everything else (grant acks, ...) gets a
// permissive 200.
type cursorBacklogMock struct {
	*httptest.Server

	mu struct {
		sync.Mutex
		allowedTools  []string
		source        *protocol.Source
		srcBatchPosts int
		toolStatus    int
		selfCalls     int
		devicePosts   int
		flipped       bool
		// postLog records every real ingest POST in global order as
		// "cursor:<batchID>" (source-batch endpoint) or "device:<batchID>"
		// (device-batch endpoint, which the history retransmission shares),
		// so tests can assert queue scheduling order (which queue posted
		// when) rather than only totals.
		postLog []string
		// Scope-move knobs: once triggered, the self view serves
		// consentRevision 6 instead of 5, modeling a server-side scope
		// change mid-run. Triggers are evaluated on self requests:
		// bumpAfterSelfCalls fires once that many self calls happened;
		// bumpAfterDevicePosts fires once at least that many device
		// batch uploads happened (deterministic across the phases).
		bumpAfterSelfCalls  int
		bumpAfterDevicePost int
		// lockProbeDir, when non-empty, makes every source-batch ingest
		// handler attempt a non-blocking runlock acquire of that
		// directory and record the outcome. It lets tests observe,
		// black-box from the server side, whether the collector holds
		// the state lock while account batches upload (ErrBusy = held,
		// a successful acquire = free).
		lockProbeDir  string
		lockProbeHeld int
		lockProbeFree int
		// partialRejectDeviceBatch makes the device-batch endpoint
		// answer a PARTIALLY rejected receipt (one of the submitted
		// records rejected with a synthetic stable code) so tests can
		// pin that such a receipt never reads as connect success.
		partialRejectDeviceBatch bool
		// onSelf, when set, is invoked at the top of the self handler
		// with the 1-based self-call number, before the response is
		// served — a deterministic mid-run hook for tests (the HTTP
		// round trip orders it before everything the caller does next).
		onSelf func(call int)
	}
}

func startCursorBacklogMock(t *testing.T) *cursorBacklogMock {
	t.Helper()
	m := &cursorBacklogMock{}
	m.mu.source = &protocol.Source{
		SourceInstanceID: cursorBacklogSource,
		SourceType:       protocol.SourceType,
		State:            "active",
		FenceVersion:     1,
		NextRevision:     1,
	}
	writeJSON := func(w http.ResponseWriter, status int, body any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self":
			m.mu.Lock()
			m.mu.selfCalls++
			onSelf := m.mu.onSelf
			call := m.mu.selfCalls
			m.mu.Unlock()
			if onSelf != nil {
				onSelf(call)
			}
			m.mu.Lock()
			tools, src := m.mu.allowedTools, m.mu.source
			if (m.mu.bumpAfterSelfCalls > 0 && m.mu.selfCalls >= m.mu.bumpAfterSelfCalls) ||
				(m.mu.bumpAfterDevicePost > 0 && m.mu.devicePosts >= m.mu.bumpAfterDevicePost) {
				m.mu.flipped = true
			}
			revision := int64(5)
			if m.mu.flipped {
				revision = 6
			}
			m.mu.Unlock()
			device := map[string]any{
				"deviceId":             cursorBacklogDevice,
				"applicationId":        "app-backlog",
				"externalSubjectId":    "sub-backlog",
				"consentRevision":      revision,
				"uploadAuthorized":     true,
				"revoked":              false,
				"paused":               false,
				"grantProtocolVersion": 1,
				"allowedTools":         tools,
			}
			if src != nil {
				device["accountSources"] = []protocol.Source{*src}
			}
			writeJSON(w, http.StatusOK, map[string]any{"device": device})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/source-batches":
			var batch struct {
				BatchID string            `json:"batchId"`
				Records []json.RawMessage `json:"records"`
			}
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				t.Errorf("invalid source-batch body: %v", err)
				writeJSON(w, http.StatusBadRequest, map[string]any{})
				return
			}
			m.mu.Lock()
			m.mu.srcBatchPosts++
			m.mu.postLog = append(m.mu.postLog, "cursor:"+batch.BatchID)
			probeDir := m.mu.lockProbeDir
			m.mu.Unlock()
			if probeDir != "" {
				// Non-blocking contention observation only: a successful
				// acquire is released immediately and counted as "free".
				switch probe, pErr := runlock.Acquire(probeDir); {
				case pErr == nil:
					_ = probe.Close()
					m.mu.Lock()
					m.mu.lockProbeFree++
					m.mu.Unlock()
				case errors.Is(pErr, runlock.ErrBusy):
					m.mu.Lock()
					m.mu.lockProbeHeld++
					m.mu.Unlock()
				default:
					t.Errorf("state lock probe failed: %v", pErr)
				}
			}
			writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
				"batchId":         batch.BatchID,
				"status":          "accepted",
				"acceptedRecords": len(batch.Records),
				"rejectedRecords": 0,
				"replay":          false,
				"receivedAt":      cursorBacklogNow.Format(time.RFC3339Nano),
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/batches":
			var body struct {
				BatchID string           `json:"batchId"`
				Records []map[string]any `json:"records"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			m.mu.Lock()
			m.mu.devicePosts++
			m.mu.postLog = append(m.mu.postLog, "device:"+body.BatchID)
			partial := m.mu.partialRejectDeviceBatch
			m.mu.Unlock()
			accepted, rejected := len(body.Records), 0
			var recordErrors []map[string]any
			if partial && len(body.Records) > 1 {
				accepted, rejected = len(body.Records)-1, 1
				recordErrors = []map[string]any{{"index": 0, "code": "synthetic_partial_rejection"}}
			}
			// The status word must agree with the counts: a partially
			// rejecting receipt claiming "accepted" is inconsistent, and
			// the syncclient now fails such receipts closed.
			status := "accepted"
			if rejected > 0 {
				status = "partial_error"
			}
			writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
				"batchId":         body.BatchID,
				"status":          status,
				"acceptedRecords": accepted,
				"rejectedRecords": rejected,
				"recordErrors":    recordErrors,
				"replay":          false,
				"receivedAt":      cursorBacklogNow.Format(time.RFC3339Nano),
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/account-sources/enable":
			m.mu.Lock()
			src := m.mu.source
			m.mu.Unlock()
			if src == nil {
				writeJSON(w, http.StatusConflict, map[string]any{})
				return
			}
			writeJSON(w, http.StatusCreated, map[string]any{"source": *src})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/devices/tool-status":
			m.mu.Lock()
			m.mu.toolStatus++
			m.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"accepted": true})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/capabilities":
			writeJSON(w, http.StatusOK, map[string]any{"features": []string{"device-grants", "account-sources"}})
		default:
			writeJSON(w, http.StatusOK, map[string]any{})
		}
	}))
	t.Cleanup(m.Server.Close)
	return m
}

func (m *cursorBacklogMock) setAllowedTools(tools []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mu.allowedTools = tools
}

// bumpRevisionAfterSelfCalls makes every self request from the n-th one
// on serve consentRevision 6.
func (m *cursorBacklogMock) bumpRevisionAfterSelfCalls(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mu.bumpAfterSelfCalls = n
}

// bumpRevisionAfterDevicePosts makes every self request observe
// consentRevision 6 once n device batch uploads have happened.
func (m *cursorBacklogMock) bumpRevisionAfterDevicePosts(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mu.bumpAfterDevicePost = n
}

// setOnSelf installs the deterministic mid-run self-handler hook.
func (m *cursorBacklogMock) setOnSelf(hook func(call int)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mu.onSelf = hook
}

// setPartialRejectDeviceBatch arms the partially-rejected receipt on the
// device-batch endpoint.
func (m *cursorBacklogMock) setPartialRejectDeviceBatch(on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mu.partialRejectDeviceBatch = on
}

func (m *cursorBacklogMock) srcBatchPosts() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mu.srcBatchPosts
}

// deviceBatchPosts reports how many device outbox batches were uploaded.
func (m *cursorBacklogMock) deviceBatchPosts() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mu.devicePosts
}

// selfCalls reports how many device self views were fetched.
func (m *cursorBacklogMock) selfCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mu.selfCalls
}

// probeLockOnSourceBatches turns on the source-batch lock observation for
// dir; see cursorBacklogMock.lockProbeDir.
func (m *cursorBacklogMock) probeLockOnSourceBatches(dir string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mu.lockProbeDir = dir
}

// lockProbeStats reports how many source-batch uploads observed the state
// lock as held (ErrBusy) versus free (acquirable).
func (m *cursorBacklogMock) lockProbeStats() (held, free int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mu.lockProbeHeld, m.mu.lockProbeFree
}

// postLog returns a copy of the ordered real-POST log ("cursor:<id>" /
// "device:<id>" entries in global submission order).
func (m *cursorBacklogMock) postLogEntries() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.mu.postLog...)
}

// postLogIndex returns the position of the first log entry equal to
// want, or -1 when absent.
func (m *cursorBacklogMock) postLogIndex(want string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, entry := range m.mu.postLog {
		if entry == want {
			return i
		}
	}
	return -1
}

// cursorBacklogAuth / cursorBacklogVerify / cursorBacklogPull are the
// synthetic cursor-side collaborators. The pull fake records every
// requested window so tests can prove the forced full-window pull ran
// exactly once and backlog passes fell back to the overlap window.
type cursorBacklogAuth struct {
	fail bool
}

func (a *cursorBacklogAuth) Fetch(ctx context.Context) (auth.Credential, error) {
	if a.fail {
		return auth.Credential{}, fmt.Errorf("synthetic credential read failure")
	}
	return auth.Credential{AccessToken: cursorBacklogToken, Source: "test-fixture"}, nil
}

type cursorBacklogVerify struct {
	fail bool
}

func (v *cursorBacklogVerify) verify(ctx context.Context, accessToken string) (api.VerifyResult, error) {
	if v.fail {
		return api.VerifyResult{}, fmt.Errorf("synthetic verification failure")
	}
	if accessToken != cursorBacklogToken {
		return api.VerifyResult{}, fmt.Errorf("unexpected credential handed to verify")
	}
	return api.VerifyResult{AccountID: cursorBacklogAccount, SessionToken: cursorBacklogSession}, nil
}

type cursorBacklogPull struct {
	events []api.UsageEvent
	calls  []struct{ from, to time.Time }
	// err, when non-nil, makes every pull attempt fail (after the call
	// is recorded, so tests can count attempts).
	err error
}

func (p *cursorBacklogPull) pull(ctx context.Context, sessionToken string, from, to time.Time) ([]api.UsageEvent, error) {
	if sessionToken != cursorBacklogSession {
		return nil, fmt.Errorf("pull called with an unverified session token")
	}
	p.calls = append(p.calls, struct{ from, to time.Time }{from, to})
	if p.err != nil {
		return nil, p.err
	}
	var out []api.UsageEvent
	for _, ev := range p.events {
		ts := time.UnixMilli(ev.TimestampMS)
		if (from.IsZero() || !ts.Before(from)) && ts.Before(to) {
			out = append(out, ev)
		}
	}
	return out, nil
}

// cursorBulkEvents returns n synthetic events (distinct stable upstream
// ids) inside the fixed clock, for scenarios that need more records than
// one source batch holds (protocol.MaxBatchRecords).
func cursorBulkEvents(n int) []api.UsageEvent {
	mk := func(i int) api.UsageEvent {
		zero, in, out := int64(0), int64(10), int64(5)
		return api.UsageEvent{
			UsageEventID:     fmt.Sprintf("usage-event-bulk-%06d", i),
			ConversationID:   fmt.Sprintf("conv-bulk-%06d", i),
			TimestampMS:      cursorBacklogNow.Add(-2 * time.Hour).UnixMilli(),
			Model:            "cursor-claude-4.5",
			InputTokens:      &in,
			OutputTokens:     &out,
			CacheReadTokens:  &zero,
			CacheWriteTokens: &zero,
		}
	}
	events := make([]api.UsageEvent, 0, n)
	for i := 0; i < n; i++ {
		events = append(events, mk(i))
	}
	return events
}

// cursorBacklogEvents returns two synthetic events well inside the fixed
// clock (visible to a full-window pull from the zero time, invisible to
// the one-hour overlap pull a normal round uses).
func cursorBacklogEvents() []api.UsageEvent {
	mk := func(id string, age time.Duration, in, out int64) api.UsageEvent {
		zero := int64(0)
		return api.UsageEvent{
			UsageEventID: id, ConversationID: "conv-" + id,
			TimestampMS: cursorBacklogNow.Add(-age).UnixMilli(), Model: "cursor-claude-4.5",
			InputTokens: &in, OutputTokens: &out, CacheReadTokens: &zero, CacheWriteTokens: &zero,
		}
	}
	return []api.UsageEvent{
		mk("usage-event-alpha", 2*time.Hour, 120, 30),
		mk("usage-event-beta", 90*time.Minute, 80, 20),
	}
}

// seedCursorBacklogState writes a bound device state matching the mock.
func seedCursorBacklogState(t *testing.T, dir, serverURL string) {
	t.Helper()
	if err := statedir.New(dir).Save(statedir.DeviceState{
		DeviceID:          cursorBacklogDevice,
		DeviceSecret:      "synthetic-device-secret-backlog",
		ServerURL:         serverURL,
		ApplicationID:     "app-backlog",
		ExternalSubjectID: "sub-backlog",
		ConsentRevision:   5,
		UploadAuthorized:  true,
	}); err != nil {
		t.Fatalf("write device state: %v", err)
	}
}

// seedCursorBacklogPermit writes a cursor permit for the synthetic
// account; status selects the permit state under test.
func seedCursorBacklogPermit(t *testing.T, dir string, status cursorsource.Status) {
	t.Helper()
	if err := cursorsource.New(dir).Save(cursorsource.License{
		SourceInstanceID: cursorBacklogSource,
		SourceType:       cursorsource.SourceType,
		AccountMatchID:   identity.MatchAccount(cursorBacklogAccount),
		Status:           status,
		ConfirmedAt:      cursorBacklogNow,
		NextRevision:     1,
		FenceVersion:     1,
	}); err != nil {
		t.Fatalf("write cursor permit: %v", err)
	}
}

// seedCursorBacklogBatch persists one hand-built pending cursor batch
// (fence 1, the synthetic source) with n distinct records.
func seedCursorBacklogBatch(t *testing.T, dir, batchID string, n int) {
	t.Helper()
	records := make([]protocol.Event, 0, n)
	for i := 0; i < n; i++ {
		records = append(records, protocol.Event{
			EventKey:       protocol.EventKeyPrefix + strings.Repeat("0", 63) + strconv.Itoa(i+1),
			Revision:       1,
			Kind:           "event",
			OccurredAt:     cursorBacklogNow.Format(time.RFC3339Nano),
			Tool:           protocol.Tool,
			AdapterVersion: usage.AdapterVersion,
			SourceType:     protocol.SourceType,
		})
	}
	batch := protocol.Batch{BatchID: batchID, SourceInstanceID: cursorBacklogSource, Records: records}
	encoded, err := protocol.EncodeBatch(batch)
	if err != nil {
		t.Fatalf("encode seed batch: %v", err)
	}
	if _, err := cursoroutbox.New(dir).AddBatch(batch, 1, encoded); err != nil {
		t.Fatalf("seed pending cursor batch: %v", err)
	}
}

// runCursorBacklogSync drives one Sync exactly the way the resync CLI
// does: cursor wiring, NO explicit account-tool list.
func runCursorBacklogSync(t *testing.T, dir, serverURL string, a *cursorBacklogAuth, v *cursorBacklogVerify, p *cursorBacklogPull, maxBatches int) (SyncResult, error) {
	t.Helper()
	return Sync(context.Background(), SyncOptions{
		StateDir:  dir,
		ServerURL: serverURL,
		Now:       func() time.Time { return cursorBacklogNow },
		Cursor: &cursorsync.Options{
			Auth:       a,
			Verify:     v.verify,
			Pull:       p.pull,
			Now:        func() time.Time { return cursorBacklogNow },
			MaxBatches: maxBatches,
		},
	})
}

// TestSyncBacklogPassesDoNotRepeatForcedCursor verifies the backlog fix:
// the initial pass forces one full-window cursor recovery round (re-
// emitting the unchanged events), and the backlog passes that drain the
// remaining cursor batches neither re-pull the full window nor re-emit
// anything — the backlog converges instead of growing forever.
func TestSyncBacklogPassesDoNotRepeatForcedCursor(t *testing.T) {
	dir := t.TempDir()
	mock := startCursorBacklogMock(t)
	seedCursorBacklogState(t, dir, mock.URL)
	seedCursorBacklogPermit(t, dir, cursorsource.StatusActive)
	// Warm the event ledger exactly like a previous collection leaves
	// it: the reinstall scenario re-covers events the local cache already
	// knows, so the forced initial round must RE-EMIT them (a normal
	// round would skip them as unchanged).
	warmCache, err := usage.LoadCache(dir)
	if err != nil {
		t.Fatalf("load cursor cache: %v", err)
	}
	_, staged, _, err := usage.Normalize(cursorBacklogEvents(), identity.SubjectNamespace("app-backlog", "sub-backlog"), cursorBacklogAccount, 1, warmCache)
	if err != nil {
		t.Fatalf("warm cursor cache: %v", err)
	}
	warmCache.Apply(staged)
	if err := warmCache.Commit(); err != nil {
		t.Fatalf("commit cursor cache: %v", err)
	}
	// Three pending cursor batches against a per-round drain bound of
	// two: the initial pass cannot drain them all, so at least one
	// backlog pass must run.
	seedCursorBacklogBatch(t, dir, "cbl-seed-1", 1)
	seedCursorBacklogBatch(t, dir, "cbl-seed-2", 1)
	seedCursorBacklogBatch(t, dir, "cbl-seed-3", 1)
	pull := &cursorBacklogPull{events: cursorBacklogEvents()}

	res, err := runCursorBacklogSync(t, dir, mock.URL, &cursorBacklogAuth{}, &cursorBacklogVerify{}, pull, 2)
	if err != nil {
		t.Fatalf("sync with cursor backlog: %v", err)
	}
	if len(res.Incomplete) != 0 {
		t.Fatalf("a converged cursor backlog is complete, got %v", res.Incomplete)
	}
	// The initial pass forced the recovery round: full-window pull, both
	// unchanged events re-emitted.
	if !res.Collection.Cursor.Ran || res.Collection.Cursor.ReemittedRecords != 2 {
		t.Fatalf("the initial pass must force the cursor recovery round: %+v", res.Collection.Cursor)
	}
	if len(pull.calls) != 1 || !pull.calls[0].from.IsZero() {
		t.Fatalf("exactly one initial full-window pull is required, got %+v", pull.calls)
	}
	// Backlog passes only drain the persisted queue and never pull again.
	if res.Backlog.Passes < 1 || res.Backlog.CursorPendingRemaining != 0 {
		t.Fatalf("the cursor backlog must converge through backlog passes: %+v", res.Backlog)
	}
	if res.Backlog.Result.Cursor.ReemittedRecords != 0 {
		t.Fatalf("backlog passes must not re-emit unchanged events (ForceResync repeated), got %d", res.Backlog.Result.Cursor.ReemittedRecords)
	}
	if got := mock.srcBatchPosts(); got != 4 {
		t.Fatalf("expected 4 cursor batch uploads (3 seeded + 1 re-emitted), got %d", got)
	}
}

// TestSyncTotalBudgetSpansDeviceAndCursorQueues verifies the
// shared-budget semantics of MaxTotalBatches on a direct Sync drive: the
// total counts BOTH queues' real POSTs, the run stops honestly when it
// is spent (the cursor round runs first inside the initial collection,
// so it claims the first slot), and the history phase — which would have
// the drained batches as its full-archive targets here — is skipped
// before any lock or preflight because no budget remains.
func TestSyncTotalBudgetSpansDeviceAndCursorQueues(t *testing.T) {
	dir := t.TempDir()
	homeDir := t.TempDir()
	mock := startCursorBacklogMock(t)
	seedCursorBacklogState(t, dir, mock.URL)
	seedCursorBacklogPermit(t, dir, cursorsource.StatusActive)
	seedCodexSessionsGrant(t, dir, homeDir)
	for i := 1; i <= 3; i++ {
		seedDeviceBacklogBatch(t, dir, homeDir, fmt.Sprintf("budget-dev-%d", i), fmt.Sprintf("budget-key-%d", i))
		seedCursorBacklogBatch(t, dir, fmt.Sprintf("budget-cursor-%d", i), 1)
	}
	pull := &cursorBacklogPull{}
	res, err := Sync(context.Background(), SyncOptions{
		StateDir: dir, ServerURL: mock.URL, HomeDir: homeDir, MaxTotalBatches: 4,
		Now:    func() time.Time { return cursorBacklogNow },
		Cursor: &cursorsync.Options{Auth: &cursorBacklogAuth{}, Verify: (&cursorBacklogVerify{}).verify, Pull: pull.pull, Now: func() time.Time { return cursorBacklogNow }, MaxBatches: 1},
	})
	if err == nil || !isErrSyncIncomplete(err) {
		t.Fatalf("a budget-exhausted run must be incomplete, got %+v, %v", res, err)
	}
	if !res.BudgetExhausted {
		t.Fatalf("the budget exhaustion must be flagged, got %+v", res)
	}
	// The cursor round (first claim inside the initial collection) spent
	// one slot; the device drain spent the remaining three and emptied
	// its queue without a decline — the budget was exactly spent.
	if res.Collection.Cursor.SyncedBatches != 1 || res.Collection.AttemptedBatches != 3 || res.Collection.PendingRemaining != 0 {
		t.Fatalf("queue accounting across the shared budget: %+v", res.Collection)
	}
	if res.Collection.Cursor.PendingRemaining != 2 {
		t.Fatalf("the cursor round bound leaves two batches pending: %+v", res.Collection.Cursor)
	}
	// The backlog short-circuits without running a pass: the run-wide
	// total is spent, so no pass (and no preflight) may run.
	if res.Backlog.Passes != 0 || res.Backlog.CursorPendingRemaining != 2 || res.Backlog.Stopped != backlogBudgetStopped {
		t.Fatalf("the backlog must stop at the spent budget without a pass: %+v", res.Backlog)
	}
	// The history phase (full archive here: the 3 device batches the
	// drain just synced) must be skipped before any preflight.
	if res.Resync.Ran || res.Resync.Skipped == "" {
		t.Fatalf("the history phase must be skipped for the spent budget, got %+v", res.Resync)
	}
	if mock.srcBatchPosts() != 1 || mock.deviceBatchPosts() != 3 {
		t.Fatalf("exactly the budget's four POSTs may happen, got cursor=%d device=%d", mock.srcBatchPosts(), mock.deviceBatchPosts())
	}
	if len(pull.calls) != 1 {
		t.Fatalf("only the initial cursor pull is allowed, got %d", len(pull.calls))
	}
	if !containsReason(res.Incomplete, "2 cursor batch(es)") || !containsReason(res.Incomplete, "shared sync POST budget") {
		t.Fatalf("the pending cursor batches and the budget stop must be named, got %v", res.Incomplete)
	}
}

// TestSyncCursorFailureNotSwallowedWithoutAccountTools verifies the
// nil-AccountTools path (the resync CLI): a cursor round that fails is
// reported as incomplete, never as a complete sync.
func TestSyncCursorFailureNotSwallowedWithoutAccountTools(t *testing.T) {
	dir := t.TempDir()
	mock := startCursorBacklogMock(t)
	seedCursorBacklogState(t, dir, mock.URL)
	seedCursorBacklogPermit(t, dir, cursorsource.StatusActive)
	pull := &cursorBacklogPull{events: cursorBacklogEvents()}

	res, err := runCursorBacklogSync(t, dir, mock.URL, &cursorBacklogAuth{}, &cursorBacklogVerify{fail: true}, pull, 2)
	if err == nil || !isErrSyncIncomplete(err) {
		t.Fatalf("a failed cursor round must make the sync incomplete, got %v", err)
	}
	if !res.Collection.Cursor.Ran {
		t.Fatalf("the cursor round ran and failed: %+v", res.Collection.Cursor)
	}
	if len(pull.calls) != 0 {
		t.Fatal("a failed verification must not pull")
	}
	if !containsReason(res.Incomplete, "account source Cursor failed") {
		t.Fatalf("the cursor failure must be named, got %v", res.Incomplete)
	}
}

// TestSyncCursorExpiredPermitIsIncompleteNotMasked verifies that a
// permit which exists in a non-collectable status (login_expired) still
// owes completion when the grant allows Cursor: the skip is reported,
// not masked as success. The current authorization needs the data.
func TestSyncCursorExpiredPermitIsIncompleteNotMasked(t *testing.T) {
	dir := t.TempDir()
	mock := startCursorBacklogMock(t)
	seedCursorBacklogState(t, dir, mock.URL)
	seedCursorBacklogPermit(t, dir, cursorsource.StatusLoginExpired)
	pull := &cursorBacklogPull{events: cursorBacklogEvents()}

	res, err := runCursorBacklogSync(t, dir, mock.URL, &cursorBacklogAuth{}, &cursorBacklogVerify{}, pull, 2)
	if err == nil || !isErrSyncIncomplete(err) {
		t.Fatalf("a login-expired cursor permit must make the sync incomplete, got %v", err)
	}
	if res.Collection.Cursor.Ran || len(pull.calls) != 0 {
		t.Fatalf("a login-expired permit must not run a round: ran=%t pulls=%d", res.Collection.Cursor.Ran, len(pull.calls))
	}
	if !containsReason(res.Incomplete, "account source Cursor did not run") {
		t.Fatalf("the login-expired skip must be named, got %v", res.Incomplete)
	}
}

// TestSyncCursorLegitimateSkipsAreNotIncomplete verifies the two skips
// that must NOT be judged as failures without an explicit account-tool
// list: no local permit at all (never enabled or logged out), and a
// server grant that excludes Cursor (an authorization verdict).
func TestSyncCursorLegitimateSkipsAreNotIncomplete(t *testing.T) {
	t.Run("no local permit", func(t *testing.T) {
		dir := t.TempDir()
		mock := startCursorBacklogMock(t)
		seedCursorBacklogState(t, dir, mock.URL)
		pull := &cursorBacklogPull{events: cursorBacklogEvents()}

		res, err := runCursorBacklogSync(t, dir, mock.URL, &cursorBacklogAuth{}, &cursorBacklogVerify{}, pull, 2)
		if err != nil {
			t.Fatalf("a device without a cursor permit must sync cleanly, got %v (incomplete=%v)", err, res.Incomplete)
		}
		if containsReason(res.Incomplete, "account source Cursor") {
			t.Fatalf("a never-enabled cursor must not be reported, got %v", res.Incomplete)
		}
	})
	t.Run("grant excludes cursor", func(t *testing.T) {
		dir := t.TempDir()
		mock := startCursorBacklogMock(t)
		mock.setAllowedTools([]string{"SomeFutureTool"})
		seedCursorBacklogState(t, dir, mock.URL)
		seedCursorBacklogPermit(t, dir, cursorsource.StatusActive)
		pull := &cursorBacklogPull{events: cursorBacklogEvents()}

		res, err := runCursorBacklogSync(t, dir, mock.URL, &cursorBacklogAuth{}, &cursorBacklogVerify{}, pull, 2)
		if err != nil {
			t.Fatalf("an unauthorized cursor skipping normally must not fail the sync, got %v (incomplete=%v)", err, res.Incomplete)
		}
		if containsReason(res.Incomplete, "account source Cursor") {
			t.Fatalf("an unauthorized cursor must not be reported, got %v", res.Incomplete)
		}
	})
}

// TestSyncCursorSkippedNoStableIDIsIncomplete verifies that a round
// which dropped usage rows without a stable upstream event id is never
// reported as a complete success: the uncounted events are a gap.
func TestSyncCursorSkippedNoStableIDIsIncomplete(t *testing.T) {
	dir := t.TempDir()
	mock := startCursorBacklogMock(t)
	seedCursorBacklogState(t, dir, mock.URL)
	seedCursorBacklogPermit(t, dir, cursorsource.StatusActive)
	// One normal event plus one without a stable id: the round succeeds
	// but leaves one usage event uncounted.
	idless := cursorBacklogEvents()[0]
	idless.UsageEventID = ""
	pull := &cursorBacklogPull{events: []api.UsageEvent{idless, cursorBacklogEvents()[1]}}

	res, err := runCursorBacklogSync(t, dir, mock.URL, &cursorBacklogAuth{}, &cursorBacklogVerify{}, pull, 2)
	if err == nil || !isErrSyncIncomplete(err) {
		t.Fatalf("dropped id-less usage events must make the sync incomplete, got %v", err)
	}
	if res.Collection.Cursor.SkippedNoStableID != 1 || res.Collection.Cursor.NewRecords != 1 {
		t.Fatalf("round accounting: %+v", res.Collection.Cursor)
	}
	if !containsReason(res.Incomplete, "without a stable upstream id") {
		t.Fatalf("the uncounted events must be named, got %v", res.Incomplete)
	}
}

func isErrSyncIncomplete(err error) bool { return errors.Is(err, ErrSyncIncomplete) }

func containsReason(reasons []string, substr string) bool {
	for _, r := range reasons {
		if strings.Contains(r, substr) {
			return true
		}
	}
	return false
}

// seedDeviceBacklogBatch writes one pending device batch attributed to a
// codex grant, mirroring what a prior collection round exported (the
// record shape passes the drain's upload gates and resync's offline
// validation).
func seedDeviceBacklogBatch(t *testing.T, dir, homeDir, batchID, key string) {
	t.Helper()
	seedDeviceBacklogBatchStatus(t, dir, homeDir, batchID, key, outbox.StatusPending)
}

// seedDeviceBacklogBatchStatus is seedDeviceBacklogBatch with the outbox
// status chosen by the caller (StatusSynced seeds already-retransmitted
// pre-connect history).
func seedDeviceBacklogBatchStatus(t *testing.T, dir, homeDir, batchID, key, status string) {
	t.Helper()
	seedDeviceBacklogBatchRecords(t, dir, homeDir, batchID, key, status, 1)
}

// seedDeviceBacklogBatchRecords is seedDeviceBacklogBatchStatus with the
// record count chosen by the caller (2+ records allow partially rejected
// receipts).
func seedDeviceBacklogBatchRecords(t *testing.T, dir, homeDir, batchID, key, status string, n int) {
	t.Helper()
	batchesDir := filepath.Join(dir, "batches")
	if err := os.MkdirAll(batchesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	records := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		recordKey := key
		if n > 1 {
			recordKey = fmt.Sprintf("%s-%d", key, i+1)
		}
		records = append(records, map[string]any{
			"recordKey":      recordKey,
			"kind":           "delta",
			"tool":           "Codex",
			"model":          "gpt-5.4",
			"occurredAt":     cursorBacklogNow.Add(-time.Hour).Format(time.RFC3339),
			"input":          "100",
			"output":         "50",
			"cacheRead":      "20",
			"cacheWrite":     "5",
			"adapterVersion": "synthetic",
			"sourceType":     "fixture",
		})
	}
	raw, err := json.Marshal(map[string]any{"batchId": batchID, "records": records})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(batchesDir, batchID+".json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(homeDir, ".codex", "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	out, err := outbox.New(dir).Load()
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
		CreatedAt:   cursorBacklogNow.Add(-time.Duration(len(out.Batches)+1) * time.Minute),
	})
	if err := outbox.New(dir).Save(out); err != nil {
		t.Fatal(err)
	}
}

// seedCodexSessionsGrant enables the codex grant the seeded device
// batches are attributed to (resync eligibility requires it).
func seedCodexSessionsGrant(t *testing.T, dir, homeDir string) string {
	t.Helper()
	input := filepath.Join(homeDir, ".codex", "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := grants.New(dir).Enable("codex-jsonl", input); err != nil {
		t.Fatalf("enable grant: %v", err)
	}
	return input
}

// TestSyncCrossPhaseScopeChangeRefusesSuccess verifies the cross-phase
// scope consistency rule: the initial collection, the history
// retransmission and the backlog drain passes must all have observed the
// same consent revision (under the active grant protocol). A run that
// straddles a server-side scope change — or cannot confirm the live
// scope at all — refuses success, because the collection drain recovered
// quarantine and uploaded under the old scope and the current
// authorization is not fully covered.
func TestSyncCrossPhaseScopeChangeRefusesSuccess(t *testing.T) {
	// The scope moves right after the initial collection's drain upload:
	// the retransmission preflight observes revision 6 while the
	// collection ran under 5.
	t.Run("retransmission sees the newer scope", func(t *testing.T) {
		dir := t.TempDir()
		homeDir := t.TempDir()
		mock := startCursorBacklogMock(t)
		mock.bumpRevisionAfterDevicePosts(1)
		seedCursorBacklogState(t, dir, mock.URL)
		seedCodexSessionsGrant(t, dir, homeDir)
		seedDeviceBacklogBatch(t, dir, homeDir, "cbl-dev-1", "cbl-dev-key-1")

		res, err := Sync(context.Background(), SyncOptions{
			StateDir: dir, ServerURL: mock.URL,
			Now: func() time.Time { return cursorBacklogNow },
		})
		if err == nil || !isErrSyncIncomplete(err) {
			t.Fatalf("a scope change between the collection and the retransmission must refuse success, got %v", err)
		}
		if res.Collection.GrantSync.ConsentRevision != 5 || res.Resync.ConsentRevision != 6 {
			t.Fatalf("revisions: collection=%d retransmission=%d, want 5/6", res.Collection.GrantSync.ConsentRevision, res.Resync.ConsentRevision)
		}
		if !res.Resync.Completed {
			t.Fatalf("the retransmission itself finished under the fresh scope; only the run must refuse success: %+v", res.Resync)
		}
		if !containsReason(res.Incomplete, "consent scope moved between the collection") {
			t.Fatalf("the scope move must be named, got %v", res.Incomplete)
		}
	})

	// No grants and no batches: the retransmission has nothing eligible
	// and never prefetches, so connect's own fresh self confirmation must
	// observe the scope move (revision 6 on its self request after the
	// grant sync's).
	t.Run("empty retransmission confirms the fresh scope", func(t *testing.T) {
		dir := t.TempDir()
		mock := startCursorBacklogMock(t)
		mock.bumpRevisionAfterSelfCalls(2)
		seedCursorBacklogState(t, dir, mock.URL)

		res, err := Sync(context.Background(), SyncOptions{
			StateDir: dir, ServerURL: mock.URL,
			Now: func() time.Time { return cursorBacklogNow },
		})
		if err == nil || !isErrSyncIncomplete(err) {
			t.Fatalf("an empty retransmission must still confirm the live scope, got %v", err)
		}
		if res.Resync.ConsentRevision != 6 {
			t.Fatalf("the fresh self confirmation must observe revision 6, got %d", res.Resync.ConsentRevision)
		}
		if !containsReason(res.Incomplete, "consent scope moved between the collection") {
			t.Fatalf("the scope move must be named, got %v", res.Incomplete)
		}
	})

	// The scope moves after the history retransmission completed under 5
	// (the unbudgeted drive keeps the original initial → history →
	// backlog order; the history replays the 5 batches the initial round
	// just synced as device posts 6-10): the first backlog pass drains 5
	// more (posts 11-15), and the scope moves right after the 10th
	// device post, so backlog pass 2's grant sync applies revision 6 and
	// its 2 uploads mix old-scope and new-scope coverage. The
	// retransmission itself stays complete under 5 — the backlog
	// comparison must refuse the success.
	t.Run("backlog drain runs under the newer scope", func(t *testing.T) {
		dir := t.TempDir()
		homeDir := t.TempDir()
		mock := startCursorBacklogMock(t)
		seedCursorBacklogState(t, dir, mock.URL)
		seedCodexSessionsGrant(t, dir, homeDir)
		// 12 pending batches: the initial round drains 5 (the round
		// bound), the history retransmission replays those 5 (device
		// posts 6-10), backlog pass 1 drains 5 more (posts 11-15), and
		// the scope moves right after the 10th device post, so backlog
		// pass 2's grant sync applies revision 6 and its 2 uploads mix
		// old-scope and new-scope coverage.
		for i := 1; i <= 12; i++ {
			seedDeviceBacklogBatch(t, dir, homeDir, fmt.Sprintf("cbl-mix-%d", i), fmt.Sprintf("cbl-mix-key-%d", i))
		}
		mock.bumpRevisionAfterDevicePosts(11)

		res, err := Sync(context.Background(), SyncOptions{
			StateDir: dir, ServerURL: mock.URL,
			Now: func() time.Time { return cursorBacklogNow },
		})
		if err == nil || !isErrSyncIncomplete(err) {
			t.Fatalf("a backlog drain under a moved scope must refuse success, got %v", err)
		}
		if res.Collection.GrantSync.ConsentRevision != 5 || res.Resync.ConsentRevision != 5 || !res.Resync.Completed {
			t.Fatalf("the collection and the history phase must both have run under 5: collected=%d history=%d completed=%t", res.Collection.GrantSync.ConsentRevision, res.Resync.ConsentRevision, res.Resync.Completed)
		}
		if res.Backlog.Passes < 2 || res.Backlog.Result.GrantSync.ConsentRevision != 6 {
			t.Fatalf("the last backlog pass must have applied the moved revision: passes=%d lastRevision=%d", res.Backlog.Passes, res.Backlog.Result.GrantSync.ConsentRevision)
		}
		if !containsReason(res.Incomplete, "backlog drain") {
			t.Fatalf("the backlog scope move must be named, got %v", res.Incomplete)
		}
	})

	// Control: a stable scope across all phases stays complete.
	t.Run("stable scope stays complete", func(t *testing.T) {
		dir := t.TempDir()
		mock := startCursorBacklogMock(t)
		seedCursorBacklogState(t, dir, mock.URL)

		res, err := Sync(context.Background(), SyncOptions{
			StateDir: dir, ServerURL: mock.URL,
			Now: func() time.Time { return cursorBacklogNow },
		})
		if err != nil {
			t.Fatalf("a stable scope must stay complete, got %v (incomplete=%v)", err, res.Incomplete)
		}
		if containsReason(res.Incomplete, "consent scope moved") {
			t.Fatalf("no scope move may be reported, got %v", res.Incomplete)
		}
	})
}

// TestConnectFirstEnablePullsCursorUpstreamExactlyOnce pins the P1
// single-pull contract for a first-time cursor enable inside connect:
// the setup enable's first sync performs the run's ONE upstream pull
// (full window — a fresh permit has no watermark), and the initial
// collection round runs its cursor phase drain-only over the freshly
// enabled source: no credential read, no second pull (neither a forced
// full-window recovery pull nor the normal incremental overlap pull),
// and no re-emission, so the enable's upload is never duplicated.
func TestConnectFirstEnablePullsCursorUpstreamExactlyOnce(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startCursorBacklogMock(t)
	cfg := startSyncConfigMock(t, mock.URL, []string{"Cursor"}, nil)

	// A bound state carrying this link's receipt (the cursor mock serves
	// no bind endpoint), with NO cursor permit: connect must run the
	// first-time enable inside its setup.
	ticket := strings.Repeat("6", 64)
	st := statedir.DeviceState{
		DeviceID:           cursorBacklogDevice,
		DeviceSecret:       strings.Repeat("a", 64),
		ServerURL:          mock.URL,
		ApplicationID:      "app-sync",
		ExternalSubjectID:  "sub-sync",
		ConsentRevision:    5,
		UploadAuthorized:   true,
		ConnectReceiptHash: computeReceiptFingerprint(ticket, cfg.URL+"/api/collector/connect"),
	}
	if err := statedir.New(stateDir).Save(st); err != nil {
		t.Fatalf("write bound state: %v", err)
	}
	pull := &cursorBacklogPull{events: cursorBacklogEvents()}

	res, err := runSyncConnectWithOptions(t, cfg, stateDir, homeDir, ticket, Options{
		Cursor: budgetCursorWiring(pull, 5),
		CursorConfirm: func(notice string, out io.Writer) (bool, error) {
			return true, nil
		},
	})
	if err != nil {
		t.Fatalf("a first-enable connect must complete: %v (incomplete=%v)", err, res.Sync.Incomplete)
	}
	// Exactly ONE upstream pull: the enable's first sync, covering the
	// full window from the zero time. The initial collection round never
	// pulls — its cursor phase is drain-only after a fresh enable.
	if len(pull.calls) != 1 {
		t.Fatalf("expected exactly the enable's first-sync pull, got %+v", pull.calls)
	}
	if !pull.calls[0].from.IsZero() {
		t.Fatalf("the enable's first sync must pull the full window, got %+v", pull.calls[0])
	}
	// The initial round's cursor phase ran drain-only: it executed (so
	// the account source is judged by the completion contract) but
	// re-emitted nothing and produced no duplicate batch — exactly the
	// enable's one batch was ever uploaded.
	if !res.Sync.Collection.Cursor.Ran {
		t.Fatalf("the initial round's drain-only cursor phase must execute, got %+v", res.Sync.Collection.Cursor)
	}
	if res.Sync.Collection.Cursor.ReemittedRecords != 0 || res.Sync.Collection.Cursor.SyncedBatches != 0 {
		t.Fatalf("the initial round must not re-emit or duplicate the enable's upload: %+v", res.Sync.Collection.Cursor)
	}
	if got := mock.srcBatchPosts(); got != 1 {
		t.Fatalf("only the enable's first-sync batch may be uploaded, got %d", got)
	}
	// The permit completed its first sync and is active.
	license, ok, lErr := cursorsource.New(stateDir).Load()
	if lErr != nil || !ok {
		t.Fatalf("expected a cursor permit after the enable, ok=%v err=%v", ok, lErr)
	}
	if license.Status != cursorsource.StatusActive || license.PullWatermark == nil {
		t.Fatalf("the enable's first sync must complete (active permit, watermark set), got %+v", license)
	}
}

// seedFirstEnableConnect prepares the shared first-enable scenario: a
// bound state already carrying this link's receipt (so connect skips the
// bind — the cursor mock serves no bind endpoint) and NO cursor permit,
// forcing the first-time enable inside connect's setup.
func seedFirstEnableConnect(t *testing.T, stateDir string, mock *cursorBacklogMock, cfg *syncConfigMock, ticket string) {
	t.Helper()
	st := statedir.DeviceState{
		DeviceID:           cursorBacklogDevice,
		DeviceSecret:       strings.Repeat("a", 64),
		ServerURL:          mock.URL,
		ApplicationID:      "app-sync",
		ExternalSubjectID:  "sub-sync",
		ConsentRevision:    5,
		UploadAuthorized:   true,
		ConnectReceiptHash: computeReceiptFingerprint(ticket, cfg.URL+"/api/collector/connect"),
	}
	if err := statedir.New(stateDir).Save(st); err != nil {
		t.Fatalf("write bound state: %v", err)
	}
}

// cursorPendingCountFor reports how many cursor outbox batches are still
// pending in the state directory.
func cursorPendingCountFor(t *testing.T, stateDir string) int {
	t.Helper()
	n, err := cursoroutbox.New(stateDir).CountPending()
	if err != nil {
		t.Fatalf("count pending cursor batches: %v", err)
	}
	return n
}

// TestConnectFirstEnableBudgetExhaustionIsHonestIncomplete pins the
// budget arm of the first-enable single-pull contract: when the enable's
// bounded first sync leaves a cursor batch pending and the run's shared
// POST budget is spent, the initial collection's drain-only cursor round
// declines BEFORE its POST, the run reports ErrSyncIncomplete (never
// success), nothing is pulled a second time, and the declined batch
// stays queued and drainable — the queue-resume state is preserved.
func TestConnectFirstEnableBudgetExhaustionIsHonestIncomplete(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startCursorBacklogMock(t)
	cfg := startSyncConfigMock(t, mock.URL, []string{"Cursor"}, nil)
	ticket := strings.Repeat("6", 64)
	seedFirstEnableConnect(t, stateDir, mock, cfg, ticket)

	// 501 events exceed one source batch (protocol.MaxBatchRecords is
	// 500), so the enable's first sync persists TWO batches; with a
	// cursor round bound of 1 and a run-wide budget of exactly 1 POST,
	// the enable uploads the first batch, the second stays pending, and
	// the initial round's drain-only attempt is declined by the budget.
	pull := &cursorBacklogPull{events: cursorBulkEvents(501)}

	res, err := runSyncConnectWithOptions(t, cfg, stateDir, homeDir, ticket, Options{
		MaxTotalBatches: 1,
		Cursor:          budgetCursorWiring(pull, 1),
		CursorConfirm: func(notice string, out io.Writer) (bool, error) {
			return true, nil
		},
	})
	if err == nil || !isErrSyncIncomplete(err) {
		t.Fatalf("a budget-exhausted first-enable connect must be incomplete, got %v", err)
	}
	if !res.Sync.BudgetExhausted {
		t.Fatalf("the budget exhaustion must be flagged, got %+v", res.Sync)
	}
	// Exactly one upstream pull — the enable's first sync. The declined
	// drain-only round never reaches a pull, and the failed-POST budget
	// stop means no second batch was ever uploaded.
	if len(pull.calls) != 1 || !pull.calls[0].from.IsZero() {
		t.Fatalf("only the enable's full-window pull may happen, got %+v", pull.calls)
	}
	if got := mock.srcBatchPosts(); got != 1 {
		t.Fatalf("exactly the enable's first batch may be uploaded, got %d", got)
	}
	// The permit completed its first sync (the enable itself succeeded);
	// only the transmission queue is incomplete.
	license, ok, lErr := cursorsource.New(stateDir).Load()
	if lErr != nil || !ok {
		t.Fatalf("expected a cursor permit after the enable, ok=%v err=%v", ok, lErr)
	}
	if license.Status != cursorsource.StatusActive {
		t.Fatalf("the enable's first sync completed, so the permit must be active, got %q", license.Status)
	}
	// The declined batch stays queued (queue-resume state preserved) and
	// the incompleteness names it and the budget honestly.
	if n := cursorPendingCountFor(t, stateDir); n != 1 {
		t.Fatalf("the declined cursor batch must stay pending, got %d", n)
	}
	if !containsReason(res.Sync.Incomplete, "1 cursor batch(es) are still pending") {
		t.Fatalf("the pending cursor batch must be named, got %v", res.Sync.Incomplete)
	}
	if !containsReason(res.Sync.Incomplete, "shared sync POST budget") {
		t.Fatalf("the budget stop must be named, got %v", res.Sync.Incomplete)
	}
	// Resume: the retained batch is still drainable under a fresh budget
	// (no pull involved), proving nothing was lost.
	resume, rErr := cursorsync.DrainPending(context.Background(), cursorsync.Options{
		StateDir:   stateDir,
		ServerURL:  mock.URL,
		HTTPClient: cfg.Client(),
		Now:        func() time.Time { return cursorBacklogNow },
		MaxBatches: 5,
	}, cursyncGateUnrestricted)
	if rErr != nil {
		t.Fatalf("the retained cursor batch must drain under a fresh budget: %v", rErr)
	}
	if !resume.Ran || resume.SyncedBatches != 1 || resume.PendingRemaining != 0 {
		t.Fatalf("the resumed drain must upload the retained batch, got %+v", resume)
	}
	if got := mock.srcBatchPosts(); got != 2 {
		t.Fatalf("the resume must upload exactly the retained batch, got %d", got)
	}
}

// cursyncGateUnrestricted is the unrestricted gate a standalone drain
// uses when the live self view governs the effective scope.
var cursyncGateUnrestricted = cursorsync.Gate{}

// TestConnectFirstEnablePullFailurePullsOnceAndStaysHonest pins the P2
// failure arm: a first enable whose upstream pull fails must never read
// as a successful connect, and the SAME command must not pull the
// upstream a second time — one pull per command, success or failure. The
// enable fails inside the setup (the permit is written, so the initial
// collection's cursor round runs DRAIN-ONLY over it: no credential read,
// no retry pull), the failure is reported as its own incompleteness
// reason, the permit stays pending_first_sync with no watermark advance,
// and the next run (connect or the scheduled collection) retries.
func TestConnectFirstEnablePullFailurePullsOnceAndStaysHonest(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startCursorBacklogMock(t)
	cfg := startSyncConfigMock(t, mock.URL, []string{"Cursor"}, nil)
	ticket := strings.Repeat("6", 64)
	seedFirstEnableConnect(t, stateDir, mock, cfg, ticket)

	pull := &cursorBacklogPull{err: errors.New("synthetic upstream pull failure")}
	out := &bytes.Buffer{}
	res, err := runCursorConnectWithOptionsOut(t, cfg, stateDir, homeDir, ticket, Options{
		Cursor: budgetCursorWiring(pull, 5),
		CursorConfirm: func(notice string, w io.Writer) (bool, error) {
			return true, nil
		},
	}, out)
	if err == nil || !isErrSyncIncomplete(err) {
		t.Fatalf("a failed first-enable pull must make the connect incomplete, got %v", err)
	}
	// Exactly ONE upstream pull — the enable's first sync attempt. The
	// initial collection's cursor round ran drain-only over the permit
	// and never pulled again.
	if len(pull.calls) != 1 {
		t.Fatalf("one upstream pull per command, success or failure: expected only the enable's attempt, got %+v", pull.calls)
	}
	// The failure is its own incompleteness reason (the clean drain-only
	// round must not mask it as success), carrying the underlying pull
	// error.
	if !containsReason(res.Sync.Incomplete, "did not complete its first sync") {
		t.Fatalf("the first-sync failure must be named, got %v", res.Sync.Incomplete)
	}
	if !containsReason(res.Sync.Incomplete, "cursor usage pull failed") {
		t.Fatalf("the underlying pull failure must be named, got %v", res.Sync.Incomplete)
	}
	if !res.Sync.Collection.Cursor.Ran || res.Sync.Collection.Cursor.Skipped != "" {
		t.Fatalf("the initial round's drain-only cursor phase must run cleanly over the permit, got %+v", res.Sync.Collection.Cursor)
	}
	// The honest guidance points at the continuation path, never at the
	// idempotent `toktrail cursor enable` (a written permit is a no-op
	// there).
	outStr := out.String()
	if !strings.Contains(outStr, "enabled; the first sync did not complete") {
		t.Fatalf("the first-sync failure must point at the continuation path, got:\n%s", outStr)
	}
	if strings.Contains(outStr, "not enabled; run `toktrail cursor enable`") {
		t.Fatalf("a written permit must not be called not-enabled, got:\n%s", outStr)
	}
	if got := mock.srcBatchPosts(); got != 0 {
		t.Fatalf("a failed pull must upload nothing, got %d source batches", got)
	}
	// The permit honestly records that the first sync never completed.
	license, ok, lErr := cursorsource.New(stateDir).Load()
	if lErr != nil || !ok {
		t.Fatalf("expected a cursor permit after the failed enable, ok=%v err=%v", ok, lErr)
	}
	if license.Status != cursorsource.StatusPendingFirstSync {
		t.Fatalf("the permit must stay pending_first_sync, got %q", license.Status)
	}
	if license.PullWatermark != nil {
		t.Fatalf("a failed pull must not advance the watermark, got %+v", license.PullWatermark)
	}
}

// TestConnectFirstEnablePullFailureWithBudgetNotMasked pins the budget
// interaction: a first pull failure under a tight shared budget neither
// masks the failure as success nor lets the budget stop hide it — the
// other sources' queue still drains under the budget, and the run stays
// an honest ErrSyncIncomplete naming the failed first sync with no
// bogus budget-exhaustion flag (nothing was ever declined).
func TestConnectFirstEnablePullFailureWithBudgetNotMasked(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startCursorBacklogMock(t)
	cfg := startSyncConfigMock(t, mock.URL, []string{"Cursor", "Codex"}, nil)
	ticket := strings.Repeat("6", 64)
	seedFirstEnableConnect(t, stateDir, mock, cfg, ticket)
	seedCodexSessionsGrant(t, stateDir, homeDir)
	seedDeviceBacklogBatch(t, stateDir, homeDir, "pullfail-budget-dev-1", "pullfail-budget-dev-key-1")

	pull := &cursorBacklogPull{err: errors.New("synthetic upstream pull failure")}
	res, err := runSyncConnectWithOptions(t, cfg, stateDir, homeDir, ticket, Options{
		MaxTotalBatches: 1,
		Cursor:          budgetCursorWiring(pull, 5),
		CursorConfirm: func(notice string, out io.Writer) (bool, error) {
			return true, nil
		},
	})
	if err == nil || !isErrSyncIncomplete(err) {
		t.Fatalf("the failed first sync must keep the connect incomplete, got %v", err)
	}
	// The failure is named; the budget was spent exactly (one device
	// POST) without a decline, so no bogus exhaustion flag may appear.
	if !containsReason(res.Sync.Incomplete, "did not complete its first sync") {
		t.Fatalf("the first-sync failure must be named, got %v", res.Sync.Incomplete)
	}
	if res.Sync.BudgetExhausted {
		t.Fatalf("an exactly-spent budget with no decline must not flag exhaustion, got %+v", res.Sync)
	}
	// One upstream pull only; the drain-only cursor round never pulled,
	// and the other source's queue kept flowing (existing source state
	// preserved).
	if len(pull.calls) != 1 {
		t.Fatalf("one upstream pull per command, got %+v", pull.calls)
	}
	if got := mock.srcBatchPosts(); got != 0 {
		t.Fatalf("a failed pull must upload no cursor batch, got %d", got)
	}
	if got := mock.deviceBatchPosts(); got != 1 {
		t.Fatalf("the device queue must still drain under the budget, got %d", got)
	}
	if n := pendingCount(t, stateDir); n != 0 {
		t.Fatalf("nothing may stay pending, got %d", n)
	}
	license, ok, lErr := cursorsource.New(stateDir).Load()
	if lErr != nil || !ok || license.Status != cursorsource.StatusPendingFirstSync || license.PullWatermark != nil {
		t.Fatalf("the permit must stay pending_first_sync with no watermark, got ok=%v err=%v license=%+v", ok, lErr, license)
	}
}

// TestConnectFirstEnablePullFailureWithDeadline pins the deadline
// interaction: when the first pull fails and the run's shared budget
// deadline then expires (a clock advance armed inside the failing pull),
// the run reports BOTH honestly — the failed first sync as its own
// incompleteness reason and the deadline stop as budget exhaustion —
// still with exactly one upstream pull, the declined device batch kept
// pending, and the permit left for the next run.
func TestConnectFirstEnablePullFailureWithDeadline(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startCursorBacklogMock(t)
	cfg := startSyncConfigMock(t, mock.URL, []string{"Cursor", "Codex"}, nil)
	ticket := strings.Repeat("6", 64)
	seedFirstEnableConnect(t, stateDir, mock, cfg, ticket)
	seedCodexSessionsGrant(t, stateDir, homeDir)
	seedDeviceBacklogBatch(t, stateDir, homeDir, "pullfail-deadline-dev-1", "pullfail-deadline-dev-key-1")

	// The clock starts at the fixed test time; the failing pull arms an
	// advance far past the run budget's default 10-minute deadline, so
	// every later reserve (the device drain below) declines with
	// ErrDeadlineExceeded. Everything is single-goroutine, so a plain
	// flag captured by the closures is race-free.
	deadlinePassed := false
	nowFn := func() time.Time {
		if deadlinePassed {
			return cursorBacklogNow.Add(time.Hour)
		}
		return cursorBacklogNow
	}
	pull := &cursorBacklogPull{err: errors.New("synthetic upstream pull failure")}
	out := &bytes.Buffer{}
	res, err := Run(context.Background(), Options{
		URL:             fmt.Sprintf("%s/api/collector/connect#%s", cfg.URL, ticket),
		StateDir:        stateDir,
		HomeDir:         homeDir,
		BinaryPath:      fakeCollectorBinary(t),
		HTTPClient:      cfg.Client(),
		SchedulerRunner: &mockRunner{},
		Now:             nowFn,
		Out:             out,
		Cursor: &cursorsync.Options{
			Auth:   &cursorBacklogAuth{},
			Verify: (&cursorBacklogVerify{}).verify,
			Pull: func(ctx context.Context, sessionToken string, from, to time.Time) ([]api.UsageEvent, error) {
				deadlinePassed = true
				return pull.pull(ctx, sessionToken, from, to)
			},
			Now: func() time.Time { return cursorBacklogNow },
		},
		CursorConfirm: func(notice string, w io.Writer) (bool, error) {
			return true, nil
		},
	})
	if err == nil || !isErrSyncIncomplete(err) {
		t.Fatalf("the failed first sync plus the expired deadline must keep the connect incomplete, got %v", err)
	}
	// Both failures are reported, neither masks the other.
	if !containsReason(res.Sync.Incomplete, "did not complete its first sync") {
		t.Fatalf("the first-sync failure must be named, got %v", res.Sync.Incomplete)
	}
	if !containsReason(res.Sync.Incomplete, "shared sync POST budget") {
		t.Fatalf("the deadline stop must be named, got %v", res.Sync.Incomplete)
	}
	if !res.Sync.BudgetExhausted {
		t.Fatalf("the expired deadline must flag budget exhaustion, got %+v", res.Sync)
	}
	// Exactly one upstream pull; the declined device batch stays pending
	// (never a lost batch), and the permit is left for the next run.
	if len(pull.calls) != 1 {
		t.Fatalf("one upstream pull per command, got %+v", pull.calls)
	}
	if got := mock.deviceBatchPosts(); got != 0 {
		t.Fatalf("the deadline must stop the device drain before its POST, got %d", got)
	}
	if n := pendingCount(t, stateDir); n != 1 {
		t.Fatalf("the declined device batch must stay pending, got %d", n)
	}
	license, ok, lErr := cursorsource.New(stateDir).Load()
	if lErr != nil || !ok || license.Status != cursorsource.StatusPendingFirstSync || license.PullWatermark != nil {
		t.Fatalf("the permit must stay pending_first_sync with no watermark, got ok=%v err=%v license=%+v", ok, lErr, license)
	}
}

// TestConnectFirstEnableKeepsExistingLocalSources pins the source-state
// arm of the single-pull contract: on a first-enable connect that also
// authorizes a local tool (Codex), the existing source state is
// preserved — the codex grant is applied, its pending outbox batch
// drains through the initial collection — while the cursor upstream is
// still pulled exactly once, and the run completes.
func TestConnectFirstEnableKeepsExistingLocalSources(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startCursorBacklogMock(t)
	cfg := startSyncConfigMock(t, mock.URL, []string{"Cursor", "Codex"}, nil)
	ticket := strings.Repeat("6", 64)
	seedFirstEnableConnect(t, stateDir, mock, cfg, ticket)
	// A pending device batch attributed to the codex grant connect is
	// about to apply (existing source state that must keep flowing).
	seedDeviceBacklogBatch(t, stateDir, homeDir, "first-enable-dev-1", "first-enable-dev-key-1")

	pull := &cursorBacklogPull{events: cursorBacklogEvents()}
	res, err := runSyncConnectWithOptions(t, cfg, stateDir, homeDir, ticket, Options{
		Cursor: budgetCursorWiring(pull, 5),
		CursorConfirm: func(notice string, out io.Writer) (bool, error) {
			return true, nil
		},
	})
	if err != nil {
		t.Fatalf("a first-enable connect with a healthy local source must complete: %v (incomplete=%v)", err, res.Sync.Incomplete)
	}
	if len(res.Sync.Incomplete) != 0 {
		t.Fatalf("a fully drained first-enable connect is complete, got %v", res.Sync.Incomplete)
	}
	// Exactly one upstream pull (the enable's); the initial round's
	// cursor phase is drain-only and the codex source needs no cursor
	// pull.
	if len(pull.calls) != 1 {
		t.Fatalf("expected exactly the enable's pull, got %+v", pull.calls)
	}
	// The cursor batch and the pre-existing device batch both uploaded.
	if got := mock.srcBatchPosts(); got != 1 {
		t.Fatalf("expected exactly the enable's source batch, got %d", got)
	}
	if got := mock.deviceBatchPosts(); got != 1 {
		t.Fatalf("the pre-existing device batch must drain, got %d device posts", got)
	}
	// The codex grant is in place and nothing stays pending.
	gcfg, gErr := grants.New(stateDir).Load()
	if gErr != nil {
		t.Fatal(gErr)
	}
	if len(gcfg.Grants) != 1 || gcfg.Grants[0].Source != "codex-jsonl" {
		t.Fatalf("the codex grant must be applied, got %#v", gcfg.Grants)
	}
	if n := pendingCount(t, stateDir); n != 0 {
		t.Fatalf("nothing may stay pending, got %d", n)
	}
	if n := cursorPendingCountFor(t, stateDir); n != 0 {
		t.Fatalf("no cursor batch may stay pending, got %d", n)
	}
	// The drain-only cursor round executed (so the cursor-only arm of
	// the completion contract was judged on a real round).
	if !res.Sync.Collection.Cursor.Ran || res.Sync.Collection.Cursor.Skipped != "" {
		t.Fatalf("the initial round's drain-only cursor phase must run cleanly, got %+v", res.Sync.Collection.Cursor)
	}
}

// probingSchedulerRunner wraps the mock scheduler runner with a probe the
// test injects: the probe runs inside scheduler.Install — one of the last
// setup actions, still under connect's setup state lock — exactly where a
// scheduled periodic task would race to grab the lock in the old
// setup→initial gap.
type probingSchedulerRunner struct {
	mockRunner
	probe    func() error
	probeErr error
	calls    int
}

func (p *probingSchedulerRunner) Run(name string, args ...string) error {
	p.calls++
	p.probeErr = p.probe()
	return p.mockRunner.Run(name, args...)
}

// TestConnectSetupLockBlocksScheduledPeriodicFromInterleaving is the
// deterministic race regression for the setup→initial lock gap: while
// connect holds its setup lock, a scheduled periodic's attempt to run a
// full collection round against the same state directory (driven from
// inside the setup, at the scheduler install hook, and again observed
// from inside the initial round itself) must fail fast with
// runlock.ErrBusy and perform no work. The pending device batch — whose
// receipt partially rejects records — is therefore processed by
// CONNECT'S OWN initial collection round, and the partially rejected
// receipt surfaces as an honest run failure (collection.ErrRecordsRejected),
// never as connect success with the backlog silently mutated underneath.
func TestConnectSetupLockBlocksScheduledPeriodicFromInterleaving(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startCursorBacklogMock(t)
	mock.setPartialRejectDeviceBatch(true)
	cfg := startSyncConfigMock(t, mock.URL, []string{"Cursor", "Codex"}, nil)
	ticket := strings.Repeat("6", 64)
	seedFirstEnableConnect(t, stateDir, mock, cfg, ticket)
	// A reconnect over an existing active cursor permit: the initial
	// round runs the full cursor round, whose Pull lands inside the
	// collection lock — the in-round probe point.
	seedCursorBacklogPermit(t, stateDir, cursorsource.StatusActive)
	seedCodexSessionsGrant(t, stateDir, homeDir)
	// A pending device batch whose receipt will partially reject one of
	// its two records.
	seedDeviceBacklogBatchRecords(t, stateDir, homeDir, "race-pending-1", "race-pending-key-1", outbox.StatusPending, 2)

	scheduledBusy := false
	runner := &probingSchedulerRunner{
		probe: func() error {
			// The scheduled periodic's real entry point: a full
			// collection.Run on the same state directory.
			_, err := collection.Run(context.Background(), collection.Options{
				StateDir:   stateDir,
				ServerURL:  mock.URL,
				HTTPClient: cfg.Client(),
				HomeDir:    homeDir,
				Now:        func() time.Time { return cursorBacklogNow },
			})
			if errors.Is(err, runlock.ErrBusy) {
				scheduledBusy = true
			}
			return err
		},
	}
	pullProbeBusy := false
	pull := &cursorBacklogPull{}
	out := &bytes.Buffer{}
	res, err := Run(context.Background(), Options{
		URL:             fmt.Sprintf("%s/api/collector/connect#%s", cfg.URL, ticket),
		StateDir:        stateDir,
		HomeDir:         homeDir,
		BinaryPath:      fakeCollectorBinary(t),
		HTTPClient:      cfg.Client(),
		SchedulerRunner: runner,
		Now:             func() time.Time { return cursorBacklogNow },
		Out:             out,
		Cursor: &cursorsync.Options{
			Auth:   &cursorBacklogAuth{},
			Verify: (&cursorBacklogVerify{}).verify,
			Pull: func(ctx context.Context, sessionToken string, from, to time.Time) ([]api.UsageEvent, error) {
				// In-round probe: the cursor pull happens inside the
				// initial collection round, under the continuous lock —
				// a scheduled acquirer must observe ErrBusy here too.
				if _, aErr := runlock.Acquire(stateDir); errors.Is(aErr, runlock.ErrBusy) {
					pullProbeBusy = true
				}
				return pull.pull(ctx, sessionToken, from, to)
			},
			Now: func() time.Time { return cursorBacklogNow },
		},
	})

	// The scheduled periodic could not interleave: its setup-time attempt
	// failed fast with ErrBusy, and the lock was still held inside the
	// initial round (at the cursor pull).
	if runner.calls == 0 || runner.probeErr == nil || !errors.Is(runner.probeErr, runlock.ErrBusy) {
		t.Fatalf("the scheduled periodic must fail fast with ErrBusy inside the setup, calls=%d err=%v", runner.calls, runner.probeErr)
	}
	if !scheduledBusy {
		t.Fatalf("the scheduled collection.Run attempt must have observed ErrBusy")
	}
	if !pullProbeBusy {
		t.Fatalf("the state lock must still be held inside the initial collection round")
	}
	// The honest outcome: connect's OWN round drained the partially
	// rejected batch and the run failed with ErrRecordsRejected — never
	// success (which is what the old interleaving allowed: the scheduled
	// task settled the batch first and connect saw a clean queue).
	if err == nil {
		t.Fatalf("a partially rejected receipt surfaced by this run's own drain must fail connect, got success: %+v", res)
	}
	if !errors.Is(err, collection.ErrRecordsRejected) {
		t.Fatalf("the failure must be the records-rejected sentinel, got %v", err)
	}
	if !strings.Contains(err.Error(), "rejected 1 record") {
		t.Fatalf("the failure must name the rejected record count, got %v", err)
	}
	// Exactly one device POST ever happened (connect's own drain): the
	// scheduled attempt performed no work, and no cursor batch existed.
	if got := mock.deviceBatchPosts(); got != 1 {
		t.Fatalf("exactly connect's own device upload may happen, got %d", got)
	}
	if got := mock.srcBatchPosts(); got != 0 {
		t.Fatalf("no cursor batch may be uploaded in this scenario, got %d", got)
	}
}

// TestConnectSnapshotCapturedAfterRefreshBeforeOwnUploads pins the §6.3
// snapshot timing through the real connect flow: the initial collection
// round captures the synced-batch ids AFTER its authorization refresh and
// BEFORE its own uploads, so the history retransmission covers exactly
// the pre-run synced archive — this run's own upload is excluded as
// after-snapshot, never immediately replayed.
func TestConnectSnapshotCapturedAfterRefreshBeforeOwnUploads(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startCursorBacklogMock(t)
	cfg := startSyncConfigMock(t, mock.URL, []string{"Codex"}, nil)
	ticket := strings.Repeat("6", 64)
	seedFirstEnableConnect(t, stateDir, mock, cfg, ticket)
	seedCodexSessionsGrant(t, stateDir, homeDir)
	// One batch already synced before the run (the pre-run history) and
	// one pending (this run's initial collection will upload it).
	seedDeviceBacklogBatchStatus(t, stateDir, homeDir, "snap-pre-1", "snap-pre-key-1", outbox.StatusSynced)
	seedDeviceBacklogBatch(t, stateDir, homeDir, "snap-pending-1", "snap-pending-key-1")

	res, err := runSyncConnectWithOptions(t, cfg, stateDir, homeDir, ticket, Options{})
	if err != nil {
		t.Fatalf("the reconnect must complete: %v (incomplete=%v)", err, res.Sync.Incomplete)
	}
	// The §6.3 capture: the initial round froze exactly the pre-run
	// synced set — the round's grant sync (authorization refresh) had
	// already run, and its own upload of the pending batch came after.
	ids := res.Sync.Collection.SyncedBatchIDs
	if len(ids) != 1 || ids[0] != "snap-pre-1" {
		t.Fatalf("the captured snapshot must freeze exactly the pre-run synced batch, got %#v", ids)
	}
	// The history phase retransmitted the pre-run batch only; this run's
	// own upload was excluded as after-snapshot.
	if res.Sync.Resync.Uploads != 1 || res.Sync.Resync.Remaining != 0 || !res.Sync.Resync.Completed {
		t.Fatalf("the history phase must retransmit exactly the pre-run batch, got %+v", res.Sync.Resync)
	}
	if res.Sync.Resync.ExcludedAfterSnapshot != 1 {
		t.Fatalf("this run's own upload must be excluded from the immediate replay, got %+v", res.Sync.Resync)
	}
	// Both batches are drained/settled and nothing stays pending.
	if n := pendingCount(t, stateDir); n != 0 {
		t.Fatalf("nothing may stay pending, got %d", n)
	}
	if got := mock.deviceBatchPosts(); got != 2 {
		t.Fatalf("exactly the two batches (drain + retransmission) may POST, got %d", got)
	}
}

// TestSyncCursorQueueCapDoesNotBlockDeviceBacklog is the mirror of
// TestSyncDeviceQueueCapDoesNotBlockCursorBacklog: a per-queue cap on
// the ACCOUNT (cursor) queue must not starve the device queue. The
// backlog passes skip the cursor drain and keep draining device batches
// (the device queue empties through skip-cursor passes), the capped
// cursor batches stay pending with the cap named, and the history queue
// keeps posting under the same run (no run-wide total is configured).
func TestSyncCursorQueueCapDoesNotBlockDeviceBacklog(t *testing.T) {
	dir := t.TempDir()
	homeDir := t.TempDir()
	mock := startCursorBacklogMock(t)
	seedCursorBacklogState(t, dir, mock.URL)
	seedCursorBacklogPermit(t, dir, cursorsource.StatusActive)
	seedCodexSessionsGrant(t, dir, homeDir)
	// 12 device batches (more than the initial round's 5-batch bound, so
	// the device queue still holds work when the cursor cap declines
	// mid-pass) and 5 cursor batches against a cursor-queue cap of 2.
	for i := 1; i <= 12; i++ {
		seedDeviceBacklogBatch(t, dir, homeDir, fmt.Sprintf("curcap-dev-%d", i), fmt.Sprintf("curcap-dev-key-%d", i))
	}
	for i := 1; i <= 5; i++ {
		seedCursorBacklogBatch(t, dir, fmt.Sprintf("curcap-cur-%d", i), 1)
	}
	pull := &cursorBacklogPull{}
	budget := syncbudget.New(syncbudget.WithQueueCap("cursor", 2))

	res, err := Sync(context.Background(), SyncOptions{
		StateDir: dir, ServerURL: mock.URL, HomeDir: homeDir,
		Now:    func() time.Time { return cursorBacklogNow },
		Budget: budget,
		Cursor: budgetCursorWiring(pull, 2),
	})
	if err == nil || !isErrSyncIncomplete(err) {
		t.Fatalf("the capped cursor queue must leave the run incomplete, got %v", err)
	}
	if res.BudgetExhausted {
		t.Fatalf("a queue-only cap must not flag run-wide budget exhaustion, got %+v", res)
	}
	// The cursor queue posted exactly its cap (the initial round's
	// cursor round); the device queue drained fully through skip-cursor
	// backlog passes despite the cursor cap.
	if res.Collection.Cursor.SyncedBatches != 2 || res.Collection.Cursor.PendingRemaining != 3 {
		t.Fatalf("the cursor queue cap must bound the cursor drain, got %+v", res.Collection.Cursor)
	}
	if res.Backlog.PendingRemaining != 0 || res.Backlog.Result.SyncedBatches != 7 {
		t.Fatalf("the device queue must drain despite the cursor cap (7 batches through the skip-cursor passes), got pending=%d synced=%d", res.Backlog.PendingRemaining, res.Backlog.Result.SyncedBatches)
	}
	if res.Backlog.CursorPendingRemaining != 3 || !strings.Contains(res.Backlog.Stopped, "cursor queue") {
		t.Fatalf("the capped cursor batches must stay pending with the cap named, got %+v", res.Backlog)
	}
	if res.Backlog.Passes != 2 {
		t.Fatalf("the skip-cursor continuation must run exactly the two device passes, got %+v", res.Backlog)
	}
	// The history queue is uncapped and the run has no total: it still
	// covers its full-archive targets (the twelve batches the drains
	// synced, replayed over the shared device ingest endpoint).
	if !res.Resync.Completed || res.Resync.Uploads != 12 || mock.deviceBatchPosts() != 24 {
		t.Fatalf("the history queue must keep posting under a cursor-only cap, got %+v devicePosts=%d", res.Resync, mock.deviceBatchPosts())
	}
	if !containsReason(res.Incomplete, "3 cursor batch(es) are still pending") {
		t.Fatalf("the pending cursor batches must be named, got %v", res.Incomplete)
	}
}

// TestSyncUnbudgetedResyncKeepsHistoryBeforeBacklog pins the original
// phase order for the UNBUDGETED explicit resync drive (the CLI): the
// history retransmission runs BEFORE the backlog drain, so the executed
// retransmission covers exactly the archive the user confirmed plus
// what the INITIAL collection synced — the backlog's own uploads (up to
// the bounded passes) are never silently folded into the executed plan.
func TestSyncUnbudgetedResyncKeepsHistoryBeforeBacklog(t *testing.T) {
	dir := t.TempDir()
	homeDir := t.TempDir()
	mock := startCursorBacklogMock(t)
	seedCursorBacklogState(t, dir, mock.URL)
	seedCodexSessionsGrant(t, dir, homeDir)
	// Two batches already synced (the archive the confirmation plan
	// lists) and eight pending ones (five drain in the initial round,
	// three in the backlog pass afterwards).
	seedDeviceBacklogBatchStatus(t, dir, homeDir, "unb-pre-1", "unb-pre-key-1", outbox.StatusSynced)
	seedDeviceBacklogBatchStatus(t, dir, homeDir, "unb-pre-2", "unb-pre-key-2", outbox.StatusSynced)
	for i := 1; i <= 8; i++ {
		seedDeviceBacklogBatch(t, dir, homeDir, fmt.Sprintf("unb-dev-%d", i), fmt.Sprintf("unb-dev-key-%d", i))
	}

	confirmedPlan := -1
	res, err := Sync(context.Background(), SyncOptions{
		StateDir: dir, ServerURL: mock.URL, HomeDir: homeDir,
		Now: func() time.Time { return cursorBacklogNow },
		ResyncConfirm: func(plan resync.Plan) error {
			confirmedPlan = len(plan.Batches)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("the unbudgeted explicit resync must complete: %v (incomplete=%v)", err, res.Incomplete)
	}
	// The confirmation plan listed the already-synced archive only.
	if confirmedPlan != 2 {
		t.Fatalf("the confirmation plan must list exactly the pre-run synced archive, got %d batches", confirmedPlan)
	}
	// The executed retransmission covered the confirmed archive plus the
	// initial collection's own five uploads — NOT the backlog's three
	// (the regressed backlog-first order would fold them in: 10 uploads).
	if !res.Resync.Completed || res.Resync.Uploads != 7 {
		t.Fatalf("the executed retransmission must cover exactly the confirmed archive plus the initial round's uploads, got %+v", res.Resync)
	}
	// Phase order in the global POST log: every history replay precedes
	// the backlog pass's first drain of the remaining three batches.
	log := mock.postLogEntries()
	lastReplay, firstBacklogDrain := -1, -1
	for i, entry := range log {
		if entry == "device:unb-dev-5" {
			lastReplay = i // replayed by the history phase (its second appearance is the replay)
		}
		if entry == "device:unb-dev-6" && firstBacklogDrain == -1 {
			firstBacklogDrain = i // first drained only by the backlog pass
		}
	}
	// unb-dev-5 appears twice (initial drain, then history replay): find
	// its LAST occurrence.
	for i := len(log) - 1; i >= 0; i-- {
		if log[i] == "device:unb-dev-5" {
			lastReplay = i
			break
		}
	}
	if lastReplay == -1 || firstBacklogDrain == -1 || lastReplay > firstBacklogDrain {
		t.Fatalf("every history replay must precede the backlog drain, log=%v", log)
	}
	// Totals: initial drain 5 + history replay 7 + backlog drain 3.
	if got := mock.deviceBatchPosts(); got != 15 {
		t.Fatalf("exactly fifteen device POSTs may happen (5 drain + 7 replay + 3 backlog), got %d", got)
	}
	if n := pendingCount(t, dir); n != 0 {
		t.Fatalf("nothing may stay pending, got %d", n)
	}
}

// TestConnectBudgetExhaustedEnablePointsAtContinuation pins the honest
// guidance when the first-time enable already succeeded server-side (the
// permit is written and its first sync durably persisted the pull) but
// the first sync's upload was stopped by this run's shared POST budget:
// the setup must point at the continuation path (the next connect or the
// scheduled collection), NOT at `toktrail cursor enable` — an existing
// healthy permit is an idempotent no-op there and drains nothing.
func TestConnectBudgetExhaustedEnablePointsAtContinuation(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startCursorBacklogMock(t)
	cfg := startSyncConfigMock(t, mock.URL, []string{"Cursor"}, nil)
	ticket := strings.Repeat("6", 64)
	seedFirstEnableConnect(t, stateDir, mock, cfg, ticket)

	// 501 events exceed one source batch, so the enable's first sync
	// persists TWO batches; with a run-wide budget of exactly one POST
	// the first batch uploads and the second is declined — the enable
	// fails on the budget AFTER the permit was already enabled and
	// flipped active.
	pull := &cursorBacklogPull{events: cursorBulkEvents(501)}
	out := &bytes.Buffer{}
	res, err := Run(context.Background(), Options{
		URL:             fmt.Sprintf("%s/api/collector/connect#%s", cfg.URL, ticket),
		StateDir:        stateDir,
		HomeDir:         homeDir,
		BinaryPath:      fakeCollectorBinary(t),
		HTTPClient:      cfg.Client(),
		SchedulerRunner: &mockRunner{},
		Now:             func() time.Time { return cursorBacklogNow },
		Out:             out,
		MaxTotalBatches: 1,
		Cursor:          budgetCursorWiring(pull, 5),
		CursorConfirm: func(notice string, w io.Writer) (bool, error) {
			return true, nil
		},
	})
	if err == nil || !isErrSyncIncomplete(err) {
		t.Fatalf("a budget-exhausted first-enable connect must be incomplete, got %v", err)
	}
	if !res.Sync.BudgetExhausted {
		t.Fatalf("the budget exhaustion must be flagged, got %+v", res.Sync)
	}
	// The honest guidance: enabled + continuation path, never the
	// misleading re-enable pointer.
	outStr := out.String()
	if !strings.Contains(outStr, "enabled; the first sync stopped at this run's shared sync budget") {
		t.Fatalf("the budget-stopped enable must point at the continuation path, got:\n%s", outStr)
	}
	if strings.Contains(outStr, "not enabled; run `toktrail cursor enable`") {
		t.Fatalf("a budget-stopped enable must not claim the source was never enabled, got:\n%s", outStr)
	}
	// The permit is active (the pull durably persisted before the
	// decline), exactly one upstream pull ever happened, and the declined
	// batch stays queued for the next run.
	license, ok, lErr := cursorsource.New(stateDir).Load()
	if lErr != nil || !ok {
		t.Fatalf("expected a cursor permit after the budget-stopped enable, ok=%v err=%v", ok, lErr)
	}
	if license.Status != cursorsource.StatusActive {
		t.Fatalf("the permit must be active after the pull persisted, got %q", license.Status)
	}
	if len(pull.calls) != 1 {
		t.Fatalf("only the enable's first-sync pull may happen, got %+v", pull.calls)
	}
	if got := mock.srcBatchPosts(); got != 1 {
		t.Fatalf("exactly the enable's first batch may be uploaded, got %d", got)
	}
	if n := cursorPendingCountFor(t, stateDir); n != 1 {
		t.Fatalf("the declined cursor batch must stay pending, got %d", n)
	}
}

// TestSyncEmptyRetransmissionConfirmationAccountsPreflight pins the
// durable accounting of the empty/nothing-eligible consent-revision
// confirmation: the self GET runResyncPhase performs after an offline
// (empty snapshot) history phase records exactly one preflight attempt
// in the outbox's authorization-attempt ledger, like every other
// authenticated self GET (the grant sync and the sync preflight) —
// before the fix this round trip was the only unaccounted one.
func TestSyncEmptyRetransmissionConfirmationAccountsPreflight(t *testing.T) {
	dir := t.TempDir()
	mock := startCursorBacklogMock(t)
	seedCursorBacklogState(t, dir, mock.URL)

	res, err := Sync(context.Background(), SyncOptions{
		StateDir: dir, ServerURL: mock.URL,
		Now:            func() time.Time { return cursorBacklogNow },
		ResyncSnapshot: resync.NewSyncedBatchSnapshot(nil), // first-install shape: nothing to replay
	})
	if err != nil {
		t.Fatalf("an empty first-install sync must complete, got %v (incomplete=%v)", err, res.Incomplete)
	}
	// Exactly two authenticated self GETs — the grant sync and the
	// confirmation after the offline empty job — and exactly two ledger
	// records, one per GET.
	if got := mock.selfCalls(); got != 2 {
		t.Fatalf("expected the grant-sync self GET and the confirmation self GET, got %d", got)
	}
	attempts, aErr := outbox.New(dir).LoadPreflightAttempts()
	if aErr != nil {
		t.Fatal(aErr)
	}
	if attempts.Count != 2 {
		t.Fatalf("every authenticated self GET must record one preflight attempt, got %d", attempts.Count)
	}
	if res.Resync.Completed != true || res.Resync.ConsentRevision != 5 {
		t.Fatalf("the empty job must complete with the confirmed scope, got %+v", res.Resync)
	}
}

// TestSyncConfirmationPreflightAccountingFailureIsZeroHTTPAndRecoverable
// pins the fail-closed contract of that accounting: when the ledger
// write fails before the confirmation's self GET (the file is corrupted
// after the grant sync already recorded), the confirmation performs ZERO
// HTTP round trips, the run keeps its honest unconfirmed-revision
// incompleteness (never a hard failure and never success), and nothing
// is mutated — the next run re-attempts under a healthy ledger.
func TestSyncConfirmationPreflightAccountingFailureIsZeroHTTPAndRecoverable(t *testing.T) {
	dir := t.TempDir()
	mock := startCursorBacklogMock(t)
	seedCursorBacklogState(t, dir, mock.URL)

	// Corrupt the authorization-attempt ledger from inside the grant
	// sync's self GET handler (the first and, with the fix, only self
	// GET of this run): the single-goroutine HTTP round trip orders the
	// corruption before every later ledger use, and the grant sync's own
	// record has already happened.
	mock.setOnSelf(func(call int) {
		if call == 1 {
			if err := os.WriteFile(filepath.Join(dir, "preflight-attempts.json"), []byte("{not json"), 0o600); err != nil {
				t.Errorf("corrupt the preflight ledger: %v", err)
			}
		}
	})

	res, err := Sync(context.Background(), SyncOptions{
		StateDir: dir, ServerURL: mock.URL,
		Now:            func() time.Time { return cursorBacklogNow },
		ResyncSnapshot: resync.NewSyncedBatchSnapshot(nil), // empty first-install history
	})
	if err == nil || !isErrSyncIncomplete(err) {
		t.Fatalf("the skipped confirmation must surface as an honest incomplete, got %v", err)
	}
	if !containsReason(res.Incomplete, "could not confirm the live consent scope") {
		t.Fatalf("the unconfirmed scope must be named, got %v", res.Incomplete)
	}
	// ZERO HTTP for the confirmation: the grant sync's self GET is the
	// only one; the accounting failure gated the confirmation's GET.
	if got := mock.selfCalls(); got != 1 {
		t.Fatalf("the failed accounting must gate the confirmation's self GET, got %d self GETs", got)
	}
	// Recoverable: the offline empty job itself completed and left its
	// journal; only the confirmation was skipped for a later run.
	if !res.Resync.Completed || res.Resync.ConsentRevision != 0 {
		t.Fatalf("the empty job must complete offline with an unconfirmed revision, got %+v", res.Resync)
	}
	if !journalExists(dir) {
		t.Fatalf("the finished empty job must leave its journal for the next run")
	}
}
