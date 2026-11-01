// Synthetic test doubles for the cursorsync orchestration tests.
//
// Nothing here touches a real Cursor desktop state, a real credential or
// the network beyond a local httptest server speaking the TokTrail wire
// protocol: the auth provider hands out synthetic tokens, Verify maps
// them onto synthetic accounts, Pull serves windowed synthetic events,
// and the fake TokTrail server answers /v1/devices/self,
// /v1/account-sources/enable, /v1/ingest/source-batches and
// /v1/capabilities.
package cursorsync_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/cursor/api"
	"toktrail-collector/internal/cursor/auth"
	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/local/statedir"
	synccmd "toktrail-collector/internal/syncclient"
)

// baseTime is the frozen round clock used by every test.
var baseTime = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

// Synthetic account identities (user_ + >= 8 alphanumerics, per the api
// account id policy). Tokens map onto them through fakeVerify only.
const (
	accountA = "user_testaccounta"
	accountB = "user_testaccountb"
)

const (
	testDeviceID     = "dev_test0001"
	testDeviceSecret = "sec_test0001"
	testApplication  = "app_test0001"
	testSubject      = "subject-1"
)

func i64(v int64) *int64 { return &v }

// writeTestJSON writes v as a JSON response with the given status.
func writeTestJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ev builds one synthetic collapsed usage event.
func ev(id string, ts time.Time, in, cacheRead, cacheWrite, out int64) api.UsageEvent {
	return api.UsageEvent{
		UsageEventID:     id,
		TimestampMS:      ts.UnixMilli(),
		Model:            "claude-sonnet-4-5",
		InputTokens:      i64(in),
		CacheReadTokens:  i64(cacheRead),
		CacheWriteTokens: i64(cacheWrite),
		OutputTokens:     i64(out),
	}
}

// ---------------------------------------------------------------------------
// fake TokTrail server (httptest)
// ---------------------------------------------------------------------------

// fakeTokTrail is a local TokTrail control-plane double. Knobs are
// guarded by a mutex so tests can flip them between rounds.
type fakeTokTrail struct {
	t   *testing.T
	srv *httptest.Server
	mu  sync.Mutex

	deviceID        string
	consentRevision int64
	paused          bool
	allowedTools    []string
	historyFrom     *time.Time
	uploadUntil     *time.Time

	// source is the server's account source for this device; nil means
	// the server currently lists none (never enabled, or deleted).
	source *protocol.Source
	// enableSource, when set, is what the enable call answers instead of
	// source — the self view keeps serving source — so a test can model
	// a malicious enable response in isolation.
	enableSource *protocol.Source
	instanceSeq  int
	capsEnabled  bool
	ingestFails  bool
	ingestStatus int    // 0 = accept; non-0 = answer this HTTP status
	ingestCode   string // non-empty = answer HTTP 409 with this stable error code
	// rejectIndex/rejectCode model a partial_error receipt: the record at
	// rejectIndex comes back rejected with the given (whitelisted) code.
	rejectIndex int
	rejectCode  string

	// ingestScript scripts the first len(ingestScript) ingest answers
	// (the retry tests): each entry may delay the answer (modeling a
	// slow server the client times out on), answer with an HTTP status
	// carrying a codeless, coded or raw non-JSON body, set a Retry-After
	// header, or durably store the batch and then answer 2xx with the
	// receipt cut off mid-stream (truncated2xx). Calls beyond the script
	// answer normally, and a scripted status of 0 also accepts normally
	// (after the delay).
	ingestScript []scriptedIngest
	// storedReceipts models the server's durable idempotency by batch
	// id: once a receipt is stored, a re-send of the same id answers the
	// stored receipt with replay=true (the duplicate contract) and is
	// never counted again.
	storedReceipts map[string]int
	// replayAnswers counts receipt answers served with replay=true.
	replayAnswers int
	// ingestHook, when set, runs at the start of every ingest handling
	// (outside the fake's lock), so a test can flip the server's state
	// deterministically between the first POST and the retry preflight.
	ingestHook func()
	// selfHook, when set, runs at the start of every self handling
	// (outside the fake's lock, after the call counter advances), so a
	// test can act on a specific self view — e.g. cancel the run context
	// exactly when the retry preflight re-fetches it.
	selfHook func()
	// selfFailAfter makes /v1/devices/self fail with HTTP 500 once the
	// call count exceeds it (0 = never): the round-start self succeeds
	// while the retry preflight's re-fetch fails.
	selfFailAfter int

	selfCalls   int
	enableCalls int
	ingestCalls int
	capsCalls   int
	ingested    []protocol.Batch
	// ingestBodies records the raw body of every ingest POST, successful
	// or not, so tests can prove retries re-sent the exact same bytes.
	ingestBodies [][]byte
}

// scriptedIngest is one scripted ingest answer (see ingestScript).
type scriptedIngest struct {
	delay      time.Duration // real-time delay before answering
	status     int           // 0 = accept normally
	code       string        // business code; "" = codeless error body
	rawBody    string        // non-empty = raw non-JSON body instead of the JSON error envelope
	retryAfter string        // Retry-After header value
	// truncated2xx durably stores the batch (and its receipt) in the
	// server's idempotency map, then answers 2xx with a receipt-shaped
	// JSON body cut off mid-stream: the upload is stored but the receipt
	// was lost in transit, so only a re-send of the same id and bytes
	// can prove it — which the server then answers with replay=true.
	truncated2xx bool
}

func newFakeTokTrail(t *testing.T, deviceID string) *fakeTokTrail {
	f := &fakeTokTrail{t: t, deviceID: deviceID, consentRevision: 5, capsEnabled: true}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/devices/self", f.handleSelf)
	mux.HandleFunc("/v1/account-sources/enable", f.handleEnable)
	mux.HandleFunc("/v1/ingest/source-batches", f.handleIngest)
	mux.HandleFunc("/v1/capabilities", f.handleCaps)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeTokTrail) url() string { return f.srv.URL }

func (f *fakeTokTrail) handleSelf(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.selfCalls++
	hook := f.selfHook
	fail := f.selfFailAfter > 0 && f.selfCalls > f.selfFailAfter
	snap := synccmd.SelfStatus{
		DeviceID:         f.deviceID,
		ConsentRevision:  f.consentRevision,
		UploadAuthorized: true,
		Paused:           f.paused,
		AllowedTools:     append([]string(nil), f.allowedTools...),
		HistoryFrom:      f.historyFrom,
		UploadUntil:      f.uploadUntil,
	}
	if f.source != nil {
		snap.AccountSources = []protocol.Source{*f.source}
	}
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	if fail {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Device *synccmd.SelfStatus `json:"device"`
	}{&snap})
}

func (f *fakeTokTrail) handleEnable(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.enableCalls++
	if f.enableSource != nil {
		// A test-poisoned enable answer: the self view keeps serving
		// f.source, so a malicious enable response can be modeled in
		// isolation (a reflected credential, for example).
		src := *f.enableSource
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Source *protocol.Source `json:"source"`
		}{&src})
		return
	}
	if f.source == nil {
		f.instanceSeq++
		f.source = &protocol.Source{
			SourceInstanceID: fmt.Sprintf("src_inst_%d", f.instanceSeq),
			SourceType:       protocol.SourceType,
			State:            "active",
			FenceVersion:     1,
			NextRevision:     1,
		}
	}
	src := *f.source
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Source *protocol.Source `json:"source"`
	}{&src})
}

func (f *fakeTokTrail) handleIngest(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}
	var batch protocol.Batch
	if err := json.Unmarshal(body, &batch); err != nil {
		http.Error(w, "bad batch", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.ingestCalls++
	f.ingestBodies = append(f.ingestBodies, append([]byte(nil), body...))
	fails := f.ingestFails
	status := f.ingestStatus
	errCode := f.ingestCode
	rejIndex, rejCode := f.rejectIndex, f.rejectCode
	hook := f.ingestHook
	var script scriptedIngest
	scripted := false
	if len(f.ingestScript) > 0 {
		script = f.ingestScript[0]
		f.ingestScript = f.ingestScript[1:]
		scripted = true
	}
	// Server-side idempotency: a re-send of an already-stored batch id
	// is a duplicate — it answers the stored receipt with replay=true
	// and is never counted twice. A fresh success (including the
	// truncated2xx mode, which stores before losing the receipt) stores
	// the id and counts the batch exactly once.
	duplicate := false
	if _, ok := f.storedReceipts[batch.BatchID]; ok {
		duplicate = true
	}
	storeNew := !fails && status == 0 && errCode == "" && rejCode == "" &&
		(!scripted || script.status == 0 || script.truncated2xx)
	if storeNew && !duplicate {
		if f.storedReceipts == nil {
			f.storedReceipts = map[string]int{}
		}
		f.storedReceipts[batch.BatchID] = len(batch.Records)
		f.ingested = append(f.ingested, batch)
	}
	f.mu.Unlock()
	if hook != nil {
		// Outside the lock: the hook flips server knobs (fence, consent,
		// scope, ...) deterministically between the first POST and the
		// retry preflight.
		hook()
	}
	if scripted {
		if script.delay > 0 {
			time.Sleep(script.delay)
		}
		if script.truncated2xx {
			// Stored durably above; the receipt itself never arrives
			// intact.
			code := script.status
			if code == 0 {
				code = http.StatusAccepted
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"batch": {"batchId": "` + batch.BatchID))
			return
		}
		if script.status == 0 {
			f.answerReceipt(w, batch, duplicate)
			return
		}
		if script.retryAfter != "" {
			w.Header().Set("Retry-After", script.retryAfter)
		}
		if script.rawBody != "" {
			w.WriteHeader(script.status)
			_, _ = w.Write([]byte(script.rawBody))
			return
		}
		writeTestJSON(w, script.status, map[string]any{
			"error": map[string]string{"code": script.code, "message": "synthetic scripted failure"},
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if fails || status != 0 {
		if status == 0 {
			status = http.StatusServiceUnavailable
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]string{"code": "unavailable", "message": "synthetic offline"},
		})
		return
	}
	if errCode != "" {
		// A stable control-plane error code (mapped onto the drain's
		// terminal-stop sentinels by the sourcebatch client).
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]string{"code": errCode, "message": "synthetic stop"},
		})
		return
	}
	if rejCode != "" {
		// A partial_error receipt: everything but rejectIndex is
		// accepted, the rejected record carries the whitelisted code.
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"batch": map[string]any{
				"batchId":         batch.BatchID,
				"status":          "partial_error",
				"acceptedRecords": len(batch.Records) - 1,
				"rejectedRecords": 1,
				"replay":          false,
				"receivedAt":      time.Now().UTC().Format(time.RFC3339Nano),
				"recordErrors":    []map[string]any{{"index": rejIndex, "code": rejCode}},
			},
		})
		return
	}
	f.answerReceipt(w, batch, duplicate)
}

// answerReceipt writes the accepted receipt for batch; a duplicate (a
// re-send of an id the server already stored durably) is answered with
// replay=true, mirroring the server's idempotent duplicate contract.
func (f *fakeTokTrail) answerReceipt(w http.ResponseWriter, batch protocol.Batch, replay bool) {
	if replay {
		f.mu.Lock()
		f.replayAnswers++
		f.mu.Unlock()
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"batch": map[string]any{
			"batchId":         batch.BatchID,
			"status":          "accepted",
			"acceptedRecords": len(batch.Records),
			"rejectedRecords": 0,
			"replay":          replay,
			"receivedAt":      time.Now().UTC().Format(time.RFC3339Nano),
		},
	})
}

func (f *fakeTokTrail) handleCaps(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.capsCalls++
	enabled := f.capsEnabled
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if !enabled {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]string{"code": "not_found", "message": "no such endpoint"},
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"features": []string{"device-grants", "account-sources"},
	})
}

// setSource replaces the server's view of this device's account source.
func (f *fakeTokTrail) setSource(s protocol.Source) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.source = &s
}

// setEnableSource poisons only the enable call's answer (the self view
// keeps serving the regular source).
func (f *fakeTokTrail) setEnableSource(s protocol.Source) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enableSource = &s
}

// dropSource removes the source server-side (deletion / reassignment
// elsewhere); the next enable call creates a fresh instance.
func (f *fakeTokTrail) dropSource() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.source = nil
}

func (f *fakeTokTrail) setHistory(from, until *time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.historyFrom, f.uploadUntil = from, until
}

func (f *fakeTokTrail) setAllowedTools(tools []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allowedTools = tools
}

func (f *fakeTokTrail) setIngestFails(fails bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ingestFails = fails
}

// setIngestStatus answers every ingest with the given HTTP status (0
// restores acceptance).
func (f *fakeTokTrail) setIngestStatus(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ingestStatus = status
}

// setIngestCode answers every ingest with HTTP 409 carrying the stable
// error code (empty restores acceptance).
func (f *fakeTokTrail) setIngestCode(code string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ingestCode = code
}

// setIngestPartialRejection answers every ingest with a partial_error
// receipt rejecting the record at index with the whitelisted code.
func (f *fakeTokTrail) setIngestPartialRejection(index int, code string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rejectIndex, f.rejectCode = index, code
}

func (f *fakeTokTrail) setCapsEnabled(enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.capsEnabled = enabled
}

// setIngestScript scripts the first len(script) ingest answers.
func (f *fakeTokTrail) setIngestScript(script ...scriptedIngest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ingestScript = append([]scriptedIngest(nil), script...)
}

// setIngestHook runs hook at the start of every ingest handling.
func (f *fakeTokTrail) setIngestHook(hook func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ingestHook = hook
}

// setSelfFailAfter fails /v1/devices/self with HTTP 500 once the call
// count exceeds n (0 = never fail).
func (f *fakeTokTrail) setSelfFailAfter(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.selfFailAfter = n
}

// setSelfHook runs hook at the start of every self handling, after the
// call counter has advanced (so a test can act on the Nth view).
func (f *fakeTokTrail) setSelfHook(hook func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.selfHook = hook
}

// setConsentRevision advances the server's device consent revision.
func (f *fakeTokTrail) setConsentRevision(v int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.consentRevision = v
}

// setPaused flips the device's server-side paused flag.
func (f *fakeTokTrail) setPaused(paused bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paused = paused
}

// ingestBodyLog snapshots the raw body of every ingest POST so far.
func (f *fakeTokTrail) ingestBodyLog() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]byte, len(f.ingestBodies))
	copy(out, f.ingestBodies)
	return out
}

// stats snapshots the call counters and ingested batches.
func (f *fakeTokTrail) stats() (self, enable, ingest, caps int, batches []protocol.Batch) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.selfCalls, f.enableCalls, f.ingestCalls, f.capsCalls, append([]protocol.Batch(nil), f.ingested...)
}

// replayAnswerCount reports how many receipt answers carried
// replay=true (re-sends of batch ids the server had already stored).
func (f *fakeTokTrail) replayAnswerCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.replayAnswers
}

// ---------------------------------------------------------------------------
// fake Cursor auth / verify / pull / confirm
// ---------------------------------------------------------------------------

// fakeAuth hands out a switchable synthetic desktop credential and
// records read order into the shared event log.
type fakeAuth struct {
	mu      sync.Mutex
	token   string
	err     error
	fetches int
	order   *[]string
}

func (a *fakeAuth) Fetch(ctx context.Context) (auth.Credential, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fetches++
	if a.order != nil {
		*a.order = append(*a.order, "auth")
	}
	if a.err != nil {
		return auth.Credential{}, a.err
	}
	return auth.Credential{AccessToken: a.token, Source: "fake-test"}, nil
}

func (a *fakeAuth) setToken(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.token = token
}

func (a *fakeAuth) fetchCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.fetches
}

// fakeVerify maps synthetic tokens onto synthetic accounts.
type fakeVerify struct {
	mu    sync.Mutex
	calls []string
}

func (v *fakeVerify) verify(ctx context.Context, token string) (api.VerifyResult, error) {
	v.mu.Lock()
	v.calls = append(v.calls, token)
	v.mu.Unlock()
	switch token {
	case "tok-A":
		return api.VerifyResult{AccountID: accountA, SessionToken: "sess-A"}, nil
	case "tok-B":
		return api.VerifyResult{AccountID: accountB, SessionToken: "sess-B"}, nil
	}
	return api.VerifyResult{}, fmt.Errorf("unknown synthetic token: %w", api.ErrSessionExpired)
}

func (v *fakeVerify) callCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.calls)
}

// pullCall records one synthetic pull request.
type pullCall struct {
	sessionToken string
	from, to     time.Time
}

// fakePull serves the configured events filtered to the requested
// window, like the real dashboard API would. With unfiltered set it
// ignores the window entirely, modeling a divergent upstream that
// answers rows outside the range it was asked for.
type fakePull struct {
	mu         sync.Mutex
	events     []api.UsageEvent
	calls      []pullCall
	unfiltered bool
}

func (p *fakePull) pull(ctx context.Context, sessionToken string, from, to time.Time) ([]api.UsageEvent, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, pullCall{sessionToken: sessionToken, from: from, to: to})
	out := make([]api.UsageEvent, 0, len(p.events))
	for _, e := range p.events {
		if p.unfiltered {
			out = append(out, e)
			continue
		}
		if !from.IsZero() && e.TimestampMS < from.UnixMilli() {
			continue
		}
		if e.TimestampMS >= to.UnixMilli() {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (p *fakePull) setUnfiltered(v bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.unfiltered = v
}

func (p *fakePull) setEvents(events ...api.UsageEvent) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append([]api.UsageEvent(nil), events...)
}

func (p *fakePull) callLog() []pullCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]pullCall(nil), p.calls...)
}

// fakeConfirm answers the local confirmation prompt and records order.
type fakeConfirm struct {
	mu         sync.Mutex
	calls      int
	answer     bool
	err        error
	order      *[]string
	lastNotice string
}

func (c *fakeConfirm) confirm(notice string, out io.Writer) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	c.lastNotice = notice
	if c.order != nil {
		*c.order = append(*c.order, "confirm")
	}
	if c.err != nil {
		return false, c.err
	}
	return c.answer, nil
}

func (c *fakeConfirm) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (c *fakeConfirm) notice() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastNotice
}

// fakeClock is a settable Now for Options that also implements
// syncretry.Clock for the retry policy: Wait records the requested wait
// and advances the clock by it instead of sleeping, so retry tests run
// deterministically on fake time.
type fakeClock struct {
	mu    sync.Mutex
	t     time.Time
	waits []time.Duration
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// Wait implements syncretry.Clock: it never sleeps — it records the wait
// and advances the fake time — while still honoring a done context, so
// external cancellation stays observable.
func (c *fakeClock) Wait(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.waits = append(c.waits, d)
	if d > 0 {
		c.t = c.t.Add(d)
	}
	return nil
}

// waitLog snapshots the waits performed so far.
func (c *fakeClock) waitLog() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.waits...)
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

// harness wires one state directory, one fake TokTrail server and the
// fake Cursor-side collaborators together.
type harness struct {
	srv    *fakeTokTrail
	dir    string
	auth   *fakeAuth
	verify *fakeVerify
	pull   *fakePull
	clock  *fakeClock
}

func newHarness(t *testing.T) *harness {
	dir := t.TempDir()
	srv := newFakeTokTrail(t, testDeviceID)
	st := statedir.DeviceState{
		ServerURL:         srv.url(),
		ApplicationID:     testApplication,
		ExternalSubjectID: testSubject,
		DeviceID:          testDeviceID,
		DeviceSecret:      testDeviceSecret,
	}
	if err := statedir.New(dir).Save(st); err != nil {
		t.Fatalf("write device state: %v", err)
	}
	return &harness{
		srv:    srv,
		dir:    dir,
		auth:   &fakeAuth{token: "tok-A"},
		verify: &fakeVerify{},
		pull:   &fakePull{},
		clock:  &fakeClock{t: baseTime},
	}
}

func (h *harness) options() cursorsync.Options {
	return cursorsync.Options{
		StateDir:  h.dir,
		ServerURL: h.srv.url(),
		Auth:      h.auth,
		Verify:    h.verify.verify,
		Pull:      h.pull.pull,
		Now:       h.clock.Now,
	}
}

// defaultSource is the server source matching a license written with
// sourceInstanceID "src_inst_1".
func defaultSource() protocol.Source {
	return protocol.Source{
		SourceInstanceID: "src_inst_1",
		SourceType:       protocol.SourceType,
		State:            "active",
		FenceVersion:     1,
		NextRevision:     1,
	}
}
