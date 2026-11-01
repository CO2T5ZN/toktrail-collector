package resync

// Retry wiring coverage for the AUTOMATIC history retransmission pass
// (connect wires Options.Retry; the explicit `resync --all` CLI leaves it
// nil and keeps the single-shot semantics covered by the rest of this
// package's tests). Everything is synthetic: tempdir state, a scripted
// httptest remote, a fake-clock retry policy so nothing ever sleeps, and
// a shared budget whose reservations are asserted against the real POST
// count. The preflight-attempt accounting is asserted to match the self
// GETs the remote actually served — exactly one durable record per GET,
// retries included, with no double-record from the pass itself.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/syncbudget"
	"toktrail-collector/internal/syncclient"
	"toktrail-collector/internal/syncretry"
)

// retryFakeRemote is a scripted TokTrail remote for the retry wiring
// tests: a self endpoint with revision 1 (allowing Codex) whose Nth GET
// can flip to 401 or corrupt the pass's preflight accounting, and an
// ingest endpoint whose first POSTs come from a script (503/429 with an
// allowlisted transient code, Retry-After support) while every further
// POST is accepted. Raw POST bodies are captured so byte-identity across
// retries is assertable.
type retryFakeRemote struct {
	serverURL string
	mu        sync.Mutex
	selfCalls int
	posts     int
	bodies    [][]byte
	// script holds the scripted responses, in order; exhausted means
	// accept.
	script []retryFakeResponse
	// unauthorizedFromSelf makes every self GET at or beyond this 1-based
	// count answer 401 device_revoked (0=never).
	unauthorizedFromSelf int
	// corruptAccountingAfterSelf corrupts the pass's preflight accounting
	// file right after this 1-based self GET count was served (0=never),
	// so the NEXT durable accounting write fails.
	corruptAccountingAfterSelf int
	// stateDir is where the accounting file to corrupt lives.
	stateDir string
}

type retryFakeResponse struct {
	status     int
	retryAfter string
}

func (f *retryFakeRemote) handle(t *testing.T, w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/v1/devices/self" {
		f.selfCalls++
		if f.unauthorizedFromSelf > 0 && f.selfCalls >= f.unauthorizedFromSelf {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "device_revoked", "message": "synthetic revocation"}})
			return
		}
		if f.corruptAccountingAfterSelf > 0 && f.selfCalls == f.corruptAccountingAfterSelf {
			// Serve the healthy snapshot first, then break the durable
			// accounting so the next write (a retry hook or the
			// completion check) fails closed.
			defer func() {
				if err := os.WriteFile(filepath.Join(f.stateDir, "preflight-attempts.json"), []byte("not json"), 0o600); err != nil {
					t.Errorf("corrupt accounting: %v", err)
				}
			}()
		}
		v := 1
		_ = json.NewEncoder(w).Encode(map[string]any{"device": syncclient.SelfStatus{
			DeviceID: "device-resync", ConsentRevision: 1, UploadAuthorized: true,
			GrantProtocolVersion: &v, AllowedTools: []string{"Codex"},
		}})
		return
	}
	if r.URL.Path != "/v1/ingest/batches" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if got := r.Header.Get("X-Consent-Revision"); got != "1" {
		t.Errorf("ingest must echo the live consent revision, got %q", got)
	}
	f.posts++
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Errorf("read ingest body: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.bodies = append(f.bodies, append([]byte(nil), body...))
	var probe syncclient.BatchRequest
	_ = json.Unmarshal(body, &probe)
	if len(f.script) > 0 {
		resp := f.script[0]
		f.script = f.script[1:]
		if resp.retryAfter != "" {
			w.Header().Set("Retry-After", resp.retryAfter)
		}
		w.WriteHeader(resp.status)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "service_unavailable", "message": "synthetic transient failure"}})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"batch": syncclient.BatchReceipt{
		BatchID: probe.BatchID, Status: "accepted", AcceptedRecords: len(probe.Records),
		ReceivedAt: time.Now().UTC(),
	}})
}

func (f *retryFakeRemote) counts() (selfs, posts int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.selfCalls, f.posts
}

func (f *retryFakeRemote) postBodies() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]byte, len(f.bodies))
	copy(out, f.bodies)
	return out
}

func newRetryRemote(t *testing.T, stateDir string, script []retryFakeResponse) *retryFakeRemote {
	t.Helper()
	f := &retryFakeRemote{script: script, stateDir: stateDir}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.handle(t, w, r)
	}))
	t.Cleanup(s.Close)
	f.serverURL = s.URL
	return f
}

// retryPreflightCount reads the durable preflight-attempt accounting.
func retryPreflightCount(t *testing.T, stateDir string) int {
	t.Helper()
	attempts, err := outbox.New(stateDir).LoadPreflightAttempts()
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatal(err)
	}
	return attempts.Count
}

// frozenRetryClock is a minimal injectable syncretry clock: "now" is
// frozen and waits are no-ops (the tests use zero base delay), so no
// test ever sleeps. The frozen now also makes deadline comparisons
// deterministic: a Retry-After of 3600s is always past a now+30s deadline.
type frozenRetryClock struct{ now time.Time }

func (c frozenRetryClock) Now() time.Time                                  { return c.now }
func (c frozenRetryClock) Wait(ctx context.Context, d time.Duration) error { return ctx.Err() }

// retryPolicyFor builds the deterministic test policy: zero base delay
// (so no test sleeps), the given run deadline, and the frozen clock.
func retryPolicyFor(deadline time.Time) *syncretry.Policy {
	return syncretry.New(syncretry.WithClock(frozenRetryClock{now: time.Now()}), syncretry.WithBaseDelay(0), syncretry.WithRunDeadline(deadline))
}

// TestResyncAutomaticPassRetriesTransientFailureAndAccountsEverySelfGet
// pins the automatic pass's retry wiring end to end: one 503 then a
// replayed accept, byte-identical resends under the same batch ID, one
// budget reservation per real POST, exactly one durable preflight record
// per self GET (no double-record from the pass itself), a single journal
// upload receipt, and the original outbox entry left untouched.
func TestResyncAutomaticPassRetriesTransientFailureAndAccountsEverySelfGet(t *testing.T) {
	dir := fixture(t, "http://placeholder.invalid", []json.RawMessage{record("retry-key-1", "2026-10-01T10:00:00Z")})
	remote := newRetryRemote(t, dir, []retryFakeResponse{{status: http.StatusServiceUnavailable}})
	opt := options(dir)
	opt.ServerURL = remote.serverURL
	budget := syncbudget.New(syncbudget.WithTotal(5))
	opt.Budget = budget
	opt.Retry = retryPolicyFor(time.Now().Add(time.Minute))
	before := snapshot(t, dir)

	res, err := Run(t.Context(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Completed || res.Uploads != 1 || res.Remaining != 0 {
		t.Fatalf("expected the retried pass to complete with one upload, got completed=%t uploads=%d remaining=%d stopped=%q",
			res.Completed, res.Uploads, res.Remaining, res.Stopped)
	}
	selfs, posts := remote.counts()
	if posts != 2 || selfs != 4 {
		t.Fatalf("remote saw posts=%d selfs=%d, want 2 POSTs (503 then accept) and 4 self GETs (run preflight + 2 attempts + completion check)", posts, selfs)
	}
	bodies := remote.postBodies()
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("the retry must resend byte-identical payloads under the same batch ID")
	}
	if budget.Used() != 2 {
		t.Fatalf("budget used = %d, want one reservation per real POST (2)", budget.Used())
	}
	// The accounting must be exactly one record per self GET. With the
	// pass's own per-target record still in place it would be 5 — under
	// the retry policy the syncclient hook owns the target attempts.
	if got := retryPreflightCount(t, dir); got != selfs {
		t.Fatalf("preflight records = %d, want exactly one per self GET (%d)", got, selfs)
	}
	// The original synced outbox entry and batch file stay untouched.
	assertOriginals(t, dir, before)
	// The journal recorded exactly one upload receipt for the batch.
	jb, ok, err := loadJob(dir)
	if err != nil || !ok {
		t.Fatalf("job journal missing: %v", err)
	}
	if len(jb.Batches) != 1 || len(jb.Batches[0].Uploads) != 1 {
		t.Fatalf("expected exactly one journal upload receipt, got %#v", jb.Batches)
	}
	if jb.Batches[0].Outcome != outcomeDone {
		t.Fatalf("expected the batch done, got %q", jb.Batches[0].Outcome)
	}
}

// TestResyncAutomaticPassStopsWhenRetryAfterPassesDeadline pins the
// deadline stop: a server Retry-After whose floor would start the next
// attempt past the policy's run deadline is refused WITHOUT waiting, so
// exactly one POST happens and the job stays resumable.
func TestResyncAutomaticPassStopsWhenRetryAfterPassesDeadline(t *testing.T) {
	dir := fixture(t, "http://placeholder.invalid", []json.RawMessage{record("retry-key-2", "2026-10-01T10:00:00Z")})
	remote := newRetryRemote(t, dir, []retryFakeResponse{{status: http.StatusTooManyRequests, retryAfter: "3600"}})
	opt := options(dir)
	opt.ServerURL = remote.serverURL
	opt.Retry = retryPolicyFor(time.Now().Add(30 * time.Second))
	before := snapshot(t, dir)

	start := time.Now()
	_, err := Run(t.Context(), opt)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a Retry-After past the run deadline must stop the pass, not succeed")
	}
	if !errors.Is(err, syncretry.ErrRetryPastDeadline) {
		t.Fatalf("expected ErrRetryPastDeadline, got %v", err)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("the deadline check must fail fast instead of waiting out the Retry-After, took %s", elapsed)
	}
	_, posts := remote.counts()
	if posts != 1 {
		t.Fatalf("posts = %d, want exactly one: the retry must not start past the deadline", posts)
	}
	// Nothing was committed: the job stays resumable and the originals
	// are untouched.
	jb, ok, jErr := loadJob(dir)
	if jErr != nil || !ok {
		t.Fatalf("job journal missing: %v", jErr)
	}
	if jb.Batches[0].Outcome == outcomeDone {
		t.Fatal("the stopped batch must not be marked done")
	}
	if len(jb.Batches[0].Uploads) != 0 {
		t.Fatalf("no upload may be recorded for the stopped batch, got %#v", jb.Batches[0].Uploads)
	}
	assertOriginals(t, dir, before)
}

// TestResyncAutomaticPassBudgetDeclineStopsTheRetry pins the shared-budget
// contract under retry: the failed first POST's reservation is real and
// never refunded, so a budget with one unit declines the retry BEFORE its
// POST — the pass stops as a budget stop, the target is not marked
// failed, and the job stays resumable.
func TestResyncAutomaticPassBudgetDeclineStopsTheRetry(t *testing.T) {
	dir := fixture(t, "http://placeholder.invalid", []json.RawMessage{record("retry-key-3", "2026-10-01T10:00:00Z")})
	remote := newRetryRemote(t, dir, []retryFakeResponse{{status: http.StatusServiceUnavailable}})
	opt := options(dir)
	opt.ServerURL = remote.serverURL
	budget := syncbudget.New(syncbudget.WithTotal(1))
	opt.Budget = budget
	opt.Retry = retryPolicyFor(time.Now().Add(time.Minute))

	res, err := Run(t.Context(), opt)
	if err == nil {
		t.Fatal("the budget decline must surface, not succeed")
	}
	if !budgetDecline(err) {
		t.Fatalf("expected the shared-budget decline sentinel, got %v", err)
	}
	if res.Stopped != budgetStopped {
		t.Fatalf("stopped = %q, want the budget-stop marker %q", res.Stopped, budgetStopped)
	}
	_, posts := remote.counts()
	if posts != 1 {
		t.Fatalf("posts = %d, want exactly one: the retry was declined before its POST", posts)
	}
	if budget.Used() != 1 {
		t.Fatalf("budget used = %d, want the one real POST's reservation", budget.Used())
	}
	jb, ok, jErr := loadJob(dir)
	if jErr != nil || !ok {
		t.Fatalf("job journal missing: %v", jErr)
	}
	if jb.Batches[0].Outcome == outcomeFailed {
		t.Fatal("a budget-declined target must not be marked failed")
	}
	if len(jb.Batches[0].Uploads) != 0 {
		t.Fatalf("no upload may be recorded for the declined target, got %#v", jb.Batches[0].Uploads)
	}
}

// TestResyncAutomaticPassAuthorizationChangeStopsTheRetry pins the
// authorization stop: when the live self view turns unauthorized between
// the first attempt and the retry's preflight, the retry stops for good —
// exactly one POST, nothing committed, the job resumable.
func TestResyncAutomaticPassAuthorizationChangeStopsTheRetry(t *testing.T) {
	dir := fixture(t, "http://placeholder.invalid", []json.RawMessage{record("retry-key-4", "2026-10-01T10:00:00Z")})
	remote := newRetryRemote(t, dir, []retryFakeResponse{{status: http.StatusServiceUnavailable}})
	// Self GET #1 is the pass's run-level preflight (authorized); self
	// GET #2 is the target's first attempt (authorized, then the 503);
	// self GET #3 is the RETRY's preflight — unauthorized from there on.
	remote.unauthorizedFromSelf = 3
	opt := options(dir)
	opt.ServerURL = remote.serverURL
	opt.Retry = retryPolicyFor(time.Now().Add(time.Minute))

	res, err := Run(t.Context(), opt)
	if err == nil {
		t.Fatal("the authorization change must stop the pass, not succeed")
	}
	if !errors.Is(err, syncclient.ErrDeviceUnauthorized) && !errors.Is(err, syncclient.ErrDeviceRevoked) {
		t.Fatalf("expected the authorization stop to surface, got %v", err)
	}
	if res.Completed {
		t.Fatal("the pass must not report completion")
	}
	selfs, posts := remote.counts()
	if posts != 1 || selfs != 3 {
		t.Fatalf("remote saw posts=%d selfs=%d, want 1 POST and 3 self GETs (the retry's preflight refused)", posts, selfs)
	}
	jb, ok, jErr := loadJob(dir)
	if jErr != nil || !ok {
		t.Fatalf("job journal missing: %v", jErr)
	}
	if len(jb.Batches[0].Uploads) != 0 {
		t.Fatalf("no upload may be recorded, got %#v", jb.Batches[0].Uploads)
	}
}

// TestResyncAutomaticPassPreflightAccountingFailureKeepsJobResumable pins
// the fail-closed accounting contract mid-pass: when the durable
// preflight accounting write fails before a target's self GET, zero HTTP
// traffic happens for it, the target is NOT marked failed, and the job
// stays resumable.
func TestResyncAutomaticPassPreflightAccountingFailureKeepsJobResumable(t *testing.T) {
	dir := fixture(t, "http://placeholder.invalid", []json.RawMessage{record("retry-key-5", "2026-10-01T10:00:00Z")})
	remote := newRetryRemote(t, dir, nil)
	// Self GET #1 is the run-level preflight; corrupt the accounting file
	// right after serving it so the target's first hook write fails.
	remote.corruptAccountingAfterSelf = 1
	opt := options(dir)
	opt.ServerURL = remote.serverURL
	opt.Retry = retryPolicyFor(time.Now().Add(time.Minute))

	res, err := Run(t.Context(), opt)
	if err == nil {
		t.Fatal("the accounting failure must stop the pass, not succeed")
	}
	if !errors.Is(err, syncclient.ErrPreflightAccounting) {
		t.Fatalf("expected ErrPreflightAccounting to surface, got %v", err)
	}
	if res.Stopped != "preflight accounting failed" {
		t.Fatalf("stopped = %q, want the preflight-accounting marker", res.Stopped)
	}
	_, posts := remote.counts()
	if posts != 0 {
		t.Fatalf("posts = %d, want zero: the accounting failure must gate every send", posts)
	}
	jb, ok, jErr := loadJob(dir)
	if jErr != nil || !ok {
		t.Fatalf("job journal missing: %v", jErr)
	}
	if jb.Batches[0].Outcome == outcomeFailed {
		t.Fatal("an accounting stop must not mark the target failed — the job stays resumable")
	}
	if len(jb.Batches[0].Uploads) != 0 {
		t.Fatalf("no upload may be recorded, got %#v", jb.Batches[0].Uploads)
	}
}

// TestResyncSingleShotWithoutRetryPolicyKeepsOneAttempt pins that the
// pass without a policy (the explicit CLI semantics) stays single-shot
// even for an allowlisted transient 503.
func TestResyncSingleShotWithoutRetryPolicyKeepsOneAttempt(t *testing.T) {
	dir := fixture(t, "http://placeholder.invalid", []json.RawMessage{record("retry-key-6", "2026-10-01T10:00:00Z")})
	remote := newRetryRemote(t, dir, []retryFakeResponse{{status: http.StatusServiceUnavailable}})
	opt := options(dir)
	opt.ServerURL = remote.serverURL

	_, err := Run(t.Context(), opt)
	if err == nil {
		t.Fatal("the single 503 must surface, not succeed")
	}
	_, posts := remote.counts()
	if posts != 1 {
		t.Fatalf("posts = %d, want exactly one without a retry policy", posts)
	}
}
