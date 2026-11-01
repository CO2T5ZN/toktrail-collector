package syncclient

// Retry tests for the P1 device ingest send. Everything here is synthetic:
// an httptest server (or a flaky RoundTripper) scripts the failures, a fake
// clock records waits instead of sleeping, and the injected jitter is a
// plain function. No test touches real state, credentials, or commits.

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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncbudget"
	"toktrail-collector/internal/syncretry"
)

// fakeRetryClock is the injected syncretry clock: waits are recorded and
// advance a fake "now" instead of sleeping, and the wait behavior can be
// overridden to simulate cancellation races.
type fakeRetryClock struct {
	mu    sync.Mutex
	now   time.Time
	waits []time.Duration
	wait  func(ctx context.Context, d time.Duration) error
}

func newFakeRetryClock(start time.Time) *fakeRetryClock {
	return &fakeRetryClock{now: start}
}

func (c *fakeRetryClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeRetryClock) Wait(ctx context.Context, d time.Duration) error {
	c.mu.Lock()
	c.waits = append(c.waits, d)
	override := c.wait
	if override == nil {
		c.now = c.now.Add(d)
	}
	c.mu.Unlock()
	if override != nil {
		return override(ctx, d)
	}
	return ctx.Err()
}

func (c *fakeRetryClock) recordedWaits() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.waits...)
}

// ingestRecorder counts self preflights and ingest POSTs and captures the
// raw body of every POST so tests can assert the batch ID and byte
// immutability across retries.
type ingestRecorder struct {
	gets   atomic.Int32
	posts  atomic.Int32
	mu     sync.Mutex
	bodies [][]byte
}

func (r *ingestRecorder) recordPost(body []byte) {
	r.mu.Lock()
	r.bodies = append(r.bodies, append([]byte(nil), body...))
	r.mu.Unlock()
}

func (r *ingestRecorder) postBodies() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]byte, len(r.bodies))
	for i, b := range r.bodies {
		out[i] = append([]byte(nil), b...)
	}
	return out
}

// setupPendingRetryBatch wires a bound device plus one pending outbox batch
// (with its cursor advance) that the retry tests send.
func setupPendingRetryBatch(t *testing.T, batchID string) (string, statedir.Store, string) {
	t.Helper()
	stateDir, store, _ := setupBoundState(t)
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": batchID,
		"records": []map[string]any{{
			"recordKey":      "record-1",
			"kind":           "delta",
			"occurredAt":     "2026-10-20T10:00:00Z",
			"tool":           "usage-json",
			"input":          "10",
			"cacheRead":      "0",
			"cacheWrite":     "0",
			"output":         "5",
			"adapterVersion": "test-adapter-1",
			"sourceType":     "fixture",
		}},
	})
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{BatchID: batchID, File: batchFile, Source: "usage-json", Input: batchFile, RecordCount: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := progress.New(stateDir).Advance(progress.AdvanceOptions{Source: "usage-json", Input: batchFile, BatchID: batchID, RecordCount: 1}); err != nil {
		t.Fatal(err)
	}
	return stateDir, store, batchFile
}

// acceptedReceipt is the standard single-record acceptance the scripted
// server writes once its script is exhausted.
func acceptedReceipt(batchID string) map[string]any {
	return map[string]any{"batch": map[string]any{
		"batchId":         batchID,
		"status":          "accepted",
		"acceptedRecords": 1,
		"rejectedRecords": 0,
		"replay":          false,
		"receivedAt":      "2026-10-20T10:12:00Z",
	}}
}

// scriptedIngestServer serves the device self preflight (via serveSelf at
// revision 7) and answers ingest POSTs from a script of raw response
// writers; once the script is exhausted every further POST is accepted.
func scriptedIngestServer(t *testing.T, script []func(w http.ResponseWriter)) (*httptest.Server, *ingestRecorder) {
	t.Helper()
	rec := &ingestRecorder{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelf(t, w, r, 7) {
			rec.gets.Add(1)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read ingest body: %v", err)
		}
		rec.recordPost(body)
		n := int(rec.posts.Add(1))
		if n <= len(script) {
			script[n-1](w)
			return
		}
		var got BatchRequest
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("invalid ingest body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusAccepted, acceptedReceipt(got.BatchID))
	}))
	return server, rec
}

// failWith writes a decodable-but-failing ingest response, optionally with
// a Retry-After header.
func failWith(status int, retryAfter string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		writeJSON(w, status, map[string]any{})
	}
}

// failRaw writes an undecodable ingest response body (an HTML error page,
// say) with the given status.
func failRaw(status int, body string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

// assertBatchPending verifies the batch is still pending and no ACK journal
// was left behind.
func assertBatchPending(t *testing.T, stateDir, batchID string) {
	t.Helper()
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for i := range out.Batches {
		if out.Batches[i].BatchID == batchID {
			found = true
			if out.Batches[i].Status != outbox.StatusPending {
				t.Fatalf("batch %s must stay pending, got %#v", batchID, out.Batches[i])
			}
		}
	}
	if !found {
		t.Fatalf("batch %s is missing from outbox", batchID)
	}
	if _, statErr := os.Stat(syncACKJournalPath(stateDir)); !os.IsNotExist(statErr) {
		t.Fatalf("expected no ACK journal left behind, stat err=%v", statErr)
	}
}

func TestRunSyncWithoutRetryPolicySendsOnce(t *testing.T) {
	stateDir, store, _ := setupPendingRetryBatch(t, "batch-noretry-1")
	server, rec := scriptedIngestServer(t, []func(w http.ResponseWriter){
		failWith(http.StatusServiceUnavailable, ""),
	})
	defer server.Close()

	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err == nil || !strings.Contains(err.Error(), "status 503") {
		t.Fatalf("expected the single 503 failure to surface untouched, got %v", err)
	}
	if got := rec.posts.Load(); got != 1 {
		t.Fatalf("posts = %d, want exactly one without a retry policy", got)
	}
	if got := rec.gets.Load(); got != 1 {
		t.Fatalf("self preflights = %d, want 1", got)
	}
	assertBatchPending(t, stateDir, "batch-noretry-1")
}

func TestRunSyncRetryResendsIdenticalBytesAfterResponseBodyLost(t *testing.T) {
	const batchID = "batch-lostbody-1"
	stateDir, store, _ := setupPendingRetryBatch(t, batchID)
	truncated := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		// A receipt that dies mid-JSON: the status said success, but the
		// body never finishes arriving.
		_, _ = io.WriteString(w, `{"batch":{"batchId":"`+batchID+`","status":"accep`)
	}
	server, rec := scriptedIngestServer(t, []func(w http.ResponseWriter){truncated})
	defer server.Close()

	budget := syncbudget.New(syncbudget.WithTotal(2))
	clock := newFakeRetryClock(time.Now())
	policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(0))
	res, err := Run(t.Context(), store, Options{
		ServerURL:   server.URL,
		StateDir:    stateDir,
		Budget:      budget,
		BudgetQueue: "device",
		Retry:       policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := rec.posts.Load(); got != 2 {
		t.Fatalf("posts = %d, want 2 (initial send plus one retry)", got)
	}
	if got := rec.gets.Load(); got != 2 {
		t.Fatalf("self preflights = %d, want 2 (every retry re-runs the full preflight)", got)
	}
	if got := budget.Used(); got != 2 {
		t.Fatalf("budget used = %d, want one reservation per actual POST", got)
	}
	bodies := rec.postBodies()
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("the retry must resend byte-identical payloads under the same batch ID")
	}
	var first, second BatchRequest
	if err := json.Unmarshal(bodies[0], &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bodies[1], &second); err != nil {
		t.Fatal(err)
	}
	if first.BatchID != batchID || second.BatchID != batchID {
		t.Fatalf("batch IDs drifted across attempts: %q then %q", first.BatchID, second.BatchID)
	}
	if res.Receipt.BatchID != batchID || res.Receipt.Status != "accepted" || res.Status != http.StatusAccepted {
		t.Fatalf("unexpected result: %#v", res)
	}
	// Exactly one ACK: the truncated first attempt never reached the ACK
	// path (no receipt was ever seen to validate), so the outbox is synced
	// once and the cursor confirmed once.
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Batches) != 1 || out.Batches[0].Status != outbox.StatusSynced || out.Batches[0].ReceiptStatus != "accepted" {
		t.Fatalf("expected the batch synced exactly once: %#v", out.Batches)
	}
	cursors, err := progress.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cursors.Cursors) != 1 || cursors.Cursors[0].ConfirmedBatchID != batchID || cursors.Cursors[0].ConfirmedAt == nil {
		t.Fatalf("expected the cursor confirmed exactly once: %#v", cursors)
	}
	if _, statErr := os.Stat(syncACKJournalPath(stateDir)); !os.IsNotExist(statErr) {
		t.Fatalf("expected no ACK journal left behind, stat err=%v", statErr)
	}
}

func TestRunSyncRetryTreatsExplicit5xxAsRetryable(t *testing.T) {
	cases := []struct {
		name   string
		status int
		raw    string
	}{
		{"503 with json body", http.StatusServiceUnavailable, ""},
		{"503 with undecodable body", http.StatusServiceUnavailable, "<html>gateway timeout</html>"},
		{"502 with json body", http.StatusBadGateway, ""},
		{"500 with json body", http.StatusInternalServerError, ""},
		{"504 with json body", http.StatusGatewayTimeout, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stateDir, store, _ := setupPendingRetryBatch(t, "batch-5xx-1")
			script := []func(w http.ResponseWriter){
				func(w http.ResponseWriter) {
					if tc.raw != "" {
						failRaw(tc.status, tc.raw)(w)
						return
					}
					failWith(tc.status, "")(w)
				},
			}
			server, rec := scriptedIngestServer(t, script)
			defer server.Close()

			clock := newFakeRetryClock(time.Now())
			policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(0))
			if _, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, Retry: policy}); err != nil {
				t.Fatal(err)
			}
			if got := rec.posts.Load(); got != 2 {
				t.Fatalf("posts = %d, want 2 (retried after HTTP %d)", got, tc.status)
			}
			if got := rec.gets.Load(); got != 2 {
				t.Fatalf("self preflights = %d, want 2", got)
			}
		})
	}
}

func TestRunSyncRetryDoesNotRetryFinalStatuses(t *testing.T) {
	for _, status := range []int{
		http.StatusUnauthorized,            // 401: authorization, never retried
		http.StatusForbidden,               // 403: authorization, never retried
		http.StatusConflict,                // 409: conflict, never retried
		http.StatusUnprocessableEntity,     // 422: validation, never retried
		http.StatusNotImplemented,          // 501: 5xx but not conventionally transient
		http.StatusHTTPVersionNotSupported, // 505: same
	} {
		t.Run(fmt.Sprintf("status %d", status), func(t *testing.T) {
			stateDir, store, _ := setupPendingRetryBatch(t, "batch-final-1")
			server, rec := scriptedIngestServer(t, []func(w http.ResponseWriter){
				failWith(status, ""),
			})
			defer server.Close()

			clock := newFakeRetryClock(time.Now())
			policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(0))
			_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, Retry: policy})
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("status %d", status)) {
				t.Fatalf("expected the final HTTP %d failure to surface, got %v", status, err)
			}
			if got := rec.posts.Load(); got != 1 {
				t.Fatalf("posts = %d, want 1: HTTP %d must never be retried", got, status)
			}
			if waits := clock.recordedWaits(); len(waits) != 0 {
				t.Fatalf("no wait may precede a final failure, waited %v", waits)
			}
			assertBatchPending(t, stateDir, "batch-final-1")
		})
	}
}

func TestRunSyncRetryHonors429RetryAfterFloor(t *testing.T) {
	const batchID = "batch-429-1"

	t.Run("valid delay-seconds floor is never sent early", func(t *testing.T) {
		stateDir, store, _ := setupPendingRetryBatch(t, batchID)
		server, rec := scriptedIngestServer(t, []func(w http.ResponseWriter){
			failWith(http.StatusTooManyRequests, "30"),
		})
		defer server.Close()

		start := time.Now()
		clock := newFakeRetryClock(start)
		// Zero base delay: the only wait may come from the server floor.
		policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(0))
		if _, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, Retry: policy}); err != nil {
			t.Fatal(err)
		}
		if got := rec.posts.Load(); got != 2 {
			t.Fatalf("posts = %d, want 2", got)
		}
		if waits := clock.recordedWaits(); len(waits) != 1 || waits[0] != 30*time.Second {
			t.Fatalf("waits = %v, want exactly one 30s server floor", waits)
		}
		if got := clock.Now(); !got.Equal(start.Add(30 * time.Second)) {
			t.Fatalf("clock advanced to %s, want %s: the resend must happen only after the floor elapsed", got, start.Add(30*time.Second))
		}
	})

	t.Run("malformed header is ignored in favor of the backoff", func(t *testing.T) {
		stateDir, store, _ := setupPendingRetryBatch(t, batchID)
		server, rec := scriptedIngestServer(t, []func(w http.ResponseWriter){
			failWith(http.StatusTooManyRequests, "soon-ish"),
		})
		defer server.Close()

		clock := newFakeRetryClock(time.Now())
		policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(time.Second))
		if _, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, Retry: policy}); err != nil {
			t.Fatal(err)
		}
		if got := rec.posts.Load(); got != 2 {
			t.Fatalf("posts = %d, want 2", got)
		}
		if waits := clock.recordedWaits(); len(waits) != 1 || waits[0] != time.Second {
			t.Fatalf("waits = %v, want the plain 1s backoff for an unparseable header", waits)
		}
	})
}

func TestRunSyncRetryReservesBudgetForEachPost(t *testing.T) {
	const batchID = "batch-budget-1"

	t.Run("one reservation per actual post", func(t *testing.T) {
		stateDir, store, _ := setupPendingRetryBatch(t, batchID)
		server, rec := scriptedIngestServer(t, []func(w http.ResponseWriter){
			failWith(http.StatusServiceUnavailable, ""),
			failWith(http.StatusServiceUnavailable, ""),
		})
		defer server.Close()

		budget := syncbudget.New(syncbudget.WithTotal(3))
		clock := newFakeRetryClock(time.Now())
		policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(0))
		if _, err := Run(t.Context(), store, Options{
			ServerURL: server.URL, StateDir: stateDir,
			Budget: budget, BudgetQueue: "device", Retry: policy,
		}); err != nil {
			t.Fatal(err)
		}
		if got := rec.posts.Load(); got != 3 {
			t.Fatalf("posts = %d, want 3", got)
		}
		if got := budget.Used(); got != 3 {
			t.Fatalf("budget used = %d, want 3 (one reservation per actual POST)", got)
		}
	})

	t.Run("decline stops the run after a fresh preflight", func(t *testing.T) {
		stateDir, store, _ := setupPendingRetryBatch(t, batchID)
		server, rec := scriptedIngestServer(t, []func(w http.ResponseWriter){
			failWith(http.StatusServiceUnavailable, ""),
		})
		defer server.Close()

		budget := syncbudget.New(syncbudget.WithTotal(1))
		clock := newFakeRetryClock(time.Now())
		policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(0))
		_, err := Run(t.Context(), store, Options{
			ServerURL: server.URL, StateDir: stateDir,
			Budget: budget, BudgetQueue: "device", Retry: policy,
		})
		if !errors.Is(err, syncbudget.ErrTotalExhausted) {
			t.Fatalf("error = %v, want syncbudget.ErrTotalExhausted", err)
		}
		if got := rec.posts.Load(); got != 1 {
			t.Fatalf("posts = %d, want 1: the declined retry must not POST", got)
		}
		// The retry still performed its full re-authorization before the
		// budget declined the reservation.
		if got := rec.gets.Load(); got != 2 {
			t.Fatalf("self preflights = %d, want 2 (fresh preflight before the reservation)", got)
		}
		assertBatchPending(t, stateDir, batchID)
	})
}

// postFlakyTransport fails the first N ingest POSTs with a transport error
// — before any byte reaches the server — and passes everything else
// (including every self preflight GET) through.
type postFlakyTransport struct {
	mu        sync.Mutex
	failPosts int
	err       error
	inner     http.RoundTripper
}

func (f *postFlakyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/v1/ingest/batches") {
		f.mu.Lock()
		n := f.failPosts
		if n > 0 {
			f.failPosts--
		}
		err := f.err
		f.mu.Unlock()
		if n > 0 {
			return nil, err
		}
	}
	return f.inner.RoundTrip(req)
}

// cancellingTransport cancels the run context in the middle of the first
// ingest POST, so client.Do fails with the context error while the run
// context is genuinely gone.
type cancellingTransport struct {
	once   sync.Once
	cancel context.CancelFunc
	inner  http.RoundTripper
}

func (f *cancellingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/v1/ingest/batches") {
		f.once.Do(f.cancel)
		if err := req.Context().Err(); err != nil {
			return nil, err
		}
	}
	return f.inner.RoundTrip(req)
}

func TestRunSyncRetryTransportFailures(t *testing.T) {
	const batchID = "batch-transport-1"

	t.Run("connection failure is retried", func(t *testing.T) {
		stateDir, store, _ := setupPendingRetryBatch(t, batchID)
		server, rec := scriptedIngestServer(t, nil)
		defer server.Close()

		budget := syncbudget.New(syncbudget.WithTotal(2))
		clock := newFakeRetryClock(time.Now())
		policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(0))
		transport := &postFlakyTransport{
			failPosts: 1,
			err:       errors.New("connection reset by peer"),
			inner:     http.DefaultTransport,
		}
		res, err := Run(t.Context(), store, Options{
			ServerURL: server.URL, StateDir: stateDir,
			HTTPClient: &http.Client{Transport: transport},
			Budget:     budget, BudgetQueue: "device", Retry: policy,
		})
		if err != nil {
			t.Fatal(err)
		}
		// The first POST died on the wire; only the retry reached the server.
		if got := rec.posts.Load(); got != 1 {
			t.Fatalf("server saw %d POSTs, want 1 (the failed attempt never arrived)", got)
		}
		if got := rec.gets.Load(); got != 2 {
			t.Fatalf("self preflights = %d, want 2", got)
		}
		// The failed attempt still spent its reservation before sending.
		if got := budget.Used(); got != 2 {
			t.Fatalf("budget used = %d, want 2 (both send attempts reserved)", got)
		}
		if res.Receipt.BatchID != batchID {
			t.Fatalf("unexpected receipt: %#v", res.Receipt)
		}
	})

	t.Run("client request timeout with a live run context is retried", func(t *testing.T) {
		stateDir, store, _ := setupPendingRetryBatch(t, batchID)
		server, rec := scriptedIngestServer(t, nil)
		defer server.Close()

		clock := newFakeRetryClock(time.Now())
		policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(0))
		// A timeout error that — exactly like real http.Client timeouts —
		// matches errors.Is(err, context.DeadlineExceeded) while the run
		// context itself is still alive. The parent context's own state is
		// the discriminator, and this case must stay retryable.
		transport := &postFlakyTransport{
			failPosts: 1,
			err:       fmt.Errorf("post %q: %w", server.URL+"/v1/ingest/batches", context.DeadlineExceeded),
			inner:     http.DefaultTransport,
		}
		if _, err := Run(t.Context(), store, Options{
			ServerURL: server.URL, StateDir: stateDir,
			HTTPClient: &http.Client{Transport: transport},
			Retry:      policy,
		}); err != nil {
			t.Fatal(err)
		}
		if got := rec.posts.Load(); got != 1 {
			t.Fatalf("server saw %d POSTs, want 1", got)
		}
		if got := rec.gets.Load(); got != 2 {
			t.Fatalf("self preflights = %d, want 2", got)
		}
	})

	t.Run("canceled run context is never retried", func(t *testing.T) {
		stateDir, store, _ := setupPendingRetryBatch(t, batchID)
		server, rec := scriptedIngestServer(t, nil)
		defer server.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		clock := newFakeRetryClock(time.Now())
		policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(0))
		transport := &cancellingTransport{cancel: cancel, inner: http.DefaultTransport}
		_, err := Run(ctx, store, Options{
			ServerURL: server.URL, StateDir: stateDir,
			HTTPClient: &http.Client{Transport: transport},
			Retry:      policy,
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
		if got := rec.posts.Load(); got != 0 {
			t.Fatalf("server saw %d POSTs, want 0", got)
		}
		if got := rec.gets.Load(); got != 1 {
			t.Fatalf("self preflights = %d, want 1 (only the first attempt started)", got)
		}
		if waits := clock.recordedWaits(); len(waits) != 0 {
			t.Fatalf("a canceled run must not wait or retry, waited %v", waits)
		}
		assertBatchPending(t, stateDir, batchID)
	})
}

func TestRunSyncRetryContextCanceledWhileWaiting(t *testing.T) {
	const batchID = "batch-cancelwait-1"
	stateDir, store, _ := setupPendingRetryBatch(t, batchID)
	server, rec := scriptedIngestServer(t, []func(w http.ResponseWriter){
		failWith(http.StatusServiceUnavailable, ""),
	})
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock := newFakeRetryClock(time.Now())
	clock.wait = func(ctx context.Context, d time.Duration) error {
		cancel() // the run is canceled while backing off
		return ctx.Err()
	}
	policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(time.Second))
	_, err := Run(ctx, store, Options{ServerURL: server.URL, StateDir: stateDir, Retry: policy})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if got := rec.posts.Load(); got != 1 {
		t.Fatalf("posts = %d, want 1: no attempt may start after cancellation", got)
	}
	assertBatchPending(t, stateDir, batchID)
}

func TestRunSyncRetryStopsWhenScopeNarrowsBeforeResend(t *testing.T) {
	const batchID = "batch-narrowed-1"
	stateDir, store, _ := setupPendingRetryBatch(t, batchID)
	rec := &ingestRecorder{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			// The first preflight allows the batch's tool; the retry's
			// fresh preflight does not — the consent scope narrowed.
			if rec.gets.Add(1) == 1 {
				serveSelfGrantProtocol(w, r, 7, []string{"usage-json"}, nil)
			} else {
				serveSelfGrantProtocol(w, r, 8, []string{"codex-cli"}, nil)
			}
			return
		}
		body, _ := io.ReadAll(r.Body)
		rec.recordPost(body)
		if rec.posts.Add(1) == 1 {
			failWith(http.StatusServiceUnavailable, "")(w)
			return
		}
		t.Error("the retry must not resend after the scope narrowed")
		writeJSON(w, http.StatusAccepted, acceptedReceipt(batchID))
	}))
	defer server.Close()

	clock := newFakeRetryClock(time.Now())
	policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(0))
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, Retry: policy})
	if err == nil || !strings.Contains(err.Error(), "was not resent") {
		t.Fatalf("expected the scope-narrowed retry to stop without resending, got %v", err)
	}
	if got := rec.posts.Load(); got != 1 {
		t.Fatalf("posts = %d, want 1 (nothing resent)", got)
	}
	if got := rec.gets.Load(); got != 2 {
		t.Fatalf("self preflights = %d, want 2 (the retry re-authorized first)", got)
	}
	assertBatchPending(t, stateDir, batchID)
	// Nothing was quarantined or reorganized mid-run: the next run owns the
	// reorganization under whatever the server then reports.
	qEntries, qErr := quarantine.New(stateDir).Load()
	if qErr != nil || len(qEntries) != 0 {
		t.Fatalf("expected an empty quarantine store, err=%v entries=%#v", qErr, qEntries)
	}
	if _, statErr := os.Stat(reorgJournalPath(stateDir)); !os.IsNotExist(statErr) {
		t.Fatalf("expected no reorg journal, stat err=%v", statErr)
	}
}

func TestRunSyncRetryAfterPastContextDeadlineFailsFast(t *testing.T) {
	const batchID = "batch-deadline-1"
	stateDir, store, _ := setupPendingRetryBatch(t, batchID)
	server, rec := scriptedIngestServer(t, []func(w http.ResponseWriter){
		failWith(http.StatusTooManyRequests, "30"),
	})
	defer server.Close()

	// A real context deadline 5s out; the fake clock is frozen at the same
	// instant, so honoring the 30s floor would start the retry 25s past
	// the run's own deadline.
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clock := newFakeRetryClock(start)
	policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(0))
	_, err := Run(ctx, store, Options{ServerURL: server.URL, StateDir: stateDir, Retry: policy})
	if !errors.Is(err, syncretry.ErrRetryPastDeadline) {
		t.Fatalf("error = %v, want syncretry.ErrRetryPastDeadline", err)
	}
	if got := rec.posts.Load(); got != 1 {
		t.Fatalf("posts = %d, want 1: the floor must never be sent early", got)
	}
	if waits := clock.recordedWaits(); len(waits) != 0 {
		t.Fatalf("must fail fast without waiting, waited %v", waits)
	}
	assertBatchPending(t, stateDir, batchID)
}

func TestRunSyncRetryJitterAppliesToBackoffNotFloor(t *testing.T) {
	const batchID = "batch-jitter-1"

	t.Run("plain 503 backoff is jittered", func(t *testing.T) {
		stateDir, store, _ := setupPendingRetryBatch(t, batchID)
		server, rec := scriptedIngestServer(t, []func(w http.ResponseWriter){
			failWith(http.StatusServiceUnavailable, ""),
		})
		defer server.Close()

		var jitterInputs []time.Duration
		clock := newFakeRetryClock(time.Now())
		policy := syncretry.New(
			syncretry.WithClock(clock),
			syncretry.WithBaseDelay(4*time.Second),
			syncretry.WithJitter(func(d time.Duration) time.Duration {
				jitterInputs = append(jitterInputs, d)
				return d / 2
			}),
		)
		if _, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, Retry: policy}); err != nil {
			t.Fatal(err)
		}
		if got := rec.posts.Load(); got != 2 {
			t.Fatalf("posts = %d, want 2", got)
		}
		if len(jitterInputs) != 1 || jitterInputs[0] != 4*time.Second {
			t.Fatalf("jitter inputs = %v, want the raw 4s backoff", jitterInputs)
		}
		if waits := clock.recordedWaits(); len(waits) != 1 || waits[0] != 2*time.Second {
			t.Fatalf("waits = %v, want the jittered 2s", waits)
		}
	})

	t.Run("a server floor is never shortened by jitter", func(t *testing.T) {
		stateDir, store, _ := setupPendingRetryBatch(t, batchID)
		server, rec := scriptedIngestServer(t, []func(w http.ResponseWriter){
			failWith(http.StatusTooManyRequests, "30"),
		})
		defer server.Close()

		clock := newFakeRetryClock(time.Now())
		policy := syncretry.New(
			syncretry.WithClock(clock),
			syncretry.WithBaseDelay(4*time.Second),
			syncretry.WithJitter(func(d time.Duration) time.Duration { return d / 2 }),
		)
		if _, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, Retry: policy}); err != nil {
			t.Fatal(err)
		}
		if got := rec.posts.Load(); got != 2 {
			t.Fatalf("posts = %d, want 2", got)
		}
		if waits := clock.recordedWaits(); len(waits) != 1 || waits[0] != 30*time.Second {
			t.Fatalf("waits = %v, want the 30s floor (jitter never applies on top of it)", waits)
		}
	})
}

func TestRunSyncRetryFreshPreflightUnauthorizedStopsRetrying(t *testing.T) {
	const batchID = "batch-reauth-1"
	stateDir, store, _ := setupPendingRetryBatch(t, batchID)
	rec := &ingestRecorder{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			if rec.gets.Add(1) == 1 {
				if !serveSelf(t, w, r, 7) {
					t.Error("serveSelf did not handle the self preflight")
				}
				return
			}
			// The retry's fresh preflight is rejected: re-authorization
			// failed, so the retry loop must stop rather than resend.
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]any{
				"code":    "device_unauthorized",
				"message": "credentials rejected",
			}})
			return
		}
		rec.posts.Add(1)
		failWith(http.StatusServiceUnavailable, "")(w)
	}))
	defer server.Close()

	clock := newFakeRetryClock(time.Now())
	policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(0))
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, Retry: policy})
	if !errors.Is(err, ErrDeviceUnauthorized) {
		t.Fatalf("error = %v, want ErrDeviceUnauthorized", err)
	}
	if got := rec.posts.Load(); got != 1 {
		t.Fatalf("posts = %d, want 1: the failed re-authorization must stop the retry", got)
	}
	if got := rec.gets.Load(); got != 2 {
		t.Fatalf("self preflights = %d, want 2", got)
	}
	assertBatchPending(t, stateDir, batchID)
}

func TestRunSyncRetryEchoesFreshConsentRevision(t *testing.T) {
	const batchID = "batch-revision-1"
	stateDir, store, _ := setupPendingRetryBatch(t, batchID)
	rec := &ingestRecorder{}
	var revMu sync.Mutex
	var revisions []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			revision := int64(7)
			if rec.gets.Add(1) > 1 {
				// The consent revision moved (widened) between the first
				// attempt and the retry.
				revision = 9
			}
			writeJSON(w, http.StatusOK, map[string]any{"device": map[string]any{
				"deviceId":         "dev-1",
				"consentRevision":  revision,
				"uploadAuthorized": true,
				"revoked":          false,
			}})
			return
		}
		body, _ := io.ReadAll(r.Body)
		rec.recordPost(body)
		revMu.Lock()
		revisions = append(revisions, r.Header.Get("X-Consent-Revision"))
		revMu.Unlock()
		if rec.posts.Add(1) == 1 {
			failWith(http.StatusServiceUnavailable, "")(w)
			return
		}
		writeJSON(w, http.StatusAccepted, acceptedReceipt(batchID))
	}))
	defer server.Close()

	clock := newFakeRetryClock(time.Now())
	policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(0))
	if _, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, Retry: policy}); err != nil {
		t.Fatal(err)
	}
	revMu.Lock()
	defer revMu.Unlock()
	if len(revisions) != 2 || revisions[0] != "7" || revisions[1] != "9" {
		t.Fatalf("X-Consent-Revision per attempt = %v, want [7 9]: every attempt echoes its own fresh preflight", revisions)
	}
}
