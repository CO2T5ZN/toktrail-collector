package collection

// Retry wiring coverage for the periodic entry's device outbox drain:
// collection.Options.Retry must reach every synccmd.Run of the drain (and
// the quarantine-recovery round's authorization check), one retry loop
// per POST with the shared budget reserved per real POST. Everything is
// synthetic: tempdir state, a scripted httptest server, a fake-clock
// policy so nothing sleeps.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/syncbudget"
	"toktrail-collector/internal/syncretry"
)

// retryFlakeServer answers the device self preflight at revision 7 and
// fails the FIRST ingest POST with a retryable 503 (allowlisted transient
// code, decodable body) before accepting everything, capturing every raw
// POST body.
type retryFlakeServer struct {
	*httptest.Server
	gets   atomic.Int64
	posts  atomic.Int64
	mu     sync.Mutex
	bodies [][]byte
}

func newRetryFlakeServer(t *testing.T) *retryFlakeServer {
	t.Helper()
	s := &retryFlakeServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelfRaw(w, r) {
			s.gets.Add(1)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/ingest/batches" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read ingest body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.bodies = append(s.bodies, append([]byte(nil), body...))
		n := len(s.bodies)
		s.mu.Unlock()
		s.posts.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "service_unavailable", "message": "synthetic transient failure"}})
			return
		}
		var batch struct {
			BatchID string `json:"batchId"`
			Records []struct {
				RecordKey string `json:"recordKey"`
			} `json:"records"`
		}
		_ = json.Unmarshal(body, &batch)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"batch": map[string]any{
			"batchId":         batch.BatchID,
			"status":          "accepted",
			"acceptedRecords": len(batch.Records),
			"rejectedRecords": 0,
			"replay":          n > 1,
			"receivedAt":      "2026-10-21T04:01:00Z",
			"recordErrors":    []map[string]any{},
		}})
	}))
	t.Cleanup(s.Close)
	return s
}

// serveSelfRaw answers the device self preflight without a *testing.T.
func serveSelfRaw(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet || r.URL.Path != "/v1/devices/self" {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"device": map[string]any{
		"deviceId":          "dev-1",
		"applicationId":     "app-1",
		"externalSubjectId": "sub-1",
		"deviceName":        "collector",
		"platform":          "darwin",
		"consentRevision":   7,
		"uploadAuthorized":  true,
		"publicAuthorized":  false,
		"revoked":           false,
		"checkedAt":         "2026-10-21T04:00:00Z",
	}})
	return true
}

func (s *retryFlakeServer) postBodies() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, len(s.bodies))
	copy(out, s.bodies)
	return out
}

// frozenRetryClock keeps "now" frozen and turns waits into no-ops, so no
// test sleeps and deadline comparisons stay deterministic.
type frozenRetryClock struct{ now time.Time }

func (c frozenRetryClock) Now() time.Time                                  { return c.now }
func (c frozenRetryClock) Wait(ctx context.Context, d time.Duration) error { return ctx.Err() }

// TestRunRetryPolicyWiredIntoDeviceDrain drives one pending device batch
// through collection.Run with Options.Retry set and a flaky server: the
// drain's synccmd.Run must retry the 503, resend byte-identical payloads
// under the same batch ID, reserve the shared budget once per real POST,
// and ACK exactly once (the outbox entry synced, no journal left).
func TestRunRetryPolicyWiredIntoDeviceDrain(t *testing.T) {
	stateDir := t.TempDir()
	server := newRetryFlakeServer(t)
	bindDevice(t, stateDir, server.URL)
	writePendingBatch(t, stateDir, "batch-collection-retry-1")

	budget := syncbudget.New(syncbudget.WithTotal(5))
	clock := frozenRetryClock{now: time.Now()}
	policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(0))
	res, err := Run(t.Context(), Options{
		StateDir:  stateDir,
		ServerURL: server.URL,
		Budget:    budget,
		Retry:     policy,
		FairDrain: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := server.posts.Load(); got != 2 {
		t.Fatalf("posts = %d, want 2 (503 then accepted)", got)
	}
	bodies := server.postBodies()
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("the retry must resend byte-identical payloads under the same batch ID")
	}
	var sent struct {
		BatchID string `json:"batchId"`
	}
	if err := json.Unmarshal(bodies[0], &sent); err != nil {
		t.Fatal(err)
	}
	if sent.BatchID != "batch-collection-retry-1" {
		t.Fatalf("batch ID drifted across attempts: %q", sent.BatchID)
	}
	if budget.Used() != 2 {
		t.Fatalf("budget used = %d, want one reservation per real POST (2)", budget.Used())
	}
	if res.SyncedBatches != 1 || res.PendingRemaining != 0 {
		t.Fatalf("expected the batch synced exactly once, got synced=%d pending=%d", res.SyncedBatches, res.PendingRemaining)
	}
	// Single ACK: the outbox is synced once and no ACK journal remains.
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Batches) != 1 || out.Batches[0].Status != outbox.StatusSynced || out.Batches[0].ReceiptStatus != "accepted" {
		t.Fatalf("expected the batch synced exactly once: %#v", out.Batches)
	}
}

// TestDrainPendingRetryPolicyWired covers the drain-only entry (the
// periodic --drain-only shape): the same wiring applies.
func TestDrainPendingRetryPolicyWired(t *testing.T) {
	stateDir := t.TempDir()
	server := newRetryFlakeServer(t)
	bindDevice(t, stateDir, server.URL)
	writePendingBatch(t, stateDir, "batch-drain-retry-1")

	budget := syncbudget.New(syncbudget.WithTotal(5))
	policy := syncretry.New(syncretry.WithClock(frozenRetryClock{now: time.Now()}), syncretry.WithBaseDelay(0))
	res, err := DrainPending(t.Context(), Options{
		StateDir:  stateDir,
		ServerURL: server.URL,
		Budget:    budget,
		Retry:     policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := server.posts.Load(); got != 2 {
		t.Fatalf("posts = %d, want 2", got)
	}
	if budget.Used() != 2 {
		t.Fatalf("budget used = %d, want 2", budget.Used())
	}
	if res.SyncedBatches != 1 || res.PendingRemaining != 0 {
		t.Fatalf("expected the batch synced, got synced=%d pending=%d", res.SyncedBatches, res.PendingRemaining)
	}
}
