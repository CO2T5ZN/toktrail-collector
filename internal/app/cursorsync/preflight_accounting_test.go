// Durable preflight accounting for every device self GET the cursor
// rounds perform: fetchSelf persists one outbox.RecordPreflightAttempt
// (preflight-attempts.json, the shared device ledger) immediately before
// each GET — the round-start preflight of Sync, DrainPending and Enable,
// the Status view, and every retry preflight of verifyUploadBoundary —
// so the self GET count and the persisted records correspond one to one.
// A ledger that cannot be written (or loads as corrupt) fails closed with
// zero HTTP traffic of any kind and the pending batch plus the local
// permit untouched; an already-canceled context returns before the write
// (no accounting state, zero GETs, cancellation still observable through
// errors.Is). A missing ledger file migrates to a valid first record and
// accumulates monotonically under the injected clock. Everything here is
// synthetic: a local fake TokTrail server, fake credential, verify, pull
// and confirm — no real user state is ever touched.
package cursorsync_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/local/outbox"
)

// preflightAttempts loads the durable authorization-attempt accounting a
// cursor round maintains (failing the test when it is unreadable).
func preflightAttempts(t *testing.T, dir string) outbox.PreflightAttempts {
	t.Helper()
	attempts, err := outbox.New(dir).LoadPreflightAttempts()
	if err != nil {
		t.Fatalf("load preflight accounting: %v", err)
	}
	return attempts
}

// requireNoPreflightFile asserts no accounting was persisted yet.
func requireNoPreflightFile(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Stat(outbox.New(dir).PreflightAttemptsPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("no preflight accounting may exist before the first self GET, stat err=%v", err)
	}
}

// corruptPreflightAttempts breaks the durable accounting in place (used
// from server handler goroutines, so it never touches testing.T).
func corruptPreflightAttempts(dir string) {
	_ = os.WriteFile(outbox.New(dir).PreflightAttemptsPath(), []byte("{ not accounting json"), 0o600)
}

// TestCursorSelfPreflightAccountedPerGET drives every fetchSelf caller
// and asserts the persisted accounting count equals the number of self
// GETs exactly: the Sync and DrainPending round-start preflights, the
// Enable view plus its first sync, the Status view, and — with a retry
// policy — the retry preflight's re-fetch (initial attempt + retry, two
// GETs, two records, timestamps from the injected clock).
func TestCursorSelfPreflightAccountedPerGET(t *testing.T) {
	t.Run("sync round-start preflight", func(t *testing.T) {
		h := newHarness(t)
		h.srv.setSource(defaultSource())
		h.writeLicense(t, activeLicenseForA())
		seedPendingBatch(t, h.dir, "cursor-preflight-sync-1", 1)
		requireNoPreflightFile(t, h.dir)

		res, err := cursorsync.Sync(context.Background(), h.options(), syncGate())
		if err != nil {
			t.Fatalf("sync round: %v", err)
		}
		if !res.Ran || res.SyncedBatches != 1 || res.PendingRemaining != 0 {
			t.Fatalf("unexpected round result: %+v", res)
		}
		self, _, _, _, _ := h.srv.stats()
		if self != 1 {
			t.Fatalf("a plain sync round performs exactly one self GET, got %d", self)
		}
		attempts := preflightAttempts(t, h.dir)
		if attempts.Count != self {
			t.Fatalf("persisted accounting count %d must equal the %d self GETs", attempts.Count, self)
		}
		if !attempts.FirstAt.Equal(baseTime) || !attempts.LastAt.Equal(baseTime) {
			t.Fatalf("the accounting must stamp the injected clock time, first=%v last=%v", attempts.FirstAt, attempts.LastAt)
		}
	})

	t.Run("drain-pending preflight", func(t *testing.T) {
		h := newHarness(t)
		h.srv.setSource(defaultSource())
		h.writeLicense(t, activeLicenseForA())
		seedPendingBatch(t, h.dir, "cursor-preflight-drain-1", 1)
		requireNoPreflightFile(t, h.dir)

		res, err := cursorsync.DrainPending(context.Background(), h.options(), syncGate())
		if err != nil {
			t.Fatalf("drain round: %v", err)
		}
		if !res.Ran || res.SyncedBatches != 1 || res.PendingRemaining != 0 {
			t.Fatalf("unexpected round result: %+v", res)
		}
		self, _, _, _, _ := h.srv.stats()
		if self != 1 {
			t.Fatalf("a drain-only round performs exactly one self GET, got %d", self)
		}
		if attempts := preflightAttempts(t, h.dir); attempts.Count != self {
			t.Fatalf("persisted accounting count %d must equal the %d self GETs", attempts.Count, self)
		}
	})

	t.Run("enable preflight plus first sync", func(t *testing.T) {
		h := newHarness(t)
		h.pull.setEvents(ev("evt-preflight-enable-1", baseTime.Add(-30*time.Minute), 100, 0, 0, 50))
		confirm := &fakeConfirm{answer: true}
		requireNoPreflightFile(t, h.dir)

		res, err := cursorsync.Enable(context.Background(), h.options(), confirm.confirm)
		if err != nil {
			t.Fatalf("enable: %v", err)
		}
		if !res.Confirmed || !res.ServerEnabled || !res.Sync.Ran || !res.Sync.FirstSyncCompleted {
			t.Fatalf("unexpected enable result: %+v", res)
		}
		// Enable's own self view plus the first sync's round-start
		// preflight: two GETs, two records.
		self, _, _, _, _ := h.srv.stats()
		if self != 2 {
			t.Fatalf("a first-time enable performs two self GETs (enable view + first sync), got %d", self)
		}
		attempts := preflightAttempts(t, h.dir)
		if attempts.Count != self {
			t.Fatalf("persisted accounting count %d must equal the %d self GETs", attempts.Count, self)
		}
		if !attempts.FirstAt.Equal(baseTime) || !attempts.LastAt.Equal(baseTime) {
			t.Fatalf("the accounting must stamp the injected clock time, first=%v last=%v", attempts.FirstAt, attempts.LastAt)
		}
	})

	t.Run("status view", func(t *testing.T) {
		h := newHarness(t)
		h.srv.setSource(defaultSource())
		h.writeLicense(t, activeLicenseForA())
		requireNoPreflightFile(t, h.dir)

		res, err := cursorsync.Status(context.Background(), h.options())
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		if !res.ServerReached || !res.HasSource {
			t.Fatalf("unexpected status result: %+v", res)
		}
		self, _, _, _, _ := h.srv.stats()
		if self != 1 {
			t.Fatalf("a status view performs exactly one self GET, got %d", self)
		}
		if attempts := preflightAttempts(t, h.dir); attempts.Count != self {
			t.Fatalf("persisted accounting count %d must equal the %d self GETs", attempts.Count, self)
		}
	})

	t.Run("retry preflight re-fetch", func(t *testing.T) {
		h := newHarness(t)
		h.srv.setSource(defaultSource())
		h.writeLicense(t, activeLicenseForA())
		seedPendingBatch(t, h.dir, "cursor-preflight-retry-1", 1)
		h.srv.setIngestScript(scriptedIngest{status: http.StatusServiceUnavailable})
		requireNoPreflightFile(t, h.dir)

		opt := h.options()
		opt.Retry = retryPolicy(h.clock, 2)
		res, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
		if err != nil {
			t.Fatalf("the retried drain must succeed: %v", err)
		}
		if !res.Ran || res.SyncedBatches != 1 || res.PendingRemaining != 0 {
			t.Fatalf("unexpected round result: %+v", res)
		}
		// Initial attempt plus retry: the round-start preflight and the
		// retry preflight's re-fetch — two GETs, two records.
		self, _, ingest, _, _ := h.srv.stats()
		if self != 2 || ingest != 2 {
			t.Fatalf("a retried upload performs two self GETs and two POSTs, self=%d ingest=%d", self, ingest)
		}
		attempts := preflightAttempts(t, h.dir)
		if attempts.Count != self {
			t.Fatalf("persisted accounting count %d must equal the %d self GETs", attempts.Count, self)
		}
		// The records carry the injected clock: the round start at
		// baseTime, the retry preflight after the 1s backoff.
		if !attempts.FirstAt.Equal(baseTime) {
			t.Fatalf("first attempt must be stamped %v, got %v", baseTime, attempts.FirstAt)
		}
		if !attempts.LastAt.Equal(baseTime.Add(time.Second)) {
			t.Fatalf("retry preflight must be stamped %v, got %v", baseTime.Add(time.Second), attempts.LastAt)
		}
	})
}

// TestCursorSelfPreflightAccountingCorruptFailsClosedZeroHTTP pins the
// fail-closed contract: when the durable accounting cannot be persisted
// (here: a corrupt ledger), the round stops BEFORE any HTTP traffic of
// any kind — zero self GETs, zero enable/ingest/capability calls, no
// credential read, no upstream pull — the seeded batch stays pending and
// the local permit is byte-for-byte unchanged, while the surfaced error
// leaks neither the device credential nor the account identity.
func TestCursorSelfPreflightAccountingCorruptFailsClosedZeroHTTP(t *testing.T) {
	for _, entry := range []struct {
		name string
		run  func(ctx context.Context, h *harness) error
	}{
		{"sync", func(ctx context.Context, h *harness) error {
			_, err := cursorsync.Sync(ctx, h.options(), syncGate())
			return err
		}},
		{"drain", func(ctx context.Context, h *harness) error {
			_, err := cursorsync.DrainPending(ctx, h.options(), syncGate())
			return err
		}},
	} {
		t.Run(entry.name, func(t *testing.T) {
			h := newHarness(t)
			h.srv.setSource(defaultSource())
			h.writeLicense(t, activeLicenseForA())
			seedPendingBatch(t, h.dir, "cursor-preflight-corrupt-1", 1)
			before := loadLicense(t, h.dir)
			corruptPreflightAttempts(h.dir)

			err := entry.run(context.Background(), h)
			if err == nil || !strings.Contains(err.Error(), "cannot persist the device self preflight accounting") {
				t.Fatalf("the unpersistable accounting must fail the round, got %v", err)
			}
			if strings.Contains(err.Error(), testDeviceSecret) || strings.Contains(err.Error(), accountA) {
				t.Fatalf("the accounting failure must not leak the credential or the account identity: %v", err)
			}
			self, enable, ingest, caps, _ := h.srv.stats()
			if self != 0 || enable != 0 || ingest != 0 || caps != 0 {
				t.Fatalf("zero HTTP traffic of any kind may happen, self=%d enable=%d ingest=%d caps=%d", self, enable, ingest, caps)
			}
			if h.auth.fetchCount() != 0 || len(h.pull.callLog()) != 0 {
				t.Fatal("a round stopped at the preflight accounting must not read the credential or pull upstream usage")
			}
			if n := pendingCount(t, h.dir); n != 1 {
				t.Fatalf("the seeded batch must stay pending, pending=%d", n)
			}
			if after := loadLicense(t, h.dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("the local permit must stay unchanged: before=%+v after=%+v", before, after)
			}
		})
	}
}

// TestCursorSelfPreflightAccountingCorruptOnRetryPreflightStopsRound
// pins the same contract for the retry preflight: the round start's self
// GET succeeded and the first POST failed transiently, but the retry's
// re-fetch cannot persist its accounting (the ledger breaks between the
// two) — the retry performs ZERO additional self GETs, nothing new is
// acknowledged, the batch stays pending and the round ends with the
// conservative stopped note instead of retrying unaccounted.
func TestCursorSelfPreflightAccountingCorruptOnRetryPreflightStopsRound(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-preflight-corrupt-retry-1", 1)
	h.srv.setIngestScript(scriptedIngest{status: http.StatusServiceUnavailable})
	h.srv.setIngestHook(func() { corruptPreflightAttempts(h.dir) })

	opt := h.options()
	opt.Retry = retryPolicy(h.clock, 2)
	res, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
	if err != nil {
		t.Fatalf("the stopped round must not fail: %v", err)
	}
	if res.SyncedBatches != 0 || res.PendingRemaining != 1 {
		t.Fatalf("nothing may be acknowledged on an unaccountable retry preflight: %+v", res)
	}
	if !strings.Contains(res.Skipped, "stopped") {
		t.Fatalf("the stop must be reported: %+v", res)
	}
	self, _, ingest, _, _ := h.srv.stats()
	if self != 1 || ingest != 1 {
		t.Fatalf("the retry preflight must perform zero self GETs when its accounting cannot persist: self=%d ingest=%d", self, ingest)
	}
	if n := pendingCount(t, h.dir); n != 1 {
		t.Fatalf("the batch must stay pending, pending=%d", n)
	}
}

// TestCursorSelfPreflightAccountingBootstrapsMissingLedger covers the
// nil-old-state migration: with no preflight-attempts.json on disk, the
// first self GET creates a well-formed accounting record (count 1, both
// timestamps stamped by the injected clock), and a later round under an
// advanced clock accumulates monotonically — the count grows with the
// GETs, FirstAt pins the first attempt and LastAt tracks the fresh now.
func TestCursorSelfPreflightAccountingBootstrapsMissingLedger(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "cursor-preflight-bootstrap-1", 1)
	requireNoPreflightFile(t, h.dir)

	if _, err := cursorsync.DrainPending(context.Background(), h.options(), syncGate()); err != nil {
		t.Fatalf("first drain: %v", err)
	}
	first := preflightAttempts(t, h.dir)
	if first.Count != 1 || !first.FirstAt.Equal(baseTime) || !first.LastAt.Equal(baseTime) {
		t.Fatalf("the missing ledger must migrate to one stamped record: %+v", first)
	}

	h.clock.Set(baseTime.Add(time.Hour))
	if _, err := cursorsync.DrainPending(context.Background(), h.options(), syncGate()); err != nil {
		t.Fatalf("second drain: %v", err)
	}
	second := preflightAttempts(t, h.dir)
	if second.Count != 2 {
		t.Fatalf("the accounting must accumulate one record per self GET, count=%d", second.Count)
	}
	if !second.FirstAt.Equal(baseTime) {
		t.Fatalf("FirstAt must pin the first attempt %v, got %v", baseTime, second.FirstAt)
	}
	if !second.LastAt.Equal(baseTime.Add(time.Hour)) {
		t.Fatalf("LastAt must track the injected clock %v, got %v", baseTime.Add(time.Hour), second.LastAt)
	}
	if self, _, _, _, _ := h.srv.stats(); self != 2 {
		t.Fatalf("two rounds perform two self GETs, got %d", self)
	}
}

// TestCursorSelfPreflightCanceledContextWritesNothingAndNeverGETs pins
// the cancellation check before the durable write: a round entered with
// an already-canceled context persists no accounting state at all,
// performs zero self GETs (and zero traffic of any other kind), keeps
// the seeded batch pending, and surfaces the cancellation so
// errors.Is(err, context.Canceled) keeps matching.
func TestCursorSelfPreflightCanceledContextWritesNothingAndNeverGETs(t *testing.T) {
	for _, entry := range []struct {
		name string
		run  func(ctx context.Context, h *harness) error
	}{
		{"sync", func(ctx context.Context, h *harness) error {
			_, err := cursorsync.Sync(ctx, h.options(), syncGate())
			return err
		}},
		{"drain", func(ctx context.Context, h *harness) error {
			_, err := cursorsync.DrainPending(ctx, h.options(), syncGate())
			return err
		}},
	} {
		t.Run(entry.name, func(t *testing.T) {
			h := newHarness(t)
			h.srv.setSource(defaultSource())
			h.writeLicense(t, activeLicenseForA())
			seedPendingBatch(t, h.dir, "cursor-preflight-cancel-1", 1)
			requireNoPreflightFile(t, h.dir)

			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			err := entry.run(ctx, h)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("the cancellation must stay observable through errors.Is, got %v", err)
			}
			self, enable, ingest, caps, _ := h.srv.stats()
			if self != 0 || enable != 0 || ingest != 0 || caps != 0 {
				t.Fatalf("a canceled round must perform zero HTTP traffic, self=%d enable=%d ingest=%d caps=%d", self, enable, ingest, caps)
			}
			requireNoPreflightFile(t, h.dir)
			if n := pendingCount(t, h.dir); n != 1 {
				t.Fatalf("the seeded batch must stay pending, pending=%d", n)
			}
		})
	}
}
