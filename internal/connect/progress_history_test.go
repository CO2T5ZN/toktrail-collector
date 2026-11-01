package connect

// History-adapter semantics tests: resync's per-parent "done" event
// AGGREGATES the parent's stored receipts (every child upload,
// including receipts recorded by earlier rounds of a resumed job, with
// Replay as the OR across them — and a resumed batch can complete with
// zero uploads this round). Those aggregates must never be presented as
// one batch's receipt or as this round's processing. Everything is
// synthetic tempdir state and httptest fakes.

import (
	"context"
	"testing"
	"time"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/app/resync"
	"toktrail-collector/internal/local/outbox"
)

// The adapter is immune to the aggregate hazard: a done event carrying
// historical totals, an OR-replay flag and zero uploads this round
// still reports NO receipt observation — never a single-batch receipt
// and never new work.
func TestHistoryBatchEventAggregatesStayUnknown(t *testing.T) {
	ev := historyBatchEvent(resync.ProgressEvent{
		Outcome:  "done",
		Records:  500,
		Uploaded: 0, // a resumed batch completing with no uploads this round
		Accepted: 417,
		Rejected: 3,
		Replay:   true, // the OR over child receipts, including earlier rounds
		Skipped:  80,
	})
	if ev.Kind != collection.ProgressBatch || ev.Queue != collection.ProgressQueueHistory {
		t.Fatalf("the event must be a history batch event: %+v", ev)
	}
	if ev.Result != "done" {
		t.Fatalf("resync's sealed outcome travels verbatim: %+v", ev)
	}
	if ev.ReceiptObserved {
		t.Fatalf("an aggregate over stored receipts is not one batch's receipt: %+v", ev)
	}
	if ev.AcceptedRecords != 0 || ev.RejectedRecords != 0 || ev.BatchReplay {
		t.Fatalf("receipt fields must stay unknown behind their gate: %+v", ev)
	}
	if ev.FirstBatchConfirmation != collection.FirstBatchConfirmationNo {
		t.Fatalf("the archive-backed parent was synced before this run: %+v", ev)
	}
	if ev.Origin != collection.OriginHistoryRetransmit {
		t.Fatalf("the origin is the history retransmission: %+v", ev)
	}

	// blocked and failed outcomes map verbatim with the same immunity.
	blocked := historyBatchEvent(resync.ProgressEvent{Outcome: "blocked", Accepted: 5})
	if blocked.Result != "blocked" || blocked.ReceiptObserved || blocked.AcceptedRecords != 0 {
		t.Fatalf("a blocked outcome carries no receipt either: %+v", blocked)
	}
}

// A resumed retransmission (run one budget-bound, run two finishing the
// journal whose earlier-round receipts are already stored) emits done
// events over PRIOR receipts: none of them may present a receipt
// observation, and the history phase contributes nothing to the
// processing rate.
func TestSyncHistoryResumeKeepsAggregatesUnknown(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	mock := startSyncToktrailMock(t, "dev-progress-history")
	seedBoundState(t, dir, mock.URL, "dev-progress-history")
	seedCodexGrant(t, dir, home)
	// A synced archive large enough that a small budget leaves the job
	// resumable, plus one pending batch so the device drain also runs.
	for i := 0; i < 4; i++ {
		seedBatch(t, dir, home, "hist-"+string(rune('a'+i)), outbox.StatusSynced,
			syncRecord("hist-key-"+string(rune('a'+i)), syncTestNow.Add(-time.Hour).Format(time.RFC3339)))
	}
	seedBatch(t, dir, home, "pend-1", outbox.StatusPending,
		syncRecord("pend-key-1", syncTestNow.Add(-time.Hour).Format(time.RFC3339)))

	// Run one: a tight total budget stops the history mid-pass and
	// leaves a resumable journal with stored receipts.
	first, err := Sync(context.Background(), SyncOptions{
		StateDir: dir, ServerURL: mock.URL, HomeDir: home,
		HTTPClient: mock.Client(), Now: func() time.Time { return syncTestNow },
		MaxTotalBatches: 2,
	})
	if err == nil {
		t.Fatalf("the budget-bound run must report incomplete: %+v", first)
	}
	if first.Resync.Completed {
		t.Fatalf("run one must leave the history job resumable: %+v", first.Resync)
	}

	// Run two: the resume finishes the journal whose earlier-round
	// receipts are already stored; every done event aggregates them.
	rec := &progressHistoryRecorder{}
	second, err := Sync(context.Background(), SyncOptions{
		StateDir: dir, ServerURL: mock.URL, HomeDir: home,
		HTTPClient: mock.Client(), Now: func() time.Time { return syncTestNow },
		MaxTotalBatches: 20,
		Progress:        rec.record,
	})
	if err != nil {
		t.Fatalf("the resumed run must complete: %v", err)
	}
	if !second.Resync.Completed {
		t.Fatalf("the resumed history must complete: %+v", second.Resync)
	}
	history := rec.batches()
	if len(history) == 0 {
		t.Fatalf("the resumed history must emit batch events")
	}
	for _, ev := range history {
		if ev.Result != "done" && ev.Result != "blocked" && ev.Result != "failed" {
			t.Fatalf("resync's sealed outcome vocabulary travels verbatim: %+v", ev)
		}
		if ev.ReceiptObserved || ev.AcceptedRecords != 0 || ev.RejectedRecords != 0 || ev.BatchReplay {
			t.Fatalf("aggregated prior-round receipts must stay unknown: %+v", ev)
		}
		if ev.FirstBatchConfirmation != collection.FirstBatchConfirmationNo {
			t.Fatalf("history parents were synced before the run: %+v", ev)
		}
	}
	// No heartbeat of the resumed run claims a rate: the history phase
	// folds no outcomes into the drain counters.
	for _, ev := range rec.ofKind(collection.ProgressHeartbeat) {
		if ev.RateKnown {
			t.Fatalf("the history phase must not fabricate a processing rate: %+v", ev)
		}
	}
}

// progressHistoryRecorder is the connect-package event recorder.
type progressHistoryRecorder struct {
	events []collection.ProgressEvent
}

func (r *progressHistoryRecorder) record(ev collection.ProgressEvent) {
	r.events = append(r.events, ev)
}

func (r *progressHistoryRecorder) ofKind(kind string) []collection.ProgressEvent {
	var out []collection.ProgressEvent
	for _, ev := range r.events {
		if ev.Kind == kind {
			out = append(out, ev)
		}
	}
	return out
}

func (r *progressHistoryRecorder) batches() []collection.ProgressEvent {
	var out []collection.ProgressEvent
	for _, ev := range r.ofKind(collection.ProgressBatch) {
		if ev.Queue == collection.ProgressQueueHistory {
			out = append(out, ev)
		}
	}
	return out
}
