package resync

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"toktrail-collector/internal/syncbudget"
)

// budgetOptions threads a shared POST budget through the standard
// execution options of one pass.
func budgetOptions(dir string, budget *syncbudget.Budget) Options {
	opt := options(dir)
	opt.Budget = budget
	return opt
}

// TestSharedBudgetDeclineKeepsSecondBatchResumable is the synthetic
// integration proof of the optional shared POST budget: with a budget of
// exactly one attempt, the first batch's POST is granted, and the second
// batch is declined BEFORE its ingest POST — not marked failed, journal
// intact and resumable — while re-running the same exhausted budget keeps
// declining without any POST, and a fresh budget resumes the pass to
// completion.
func TestSharedBudgetDeclineKeepsSecondBatchResumable(t *testing.T) {
	remote, server := newRemote(t)
	dir := fixture(t, server.URL,
		[]json.RawMessage{record("a", "2026-10-28T00:00:00Z")},
		[]json.RawMessage{record("b", "2026-10-27T00:00:00Z")},
	)
	budget := syncbudget.New(syncbudget.WithTotal(1))
	opt := budgetOptions(dir, budget)
	var events []ProgressEvent
	opt.Progress = func(ev ProgressEvent) { events = append(events, ev) }

	first, err := Run(context.Background(), opt)
	if err == nil || first.Completed {
		t.Fatalf("the shared budget must stop the pass before it finishes: %+v err=%v", first, err)
	}
	if first.Stopped != budgetStopped || first.Failed != 0 || first.Blocked != 0 {
		t.Fatalf("the budget decline must be a clean stop, never a failure: %+v err=%v", first, err)
	}
	if first.Uploads != 1 || first.UploadedBatches != 1 || first.Remaining != 1 {
		t.Fatalf("exactly the first batch may be uploaded under a one-attempt budget: %+v", first)
	}
	if !errors.Is(err, syncbudget.ErrTotalExhausted) {
		t.Fatalf("the stop must surface the budget sentinel for callers: %v", err)
	}
	for _, want := range []string{"no ingest POST was made", "job stays resumable"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the stop must state %q: %v", want, err)
		}
	}
	if remote.postCount() != 1 || budget.Used() != 1 || budget.QueueUsed("history") != 1 {
		t.Fatalf("the declined target must never POST: posts=%d used=%d history=%d", remote.postCount(), budget.Used(), budget.QueueUsed("history"))
	}
	if len(events) != 1 || events[0].BatchID != "batch-00" || events[0].Outcome != outcomeDone {
		t.Fatalf("the declined batch must not emit a failed outcome: %+v", events)
	}

	// The journal survives the budget stop: the uploaded batch is done
	// with its receipt, the declined batch stays planned and un-failed.
	jb, exists, err := loadJob(dir)
	if err != nil || !exists {
		t.Fatalf("the journal must survive the budget stop: exists=%t err=%v", exists, err)
	}
	if jb.CompletedAt != nil {
		t.Fatalf("a budget-stopped job must not be complete: %+v", jb)
	}
	if jb.Batches[0].Outcome != outcomeDone || len(jb.Batches[0].Uploads) != 1 {
		t.Fatalf("the uploaded batch must be recorded as done: %+v", jb.Batches[0])
	}
	if jb.Batches[1].Outcome != outcomePlanned || jb.Batches[1].Error != "" || len(jb.Batches[1].Uploads) != 0 {
		t.Fatalf("the declined batch must stay planned and un-failed: %+v", jb.Batches[1])
	}

	// Re-running under the SAME exhausted budget must keep declining
	// without a single POST and without corrupting the journal.
	again, err := Run(context.Background(), budgetOptions(dir, budget))
	if err == nil || again.Completed || again.Stopped != budgetStopped || !errors.Is(err, syncbudget.ErrTotalExhausted) {
		t.Fatalf("an exhausted budget must keep declining: %+v err=%v", again, err)
	}
	if remote.postCount() != 1 || again.Uploads != 0 || again.Remaining != 1 {
		t.Fatalf("the re-run under an exhausted budget must not POST: posts=%d result=%+v", remote.postCount(), again)
	}
	declined, exists, err := loadJob(dir)
	if err != nil || !exists || declined.CompletedAt != nil || declined.Batches[1].Outcome != outcomePlanned {
		t.Fatalf("the journal must stay resumable across repeated declines: exists=%t err=%v job=%+v", exists, err, declined)
	}

	// A fresh budget resumes the pass and completes it: only the second
	// batch uploads, and both records reach the server exactly once.
	final, err := Run(context.Background(), budgetOptions(dir, syncbudget.New(syncbudget.WithTotal(1))))
	if err != nil {
		t.Fatal(err)
	}
	if !final.Completed || !final.Plan.Resumed || final.Uploads != 1 || final.Failed != 0 {
		t.Fatalf("the resumed pass must finish the remaining batch: %+v", final)
	}
	if remote.postCount() != 2 || !remote.seenHas("a") || !remote.seenHas("b") {
		t.Fatalf("both batches must be retransmitted exactly once: posts=%d seen-a=%t seen-b=%t", remote.postCount(), remote.seenHas("a"), remote.seenHas("b"))
	}
}

// TestSharedBudgetHistoryQueueCapStopsBeforePost pins the queue name the
// history retransmission reserves under: a budget whose only cap is the
// "history" queue declines the second POST, proving the reserve happens
// under exactly that queue (collection reserves under "device").
func TestSharedBudgetHistoryQueueCapStopsBeforePost(t *testing.T) {
	remote, server := newRemote(t)
	dir := fixture(t, server.URL,
		[]json.RawMessage{record("a", "2026-10-28T00:00:00Z")},
		[]json.RawMessage{record("b", "2026-10-27T00:00:00Z")},
	)
	budget := syncbudget.New(syncbudget.WithQueueCap("history", 1))
	result, err := Run(context.Background(), budgetOptions(dir, budget))
	if err == nil || result.Completed || result.Stopped != budgetStopped {
		t.Fatalf("the history queue cap must stop the pass: %+v err=%v", result, err)
	}
	if !errors.Is(err, syncbudget.ErrQueueExhausted) {
		t.Fatalf("the stop must surface the queue sentinel: %v", err)
	}
	if remote.postCount() != 1 || budget.QueueUsed("history") != 1 || budget.Used() != 1 {
		t.Fatalf("the queue-capped target must never POST: posts=%d history=%d used=%d", remote.postCount(), budget.QueueUsed("history"), budget.Used())
	}
	// A nil budget (the default) resumes and completes the pass unchanged.
	final, err := Run(context.Background(), options(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !final.Completed || !final.Plan.Resumed || remote.postCount() != 2 {
		t.Fatalf("the uncapped resume must finish the pass: %+v posts=%d", final, remote.postCount())
	}
}

// TestBudgetedPassWithLostResponseCommitReplaysIdempotently proves the
// crash window the journal plus the server's replay receipts close under
// a one-attempt budget: the test server COMMITS the first batch's ingest
// but loses the response, so the client cannot record the receipt. The
// pass stops with only that batch failed while the second batch stays
// resumable in the journal; the resume re-POSTs the committed batch,
// which the server answers with a replay receipt instead of double
// counting it, and finishes the remaining batch.
func TestBudgetedPassWithLostResponseCommitReplaysIdempotently(t *testing.T) {
	remote, server := newRemote(t)
	dir := fixture(t, server.URL,
		[]json.RawMessage{record("a", "2026-10-28T00:00:00Z")},
		[]json.RawMessage{record("b", "2026-10-27T00:00:00Z")},
	)
	// One attempt of budget; the server commits batch-00's POST but
	// drops its response on the wire.
	remote.dropResponseBatch = "batch-00"
	budget := syncbudget.New(syncbudget.WithTotal(1))
	first, err := Run(context.Background(), budgetOptions(dir, budget))
	if err == nil || first.Completed {
		t.Fatalf("the lost response must stop the pass: %+v err=%v", first, err)
	}
	if first.Stopped != "upload failed" || first.Failed != 1 || first.Uploads != 0 {
		t.Fatalf("a lost response keeps the original upload-failure semantics: %+v err=%v", first, err)
	}
	if remote.postCount() != 1 || budget.Used() != 1 || budget.QueueUsed("history") != 1 {
		t.Fatalf("exactly one POST may be spent: posts=%d used=%d history=%d", remote.postCount(), budget.Used(), budget.QueueUsed("history"))
	}
	// The server committed despite the lost response.
	if !remote.seenHas("a") {
		t.Fatal("the server must have committed the record whose response was lost")
	}
	committed, ok := remote.receiptFor("batch-00")
	if !ok || committed.AcceptedRecords != 1 {
		t.Fatalf("the committed receipt must stand: %+v ok=%t", committed, ok)
	}
	// The journal keeps the pass resumable: only the batch whose response
	// was lost is failed; the untouched second batch stays planned.
	jb, exists, err := loadJob(dir)
	if err != nil || !exists || jb.CompletedAt != nil {
		t.Fatalf("the journal must survive the lost response: exists=%t err=%v", exists, err)
	}
	if jb.Batches[0].Outcome != outcomeFailed || jb.Batches[0].Error == "" {
		t.Fatalf("the lost-response batch alone is marked failed: %+v", jb.Batches[0])
	}
	if jb.Batches[1].Outcome != outcomePlanned || jb.Batches[1].Error != "" {
		t.Fatalf("the second batch must stay resumable: %+v", jb.Batches[1])
	}

	// Resume under a fresh budget: the re-POST of the committed batch
	// replays idempotently (no double counting) and the remaining batch
	// uploads fresh.
	remote.dropResponseBatch = ""
	resumed, err := Run(context.Background(), budgetOptions(dir, syncbudget.New(syncbudget.WithTotal(2))))
	if err != nil {
		t.Fatal(err)
	}
	if !resumed.Completed || !resumed.Plan.Resumed || resumed.Uploads != 2 || resumed.Failed != 0 {
		t.Fatalf("the resume must finish both batches: %+v", resumed)
	}
	if resumed.ReplayReceipts != 1 {
		t.Fatalf("the committed batch must replay its receipt: %+v", resumed)
	}
	if remote.postCount() != 3 {
		t.Fatalf("the resume must re-send exactly the two batches: posts=%d", remote.postCount())
	}
	if !remote.seenHas("a") || !remote.seenHas("b") {
		t.Fatalf("both records must be committed exactly once: seen-a=%t seen-b=%t", remote.seenHas("a"), remote.seenHas("b"))
	}
	replayed, ok := remote.receiptFor("batch-00")
	if !ok || replayed.AcceptedRecords != 1 || replayed.BatchID != "batch-00" {
		t.Fatalf("the replay must not double count the committed batch: %+v ok=%t", replayed, ok)
	}
}
