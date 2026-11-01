// The optional progress hook (Options.Progress): exactly one sanitized
// PostProgress report per PostBatch call, carrying only closed facts —
// whether the request was actually handed to the transport (a budget
// decline or local refusal is NOT an attempt), whether a
// strictly-validated receipt arrived (only then the counts), and the
// payload's planned/attempted size. Everything here is synthetic: a
// local httptest server (or a closed one for transport failures), a
// zeroed shared budget for declines, synthetic batches — no real
// device, credential or server is ever touched.
package sourcebatch

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"toktrail-collector/internal/syncbudget"
)

// hookProgress collects the reports of one wired hook.
type hookProgress struct {
	reports []PostProgress
}

func (h *hookProgress) record(p PostProgress) {
	h.reports = append(h.reports, p)
}

func (h *hookProgress) count() int { return len(h.reports) }

// TestPostProgressAcceptedReceipt: a successful upload reports exactly
// one event with the trustworthy facts — attempted, strictly-validated
// receipt counts, the payload's planned size and no replay.
func TestPostProgressAcceptedReceipt(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 2))
	var posts atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		writeJSON(w, http.StatusAccepted, serverReceipt(testBatchID, "accepted", 2, 0, testReceivedAt, false, nil))
	}))
	t.Cleanup(server.Close)
	opt := testOptions(server.URL)
	hook := &hookProgress{}
	opt.Progress = hook.record

	if _, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if hook.count() != 1 {
		t.Fatalf("exactly one report per call, got %d", hook.count())
	}
	p := hook.reports[0]
	if !p.Attempted || !p.ValidReceipt {
		t.Fatalf("an accepted upload is attempted with a valid receipt: %+v", p)
	}
	if p.PayloadBytes != len(encoded) {
		t.Fatalf("payload bytes = %d, want the planned size %d", p.PayloadBytes, len(encoded))
	}
	if p.AcceptedRecords != 2 || p.RejectedRecords != 0 || p.Replay {
		t.Fatalf("receipt counts must mirror the validated receipt: %+v", p)
	}
	if posts.Load() != 1 {
		t.Fatalf("exactly one POST, posts=%d", posts.Load())
	}
}

// TestPostProgressReplayReceipt: a duplicate re-send answered with
// replay=true reports the replay flag batch-level alongside the stored
// receipt's counts.
func TestPostProgressReplayReceipt(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 1))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusAccepted, serverReceipt(testBatchID, "accepted", 1, 0, testReceivedAt, true, nil))
	}))
	t.Cleanup(server.Close)
	opt := testOptions(server.URL)
	hook := &hookProgress{}
	opt.Progress = hook.record

	if _, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent); err != nil {
		t.Fatalf("upload: %v", err)
	}
	p := hook.reports[0]
	if !p.ValidReceipt || !p.Replay || p.AcceptedRecords != 1 {
		t.Fatalf("the replay receipt must report its counts and flag: %+v", p)
	}
}

// TestPostProgressPartialReceipt: a receipt with rejected records is
// still a strictly-validated receipt — the counts are known (one
// accepted, one rejected) even though the caller treats them as a
// failure of the batch.
func TestPostProgressPartialReceipt(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 2))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusAccepted, serverReceipt(testBatchID, "partial_error", 1, 1, testReceivedAt, false,
			[]map[string]any{recordErr(0, "stale_revision")}))
	}))
	t.Cleanup(server.Close)
	opt := testOptions(server.URL)
	hook := &hookProgress{}
	opt.Progress = hook.record

	if _, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent); err != nil {
		t.Fatalf("a partial receipt is a valid protocol answer: %v", err)
	}
	p := hook.reports[0]
	if !p.Attempted || !p.ValidReceipt {
		t.Fatalf("a partial receipt is attempted and valid: %+v", p)
	}
	if p.AcceptedRecords != 1 || p.RejectedRecords != 1 {
		t.Fatalf("the counts must split accepted/rejected: %+v", p)
	}
}

// TestPostProgressTransportFailure: a POST that never gets a response
// is attempted (the request was handed to the transport) but carries no
// receipt — the counts stay unknown, never a claim of zero records.
func TestPostProgressTransportFailure(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 1))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Close() // refused connections model the transport failure

	opt := testOptions(server.URL)
	hook := &hookProgress{}
	opt.Progress = hook.record

	if _, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent); err == nil {
		t.Fatal("the transport failure must surface")
	}
	p := hook.reports[0]
	if !p.Attempted {
		t.Fatalf("the request was handed to the transport: %+v", p)
	}
	if p.ValidReceipt || p.AcceptedRecords != 0 || p.RejectedRecords != 0 || p.Replay {
		t.Fatalf("no receipt means unknown counts, never zero facts: %+v", p)
	}
	if p.PayloadBytes != len(encoded) {
		t.Fatalf("the planned payload size stays known: %+v", p)
	}
}

// TestPostProgressNon2xxAnswer: an error status is attempted without a
// valid receipt; its counts are unknown.
func TestPostProgressNon2xxAnswer(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 1))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "unavailable", "message": marker}})
	}))
	t.Cleanup(server.Close)
	opt := testOptions(server.URL)
	hook := &hookProgress{}
	opt.Progress = hook.record

	if _, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent); err == nil {
		t.Fatal("the failed status must surface")
	}
	p := hook.reports[0]
	if !p.Attempted || p.ValidReceipt {
		t.Fatalf("attempted, no valid receipt: %+v", p)
	}
}

// TestPostProgressInvalidReceipt: a 2xx answer whose receipt fails
// strict validation is attempted with ValidReceipt false — the counts
// are unknown, not zero.
func TestPostProgressInvalidReceipt(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 1))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Right shape, wrong batch id: strict validation refuses it.
		writeJSON(w, http.StatusAccepted, serverReceipt("batch-someone-else", "accepted", 1, 0, testReceivedAt, false, nil))
	}))
	t.Cleanup(server.Close)
	opt := testOptions(server.URL)
	hook := &hookProgress{}
	opt.Progress = hook.record

	if _, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("the invalid receipt must surface, got %v", err)
	}
	p := hook.reports[0]
	if !p.Attempted || p.ValidReceipt || p.AcceptedRecords != 0 || p.RejectedRecords != 0 {
		t.Fatalf("attempted, invalid receipt, unknown counts: %+v", p)
	}
}

// TestPostProgressBudgetDeclineNeverAttempted: a declined shared budget
// prevents the POST entirely — the report states the call was never
// attempted, and the planned payload size is the only other fact.
func TestPostProgressBudgetDeclineNeverAttempted(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 1))
	var posts atomic.Int64
	server := newBudgetServer(t, &posts)
	opt := testOptions(server.URL)
	opt.Budget = syncbudget.New(syncbudget.WithTotal(0))
	hook := &hookProgress{}
	opt.Progress = hook.record

	if _, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent); !errors.Is(err, syncbudget.ErrTotalExhausted) {
		t.Fatalf("the decline must surface, got %v", err)
	}
	if posts.Load() != 0 {
		t.Fatalf("a declined budget must not POST, posts=%d", posts.Load())
	}
	p := hook.reports[0]
	if p.Attempted || p.ValidReceipt || p.AcceptedRecords != 0 || p.RejectedRecords != 0 || p.Replay {
		t.Fatalf("a decline is never an attempt and carries no receipt facts: %+v", p)
	}
	if p.PayloadBytes != len(encoded) {
		t.Fatalf("the planned payload size stays known: %+v", p)
	}
}

// TestPostProgressLocalRefusalNeverAttempted: a batch refused by local
// validation (here: belonging to another source) never reaches the
// transport and spends nothing.
func TestPostProgressLocalRefusalNeverAttempted(t *testing.T) {
	var posts atomic.Int64
	server := newBudgetServer(t, &posts)
	opt := testOptions(server.URL)
	foreign := testBatch(testBatchID, 1)
	foreign.SourceInstanceID = "src-inst-someone-else"
	hook := &hookProgress{}
	opt.Progress = hook.record

	if _, err := PostBatch(t.Context(), opt, mustEncode(t, foreign), testFence, testConsent); err == nil {
		t.Fatal("the local refusal must surface")
	}
	if posts.Load() != 0 {
		t.Fatalf("a locally refused batch must not POST, posts=%d", posts.Load())
	}
	p := hook.reports[0]
	if p.Attempted || p.ValidReceipt {
		t.Fatalf("a local refusal is never an attempt: %+v", p)
	}
}

// TestGetBatchNeverReports: the receipt-fetch GET path is not a send
// and never fires the progress hook.
func TestGetBatchNeverReports(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, serverReceipt(testBatchID, "accepted", 1, 0, testReceivedAt, true, nil))
	}))
	t.Cleanup(server.Close)
	opt := testOptions(server.URL)
	hook := &hookProgress{}
	opt.Progress = hook.record

	if _, _, err := GetBatch(t.Context(), opt, testBatchID, testFence, testConsent); err != nil {
		t.Fatalf("get: %v", err)
	}
	if hook.count() != 0 {
		t.Fatalf("the GET path must never report, got %d reports", hook.count())
	}
}

// TestPostProgressNilHookKeepsUploadWorking: the hook is optional — a
// nil Progress changes nothing about a successful upload.
func TestPostProgressNilHookKeepsUploadWorking(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 1))
	var posts atomic.Int64
	server := newBudgetServer(t, &posts)
	opt := testOptions(server.URL)
	opt.Progress = nil

	if _, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if posts.Load() != 1 {
		t.Fatalf("exactly one POST, posts=%d", posts.Load())
	}
}
