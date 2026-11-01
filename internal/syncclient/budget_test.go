package syncclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncbudget"
)

func TestIngestBudgetReservesOnlyBeforePost(t *testing.T) {
	store := statedir.New(t.TempDir())
	if err := store.Save(statedir.DeviceState{ServerURL: "http://unused", DeviceID: "dev-1", DeviceSecret: strings.Repeat("b", 64)}); err != nil {
		t.Fatal(err)
	}
	batch := writeBatchFile(t, map[string]any{"batchId": "budget-batch", "records": []map[string]any{{"recordKey": "budget-key", "kind": "delta", "occurredAt": "2026-10-20T10:00:00Z", "tool": "claude-code", "input": "10", "output": "5", "adapterVersion": "test", "sourceType": "fixture"}}})
	var posts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelf(t, w, r, 7) {
			return
		}
		posts.Add(1)
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{"batchId": "budget-batch", "status": "accepted", "acceptedRecords": 1, "rejectedRecords": 0, "receivedAt": "2026-10-20T10:12:00Z"}})
	}))
	defer srv.Close()
	budget := syncbudget.New(syncbudget.WithTotal(0))
	_, err := Run(context.Background(), store, Options{ServerURL: srv.URL, BatchFile: batch, Budget: budget, BudgetQueue: "device"})
	if !errors.Is(err, syncbudget.ErrTotalExhausted) || posts.Load() != 0 || budget.Used() != 0 {
		t.Fatalf("exhausted budget: err=%v posts=%d used=%d", err, posts.Load(), budget.Used())
	}
	budget = syncbudget.New(syncbudget.WithTotal(1))
	_, err = Run(context.Background(), store, Options{ServerURL: srv.URL, BatchFile: batch, Budget: budget, BudgetQueue: "device"})
	if err != nil || posts.Load() != 1 || budget.Used() != 1 {
		t.Fatalf("allowed budget: err=%v posts=%d used=%d", err, posts.Load(), budget.Used())
	}
}
