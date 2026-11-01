package collection

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/syncbudget"
)

func TestFairDrainWithoutBudgetKeepsBound(t *testing.T) {
	dir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, dir, server.URL)
	for i := 0; i < 7; i++ {
		writePendingBatch(t, dir, fmt.Sprintf("fair-unbudgeted-%d", i))
	}
	res, err := DrainPending(context.Background(), Options{StateDir: dir, FairDrain: true})
	if err != nil || res.SyncedBatches != DefaultMaxSyncBatches || res.PendingRemaining != 2 {
		t.Fatalf("unbudgeted fair drain must remain bounded: res=%+v err=%v", res, err)
	}
}

func TestFairDrainRequiresOneSharedBudget(t *testing.T) {
	budget := syncbudget.New(syncbudget.WithTotal(0))
	other := syncbudget.New(syncbudget.WithTotal(1))
	_, err := Run(context.Background(), Options{StateDir: t.TempDir(), FairDrain: true, Budget: budget, Cursor: &cursorsync.Options{Budget: other}})
	if err == nil {
		t.Fatal("different device and cursor budgets must be rejected")
	}

	dir := t.TempDir()
	server := startBudgetFakeServer(t)
	bindCursorDevice(t, dir, server.URL)
	writeCursorPermit(t, dir)
	seedCursorPendingBatch(t, dir, "budget-inherited", 1)
	_, err = Run(context.Background(), Options{
		StateDir: dir, ServerURL: server.URL, HTTPClient: server.Client(), FairDrain: true, Budget: budget,
		Cursor: &cursorsync.Options{StateDir: dir, ServerURL: server.URL, HTTPClient: server.Client()},
	})
	if !errors.Is(err, syncbudget.ErrTotalExhausted) || budget.Used() != 0 || len(server.uploadOrder()) != 0 {
		t.Fatalf("cursor must inherit the exhausted shared budget: err=%v used=%d uploads=%v", err, budget.Used(), server.uploadOrder())
	}
}

func TestCanceledRunDoesNotReportComplete(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, drainOnly := range []bool{false, true} {
		t.Run(fmt.Sprintf("drainOnly=%t", drainOnly), func(t *testing.T) {
			var events []ProgressEvent
			opt := Options{StateDir: t.TempDir(), FairDrain: true, Progress: func(e ProgressEvent) { events = append(events, e) }}
			var err error
			if drainOnly {
				_, err = DrainPending(ctx, opt)
			} else {
				_, err = Run(ctx, opt)
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("expected cancellation, got %v", err)
			}
			for _, e := range events {
				if e.Stage == "complete" {
					t.Fatal("canceled run reported completion")
				}
			}
		})
	}
}
