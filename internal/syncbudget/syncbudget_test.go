package syncbudget

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestLimitsAndCancellation(t *testing.T) {
	ctx := context.Background()
	b := New(WithTotal(2), WithQueueCap("device", 1))
	if err := b.Reserve(ctx, "device"); err != nil {
		t.Fatal(err)
	}
	if err := b.Reserve(ctx, "device"); !errors.Is(err, ErrQueueExhausted) {
		t.Fatalf("queue cap: %v", err)
	}
	if err := b.Reserve(ctx, "cursor"); err != nil {
		t.Fatal(err)
	}
	if err := b.Reserve(ctx, "history"); !errors.Is(err, ErrTotalExhausted) {
		t.Fatalf("total cap: %v", err)
	}
	if n, ok := b.Remaining(); !ok || n != 0 {
		t.Fatalf("remaining: %d %t", n, ok)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := b.Reserve(cancelled, "device"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	var unlimited *Budget
	if err := unlimited.Reserve(ctx, "device"); err != nil {
		t.Fatal(err)
	}
	if _, ok := unlimited.Remaining(); ok {
		t.Fatal("nil budget must be unlimited")
	}
	zero := New(WithTotal(0))
	if err := zero.Reserve(ctx, "device"); !errors.Is(err, ErrTotalExhausted) {
		t.Fatalf("zero cap: %v", err)
	}
}

func TestDeadlineAndConcurrentReservations(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b := New(WithDeadline(now), WithNow(func() time.Time { return now }))
	if err := b.Reserve(context.Background(), "device"); !errors.Is(err, ErrDeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
	if b.Used() != 0 {
		t.Fatal("expired reservation spent budget")
	}
	b = New(WithTotal(37))
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = b.Reserve(context.Background(), "device") }()
	}
	wg.Wait()
	if b.Used() != 37 {
		t.Fatalf("concurrent attempts spent %d, want 37", b.Used())
	}
}
