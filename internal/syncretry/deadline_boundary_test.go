package syncretry

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"
)

func TestHugeRetryAfterSaturates(t *testing.T) {
	wait, ok := ParseRetryAfter(fixedNow(), "99999999999999999999999999999999999999")
	if !ok || wait != time.Duration(math.MaxInt64) {
		t.Fatalf("huge Retry-After must not be ignored: wait=%s ok=%t", wait, ok)
	}
}

func TestHugeRetryAfterWithoutDeadlineStopsWithoutWaiting(t *testing.T) {
	clock := newFakeClock(fixedNow())
	policy := New(WithClock(clock))
	calls := 0
	err := policy.Do(context.Background(), func(context.Context, int) error {
		calls++
		return RetryAfterHeader(errTransient, "86400")
	})
	if !errors.Is(err, ErrRetryPastDeadline) || calls != 1 || len(clock.recorded()) != 0 {
		t.Fatalf("unbounded Retry-After must stop: err=%v calls=%d waits=%v", err, calls, clock.recorded())
	}
}

func TestFullJitterStaysWithinBackoff(t *testing.T) {
	if FullJitter(0) != 0 || FullJitter(-time.Second) != 0 {
		t.Fatal("non-positive backoff must not wait")
	}
	for i := 0; i < 100; i++ {
		if got := FullJitter(time.Second); got < 0 || got >= time.Second {
			t.Fatalf("jitter outside backoff: %v", got)
		}
	}
}

func TestRunDeadlineDoesNotStartAtOrAfterLimit(t *testing.T) {
	now := fixedNow()
	clock := newFakeClock(now)
	calls := 0
	p := New(WithClock(clock), WithRunDeadline(now))
	err := p.Do(context.Background(), func(context.Context, int) error { calls++; return nil })
	if !errors.Is(err, ErrRetryPastDeadline) || calls != 0 {
		t.Fatalf("expired run must not send: calls=%d err=%v", calls, err)
	}
	clock = newFakeClock(now)
	p = New(WithClock(clock), WithRunDeadline(now.Add(time.Second)))
	calls = 0
	err = p.Do(context.Background(), func(context.Context, int) error { calls++; return Retryable(errTransient) })
	if !errors.Is(err, ErrRetryPastDeadline) || calls != 1 || len(clock.recorded()) != 0 {
		t.Fatalf("retry at deadline must not wait or send: calls=%d err=%v waits=%v", calls, err, clock.recorded())
	}
}
