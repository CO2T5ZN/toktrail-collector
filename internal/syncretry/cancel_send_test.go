package syncretry

import (
	"context"
	"errors"
	"testing"
	"time"
)

// HTTP may return its response even as the caller cancels. Send layers then
// stop marking failures retryable; Do must preserve cancellation independently
// of that marker, without discarding the failed attempt's original cause.
func TestDoCancellationDuringFailedSend(t *testing.T) {
	cause := errors.New("synthetic response failure")
	for _, tc := range []struct {
		name       string
		failure    error
		maxRetries int
		deadline   bool
	}{
		{"terminal response after cancellation", cause, 3, false},
		{"retryable response after cancellation", Retryable(cause), 3, false},
		{"exhausted retry allowance after cancellation", Retryable(cause), 0, false},
		{"Retry-After cannot fit after cancellation", RetryAfter(cause, time.Hour), 3, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := newFakeClock(fixedNow())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			opts := []Option{WithClock(clock), WithMaxRetries(tc.maxRetries)}
			if tc.deadline {
				opts = append(opts, WithRunDeadline(fixedNow().Add(time.Minute)))
			}
			calls := 0
			err := New(opts...).Do(ctx, func(context.Context, int) error {
				calls++
				cancel()
				return tc.failure
			})
			if !errors.Is(err, context.Canceled) || !errors.Is(err, cause) {
				t.Fatalf("cancellation must preserve both context and send cause: %v", err)
			}
			if calls != 1 || len(clock.recorded()) != 0 {
				t.Fatalf("cancelled send must not wait or send again: calls=%d waits=%v", calls, clock.recorded())
			}
			if errors.Is(err, ErrRetryExhausted) || errors.Is(err, ErrRetryPastDeadline) {
				t.Fatalf("cancellation must not fabricate a retry-budget stop: %v", err)
			}
		})
	}
}

func TestDoConfirmedSuccessWinsConcurrentCancellation(t *testing.T) {
	clock := newFakeClock(fixedNow())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	err := New(WithClock(clock)).Do(ctx, func(context.Context, int) error {
		calls++
		cancel()
		return nil
	})
	if err != nil || calls != 1 || len(clock.recorded()) != 0 {
		t.Fatalf("a confirmed successful attempt must not be turned into a failure: calls=%d waits=%v err=%v", calls, clock.recorded(), err)
	}
}
