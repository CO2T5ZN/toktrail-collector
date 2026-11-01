package syncretry

import (
	"context"
	"math/rand/v2"
	"time"
)

// Clock is the policy's view of time: what "now" is and how to wait.
// Production code uses RealClock; tests inject fakes so that no test
// ever sleeps.
type Clock interface {
	// Now reports the current instant. The policy uses it to interpret
	// Retry-After HTTP-date values and to compare waits against the run
	// deadline.
	Now() time.Time

	// Wait blocks for d, or until ctx is done, whichever happens first.
	// It returns nil once d has elapsed, and the context error —
	// context.Canceled or context.DeadlineExceeded — when the context
	// won, so external cancellation stays observable through errors.Is.
	// Implementations must return the context error without delay when
	// ctx is already done, and must not wait at all when d is
	// non-positive.
	Wait(ctx context.Context, d time.Duration) error
}

// RealClock is the Clock backed by the runtime.
type RealClock struct{}

var _ Clock = RealClock{}

func (RealClock) Now() time.Time { return time.Now() }

func (RealClock) Wait(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Jitter decorrelates retries by transforming a computed backoff into
// the delay actually waited. It must be fast and non-blocking — the
// policy calls it inline — and its result is clamped to
// [0, maxDelay], so the cap bounds the final delay including jitter.
// Returning the input unchanged (or using a nil Jitter) yields
// deterministic waits. Jitter applies only to the computed backoff,
// never on top of a server Retry-After floor.
type Jitter func(backoff time.Duration) time.Duration

// FullJitter selects a uniformly distributed delay in [0, backoff).
// Server Retry-After remains a separate floor enforced by Policy.
func FullJitter(backoff time.Duration) time.Duration {
	if backoff <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(backoff)))
}
