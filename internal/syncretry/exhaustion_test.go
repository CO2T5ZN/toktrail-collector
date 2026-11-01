package syncretry

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/syncbudget"
)

// TestDoRetryExhaustionSentinelClassification pins the exhaustion error
// contract callers classify on (plan §6.5 stop_reason=retry_exhausted):
// a retryable failure that outlives the retry budget wraps BOTH
// ErrRetryExhausted and the last send cause, while the two other stop
// shapes — a deadline stop and a final (non-retryable) send error —
// match neither the exhaustion sentinel nor each other's.
func TestDoRetryExhaustionSentinelClassification(t *testing.T) {
	cause := errors.New("upstream 503")
	clock := newFakeClock(fixedNow())
	p := New(WithClock(clock), WithMaxRetries(2))
	rec := &sendRecorder{}

	err := p.Do(context.Background(), rec.script(persistent(cause, 10)))

	if err == nil {
		t.Fatal("exhausted retries must surface as an error")
	}
	if !errors.Is(err, ErrRetryExhausted) {
		t.Fatalf("exhaustion must wrap ErrRetryExhausted: %v", err)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("exhaustion must keep matching the last send cause: %v", err)
	}
	if errors.Is(err, ErrRetryPastDeadline) {
		t.Fatalf("exhaustion must not read as a deadline stop: %v", err)
	}
	if got := rec.count(); got != 3 {
		t.Fatalf("send calls = %d, want 3 (initial + 2 retries)", got)
	}
	// The human message keeps the historical "giving up after N
	// attempts" wording (cursorsync's retry tests pin it).
	if !strings.Contains(err.Error(), "giving up after 3 attempts") {
		t.Fatalf("exhaustion message must keep the attempt count wording: %v", err)
	}
}

// TestDoRetryExhaustionPreservesCauseSentinels proves a sentinel the
// send layer wrapped inside its retryable marker — here a shared-budget
// decline — stays errors.Is-matchable through the exhaustion chain, so
// callers can still distinguish the underlying stop condition.
func TestDoRetryExhaustionPreservesCauseSentinels(t *testing.T) {
	decline := syncbudget.ErrTotalExhausted
	clock := newFakeClock(fixedNow())
	p := New(WithClock(clock), WithMaxRetries(1))
	rec := &sendRecorder{}

	err := p.Do(context.Background(), rec.script(persistent(decline, 5)))

	if !errors.Is(err, ErrRetryExhausted) {
		t.Fatalf("exhaustion must wrap ErrRetryExhausted: %v", err)
	}
	if !errors.Is(err, syncbudget.ErrTotalExhausted) {
		t.Fatalf("the budget decline cause must stay matchable: %v", err)
	}
}

// TestDoDeadlineStopIsNotExhaustion pins the distinction between the
// two policy stops: a deadline stop (ErrRetryPastDeadline) happens
// before an attempt is made and must never classify as exhaustion.
func TestDoDeadlineStopIsNotExhaustion(t *testing.T) {
	clock := newFakeClock(fixedNow())
	p := New(
		WithClock(clock),
		WithRunDeadline(fixedNow().Add(time.Second)),
	)
	rec := &sendRecorder{}

	err := p.Do(context.Background(), rec.script(persistent(errTransient, 10)))

	if !errors.Is(err, ErrRetryPastDeadline) {
		t.Fatalf("want a deadline stop: %v", err)
	}
	if errors.Is(err, ErrRetryExhausted) {
		t.Fatalf("a deadline stop must not read as exhaustion: %v", err)
	}
}

// TestDoFinalErrorIsNeitherSentinel pins the third shape: a final
// (non-retryable) send error is returned unchanged and matches neither
// policy sentinel.
func TestDoFinalErrorIsNeitherSentinel(t *testing.T) {
	final := errors.New("hard failure")
	clock := newFakeClock(fixedNow())
	p := New(WithClock(clock))
	rec := &sendRecorder{}

	err := p.Do(context.Background(), rec.script([]error{final}))

	if !errors.Is(err, final) {
		t.Fatalf("the final error must be returned as-is: %v", err)
	}
	if errors.Is(err, ErrRetryExhausted) || errors.Is(err, ErrRetryPastDeadline) {
		t.Fatalf("a final error must match no policy sentinel: %v", err)
	}
	if got := rec.count(); got != 1 {
		t.Fatalf("send calls = %d, want 1 (final errors are not retried)", got)
	}
}
