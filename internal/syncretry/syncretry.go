// Package syncretry is the retry policy for upload sends: it decides how
// long to wait between attempts, how a server Retry-After hint and the
// remaining run deadline constrain that wait, and when retrying stops.
//
// Upload clients accept this policy optionally; callers choose whether to
// enable it and must supply a run deadline for longer Retry-After waits.
//
// # Retry shape
//
// New returns the policy the send path wants: at most three retries
// after the initial attempt (four attempts in total), exponential
// backoff from a one-second base that doubles up to a thirty-second
// cap. Everything involving time is injected — the Clock (reading
// "now" and waiting cancellably) and the Jitter transform applied to
// each computed backoff — so tests run on fakes and never sleep.
//
// # Error contract
//
// A send whose failure should be retried says so by wrapping its error
// with Retryable, RetryAfter, or RetryAfterHeader; translating HTTP
// responses (429, 5xx, …) into those markers is future send-layer
// work, not this package's. Any other error is final: Do returns it
// immediately, unchanged. A Retry-After hint is a floor, never a
// ceiling — the next attempt never starts earlier than the server
// allows, and the (larger) computed backoff wins when it exceeds the
// hint.
//
// # Deadlines and cancellation
//
// Before every wait the policy checks the earliest instant the next
// attempt may start — now plus the required wait — against the run
// deadline, which is the earlier of WithRunDeadline and the context
// deadline. When honoring the wait would start the next attempt at or past
// that deadline, Do fails fast with an error wrapping
// ErrRetryPastDeadline without waiting at all. Without a deadline, waits
// above 30 seconds also fail closed instead of holding a caller's lock
// indefinitely. External cancellation
// always stays observable: an error returned because a context was
// canceled satisfies errors.Is(err, context.Canceled).
//
// # Caller-owned obligations
//
// Send documents the two things syncretry deliberately does not do:
// keeping the payload and target ID identical across attempts, and
// reserving upload budget (internal/syncbudget) before each actual
// send. Both are caller guarantees inside the send callback.
package syncretry

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"
)

// Defaults for the send path's retry policy.
const (
	// DefaultMaxRetries is the number of retries that may follow the
	// initial attempt: three, so at most four attempts in total.
	DefaultMaxRetries = 3

	// DefaultBaseDelay is the exponential backoff base.
	DefaultBaseDelay = 1 * time.Second

	// DefaultMaxDelay caps the jittered backoff between attempts.
	DefaultMaxDelay = 30 * time.Second
)

// Policy decides how a single logical send is retried. Build one with
// New. A Policy is fixed after construction and safe for concurrent
// use to the extent the injected Clock and Jitter are.
type Policy struct {
	maxRetries  int
	baseDelay   time.Duration
	maxDelay    time.Duration
	runDeadline time.Time
	clock       Clock
	jitter      Jitter
}

// New returns a Policy with the defaults described in the package
// documentation, adjusted by opts.
func New(opts ...Option) *Policy {
	p := &Policy{
		maxRetries: DefaultMaxRetries,
		baseDelay:  DefaultBaseDelay,
		maxDelay:   DefaultMaxDelay,
		clock:      RealClock{},
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Option adjusts a Policy at construction time.
type Option func(*Policy)

// WithMaxRetries sets how many retries may follow the initial attempt.
// Negative values clamp to zero: a single attempt, no retries.
func WithMaxRetries(n int) Option {
	return func(p *Policy) {
		if n < 0 {
			n = 0
		}
		p.maxRetries = n
	}
}

// WithBaseDelay sets the exponential backoff base. A non-positive base
// means the policy adds no backoff of its own: waits then come only
// from server Retry-After hints.
func WithBaseDelay(d time.Duration) Option {
	return func(p *Policy) {
		if d < 0 {
			d = 0
		}
		p.baseDelay = d
	}
}

// WithMaxDelay caps the backoff, after jitter. It never truncates a
// server Retry-After floor — honoring the server matters more than the
// local cap, and the deadline check is what rejects floors the run
// cannot afford. A non-positive cap disables the policy's own backoff
// the same way a non-positive base does.
func WithMaxDelay(d time.Duration) Option {
	return func(p *Policy) {
		if d < 0 {
			d = 0
		}
		p.maxDelay = d
	}
}

// WithRunDeadline sets the policy's run deadline. The zero time (the
// default) means "no policy deadline"; the context deadline still
// applies, and when both exist the earlier one wins.
func WithRunDeadline(t time.Time) Option {
	return func(p *Policy) { p.runDeadline = t }
}

// WithClock injects the clock used to read "now" and to wait. A nil
// clock falls back to RealClock.
func WithClock(c Clock) Option {
	return func(p *Policy) {
		if c == nil {
			c = RealClock{}
		}
		p.clock = c
	}
}

// WithJitter injects the transform applied to each computed backoff. A
// nil Jitter means deterministic, jitter-free waits.
func WithJitter(j Jitter) Option {
	return func(p *Policy) { p.jitter = j }
}

// Send performs exactly one attempt of a logical upload. Do invokes it
// once per attempt — with the 1-based attempt number and only after
// the context has been checked — and a nil return ends the retry loop
// with success.
//
// Two obligations deliberately stay with the caller:
//
//   - Identical payload and target ID on every invocation. syncretry
//     neither knows nor carries them; identity across attempts is a
//     caller guarantee, not a package feature.
//   - Budget gating. Callers that account attempts against the shared
//     upload budget (internal/syncbudget) Reserve at the top of Send —
//     before the actual network send — and return a decline as a plain
//     error. Plain errors are final, so Do stops immediately without
//     waiting, and the reservation decision stays with the run's
//     accounting instead of inside this package.
type Send func(ctx context.Context, attempt int) error

// Do runs send under the policy until it succeeds, returns a final
// (non-retryable) error, exhausts the retry budget, or would have to
// wait past the run deadline.
//
// The returned error wraps its cause, so errors.Is matches the last
// send error, this package's sentinels, and — when an external context
// was canceled — context.Canceled. Exhausting the retry budget wraps
// the last send error with ErrRetryExhausted; a deadline stop wraps it
// with ErrRetryPastDeadline; a final (non-retryable) send error is
// returned unchanged, matching none of the sentinels.
func (p *Policy) Do(ctx context.Context, send Send) error {
	if p == nil {
		return errors.New("syncretry: Do: nil policy")
	}
	if send == nil {
		return errors.New("syncretry: Do: nil send")
	}
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("syncretry: attempt %d not started: %w", attempt, err)
		}
		if deadline, ok := p.effectiveDeadline(ctx); ok && !p.clock.Now().Before(deadline) {
			return fmt.Errorf("%w: attempt %d cannot start at or after the run deadline", ErrRetryPastDeadline, attempt)
		}
		err := send(ctx, attempt)
		if err == nil {
			return nil
		}
		// A response and cancellation can arrive together. Send layers may
		// deliberately stop marking the failure retryable once ctx is done;
		// preserve that cancellation before classifying the response or retry
		// budget. Keep confirmed success above, and keep both failure causes.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("syncretry: attempt %d stopped: %w: %w", attempt, ctxErr, err)
		}
		if !IsRetryable(err) {
			return err
		}
		if retriesUsed := attempt - 1; retriesUsed >= p.maxRetries {
			return fmt.Errorf(
				"%w: giving up after %d attempts (%d retries used of max %d): %w",
				ErrRetryExhausted, attempt, retriesUsed, p.maxRetries, err)
		}
		wait, hint, hasHint := p.nextWait(attempt, err)
		if deadline, ok := p.effectiveDeadline(ctx); ok {
			readyAt := p.clock.Now().Add(wait)
			if !readyAt.Before(deadline) {
				return fmt.Errorf(
					"%w: attempt %d could start no earlier than %s (required wait %s%s), past run deadline %s",
					ErrRetryPastDeadline, attempt+1,
					readyAt.Format(time.RFC3339), wait, hintSuffix(hint, hasHint),
					deadline.Format(time.RFC3339))
			}
		} else if wait > DefaultMaxDelay {
			return fmt.Errorf("%w: required wait %s exceeds the %s safety limit without a run deadline", ErrRetryPastDeadline, wait, DefaultMaxDelay)
		}
		if werr := p.clock.Wait(ctx, wait); werr != nil {
			return fmt.Errorf("syncretry: waiting %s before attempt %d: %w", wait, attempt+1, werr)
		}
	}
}

func hintSuffix(hint time.Duration, hasHint bool) string {
	if !hasHint {
		return ""
	}
	return fmt.Sprintf(", server Retry-After floor %s", hint)
}

// nextWait computes the delay before the retry that follows the failed
// attempt: the exponential backoff for that retry — jittered and capped
// — raised to the server Retry-After floor when the failure carries
// one.
func (p *Policy) nextWait(attempt int, err error) (wait, hint time.Duration, hasHint bool) {
	hint, hasHint = RetryAfterHint(err, p.clock.Now())
	wait = p.backoffFor(attempt)
	if hasHint && hint > wait {
		wait = hint
	}
	return wait, hint, hasHint
}

// backoffFor returns the jittered, capped backoff for the retry that
// follows the given failed attempt: the base for the first retry, the
// base doubled once per earlier retry.
func (p *Policy) backoffFor(attempt int) time.Duration {
	d := p.baseDelay
	for i := 1; i < attempt; i++ {
		if d >= p.maxDelay || d > math.MaxInt64/2 {
			break
		}
		d *= 2
	}
	if d > p.maxDelay {
		d = p.maxDelay
	}
	if p.jitter != nil {
		d = p.jitter(d)
		if d < 0 {
			d = 0
		}
		if d > p.maxDelay {
			d = p.maxDelay
		}
	}
	return d
}

// effectiveDeadline returns the earlier of the policy deadline and the
// context deadline, reporting whether any deadline exists.
func (p *Policy) effectiveDeadline(ctx context.Context) (time.Time, bool) {
	if !p.runDeadline.IsZero() {
		if d, ok := ctx.Deadline(); ok && d.Before(p.runDeadline) {
			return d, true
		}
		return p.runDeadline, true
	}
	return ctx.Deadline()
}
