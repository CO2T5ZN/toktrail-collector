package syncretry

// The syncbudget import below appears only in this demonstration test:
// it exercises the documented caller pattern (Reserve at the top of
// Send, before each actual send) against a real budget. The syncretry
// package itself never imports or reserves any budget.

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"toktrail-collector/internal/syncbudget"
)

var errTransient = errors.New("transient send failure")

func fixedNow() time.Time {
	return time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
}

// fakeClock replaces RealClock in tests: waits are recorded (and the
// fake "now" advanced) instead of slept through, and the wait behavior
// can be overridden to simulate cancellation races. All methods are
// safe under -race for a Do goroutine plus a test goroutine.
type fakeClock struct {
	mu    sync.Mutex
	now   time.Time
	waits []time.Duration
	wait  func(ctx context.Context, d time.Duration) error
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Wait(ctx context.Context, d time.Duration) error {
	c.mu.Lock()
	c.waits = append(c.waits, d)
	override := c.wait
	if override == nil {
		c.now = c.now.Add(d)
	}
	c.mu.Unlock()
	if override != nil {
		return override(ctx, d)
	}
	return ctx.Err()
}

func (c *fakeClock) recorded() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.waits...)
}

// sendRecorder records which attempts Send ran with.
type sendRecorder struct {
	mu   sync.Mutex
	seen []int
}

func (r *sendRecorder) record(attempt int) {
	r.mu.Lock()
	r.seen = append(r.seen, attempt)
	r.mu.Unlock()
}

// script returns a Send that records each attempt and replays
// outcomes: outcomes[i] is the error for attempt i+1, nil means
// success, and attempts beyond the script succeed.
func (r *sendRecorder) script(outcomes []error) Send {
	return func(ctx context.Context, attempt int) error {
		r.record(attempt)
		if attempt <= len(outcomes) {
			return outcomes[attempt-1]
		}
		return nil
	}
}

func (r *sendRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.seen)
}

func (r *sendRecorder) attempts() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int(nil), r.seen...)
}

// persistent returns n retryable failures, mimicking a send that keeps
// answering 5xx (the future HTTP adapter marks those Retryable).
func persistent(cause error, n int) []error {
	out := make([]error, n)
	for i := range out {
		out[i] = Retryable(cause)
	}
	return out
}

func TestDoSucceedsOnFirstAttempt(t *testing.T) {
	clock := newFakeClock(fixedNow())
	p := New(WithClock(clock))
	rec := &sendRecorder{}

	err := p.Do(context.Background(), rec.script(nil))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rec.count(); got != 1 {
		t.Fatalf("send calls = %d, want 1", got)
	}
	if got := rec.attempts(); !reflect.DeepEqual(got, []int{1}) {
		t.Fatalf("attempts = %v, want [1] (1-based)", got)
	}
	if waits := clock.recorded(); len(waits) != 0 {
		t.Fatalf("waits = %v, want none", waits)
	}
}

func TestDoRetriesTransientFailureThenSucceeds(t *testing.T) {
	// Two 5xx-shaped failures, then success.
	clock := newFakeClock(fixedNow())
	p := New(WithClock(clock))
	rec := &sendRecorder{}

	err := p.Do(context.Background(), rec.script([]error{
		Retryable(errors.New("500 internal server error")),
		Retryable(errors.New("502 bad gateway")),
	}))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rec.count(); got != 3 {
		t.Fatalf("send calls = %d, want 3", got)
	}
	if got := rec.attempts(); !reflect.DeepEqual(got, []int{1, 2, 3}) {
		t.Fatalf("attempts = %v, want [1 2 3]", got)
	}
	want := []time.Duration{time.Second, 2 * time.Second}
	if got := clock.recorded(); !reflect.DeepEqual(got, want) {
		t.Fatalf("waits = %v, want %v", got, want)
	}
}

func TestDoRetryBudgetBoundary(t *testing.T) {
	cause := errors.New("503 service unavailable")

	t.Run("default allows exactly three extra retries", func(t *testing.T) {
		clock := newFakeClock(fixedNow())
		p := New(WithClock(clock))
		rec := &sendRecorder{}

		err := p.Do(context.Background(), rec.script(persistent(cause, 4)))

		if err == nil {
			t.Fatal("want exhaustion error, got nil")
		}
		if !errors.Is(err, cause) {
			t.Fatalf("exhaustion must wrap the last send error: %v", err)
		}
		if got := rec.count(); got != 4 {
			t.Fatalf("send calls = %d, want 4 (initial + 3 retries)", got)
		}
		if got := rec.attempts(); !reflect.DeepEqual(got, []int{1, 2, 3, 4}) {
			t.Fatalf("attempts = %v, want [1 2 3 4]", got)
		}
		want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
		if got := clock.recorded(); !reflect.DeepEqual(got, want) {
			t.Fatalf("waits = %v, want %v", got, want)
		}
		for _, s := range []string{"4 attempts", "max 3"} {
			if !strings.Contains(err.Error(), s) {
				t.Errorf("error %q missing %q", err, s)
			}
		}
	})

	t.Run("zero retries means a single attempt", func(t *testing.T) {
		clock := newFakeClock(fixedNow())
		p := New(WithClock(clock), WithMaxRetries(0))
		rec := &sendRecorder{}

		err := p.Do(context.Background(), rec.script(persistent(cause, 1)))

		if !errors.Is(err, cause) {
			t.Fatalf("error = %v, want wrapped cause", err)
		}
		if got := rec.count(); got != 1 {
			t.Fatalf("send calls = %d, want 1", got)
		}
		if waits := clock.recorded(); len(waits) != 0 {
			t.Fatalf("waits = %v, want none", waits)
		}
	})

	t.Run("one retry", func(t *testing.T) {
		clock := newFakeClock(fixedNow())
		p := New(WithClock(clock), WithMaxRetries(1))
		rec := &sendRecorder{}

		err := p.Do(context.Background(), rec.script(persistent(cause, 2)))

		if !errors.Is(err, cause) {
			t.Fatalf("error = %v, want wrapped cause", err)
		}
		if got := rec.count(); got != 2 {
			t.Fatalf("send calls = %d, want 2", got)
		}
		want := []time.Duration{time.Second}
		if got := clock.recorded(); !reflect.DeepEqual(got, want) {
			t.Fatalf("waits = %v, want %v", got, want)
		}
	})
}

func TestDoFinalErrorReturnsImmediately(t *testing.T) {
	t.Run("first attempt final", func(t *testing.T) {
		sentinel := errors.New("400 bad request")
		clock := newFakeClock(fixedNow())
		p := New(WithClock(clock))
		rec := &sendRecorder{}

		err := p.Do(context.Background(), rec.script([]error{sentinel}))

		if err != sentinel {
			t.Fatalf("final error must be returned unchanged: %v", err)
		}
		if got := rec.count(); got != 1 {
			t.Fatalf("send calls = %d, want 1", got)
		}
		if waits := clock.recorded(); len(waits) != 0 {
			t.Fatalf("waits = %v, want none", waits)
		}
	})

	t.Run("final after a retryable failure", func(t *testing.T) {
		sentinel := errors.New("409 conflict")
		clock := newFakeClock(fixedNow())
		p := New(WithClock(clock))
		rec := &sendRecorder{}

		err := p.Do(context.Background(), rec.script([]error{Retryable(errTransient), sentinel}))

		if err != sentinel {
			t.Fatalf("final error must be returned unchanged: %v", err)
		}
		if got := rec.count(); got != 2 {
			t.Fatalf("send calls = %d, want 2", got)
		}
		want := []time.Duration{time.Second}
		if got := clock.recorded(); !reflect.DeepEqual(got, want) {
			t.Fatalf("waits = %v, want %v", got, want)
		}
	})
}

func TestDo429RetryAfterSeconds(t *testing.T) {
	clock := newFakeClock(fixedNow())
	p := New(WithClock(clock), WithRunDeadline(fixedNow().Add(3*time.Minute)))
	rec := &sendRecorder{}

	err := p.Do(context.Background(), rec.script([]error{
		RetryAfterHeader(errors.New("429 too many requests"), "120"),
	}))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []time.Duration{2 * time.Minute}
	if got := clock.recorded(); !reflect.DeepEqual(got, want) {
		t.Fatalf("waits = %v, want %v (Retry-After is a floor over the 1s backoff)", got, want)
	}
}

func TestDo429RetryAfterHTTPDate(t *testing.T) {
	now := fixedNow()

	t.Run("future date sets the floor", func(t *testing.T) {
		clock := newFakeClock(now)
		p := New(WithClock(clock), WithRunDeadline(now.Add(2*time.Minute)))
		rec := &sendRecorder{}
		header := now.Add(45 * time.Second).UTC().Format(time.RFC1123)

		err := p.Do(context.Background(), rec.script([]error{
			RetryAfterHeader(errors.New("429 too many requests"), header),
		}))

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []time.Duration{45 * time.Second}
		if got := clock.recorded(); !reflect.DeepEqual(got, want) {
			t.Fatalf("waits = %v, want %v", got, want)
		}
	})

	t.Run("past date means no floor beyond backoff", func(t *testing.T) {
		clock := newFakeClock(now)
		p := New(WithClock(clock))
		rec := &sendRecorder{}
		header := now.Add(-time.Hour).UTC().Format(time.RFC1123)

		err := p.Do(context.Background(), rec.script([]error{
			RetryAfterHeader(errors.New("429 too many requests"), header),
		}))

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []time.Duration{time.Second}
		if got := clock.recorded(); !reflect.DeepEqual(got, want) {
			t.Fatalf("waits = %v, want %v", got, want)
		}
	})

	t.Run("malformed value is ignored", func(t *testing.T) {
		clock := newFakeClock(now)
		p := New(WithClock(clock))
		rec := &sendRecorder{}

		err := p.Do(context.Background(), rec.script([]error{
			RetryAfterHeader(errors.New("429 too many requests"), "soon"),
		}))

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []time.Duration{time.Second}
		if got := clock.recorded(); !reflect.DeepEqual(got, want) {
			t.Fatalf("waits = %v, want %v", got, want)
		}
	})
}

func TestDoRetryAfterFloorDoesNotShortenBackoff(t *testing.T) {
	// A 500ms floor must not make the policy retry earlier than its own
	// 1s backoff: the hint is a floor, never a ceiling.
	clock := newFakeClock(fixedNow())
	p := New(WithClock(clock))
	rec := &sendRecorder{}

	err := p.Do(context.Background(), rec.script([]error{
		RetryAfter(errTransient, 500*time.Millisecond),
		RetryAfter(errTransient, 500*time.Millisecond),
	}))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []time.Duration{time.Second, 2 * time.Second}
	if got := clock.recorded(); !reflect.DeepEqual(got, want) {
		t.Fatalf("waits = %v, want %v", got, want)
	}
}

func TestDoRetryAfterOverDeadlineFailsWithoutWaiting(t *testing.T) {
	now := fixedNow()

	t.Run("server hint exceeds the remaining run deadline", func(t *testing.T) {
		clock := newFakeClock(now)
		p := New(WithClock(clock), WithRunDeadline(now.Add(60*time.Second)))
		rec := &sendRecorder{}

		err := p.Do(context.Background(), rec.script([]error{
			RetryAfterHeader(errors.New("429 too many requests"), "120"),
		}))

		if !errors.Is(err, ErrRetryPastDeadline) {
			t.Fatalf("error = %v, want ErrRetryPastDeadline", err)
		}
		for _, want := range []string{"2m0s", "Retry-After floor", "run deadline"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q missing %q", err, want)
			}
		}
		if waits := clock.recorded(); len(waits) != 0 {
			t.Fatalf("must fail fast without waiting, waited %v", waits)
		}
		if got := rec.count(); got != 1 {
			t.Fatalf("send calls = %d, want 1", got)
		}
	})

	t.Run("absurd hint saturates instead of wrapping negative", func(t *testing.T) {
		clock := newFakeClock(now)
		p := New(WithClock(clock), WithRunDeadline(now.Add(time.Hour)))
		rec := &sendRecorder{}

		err := p.Do(context.Background(), rec.script([]error{
			RetryAfterHeader(errors.New("429 too many requests"), "10000000000"),
		}))

		if !errors.Is(err, ErrRetryPastDeadline) {
			t.Fatalf("error = %v, want ErrRetryPastDeadline", err)
		}
		if waits := clock.recorded(); len(waits) != 0 {
			t.Fatalf("must fail fast without waiting, waited %v", waits)
		}
	})
}

func TestDoBackoffOverDeadlineFailsWithoutWaiting(t *testing.T) {
	// Even without a server hint, a 1s backoff that cannot fit before
	// the deadline stops without sleeping.
	now := fixedNow()
	clock := newFakeClock(now)
	p := New(WithClock(clock), WithRunDeadline(now.Add(500*time.Millisecond)))
	rec := &sendRecorder{}

	err := p.Do(context.Background(), rec.script(persistent(errTransient, 1)))

	if !errors.Is(err, ErrRetryPastDeadline) {
		t.Fatalf("error = %v, want ErrRetryPastDeadline", err)
	}
	if !strings.Contains(err.Error(), "required wait 1s") {
		t.Errorf("error %q must name the wait that did not fit", err)
	}
	if waits := clock.recorded(); len(waits) != 0 {
		t.Fatalf("must fail fast without waiting, waited %v", waits)
	}
	if got := rec.count(); got != 1 {
		t.Fatalf("send calls = %d, want 1", got)
	}
}

func TestDoDeadlineIsEarliestOfOptionAndContext(t *testing.T) {
	// base is a real instant so the context deadline below is a real
	// one; the fake clock starts at the same instant, and the margins
	// (30s/60s/120s) dwarf any drift between the two readings.
	base := time.Now()
	over := []error{RetryAfterHeader(errors.New("429 too many requests"), "120")}

	t.Run("policy deadline earlier than context deadline", func(t *testing.T) {
		clock := newFakeClock(base)
		ctx, cancel := context.WithDeadline(context.Background(), base.Add(time.Hour))
		defer cancel()
		p := New(WithClock(clock), WithRunDeadline(base.Add(30*time.Second)))
		rec := &sendRecorder{}

		err := p.Do(ctx, rec.script(over))

		if !errors.Is(err, ErrRetryPastDeadline) {
			t.Fatalf("error = %v, want ErrRetryPastDeadline", err)
		}
		if waits := clock.recorded(); len(waits) != 0 {
			t.Fatalf("waits = %v, want none", waits)
		}
	})

	t.Run("context deadline earlier than policy deadline", func(t *testing.T) {
		clock := newFakeClock(base)
		ctx, cancel := context.WithDeadline(context.Background(), base.Add(30*time.Second))
		defer cancel()
		p := New(WithClock(clock), WithRunDeadline(base.Add(time.Hour)))
		rec := &sendRecorder{}

		err := p.Do(ctx, rec.script(over))

		if !errors.Is(err, ErrRetryPastDeadline) {
			t.Fatalf("error = %v, want ErrRetryPastDeadline", err)
		}
		if waits := clock.recorded(); len(waits) != 0 {
			t.Fatalf("waits = %v, want none", waits)
		}
	})
}

func TestDoContextCanceledDuringWait(t *testing.T) {
	// External cancellation while waiting must surface as
	// errors.Is(err, context.Canceled) and must not start another send.
	clock := newFakeClock(fixedNow())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock.wait = func(ctx context.Context, d time.Duration) error {
		<-ctx.Done() // a wait that only cancellation can end
		return ctx.Err()
	}
	p := New(WithClock(clock))
	rec := &sendRecorder{}
	firstAttempt := make(chan struct{})
	send := func(ctx context.Context, attempt int) error {
		rec.record(attempt)
		if attempt == 1 {
			close(firstAttempt)
		}
		return Retryable(errTransient)
	}

	result := make(chan error, 1)
	go func() { result <- p.Do(ctx, send) }()

	<-firstAttempt
	cancel()
	err := <-result

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if got := rec.count(); got != 1 {
		t.Fatalf("send calls = %d, want 1: no attempt after cancellation", got)
	}
}

func TestDoContextCanceledAfterWaitBeforeAttempt(t *testing.T) {
	// The wait "finished" at the same instant the context was canceled:
	// the next attempt must not start.
	clock := newFakeClock(fixedNow())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock.wait = func(ctx context.Context, d time.Duration) error {
		cancel()
		return nil
	}
	p := New(WithClock(clock))
	rec := &sendRecorder{}

	err := p.Do(ctx, rec.script(persistent(errTransient, 4)))

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if got := rec.count(); got != 1 {
		t.Fatalf("send calls = %d, want 1", got)
	}
}

func TestDoContextCanceledBeforeFirstAttempt(t *testing.T) {
	clock := newFakeClock(fixedNow())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := New(WithClock(clock))
	rec := &sendRecorder{}

	err := p.Do(ctx, rec.script(nil))

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if got := rec.count(); got != 0 {
		t.Fatalf("send calls = %d, want 0", got)
	}
	if waits := clock.recorded(); len(waits) != 0 {
		t.Fatalf("waits = %v, want none", waits)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := fixedNow()
	cases := []struct {
		name string
		in   string
		wait time.Duration
		ok   bool
	}{
		{"zero seconds", "0", 0, true},
		{"delay-seconds", "120", 2 * time.Minute, true},
		{"whitespace tolerated", "  60  ", time.Minute, true},
		{"leading sign tolerated", "+30", 30 * time.Second, true},
		{"negative is invalid", "-1", 0, false},
		{"fraction is invalid", "1.5", 0, false},
		{"not a number or date", "soon", 0, false},
		{"empty", "", 0, false},
		{"blank", "   ", 0, false},
		{"http-date rfc1123", now.Add(90 * time.Second).UTC().Format(time.RFC1123), 90 * time.Second, true},
		{"http-date in the past", now.Add(-time.Hour).UTC().Format(time.RFC1123), 0, true},
		{"http-date rfc850 before now", "Wednesday, 21-Oct-15 07:28:00 GMT", 0, true},
		{"http-date ansic before now", "Wed Oct 21 07:28:00 2015", 0, true},
		{"seconds beyond int64", "99999999999999999999", time.Duration(math.MaxInt64), true},
		{"seconds saturating duration", "10000000000", time.Duration(math.MaxInt64), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wait, ok := ParseRetryAfter(now, tc.in)
			if ok != tc.ok || wait != tc.wait {
				t.Fatalf("ParseRetryAfter(now, %q) = (%s, %t), want (%s, %t)",
					tc.in, wait, ok, tc.wait, tc.ok)
			}
		})
	}
}

func TestJitterTransformsBackoffWithinCap(t *testing.T) {
	t.Run("half added", func(t *testing.T) {
		clock := newFakeClock(fixedNow())
		p := New(WithClock(clock), WithMaxRetries(6),
			WithJitter(func(d time.Duration) time.Duration { return d + d/2 }))
		rec := &sendRecorder{}

		err := p.Do(context.Background(), rec.script(persistent(errTransient, 7)))

		if err == nil {
			t.Fatal("want exhaustion error")
		}
		// Raw backoffs 1,2,4,8,16,30(capped); +50% jitter gives
		// 1.5,3,6,12,24,45 — and the 45 is clamped back to the 30s cap.
		want := []time.Duration{
			1500 * time.Millisecond, 3 * time.Second, 6 * time.Second,
			12 * time.Second, 24 * time.Second, 30 * time.Second,
		}
		if got := clock.recorded(); !reflect.DeepEqual(got, want) {
			t.Fatalf("waits = %v, want %v", got, want)
		}
	})

	t.Run("negative result clamps to zero", func(t *testing.T) {
		clock := newFakeClock(fixedNow())
		p := New(WithClock(clock), WithMaxRetries(1),
			WithJitter(func(d time.Duration) time.Duration { return -time.Minute }))
		rec := &sendRecorder{}

		err := p.Do(context.Background(), rec.script(persistent(errTransient, 2)))

		if err == nil {
			t.Fatal("want exhaustion error")
		}
		want := []time.Duration{0}
		if got := clock.recorded(); !reflect.DeepEqual(got, want) {
			t.Fatalf("waits = %v, want %v", got, want)
		}
	})
}

func TestRetryMarkersAndHints(t *testing.T) {
	now := fixedNow()
	httpDate := now.Add(45 * time.Second).UTC().Format(time.RFC1123)

	if IsRetryable(errTransient) {
		t.Fatal("plain error must not be retryable")
	}
	if _, ok := RetryAfterHint(errTransient, now); ok {
		t.Fatal("plain error carries no hint")
	}

	plain := Retryable(errTransient)
	if !IsRetryable(plain) {
		t.Fatal("Retryable must mark retryable")
	}
	if _, ok := RetryAfterHint(plain, now); ok {
		t.Fatal("Retryable carries no hint")
	}
	if !errors.Is(plain, errTransient) {
		t.Fatal("Retryable must stay errors.Is-compatible with its cause")
	}

	if hint, ok := RetryAfterHint(RetryAfter(errTransient, 5*time.Second), now); !ok || hint != 5*time.Second {
		t.Fatalf("direct hint = (%s, %t), want (5s, true)", hint, ok)
	}
	if hint, ok := RetryAfterHint(RetryAfterHeader(errTransient, "90"), now); !ok || hint != 90*time.Second {
		t.Fatalf("header hint = (%s, %t), want (1m30s, true)", hint, ok)
	}
	if hint, ok := RetryAfterHint(RetryAfterHeader(errTransient, httpDate), now); !ok || hint != 45*time.Second {
		t.Fatalf("http-date hint = (%s, %t), want (45s, true)", hint, ok)
	}

	wrapped := fmt.Errorf("upload batch 42: %w", RetryAfterHeader(errTransient, "30"))
	if !IsRetryable(wrapped) {
		t.Fatal("wrapped marker must stay retryable")
	}
	if hint, ok := RetryAfterHint(wrapped, now); !ok || hint != 30*time.Second {
		t.Fatalf("wrapped hint = (%s, %t), want (30s, true)", hint, ok)
	}
	if !errors.Is(wrapped, errTransient) {
		t.Fatal("wrapped marker must stay errors.Is-compatible with its cause")
	}

	// The shallowest marker wins; within it, the larger floor wins.
	both := RetryAfter(RetryAfterHeader(errTransient, "30"), 45*time.Second)
	if hint, ok := RetryAfterHint(both, now); !ok || hint != 45*time.Second {
		t.Fatalf("combined hint = (%s, %t), want (45s, true)", hint, ok)
	}

	for _, e := range []error{
		RetryAfter(errTransient, 0),
		RetryAfter(errTransient, -time.Second),
		RetryAfterHeader(errTransient, "   "),
	} {
		if _, ok := RetryAfterHint(e, now); ok {
			t.Fatalf("non-positive floors must be no hint at all: %v", e)
		}
	}

	if Retryable(nil) != nil || RetryAfter(nil, time.Second) != nil || RetryAfterHeader(nil, "5") != nil {
		t.Fatal("nil errors must stay nil")
	}

	// The human message states retryability and that a hint was
	// supplied, but never echoes the raw header value itself — it is
	// untrusted server text.
	if s := RetryAfterHeader(errTransient, "120").Error(); !strings.Contains(s, "retryable") || !strings.Contains(s, "Retry-After supplied") || strings.Contains(s, "120") {
		t.Fatalf("error string %q must mention retryability and the supplied hint without echoing the header", s)
	}
}

func TestBudgetReservedBeforeEverySend(t *testing.T) {
	// Demonstrates the API's intended wiring for per-attempt budget
	// gating: the caller Reserves at the top of Send — before the actual
	// network send would run — and returns declines as plain errors,
	// which the policy treats as final. syncretry itself never touches
	// syncbudget, so the reservation stays in the run's accounting.
	budget := syncbudget.New(syncbudget.WithTotal(2))
	clock := newFakeClock(fixedNow())
	p := New(WithClock(clock))
	rec := &sendRecorder{}

	err := p.Do(context.Background(), func(ctx context.Context, attempt int) error {
		rec.record(attempt)
		if err := budget.Reserve(ctx, "upload"); err != nil {
			return err // plain, non-retryable: stop the whole run
		}
		return Retryable(errors.New("503 service unavailable")) // the reserved attempt failed
	})

	if !errors.Is(err, syncbudget.ErrTotalExhausted) {
		t.Fatalf("error = %v, want syncbudget.ErrTotalExhausted", err)
	}
	if got := rec.attempts(); !reflect.DeepEqual(got, []int{1, 2, 3}) {
		t.Fatalf("attempts = %v, want [1 2 3]", got)
	}
	want := []time.Duration{time.Second, 2 * time.Second}
	if got := clock.recorded(); !reflect.DeepEqual(got, want) {
		t.Fatalf("waits = %v, want %v (no wait after the decline)", got, want)
	}
	if budget.Used() != 2 {
		t.Fatalf("budget used = %d, want 2", budget.Used())
	}
}

func TestDoRejectsNilArguments(t *testing.T) {
	if err := New().Do(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "nil send") {
		t.Fatalf("nil send: %v", err)
	}
	var p *Policy
	if err := p.Do(context.Background(), func(context.Context, int) error { return nil }); err == nil || !strings.Contains(err.Error(), "nil policy") {
		t.Fatalf("nil policy: %v", err)
	}
}

func TestOptionClamping(t *testing.T) {
	p := New(
		WithMaxRetries(-2),
		WithBaseDelay(-time.Second),
		WithMaxDelay(-time.Minute),
		WithClock(nil),
		WithJitter(nil),
	)
	if p.maxRetries != 0 {
		t.Fatalf("maxRetries = %d, want 0", p.maxRetries)
	}
	if p.baseDelay != 0 {
		t.Fatalf("baseDelay = %s, want 0", p.baseDelay)
	}
	if p.maxDelay != 0 {
		t.Fatalf("maxDelay = %s, want 0", p.maxDelay)
	}
	if _, ok := p.clock.(RealClock); !ok {
		t.Fatalf("clock = %T, want RealClock", p.clock)
	}
	if p.jitter != nil {
		t.Fatal("jitter must stay nil")
	}
}
