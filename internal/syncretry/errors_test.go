package syncretry

// Security regression tests for retryError's human message: the raw
// Retry-After header value is untrusted server text — a hostile endpoint
// can put anything there, including echoed credentials — so the error
// string must state only that a hint was supplied, while RetryAfterHint
// keeps parsing the raw value against the policy clock and the marker's
// errors.Is/As behavior and the policy's wait behavior stay untouched.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const hostileHeader = "Bearer dev-1.TOPSECRET-credential-echo-0123456789abcdef"

func TestRetryErrorMessageNeverEchoesRetryAfterHeader(t *testing.T) {
	inner := errors.New("transient send failure")
	for _, header := range []string{
		"120",
		hostileHeader,
		"Wed, 21 Oct 2015 07:28:00 GMT",
		"garbage \x00 %s \"quoted\"",
	} {
		marked := RetryAfterHeader(inner, header)
		if marked == nil {
			t.Fatal("marker must not be nil")
		}
		got := marked.Error()
		want := "retryable (Retry-After supplied): transient send failure"
		if got != want {
			t.Fatalf("header %q: error string = %q, want the fixed %q", header, got, want)
		}
		if strings.Contains(got, header) {
			t.Fatalf("header %q leaked into: %s", header, got)
		}
	}
	// The duration form keeps its typed, bounded rendering.
	if got := RetryAfter(inner, 90*time.Second).Error(); got != "retryable (retry after 1m30s): transient send failure" {
		t.Fatalf("duration marker text = %q", got)
	}
	if got := Retryable(inner).Error(); got != "retryable: transient send failure" {
		t.Fatalf("plain marker text = %q", got)
	}
}

func TestRetryAfterHeaderHintStillParsedFromRawValue(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	inner := errors.New("throttled")

	// Delay-seconds parse against the given clock.
	if hint, ok := RetryAfterHint(RetryAfterHeader(inner, "120"), now); !ok || hint != 2*time.Minute {
		t.Fatalf("delay-seconds hint = (%s, %t), want (2m0s, true)", hint, ok)
	}
	// HTTP-date parse against the given clock.
	if hint, ok := RetryAfterHint(RetryAfterHeader(inner, "Wed, 31 Oct 2026 12:00:30 GMT"), now); !ok || hint != 30*time.Second {
		t.Fatalf("http-date hint = (%s, %t), want (30s, true)", hint, ok)
	}
	// Malformed values carry no hint, leaving plain retryable waits.
	if _, ok := RetryAfterHint(RetryAfterHeader(inner, hostileHeader), now); ok {
		t.Fatal("a hostile header must not produce a hint")
	}
	// The explicit duration form still works and wins the max.
	both := RetryAfter(RetryAfterHeader(inner, "30"), 45*time.Second)
	if hint, ok := RetryAfterHint(both, now); !ok || hint != 45*time.Second {
		t.Fatalf("combined hint = (%s, %t), want (45s, true)", hint, ok)
	}
}

func TestRetryMarkerIdentityAndPolicyWaitUnchanged(t *testing.T) {
	inner := errors.New("throttled")
	marked := RetryAfterHeader(inner, "1")
	if !errors.Is(marked, inner) {
		t.Fatal("marker must stay errors.Is-compatible with its cause")
	}
	if !IsRetryable(marked) {
		t.Fatal("marker must classify as retryable")
	}

	// End to end: the policy still honors a legitimate 1s floor parsed
	// from the raw header against the policy clock.
	clock := newFakeClock(time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC))
	p := New(WithClock(clock), WithBaseDelay(0))
	calls := 0
	if err := p.Do(context.Background(), func(ctx context.Context, attempt int) error {
		calls++
		if attempt == 1 {
			return RetryAfterHeader(inner, "1")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("attempts = %d, want 2", calls)
	}
	waits := clock.recorded()
	if len(waits) != 1 || waits[0] != 1*time.Second {
		t.Fatalf("waits = %v, want the header's 1s floor", waits)
	}
}
