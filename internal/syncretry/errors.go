package syncretry

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrRetryPastDeadline reports that the policy stopped without waiting:
// honoring the required delay — the computed backoff, or more often a
// server Retry-After floor — would start the next attempt after the run
// deadline (the earlier of WithRunDeadline and the context deadline).
// The wrapping message names the wait, the earliest allowed start, and
// the deadline it would pass.
var ErrRetryPastDeadline = errors.New("syncretry: next retry would pass the run deadline")

// ErrRetryExhausted reports that a retryable failure outlived the retry
// budget: the send was attempted the maximum number of times and the
// last failure is still marked retryable. The exhaustion error wraps
// the last send error, so errors.Is keeps matching the original cause
// (and any sentinel it carries) alongside this one. It is deliberately
// distinct from ErrRetryPastDeadline — a deadline stop happens before
// an attempt is made, an exhaustion stop happens after the budget of
// retries was spent on real attempts.
var ErrRetryExhausted = errors.New("syncretry: retries exhausted")

// retryError marks a send failure as retryable and may carry the
// server's minimum-wait hint, either as a duration or as the raw value
// of a Retry-After header. The raw form is parsed against the policy
// clock when the wait is computed, so HTTP-date values are interpreted
// with the same — possibly injected — clock as every other policy
// decision.
type retryError struct {
	err     error
	minWait time.Duration
	header  string
}

// Error never echoes the raw Retry-After header: its value is untrusted
// server text — a hostile endpoint can put anything there, including
// echoed credentials, and even a plausible-looking number can be a
// secret — so the human message states only that a hint was supplied.
// The raw header stays on the struct solely for RetryAfterHint, which
// parses it against the policy clock; call sites must not pre-filter or
// pre-parse it against any other clock.
func (e *retryError) Error() string {
	switch {
	case e.header != "":
		return "retryable (Retry-After supplied): " + e.err.Error()
	case e.minWait > 0:
		return fmt.Sprintf("retryable (retry after %s): %v", e.minWait, e.err)
	default:
		return fmt.Sprintf("retryable: %v", e.err)
	}
}

func (e *retryError) Unwrap() error { return e.err }

// Retryable marks err as retryable under the policy: the failure is
// assumed transient and the next attempt waits out the computed
// backoff. A nil err returns nil.
func Retryable(err error) error {
	if err == nil {
		return nil
	}
	return &retryError{err: err}
}

// RetryAfter marks err as retryable with a minimum wait the server
// asked for. The next attempt waits at least wait — and the computed
// backoff when that is larger. A non-positive wait behaves exactly like
// Retryable. A nil err returns nil.
func RetryAfter(err error, wait time.Duration) error {
	if err == nil {
		return nil
	}
	if wait < 0 {
		wait = 0
	}
	return &retryError{err: err, minWait: wait}
}

// RetryAfterHeader marks err as retryable and carries the raw value of
// a standard Retry-After header — delay-seconds ("120") or HTTP-date
// ("Wed, 21 Oct 2015 07:28:00 GMT"). The value is untrusted server
// text: it is never echoed into the error's human message (see
// retryError.Error), and it is parsed only by RetryAfterHint against
// the policy clock — callers must not pre-filter or pre-parse it
// against any other clock. Empty or malformed values are ignored,
// leaving plain Retryable semantics, which matches the RFC's leniency
// toward unparseable header values. A nil err returns nil.
func RetryAfterHeader(err error, header string) error {
	if err == nil {
		return nil
	}
	return &retryError{err: err, header: strings.TrimSpace(header)}
}

// IsRetryable reports whether err, or any error it wraps, was marked
// retryable with Retryable, RetryAfter, or RetryAfterHeader.
func IsRetryable(err error) bool {
	var re *retryError
	return errors.As(err, &re)
}

// RetryAfterHint reports the minimum server-requested wait carried by
// err: the hint of the shallowest retry marker in its chain, taking the
// larger of a direct RetryAfter duration and a parsed Retry-After
// header value. ok is false when err carries no usable hint.
func RetryAfterHint(err error, now time.Time) (time.Duration, bool) {
	var re *retryError
	if !errors.As(err, &re) {
		return 0, false
	}
	hint := re.minWait
	if re.header != "" {
		if d, ok := ParseRetryAfter(now, re.header); ok && d > hint {
			hint = d
		}
	}
	if hint <= 0 {
		return 0, false
	}
	return hint, true
}
