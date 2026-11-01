package syncretry

import (
	"errors"
	"math"
	"strconv"
	"strings"
	"time"
)

// httpDateFormats are the three layouts RFC 9110 permits for HTTP-date,
// in the order net/http accepts them.
var httpDateFormats = []string{time.RFC1123, time.RFC850, time.ANSIC}

// ParseRetryAfter parses a standard Retry-After value: either
// delay-seconds ("120") or an HTTP-date
// ("Wed, 21 Oct 2015 07:28:00 GMT") interpreted relative to now.
//
// It reports ok=false for empty, negative, or malformed values; callers
// treat those as "no hint", matching the RFC's
// leniency toward unparseable header values. An HTTP-date in the past
// yields a zero wait. Delay-seconds large enough to overflow a Duration
// saturate at the largest representable wait instead of wrapping
// negative.
func ParseRetryAfter(now time.Time, value string) (time.Duration, bool) {
	v := strings.TrimSpace(value)
	if v == "" {
		return 0, false
	}
	seconds := strings.TrimPrefix(v, "+")
	if seconds != "" && strings.Trim(seconds, "0123456789") == "" {
		secs, err := strconv.ParseUint(seconds, 10, 64)
		if err != nil {
			if errors.Is(err, strconv.ErrRange) {
				return time.Duration(math.MaxInt64), true
			}
			return 0, false
		}
		if secs > uint64(math.MaxInt64)/uint64(time.Second) {
			return time.Duration(math.MaxInt64), true
		}
		return time.Duration(secs) * time.Second, true
	}
	for _, layout := range httpDateFormats {
		if t, err := time.Parse(layout, v); err == nil {
			wait := t.Sub(now)
			if wait < 0 {
				wait = 0
			}
			return wait, true
		}
	}
	return 0, false
}
