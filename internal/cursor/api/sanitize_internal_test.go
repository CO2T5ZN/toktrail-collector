package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

// sanitizeTestToken is the synthetic session-token stand-in used by these
// unit tests.
const sanitizeTestToken = "user_secret1234%3A%3Ajwt.value"

// TestSanitizeTokenRedactsMessageKeepsCauseChain verifies the redaction
// contract: a secret-bearing error renders redacted (normal logging —
// fmt %v/%+v, log, %w-wrapping — prints only the outer message and never
// the chain), while the original cause stays reachable through Unwrap so
// every errors.Is/As contract of the wrapped error survives.
func TestSanitizeTokenRedactsMessageKeepsCauseChain(t *testing.T) {
	secret := fmt.Errorf("request to https://cursor.com/api with cookie %s failed: %w", sanitizeTestToken, context.DeadlineExceeded)

	sanitized := sanitizeToken(secret, sanitizeTestToken)

	if strings.Contains(sanitized.Error(), sanitizeTestToken) {
		t.Fatalf("message must be redacted: %q", sanitized.Error())
	}
	if !strings.Contains(sanitized.Error(), "[REDACTED]") {
		t.Fatalf("message must mark the redaction: %q", sanitized.Error())
	}
	// Normal logging renders only the outer message: both %v and the
	// verbose %+v stay redacted — fmt never walks an error's chain.
	for _, rendered := range []string{fmt.Sprintf("%v", sanitized), fmt.Sprintf("%+v", sanitized)} {
		if strings.Contains(rendered, sanitizeTestToken) {
			t.Fatalf("formatting must never render the cause chain: %q", rendered)
		}
	}
	// The cause stays reachable and IS the original secret-bearing error.
	if errors.Unwrap(sanitized) != secret {
		t.Fatal("the original cause must stay reachable through Unwrap")
	}
	// Sentinel classification survives through the kept chain.
	if !errors.Is(sanitized, context.DeadlineExceeded) {
		t.Fatal("deadline sentinel must stay detectable through Is")
	}
	if errors.Is(sanitized, context.Canceled) {
		t.Fatal("a deadline error must not report cancellation")
	}

	canceled := fmt.Errorf("post with %s: %w", sanitizeTestToken, context.Canceled)
	sanitizedCanceled := sanitizeToken(canceled, sanitizeTestToken)
	if !errors.Is(sanitizedCanceled, context.Canceled) {
		t.Fatal("cancellation sentinel must stay detectable through Is")
	}
	if errors.Is(sanitizedCanceled, context.DeadlineExceeded) {
		t.Fatal("a cancellation error must not report a deadline")
	}
	if errors.Unwrap(sanitizedCanceled) != canceled {
		t.Fatal("the original cause must stay reachable through Unwrap")
	}
}

// TestSanitizeTokenKeepsSentinelClassificationWithTokenBearingErrors is
// the classification-loss regression the wrapper exists for: a
// token-bearing error that also carries an authorization sentinel or a
// net.Error shape keeps BOTH — the message redacts, while the Is/As
// semantics of the unredacted error survive exactly. The previous
// drop-the-cause behavior stripped these and would have mis-classified
// the failure (for example, an expired login read as a hard error).
func TestSanitizeTokenKeepsSentinelClassificationWithTokenBearingErrors(t *testing.T) {
	t.Run("authorization sentinel survives", func(t *testing.T) {
		bearing := fmt.Errorf("cursor api: credential rejected with %s: %w", sanitizeTestToken, ErrSessionExpired)
		sanitized := sanitizeToken(bearing, sanitizeTestToken)
		if strings.Contains(sanitized.Error(), sanitizeTestToken) {
			t.Fatalf("message must be redacted: %q", sanitized.Error())
		}
		if !errors.Is(sanitized, ErrSessionExpired) {
			t.Fatalf("ErrSessionExpired must survive the redaction, got %v", sanitized)
		}
	})

	t.Run("custom net.Error survives As", func(t *testing.T) {
		netErr := &fakeNetError{msg: "dial " + sanitizeTestToken + " refused", timeout: true}
		bearing := fmt.Errorf("cursor api: request failed: %w", netErr)
		sanitized := sanitizeToken(bearing, sanitizeTestToken)
		if strings.Contains(sanitized.Error(), sanitizeTestToken) {
			t.Fatalf("message must be redacted: %q", sanitized.Error())
		}
		var found net.Error
		if !errors.As(sanitized, &found) {
			t.Fatalf("the net.Error shape must stay reachable through As, got %v", sanitized)
		}
		if !found.Timeout() {
			t.Fatal("the net.Error's own classification must survive As")
		}
		// Normal logging still prints only the redacted outer text; the
		// cause's raw message is reachable solely through the explicit
		// As/Unwrap traversal above, never through formatting.
		if strings.Contains(fmt.Sprintf("%v", sanitized), sanitizeTestToken) {
			t.Fatalf("formatting must never render the cause: %v", sanitized)
		}
	})

	t.Run("double sanitization is stable", func(t *testing.T) {
		bearing := fmt.Errorf("cursor api: request failed with %s: %w", sanitizeTestToken, context.Canceled)
		once := sanitizeToken(bearing, sanitizeTestToken)
		twice := sanitizeToken(once, sanitizeTestToken)
		if once != twice {
			t.Fatal("an already-redacted error must pass through the second layer unchanged")
		}
		if !errors.Is(twice, context.Canceled) {
			t.Fatal("the sentinel must survive both layers")
		}
	})
}

// fakeNetError is a synthetic net.Error carrying token-shaped text,
// standing in for a transport failure whose message reflected the
// credential.
type fakeNetError struct {
	msg     string
	timeout bool
}

func (e *fakeNetError) Error() string   { return e.msg }
func (e *fakeNetError) Timeout() bool   { return e.timeout }
func (e *fakeNetError) Temporary() bool { return e.timeout }

// TestSanitizeTokenKeepsCleanChainsIntact verifies that errors carrying no
// token pass through untouched, preserving their full chain.
func TestSanitizeTokenKeepsCleanChainsIntact(t *testing.T) {
	clean := fmt.Errorf("request failed: %w", context.DeadlineExceeded)
	if got := sanitizeToken(clean, sanitizeTestToken); got != clean {
		t.Fatal("a clean error must be returned unchanged")
	}
	if !errors.Is(clean, context.DeadlineExceeded) || errors.Unwrap(clean) == nil {
		t.Fatal("the clean chain must stay intact")
	}
}
