// Retry classification for the cursor source-batch send path
// (Options.ClassifyRetryable): which failures carry a syncretry marker so
// an opted-in policy may retry them, and which stay final. The decision
// table mirrors the device-batch send path (internal/syncclient): only
// network-shaped transport failures under a still-live caller context,
// HTTP 429/500/502/503/504 whose business code is absent or known
// transient, and 2xx answers whose receipt was lost or truncated in
// transit are retryable. Business codes are final authority over the HTTP
// status — known terminal codes map to their sentinels and unknown codes
// are conservatively final — and format-invalid receipts never retry.
package sourcebatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/syncretry"
)

func TestRetryableIngestStatusAllowlist(t *testing.T) {
	for status, want := range map[int]bool{
		http.StatusTooManyRequests:         true,
		http.StatusInternalServerError:     true,
		http.StatusBadGateway:              true,
		http.StatusServiceUnavailable:      true,
		http.StatusGatewayTimeout:          true,
		http.StatusBadRequest:              false,
		http.StatusUnauthorized:            false,
		http.StatusForbidden:               false,
		http.StatusNotFound:                false,
		http.StatusConflict:                false,
		http.StatusGone:                    false,
		http.StatusNotImplemented:          false,
		http.StatusHTTPVersionNotSupported: false,
	} {
		if got := retryableIngestStatus(status); got != want {
			t.Errorf("retryableIngestStatus(%d) = %v, want %v", status, got, want)
		}
	}
}

func TestRetryableIngestCodeFailsClosedOnUnknownCodes(t *testing.T) {
	for code, want := range map[string]bool{
		"":                    true,
		"internal_error":      true,
		"service_unavailable": true,
		"rate_limited":        true,
		"too_many_requests":   true,
		// Known terminal codes (they map to sentinels before this check
		// ever runs, but must never be allowlisted here either).
		"scope_changed":        false,
		"source_fence_changed": false,
		"source_paused":        false,
		"stale_revision":       false,
		// Unknown codes: conservatively final.
		"outside_scope":        false,
		"unavailable":          false,
		"some_new_server_code": false,
	} {
		if got := retryableIngestCode(code); got != want {
			t.Errorf("retryableIngestCode(%q) = %v, want %v", code, got, want)
		}
	}
}

func TestTransportRetryableClassification(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"context canceled", context.Canceled, false},
		{"context canceled wrapped", fmt.Errorf("post: %w", context.Canceled), false},
		{"redirect refusal", errRedirectRefused, false},
		{"redirect refusal wrapped", fmt.Errorf("post: %w", errRedirectRefused), false},
		{"client timeout", context.DeadlineExceeded, true},
		{"client timeout wrapped in url error", fmt.Errorf(`Post "http://x": %w`, context.DeadlineExceeded), true},
		{"premature EOF", io.ErrUnexpectedEOF, true},
		{"EOF", io.EOF, true},
		{"connection refused", refused, true},
		{"op error wrapped", fmt.Errorf(`Post "http://x": %w`, refused), true},
		{"dns error", &net.DNSError{Err: "no such host", Name: "x.invalid"}, true},
		{"plain local error", errors.New("unsupported protocol scheme ftp"), false},
	} {
		if got := transportRetryable(tc.err); got != tc.want {
			t.Errorf("%s: transportRetryable = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestTruncatedJSONSignature(t *testing.T) {
	var v map[string]any
	for body, want := range map[string]bool{
		"":                         true,  // empty body is the truncation signature too
		`{"batch": {"batchId": "x`: true,  // cut mid-document
		"{not json":                false, // malformed, not truncated
		"[]":                       false, // wrong shape (unmarshal type error)
	} {
		err := json.Unmarshal([]byte(body), &v)
		if got := truncatedJSON(err); got != want {
			t.Errorf("truncatedJSON(body %q) = %v, want %v", body, got, want)
		}
	}
}

// TestMarkRetryableIsIdempotent proves the same failure is never
// double-wrapped: marking an already-marked error returns it unchanged.
func TestMarkRetryableIsIdempotent(t *testing.T) {
	base := errors.New("transient")
	once := markRetryable(base)
	twice := markRetryable(once)
	if once != twice {
		t.Fatal("markRetryable must return an already-marked error unchanged")
	}
	if !syncretry.IsRetryable(twice) {
		t.Fatal("the marker must survive")
	}
	if strings.Count(twice.Error(), "retryable") != 1 {
		t.Fatalf("the error was double-wrapped: %v", twice)
	}
	hdr := markRetryableWithHeader(once, "120")
	if hdr != once {
		t.Fatalf("markRetryableWithHeader must also leave a marked error unchanged: %v", hdr)
	}
}

// TestPostBatchClassifyRetryableCrossStatusAndCodes is the cross-status
// decision table the device-side review asked for: business codes win over
// retryable HTTP statuses, unknown codes are conservatively final, and
// only absent/known-transient codes on 429/500/502/503/504 retry.
func TestPostBatchClassifyRetryableCrossStatusAndCodes(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 1))
	cases := []struct {
		name        string
		status      int
		code        string // business code in the JSON error envelope; "" = codeless envelope
		rawBody     string // non-empty = raw non-JSON body instead of the envelope
		retryAfter  string
		wantRetry   bool
		wantHint    time.Duration
		wantHasHint bool
		wantErr     error // optional sentinel the final error must wrap
	}{
		{"503 codeless", http.StatusServiceUnavailable, "", "", "", true, 0, false, nil},
		{"500 internal_error", http.StatusInternalServerError, "internal_error", "", "", true, 0, false, nil},
		{"503 internal_error", http.StatusServiceUnavailable, "internal_error", "", "", true, 0, false, nil},
		{"502 codeless", http.StatusBadGateway, "", "", "", true, 0, false, nil},
		{"504 service_unavailable", http.StatusGatewayTimeout, "service_unavailable", "", "", true, 0, false, nil},
		{"429 rate_limited", http.StatusTooManyRequests, "rate_limited", "", "", true, 0, false, nil},
		{"429 too_many_requests with Retry-After", http.StatusTooManyRequests, "too_many_requests", "", "120", true, 120 * time.Second, true, nil},
		{"503 codeless with Retry-After date", http.StatusServiceUnavailable, "", "", "Wed, 21 Oct 2026 12:00:30 GMT", true, 30 * time.Second, true, nil},
		{"503 raw non-JSON body", http.StatusServiceUnavailable, "", "Service Unavailable (proxy)", "", true, 0, false, nil},
		// Business codes win over retryable statuses.
		{"503 scope_changed is final", http.StatusServiceUnavailable, "scope_changed", "", "", false, 0, false, ErrConsentStale},
		{"429 source_paused is final", http.StatusTooManyRequests, "source_paused", "", "", false, 0, false, ErrSourcePaused},
		{"500 source_fence_changed is final", http.StatusInternalServerError, "source_fence_changed", "", "", false, 0, false, ErrFenceStale},
		{"503 stale_revision is final", http.StatusServiceUnavailable, "stale_revision", "", "", false, 0, false, ErrStaleRevision},
		// Unknown codes are conservatively final, even on 429/5xx.
		{"503 outside_scope is final", http.StatusServiceUnavailable, "outside_scope", "", "", false, 0, false, nil},
		{"429 unknown code is final", http.StatusTooManyRequests, "some_new_server_code", "", "", false, 0, false, nil},
		{"500 unavailable is final", http.StatusInternalServerError, "unavailable", "", "", false, 0, false, nil},
		// Non-retryable statuses stay final whatever the code.
		{"400 codeless is final", http.StatusBadRequest, "", "", "", false, 0, false, nil},
		{"401 is final", http.StatusUnauthorized, "", "", "", false, 0, false, ErrDeviceUnauthorized},
		{"403 is final", http.StatusForbidden, "", "", "", false, 0, false, ErrDeviceUnauthorized},
		{"409 stale_revision is final", http.StatusConflict, "stale_revision", "", "", false, 0, false, ErrStaleRevision},
		{"501 is final", http.StatusNotImplemented, "", "", "", false, 0, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				if tc.rawBody != "" {
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte(tc.rawBody))
					return
				}
				writeJSON(w, tc.status, map[string]any{
					"error": map[string]string{"code": tc.code, "message": marker},
				})
			}))
			defer server.Close()
			opt := testOptions(server.URL)
			opt.ClassifyRetryable = true
			_, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent)
			if err == nil {
				t.Fatal("expected a failure")
			}
			if got := syncretry.IsRetryable(err); got != tc.wantRetry {
				t.Fatalf("retryable = %v, want %v (err: %v)", got, tc.wantRetry, err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v in the chain, got %v", tc.wantErr, err)
			}
			if !tc.wantRetry && tc.wantErr == nil && strings.Contains(err.Error(), "retryable") {
				// Final errors keep the historical unwrapped shape.
				t.Fatalf("a final error must not carry a marker: %v", err)
			}
			hint, hasHint := syncretry.RetryAfterHint(err, time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC))
			if hasHint != tc.wantHasHint {
				t.Fatalf("hasHint = %v, want %v (err: %v)", hasHint, tc.wantHasHint, err)
			}
			if hasHint && tc.wantHint > 0 && hint != tc.wantHint {
				t.Fatalf("hint = %v, want %v", hint, tc.wantHint)
			}
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("error echoes untrusted server message: %v", err)
			}
			if strings.Contains(err.Error(), testDeviceSecret) {
				t.Fatalf("error leaks the device secret: %v", err)
			}
		})
	}
}

// TestPostBatchClassifyOffKeepsErrorsExactlyAsBefore proves the nil-retry
// contract at the client level: without ClassifyRetryable no error carries
// a marker and the messages keep their historical shape.
func TestPostBatchClassifyOffKeepsErrorsExactlyAsBefore(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 1))
	cases := []struct {
		name       string
		status     int
		code       string
		rawBody    string
		wantSubstr string
	}{
		{"503 codeless", http.StatusServiceUnavailable, "", "", `source-batch request failed: HTTP 503 code=""`},
		{"500 internal_error", http.StatusInternalServerError, "internal_error", "", `source-batch request failed: HTTP 500 code="internal_error"`},
		{"503 raw body", http.StatusServiceUnavailable, "", "no json", "source-batch request failed: HTTP 503"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.rawBody != "" {
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte(tc.rawBody))
					return
				}
				writeJSON(w, tc.status, map[string]any{
					"error": map[string]string{"code": tc.code, "message": marker},
				})
			}))
			defer server.Close()
			opt := testOptions(server.URL)
			_, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent)
			if err == nil {
				t.Fatal("expected a failure")
			}
			if syncretry.IsRetryable(err) {
				t.Fatalf("without classification no error may carry a marker: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("historical message shape changed: %v (want substring %q)", err, tc.wantSubstr)
			}
		})
	}
}

// TestPostBatchClassifyRetryableTransportErrors covers the POST-level
// failures: connection refused and a client timeout under a live parent
// context are retryable; the no-redirect security refusal and a canceled
// parent context are final.
func TestPostBatchClassifyRetryableTransportErrors(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 1))

	t.Run("connection refused is retryable", func(t *testing.T) {
		dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		url := dead.URL
		dead.Close()
		opt := testOptions(url)
		opt.ClassifyRetryable = true
		_, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent)
		if err == nil {
			t.Fatal("expected the refused connection to fail")
		}
		if !syncretry.IsRetryable(err) {
			t.Fatalf("a connection refusal under a live context must be retryable: %v", err)
		}
	})

	t.Run("client timeout under live parent context is retryable", func(t *testing.T) {
		release := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-release
		}))
		defer server.Close()
		defer close(release)
		opt := testOptions(server.URL)
		opt.HTTPClient = &http.Client{Timeout: 80 * time.Millisecond}
		opt.ClassifyRetryable = true
		start := time.Now()
		_, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent)
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("timeout took %v", elapsed)
		}
		if err == nil {
			t.Fatal("expected the hung server to time out")
		}
		if !syncretry.IsRetryable(err) {
			t.Fatalf("a client timeout with a live parent context must be retryable: %v", err)
		}
	})

	t.Run("redirect refusal is final", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("the redirect must never be followed")
		}))
		defer target.Close()
		var redirector *httptest.Server
		redirector = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"/steal", http.StatusFound)
		}))
		defer redirector.Close()
		opt := testOptions(redirector.URL)
		opt.ClassifyRetryable = true
		_, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent)
		if err == nil || syncretry.IsRetryable(err) {
			t.Fatalf("the no-redirect security refusal must be final: %v", err)
		}
	})

	t.Run("canceled parent context is final", func(t *testing.T) {
		release := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-release
		}))
		defer server.Close()
		defer close(release)
		opt := testOptions(server.URL)
		opt.ClassifyRetryable = true
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(40 * time.Millisecond)
			cancel()
		}()
		_, err := PostBatch(ctx, opt, encoded, testFence, testConsent)
		if err == nil {
			t.Fatal("expected the canceled context to fail the POST")
		}
		if syncretry.IsRetryable(err) {
			t.Fatalf("a canceled parent context must never be marked retryable: %v", err)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("the cancellation must stay observable: %v", err)
		}
	})
}

// TestPostBatchClassifyRetryableReceiptLostOrTruncated covers the success
// receipt cases: a 2xx body that never arrives intact (lost) or is cut off
// mid-stream (truncated) is retryable — the same batch id and bytes
// re-send idempotently — while complete-but-invalid bodies are format
// errors and stay final.
func TestPostBatchClassifyRetryableReceiptLostOrTruncated(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 2))
	cases := []struct {
		name      string
		status    int
		serve     func(w http.ResponseWriter)
		wantRetry bool
	}{
		{"202 body lost mid-read", http.StatusAccepted, func(w http.ResponseWriter) {
			// Promise more bytes than are written, then let the handler
			// return: the connection closes and the read fails.
			w.Header().Set("Content-Length", "4096")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"batch": {"batchId": "`))
		}, true},
		{"503 body lost mid-read", http.StatusServiceUnavailable, func(w http.ResponseWriter) {
			w.Header().Set("Content-Length", "4096")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error": `))
		}, true},
		{"202 truncated JSON", http.StatusAccepted, func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"batch": {"batchId": "batch-cursor-`))
		}, true},
		{"202 empty body", http.StatusAccepted, func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusAccepted)
		}, true},
		{"400 body lost mid-read stays final", http.StatusBadRequest, func(w http.ResponseWriter) {
			w.Header().Set("Content-Length", "4096")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error": `))
		}, false},
		{"202 malformed JSON is a format error", http.StatusAccepted, func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte("{not json"))
		}, false},
		{"202 wrong shape is a format error", http.StatusAccepted, func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte("[]"))
		}, false},
		{"202 parses but carries no receipt", http.StatusAccepted, func(w http.ResponseWriter) {
			writeJSON(w, http.StatusAccepted, map[string]any{"error": nil})
		}, false},
		{"202 oversized receipt is a format error", http.StatusAccepted, func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write(make([]byte, maxResponseBytes+1))
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tc.serve(w)
			}))
			defer server.Close()
			opt := testOptions(server.URL)
			opt.ClassifyRetryable = true
			_, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent)
			if err == nil {
				t.Fatal("expected a failure")
			}
			if got := syncretry.IsRetryable(err); got != tc.wantRetry {
				t.Fatalf("retryable = %v, want %v (err: %v)", got, tc.wantRetry, err)
			}
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("error echoes untrusted server message: %v", err)
			}
			if strings.Contains(err.Error(), testDeviceSecret) {
				t.Fatalf("error leaks the device secret: %v", err)
			}
		})
	}
}
