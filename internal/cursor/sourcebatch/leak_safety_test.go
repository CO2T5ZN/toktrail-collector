// Error-privacy contract against untrusted server text: a business code
// the client does not recognize, a receipt's batch id or status, and any
// other server-controlled string must never be reflected into an error
// message — they could carry a reflected credential or response
// content. Only the fixed known codes keep their name; everything else
// renders as the fixed word "unknown". Everything here is synthetic: a
// local httptest server answering hostile envelopes and receipts that
// embed the synthetic device secret and random text; no real device,
// credential or server is ever touched.
package sourcebatch

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"toktrail-collector/internal/syncretry"
)

// leakMarker is random synthetic response text standing in for content a
// hostile server could reflect.
const leakMarker = "RANDOM-BODY-TEXT-3b81e5d0a9c24f67"

// TestPostBatchUnrecognizedCodeNeverReflected: an unrecognized business
// code — here the device secret and random text planted where the code
// belongs — surfaces as a final failure carrying the fixed "unknown"
// label, never the raw string. The classification is unchanged: an
// unknown code on a retryable status stays final (never retried).
func TestPostBatchUnrecognizedCodeNeverReflected(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 1))
	cases := []struct {
		name   string
		status int
		code   string
	}{
		{"secret as the code on 503", http.StatusServiceUnavailable, testDeviceSecret},
		{"random text as the code on 503", http.StatusServiceUnavailable, leakMarker},
		{"secret as the code on 400", http.StatusBadRequest, testDeviceSecret},
		{"random text as the code on 429", http.StatusTooManyRequests, leakMarker},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			if !strings.Contains(err.Error(), `code="unknown"`) {
				t.Fatalf("an unrecognized code must render as the fixed unknown label: %v", err)
			}
			if strings.Contains(err.Error(), testDeviceSecret) || strings.Contains(err.Error(), leakMarker) {
				t.Fatalf("the error must not reflect untrusted code text: %v", err)
			}
			// Classification is untouched: an unknown code is
			// conservatively final even on a retryable status.
			if syncretry.IsRetryable(err) {
				t.Fatalf("an unknown code must stay final: %v", err)
			}
		})
	}
}

// TestPostBatchKnownCodeStillRendered: codes from the fixed known set
// keep their name in the message — the sanitization collapses only
// unrecognized strings, so legitimate diagnostics are unchanged.
func TestPostBatchKnownCodeStillRendered(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 1))
	for _, code := range []string{"internal_error", "service_unavailable", "rate_limited", "too_many_requests"} {
		t.Run(code, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{
					"error": map[string]string{"code": code, "message": marker},
				})
			}))
			defer server.Close()
			_, err := PostBatch(t.Context(), testOptions(server.URL), encoded, testFence, testConsent)
			if err == nil {
				t.Fatal("expected a failure")
			}
			if !strings.Contains(err.Error(), `code="`+code+`"`) {
				t.Fatalf("a known code must keep its fixed name: %v", err)
			}
		})
	}
}

// TestPostBatchReceiptUntrustedTextNeverReflected: a 2xx receipt whose
// batch id or status carries the device secret or random text fails
// strict validation without reflecting either — the sentinel is the
// contract, never the server's strings.
func TestPostBatchReceiptUntrustedTextNeverReflected(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 1))
	cases := []struct {
		name string
		body map[string]any
	}{
		{"secret as the receipt batch id", serverReceipt(testDeviceSecret, "accepted", 1, 0, testReceivedAt, false, nil)},
		{"random text as the receipt batch id", serverReceipt(leakMarker, "accepted", 1, 0, testReceivedAt, false, nil)},
		{"secret as the receipt status", serverReceipt(testBatchID, testDeviceSecret, 1, 0, testReceivedAt, false, nil)},
		{"random text as the receipt status", serverReceipt(testBatchID, leakMarker, 1, 0, testReceivedAt, false, nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, http.StatusAccepted, tc.body)
			}))
			defer server.Close()
			_, err := PostBatch(t.Context(), testOptions(server.URL), encoded, testFence, testConsent)
			if !errors.Is(err, ErrInvalidReceipt) {
				t.Fatalf("expected ErrInvalidReceipt, got %v", err)
			}
			if strings.Contains(err.Error(), testDeviceSecret) || strings.Contains(err.Error(), leakMarker) {
				t.Fatalf("the error must not reflect untrusted receipt text: %v", err)
			}
		})
	}
}

// TestPostBatchForeignSourceIDsNeverEchoed: a persisted batch or a
// configured source id may carry text a malicious server once mirrored
// into a permit from before the reflection boundary (an old polluted
// permit); the mismatch refusal names neither, so the historical ids
// never travel into diagnostics.
func TestPostBatchForeignSourceIDsNeverEchoed(t *testing.T) {
	foreign := testBatch(testBatchID, 1)
	foreign.SourceInstanceID = testDeviceSecret
	opt := testOptions("http://127.0.0.1:1") // never reached: local refusal
	opt.SourceInstanceID = leakMarker

	_, err := PostBatch(t.Context(), opt, mustEncode(t, foreign), testFence, testConsent)
	if err == nil {
		t.Fatal("expected the foreign-source refusal")
	}
	if strings.Contains(err.Error(), testDeviceSecret) || strings.Contains(err.Error(), leakMarker) {
		t.Fatalf("the refusal must never echo the historical source ids: %v", err)
	}
	if !strings.Contains(err.Error(), "belongs to a different source") {
		t.Fatalf("unexpected refusal message: %v", err)
	}
}

// TestSourceBatchRedirectLocationNeverLeaks: 302/307 answers whose
// Location carries the device secret — verbatim, uppercased, or behind
// a malformed escape — are refused with fixed wording on both the POST
// upload and the GET receipt fetch (whose query additionally carries a
// poisoned source id); the redirect target receives zero requests, no
// retry may start on a redirect refusal, and neither the secret (any
// case), the source id, nor any URL or raw transport text reaches the
// error.
func TestSourceBatchRedirectLocationNeverLeaks(t *testing.T) {
	locations := []struct {
		name        string
		loc         string
		wantWording string
	}{
		{"legal url carrying the secret", "http://127.0.0.1:1/steal-" + testDeviceSecret, "redirect refused"},
		{"uppercase secret variant", "http://127.0.0.1:1/steal-" + strings.ToUpper(testDeviceSecret), "redirect refused"},
		{"malformed escape carrying the secret", "http://127.0.0.1:1/%zz" + testDeviceSecret, "transport failure"},
	}
	for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect} {
		for _, tc := range locations {
			t.Run(fmt.Sprintf("HTTP %d / %s", status, tc.name), func(t *testing.T) {
				// The batch carries the SAME poisoned source id as the
				// option, so the local foreign-source check passes and
				// the POST actually reaches the redirecting server.
				batch := testBatch(testBatchID, 1)
				batch.SourceInstanceID = testDeviceSecret
				encoded := mustEncode(t, batch)
				var hits atomic.Int64
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)
				}))
				defer target.Close()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, tc.loc, status)
				}))
				defer server.Close()
				// The poisoned source id rides the GET query — it must
				// never surface either.
				opt := testOptions(server.URL)
				opt.SourceInstanceID = testDeviceSecret
				opt.ClassifyRetryable = true

				_, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent)
				if err == nil {
					t.Fatal("expected the redirect to be refused")
				}
				assertTransportClean(t, err)
				if !strings.Contains(err.Error(), tc.wantWording) {
					t.Fatalf("the POST refusal must carry its fixed wording: %v", err)
				}
				if syncretry.IsRetryable(err) {
					t.Fatalf("a redirect refusal must never be retryable: %v", err)
				}

				_, _, getErr := GetBatch(t.Context(), opt, testBatchID, testFence, testConsent)
				if getErr == nil {
					t.Fatal("expected the GET redirect to be refused")
				}
				assertTransportClean(t, getErr)
				if n := hits.Load(); n != 0 {
					t.Fatalf("the redirect target must receive zero requests, got %d", n)
				}
			})
		}
	}
}

// assertTransportClean fails when the rendered error carries the device
// secret (any case) or raw transport text.
func assertTransportClean(t *testing.T, err error) {
	t.Helper()
	msg := err.Error()
	if strings.Contains(msg, testDeviceSecret) || strings.Contains(msg, strings.ToUpper(testDeviceSecret)) {
		t.Fatalf("the error must not echo the device secret: %v", err)
	}
	for _, forbidden := range []string{"http://", "https://", "127.0.0.1", "%zz"} {
		if strings.Contains(msg, forbidden) {
			t.Fatalf("the error must not echo raw transport text (%q): %v", forbidden, err)
		}
	}
}

// TestPostBatchTransportRetryMarkerSurvivesWrapping pins the retry
// contract through the wrapper: a connection-refused transport failure
// under a live context keeps its retryable marker (the policy still
// waits and re-sends), and the url.Error / net.Error shapes stay
// reachable through As for programmatic matching.
func TestPostBatchTransportRetryMarkerSurvivesWrapping(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 1))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Close() // refused connections model the transient transport failure
	opt := testOptions(server.URL)
	opt.ClassifyRetryable = true

	_, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent)
	if err == nil {
		t.Fatal("expected the transport failure")
	}
	assertTransportClean(t, err)
	if !syncretry.IsRetryable(err) {
		t.Fatalf("the retryable classification must survive the wrapper: %v", err)
	}
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		t.Fatalf("the url.Error must stay reachable through As: %v", err)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) {
		t.Fatalf("the net.Error shape must stay reachable through As: %v", err)
	}
}
