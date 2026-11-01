// Error-privacy contract against untrusted server text: a business code
// the package does not recognize must never be reflected into an error
// message — it could carry a reflected credential or response content.
// Only the fixed known codes keep their name; everything else renders as
// the fixed word "unknown". The enable trust boundary additionally
// refuses a returned source whose strings mirror the device credential,
// so nothing reflected is ever persisted. Everything here is synthetic:
// a local httptest server answering hostile envelopes that embed the
// synthetic device secret and random text; no real device, credential
// or server is ever touched.
package accountsource

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/cursor/protocol"
)

// leakMarker is random synthetic response text standing in for content a
// hostile server could reflect.
const leakMarker = "RANDOM-BODY-TEXT-9d2c47f1b6e83a05"

// TestEnableUnrecognizedCodeNeverReflected: enable failures carrying an
// unrecognized code — here the device secret and random text planted
// where the code belongs — render the fixed "unknown" label and never
// the raw string, on both the 401/403 rejection path and the generic
// failure path.
func TestEnableUnrecognizedCodeNeverReflected(t *testing.T) {
	cases := []struct {
		name   string
		status int
		code   string
	}{
		{"secret as the code on 403", http.StatusForbidden, testDeviceSecret},
		{"random text as the code on 401", http.StatusUnauthorized, leakMarker},
		{"secret as the code on 500", http.StatusInternalServerError, testDeviceSecret},
		{"random text as the code on 502", http.StatusBadGateway, leakMarker},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, tc.status, map[string]any{
					"error": map[string]string{"code": tc.code, "message": marker},
				})
			}))
			defer server.Close()
			_, err := Enable(t.Context(), testOptions(server.URL), protocol.SourceType)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), `code="unknown"`) {
				t.Fatalf("an unrecognized code must render as the fixed unknown label: %v", err)
			}
			if strings.Contains(err.Error(), testDeviceSecret) || strings.Contains(err.Error(), leakMarker) {
				t.Fatalf("the error must not reflect untrusted code text: %v", err)
			}
		})
	}
}

// TestEnableKnownCodeStillRendered: codes from the fixed known set keep
// their name in the message, so legitimate diagnostics are unchanged.
func TestEnableKnownCodeStillRendered(t *testing.T) {
	for _, code := range []string{"unauthorized", "device_revoked", "internal_error", "store_unavailable"} {
		t.Run(code, func(t *testing.T) {
			status := http.StatusInternalServerError
			if code == "unauthorized" || code == "device_revoked" {
				status = http.StatusUnauthorized
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, status, map[string]any{
					"error": map[string]string{"code": code, "message": marker},
				})
			}))
			defer server.Close()
			_, err := Enable(t.Context(), testOptions(server.URL), protocol.SourceType)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), `code="`+code+`"`) {
				t.Fatalf("a known code must keep its fixed name: %v", err)
			}
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("the error must not echo the untrusted message: %v", err)
			}
		})
	}
}

// TestRequireCapabilityUnrecognizedCodeNeverReflected: the capability
// probe's non-200 failures render unrecognized codes the same fixed way.
func TestRequireCapabilityUnrecognizedCodeNeverReflected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": map[string]string{"code": testDeviceSecret, "message": leakMarker},
		})
	}))
	defer server.Close()
	err := RequireCapability(t.Context(), testOptions(server.URL))
	if err == nil {
		t.Fatal("expected the capability check to fail closed")
	}
	if !strings.Contains(err.Error(), `code="unknown"`) {
		t.Fatalf("an unrecognized code must render as the fixed unknown label: %v", err)
	}
	if strings.Contains(err.Error(), testDeviceSecret) || strings.Contains(err.Error(), leakMarker) {
		t.Fatalf("the error must not reflect untrusted code text: %v", err)
	}
}

// TestEnableRefusesSourceMirroringDeviceSecret is the trust-boundary
// contract against reflected credentials: the enable request presents
// the long-lived device secret, and a hostile server can plant it into
// any string of the source it returns — where the caller would persist
// it into the permit and later status output would print it forever.
// Every string field is checked, case-insensitively (the secret is
// hex-shaped), a label check would not do (the secret is a valid
// label), and the refusal is the fixed sentinel: no field value, no
// credential, nothing returned.
func TestEnableRefusesSourceMirroringDeviceSecret(t *testing.T) {
	cases := []struct {
		name   string
		source map[string]any
	}{
		{"secret as the source instance id", map[string]any{
			"sourceInstanceId": testDeviceSecret, "sourceType": "cursor-account", "state": "active",
		}},
		{"secret embedded in the source instance id", map[string]any{
			"sourceInstanceId": "src-inst-" + testDeviceSecret + "-x", "sourceType": "cursor-account", "state": "active",
		}},
		{"uppercase secret in the source instance id", map[string]any{
			"sourceInstanceId": strings.ToUpper(testDeviceSecret), "sourceType": "cursor-account", "state": "active",
		}},
		{"secret as the source type", map[string]any{
			"sourceInstanceId": "src-inst-1", "sourceType": testDeviceSecret, "state": "active",
		}},
		{"secret as the state", map[string]any{
			"sourceInstanceId": "src-inst-1", "sourceType": "cursor-account", "state": testDeviceSecret,
		}},
		{"uppercase secret embedded in the state", map[string]any{
			"sourceInstanceId": "src-inst-1", "sourceType": "cursor-account", "state": "paused-" + strings.ToUpper(testDeviceSecret),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, http.StatusCreated, map[string]any{"source": tc.source})
			}))
			defer server.Close()
			src, err := Enable(t.Context(), testOptions(server.URL), protocol.SourceType)
			if !errors.Is(err, ErrMirroredCredential) {
				t.Fatalf("a mirrored credential must be refused with the sentinel, got source=%+v err=%v", src, err)
			}
			if strings.Contains(err.Error(), testDeviceSecret) || strings.Contains(err.Error(), strings.ToUpper(testDeviceSecret)) {
				t.Fatalf("the refusal must never echo the credential: %v", err)
			}
			if src != (protocol.Source{}) {
				t.Fatalf("nothing of the mirrored source may be returned: %+v", src)
			}
		})
	}
}

// TestEnableAcceptsSecretShapedButCleanLabels: valid hex-shaped values
// that do NOT contain the actual secret still pass — the boundary
// matches the real credential, not a shape, so legitimate ids and states
// are unaffected.
func TestEnableAcceptsSecretShapedButCleanLabels(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusCreated, map[string]any{"source": map[string]any{
			// Hex-shaped and secret-like, but sharing no substring
			// with the actual credential.
			"sourceInstanceId": "fedcba9876543210deadbeef", "sourceType": "cursor-account", "state": "active",
			"fenceVersion": 1, "nextRevision": 1,
		}})
	}))
	defer server.Close()
	src, err := Enable(t.Context(), testOptions(server.URL), protocol.SourceType)
	if err != nil {
		t.Fatalf("a clean hex-shaped source must be accepted: %v", err)
	}
	if src.SourceInstanceID != "fedcba9876543210deadbeef" || src.State != "active" {
		t.Fatalf("unexpected source: %+v", src)
	}
}

// TestEnableAndCapabilityRedirectLocationNeverLeaks: 302/307 answers
// whose Location carries the device secret — verbatim, uppercased, or
// behind a malformed escape — are refused with fixed wording; the
// redirect target receives zero requests and neither the secret (any
// case) nor any URL, host or raw transport text reaches the error.
func TestEnableAndCapabilityRedirectLocationNeverLeaks(t *testing.T) {
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
				var hits atomic.Int64
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)
				}))
				defer target.Close()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, tc.loc, status)
				}))
				defer server.Close()
				opt := testOptions(server.URL)

				_, err := Enable(t.Context(), opt, protocol.SourceType)
				if err == nil {
					t.Fatal("expected the redirect to be refused")
				}
				if strings.Contains(err.Error(), testDeviceSecret) || strings.Contains(err.Error(), strings.ToUpper(testDeviceSecret)) {
					t.Fatalf("the error must not echo the device secret: %v", err)
				}
				for _, forbidden := range []string{"http://", "https://", "127.0.0.1", "%zz"} {
					if strings.Contains(err.Error(), forbidden) {
						t.Fatalf("the error must not echo raw transport text (%q): %v", forbidden, err)
					}
				}
				if !strings.Contains(err.Error(), tc.wantWording) {
					t.Fatalf("the refusal must carry its fixed wording: %v", err)
				}

				capsErr := RequireCapability(t.Context(), opt)
				if capsErr == nil {
					t.Fatal("expected the capability redirect to be refused")
				}
				if strings.Contains(capsErr.Error(), testDeviceSecret) || strings.Contains(capsErr.Error(), strings.ToUpper(testDeviceSecret)) {
					t.Fatalf("the capability error must not echo the device secret: %v", capsErr)
				}
				if !strings.Contains(capsErr.Error(), tc.wantWording) {
					t.Fatalf("the capability refusal must carry its fixed wording: %v", capsErr)
				}
				if n := hits.Load(); n != 0 {
					t.Fatalf("the redirect target must receive zero requests, got %d", n)
				}
			})
		}
	}
}

// TestTransportErrorsKeepCancellationAndNetShapes pins the wrapper's
// contract for the account-source endpoints: cancellation and deadlines
// stay matchable through Unwrap with fixed rendered wording.
func TestTransportErrorsKeepCancellationAndNetShapes(t *testing.T) {
	t.Run("client timeout stays a deadline", func(t *testing.T) {
		release := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-release
		}))
		defer server.Close()
		defer close(release)
		opt := testOptions(server.URL)
		opt.HTTPClient = &http.Client{Timeout: 80 * time.Millisecond}

		err := RequireCapability(t.Context(), opt)
		if err == nil {
			t.Fatal("expected the hung server to time out")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("the deadline must stay detectable through the wrapper, got %v", err)
		}
		if !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("the fixed wording must identify the timeout: %v", err)
		}
	})

	t.Run("cancellation stays detectable", func(t *testing.T) {
		release := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-release
		}))
		defer server.Close()
		defer close(release)
		opt := testOptions(server.URL)

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()
		err := RequireCapability(ctx, opt)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation must stay detectable through the wrapper, got %v", err)
		}
	})
}
