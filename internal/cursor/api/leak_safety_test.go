// Error-privacy contract of the strict usage-event parser and the
// FetchUsageEvents boundary: a malicious or compromised response can
// plant the session token or arbitrary conversation/body text in any
// row field, and none of it may travel into an error message — neither
// raw, nor as a value, nor as a truncated preview. Everything here is
// synthetic: a local loopback httptest server answering malicious rows
// that embed a synthetic session token and random body text; no real
// Cursor account, credential or server is ever touched.
package api_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/cursor/api"
)

// leakMarker is random synthetic response text standing in for
// conversation content a hostile server could reflect.
const leakMarker = "RANDOM-BODY-TEXT-7f3a9c1e5b2d8e40"

// leakFree asserts the rendered error carries neither the session token
// nor the random body text.
func leakFree(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("an error was expected")
	}
	if msg := err.Error(); strings.Contains(msg, testToken) || strings.Contains(msg, leakMarker) {
		t.Fatalf("the error must not echo the session token or response text: %q", msg)
	}
}

// TestParseUsageEventNeverEchoesUntrustedRowText drives every
// strict-parse failure branch with rows that plant the session token
// and random body text in the offending fields: each error must name
// only the fixed field and category, never the row, a field value, or a
// preview of either.
func TestParseUsageEventNeverEchoesUntrustedRowText(t *testing.T) {
	rows := []string{
		// Non-string conversationId / model / usageEventId.
		`{"conversationId": 42, "timestamp": "1792841120156", "model": "m"}`,
		`{"conversationId": "` + leakMarker + `", "timestamp": "1792841120156", "model": 42}`,
		`{"conversationId": "c", "timestamp": "1792841120156", "model": "m", "usageEventId": [1]}`,
		// Timestamps that are neither Unix milliseconds nor RFC 3339.
		`{"conversationId": "c", "timestamp": "` + testToken + `", "model": "m"}`,
		`{"conversationId": "c", "timestamp": "` + leakMarker + `", "model": "m"}`,
		`{"conversationId": "c", "timestamp": {"nested": "` + testToken + `"}, "model": "m"}`,
		`{"conversationId": "c", "timestamp": true, "model": "m"}`,
		`{"conversationId": "c", "timestamp": 1.5, "model": "m"}`,
		`{"conversationId": "c", "timestamp": "0", "model": "m"}`,
		// Non-object tokenUsage.
		`{"conversationId": "c", "timestamp": "1792841120156", "model": "m", "tokenUsage": "` + testToken + `"}`,
		`{"conversationId": "c", "timestamp": "1792841120156", "model": "m", "tokenUsage": 7}`,
		// Token counts of the wrong shape, embedding secrets and text.
		`{"conversationId": "c", "timestamp": "1792841120156", "model": "m", "tokenUsage": {"inputTokens": "` + testToken + `"}}`,
		`{"conversationId": "c", "timestamp": "1792841120156", "model": "m", "tokenUsage": {"outputTokens": "` + leakMarker + `"}}`,
		`{"conversationId": "c", "timestamp": "1792841120156", "model": "m", "tokenUsage": {"cacheReadTokens": {"v": "` + testToken + `"}}}`,
		`{"conversationId": "c", "timestamp": "1792841120156", "model": "m", "tokenUsage": {"cacheWriteTokens": true}}`,
		`{"conversationId": "c", "timestamp": "1792841120156", "model": "m", "tokenUsage": {"inputTokens": -5}}`,
		`{"conversationId": "c", "timestamp": "1792841120156", "model": "m", "tokenUsage": {"inputTokens": 1e999}}`,
		// Positional rows with hostile elements (the timestamp slot is
		// the second element; conversationId legitimately accepts any
		// string and is never rendered).
		`["c", "` + leakMarker + `", "m"]`,
		`[42, "1792841120156", "m"]`,
		`["c", "` + testToken + `", "m", 0, {"inputTokens": "` + leakMarker + `"}]`,
		`["c"]`,
		// Rows that are not objects or arrays at all.
		`"` + testToken + `"`,
		"`" + leakMarker + "`",
	}
	for _, row := range rows {
		_, err := api.ParseUsageEvent([]byte(row))
		leakFree(t, err)
		if strings.TrimSpace(err.Error()) == "" {
			t.Fatalf("the error must still name its fixed category: %q", row)
		}
	}
}

// TestFetchUsageEventsMaliciousRowsNeverLeakThroughFinalError is the
// end-to-end contract: a malicious page plants the session token and
// random body text in usage rows, the walk fails closed on the first
// invalid row (exactly one page requested), and the final error leaving
// FetchUsageEvents carries neither the token nor the text — through
// both the category-only parser errors and the boundary sanitization.
func TestFetchUsageEventsMaliciousRowsNeverLeakThroughFinalError(t *testing.T) {
	pages := 0
	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		pages++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"totalUsageEventsCount":2,"usageEventsDisplay":[
			{"conversationId":"c","timestamp":"` + testToken + `","model":"m"},
			{"conversationId":"c","timestamp":"1792841120156","model":"m","tokenUsage":{"inputTokens":"` + leakMarker + `"}}
		]}`))
	})
	client := newTestClient(t, server, nil)

	_, err := client.FetchUsageEvents(t.Context(), api.Session{Token: testToken}, api.FetchOptions{})
	leakFree(t, err)
	if !strings.Contains(err.Error(), "invalid event row") {
		t.Fatalf("the failure must stay a strict-parse failure: %v", err)
	}
	if pages != 1 {
		t.Fatalf("the walk must fail closed on the first invalid row, pages=%d", pages)
	}
}

// TestFetchUsageEventsBoundaryKeepsErrorsIsContracts pins the boundary
// sanitization's errors.Is contract: token-free errors pass through the
// FetchUsageEvents boundary untouched, so the session-expired sentinel
// and external cancellation stay detectable exactly as before.
func TestFetchUsageEventsBoundaryKeepsErrorsIsContracts(t *testing.T) {
	t.Run("session expired stays detectable", func(t *testing.T) {
		server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})
		client := newTestClient(t, server, nil)
		_, err := client.FetchUsageEvents(t.Context(), api.Session{Token: testToken}, api.FetchOptions{})
		if !errors.Is(err, api.ErrSessionExpired) {
			t.Fatalf("ErrSessionExpired must stay detectable through the boundary, got %v", err)
		}
	})

	t.Run("cancellation stays detectable", func(t *testing.T) {
		block := make(chan struct{})
		server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
			<-block
		})
		t.Cleanup(func() { close(block) })
		client := newTestClient(t, server, nil)

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()
		_, err := client.FetchUsageEvents(ctx, api.Session{Token: testToken}, api.FetchOptions{})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("context.Canceled must stay detectable through the boundary, got %v", err)
		}
		leakFree(t, err)
	})
}

// TestFetchUsageEventsBoundarySanitizesTokenBearingMessages proves the
// boundary's second sanitization layer is wired on the error exits, not
// dead code: a (deliberately pathological) session token that appears in
// a failure message — here a substring of the invalid-JSON failure — is
// redacted by the FetchUsageEvents boundary itself while the failure
// still surfaces. Today no natural error message can carry the token
// (every message is fixed text plus numbers, and Go's http errors never
// include headers); this pins the defense-in-depth layer regardless.
func TestFetchUsageEventsBoundarySanitizesTokenBearingMessages(t *testing.T) {
	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json at all"))
	})
	client := newTestClient(t, server, nil)

	// A pathological token that collides with the fixed failure text:
	// the boundary must redact it from the message it returns.
	pathological := "usage events JSON"
	_, err := client.FetchUsageEvents(t.Context(), api.Session{Token: pathological}, api.FetchOptions{})
	if err == nil {
		t.Fatal("the malformed page must fail closed")
	}
	if !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("the boundary must redact a token-bearing message: %q", err.Error())
	}
	if strings.Contains(err.Error(), pathological) {
		t.Fatalf("the token must not survive the boundary: %q", err.Error())
	}
}

// redirectLocations is the malicious Location matrix: a hostile server
// plants the session token into the redirect target it answers with —
// verbatim, uppercased, case-mixed, or behind a malformed escape — and
// net/http writes that Location into the url.Error it returns when the
// redirect is refused. The transport wrapper must keep every variant
// out of the human message.
var redirectLocations = []struct {
	name string
	loc  string
	// wantWording is the fixed wording the refusal must carry: a
	// parseable Location is refused by the no-redirect policy; a
	// malformed one fails Location parsing before that, surfacing the
	// withheld-cause wording. Both stay free of the Location's text.
	wantWording string
}{
	{"legal url carrying the token", "http://127.0.0.1:1/steal-" + testToken, "redirect refused"},
	{"uppercase token variant", "http://127.0.0.1:1/steal-" + strings.ToUpper(testToken), "redirect refused"},
	{"case-mixed token variant", "http://127.0.0.1:1/steal-" + strings.ToUpper(testToken[:8]) + testToken[8:], "redirect refused"},
	{"malformed escape carrying the token", "http://127.0.0.1:1/%zz" + testToken, "transport failure"},
}

// assertNoTransportEcho fails when the rendered error carries any
// sensitive or raw transport text: the token in any case, a URL, the
// malformed escape, or a host address.
func assertNoTransportEcho(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("an error was expected")
	}
	msg := err.Error()
	lower := strings.ToLower(msg)
	if strings.Contains(lower, strings.ToLower(testToken)) {
		t.Fatalf("the error must not echo the session token: %q", msg)
	}
	for _, forbidden := range []string{"http://", "https://", "127.0.0.1", "%zz", "example.com"} {
		if strings.Contains(msg, forbidden) {
			t.Fatalf("the error must not echo raw transport text (%q): %q", forbidden, msg)
		}
	}
}

// TestFetchUsageSummaryRedirectLocationNeverLeaks: 302/307 answers whose
// Location carries the token in every variant are refused with a fixed
// message; the redirect target receives zero requests, and neither the
// token (any case) nor any URL, host or raw transport text reaches the
// error.
func TestFetchUsageSummaryRedirectLocationNeverLeaks(t *testing.T) {
	for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect} {
		for _, tc := range redirectLocations {
			t.Run(fmt.Sprintf("HTTP %d / %s", status, tc.name), func(t *testing.T) {
				var hits atomic.Int64
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)
				}))
				defer target.Close()
				server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, tc.loc, status)
				})
				client := newTestClient(t, server, nil)

				_, err := client.FetchUsageSummary(t.Context(), api.Session{Token: testToken})
				assertNoTransportEcho(t, err)
				if !strings.Contains(err.Error(), tc.wantWording) {
					t.Fatalf("the refusal must carry its fixed wording: %v", err)
				}
				if n := hits.Load(); n != 0 {
					t.Fatalf("the redirect target must receive zero requests, got %d", n)
				}
			})
		}
	}
}

// TestFetchUsageEventsPostRedirectLocationNeverLeaks covers the POST
// walk (307 preserves the method; the cookie must never follow).
func TestFetchUsageEventsPostRedirectLocationNeverLeaks(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer target.Close()
	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/steal-"+strings.ToUpper(testToken), http.StatusTemporaryRedirect)
	})
	client := newTestClient(t, server, nil)

	_, err := client.FetchUsageEvents(t.Context(), api.Session{Token: testToken}, api.FetchOptions{})
	assertNoTransportEcho(t, err)
	if n := hits.Load(); n != 0 {
		t.Fatalf("the redirect target must receive zero requests, got %d", n)
	}
}

// TestTransportErrorsKeepIsAsAndFixedText pins the wrapper's contract:
// cancellation, deadlines and net.Error shapes stay matchable through
// Unwrap while the rendered message is fixed wording only.
func TestTransportErrorsKeepIsAsAndFixedText(t *testing.T) {
	t.Run("client timeout stays a deadline", func(t *testing.T) {
		release := make(chan struct{})
		server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
			<-release
		})
		t.Cleanup(func() { close(release) })
		client := newTestClient(t, server, func(o *api.Options) { o.Timeout = 80 * time.Millisecond })

		_, err := client.FetchUsageSummary(t.Context(), api.Session{Token: testToken})
		assertNoTransportEcho(t, err)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("the deadline must stay detectable through the wrapper, got %v", err)
		}
		if !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("the fixed wording must identify the timeout: %v", err)
		}
	})

	t.Run("cancellation stays detectable with fixed text", func(t *testing.T) {
		release := make(chan struct{})
		server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
			<-release
		})
		t.Cleanup(func() { close(release) })
		client := newTestClient(t, server, nil)

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()
		_, err := client.FetchUsageSummary(ctx, api.Session{Token: testToken})
		assertNoTransportEcho(t, err)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation must stay detectable through the wrapper, got %v", err)
		}
	})

	t.Run("connection refused keeps the url.Error reachable", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		server.Close()
		client := newTestClient(t, server.URL, nil)

		_, err := client.FetchUsageSummary(t.Context(), api.Session{Token: testToken})
		assertNoTransportEcho(t, err)
		var urlErr *url.Error
		if !errors.As(err, &urlErr) {
			t.Fatalf("the url.Error must stay reachable through As, got %v", err)
		}
		var netErr net.Error
		if !errors.As(err, &netErr) {
			t.Fatalf("the net.Error shape must stay reachable through As, got %v", err)
		}
		if !strings.Contains(err.Error(), "transport failure") {
			t.Fatalf("an unrecognized transport shape must render the withheld-cause wording: %v", err)
		}
	})
}
