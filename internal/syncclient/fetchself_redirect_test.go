package syncclient

// Redirect protection for the device self GET: the request carries the
// device credential, so a 3xx answer must never be followed. These tests
// stand up a redirecting server aimed at a second server that records
// every request, and assert the second server sees ZERO requests (no
// credential ever leaves the first hop) while the run fails closed.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/local/statedir"
)

// redirectPair builds two servers: the first answers GET /v1/devices/self
// with a redirect of the given code aimed at the second; the second
// records any request it ever receives (it must stay at zero). It also
// counts every request the redirecting server itself receives.
func redirectPair(t *testing.T, code int) (*httptest.Server, *httptest.Server, *atomic.Int64, *atomic.Int64) {
	t.Helper()
	var targetHits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)
	var redirectorHits atomic.Int64
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectorHits.Add(1)
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			http.Redirect(w, r, target.URL+"/v1/devices/self", code)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(redirector.Close)
	return redirector, target, &targetHits, &redirectorHits
}

// boundStoreForRedirect prepares a bound state directory so the self GET
// carries a credential a redirect would leak.
func boundStoreForRedirect(t *testing.T, serverURL string) statedir.Store {
	t.Helper()
	stateDir := t.TempDir()
	store := statedir.New(stateDir)
	if err := store.Save(statedir.DeviceState{
		ServerURL:    serverURL,
		DeviceID:     "dev-redirect",
		DeviceSecret: "redirect-secret",
	}); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestFetchDeviceSelfRefusesRedirects(t *testing.T) {
	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			redirector, _, targetHits, redirectorHits := redirectPair(t, code)
			store := boundStoreForRedirect(t, redirector.URL)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := FetchDeviceSelf(ctx, store, Options{ServerURL: redirector.URL})
			if err == nil {
				t.Fatal("a redirecting self endpoint must fail closed, not succeed")
			}
			// The refusal is matched programmatically: the sanitized
			// transport wrapper states the cause in fixed wording and
			// never echoes the raw error text.
			if !errors.Is(err, errDeviceRedirect) {
				t.Fatalf("expected the redirect refusal to surface, got %v", err)
			}
			if got := targetHits.Load(); got != 0 {
				t.Fatalf("the redirect target must receive ZERO requests (credential leak), got %d", got)
			}
			if got := redirectorHits.Load(); got != 1 {
				t.Fatalf("exactly one request may reach the redirecting server, got %d", got)
			}
		})
	}
}

// TestFetchDeviceSelfRedirectRefusalLeavesCallerClientUntouched pins the
// clone contract: the caller's http.Client object keeps its own
// CheckRedirect (nil here) and Timeout after the self GET ran.
func TestFetchDeviceSelfRedirectRefusalLeavesCallerClientUntouched(t *testing.T) {
	redirector, _, targetHits, _ := redirectPair(t, http.StatusFound)
	store := boundStoreForRedirect(t, redirector.URL)

	caller := &http.Client{Timeout: 3 * time.Second}
	if caller.CheckRedirect != nil {
		t.Fatal("precondition: the caller client must start without a CheckRedirect")
	}
	_, err := FetchDeviceSelf(t.Context(), store, Options{ServerURL: redirector.URL, HTTPClient: caller})
	if err == nil {
		t.Fatal("expected the redirect to fail closed")
	}
	if caller.CheckRedirect != nil {
		t.Fatal("the caller's client object must never be modified")
	}
	if caller.Timeout != 3*time.Second {
		t.Fatalf("the caller's timeout must be preserved, got %s", caller.Timeout)
	}
	if got := targetHits.Load(); got != 0 {
		t.Fatalf("the redirect target must receive ZERO requests, got %d", got)
	}
}

// TestRunPreflightSelfRefusesRedirects drives the refusal through the
// full send path (Run's preflight): exactly ONE request is made to the
// redirecting server, no ingest POST follows, and the run fails closed.
func TestRunPreflightSelfRefusesRedirects(t *testing.T) {
	redirector, _, targetHits, redirectorHits := redirectPair(t, http.StatusFound)
	stateDir := t.TempDir()
	store := statedir.New(stateDir)
	if err := store.Save(statedir.DeviceState{
		ServerURL:    redirector.URL,
		DeviceID:     "dev-redirect",
		DeviceSecret: "redirect-secret",
	}); err != nil {
		t.Fatal(err)
	}
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": "batch-redirect-1",
		"records": []map[string]any{{
			"recordKey":      "record-redirect-1",
			"kind":           "delta",
			"occurredAt":     "2026-10-20T10:00:00Z",
			"tool":           "usage-json",
			"input":          "10",
			"cacheRead":      "0",
			"cacheWrite":     "0",
			"output":         "5",
			"adapterVersion": "test-adapter-1",
			"sourceType":     "fixture",
		}},
	})

	_, err := Run(t.Context(), store, Options{
		ServerURL: redirector.URL,
		BatchFile: batchFile,
		BatchID:   "batch-redirect-1",
	})
	if err == nil {
		t.Fatal("the run must fail closed when the self preflight is a redirect")
	}
	if !errors.Is(err, errDeviceRedirect) {
		t.Fatalf("expected the redirect refusal to surface, got %v", err)
	}
	if got := redirectorHits.Load(); got != 1 {
		t.Fatalf("exactly one request (the redirect answer) may happen, got %d", got)
	}
	if got := targetHits.Load(); got != 0 {
		t.Fatalf("the redirect target must receive ZERO requests, got %d", got)
	}
}
