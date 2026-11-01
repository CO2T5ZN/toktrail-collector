package status

// Security-boundary tests for the device self status query. The GET
// carries the device credential, so every test drives hostile or broken
// servers through t.TempDir state directories and httptest servers and
// asserts the fail-closed contract: redirects never followed (zero
// requests to the redirect target, caller client untouched), no server
// free text or credential material ever echoed into an error, and the
// persisted device.json byte-for-byte unchanged on every failure.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/local/statedir"
)

func TestRunStatusUsesLocalCredentialAndPersistsServerState(t *testing.T) {
	store := statedir.New(t.TempDir())
	secret := strings.Repeat("a", 64)
	if err := store.Save(statedir.DeviceState{ServerURL: "http://unused", DeviceID: "dev-1", DeviceSecret: secret}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/devices/self" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer dev-1."+secret {
			t.Fatalf("unexpected auth header %q", got)
		}
		writeJSON(w, http.StatusOK, map[string]any{"device": map[string]any{
			"deviceId":          "dev-1",
			"applicationId":     "leaderboard-local",
			"externalSubjectId": "user-1",
			"deviceName":        "MacBook",
			"platform":          "darwin-arm64",
			"consentRevision":   2,
			"uploadAuthorized":  true,
			"publicAuthorized":  false,
			"revoked":           false,
			"checkedAt":         "2026-10-20T10:11:00Z",
		}})
	}))
	defer server.Close()
	res, err := Run(t.Context(), store, Options{ServerURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if res.State.ConsentRevision != 2 || !res.State.UploadAuthorized || res.State.PublicAuthorized || res.State.LastCheckedAt.IsZero() {
		t.Fatalf("unexpected status result: %#v", res.State)
	}
	saved, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if saved.ConsentRevision != 2 || saved.ApplicationID != "leaderboard-local" || saved.DeviceSecret != secret {
		t.Fatalf("status was not persisted: %#v", saved)
	}
	if saved.ExternalSubjectID != "user-1" {
		t.Fatalf("empty subject identity must be backfilled, got %#v", saved)
	}
	// A --server override targets the query, never the binding.
	if saved.ServerURL != "http://unused" {
		t.Fatalf("status must not rebind the bound server URL, got %q", saved.ServerURL)
	}
}

func TestRunStatusRequiresBoundDevice(t *testing.T) {
	_, err := Run(t.Context(), statedir.New(t.TempDir()), Options{})
	if err == nil {
		t.Fatal("expected unbound error")
	}
}

func TestRunStatusReturnsServerError(t *testing.T) {
	store := statedir.New(t.TempDir())
	secret := strings.Repeat("a", 64)
	if err := store.Save(statedir.DeviceState{DeviceID: "dev-1", DeviceSecret: secret}); err != nil {
		t.Fatal(err)
	}
	before := stateFileBytes(t, store)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]any{
			"code":    "unauthorized-" + secret,
			"message": "MARKERXYZ bad credential " + strings.ToUpper(secret),
		}})
	}))
	defer server.Close()
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL})
	if err == nil {
		t.Fatal("expected server error")
	}
	assertNoEcho(t, err.Error(), secret, "MARKERXYZ")
	assertStateUnchanged(t, before, store)
}

// redirectPair builds two servers: the first answers GET /v1/devices/self
// with a redirect of the given code aimed at the second; the second
// records any request it ever receives (it must stay at zero). It also
// counts every request the redirecting server itself receives.
func redirectPair(t *testing.T, code int) (*httptest.Server, *atomic.Int64, *atomic.Int64) {
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
	return redirector, &targetHits, &redirectorHits
}

// boundStore saves a bound state and returns the store plus the exact
// on-disk bytes for byte-identity assertions.
func boundStore(t *testing.T, serverURL, deviceID, secret string, extra ...func(*statedir.DeviceState)) (statedir.Store, []byte) {
	t.Helper()
	st := statedir.DeviceState{ServerURL: serverURL, DeviceID: deviceID, DeviceSecret: secret}
	for _, fn := range extra {
		fn(&st)
	}
	store := statedir.New(t.TempDir())
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	return store, stateFileBytes(t, store)
}

func TestRunStatusRefusesRedirects(t *testing.T) {
	for _, code := range []int{
		http.StatusMovedPermanently,  // 301
		http.StatusFound,             // 302
		http.StatusSeeOther,          // 303
		http.StatusTemporaryRedirect, // 307
		http.StatusPermanentRedirect, // 308
	} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			redirector, targetHits, redirectorHits := redirectPair(t, code)
			store, before := boundStore(t, redirector.URL, "dev-redirect", "redirect-secret")

			_, err := Run(t.Context(), store, Options{ServerURL: redirector.URL})
			if err == nil {
				t.Fatal("a redirecting self endpoint must fail closed, not succeed")
			}
			if !errors.Is(err, errStatusRedirect) {
				t.Fatalf("expected the redirect refusal to surface, got %v", err)
			}
			if got := targetHits.Load(); got != 0 {
				t.Fatalf("the redirect target must receive ZERO requests (credential leak), got %d", got)
			}
			if got := redirectorHits.Load(); got != 1 {
				t.Fatalf("exactly one request may reach the redirecting server, got %d", got)
			}
			assertStateUnchanged(t, before, store)
		})
	}
}

// TestRunStatusRedirectRefusalLeavesCallerClientUntouched pins the
// shallow-clone contract: the caller's http.Client object keeps its own
// CheckRedirect (nil here) and Timeout after the status query ran.
func TestRunStatusRedirectRefusalLeavesCallerClientUntouched(t *testing.T) {
	redirector, targetHits, _ := redirectPair(t, http.StatusFound)
	store, before := boundStore(t, redirector.URL, "dev-redirect", "redirect-secret")

	caller := &http.Client{Timeout: 3 * time.Second}
	if caller.CheckRedirect != nil {
		t.Fatal("precondition: the caller client must start without a CheckRedirect")
	}
	_, err := Run(t.Context(), store, Options{ServerURL: redirector.URL, HTTPClient: caller})
	if err == nil {
		t.Fatal("expected the redirect to fail closed")
	}
	if !errors.Is(err, errStatusRedirect) {
		t.Fatalf("expected the redirect refusal to surface, got %v", err)
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
	assertStateUnchanged(t, before, store)
}

func TestRunStatusRefusesDifferentDevice(t *testing.T) {
	store, before := boundStore(t, "", "dev-1", strings.Repeat("a", 64))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"device": map[string]any{
			"deviceId":          "dev-other",
			"applicationId":     "app-other",
			"externalSubjectId": "subject-other",
			"deviceName":        "NotThisDevice",
			"consentRevision":   99,
			"uploadAuthorized":  true,
			"checkedAt":         "2026-10-20T10:11:00Z",
		}})
	}))
	defer server.Close()
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL})
	if err == nil {
		t.Fatal("a response describing another device must fail closed")
	}
	assertNoEcho(t, err.Error(), "dev-other", "app-other", "subject-other", "NotThisDevice")
	assertStateUnchanged(t, before, store)
}

func TestRunStatusRefusesReflectedSecret(t *testing.T) {
	// A mixed-case secret proves the check is case-insensitive in both
	// directions: upper- and lower-cased reflections must both be caught.
	secret := "aBcD" + strings.Repeat("e", 60)
	for _, tc := range []struct {
		name  string
		field string
		value string
	}{
		{"deviceName", "deviceName", strings.ToUpper(secret)},
		{"platform", "platform", strings.ToLower(secret)},
		{"applicationId", "applicationId", "app-" + secret},
		{"externalSubjectId", "externalSubjectId", "subject-" + strings.ToUpper(secret)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, before := boundStore(t, "", "dev-1", secret)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, http.StatusOK, map[string]any{"device": map[string]any{
					"deviceId":        "dev-1",
					tc.field:          tc.value,
					"consentRevision": 7,
					"checkedAt":       "2026-10-20T10:11:00Z",
				}})
			}))
			defer server.Close()
			_, err := Run(t.Context(), store, Options{ServerURL: server.URL})
			if err == nil {
				t.Fatal("a response reflecting the device secret must fail closed")
			}
			assertNoEcho(t, err.Error(), secret, strings.ToUpper(secret), strings.ToLower(secret))
			assertStateUnchanged(t, before, store)
		})
	}
}

func TestRunStatusRefusesIdentityMismatch(t *testing.T) {
	newServer := func(t *testing.T, applicationID, subjectID string) *httptest.Server {
		t.Helper()
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"device": map[string]any{
				"deviceId":          "dev-1",
				"applicationId":     applicationID,
				"externalSubjectId": subjectID,
				"consentRevision":   3,
				"uploadAuthorized":  true,
				"checkedAt":         "2026-10-20T10:11:00Z",
			}})
		}))
	}
	t.Run("application mismatch", func(t *testing.T) {
		store, before := boundStore(t, "", "dev-1", strings.Repeat("a", 64),
			func(st *statedir.DeviceState) { st.ApplicationID = "app-1"; st.ExternalSubjectID = "user-1" })
		server := newServer(t, "app-2", "user-1")
		defer server.Close()
		_, err := Run(t.Context(), store, Options{ServerURL: server.URL})
		if err == nil {
			t.Fatal("a same-device response with a different application identity must fail closed")
		}
		assertNoEcho(t, err.Error(), "app-2")
		assertStateUnchanged(t, before, store)
	})
	t.Run("subject mismatch", func(t *testing.T) {
		store, before := boundStore(t, "", "dev-1", strings.Repeat("a", 64),
			func(st *statedir.DeviceState) { st.ApplicationID = "app-1"; st.ExternalSubjectID = "user-1" })
		server := newServer(t, "app-1", "user-2")
		defer server.Close()
		_, err := Run(t.Context(), store, Options{ServerURL: server.URL})
		if err == nil {
			t.Fatal("a same-device response with a different subject identity must fail closed")
		}
		assertNoEcho(t, err.Error(), "user-2")
		assertStateUnchanged(t, before, store)
	})
	t.Run("empty identity backfills", func(t *testing.T) {
		store, _ := boundStore(t, "", "dev-1", strings.Repeat("a", 64))
		server := newServer(t, "app-9", "user-9")
		defer server.Close()
		if _, err := Run(t.Context(), store, Options{ServerURL: server.URL}); err != nil {
			t.Fatal(err)
		}
		saved, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		if saved.ApplicationID != "app-9" || saved.ExternalSubjectID != "user-9" {
			t.Fatalf("empty identity fields must be backfilled, got %#v", saved)
		}
	})
}

func TestRunStatusDoesNotRebindServerURL(t *testing.T) {
	valid := func(t *testing.T) *httptest.Server {
		t.Helper()
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"device": map[string]any{
				"deviceId":         "dev-1",
				"consentRevision":  4,
				"uploadAuthorized": true,
				"checkedAt":        "2026-10-20T10:11:00Z",
			}})
		}))
	}
	t.Run("override does not rebind", func(t *testing.T) {
		store, _ := boundStore(t, "http://bound.example", "dev-1", strings.Repeat("a", 64))
		server := valid(t)
		defer server.Close()
		if _, err := Run(t.Context(), store, Options{ServerURL: server.URL}); err != nil {
			t.Fatal(err)
		}
		saved, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		if saved.ServerURL != "http://bound.example" {
			t.Fatalf("a --server override must not rebind the bound server, got %q", saved.ServerURL)
		}
	})
	t.Run("empty server URL backfills", func(t *testing.T) {
		store, _ := boundStore(t, "", "dev-1", strings.Repeat("a", 64))
		server := valid(t)
		defer server.Close()
		if _, err := Run(t.Context(), store, Options{ServerURL: server.URL}); err != nil {
			t.Fatal(err)
		}
		saved, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		if saved.ServerURL != server.URL {
			t.Fatalf("an empty server URL must be backfilled from the queried server, got %q", saved.ServerURL)
		}
	})
}

func TestRunStatusPersistsRevokedState(t *testing.T) {
	secret := strings.Repeat("a", 64)
	store, _ := boundStore(t, "", "dev-1", secret)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"device": map[string]any{
			"deviceId":         "dev-1",
			"consentRevision":  5,
			"uploadAuthorized": false,
			"publicAuthorized": false,
			"revoked":          true,
			"checkedAt":        "2026-10-21T10:11:00Z",
		}})
	}))
	defer server.Close()
	res, err := Run(t.Context(), store, Options{ServerURL: server.URL})
	if err != nil {
		t.Fatalf("a legitimate revoked snapshot must persist, got %v", err)
	}
	if !res.State.Revoked || res.State.UploadAuthorized {
		t.Fatalf("unexpected revoked result: %#v", res.State)
	}
	saved, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !saved.Revoked || saved.UploadAuthorized || saved.ConsentRevision != 5 || saved.DeviceSecret != secret {
		t.Fatalf("revoked state was not persisted correctly: %#v", saved)
	}
}

func TestRunStatusTransportCancellationClassifies(t *testing.T) {
	t.Run("canceled", func(t *testing.T) {
		store, before := boundStore(t, "", "dev-1", strings.Repeat("a", 64))
		var hits atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			writeJSON(w, http.StatusOK, map[string]any{"device": map[string]any{"deviceId": "dev-1"}})
		}))
		defer server.Close()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := Run(ctx, store, Options{ServerURL: server.URL})
		if err == nil {
			t.Fatal("expected a transport error")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation must stay matchable through the sanitized wrapper, got %v", err)
		}
		if !strings.Contains(err.Error(), "canceled") {
			t.Fatalf("expected fixed canceled wording, got %q", err.Error())
		}
		// The raw url.Error names the endpoint; it must never surface.
		assertNoEcho(t, err.Error(), server.URL)
		assertStateUnchanged(t, before, store)
	})
	t.Run("deadline exceeded", func(t *testing.T) {
		store, before := boundStore(t, "", "dev-1", strings.Repeat("a", 64))
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Outlive the 50ms run-context deadline; Close() then only
			// waits out this short handler.
			time.Sleep(250 * time.Millisecond)
			writeJSON(w, http.StatusOK, map[string]any{"device": map[string]any{"deviceId": "dev-1"}})
		}))
		defer server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, err := Run(ctx, store, Options{ServerURL: server.URL})
		if err == nil {
			t.Fatal("expected a transport error")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("a run-context deadline must stay matchable through the sanitized wrapper, got %v", err)
		}
		if !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("expected fixed timed-out wording, got %q", err.Error())
		}
		assertNoEcho(t, err.Error(), server.URL)
		assertStateUnchanged(t, before, store)
	})
}

func TestRunStatusRejectsOversizedBody(t *testing.T) {
	store, before := boundStore(t, "", "dev-1", strings.Repeat("a", 64))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"device":{"deviceName":"`))
		chunk := strings.Repeat("a", 64*1024)
		// 130 chunks = 8.125 MiB, past the 8 MiB cap, and the JSON
		// value never closes so the decoder stays hungry.
		for i := 0; i < 130; i++ {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL})
	if err == nil {
		t.Fatal("an over-cap response body must fail closed")
	}
	if !strings.Contains(err.Error(), "safety limit") {
		t.Fatalf("expected the fixed safety-limit wording, got %q", err.Error())
	}
	if !errors.Is(err, errResponseBodyTooLarge) {
		t.Fatalf("the over-cap outcome must stay matchable, got %v", err)
	}
	assertStateUnchanged(t, before, store)
}

func TestRunStatusSanitizesDecodeError(t *testing.T) {
	store, before := boundStore(t, "", "dev-1", strings.Repeat("a", 64))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Invalid, unterminated JSON: the decoder's syntax error would
		// quote body content, which must never reach the error text.
		_, _ = w.Write([]byte(`{"device":{"deviceName":"DECODEMARKER`))
	}))
	defer server.Close()
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL})
	if err == nil {
		t.Fatal("expected a decode error")
	}
	assertNoEcho(t, err.Error(), "DECODEMARKER")
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("the truncated-body cause must stay matchable through the sanitized wrapper, got %v", err)
	}
	assertStateUnchanged(t, before, store)
}

// stateFileBytes reads the exact on-disk device.json bytes.
func stateFileBytes(t *testing.T, store statedir.Store) []byte {
	t.Helper()
	b, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// assertStateUnchanged proves zero state modification: the persisted
// device.json is byte-for-byte identical to before the failed run.
func assertStateUnchanged(t *testing.T, before []byte, store statedir.Store) {
	t.Helper()
	after := stateFileBytes(t, store)
	if !bytes.Equal(before, after) {
		t.Fatalf("the persisted state must stay byte-for-byte unchanged on failure\nbefore: %s\nafter:  %s", before, after)
	}
}

// assertNoEcho fails when any fragment (compared case-insensitively)
// appears in the surfaced error text.
func assertNoEcho(t *testing.T, text string, fragments ...string) {
	t.Helper()
	lowered := strings.ToLower(text)
	for _, fragment := range fragments {
		if fragment != "" && strings.Contains(lowered, strings.ToLower(fragment)) {
			t.Fatalf("error text must not echo untrusted or credential material (%q leaked): %q", fragment, text)
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
