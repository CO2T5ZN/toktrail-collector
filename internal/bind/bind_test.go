package bind

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/local/statedir"
)

func TestRunBindGeneratesLocalSecretAndPersistsReceipt(t *testing.T) {
	var got bindRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/devices/bind" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.Ticket != "ticket-1" || got.DeviceSecret == "" || len(got.DeviceSecret) != 64 || got.RequestID == "" {
			t.Fatalf("unexpected bind request: %#v", got)
		}
		writeJSON(w, http.StatusCreated, map[string]any{"device": map[string]any{
			"deviceId":          "dev-1",
			"applicationId":     got.ApplicationID,
			"externalSubjectId": got.ExternalSubjectID,
			"deviceName":        got.DeviceName,
			"platform":          got.Platform,
			"consentRevision":   1,
			"boundAt":           "2026-10-20T10:00:00Z",
			"replay":            false,
		}})
	}))
	defer server.Close()

	store := statedir.New(t.TempDir())
	res, err := Run(t.Context(), store, Options{
		ServerURL:         server.URL,
		Ticket:            "ticket-1",
		ApplicationID:     "leaderboard-local",
		ExternalSubjectID: "user-1",
		DeviceName:        "MacBook",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.State.DeviceID != "dev-1" || res.State.DeviceSecret == "" || res.State.BindRequestID == "" || res.Replay {
		t.Fatalf("unexpected result: %#v", res)
	}
	saved, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if saved.DeviceSecret != got.DeviceSecret || saved.BindRequestID != got.RequestID || saved.ConsentRevision != 1 {
		t.Fatalf("state was not persisted correctly: %#v", saved)
	}
}

func TestRunBindReusesRequestIDAndSecretForReplay(t *testing.T) {
	store := statedir.New(t.TempDir())
	initialSecret := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	initialRequest := "req-replay"
	if err := store.Save(statedir.DeviceState{DeviceSecret: initialSecret, BindRequestID: initialRequest}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got bindRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.DeviceSecret != initialSecret || got.RequestID != initialRequest {
			t.Fatalf("did not reuse local replay identity: %#v", got)
		}
		writeJSON(w, http.StatusOK, map[string]any{"device": map[string]any{
			"deviceId":          "dev-1",
			"applicationId":     got.ApplicationID,
			"externalSubjectId": got.ExternalSubjectID,
			"deviceName":        got.DeviceName,
			"platform":          got.Platform,
			"consentRevision":   1,
			"boundAt":           time.Now().UTC().Format(time.RFC3339),
			"replay":            true,
		}})
	}))
	defer server.Close()
	res, err := Run(t.Context(), store, Options{ServerURL: server.URL, Ticket: "ticket-1", ExternalSubjectID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Replay || res.Status != http.StatusOK {
		t.Fatalf("expected replay OK, got %#v", res)
	}
}

func TestRunBindGeneratesFreshRequestIDAfterSuccessfulBind(t *testing.T) {
	store := statedir.New(t.TempDir())
	initialSecret := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	initialRequest := "req-bound"
	if err := store.Save(statedir.DeviceState{DeviceID: "dev-old", DeviceSecret: initialSecret, BindRequestID: initialRequest}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got bindRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.DeviceSecret != initialSecret {
			t.Fatalf("expected existing device secret reuse, got %#v", got)
		}
		if got.RequestID == "" || got.RequestID == initialRequest {
			t.Fatalf("expected fresh request ID after prior successful bind, got %#v", got)
		}
		writeJSON(w, http.StatusCreated, map[string]any{"device": map[string]any{
			"deviceId":          "dev-new",
			"applicationId":     got.ApplicationID,
			"externalSubjectId": got.ExternalSubjectID,
			"deviceName":        got.DeviceName,
			"platform":          got.Platform,
			"consentRevision":   2,
			"boundAt":           time.Now().UTC().Format(time.RFC3339),
			"replay":            false,
		}})
	}))
	defer server.Close()
	res, err := Run(t.Context(), store, Options{ServerURL: server.URL, Ticket: "ticket-2", ExternalSubjectID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.State.DeviceID != "dev-new" || res.State.BindRequestID == initialRequest {
		t.Fatalf("unexpected refreshed bind state: %#v", res.State)
	}
}

func TestRunBindReturnsServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]any{"code": "unauthorized", "message": "bad ticket"}})
	}))
	defer server.Close()
	_, err := Run(t.Context(), statedir.New(t.TempDir()), Options{ServerURL: server.URL, Ticket: "wrong", ExternalSubjectID: "user-1"})
	if err == nil {
		t.Fatal("expected bind error")
	}
	if !strings.Contains(err.Error(), "status 401") || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("expected whitelisted category and status in error, got %q", err.Error())
	}
	if strings.Contains(err.Error(), "bad ticket") {
		t.Fatalf("server free-text message leaked into error: %q", err.Error())
	}
	var be *Error
	if !errors.As(err, &be) || be.Category() != "unauthorized" || be.Status() != http.StatusUnauthorized {
		t.Fatalf("unexpected sanitized error: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestLostBindResponsePersistsReplayIdentity(t *testing.T) {
	store := statedir.New(t.TempDir())
	var requests []bindRequest
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var request bindRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		requests = append(requests, request)
		saved, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		if saved.DeviceSecret != request.DeviceSecret || saved.BindRequestID != request.RequestID || saved.PendingBindFingerprint == "" {
			t.Fatal("replay identity was not durable before network request")
		}
		if len(requests) == 1 {
			return nil, errors.New("response lost after server accepted ticket")
		}
		body, _ := json.Marshal(map[string]any{"device": map[string]any{
			"deviceId": "dev-1", "applicationId": request.ApplicationID,
			"externalSubjectId": request.ExternalSubjectID, "replay": true,
		}})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header)}, nil
	})}
	opt := Options{Ticket: "ticket-one", ExternalSubjectID: "user-1", HTTPClient: client}
	if _, err := Run(t.Context(), store, opt); err == nil {
		t.Fatal("expected lost response")
	}
	result, err := Run(t.Context(), store, opt)
	if err != nil {
		t.Fatal(err)
	}
	if requests[0] != requests[1] || !result.Replay {
		t.Fatal("retry changed bind payload")
	}
	if result.State.PendingBindFingerprint != "" {
		t.Fatal("confirmed bind retained pending marker")
	}
	data, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "ticket-one") {
		t.Fatal("plaintext ticket persisted")
	}
}

func TestReplacementTicketGetsNewRequestAfterFailure(t *testing.T) {
	store := statedir.New(t.TempDir())
	var requests []bindRequest
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var request bindRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		requests = append(requests, request)
		return nil, errors.New("network unavailable")
	})}
	opt := Options{Ticket: "ticket-one", ExternalSubjectID: "user-1", HTTPClient: client}
	_, _ = Run(t.Context(), store, opt)
	opt.Ticket = "ticket-two"
	_, _ = Run(t.Context(), store, opt)
	if len(requests) != 2 || requests[0].RequestID == requests[1].RequestID || requests[0].DeviceSecret != requests[1].DeviceSecret {
		t.Fatal("replacement ticket did not get fresh request identity with existing device secret")
	}
}

// assertNoCredentialLeak renders err the ways a CLI surfaces errors to humans
// (direct printing plus %v/%w wrapping) and fails if the bind ticket or
// deviceSecret appears in any rendering.
func assertNoCredentialLeak(t *testing.T, err error, ticket, deviceSecret string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected bind error")
	}
	renderings := []string{
		err.Error(),
		fmt.Sprint(err),
		fmt.Sprintf("%v", err),
		fmt.Errorf("direct bind: %w", err).Error(),
		fmt.Errorf("direct bind: %v", err).Error(),
	}
	for _, text := range renderings {
		for _, credential := range []string{ticket, deviceSecret} {
			if credential != "" && strings.Contains(text, credential) {
				t.Fatalf("credential leaked into error text: %q", text)
			}
		}
	}
}

func TestRunBindHostileServerReflectingCredentialsNeverLeaks(t *testing.T) {
	ticket := "ticket-hostile-reflect-0123456789abcdef"
	var mu sync.Mutex
	var deviceSecret string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got bindRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		deviceSecret = got.DeviceSecret
		mu.Unlock()
		// Hostile server reflects the request ticket and deviceSecret
		// verbatim into the error code and message.
		writeJSON(w, http.StatusTeapot, map[string]any{
			"error": map[string]any{"code": got.Ticket, "message": got.DeviceSecret},
		})
	}))
	defer server.Close()

	_, err := Run(t.Context(), statedir.New(t.TempDir()), Options{ServerURL: server.URL, Ticket: ticket, ExternalSubjectID: "user-1"})
	mu.Lock()
	secret := deviceSecret
	mu.Unlock()
	assertNoCredentialLeak(t, err, ticket, secret)

	var be *Error
	if !errors.As(err, &be) {
		t.Fatalf("expected *Error, got %T", err)
	}
	if be.Category() != CategoryOther {
		t.Fatalf("expected unknown reflected code to collapse to %q, got %q", CategoryOther, be.Category())
	}
	if be.Status() != http.StatusTeapot {
		t.Fatalf("expected status %d, got %d", http.StatusTeapot, be.Status())
	}
	if !strings.Contains(err.Error(), fmt.Sprint(http.StatusTeapot)) {
		t.Fatalf("expected numeric status in error, got %q", err.Error())
	}
}

func TestRunBindWhitelistedCodeWithHostileMessageNeverLeaks(t *testing.T) {
	ticket := "ticket-whitelist-789abcdef0123"
	var mu sync.Mutex
	var deviceSecret string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got bindRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		deviceSecret = got.DeviceSecret
		mu.Unlock()
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": map[string]any{"code": "unauthorized", "message": got.DeviceSecret},
		})
	}))
	defer server.Close()

	_, err := Run(t.Context(), statedir.New(t.TempDir()), Options{ServerURL: server.URL, Ticket: ticket, ExternalSubjectID: "user-1"})
	mu.Lock()
	secret := deviceSecret
	mu.Unlock()
	assertNoCredentialLeak(t, err, ticket, secret)

	var be *Error
	if !errors.As(err, &be) || be.Category() != "unauthorized" || be.Status() != http.StatusUnauthorized {
		t.Fatalf("unexpected sanitized error: %v", err)
	}
	if !strings.Contains(err.Error(), "status 401") {
		t.Fatalf("expected status in error, got %q", err.Error())
	}
}

func TestRunBindMalformedBodyNeverLeaksCredentials(t *testing.T) {
	ticket := "ticket-malformed-9876543210abcdef"
	var mu sync.Mutex
	var deviceSecret string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got bindRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		deviceSecret = got.DeviceSecret
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Malformed body that reflects both credentials verbatim.
		_, _ = fmt.Fprintf(w, "<<%s|%s>> is not json", got.Ticket, got.DeviceSecret)
	}))
	defer server.Close()

	_, err := Run(t.Context(), statedir.New(t.TempDir()), Options{ServerURL: server.URL, Ticket: ticket, ExternalSubjectID: "user-1"})
	mu.Lock()
	secret := deviceSecret
	mu.Unlock()
	assertNoCredentialLeak(t, err, ticket, secret)

	var be *Error
	if !errors.As(err, &be) || be.Category() != CategoryInvalidResponse || be.Status() != http.StatusOK {
		t.Fatalf("unexpected sanitized error: %v", err)
	}
	var syntaxErr *json.SyntaxError
	if !errors.As(err, &syntaxErr) {
		t.Fatal("expected underlying json.SyntaxError to stay reachable via errors.As")
	}
}

func TestRunBindOversizedBodyFailsWithSanitizedError(t *testing.T) {
	ticket := "ticket-oversized-1234abcdef"
	var mu sync.Mutex
	var deviceSecret string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got bindRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		deviceSecret = got.DeviceSecret
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		// A single JSON value far beyond maxResponseBodyBytes, with the
		// credentials reflected at the start of it.
		_, _ = fmt.Fprintf(w, `{"padding":"%s%s%s"}`, got.Ticket, got.DeviceSecret, strings.Repeat("x", 2*maxResponseBodyBytes))
	}))
	defer server.Close()

	_, err := Run(t.Context(), statedir.New(t.TempDir()), Options{ServerURL: server.URL, Ticket: ticket, ExternalSubjectID: "user-1"})
	mu.Lock()
	secret := deviceSecret
	mu.Unlock()
	assertNoCredentialLeak(t, err, ticket, secret)

	var be *Error
	if !errors.As(err, &be) || be.Category() != CategoryInvalidResponse {
		t.Fatalf("unexpected sanitized error: %v", err)
	}
}

func TestRunBindAcceptsLargeLegitimateReceipt(t *testing.T) {
	// Documents the headroom of maxResponseBodyBytes: a receipt padded far
	// beyond any realistic size (but under the ceiling) still binds, so the
	// bound cannot reject large legitimate receipts.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got bindRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"device": map[string]any{
				"deviceId":          "dev-big",
				"applicationId":     got.ApplicationID,
				"externalSubjectId": got.ExternalSubjectID,
				"replay":            false,
			},
			"receiptPadding": strings.Repeat("p", maxResponseBodyBytes/2),
		})
	}))
	defer server.Close()

	res, err := Run(t.Context(), statedir.New(t.TempDir()), Options{ServerURL: server.URL, Ticket: "ticket-big", ExternalSubjectID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.State.DeviceID != "dev-big" || res.Replay {
		t.Fatalf("unexpected result: %#v", res)
	}
}

var errTransportSentinel = errors.New("sentinel transport failure")

func TestRunBindTransportErrorEchoingBindPayloadIsSuppressed(t *testing.T) {
	ticket := "ticket-transport-echo-456789abcdef"
	store := statedir.New(t.TempDir())
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		// Hostile transport echoes the whole request body (this run's ticket
		// and deviceSecret included) inside its error text.
		return nil, fmt.Errorf("upstream rejected request %q: %w", string(payload), errTransportSentinel)
	})}
	_, err := Run(t.Context(), store, Options{Ticket: ticket, ExternalSubjectID: "user-1", HTTPClient: client})
	if err == nil {
		t.Fatal("expected transport error")
	}
	saved, serr := store.Load()
	if serr != nil {
		t.Fatal(serr)
	}
	assertNoCredentialLeak(t, err, ticket, saved.DeviceSecret)
	if err.Error() != transportErrorMessage {
		t.Fatalf("expected the fixed transport message, got %q", err.Error())
	}

	var be *Error
	if !errors.As(err, &be) || be.Category() != CategoryTransport {
		t.Fatalf("unexpected sanitized error: %v", err)
	}
	if !errors.Is(err, errTransportSentinel) {
		t.Fatal("expected wrapped sentinel to stay reachable via errors.Is")
	}
}

func TestRunBindTransportErrorNeverSurfacesErrorText(t *testing.T) {
	// Transport error text can carry secrets that are NOT this run's
	// credentials (another principal's password, proxy details), so the
	// surfaced message must be fixed regardless of the cause's content.
	for _, tc := range []struct {
		name    string
		ticket  string
		errText string
		markers []string
	}{
		{
			name:    "unrelated_secret_in_error_text",
			ticket:  "ticket-transport-other-1234567890",
			errText: "proxy auth failed for user admin: password=OtherDeviceSecret999 via proxy.internal:3128",
			markers: []string{"OtherDeviceSecret999", "proxy.internal", "admin"},
		},
		{
			name:    "clean_network_text",
			ticket:  "ticket-transport-clean-abcdefghij",
			errText: "network unavailable",
			markers: []string{"network unavailable"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cause := fmt.Errorf("%s: %w", tc.errText, errTransportSentinel)
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, cause
			})}
			store := statedir.New(t.TempDir())
			_, err := Run(t.Context(), store, Options{Ticket: tc.ticket, ExternalSubjectID: "user-1", HTTPClient: client})
			if err == nil {
				t.Fatal("expected transport error")
			}
			if err.Error() != transportErrorMessage {
				t.Fatalf("expected the fixed transport message, got %q", err.Error())
			}
			var be *Error
			if !errors.As(err, &be) || be.Category() != CategoryTransport {
				t.Fatalf("unexpected sanitized error: %v", err)
			}
			if !errors.Is(err, errTransportSentinel) {
				t.Fatal("expected wrapped sentinel to stay reachable via errors.Is")
			}
			saved, serr := store.Load()
			if serr != nil {
				t.Fatal(serr)
			}
			for _, text := range []string{err.Error(), fmt.Sprintf("%v", err), fmt.Errorf("direct bind: %w", err).Error()} {
				for _, marker := range append(append([]string{}, tc.markers...), tc.ticket, saved.DeviceSecret) {
					if marker != "" && strings.Contains(text, marker) {
						t.Fatalf("transport error text surfaced: %q", text)
					}
				}
			}
		})
	}
}

func TestRunBindHostileFailureKeepsDurableRetryIdentity(t *testing.T) {
	ticket := "ticket-retry-identity-abcdef987654"
	var mu sync.Mutex
	var requests []bindRequest
	hostileMode := true
	// One server for every phase: the bind fingerprint scopes to the server
	// URL, so the honest completion must keep the same endpoint for the
	// durable identity to be reused.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got bindRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		requests = append(requests, got)
		hostile := hostileMode
		mu.Unlock()
		if hostile {
			// Refuse the bind while reflecting both credentials in the
			// error code and message.
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error": map[string]any{"code": got.Ticket, "message": got.DeviceSecret},
			})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"device": map[string]any{
			"deviceId":          "dev-1",
			"applicationId":     got.ApplicationID,
			"externalSubjectId": got.ExternalSubjectID,
			"replay":            true,
		}})
	}))
	defer server.Close()

	store := statedir.New(t.TempDir())
	opt := Options{ServerURL: server.URL, Ticket: ticket, ExternalSubjectID: "user-1"}
	_, err := Run(t.Context(), store, opt)
	if err == nil {
		t.Fatal("expected hostile bind to fail")
	}
	mu.Lock()
	first := requests[0]
	mu.Unlock()
	assertNoCredentialLeak(t, err, ticket, first.DeviceSecret)

	saved, serr := store.Load()
	if serr != nil {
		t.Fatal(serr)
	}
	if saved.DeviceSecret == "" || saved.BindRequestID == "" || saved.PendingBindFingerprint == "" {
		t.Fatalf("failure cleared the durable replay identity: %#v", saved)
	}

	// Retrying the same scope must resend the identical payload.
	if _, err := Run(t.Context(), store, opt); err == nil {
		t.Fatal("expected retry against hostile server to fail")
	}
	mu.Lock()
	second := requests[1]
	mu.Unlock()
	if first != second {
		t.Fatal("retry after hostile failure rotated the bind identity")
	}

	// The same endpoint turning honest completes the bind with the same
	// identity.
	mu.Lock()
	hostileMode = false
	mu.Unlock()
	res, err := Run(t.Context(), store, opt)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	third := requests[2]
	mu.Unlock()
	if third.RequestID != first.RequestID || third.DeviceSecret != first.DeviceSecret {
		t.Fatal("successful retry did not reuse the durable identity")
	}
	if res.State.PendingBindFingerprint != "" || res.State.DeviceID != "dev-1" || !res.Replay {
		t.Fatalf("unexpected final state: %#v", res.State)
	}
}

func TestRunBindReflectedReceiptFailsClosedAndKeepsPending(t *testing.T) {
	ticket := "ticket-receipt-reflect-abcdef"
	newServer := func(t *testing.T, mutate func(device map[string]any, got bindRequest)) *httptest.Server {
		t.Helper()
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var got bindRequest
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Error(err)
				return
			}
			device := map[string]any{
				"deviceId":          "dev-1",
				"applicationId":     got.ApplicationID,
				"externalSubjectId": got.ExternalSubjectID,
				"deviceName":        got.DeviceName,
				"platform":          got.Platform,
				"replay":            false,
			}
			if mutate != nil {
				mutate(device, got)
			}
			writeJSON(w, http.StatusCreated, map[string]any{"device": device})
		}))
	}
	for _, tc := range []struct {
		name    string
		options func(opt *Options)
		mutate  func(device map[string]any, got bindRequest)
	}{
		{
			name:   "deviceId_echoes_ticket",
			mutate: func(device map[string]any, got bindRequest) { device["deviceId"] = got.Ticket },
		},
		{
			name:   "deviceId_echoes_device_secret",
			mutate: func(device map[string]any, got bindRequest) { device["deviceId"] = got.DeviceSecret },
		},
		{
			name:   "deviceName_echoes_ticket",
			mutate: func(device map[string]any, got bindRequest) { device["deviceName"] = got.Ticket },
		},
		{
			name:   "deviceName_echoes_uppercase_device_secret",
			mutate: func(device map[string]any, got bindRequest) { device["deviceName"] = strings.ToUpper(got.DeviceSecret) },
		},
		{
			name:   "platform_echoes_ticket",
			mutate: func(device map[string]any, got bindRequest) { device["platform"] = got.Ticket },
		},
		{
			// The identity check constrains applicationId to echo the
			// request, so the reflection only reaches the gate when the
			// configured application itself embeds the ticket.
			name:    "applicationId_embeds_ticket",
			options: func(opt *Options) { opt.ApplicationID = "app-" + ticket },
		},
		{
			name:    "subjectId_embeds_ticket",
			options: func(opt *Options) { opt.ExternalSubjectID = "user-" + ticket },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newServer(t, tc.mutate)
			defer server.Close()
			store := statedir.New(t.TempDir())
			opt := Options{ServerURL: server.URL, Ticket: ticket, ExternalSubjectID: "user-1"}
			if tc.options != nil {
				tc.options(&opt)
			}
			res, err := Run(t.Context(), store, opt)
			if err == nil {
				t.Fatal("expected reflected-credential rejection")
			}
			if err.Error() != reflectedCredentialMessage {
				t.Fatalf("expected fixed reflected-credential message, got %q", err.Error())
			}
			var be *Error
			if !errors.As(err, &be) || be.Category() != CategoryInvalidResponse || be.Status() != http.StatusCreated {
				t.Fatalf("unexpected sanitized error: %v", err)
			}
			saved, serr := store.Load()
			if serr != nil {
				t.Fatal(serr)
			}
			assertNoCredentialLeak(t, err, ticket, saved.DeviceSecret)
			// Fail closed before persisting: no bound state, pending replay
			// identity kept (not ACKed), retry identity intact.
			if res.State.DeviceID != "" || saved.DeviceID != "" || saved.ApplicationID != "" {
				t.Fatalf("reflected receipt was persisted: %#v", saved)
			}
			if saved.PendingBindFingerprint == "" || saved.BindRequestID == "" || saved.DeviceSecret == "" {
				t.Fatalf("pending replay identity was cleared: %#v", saved)
			}
		})
	}
}

func TestNoRedirectClientClonesWithoutTouchingCaller(t *testing.T) {
	transport := &http.Transport{}
	original := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	cloned := noRedirectClient(original)
	if cloned == original || original.CheckRedirect != nil {
		t.Fatal("caller client must not be modified")
	}
	if cloned.Transport != transport || cloned.Timeout != 3*time.Second {
		t.Fatal("clone must preserve transport and timeout")
	}
	if err := cloned.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatalf("clone must refuse redirects via ErrUseLastResponse, got %v", err)
	}

	nilCloned := noRedirectClient(nil)
	if nilCloned == nil || nilCloned.CheckRedirect == nil {
		t.Fatal("nil client must become a redirect-refusing client")
	}
}

func TestRunBindRefusesRedirectsAndNeverForwardsCredentials(t *testing.T) {
	ticket := "ticket-redirect-abcdef0123456789"
	var targetHits int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&targetHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			var mu sync.Mutex
			var deviceSecret string
			redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var got bindRequest
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				deviceSecret = got.DeviceSecret
				mu.Unlock()
				// The redirect target embeds both credentials, so any follow
				// would leak them and be observable at the target; the
				// auto-generated HTML body reflects them too.
				http.Redirect(w, r, target.URL+"/leak?ticket="+url.QueryEscape(got.Ticket)+"&secret="+url.QueryEscape(got.DeviceSecret), status)
			}))
			defer redirector.Close()

			callerClient := &http.Client{Timeout: 5 * time.Second}
			_, err := Run(t.Context(), statedir.New(t.TempDir()), Options{
				ServerURL:         redirector.URL,
				Ticket:            ticket,
				ExternalSubjectID: "user-1",
				HTTPClient:        callerClient,
			})
			mu.Lock()
			secret := deviceSecret
			mu.Unlock()
			assertNoCredentialLeak(t, err, ticket, secret)

			if hits := atomic.LoadInt64(&targetHits); hits != 0 {
				t.Fatalf("redirect target received %d requests; credentials must never be forwarded", hits)
			}
			var be *Error
			if !errors.As(err, &be) {
				t.Fatalf("expected *Error, got %T", err)
			}
			if be.Status() != status || be.Category() != "redirect" {
				t.Fatalf("expected refused redirect status %d / category redirect, got %d / %q", status, be.Status(), be.Category())
			}
			if !strings.Contains(err.Error(), fmt.Sprintf("status %d", status)) {
				t.Fatalf("expected status %d in error, got %q", status, err.Error())
			}
			if callerClient.CheckRedirect != nil || callerClient.Timeout != 5*time.Second {
				t.Fatal("caller client must stay untouched by the redirect refusal")
			}
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
