package syncclient

// Security tests for the human-message hygiene of server-facing error
// paths: a malicious (or compromised) server that echoes the collector's
// own Authorization credential, session content, or arbitrary codes back
// in response bodies, headers, or transport-level errors must never see
// any of that text surface in an error a human reads. Everything here is
// synthetic: temporary directories, httptest servers, fake retry
// clocks, and scripted hostile responses. No real state, no deployment,
// no commits.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncbudget"
	"toktrail-collector/internal/syncretry"
)

// maliciousSecret stands in for the device credential (or any session
// content) a hostile server could echo back.
const maliciousSecret = "TOPSECRET-credential-echo-0123456789abcdef"

// maliciousSelfServer answers the self GET with an arbitrary hostile
// payload of raw bytes and status.
func maliciousSelfServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
}

// assertNoServerText fails when the error's human text carries the
// secret or any other untrusted marker.
func assertNoServerText(t *testing.T, err error, markers ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	text := err.Error()
	for _, marker := range append([]string{maliciousSecret}, markers...) {
		if strings.Contains(text, marker) {
			t.Fatalf("error text leaks server-controlled content %q: %s", marker, text)
		}
	}
}

func TestResponseSafetySelfCheckNeverEchoesServerText(t *testing.T) {
	_, store, _ := setupBoundState(t)
	cases := []struct {
		name      string
		status    int
		body      string
		wantIs    error
		wantText  string
		noWantTxt []string
	}{
		{
			name:     "revoked_snapshot_with_hostile_device_id",
			status:   http.StatusOK,
			body:     `{"device":{"deviceId":"` + maliciousSecret + `","consentRevision":7,"uploadAuthorized":false,"revoked":true}}`,
			wantIs:   ErrDeviceRevoked,
			wantText: "never re-binds",
		},
		{
			name:     "different_device_with_hostile_id",
			status:   http.StatusOK,
			body:     `{"device":{"deviceId":"` + maliciousSecret + `","consentRevision":7,"uploadAuthorized":true,"revoked":false}}`,
			wantIs:   ErrDeviceUnauthorized,
			wantText: "another device's authorization",
		},
		{
			name:     "revoked_code_with_hostile_message",
			status:   http.StatusUnauthorized,
			body:     `{"error":{"code":"device_revoked","message":"` + maliciousSecret + `"}}`,
			wantIs:   ErrDeviceRevoked,
			wantText: "never re-binds",
		},
		{
			name:     "subject_deleted_code_with_hostile_message",
			status:   http.StatusUnauthorized,
			body:     `{"error":{"code":"subject_deleted","message":"` + maliciousSecret + `"}}`,
			wantIs:   ErrSubjectDeleted,
			wantText: "never re-binds",
		},
		{
			name:      "unknown_code_and_message",
			status:    http.StatusTeapot,
			body:      `{"error":{"code":"` + maliciousSecret + `","message":"` + maliciousSecret + `"}}`,
			wantText:  "(server error code: other)",
			noWantTxt: []string{maliciousSecret},
		},
		{
			name:     "undecodable_body_with_secret",
			status:   http.StatusOK,
			body:     `{"device":{"deviceId":"` + maliciousSecret + `","consentRev`,
			wantIs:   ErrSelfProtocol,
			wantText: "undecodable body",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := maliciousSelfServer(t, tc.status, tc.body)
			defer server.Close()
			_, err := FetchDeviceSelf(t.Context(), store, Options{ServerURL: server.URL})
			assertNoServerText(t, err, tc.noWantTxt...)
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("sentinel %v not preserved: %v", tc.wantIs, err)
			}
			if tc.wantText != "" && !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("expected fixed text %q in: %s", tc.wantText, err.Error())
			}
		})
	}
}

func TestResponseSafetySelfCheckOverCapBodyFailsClosed(t *testing.T) {
	_, store, _ := setupBoundState(t)
	// A JSON value that never completes and embeds the secret well past
	// the 8 MiB cap: the capped reader probes one byte past the limit,
	// records nothing, and the self check fails closed.
	huge := `{"device":{"deviceId":"` + strings.Repeat("x", 9<<20) + maliciousSecret + `"`
	server := maliciousSelfServer(t, http.StatusOK, huge)
	defer server.Close()
	_, err := FetchDeviceSelf(t.Context(), store, Options{ServerURL: server.URL})
	assertNoServerText(t, err)
	if !errors.Is(err, ErrSelfProtocol) {
		t.Fatalf("over-cap self body must fail closed as ErrSelfProtocol, got %v", err)
	}
	if !strings.Contains(err.Error(), "body limit") {
		t.Fatalf("the over-cap outcome must be explicitly identified: %s", err.Error())
	}
}

// fileBatchForTest writes a one-record --file batch and returns the
// bound store plus the batch file path.
func fileBatchForTest(t *testing.T, batchID string) (statedir.Store, string) {
	t.Helper()
	_, store, _ := setupBoundState(t)
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": batchID,
		"records": []map[string]any{singleFixtureRecord()},
	})
	return store, batchFile
}

func TestResponseSafetyIngestNeverEchoesServerText(t *testing.T) {
	cases := []struct {
		name     string
		handler  http.HandlerFunc
		wantIs   error
		wantText string
	}{
		{
			name: "unknown_code_and_message",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if serveSelf(t, w, r, 7) {
					return
				}
				writeJSON(w, http.StatusForbidden, map[string]any{"error": map[string]any{
					"code": maliciousSecret, "message": maliciousSecret,
				}})
			},
			wantText: "sync failed: status 403 (server error code: other)",
		},
		{
			name: "scope_changed_with_hostile_message",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if serveSelf(t, w, r, 7) {
					return
				}
				writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]any{
					"code": "scope_changed", "message": maliciousSecret,
				}})
			},
			wantIs:   ErrScopeChanged,
			wantText: "consent scope changed",
		},
		{
			name: "receipt_batch_id_is_hostile",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if serveSelf(t, w, r, 7) {
					return
				}
				writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
					"batchId": maliciousSecret, "status": "accepted",
					"acceptedRecords": 1, "rejectedRecords": 0, "replay": false,
					"receivedAt": "2026-10-20T10:12:00Z",
				}})
			},
			wantText: "does not match submitted batch",
		},
		{
			name: "record_error_key_is_hostile",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if serveSelf(t, w, r, 7) {
					return
				}
				writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
					"batchId": "batch-safety-1", "status": "rejected",
					"acceptedRecords": 0, "rejectedRecords": 1, "replay": false,
					"receivedAt": "2026-10-20T10:12:00Z",
					"recordErrors": []map[string]any{{
						"index": 0, "recordKey": maliciousSecret,
						"code": maliciousSecret, "message": maliciousSecret,
					}},
				}})
			},
			wantText: "references a recordKey that does not match",
		},
		{
			name: "success_status_body_truncated_with_secret",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if serveSelf(t, w, r, 7) {
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusAccepted)
				_, _ = io.WriteString(w, `{"batch":{"batchId":"batch-safety-1","status":"accep`+maliciousSecret)
			},
			wantText: "unexpected EOF",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, batchFile := fileBatchForTest(t, "batch-safety-1")
			server := httptest.NewServer(tc.handler)
			defer server.Close()
			_, err := Run(t.Context(), store, Options{ServerURL: server.URL, BatchFile: batchFile})
			assertNoServerText(t, err)
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("sentinel %v not preserved: %v", tc.wantIs, err)
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("expected fixed text %q in: %s", tc.wantText, err.Error())
			}
		})
	}
}

func TestResponseSafetyLostBodyRetryWordingNeverEchoesContent(t *testing.T) {
	// With a retry policy that gives up immediately, the retryable
	// lost-body wording surfaces through exhaustion and must carry only
	// the status and the identity-derived decode description.
	stateDir, store, _ := setupPendingRetryBatch(t, "batch-lostword-1")
	server, _ := scriptedIngestServer(t, []func(w http.ResponseWriter){
		func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"batch":{"batchId":"batch-lostword-1","status":"accep`+maliciousSecret)
		},
	})
	defer server.Close()
	policy := syncretry.New(syncretry.WithClock(newFakeRetryClock(time.Now())), syncretry.WithMaxRetries(0), syncretry.WithBaseDelay(0))
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, Retry: policy})
	assertNoServerText(t, err)
	if !strings.Contains(err.Error(), "body lost or truncated") || !strings.Contains(err.Error(), "unexpected EOF") {
		t.Fatalf("expected the fixed lost-body wording with the EOF identity: %s", err.Error())
	}
}

func TestResponseSafetyOverCapIngestKeepsLostBodyRetrySemantics(t *testing.T) {
	// Attempt 1 answers a success status with an over-cap, never-ending
	// JSON body embedding the secret; attempt 2 accepts. The over-cap
	// outcome must be retryable exactly like a lost body — the receipt
	// never arrived intact, so an idempotent resend is safe.
	huge := `{"batch":{"batchId":"batch-cap-1","pad":"` + strings.Repeat("x", 9<<20) + maliciousSecret
	stateDir, store, _ := setupPendingRetryBatch(t, "batch-cap-1")
	server, rec := scriptedIngestServer(t, []func(w http.ResponseWriter){
		func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, huge)
		},
	})
	defer server.Close()

	budget := syncbudget.New(syncbudget.WithTotal(2))
	policy := syncretry.New(syncretry.WithClock(newFakeRetryClock(time.Now())), syncretry.WithBaseDelay(0))
	if _, err := Run(t.Context(), store, Options{
		ServerURL: server.URL, StateDir: stateDir,
		Budget: budget, BudgetQueue: "device", Retry: policy,
	}); err != nil {
		t.Fatal(err)
	}
	if got := rec.posts.Load(); got != 2 {
		t.Fatalf("posts = %d, want the over-cap failure to be retried like a lost body", got)
	}
	if got := budget.Used(); got != 2 {
		t.Fatalf("budget used = %d, want one reservation per POST", got)
	}

	// Without a retry policy the same over-cap failure surfaces as a
	// final, explicitly identified error with no content echo.
	stateDir2, store2, _ := setupPendingRetryBatch(t, "batch-cap-1")
	server2, _ := scriptedIngestServer(t, []func(w http.ResponseWriter){
		func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, huge)
		},
	})
	defer server2.Close()
	_, err := Run(t.Context(), store2, Options{ServerURL: server2.URL, StateDir: stateDir2})
	assertNoServerText(t, err)
	if !strings.Contains(err.Error(), "exceeded the 8 MiB safety limit") {
		t.Fatalf("the over-cap outcome must be explicit: %s", err.Error())
	}
}

func TestResponseSafetyRetryAfterHeaderNeverEchoed(t *testing.T) {
	stateDir, store, _ := setupPendingRetryBatch(t, "batch-ra-1")
	malicious := func(w http.ResponseWriter) {
		w.Header().Set("Retry-After", maliciousSecret)
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]any{
			"code": "rate_limited", "message": maliciousSecret,
		}})
	}
	server, _ := scriptedIngestServer(t, []func(w http.ResponseWriter){malicious})
	defer server.Close()

	// The error surfaces through retry exhaustion; every layer — the
	// exhaustion wrapper, the retry marker, the classification — must
	// state the hint's existence without echoing its value.
	policy := syncretry.New(syncretry.WithClock(newFakeRetryClock(time.Now())), syncretry.WithMaxRetries(0), syncretry.WithBaseDelay(0))
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, Retry: policy})
	assertNoServerText(t, err)
	if !errors.Is(err, syncretry.ErrRetryExhausted) {
		t.Fatalf("the retryable classification must survive sanitization, got %v", err)
	}
	if !strings.Contains(err.Error(), "Retry-After supplied") {
		t.Fatalf("the marker must state that a hint was supplied: %s", err.Error())
	}

	// A legitimate numeric hint still drives the policy wait, parsed
	// against the policy clock exactly as before.
	stateDir2, store2, _ := setupPendingRetryBatch(t, "batch-ra-1")
	server2, _ := scriptedIngestServer(t, []func(w http.ResponseWriter){
		func(w http.ResponseWriter) {
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]any{
				"code": "rate_limited",
			}})
		},
	})
	defer server2.Close()
	clock := newFakeRetryClock(time.Now())
	policy2 := syncretry.New(syncretry.WithClock(clock), syncretry.WithMaxRetries(1), syncretry.WithBaseDelay(0))
	if _, err := Run(t.Context(), store2, Options{ServerURL: server2.URL, StateDir: stateDir2, Retry: policy2}); err != nil {
		t.Fatal(err)
	}
	waits := clock.recordedWaits()
	if len(waits) != 1 || waits[0] != 1*time.Second {
		t.Fatalf("waits = %v, want the server's 1s floor to be honored", waits)
	}
}

// leakyRoundTripper simulates a transport stack whose error text embeds
// the credential (an intermediary reflecting request detail).
type leakyRoundTripper struct{ err error }

func (l leakyRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, l.err }

// selectiveLeakyRoundTripper lets every request through the default
// transport except one path, whose round trip fails with the leaky error
// — so a run can pass its self check and hit the leak on the ingest POST.
type selectiveLeakyRoundTripper struct {
	failPath string
	err      error
}

func (l selectiveLeakyRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == l.failPath {
		return nil, l.err
	}
	return http.DefaultTransport.RoundTrip(r)
}

func TestResponseSafetyTransportErrorsNeverEchoEndpointsOrSecrets(t *testing.T) {
	leakyErr := fmt.Errorf("auth header was Bearer dev-1.%s at %%s", maliciousSecret)
	leakyClient := &http.Client{Transport: selectiveLeakyRoundTripper{failPath: "/v1/ingest/batches", err: leakyErr}, Timeout: 5 * time.Second}

	stateDir, store, _ := setupPendingRetryBatch(t, "batch-transport-1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelf(t, w, r, 7) {
			return
		}
		t.Errorf("the ingest POST must fail in the transport before reaching the server")
	}))
	defer server.Close()
	_, err := Run(t.Context(), store, Options{
		ServerURL:  server.URL,
		StateDir:   stateDir,
		HTTPClient: leakyClient,
	})
	assertNoServerText(t, err)
	if !strings.Contains(err.Error(), "sync upload") {
		t.Fatalf("expected the sanitized upload transport wrapper: %s", err.Error())
	}
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		t.Fatal("the sanitized wrapper must keep the cause matchable with errors.As(*url.Error)")
	}
	if syncretry.IsRetryable(err) {
		t.Fatal("a final transport failure must stay final")
	}

	// The retry classification of transport failures survives the
	// wrapper: with a policy, the same leaky transport is retried and
	// surfaces through exhaustion.
	stateDir2, store2, _ := setupPendingRetryBatch(t, "batch-transport-1")
	policy := syncretry.New(syncretry.WithClock(newFakeRetryClock(time.Now())), syncretry.WithMaxRetries(1), syncretry.WithBaseDelay(0))
	_, err = Run(t.Context(), store2, Options{
		ServerURL: server.URL, StateDir: stateDir2,
		HTTPClient: leakyClient, Retry: policy,
	})
	assertNoServerText(t, err)
	if !errors.Is(err, syncretry.ErrRetryExhausted) {
		t.Fatalf("the retryable transport classification must survive, got %v", err)
	}

	// The io.EOF identity of a dropped connection stays reachable
	// through the wrapper — the semantics collection's network-drop
	// recovery relies on.
	_, store3, _ := setupBoundState(t)
	eofClient := &http.Client{Transport: leakyRoundTripper{err: io.EOF}, Timeout: 5 * time.Second}
	_, err = FetchDeviceSelf(t.Context(), store3, Options{ServerURL: "http://transport.invalid", HTTPClient: eofClient})
	assertNoServerText(t, err, "transport.invalid")
	if !strings.Contains(err.Error(), "device self check failed") {
		t.Fatalf("expected the self-check scope prefix: %s", err.Error())
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("the dropped-connection io.EOF identity must stay matchable, got %v", err)
	}
}

func TestResponseSafetyToolStatusAndGrantAckNeverEchoServerText(t *testing.T) {
	t.Run("tool_status_unknown_code", func(t *testing.T) {
		_, store, _ := setupBoundState(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if serveSelf(t, w, r, 7) {
				return
			}
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{
				"code": maliciousSecret, "message": maliciousSecret,
			}})
		}))
		defer server.Close()
		_, err := ReportToolStatuses(t.Context(), store, Options{
			ServerURL: server.URL,
			ToolStatuses: []ToolStatus{{
				Tool: "Codex", Status: "no_new_records",
			}},
		})
		assertNoServerText(t, err)
		if !strings.Contains(err.Error(), "(server error code: other)") {
			t.Fatalf("unknown codes must reduce to other: %s", err.Error())
		}
	})

	t.Run("grant_ack_scope_changed_message", func(t *testing.T) {
		_, store, _ := setupBoundState(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]any{
				"code": "scope_changed", "message": maliciousSecret,
			}})
		}))
		defer server.Close()
		_, err := ReportGrantAck(t.Context(), store, Options{ServerURL: server.URL}, GrantAckRequest{
			ConsentRevision: 5, ApplyState: "applied",
		})
		assertNoServerText(t, err)
		if !errors.Is(err, ErrAckRevisionAdvanced) {
			t.Fatalf("sentinel not preserved: %v", err)
		}
	})

	t.Run("grant_ack_unknown_fields_detail", func(t *testing.T) {
		_, store, _ := setupBoundState(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{
				"code": maliciousSecret, "message": maliciousSecret,
			}})
		}))
		defer server.Close()
		_, err := ReportGrantAck(t.Context(), store, Options{ServerURL: server.URL}, GrantAckRequest{
			ConsentRevision: 5, ApplyState: "applied", SupportedTools: []string{"Codex"},
		})
		assertNoServerText(t, err)
		if !errors.Is(err, ErrAckUnknownFields) {
			t.Fatalf("sentinel not preserved: %v", err)
		}
		if strings.Contains(err.Error(), "(") && strings.Contains(err.Error(), ": ") {
			t.Fatalf("the unknown-fields sentinel must not carry a server detail: %s", err.Error())
		}
	})

	t.Run("grant_ack_echoed_state", func(t *testing.T) {
		_, store, _ := setupBoundState(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"grantAck": map[string]any{
				"consentRevision": 5, "ackedState": maliciousSecret,
			}})
		}))
		defer server.Close()
		_, err := ReportGrantAck(t.Context(), store, Options{ServerURL: server.URL}, GrantAckRequest{
			ConsentRevision: 5, ApplyState: "applied",
		})
		assertNoServerText(t, err)
		if !errors.Is(err, ErrAckEchoMismatch) {
			t.Fatalf("sentinel not preserved: %v", err)
		}
		if !strings.Contains(err.Error(), "confirmed a different state") {
			t.Fatalf("expected the no-echo mismatch wording: %s", err.Error())
		}
	})

	t.Run("grant_ack_transport", func(t *testing.T) {
		_, store, _ := setupBoundState(t)
		leaky := &http.Client{Transport: leakyRoundTripper{err: fmt.Errorf("Bearer dev-1.%s", maliciousSecret)}, Timeout: 5 * time.Second}
		_, err := ReportGrantAck(t.Context(), store, Options{ServerURL: "http://transport.invalid", HTTPClient: leaky}, GrantAckRequest{
			ConsentRevision: 5, ApplyState: "applied",
		})
		assertNoServerText(t, err, "transport.invalid")
		if !strings.Contains(err.Error(), "grant ack failed") {
			t.Fatalf("expected the grant-ack scope prefix: %s", err.Error())
		}
	})
}

func TestResponseSafetyWalInvarianceUnderMaliciousFailures(t *testing.T) {
	stateDir, store, _ := setupPendingRetryBatch(t, "batch-wal-1")
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelf(t, w, r, 7) {
			return
		}
		posts.Add(1)
		writeJSON(w, http.StatusForbidden, map[string]any{"error": map[string]any{
			"code": maliciousSecret, "message": maliciousSecret,
		}})
	}))
	defer server.Close()

	policy := syncretry.New(syncretry.WithClock(newFakeRetryClock(time.Now())), syncretry.WithBaseDelay(0))
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, Retry: policy})
	assertNoServerText(t, err)
	if got := posts.Load(); got != 1 {
		t.Fatalf("posts = %d, an unknown business code must not be retried", got)
	}
	// The outbox and durable accounting must be exactly as a clean final
	// failure leaves them: pending batch, one preflight ledger entry.
	assertBatchPending(t, stateDir, "batch-wal-1")
	preflight, err := outbox.New(stateDir).LoadPreflightAttempts()
	if err != nil {
		t.Fatal(err)
	}
	if preflight.Count != 1 {
		t.Fatalf("preflight ledger count = %d, want 1", preflight.Count)
	}
}

// setupPendingBatchN wires a bound device plus one pending outbox batch
// of n records, mirroring setupPendingRetryBatch.
func setupPendingBatchN(t *testing.T, batchID string, n int) (string, statedir.Store, string) {
	t.Helper()
	stateDir, store, _ := setupBoundState(t)
	records := make([]map[string]any, n)
	for i := range records {
		rec := singleFixtureRecord()
		rec["recordKey"] = fmt.Sprintf("record-%04d", i)
		records[i] = rec
	}
	batchFile := writeBatchFile(t, map[string]any{"batchId": batchID, "records": records})
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{
		BatchID: batchID, File: batchFile, Source: "usage-json", Input: batchFile, RecordCount: n,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := progress.New(stateDir).Advance(progress.AdvanceOptions{
		Source: "usage-json", Input: batchFile, BatchID: batchID, RecordCount: n,
	}); err != nil {
		t.Fatal(err)
	}
	return stateDir, store, batchFile
}

func TestResponseSafetyFiveHundredRecordReceiptStillValid(t *testing.T) {
	// The body cap must not break a normal maximum-size receipt: 500
	// submitted records, 500 accepted, zero rejected.
	const batchID = "batch-500-1"
	stateDir, store, _ := setupPendingBatchN(t, batchID, 500)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelf(t, w, r, 7) {
			return
		}
		var got BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("invalid ingest body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId":         got.BatchID,
			"status":          "accepted",
			"acceptedRecords": len(got.Records),
			"rejectedRecords": 0,
			"replay":          false,
			"receivedAt":      "2026-10-20T10:12:00Z",
		}})
	}))
	defer server.Close()
	res, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if res.Receipt.AcceptedRecords != 500 || res.Receipt.RejectedRecords != 0 {
		t.Fatalf("unexpected receipt: %#v", res.Receipt)
	}
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Batches) != 1 || out.Batches[0].Status != outbox.StatusSynced {
		t.Fatalf("the 500-record batch must sync exactly once: %#v", out.Batches)
	}
}

func TestResponseSafetyMaliciousSuccessReceiptCollapsedToClosedSets(t *testing.T) {
	// The success path, not an error path: a 202 receipt that fully
	// reconciles (right batch ID, right counts, matching record key)
	// but carries the device credential in its status and record-error
	// code/message. The run must ACK normally while everything carried
	// onward collapses to the closed vocabulary.
	const batchID = "batch-malice-1"
	stateDir, store, _ := setupPendingBatchN(t, batchID, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelf(t, w, r, 7) {
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId":         batchID,
			"status":          maliciousSecret,
			"acceptedRecords": 1,
			"rejectedRecords": 1,
			"replay":          false,
			"receivedAt":      "2026-10-20T10:12:00Z",
			"recordErrors": []map[string]any{{
				"index": 1, "recordKey": "record-0001",
				"code": maliciousSecret, "message": maliciousSecret,
			}},
		}})
	}))
	defer server.Close()

	res, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if res.Receipt.Status != "partial_error" {
		t.Fatalf("hostile status must be replaced by the counts-derived value, got %q", res.Receipt.Status)
	}
	if len(res.Receipt.RecordErrors) != 1 {
		t.Fatalf("record errors = %d, want the reconciled one", len(res.Receipt.RecordErrors))
	}
	re := res.Receipt.RecordErrors[0]
	if re.Index != 1 || re.RecordKey != "record-0001" || re.Code != "record_rejected" || re.Message != "" {
		t.Fatalf("record error not closed-set: %#v", re)
	}
	// Nothing the run persisted or returned carries the hostile text.
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.LastSyncStatus != "partial_error" {
		t.Fatalf("persisted status = %q, want the derived partial_error", st.LastSyncStatus)
	}
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Batches) != 1 || out.Batches[0].Status != outbox.StatusSynced || out.Batches[0].ReceiptStatus != "partial_error" {
		t.Fatalf("the ACK must persist exactly as before with the derived status: %#v", out.Batches)
	}
	b, err := json.Marshal(res.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), maliciousSecret) {
		t.Fatalf("the returned receipt leaks hostile text: %s", b)
	}
}

func TestResponseSafetyNegativeCountsFailClosed(t *testing.T) {
	// A hostile receipt whose counts sum to the record count only
	// because one is negative must not pass the sum check: -1 accepted
	// + 2 rejected == 1 submitted record.
	stateDir, store, _ := setupPendingRetryBatch(t, "batch-negative-1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelf(t, w, r, 7) {
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId": "batch-negative-1", "status": "accepted",
			"acceptedRecords": -1, "rejectedRecords": 2, "replay": false,
			"receivedAt": "2026-10-20T10:12:00Z",
		}})
	}))
	defer server.Close()
	events := &eventRecorder{}
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, Progress: events.record})
	if err == nil || !strings.Contains(err.Error(), "negative decision counts") {
		t.Fatalf("expected the negative-count failure, got %v", err)
	}
	assertBatchPending(t, stateDir, "batch-negative-1")
	evs := events.snapshot()
	if len(evs) != 1 || evs[0].Result != ResultFinalFailure || evs[0].ReceiptKnown {
		t.Fatalf("the receipt must stay unknown with no ACK: %#v", evs)
	}
}

func TestResponseSafetyDuplicateRejectionIndexFailsClosed(t *testing.T) {
	// Two record errors sharing one index would merge in the per-message
	// map and leave the OTHER rejected record confirmed as accepted.
	const batchID = "batch-dupidx-1"
	stateDir, store, _ := setupPendingBatchN(t, batchID, 2)
	// Two messages ride the batch so the duplicate-index merge would
	// otherwise leave msg-b's rejection invisible to the confirm step.
	cursors := progress.New(stateDir)
	if err := cursors.ApplyMessagePending("usage-json", batchID, []progress.MessagePendingUpdate{
		{MessageID: "msg-a", RecordKey: "record-0000", To: &progress.MessageUsageState{Input: u64ptr(13)}},
		{MessageID: "msg-b", RecordKey: "record-0001", To: &progress.MessageUsageState{Input: u64ptr(15)}},
	}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelf(t, w, r, 7) {
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId": batchID, "status": "rejected",
			"acceptedRecords": 0, "rejectedRecords": 2, "replay": false,
			"receivedAt": "2026-10-20T10:12:00Z",
			"recordErrors": []map[string]any{
				{"index": 0, "recordKey": "record-0000", "code": "record_conflict"},
				{"index": 0, "recordKey": "record-0000", "code": "record_conflict"},
			},
		}})
	}))
	defer server.Close()
	events := &eventRecorder{}
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, Progress: events.record})
	if err == nil || !strings.Contains(err.Error(), "appears more than once") {
		t.Fatalf("expected the duplicate-index failure, got %v", err)
	}
	assertBatchPending(t, stateDir, batchID)
	// No per-message state may have been confirmed: both messages keep
	// their frozen pending intervals, nothing is counted as accepted.
	msgs, _, msgErr := progress.New(stateDir).MessageProgressFor("usage-json")
	if msgErr != nil {
		t.Fatal(msgErr)
	}
	for _, msg := range msgs {
		if msg.Confirmed != nil {
			t.Fatalf("a duplicate-index receipt must confirm nothing: %#v", msg)
		}
	}
	evs := events.snapshot()
	if len(evs) != 1 || evs[0].Result != ResultFinalFailure || evs[0].ReceiptKnown {
		t.Fatalf("the receipt must stay unknown with no ACK: %#v", evs)
	}
}

func TestResponseSafetySelfSnapshotSecretReflectionFailsClosed(t *testing.T) {
	// Each downstream-propagating string field of a 200 self snapshot,
	// individually, echoes the device secret: the guard must fail closed
	// with ErrSelfProtocol, a fixed message, no state change, and no
	// extra HTTP beyond the single GET.
	secret := strings.Repeat("a", 64)
	// Each case overwrites one downstream-propagating field of the base
	// snapshot with a reflection of the secret.
	base := func() map[string]any {
		return map[string]any{
			"deviceId":         "dev-1",
			"consentRevision":  7,
			"uploadAuthorized": true,
			"revoked":          false,
			"allowedTools":     []string{"Codex"},
		}
	}
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"device_id", func(d map[string]any) { d["deviceId"] = "x" + secret + "x" }},
		{"allowed_tools_entry", func(d map[string]any) { d["allowedTools"] = []string{"Codex", secret} }},
		{"account_source_instance_id", func(d map[string]any) {
			d["accountSources"] = []map[string]any{{"sourceInstanceId": secret, "sourceType": "codex-jsonl", "state": "active"}}
		}},
		{"account_source_type", func(d map[string]any) {
			d["accountSources"] = []map[string]any{{"sourceInstanceId": "src-1", "sourceType": secret, "state": "active"}}
		}},
		{"account_source_state", func(d map[string]any) {
			d["accountSources"] = []map[string]any{{"sourceInstanceId": "src-1", "sourceType": "codex-jsonl", "state": secret}}
		}},
		{"secret_uppercased", func(d map[string]any) { d["deviceId"] = "x" + strings.ToUpper(secret) + "x" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, store, _ := setupBoundState(t)
			snapshot := base()
			tc.mutate(snapshot)
			var gets atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gets.Add(1)
				writeJSON(w, http.StatusOK, map[string]any{"device": snapshot})
			}))
			defer server.Close()
			_, err := FetchDeviceSelf(t.Context(), store, Options{ServerURL: server.URL})
			assertNoServerText(t, err, strings.Repeat("a", 64))
			if !errors.Is(err, ErrSelfProtocol) {
				t.Fatalf("reflected credential must fail closed as ErrSelfProtocol, got %v", err)
			}
			if !strings.Contains(err.Error(), "reflected credential material") {
				t.Fatalf("expected the fixed guard wording: %s", err.Error())
			}
			if got := gets.Load(); got != 1 {
				t.Fatalf("self GETs = %d, want exactly one", got)
			}
			// No local state change: the bound state is untouched.
			st, loadErr := store.Load()
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if st.DeviceID != "dev-1" || st.DeviceSecret != strings.Repeat("a", 64) {
				t.Fatalf("local state must not change: %#v", st.DeviceID)
			}
		})
	}
}

func TestResponseSafetySelfReflectionInRunKeepsLedgerSemantics(t *testing.T) {
	// Through the full Run path: the reflected snapshot stops the send
	// at the preflight with zero POSTs, and the durable accounting that
	// preceded the GET stands exactly as any self-check failure leaves
	// it — no extra HTTP, no ledger semantics change.
	secret := strings.Repeat("a", 64)
	stateDir, store, _ := setupPendingRetryBatch(t, "batch-reflect-1")
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			writeJSON(w, http.StatusOK, map[string]any{"device": map[string]any{
				"deviceId": "dev-1", "consentRevision": 7,
				"uploadAuthorized": true, "revoked": false,
				"allowedTools": []string{secret},
			}})
			return
		}
		posts.Add(1)
		t.Errorf("no upload may happen after a reflected snapshot, saw %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	events := &eventRecorder{}
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, Progress: events.record})
	if !errors.Is(err, ErrSelfProtocol) {
		t.Fatalf("expected ErrSelfProtocol, got %v", err)
	}
	assertNoServerText(t, err, secret)
	if posts.Load() != 0 {
		t.Fatalf("posts = %d, want 0", posts.Load())
	}
	assertBatchPending(t, stateDir, "batch-reflect-1")
	preflight, err := outbox.New(stateDir).LoadPreflightAttempts()
	if err != nil {
		t.Fatal(err)
	}
	if preflight.Count != 1 {
		t.Fatalf("preflight ledger count = %d, want the unchanged 1", preflight.Count)
	}
	evs := events.snapshot()
	if len(evs) != 1 || evs[0].Stage != StagePrepare || evs[0].Result != ResultFinalFailure {
		t.Fatalf("expected one prepare-stage final failure event: %#v", evs)
	}
}

func TestResponseSafetyKnownStatusContradictingCountsFailsClosed(t *testing.T) {
	// A receipt whose KNOWN status word disagrees with its counts is an
	// inconsistent receipt: no ACK, batch pending, receipt unknown.
	// Legacy compatibility: the "partial" alias is recognized alongside
	// "partial_error", and both must match counts like any known word.
	cases := []struct {
		name            string
		status          string
		acceptedRecords int
		rejectedRecords int
		recordErrors    int
	}{
		{"accepted_with_rejections", "accepted", 0, 1, 1},
		{"rejected_with_acceptances", "rejected", 1, 0, 0},
		{"partial_alias_with_no_rejections", "partial", 1, 0, 0},
		{"partial_error_with_no_rejections", "partial_error", 1, 0, 0},
		{"partial_alias_fully_rejected", "partial", 0, 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const batchID = "batch-status-1"
			stateDir, store, _ := setupPendingRetryBatch(t, batchID)
			receipt := map[string]any{
				"batchId": batchID, "status": tc.status,
				"acceptedRecords": tc.acceptedRecords, "rejectedRecords": tc.rejectedRecords,
				"replay": false, "receivedAt": "2026-10-20T10:12:00Z",
			}
			if tc.recordErrors > 0 {
				receipt["recordErrors"] = []map[string]any{
					{"index": 0, "code": "record_conflict"},
				}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if serveSelf(t, w, r, 7) {
					return
				}
				writeJSON(w, http.StatusAccepted, map[string]any{"batch": receipt})
			}))
			defer server.Close()
			events := &eventRecorder{}
			_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, Progress: events.record})
			if err == nil || !strings.Contains(err.Error(), "contradicts the decision counts") {
				t.Fatalf("expected the status/counts contradiction to fail closed, got %v", err)
			}
			assertBatchPending(t, stateDir, batchID)
			evs := events.snapshot()
			if len(evs) != 1 || evs[0].Result != ResultFinalFailure || evs[0].ReceiptKnown {
				t.Fatalf("the contradictory receipt must stay unknown with no ACK: %#v", evs)
			}
		})
	}
}

func TestResponseSafetyMissingStatusStaysCompatibleWithDerivedValue(t *testing.T) {
	// Evidence-backed compatibility: the device path has never required
	// the status word, so a receipt without one still ACKs, and the
	// persisted/displayed status is the counts-derived value.
	const batchID = "batch-nostatus-1"
	stateDir, store, _ := setupPendingRetryBatch(t, batchID)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelf(t, w, r, 7) {
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId":         batchID,
			"acceptedRecords": 1, "rejectedRecords": 0,
			"replay": false, "receivedAt": "2026-10-20T10:12:00Z",
		}})
	}))
	defer server.Close()
	res, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if res.Receipt.Status != "accepted" {
		t.Fatalf("missing status must derive from counts, got %q", res.Receipt.Status)
	}
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.LastSyncStatus != "accepted" {
		t.Fatalf("persisted status = %q, want the derived accepted", st.LastSyncStatus)
	}
}
