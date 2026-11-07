package syncclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/syncretry"
)

func TestToolStatusRetryTransientHTTP(t *testing.T) {
	for _, stage := range []string{"self", "post"} {
		for _, status := range []int{429, 500, 502, 503, 504} {
			for _, body := range []string{`{"error":{"code":"service_unavailable"}}`, "proxy unavailable"} {
				t.Run(fmt.Sprintf("%s/%d/%s", stage, status, body[:5]), func(t *testing.T) {
					dir, store, _ := setupBoundState(t)
					before, err := os.ReadFile(store.Path())
					if err != nil {
						t.Fatal(err)
					}
					gets, posts := 0, 0
					var payloads [][]byte
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path == "/v1/devices/self" {
							gets++
							if stage == "self" && gets == 1 {
								w.Header().Set("Retry-After", "3")
								w.WriteHeader(status)
								_, _ = io.WriteString(w, body)
								return
							}
							serveSelf(t, w, r, int64(gets))
							return
						}
						if r.URL.Path != "/v1/devices/tool-status" {
							t.Errorf("unexpected endpoint %s", r.URL.Path)
							w.WriteHeader(400)
							return
						}
						posts++
						payload, _ := io.ReadAll(r.Body)
						payloads = append(payloads, payload)
						if r.Header.Get("X-Consent-Revision") != strconv.Itoa(gets) {
							t.Error("stale authorization revision")
						}
						if stage == "post" && posts == 1 {
							w.Header().Set("Retry-After", "3")
							w.WriteHeader(status)
							_, _ = io.WriteString(w, body)
							return
						}
						w.WriteHeader(http.StatusAccepted)
					}))
					defer server.Close()
					clock := newFakeRetryClock(time.Now())
					policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithRunDeadline(clock.Now().Add(time.Minute)))
					res, err := ReportToolStatuses(t.Context(), store, Options{StateDir: dir, ServerURL: server.URL, Retry: policy, ToolStatuses: []ToolStatus{{Tool: "Codex", Status: "synced"}}})
					wantPosts := 1
					if stage == "post" {
						wantPosts = 2
					}
					if err != nil || res.Status != 202 || gets != 2 || posts != wantPosts {
						t.Fatalf("gets=%d posts=%d status=%d err=%v", gets, posts, res.Status, err)
					}
					if waits := clock.recordedWaits(); !reflect.DeepEqual(waits, []time.Duration{3 * time.Second}) {
						t.Fatalf("Retry-After not honored: %v", waits)
					}
					if len(payloads) == 2 && !bytes.Equal(payloads[0], payloads[1]) {
						t.Fatal("payload changed between attempts")
					}
					after, _ := os.ReadFile(store.Path())
					if !bytes.Equal(before, after) {
						t.Fatal("status retries changed usage state")
					}
					attempts, err := outbox.New(dir).LoadPreflightAttempts()
					if err != nil {
						t.Fatal(err)
					}
					if attempts.Count != 2 {
						t.Fatalf("preflight accounting: %+v", attempts)
					}
				})
			}
		}
	}
}

type toolStatusRoundTrip func(*http.Request) (*http.Response, error)

func (f toolStatusRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestToolStatusRetryTransport(t *testing.T) {
	for _, stage := range []string{"self", "post"} {
		t.Run(stage, func(t *testing.T) {
			dir, store, _ := setupBoundState(t)
			gets, posts := 0, 0
			dropped := errors.New("transport private-endpoint secret-marker")
			client := &http.Client{Transport: toolStatusRoundTrip(func(r *http.Request) (*http.Response, error) {
				self := r.URL.Path == "/v1/devices/self"
				if self {
					gets++
					if stage == "self" && gets == 1 {
						return nil, dropped
					}
				} else {
					posts++
					if stage == "post" && posts == 1 {
						return nil, dropped
					}
				}
				body := ""
				if self {
					body = `{"device":{"deviceId":"dev-1","uploadAuthorized":true,"consentRevision":4}}`
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})}
			clock := newFakeRetryClock(time.Now())
			_, err := ReportToolStatuses(t.Context(), store, Options{StateDir: dir, ServerURL: "http://example.test", HTTPClient: client, Retry: syncretry.New(syncretry.WithClock(clock)), ToolStatuses: []ToolStatus{{Tool: "Codex", Status: "synced"}}})
			wantPosts := 1
			if stage == "post" {
				wantPosts = 2
			}
			if err != nil || gets != 2 || posts != wantPosts {
				t.Fatalf("gets=%d posts=%d err=%v", gets, posts, err)
			}
			if waits := clock.recordedWaits(); !reflect.DeepEqual(waits, []time.Duration{time.Second}) {
				t.Fatalf("backoff=%v", waits)
			}
		})
	}
}

func TestToolStatusRetryStopsAtAuthorizationChange(t *testing.T) {
	for _, mode := range []string{"revoked", "paused", "scope", "unauthorized", "deleted"} {
		t.Run(mode, func(t *testing.T) {
			dir, store, _ := setupBoundState(t)
			gets, posts := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/devices/self" {
					gets++
					if gets == 1 {
						serveSelf(t, w, r, 1)
						return
					}
					if mode == "unauthorized" {
						writeJSON(w, 401, map[string]any{})
						return
					}
					if mode == "deleted" {
						writeJSON(w, 401, map[string]any{"error": map[string]any{"code": "subject_deleted"}})
						return
					}
					device := map[string]any{"deviceId": "dev-1", "uploadAuthorized": mode != "revoked", "consentRevision": 2, "grantProtocolVersion": 1, "paused": mode == "paused"}
					if mode == "scope" {
						device["allowedTools"] = []string{"Claude Code"}
					}
					writeJSON(w, 200, map[string]any{"device": device})
					return
				}
				posts++
				writeJSON(w, 503, map[string]any{})
			}))
			defer server.Close()
			clock := newFakeRetryClock(time.Now())
			_, err := ReportToolStatuses(t.Context(), store, Options{StateDir: dir, ServerURL: server.URL, Retry: syncretry.New(syncretry.WithClock(clock)), ToolStatuses: []ToolStatus{{Tool: "Codex", Status: "synced"}}})
			want := map[string]error{"revoked": ErrDeviceRevoked, "paused": ErrDevicePaused, "scope": ErrOutsideScope, "unauthorized": ErrDeviceUnauthorized, "deleted": ErrSubjectDeleted}[mode]
			if !errors.Is(err, want) || gets != 2 || posts != 1 || errors.Is(err, syncretry.ErrRetryExhausted) {
				t.Fatalf("gets=%d posts=%d err=%v want=%v", gets, posts, err, want)
			}
		})
	}
}

func TestToolStatusRetryTerminalHTTP(t *testing.T) {
	for _, stage := range []string{"self", "post"} {
		for _, tc := range []struct {
			status int
			body   string
		}{
			{401, `{}`}, {403, `{}`}, {409, `{"error":{"code":"scope_changed"}}`}, {422, `{}`}, {501, `{}`},
			{503, `{"error":{"code":"outside_scope"}}`}, {503, `{"error":{"code":"unknown-private-business-code"}}`},
		} {
			t.Run(fmt.Sprintf("%s/%d/%s", stage, tc.status, tc.body), func(t *testing.T) {
				dir, store, _ := setupBoundState(t)
				gets, posts := 0, 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/v1/devices/self" {
						gets++
						if stage == "post" {
							serveSelf(t, w, r, 1)
							return
						}
					} else {
						posts++
					}
					w.WriteHeader(tc.status)
					_, _ = io.WriteString(w, tc.body)
				}))
				defer server.Close()
				clock := newFakeRetryClock(time.Now())
				_, err := ReportToolStatuses(t.Context(), store, Options{StateDir: dir, ServerURL: server.URL, Retry: syncretry.New(syncretry.WithClock(clock)), ToolStatuses: []ToolStatus{{Tool: "Codex", Status: "synced"}}})
				wantPosts := 0
				if stage == "post" {
					wantPosts = 1
				}
				if err == nil || gets != 1 || posts != wantPosts || len(clock.recordedWaits()) != 0 {
					t.Fatalf("gets=%d posts=%d err=%v waits=%v", gets, posts, err, clock.recordedWaits())
				}
				if strings.Contains(err.Error(), "unknown-private-business-code") {
					t.Fatal("server error code leaked")
				}
			})
		}
	}
}

// Return a real HTTP response from a deterministic transport after cancelling
// the request context. A live httptest server can instead surface transport
// cancellation, hiding the response/cancellation boundary that broke macOS CI.
func TestToolStatusRetryResponseAfterCancellation(t *testing.T) {
	for _, stage := range []string{"self", "post"} {
		for _, body := range []string{"", `{}`} {
			t.Run(stage+"/"+body, func(t *testing.T) {
				dir, store, _ := setupBoundState(t)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				gets, posts := 0, 0
				client := &http.Client{Transport: toolStatusRoundTrip(func(r *http.Request) (*http.Response, error) {
					self := r.URL.Path == "/v1/devices/self"
					if self {
						gets++
					} else {
						posts++
					}
					status, content := http.StatusServiceUnavailable, body
					if self && stage == "post" {
						status = http.StatusOK
						content = `{"device":{"deviceId":"dev-1","uploadAuthorized":true,"consentRevision":4}}`
					} else {
						cancel()
					}
					return &http.Response{StatusCode: status, Header: http.Header{"Retry-After": []string{"3"}}, Body: io.NopCloser(strings.NewReader(content)), Request: r}, nil
				})}
				clock := newFakeRetryClock(time.Now())
				_, err := ReportToolStatuses(ctx, store, Options{
					StateDir: dir, ServerURL: "http://example.test", HTTPClient: client,
					Retry:        syncretry.New(syncretry.WithClock(clock)),
					ToolStatuses: []ToolStatus{{Tool: "Codex", Status: "synced"}},
				})
				wantPosts := 0
				if stage == "post" {
					wantPosts = 1
				}
				if !errors.Is(err, context.Canceled) || gets != 1 || posts != wantPosts || len(clock.recordedWaits()) != 0 {
					t.Fatalf("cancelled response must not wait or retry: gets=%d posts=%d waits=%v err=%v", gets, posts, clock.recordedWaits(), err)
				}
				if errors.Is(err, syncretry.ErrRetryExhausted) || errors.Is(err, syncretry.ErrRetryPastDeadline) {
					t.Fatalf("cancelled response must not report retry exhaustion or deadline: %v", err)
				}
			})
		}
	}
}

func TestToolStatusRetryBoundsAndCompatibility(t *testing.T) {
	for _, mode := range []string{"exhausted", "deadline", "cancelled", "nil", "old", "redirect", "bad-self"} {
		t.Run(mode, func(t *testing.T) {
			dir, store, _ := setupBoundState(t)
			gets, posts := 0, 0
			clock := newFakeRetryClock(time.Now())
			policy := syncretry.New(syncretry.WithClock(clock))
			if mode == "deadline" {
				policy = syncretry.New(syncretry.WithClock(clock), syncretry.WithRunDeadline(clock.Now().Add(2*time.Second)))
			}
			if mode == "nil" {
				policy = nil
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/devices/self" {
					gets++
					if mode == "bad-self" {
						_, _ = io.WriteString(w, "malformed")
						return
					}
					serveSelf(t, w, r, 1)
					return
				}
				posts++
				switch mode {
				case "cancelled":
					cancel()
				case "old":
					w.WriteHeader(404)
					return
				case "redirect":
					w.Header().Set("Location", "/must-not-follow")
					w.WriteHeader(307)
					return
				}
				w.Header().Set("Retry-After", "3")
				w.WriteHeader(503)
			}))
			defer server.Close()
			_, err := ReportToolStatuses(ctx, store, Options{StateDir: dir, ServerURL: server.URL, Retry: policy, ToolStatuses: []ToolStatus{{Tool: "Codex", Status: "synced"}}})
			switch mode {
			case "exhausted":
				if !errors.Is(err, syncretry.ErrRetryExhausted) || gets != 4 || posts != 4 {
					t.Fatalf("gets=%d posts=%d err=%v", gets, posts, err)
				}
			case "deadline":
				if !errors.Is(err, syncretry.ErrRetryPastDeadline) || gets != 1 || posts != 1 || len(clock.recordedWaits()) != 0 {
					t.Fatalf("gets=%d posts=%d err=%v", gets, posts, err)
				}
			case "cancelled":
				if !errors.Is(err, context.Canceled) || gets != 1 || posts != 1 {
					t.Fatalf("gets=%d posts=%d err=%v", gets, posts, err)
				}
			case "nil":
				if err == nil || gets != 1 || posts != 1 || syncretry.IsRetryable(err) {
					t.Fatalf("gets=%d posts=%d err=%v", gets, posts, err)
				}
			case "old":
				if err != nil || gets != 1 || posts != 1 {
					t.Fatalf("gets=%d posts=%d err=%v", gets, posts, err)
				}
			case "redirect":
				if !errors.Is(err, errDeviceRedirect) || gets != 1 || posts != 1 {
					t.Fatalf("gets=%d posts=%d err=%v", gets, posts, err)
				}
			case "bad-self":
				if !errors.Is(err, ErrSelfProtocol) || gets != 1 || posts != 0 {
					t.Fatalf("gets=%d posts=%d err=%v", gets, posts, err)
				}
			}
		})
	}
}
