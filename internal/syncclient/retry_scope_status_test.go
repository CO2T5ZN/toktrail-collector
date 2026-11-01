package syncclient

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"toktrail-collector/internal/syncretry"
)

func TestRetryableHTTPStatusDoesNotOverrideTerminalBusinessCode(t *testing.T) {
	for _, code := range []string{"bad_request", "unauthorized", "conflict", "unknown_terminal_code"} {
		t.Run(code, func(t *testing.T) {
			_, store, batchFile := setupPendingRetryBatch(t, "terminal-code")
			server, rec := scriptedIngestServer(t, []func(http.ResponseWriter){func(w http.ResponseWriter) {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]any{"code": code}})
			}})
			defer server.Close()
			clock := newFakeRetryClock(time.Now())
			policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(0))
			_, err := Run(t.Context(), store, Options{ServerURL: server.URL, BatchFile: batchFile, Retry: policy})
			if err == nil || rec.posts.Load() != 1 || len(clock.recordedWaits()) != 0 {
				t.Fatalf("business error must stop immediately: err=%v posts=%d waits=%v", err, rec.posts.Load(), clock.recordedWaits())
			}
		})
	}
}

func TestRetryableHTTPStatusDoesNotOverrideScopeError(t *testing.T) {
	for _, tc := range []struct {
		code string
		want error
	}{
		{"scope_changed", ErrScopeChanged},
		{"outside_scope", ErrOutsideScope},
	} {
		for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
			t.Run(tc.code+http.StatusText(status), func(t *testing.T) {
				_, store, batchFile := setupPendingRetryBatch(t, "scope-final")
				server, rec := scriptedIngestServer(t, []func(http.ResponseWriter){func(w http.ResponseWriter) {
					writeJSON(w, status, map[string]any{"error": map[string]any{"code": tc.code, "message": "scope rejected"}})
				}})
				defer server.Close()
				clock := newFakeRetryClock(time.Now())
				policy := syncretry.New(syncretry.WithClock(clock), syncretry.WithBaseDelay(0))
				_, err := Run(t.Context(), store, Options{ServerURL: server.URL, BatchFile: batchFile, Retry: policy})
				if !errors.Is(err, tc.want) || rec.posts.Load() != 1 || len(clock.recordedWaits()) != 0 {
					t.Fatalf("scope error must stop immediately: err=%v posts=%d waits=%v", err, rec.posts.Load(), clock.recordedWaits())
				}
			})
		}
	}
}
