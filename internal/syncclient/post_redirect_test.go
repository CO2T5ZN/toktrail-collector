package syncclient

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"toktrail-collector/internal/syncretry"
)

func TestDevicePostsNeverFollowRedirects(t *testing.T) {
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		for _, endpoint := range []string{"ingest", "tool-status", "grant-ack"} {
			for _, injected := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/injected=%t", http.StatusText(status), endpoint, injected), func(t *testing.T) {
					var leaked atomic.Int64
					target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						leaked.Add(1)
						w.WriteHeader(http.StatusOK)
					}))
					defer target.Close()
					var posts atomic.Int64
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if serveSelf(t, w, r, 7) {
							return
						}
						posts.Add(1)
						http.Redirect(w, r, target.URL+"/capture", status)
					}))
					defer server.Close()
					_, store, batch := setupPendingRetryBatch(t, "redirect-batch")
					caller := server.Client()
					var client *http.Client
					if injected {
						client = caller
					}
					var err error
					switch endpoint {
					case "ingest":
						_, err = Run(t.Context(), store, Options{ServerURL: server.URL, BatchFile: batch, HTTPClient: client, Retry: syncretry.New(syncretry.WithBaseDelay(0))})
					case "tool-status":
						_, err = ReportToolStatuses(t.Context(), store, Options{ServerURL: server.URL, HTTPClient: client, ToolStatuses: []ToolStatus{{Tool: "Claude Code", Status: "synced"}}})
					case "grant-ack":
						_, err = ReportGrantAck(t.Context(), store, Options{ServerURL: server.URL, HTTPClient: client}, GrantAckRequest{ConsentRevision: 7})
					}
					if !errors.Is(err, errDeviceRedirect) || posts.Load() != 1 || leaked.Load() != 0 {
						t.Fatalf("redirect must be terminal and never followed: err=%v posts=%d target=%d", err, posts.Load(), leaked.Load())
					}
					if caller.CheckRedirect != nil {
						t.Fatal("caller client was mutated")
					}
				})
			}
		}
	}
}
