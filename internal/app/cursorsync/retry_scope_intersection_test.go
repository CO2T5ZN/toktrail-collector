package cursorsync_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/app/cursorsync"
)

func TestRetryRechecksBothAuthorizationScopes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*harness)
	}{
		{"tools", func(h *harness) { h.srv.setAllowedTools([]string{"Codex"}) }},
		{"history", func(h *harness) { from := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC); h.srv.setHistory(&from, nil) }},
		{"upload window", func(h *harness) {
			until := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
			h.srv.setHistory(nil, &until)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.srv.setSource(defaultSource())
			h.srv.setAllowedTools([]string{"Cursor"})
			h.writeLicense(t, activeLicenseForA())
			seedPendingBatch(t, h.dir, "scope-intersection", 1)
			h.srv.setIngestScript(scriptedIngest{status: http.StatusServiceUnavailable})
			h.srv.setIngestHook(func() { tc.change(h) })
			opt := h.options()
			opt.Retry = retryPolicy(h.clock, 2)
			result, err := cursorsync.DrainPending(context.Background(), opt, cursorsync.Gate{AllowedTools: []string{"Cursor"}})
			if err != nil || !strings.Contains(result.Skipped, "stopped") || result.PendingRemaining != 1 {
				t.Fatalf("narrowed authorization must stop with the batch pending: result=%+v err=%v", result, err)
			}
			if _, _, posts, _, _ := h.srv.stats(); posts != 1 {
				t.Fatalf("narrowed authorization must prevent retry, posts=%d", posts)
			}
		})
	}
}

func TestInitialSyncIntersectsFreshAndCallerScopes(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.srv.setAllowedTools([]string{"Codex"})
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "sync-scope-intersection", 1)
	result, err := cursorsync.Sync(context.Background(), h.options(), cursorsync.Gate{AllowedTools: []string{"Cursor"}})
	if err != nil || !strings.Contains(result.Skipped, "not allowed") {
		t.Fatalf("fresh scope must prevent collection: result=%+v err=%v", result, err)
	}
	if _, _, posts, _, _ := h.srv.stats(); posts != 0 {
		t.Fatalf("unauthorized initial sync sent %d posts", posts)
	}
}

func TestInitialDrainIntersectsFreshAndCallerScopes(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.srv.setAllowedTools([]string{"Codex"})
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "initial-scope-intersection", 1)
	result, err := cursorsync.DrainPending(context.Background(), h.options(), cursorsync.Gate{AllowedTools: []string{"Cursor"}})
	if err != nil || !strings.Contains(result.Skipped, "not allowed") {
		t.Fatalf("fresh scope must prevent upload: result=%+v err=%v", result, err)
	}
	if _, _, posts, _, _ := h.srv.stats(); posts != 0 {
		t.Fatalf("unauthorized initial drain sent %d posts", posts)
	}
}
