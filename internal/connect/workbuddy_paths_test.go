package connect

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/local/grants"
)

func TestConnectWorkBuddyFallbackDoesNotHideProbeErrors(t *testing.T) {
	for _, failingLayout := range []string{".workbuddy-ai", ".workbuddy"} {
		t.Run(failingLayout, func(t *testing.T) {
			url, statusPosts := probeFailServers(t, []string{"WorkBuddy"})
			home := t.TempDir()
			_, err := Run(context.Background(), Options{
				URL: url, StateDir: t.TempDir(), HomeDir: home, HTTPClient: http.DefaultClient,
				statDefaultDir: func(path string) (os.FileInfo, error) {
					if path == filepath.Join(home, failingLayout, "projects") {
						return nil, os.ErrPermission
					}
					return nil, os.ErrNotExist
				},
			})
			if !errors.Is(err, os.ErrPermission) {
				t.Fatalf("probe failure must surface, got %v", err)
			}
			if *statusPosts != 0 {
				t.Fatalf("probe error must not report not_detected: %d reports", *statusPosts)
			}
		})
	}
}

func TestConnectWorkBuddyDirectoryLayouts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		layouts []string
		want    string
	}{
		{"alternate only", []string{".workbuddy"}, ".workbuddy"},
		{"preferred only", []string{".workbuddy-ai"}, ".workbuddy-ai"},
		{"both prefer current default", []string{".workbuddy", ".workbuddy-ai"}, ".workbuddy-ai"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stateDir, home := t.TempDir(), t.TempDir()
			mock := startCursorBacklogMock(t)
			cfg := startSyncConfigMock(t, mock.URL, []string{"WorkBuddy"}, nil)
			ticket := strings.Repeat("7", 64)
			seedFirstEnableConnect(t, stateDir, mock, cfg, ticket)
			for _, layout := range tc.layouts {
				input := filepath.Join(home, layout, "projects")
				if err := os.MkdirAll(input, 0o700); err != nil {
					t.Fatal(err)
				}
				line := `{"id":"call-1","timestamp":1780000000100,"type":"function_call","sessionId":"synthetic-session","providerData":{"messageId":"msg-1","requestModelId":"synthetic-model","rawUsage":{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120,"prompt_cache_hit_tokens":40,"cache_creation_input_tokens":0}}}` + "\n"
				if err := os.WriteFile(filepath.Join(input, "session.jsonl"), []byte(line), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for attempt := 0; attempt < 2; attempt++ {
				out := &bytes.Buffer{}
				res, err := runCursorConnectWithOptionsOut(t, cfg, stateDir, home, ticket, Options{}, out)
				if err != nil {
					t.Fatalf("connect attempt %d: %v\n%s", attempt, err, out.String())
				}
				if got := SummarizeRun(res, err, nil, 1).StopReason; got != collection.StopComplete {
					t.Fatalf("stop reason = %s", got)
				}
				enabled, err := grants.New(stateDir).Enabled()
				if err != nil {
					t.Fatal(err)
				}
				want := filepath.Join(home, tc.want, "projects")
				if len(enabled) != 1 || enabled[0].Source != "workbuddy-jsonl" || enabled[0].Input != want {
					t.Fatalf("grants = %+v, want only %s", enabled, want)
				}
				if !strings.Contains(out.String(), "1 detected") {
					t.Fatalf("WorkBuddy must be detected:\n%s", out.String())
				}
				if attempt == 0 && res.PeriodicResult.SyncedRecords != 1 {
					t.Fatalf("expected the selected WorkBuddy session to upload: %+v", res.PeriodicResult)
				}
			}
		})
	}
}
