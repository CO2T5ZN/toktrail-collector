package connect

import (
	"bytes"
	"strings"
	"testing"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/cursor/auth"
	"toktrail-collector/internal/local/cursorsource"
)

// An authorization may include tools installed on other devices. An absent
// desktop login with no prior permit must not prevent local uploads or reconnect.
func TestConnectMissingCursorLoginIsSkipped(t *testing.T) {
	for _, withCodex := range []bool{false, true} {
		name := "cursor only"
		if withCodex {
			name = "cursor and local upload"
		}
		t.Run(name, func(t *testing.T) {
			stateDir, homeDir := t.TempDir(), t.TempDir()
			mock := startCursorBacklogMock(t)
			tools := []string{"Cursor"}
			if withCodex {
				tools = append(tools, "Codex")
				seedCodexSessionsGrant(t, stateDir, homeDir)
				seedDeviceBacklogBatch(t, stateDir, homeDir, "missing-cursor-batch", "missing-cursor-key")
			}
			cfg := startSyncConfigMock(t, mock.URL, tools, nil)
			ticket := strings.Repeat("7", 64)
			seedFirstEnableConnect(t, stateDir, mock, cfg, ticket)
			pull := &cursorBacklogPull{events: cursorBulkEvents(1)}
			wiring := budgetCursorWiring(pull, 5)
			// The real desktop reader sees only a synthetic, empty home.
			wiring.Auth = auth.DesktopProvider(auth.Options{HomeDir: t.TempDir(), GOOS: "linux", XDGConfigHome: t.TempDir()})
			for attempt := 0; attempt < 2; attempt++ {
				out := &bytes.Buffer{}
				res, err := runCursorConnectWithOptionsOut(t, cfg, stateDir, homeDir, ticket, Options{Cursor: wiring, Verbose: true}, out)
				if err != nil {
					t.Fatalf("attempt %d: absent Cursor must be skipped: %v\n%s", attempt, err, out.String())
				}
				summary := SummarizeRun(res, err, nil, 1)
				if summary.StopReason != collection.StopComplete || res.Sync.accountIncomplete {
					t.Fatalf("attempt %d: missing Cursor must not block completion: %+v", attempt, summary)
				}
				if !strings.Contains(out.String(), "1 not detected (skipped)") || strings.Contains(out.String(), "account source(s) not enabled") {
					t.Fatalf("missing Cursor must be counted as not detected:\n%s", out.String())
				}
				if _, exists, err := cursorsource.New(stateDir).Load(); err != nil || exists {
					t.Fatalf("missing Cursor must not create a permit: exists=%t err=%v", exists, err)
				}
			}
			if len(pull.calls) != 0 {
				t.Fatalf("missing Cursor must not pull usage: %v", pull.calls)
			}
			mock.mu.Lock()
			defer mock.mu.Unlock()
			if mock.mu.toolStatus < 2 || mock.mu.srcBatchPosts != 0 {
				t.Fatalf("expected probe reports and no Cursor uploads: statuses=%d source batches=%d", mock.mu.toolStatus, mock.mu.srcBatchPosts)
			}
			if withCodex && mock.mu.devicePosts == 0 {
				t.Fatal("the local batch must upload despite missing Cursor")
			}
		})
	}
}
