package connect

// First-enable retry wiring coverage: the run's single retry policy
// (Options.Retry) must reach the account-source first-enable round
// connect's setup performs — the cursor source-batch uploads retry under
// it inside cursorsync, resending byte-identical bytes under the same
// batch ID. Everything is synthetic: the cursor integration fakes (no
// real credential, no real upstream pull) and a frozen-clock policy.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/local/cursorsource"
)

// TestConnectRetryWiredIntoFirstCursorEnable drives a full cursor-wired
// connect whose FIRST source-batch POST fails with a retryable 503: the
// first-enable round must retry it, resend byte-identical bytes under the
// same batch ID, and complete the run with the account source fully
// drained.
func TestConnectRetryWiredIntoFirstCursorEnable(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()

	toktrail := startCursorToktrailMock(t)
	toktrail.flakeFirstSrcBatch = true
	cfgServer := startConnectConfigMock(t, Config{
		SchemaVersion: 1,
		ServerURL:     toktrail.URL,
		ApplicationID: "app-cursor-1",
		SubjectID:     cursorTestSubjectID,
		Tools:         []string{cursorsource.ToolName},
		Days:          intPtr(30),
		ExpiresAt:     cursorTestNow.Add(24 * time.Hour).Format(time.RFC3339),
	})

	authFake := &fakeCursorAuth{}
	pullFake := &fakeCursorPull{events: cursorFixtureEvents()}
	out := &bytes.Buffer{}

	res, err := Run(context.Background(), Options{
		URL:             fmt.Sprintf("%s/api/collector/connect#%s", cfgServer.URL, strings.Repeat("9", 64)),
		StateDir:        stateDir,
		HomeDir:         homeDir,
		BinaryPath:      fakeCollectorBinary(t),
		HTTPClient:      cfgServer.Client(),
		SchedulerRunner: &mockRunner{},
		Now:             func() time.Time { return cursorTestNow },
		Out:             out,
		Cursor: &cursorsync.Options{
			Auth:   authFake,
			Verify: fakeCursorVerify,
			Pull:   pullFake.Pull,
			Now:    func() time.Time { return cursorTestNow },
		},
		CursorConfirm: func(string, io.Writer) (bool, error) { return true, nil },
		Retry:         connectTestRetryPolicy(),
	})
	if err != nil {
		t.Fatalf("cursor connect with a retried transient failure must succeed, got: %v\noutput:\n%s", err, out.String())
	}
	if len(res.Sync.Incomplete) != 0 {
		t.Fatalf("the retried cursor connect must be complete, got incompleteness: %v", res.Sync.Incomplete)
	}
	toktrail.mu.Lock()
	posts := toktrail.srcBatchPosts
	bodies := make([][]byte, len(toktrail.srcBatchBodies))
	copy(bodies, toktrail.srcBatchBodies)
	toktrail.mu.Unlock()
	if posts != 2 {
		t.Fatalf("source-batch POSTs = %d, want 2 (503 then accepted)", posts)
	}
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("the retry must resend byte-identical source-batch payloads under the same batch ID")
	}
	// The empty incompleteness list above already pins the completion
	// contract (the account tool ran, nothing skipped, nothing pending);
	// the drain-only initial round reports the enable's uploads through
	// the enable result, so the cursor aggregate starts zeroed here.
	if res.Sync.Collection.Cursor.Ran && res.Sync.Collection.Cursor.Skipped != "" {
		t.Fatalf("the cursor round must not report a skip, got %+v", res.Sync.Collection.Cursor)
	}
}
