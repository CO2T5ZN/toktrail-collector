package connect

// D1 wiring tests: the first-enable Cursor round (the integrated
// confirmation, the real upstream pull and the real source-batch POSTs)
// emits the unified progress stream like every other queue. The emitter
// is scoped to the enable call alone, a nil Progress keeps the enable
// byte-for-byte on its historical path, and the events carry only
// sealed facts. Everything is synthetic (tempdir state, httptest fakes,
// injected auth/verify/pull providers); no real credentials or Cursor
// state are ever touched.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/app/cursorsync"
)

// progressEnableRecorder captures the connect run's unified stream.
type progressEnableRecorder struct {
	mu     sync.Mutex
	events []collection.ProgressEvent
}

func (r *progressEnableRecorder) capture(ev collection.ProgressEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *progressEnableRecorder) batches(queue string) []collection.ProgressEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []collection.ProgressEvent
	for _, ev := range r.events {
		if ev.Kind == collection.ProgressBatch && ev.Queue == queue {
			out = append(out, ev)
		}
	}
	return out
}

// runCursorConnectProgress is runCursorConnect's twin with an optional
// progress callback; the returned recorder is the one the events flow
// to when progress is enabled.
func runCursorConnectProgress(t *testing.T, useProgress bool, confirm cursorsync.ConfirmFunc) (Result, string, *progressEnableRecorder, *cursorToktrailMock) {
	t.Helper()
	stateDir := t.TempDir()
	homeDir := t.TempDir()

	toktrail := startCursorToktrailMock(t)
	cfgServer := startConnectConfigMock(t, Config{
		SchemaVersion: 1,
		ServerURL:     toktrail.URL,
		ApplicationID: "app-cursor-1",
		SubjectID:     cursorTestSubjectID,
		Tools:         []string{"Cursor"},
		Days:          intPtr(30),
		ExpiresAt:     cursorTestNow.Add(24 * time.Hour).Format(time.RFC3339),
	})

	rec := &progressEnableRecorder{}
	var progress func(collection.ProgressEvent)
	if useProgress {
		progress = rec.capture
	}
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
		CursorConfirm: confirm,
		Progress:      progress,
	})
	if err != nil {
		t.Fatalf("connect Run failed: %v", err)
	}
	return res, out.String(), rec, toktrail
}

func cursorMockSrcBatchPosts(mock *cursorToktrailMock) int {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	return mock.srcBatchPosts
}

// The first-enable round emits the account queue's per-phase events:
// real POSTs with the acknowledged terminal proving the first local
// confirmation, a conservatively unknown origin, and only sealed facts.
func TestConnectCursorEnableEmitsProgressEvents(t *testing.T) {
	confirm := func(notice string, w io.Writer) (bool, error) {
		if notice != cursorsync.EnableNotice {
			t.Errorf("confirmation notice = %q, want cursorsync.EnableNotice", notice)
		}
		return true, nil
	}
	res, _, recorded, toktrail := runCursorConnectProgress(t, true, confirm)
	if len(res.AuthorizedTools) != 1 || res.AuthorizedTools[0] != "Cursor" {
		t.Fatalf("the run must authorize exactly Cursor: %+v", res.AuthorizedTools)
	}
	events := recorded.batches(collection.ProgressQueueCursor)
	if len(events) == 0 {
		t.Fatalf("the first-enable round must emit cursor batch events")
	}
	var acknowledged int
	for _, ev := range events {
		switch ev.Phase {
		case "preflight", "wait", "http", "outcome":
		default:
			t.Fatalf("the account phases travel verbatim: %+v", ev)
		}
		if ev.Origin != collection.OriginUnknown {
			t.Fatalf("the enable round's origin stays conservatively unknown: %+v", ev)
		}
		if ev.Phase == "outcome" && ev.Result == "acknowledged" {
			acknowledged++
			if ev.FirstBatchConfirmation != collection.FirstBatchConfirmationYes {
				t.Fatalf("the acknowledged terminal proves the first local confirmation: %+v", ev)
			}
			if !ev.ReceiptObserved || ev.AcceptedRecords <= 0 {
				t.Fatalf("the acknowledged terminal carries its receipt counts: %+v", ev)
			}
		}
	}
	if acknowledged == 0 {
		t.Fatalf("the enable's first sync must reach the acknowledged terminal: %+v", events)
	}
	// The shared run budget saw the enable's real POSTs.
	if got := cursorMockSrcBatchPosts(toktrail); got == 0 {
		t.Fatalf("the enable round must perform real source-batch POSTs")
	}
}

// A nil Progress keeps the enable on its historical path: the same
// authorization outcome, the same real POSTs, no events and no progress
// JSONL in the human output.
func TestConnectCursorEnableNilProgressChangesNothing(t *testing.T) {
	confirm := func(string, io.Writer) (bool, error) { return true, nil }
	res, out, recorded, toktrail := runCursorConnectProgress(t, false, confirm)
	if len(res.AuthorizedTools) != 1 || res.AuthorizedTools[0] != "Cursor" {
		t.Fatalf("the run must authorize exactly Cursor: %+v", res.AuthorizedTools)
	}
	if len(recorded.batches(collection.ProgressQueueCursor)) != 0 {
		t.Fatalf("no events may be recorded with a nil Progress")
	}
	if cursorMockSrcBatchPosts(toktrail) == 0 {
		t.Fatalf("the enable round still performs its real POSTs")
	}
	if strings.Contains(out, "collection_progress") {
		t.Fatalf("no progress JSONL may leak into the human output")
	}
}
