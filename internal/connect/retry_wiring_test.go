package connect

// Entry-level retry wiring coverage for the connect orchestration: the
// run's single retry policy (Options.Retry; production builds it with
// full jitter against the ctx deadline) must reach every sending queue
// with the retry loop INSIDE each POST's send — the history
// retransmission here — resending byte-identical payloads under the same
// batch ID, reserving the shared run budget per real POST, and ACKing
// exactly once. Everything is synthetic: tempdir state, the shared mock
// pair from sync_test.go, and a frozen-clock policy so nothing sleeps.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/syncretry"
)

// connectFrozenRetryClock keeps "now" frozen and turns waits into
// no-ops, so no test sleeps.
type connectFrozenRetryClock struct{ now time.Time }

func (c connectFrozenRetryClock) Now() time.Time                                  { return c.now }
func (c connectFrozenRetryClock) Wait(ctx context.Context, d time.Duration) error { return ctx.Err() }

// connectTestRetryPolicy builds the deterministic test policy.
func connectTestRetryPolicy() *syncretry.Policy {
	return syncretry.New(
		syncretry.WithClock(connectFrozenRetryClock{now: time.Now()}),
		syncretry.WithBaseDelay(0),
		syncretry.WithRunDeadline(time.Now().Add(time.Minute)),
	)
}

// TestConnectRetryWiredIntoHistoryRetransmission drives a full
// connect.Run (reconnect over prior synced history) whose FIRST ingest
// POST — the history retransmission — fails with a retryable 503: the
// run must retry it, resend byte-identical bytes under the same batch ID,
// accept the replay receipt, record exactly one journal upload, and leave
// the already-synced outbox entry untouched (BatchFile selection, no
// StateDir on the send, single ACK).
func TestConnectRetryWiredIntoHistoryRetransmission(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startSyncToktrailMock(t, "dev-retry-1")
	cfg := startSyncConfigMock(t, mock.URL, []string{"Codex"}, intPtr(30))

	seedBoundState(t, stateDir, mock.URL, "dev-retry-1")
	seedCodexGrant(t, stateDir, homeDir)
	seedBatch(t, stateDir, homeDir, "retry-synced-1", outbox.StatusSynced,
		syncRecord("retry-key-1", syncTestNow.Add(-time.Hour).Format(time.RFC3339)))
	batchFile := filepath.Join(stateDir, "batches", "retry-synced-1.json")
	beforeBatch, err := os.ReadFile(batchFile)
	if err != nil {
		t.Fatal(err)
	}
	beforeOutbox, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}

	mock.setFlakeFirstIngest()
	res, err := runSyncConnectWithOptions(t, cfg, stateDir, homeDir, repeatTicket('7'), Options{Retry: connectTestRetryPolicy()})
	if err != nil {
		t.Fatalf("reconnect with a retried transient failure must succeed, got: %v", err)
	}
	if len(res.Sync.Incomplete) != 0 {
		t.Fatalf("the retried run must be complete, got incompleteness: %v", res.Sync.Incomplete)
	}
	if !res.Sync.Resync.Completed || res.Sync.Resync.Uploads != 1 {
		t.Fatalf("the retried retransmission must complete with one upload, got %+v", res.Sync.Resync)
	}
	// The 503 never committed server-side, so the accepted retry is a
	// fresh receipt, not a replay — exactly one upload receipt in total.
	if res.Sync.Resync.ReplayReceipts != 0 || res.Sync.Resync.AcceptedRecords != 1 {
		t.Fatalf("expected one fresh accepted receipt (the 503 committed nothing), got %+v", res.Sync.Resync)
	}
	if got := mock.ingestTotalCount(); got != 2 {
		t.Fatalf("batch retry-synced-1 must be POSTed exactly twice (503 then accepted), got %d", got)
	}
	bodies := mock.ingestRawBodies()
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("the retry must resend byte-identical payloads under the same batch ID")
	}
	// The already-synced outbox entry and the original batch file stay
	// untouched: the retransmission selects the batch by file and never
	// re-marks the synced outbox.
	afterBatch, err := os.ReadFile(batchFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeBatch, afterBatch) {
		t.Fatal("the original batch file must stay byte-identical")
	}
	afterOutbox, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(afterOutbox.Batches) != len(beforeOutbox.Batches) {
		t.Fatalf("the outbox must not grow: before %d after %d", len(beforeOutbox.Batches), len(afterOutbox.Batches))
	}
	for i := range afterOutbox.Batches {
		if afterOutbox.Batches[i].Status != outbox.StatusSynced || afterOutbox.Batches[i].SyncedAt != beforeOutbox.Batches[i].SyncedAt {
			t.Fatalf("the synced outbox entry must stay untouched, got %#v", afterOutbox.Batches[i])
		}
	}
	// The journal recorded exactly one upload receipt (a single ACK).
	if ids := journalBatchIDs(t, stateDir); len(ids) != 1 || ids[0] != "retry-synced-1" {
		t.Fatalf("the job must cover exactly the prior batch, got %v", ids)
	}
}

// TestConnectRetryBudgetDeclineStopsTheRetry pins the budget consistency
// of the retried send at the connect entry: with a one-POST run budget
// the failed first retransmission POST consumes the only unit, the retry
// is declined BEFORE its POST, and the run reports the honest budget
// incompleteness with the job resumable.
func TestConnectRetryBudgetDeclineStopsTheRetry(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startSyncToktrailMock(t, "dev-retry-2")
	cfg := startSyncConfigMock(t, mock.URL, []string{"Codex"}, intPtr(30))

	seedBoundState(t, stateDir, mock.URL, "dev-retry-2")
	seedCodexGrant(t, stateDir, homeDir)
	seedBatch(t, stateDir, homeDir, "retry-synced-2", outbox.StatusSynced,
		syncRecord("retry-key-2", syncTestNow.Add(-time.Hour).Format(time.RFC3339)))

	mock.setFlakeFirstIngest()
	res, err := runSyncConnectWithOptions(t, cfg, stateDir, homeDir, repeatTicket('8'), Options{
		Retry:           connectTestRetryPolicy(),
		MaxTotalBatches: 1,
	})
	if err == nil {
		t.Fatal("the budget-exhausted run must fail honestly, not succeed")
	}
	if !errors.Is(err, ErrSyncIncomplete) {
		t.Fatalf("expected ErrSyncIncomplete, got %v", err)
	}
	if !res.Sync.BudgetExhausted {
		t.Fatal("the run must report the budget exhaustion")
	}
	if got := mock.ingestTotalCount(); got != 1 {
		t.Fatalf("exactly one POST may happen (the 503); the retry must be declined before its POST, got %d", got)
	}
	if res.Sync.Resync.Completed {
		t.Fatal("the retransmission job must stay unfinished and resumable")
	}
	if res.Sync.Resync.Stopped == "" {
		t.Fatal("the stop reason must be reported")
	}
}

// repeatTicket builds a 64-hex-ish synthetic connect ticket.
func repeatTicket(char byte) string {
	out := make([]byte, 64)
	for i := range out {
		out[i] = char
	}
	return string(out)
}

// TestCursorOptionsForCollectionAdoptRunRetry pins the cursor wiring of
// the shared policy: a collection cursor round built by Sync adopts the
// run's retry policy when the caller did not wire its own, and an
// explicitly wired Cursor.Retry always wins.
func TestCursorOptionsForCollectionAdoptRunRetry(t *testing.T) {
	runPolicy := connectTestRetryPolicy()
	own := connectTestRetryPolicy()
	cases := []struct {
		name   string
		cursor *cursorsync.Options
		want   *syncretry.Policy
	}{
		{"adopts the run policy when unset", &cursorsync.Options{}, runPolicy},
		{"keeps an explicitly wired policy", &cursorsync.Options{Retry: own}, own},
		{"no cursor wiring stays nil", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cursorOptionsForCollection(SyncOptions{Cursor: tc.cursor, Retry: runPolicy}, true)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("expected no cursor options, got %+v", got)
				}
				return
			}
			if got == nil || got.Retry != tc.want {
				t.Fatalf("the cursor round must carry %p, got %+v", tc.want, got)
			}
		})
	}
}
