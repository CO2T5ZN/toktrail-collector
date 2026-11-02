package connect

// Shared-budget scheduling integration tests (P1): connect's sync phase
// reserves every real ingest POST — device outbox, account source and
// history retransmission — under one syncbudget.Budget, drains the two
// NEW queues with fair rotation before the history replay, and reports a
// spent budget as an honest ErrSyncIncomplete with consistent pending
// counts and a resumable history journal.
//
// The scenarios are end-to-end through the real orchestration (connect.Run
// or Sync) against synthetic httptest servers with hand-seeded outboxes:
// no real tool state, credential or account is ever read. The 174-batch
// scenario deliberately exceeds the historical 10-pass × 5-batch backlog
// ceiling (~50 device batches) to prove a budgeted run drains to empty.
import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/app/resync"
	"toktrail-collector/internal/local/cursorsource"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncbudget"
)

// budgetCursorWiring builds the synthetic cursor wiring the budget
// scenarios inject into connect.Run / Sync.
func budgetCursorWiring(pull *cursorBacklogPull, maxBatches int) *cursorsync.Options {
	return &cursorsync.Options{
		Auth:       &cursorBacklogAuth{},
		Verify:     (&cursorBacklogVerify{}).verify,
		Pull:       pull.pull,
		Now:        func() time.Time { return cursorBacklogNow },
		MaxBatches: maxBatches,
	}
}

// TestConnectDefaultBudgetDrains174BatchesAcrossQueues is the P1
// end-to-end scenario: a reconnect holding 120 pending device batches, 30
// pending account-source batches and 24 already-synced history batches —
// 174 real POSTs in total — completes in ONE connect run under the
// default budget (1000 POSTs / 10 minutes). It proves:
//
//   - the historical 10-pass × 5-batch backlog ceiling (~50 device
//     batches) no longer stops a budgeted run: 120 device batches drain
//     through 23 backlog passes;
//   - the device and account queues rotate fairly (both advance inside
//     the same passes while both hold work);
//   - the history retransmission runs LAST: every device/account POST
//     precedes the first history POST in the global order;
//   - the run is complete — no incompleteness, nothing pending.
func TestConnectDefaultBudgetDrains174BatchesAcrossQueues(t *testing.T) {
	stateDir, homeDir, mock, cfg := seed174Scenario(t)
	pull := &cursorBacklogPull{}

	res, err, humanOut := runSyncConnectWithOutput(t, cfg, stateDir, homeDir, strings.Repeat("8", 64), Options{
		Cursor: budgetCursorWiring(pull, 5),
	})
	if err != nil {
		t.Fatalf("the 174-batch reconnect must complete under the default budget: %v (incomplete=%v)", err, res.Sync.Incomplete)
	}
	if len(res.Sync.Incomplete) != 0 {
		t.Fatalf("a fully drained budgeted run is complete, got %v", res.Sync.Incomplete)
	}
	if res.Sync.BudgetExhausted {
		t.Fatalf("the default budget must cover 174 POSTs, got %+v", res.Sync)
	}
	// 120 device batches need the initial round (5) plus 23 backlog
	// passes (5 each): the pass bound (10) must not stop the drain.
	if res.Sync.Backlog.Passes != 23 || res.Sync.Backlog.PendingRemaining != 0 || res.Sync.Backlog.CursorPendingRemaining != 0 {
		t.Fatalf("both new queues must drain to empty through unbounded passes: %+v", res.Sync.Backlog)
	}
	if res.Sync.Resync.Completed != true || res.Sync.Resync.Uploads != 24 || res.Sync.Resync.Remaining != 0 {
		t.Fatalf("the history retransmission must cover the 24 pre-connect batches, got %+v", res.Sync.Resync)
	}
	// Exactly 174 real POSTs: 120 device + 24 history on the device
	// endpoint, 30 on the account endpoint.
	if got := mock.deviceBatchPosts(); got != 144 {
		t.Fatalf("expected 144 device-endpoint POSTs (120 drain + 24 history), got %d", got)
	}
	if got := mock.srcBatchPosts(); got != 30 {
		t.Fatalf("expected 30 account-source POSTs, got %d", got)
	}
	if len(pull.calls) != 1 {
		t.Fatalf("only the initial forced cursor pull may happen, got %d", len(pull.calls))
	}

	// Scheduling order, from the server-side POST log:
	//   1. NEW queues first — the first history POST happens strictly
	//      after every device-drain and account POST;
	//   2. fair rotation — while the device queue still held batches,
	//      account batches advanced in the very same passes (and the
	//      device drain leads inside each pass).
	firstHistory := len(mock.postLogEntries())
	for i, entry := range mock.postLogEntries() {
		if strings.HasPrefix(entry, "device:hist-synced-") && i < firstHistory {
			firstHistory = i
		}
	}
	lastNewQueue := -1
	for i, entry := range mock.postLogEntries() {
		if strings.HasPrefix(entry, "device:dev-pending-") || strings.HasPrefix(entry, "cursor:") {
			lastNewQueue = i
		}
	}
	if firstHistory == len(mock.postLogEntries()) || lastNewQueue == -1 || firstHistory < lastNewQueue {
		log := mock.postLogEntries()
		t.Fatalf("every new-queue POST must precede the first history POST (firstHistory=%d lastNewQueue=%d of %d)", firstHistory, lastNewQueue, len(log))
	}
	deviceLead := mock.postLogIndex("device:dev-pending-6")
	cursorFollow := mock.postLogIndex("cursor:cur-pending-6")
	cursorLate := mock.postLogIndex("cursor:cur-pending-30")
	deviceLate := mock.postLogIndex("device:dev-pending-120")
	if deviceLead < 0 || cursorFollow < 0 || cursorLate < 0 || deviceLate < 0 {
		t.Fatalf("expected the rotation batch posts in the log, got %v", mock.postLogEntries())
	}
	if !(deviceLead < cursorFollow && cursorFollow < deviceLate) {
		t.Fatalf("the account queue must advance between device batches of the same passes (rotation), deviceLead=%d cursorFollow=%d deviceLate=%d", deviceLead, cursorFollow, deviceLate)
	}
	_ = cursorLate

	// Concise display volume: 174 real POSTs across 23 backlog passes
	// must NOT become 23 "backlog pass N" lines or any per-batch line.
	// The regular complete output (excluding the heartbeat lines, the
	// authorization-interaction lines and any error/incomplete lines)
	// stays within ten lines: the phase outcomes, the one-line plan with
	// its coverage note, and the boundary note - never a second verbose
	// log wearing a concise costume.
	regular := 0
	for _, line := range strings.Split(strings.TrimSpace(humanOut), "\n") {
		if line == "" || strings.HasPrefix(line, "tool \"") || strings.HasPrefix(line, "still working") || strings.HasPrefix(line, "Still working") {
			// The account-source permit status is authorization
			// interaction; the heartbeat lines are the progress signal;
			// neither counts against the concise budget.
			continue
		}
		regular++
	}
	if regular > 10 {
		t.Fatalf("the regular complete output must stay within ten lines over a 174-batch drain, got %d:\n%s", regular, humanOut)
	}
	for _, banned := range []string{
		"backlog pass", "history batch:", "dev-pending-", "hist-synced-", "cur-pending-",
		"exportedBatches=", "syncedBatches=", "passes=", "submitted=",
		"running initial collection...", "draining backlog...", "retransmitting history...",
	} {
		if strings.Contains(humanOut, banned) {
			t.Fatalf("the concise default must never carry %q, got:\n%s", banned, humanOut)
		}
	}
	for _, want := range []string{
		"connected to server; device already bound",
		"Collecting local usage...", "backlog: drained",
		"History replay covers this device only, and only the batches already synced before this run",
	} {
		if !strings.Contains(humanOut, want) {
			t.Fatalf("the concise default must carry the brief line %q, got:\n%s", want, humanOut)
		}
	}
	if strings.Contains(humanOut, "initial collection: finished") {
		t.Fatalf("the healthy round outcome belongs to the final summary (or --verbose), got:\n%s", humanOut)
	}
	if strings.Contains(humanOut, "resync covers the device outbox") {
		t.Fatalf("the long coverage note must stay behind --verbose, got:\n%s", humanOut)
	}
}

// TestConnectVerboseBudget174BatchesShowsPerPassDetail: --verbose adds
// the per-pass collection rounds and the per-batch history lines (no
// batch ids) over the same 174-batch scenario.
func TestConnectVerboseBudget174BatchesShowsPerPassDetail(t *testing.T) {
	stateDir, homeDir, mock, cfg := seed174Scenario(t)
	pull := &cursorBacklogPull{}

	res, err, humanOut := runSyncConnectWithOutput(t, cfg, stateDir, homeDir, strings.Repeat("8", 64), Options{
		Cursor:  budgetCursorWiring(pull, 5),
		Verbose: true,
	})
	if err != nil {
		t.Fatalf("the verbose 174-batch reconnect must complete: %v (incomplete=%v)", err, res.Sync.Incomplete)
	}
	if !strings.Contains(humanOut, "backlog pass 1:") || !strings.Contains(humanOut, "backlog pass 23:") {
		t.Fatalf("verbose must show the per-pass rounds, got:\n%s", humanOut)
	}
	if !strings.Contains(humanOut, "history batch: done") {
		t.Fatalf("verbose must show the per-batch history lines, got:\n%s", humanOut)
	}
	for _, banned := range []string{"dev-pending-1", "hist-synced-1", "cur-pending-1"} {
		if strings.Contains(humanOut, banned) {
			t.Fatalf("no mode may echo a batch id, got %q in:\n%s", banned, humanOut)
		}
	}
	_ = mock
}

// seed174Scenario builds the full 174-batch reconnect scenario (120
// pending device batches, 30 pending account batches, 24 synced
// history batches) with fresh state directories.
func seed174Scenario(t *testing.T) (stateDir, homeDir string, mock *cursorBacklogMock, cfg *syncConfigMock) {
	t.Helper()
	stateDir = t.TempDir()
	homeDir = t.TempDir()
	mock = startCursorBacklogMock(t)
	cfg = startSyncConfigMock(t, mock.URL, []string{"Codex", "Cursor"}, intPtr(90))

	// A bound state that already carries this link's receipt, so connect
	// skips the bind (the cursor mock serves no bind endpoint) and runs
	// the reconnect path: identity matches the config mock (app-sync /
	// sub-sync) while /self serves the cursor mock's device and account
	// source.
	ticket := strings.Repeat("8", 64)
	st := statedir.DeviceState{
		DeviceID:           cursorBacklogDevice,
		DeviceSecret:       strings.Repeat("a", 64),
		ServerURL:          mock.URL,
		ApplicationID:      "app-sync",
		ExternalSubjectID:  "sub-sync",
		ConsentRevision:    5,
		UploadAuthorized:   true,
		ConnectReceiptHash: computeReceiptFingerprint(ticket, cfg.URL+"/api/collector/connect"),
	}
	if err := statedir.New(stateDir).Save(st); err != nil {
		t.Fatalf("write bound state: %v", err)
	}
	seedCursorBacklogPermit(t, stateDir, cursorsource.StatusActive)
	seedCodexSessionsGrant(t, stateDir, homeDir)
	for i := 1; i <= 24; i++ {
		seedDeviceBacklogBatchStatus(t, stateDir, homeDir, fmt.Sprintf("hist-synced-%d", i), fmt.Sprintf("hist-key-%d", i), outbox.StatusSynced)
	}
	for i := 1; i <= 120; i++ {
		seedDeviceBacklogBatch(t, stateDir, homeDir, fmt.Sprintf("dev-pending-%d", i), fmt.Sprintf("dev-key-%d", i))
	}
	for i := 1; i <= 30; i++ {
		seedCursorBacklogBatch(t, stateDir, fmt.Sprintf("cur-pending-%d", i), 1)
	}
	return stateDir, homeDir, mock, cfg
}

// TestSyncBudgetDeadlineStopsAllQueuesHonestly verifies the budget
// deadline path with a deterministic clock: an already-expired deadline
// declines every Reserve, so no POST happens anywhere, every queue keeps
// its honest pending count, the history phase is skipped before any
// preflight, and the run reports ErrSyncIncomplete with the budget named.
func TestSyncBudgetDeadlineStopsAllQueuesHonestly(t *testing.T) {
	dir := t.TempDir()
	homeDir := t.TempDir()
	mock := startCursorBacklogMock(t)
	seedCursorBacklogState(t, dir, mock.URL)
	seedCursorBacklogPermit(t, dir, cursorsource.StatusActive)
	seedCodexSessionsGrant(t, dir, homeDir)
	for i := 1; i <= 2; i++ {
		seedDeviceBacklogBatch(t, dir, homeDir, fmt.Sprintf("dl-dev-%d", i), fmt.Sprintf("dl-dev-key-%d", i))
		seedCursorBacklogBatch(t, dir, fmt.Sprintf("dl-cur-%d", i), 1)
		seedDeviceBacklogBatchStatus(t, dir, homeDir, fmt.Sprintf("dl-hist-%d", i), fmt.Sprintf("dl-hist-key-%d", i), outbox.StatusSynced)
	}
	pull := &cursorBacklogPull{}
	budget := syncbudget.New(
		syncbudget.WithTotal(1000),
		syncbudget.WithNow(func() time.Time { return cursorBacklogNow }),
		syncbudget.WithDeadline(cursorBacklogNow.Add(-time.Second)),
	)

	res, err := Sync(context.Background(), SyncOptions{
		StateDir: dir, ServerURL: mock.URL, HomeDir: homeDir,
		Now:    func() time.Time { return cursorBacklogNow },
		Budget: budget,
		Cursor: budgetCursorWiring(pull, 5),
	})
	if err == nil || !isErrSyncIncomplete(err) {
		t.Fatalf("an expired budget deadline must report an incomplete run, got %v", err)
	}
	if !res.BudgetExhausted {
		t.Fatalf("the deadline decline must be flagged, got %+v", res)
	}
	if mock.deviceBatchPosts() != 0 || mock.srcBatchPosts() != 0 || len(pull.calls) != 0 {
		t.Fatalf("no POST or pull may happen under an expired budget, got device=%d cursor=%d pulls=%d", mock.deviceBatchPosts(), mock.srcBatchPosts(), len(pull.calls))
	}
	if budget.Used() != 0 {
		t.Fatalf("declines must not consume budget, got used=%d", budget.Used())
	}
	// Honest pending counts everywhere: the initial round's cursor drain
	// declined before the pull (its skip carries the sentinel), the
	// device drain declined, and the history phase never ran.
	if res.Collection.Cursor.PendingRemaining != 2 || res.Collection.PendingRemaining != 2 {
		t.Fatalf("the declined batches must stay pending: %+v", res.Collection)
	}
	if res.Resync.Ran || res.Resync.Skipped == "" {
		t.Fatalf("the history phase must be skipped before any preflight, got %+v", res.Resync)
	}
	if !containsReason(res.Incomplete, "shared sync POST budget") {
		t.Fatalf("the budget deadline must be named, got %v", res.Incomplete)
	}
	// The two declined device batches stay pending; the two history
	// batches stay synced (no job was started, nothing was re-sent).
	if pendingCount(t, dir) != 2 {
		t.Fatalf("the outbox must keep the declined device batches pending, got %d", pendingCount(t, dir))
	}
}

// TestSyncDeviceQueueCapDoesNotBlockCursorBacklog verifies that a
// per-queue cap on the DEVICE queue (max per queue preserved) does not
// starve the account queue: the backlog passes skip the device drain and
// keep draining cursor batches, and the history queue keeps posting under
// the same run (no run-wide total is configured).
func TestSyncDeviceQueueCapDoesNotBlockCursorBacklog(t *testing.T) {
	dir := t.TempDir()
	homeDir := t.TempDir()
	mock := startCursorBacklogMock(t)
	seedCursorBacklogState(t, dir, mock.URL)
	seedCursorBacklogPermit(t, dir, cursorsource.StatusActive)
	seedCodexSessionsGrant(t, dir, homeDir)
	for i := 1; i <= 4; i++ {
		seedDeviceBacklogBatch(t, dir, homeDir, fmt.Sprintf("cap-dev-%d", i), fmt.Sprintf("cap-dev-key-%d", i))
	}
	for i := 1; i <= 5; i++ {
		seedCursorBacklogBatch(t, dir, fmt.Sprintf("cap-cur-%d", i), 1)
	}
	pull := &cursorBacklogPull{}
	budget := syncbudget.New(syncbudget.WithQueueCap("device", 2))

	res, err := Sync(context.Background(), SyncOptions{
		StateDir: dir, ServerURL: mock.URL, HomeDir: homeDir,
		Now:    func() time.Time { return cursorBacklogNow },
		Budget: budget,
		Cursor: budgetCursorWiring(pull, 2),
	})
	if err == nil || !isErrSyncIncomplete(err) {
		t.Fatalf("the capped device queue must leave the run incomplete, got %v", err)
	}
	if res.BudgetExhausted {
		t.Fatalf("a queue-only cap must not flag run-wide budget exhaustion, got %+v", res)
	}
	// The device queue posted exactly its cap (the initial round's
	// drain); the account queue drained fully through skip-device
	// backlog passes.
	if res.Collection.SyncedBatches != 2 {
		t.Fatalf("the device queue cap must bound the device drain, got %d synced", res.Collection.SyncedBatches)
	}
	if res.Backlog.CursorPendingRemaining != 0 || mock.srcBatchPosts() != 5 {
		t.Fatalf("the account queue must drain despite the device cap, got pending=%d posts=%d", res.Backlog.CursorPendingRemaining, mock.srcBatchPosts())
	}
	if res.Backlog.PendingRemaining != 2 || !strings.Contains(res.Backlog.Stopped, "device queue") {
		t.Fatalf("the capped device batches must stay pending with the cap named, got %+v", res.Backlog)
	}
	// The history queue is uncapped and the run has no total: it still
	// covers its full-archive targets (the two batches the drain synced,
	// replayed over the shared device ingest endpoint).
	if !res.Resync.Completed || res.Resync.Uploads != 2 || mock.deviceBatchPosts() != 4 {
		t.Fatalf("the history queue must keep posting under a device-only cap, got %+v devicePosts=%d", res.Resync, mock.deviceBatchPosts())
	}
}

// TestSyncNilBudgetKeepsBoundedBacklogPasses pins the nil-compatibility
// contract (the resync CLI drive): without a budget and without a total,
// the backlog drain keeps the historical DefaultMaxBacklogPasses bound —
// a 60-batch device backlog leaves 5 pending after the initial round
// (5) plus 10 bounded passes (50) — and reports it as incomplete.
func TestSyncNilBudgetKeepsBoundedBacklogPasses(t *testing.T) {
	dir := t.TempDir()
	homeDir := t.TempDir()
	mock := startCursorBacklogMock(t)
	seedCursorBacklogState(t, dir, mock.URL)
	seedCodexSessionsGrant(t, dir, homeDir)
	for i := 1; i <= 60; i++ {
		seedDeviceBacklogBatch(t, dir, homeDir, fmt.Sprintf("nil-dev-%d", i), fmt.Sprintf("nil-dev-key-%d", i))
	}

	res, err := Sync(context.Background(), SyncOptions{
		StateDir: dir, ServerURL: mock.URL, HomeDir: homeDir,
		Now:            func() time.Time { return cursorBacklogNow },
		ResyncSnapshot: resync.NewSyncedBatchSnapshot(nil), // connect's first-install shape: no history to replay
	})
	if err == nil || !isErrSyncIncomplete(err) {
		t.Fatalf("an unbudgeted bounded run must report its remainder, got %v", err)
	}
	if res.BudgetExhausted {
		t.Fatalf("an unbudgeted run never reports budget exhaustion, got %+v", res)
	}
	if res.Backlog.Passes != DefaultMaxBacklogPasses || res.Backlog.PendingRemaining != 5 {
		t.Fatalf("the nil-budget drive must keep the 10-pass bound: %+v", res.Backlog)
	}
	if !strings.Contains(res.Backlog.Stopped, "backlog pass bound") {
		t.Fatalf("the pass bound must be the stop reason, got %+v", res.Backlog)
	}
	if got := mock.deviceBatchPosts(); got != 55 {
		t.Fatalf("the bounded unbudgeted run drains 55 batches with no replay, got %d", got)
	}
}

// TestBuildSyncBudgetDefaults pins connect.Run's default budget
// construction: 1000 total POSTs and a 10-minute deadline derived from
// the same clock (a fixed clock can never expire it), with
// MaxTotalBatches overriding the total and negatives rejected by Run
// before any work happens.
func TestBuildSyncBudgetDefaults(t *testing.T) {
	b := buildSyncBudget(0, func() time.Time { return cursorBacklogNow })
	if n, ok := b.Remaining(); !ok || n != DefaultBudgetTotal {
		t.Fatalf("the default budget total must be %d, got (%d, %t)", DefaultBudgetTotal, n, ok)
	}
	// The budget grants under the fixed clock (its deadline shares that
	// clock): a Reserve succeeds and consumes exactly one unit.
	if err := b.Reserve(context.Background(), budgetQueueDevice); err != nil {
		t.Fatalf("the default budget must grant under its own clock: %v", err)
	}
	if n, _ := b.Remaining(); n != DefaultBudgetTotal-1 {
		t.Fatalf("one Reserve must consume one unit, got %d", n)
	}

	capped := buildSyncBudget(7, func() time.Time { return cursorBacklogNow })
	if n, ok := capped.Remaining(); !ok || n != 7 {
		t.Fatalf("MaxTotalBatches must override the total, got (%d, %t)", n, ok)
	}

	// Negative totals are rejected by Run up front, before any ticket
	// fetch, bind or scan.
	if _, err := Run(context.Background(), Options{StateDir: t.TempDir(), URL: "https://example.invalid/api/collector/connect#" + strings.Repeat("a", 64), MaxTotalBatches: -1}); err == nil || !strings.Contains(err.Error(), "max total batches must be non-negative") {
		t.Fatalf("Run must reject a negative MaxTotalBatches up front, got %v", err)
	}
}
