package connect

// Real-chain integration tests for the §6.5 summary's account verdict
// codes: unlike the unit tests in summary_test.go (which pin the
// mapping over hand-built SyncResult shapes), these drive the FULL
// production chain — connect.Run → Sync → evaluateIncomplete setting
// its structural twin markers → SummarizeRun — against the synthetic
// server and cursor fakes, so the markers are produced by the real
// reason-production points, never hand-set. Everything runs against
// t.TempDir() state directories and httptest mocks: no real server,
// credential or deployment state is touched, and no production output
// shape changes (these tests only read what the chain already
// produces).

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/local/cursorsource"
)

// hasCode reports whether the closed code list carries the code.
func hasCode(codes []string, code string) bool {
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}

// TestSummarizeFirstSyncFailureChainDrivesPendingCode drives the real
// first-sync-failure chain: a first-time Cursor enable whose upstream
// pull fails writes the permit (pending_first_sync, no watermark),
// connect hands CursorFirstSyncFailed to Sync, the initial collection
// round runs its cursor phase drain-only, evaluateIncomplete appends
// the first-sync reason and sets firstSyncIncomplete, and SummarizeRun
// maps that marker onto the closed account_pending_first_sync code —
// with no hand-set flags anywhere in the chain.
func TestSummarizeFirstSyncFailureChainDrivesPendingCode(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startCursorBacklogMock(t)
	cfg := startSyncConfigMock(t, mock.URL, []string{"Cursor"}, nil)
	ticket := strings.Repeat("6", 64)
	seedFirstEnableConnect(t, stateDir, mock, cfg, ticket)

	pull := &cursorBacklogPull{err: errors.New("synthetic upstream pull failure")}
	out := &bytes.Buffer{}
	res, err := runCursorConnectWithOptionsOut(t, cfg, stateDir, homeDir, ticket, Options{
		Cursor: budgetCursorWiring(pull, 5),
		CursorConfirm: func(notice string, w io.Writer) (bool, error) {
			return true, nil
		},
	}, out)
	if err == nil || !isErrSyncIncomplete(err) {
		t.Fatalf("the failed first sync must keep the connect incomplete, got %v", err)
	}
	// The chain's structural facts: the real evaluateIncomplete set the
	// first-sync marker; the drain-only round over the written permit
	// ran cleanly (so the accountTools loop appended no reason and the
	// account marker stays unset); the permit honestly records that the
	// first sync never completed.
	if !res.Sync.firstSyncIncomplete {
		t.Fatalf("evaluateIncomplete must set firstSyncIncomplete when it appends the CursorFirstSyncFailed reason, reasons: %v", res.Sync.Incomplete)
	}
	if res.Sync.accountIncomplete {
		t.Fatalf("a clean drain-only round produced no accountTools reason, the account marker must stay unset, reasons: %v", res.Sync.Incomplete)
	}
	if !res.Sync.Collection.Cursor.Ran || res.Sync.Collection.Cursor.Skipped != "" {
		t.Fatalf("the initial round's drain-only cursor phase must run cleanly, got %+v", res.Sync.Collection.Cursor)
	}
	license, ok, lErr := cursorsource.New(stateDir).Load()
	if lErr != nil || !ok || license.Status != cursorsource.StatusPendingFirstSync || license.PullWatermark != nil {
		t.Fatalf("the permit must stay pending_first_sync with no watermark, ok=%v err=%v license=%+v", ok, lErr, license)
	}
	// The §6.5 verdict over the REAL run result.
	summary := SummarizeRun(res, err, nil, 42)
	if !hasCode(summary.IncompleteCodes, "account_pending_first_sync") {
		t.Fatalf("the real first-sync failure must drive account_pending_first_sync, got %v (reasons: %v)", summary.IncompleteCodes, res.Sync.Incomplete)
	}
	if hasCode(summary.IncompleteCodes, "account_no_permit") {
		t.Fatalf("a written permit must never report account_no_permit, got %v", summary.IncompleteCodes)
	}
	if summary.StopReason != collection.StopFatalError {
		t.Fatalf("stopReason = %q, want fatal_error (the code explains the verdict, never changes it)", summary.StopReason)
	}
}

// TestSummarizeDeclinedEnableChainDrivesNoPermitCode drives the real
// declined-first-enable chain: the authorization names Cursor, the
// local confirmation is declined, no permit is ever written, the
// initial collection's full cursor round ends RoundNoPermit, and
// evaluateIncomplete's accountTools loop appends the did-not-run
// reason and sets accountIncomplete — SummarizeRun then reports the
// closed account_no_permit code over the real result.
func TestSummarizeDeclinedEnableChainDrivesNoPermitCode(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startCursorBacklogMock(t)
	cfg := startSyncConfigMock(t, mock.URL, []string{"Cursor"}, nil)
	ticket := strings.Repeat("7", 64)
	seedFirstEnableConnect(t, stateDir, mock, cfg, ticket)

	// The pull fake is never invoked: a declined confirmation reads no
	// credential and pulls nothing.
	pull := &cursorBacklogPull{events: cursorBulkEvents(2)}
	out := &bytes.Buffer{}
	res, err := runCursorConnectWithOptionsOut(t, cfg, stateDir, homeDir, ticket, Options{
		Cursor: budgetCursorWiring(pull, 5),
		CursorConfirm: func(notice string, w io.Writer) (bool, error) {
			return false, nil
		},
	}, out)
	if err == nil || !isErrSyncIncomplete(err) {
		t.Fatalf("a declined first-time confirmation must leave the connect incomplete, got %v", err)
	}
	if len(pull.calls) != 0 {
		t.Fatalf("a declined confirmation must never pull usage, got %+v", pull.calls)
	}
	// The chain's structural facts: the round really observed the
	// absent permit, and the accountTools reason was actually appended.
	if res.Sync.Collection.Cursor.Outcome != cursorsync.RoundNoPermit {
		t.Fatalf("the initial round must end RoundNoPermit, got %+v", res.Sync.Collection.Cursor)
	}
	if !res.Sync.accountIncomplete {
		t.Fatalf("evaluateIncomplete must set accountIncomplete when the named account source did not run, reasons: %v", res.Sync.Incomplete)
	}
	if res.Sync.firstSyncIncomplete {
		t.Fatalf("no permit was written, so no first-sync failure reason may exist, reasons: %v", res.Sync.Incomplete)
	}
	if _, ok, lErr := cursorsource.New(stateDir).Load(); lErr != nil || ok {
		t.Fatalf("a declined confirmation must leave no permit, ok=%v err=%v", ok, lErr)
	}
	summary := SummarizeRun(res, err, nil, 7)
	if !hasCode(summary.IncompleteCodes, "account_no_permit") {
		t.Fatalf("the real declined enable must drive account_no_permit, got %v (reasons: %v)", summary.IncompleteCodes, res.Sync.Incomplete)
	}
	if hasCode(summary.IncompleteCodes, "account_pending_first_sync") {
		t.Fatalf("no permit exists, so no first-sync code may appear, got %v", summary.IncompleteCodes)
	}
	if summary.StopReason != collection.StopFatalError {
		t.Fatalf("stopReason = %q, want fatal_error", summary.StopReason)
	}
}

// TestSummarizeUnrelatedFailuresNeverFabricateAccountCodesChain drives
// the real negative chain: the authorization names only Codex (the
// account source is NOT named, no permit exists, so the cursor round's
// RoundNoPermit is the clean never-enabled steady state), while the
// run-wide budget declines over the device queue and makes the run
// incomplete for unrelated reasons. The account markers must stay
// unset and the summary must report only the budget/pending codes —
// never a fabricated account verdict code — over the real result.
func TestSummarizeUnrelatedFailuresNeverFabricateAccountCodesChain(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startCursorBacklogMock(t)
	cfg := startSyncConfigMock(t, mock.URL, []string{"Codex"}, nil)
	ticket := strings.Repeat("9", 64)
	seedFirstEnableConnect(t, stateDir, mock, cfg, ticket)
	seedCodexSessionsGrant(t, stateDir, homeDir)
	seedDeviceBacklogBatch(t, stateDir, homeDir, "neg-chain-dev-1", "neg-chain-key-1")
	seedDeviceBacklogBatch(t, stateDir, homeDir, "neg-chain-dev-2", "neg-chain-key-2")

	// The cursor wiring exists, so the initial round really runs its
	// cursor phase and observes the absent permit — but the pull fake
	// is never invoked.
	pull := &cursorBacklogPull{events: cursorBulkEvents(2)}
	res, err := runSyncConnectWithOptions(t, cfg, stateDir, homeDir, ticket, Options{
		MaxTotalBatches: 1,
		Cursor:          budgetCursorWiring(pull, 5),
	})
	if err == nil || !isErrSyncIncomplete(err) {
		t.Fatalf("the budget-declined run must stay incomplete, got %v", err)
	}
	if !res.Sync.BudgetExhausted {
		t.Fatalf("the shared budget decline must be flagged, got %+v", res.Sync)
	}
	if len(pull.calls) != 0 {
		t.Fatalf("a never-enabled account source must never pull, got %+v", pull.calls)
	}
	// The chain's structural facts: the round observed the absent
	// permit, but no account reason was ever appended (the
	// authorization did not name the source and no permit exists for
	// the implicit expectation to pick up).
	if res.Sync.Collection.Cursor.Outcome != cursorsync.RoundNoPermit {
		t.Fatalf("the initial round must observe the absent permit, got %+v", res.Sync.Collection.Cursor)
	}
	if res.Sync.accountIncomplete || res.Sync.firstSyncIncomplete {
		t.Fatalf("an unnamed account source must set no account markers, got account=%t firstSync=%t (reasons: %v)",
			res.Sync.accountIncomplete, res.Sync.firstSyncIncomplete, res.Sync.Incomplete)
	}
	summary := SummarizeRun(res, err, nil, 9)
	for _, code := range []string{"account_no_permit", "account_auth_withheld", "account_pending_first_sync"} {
		if hasCode(summary.IncompleteCodes, code) {
			t.Fatalf("an unnamed account source must never fabricate %s, got %v (reasons: %v)", code, summary.IncompleteCodes, res.Sync.Incomplete)
		}
	}
	if !hasCode(summary.IncompleteCodes, "budget_exhausted") {
		t.Fatalf("the real budget decline must still be reported, got %v (reasons: %v)", summary.IncompleteCodes, res.Sync.Incomplete)
	}
	if summary.StopReason != collection.StopBudgetExhausted {
		t.Fatalf("stopReason = %q, want budget_exhausted", summary.StopReason)
	}
}
