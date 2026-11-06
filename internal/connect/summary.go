package connect

// The connect command's stable §6.5 result contract: a single
// low-cardinality StopReason plus the redacted per-phase core the
// periodic command shares (collection.Phases), the connect-only
// binding/scheduler/history blocks, and the closed IncompleteCodes
// mirror of SyncResult.Incomplete. Like the collection contract, it
// carries ONLY closed enums, registry-known names (already filtered by
// collection.SummarizePhases) and counters — never URLs, tickets,
// tokens, device/subject identifiers, paths, batch or job ids, or any
// free text. Classification reads structure only (error sentinels,
// DrainStop/ResyncStop codes, cursor outcomes, evaluateIncomplete's
// twin markers), never message text. The account-verdict codes (no
// permit, authorization withheld, first sync still pending) key on the
// markers evaluateIncomplete sets exactly when it appends the
// corresponding account reason — the same cursor outcomes are also the
// honest steady state of a run whose authorization never owed the
// account source, so the outcome alone must never fabricate a code; a
// reason no closed code maps degrades to the unmapped_incomplete
// fallback so an incomplete run never carries an empty machine
// explanation.

import (
	"errors"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/app/cursorsync"
)

// Summary-only history stop codes: derived by SummarizeRun, never
// assigned on a ResyncSummary.
const (
	// ResyncStopNotRun: the phase never ran (the orchestration exited
	// before reaching it).
	ResyncStopNotRun ResyncStopCode = "not_run"
	// ResyncStopUnknown: the phase ran but recorded no structured end
	// (a future shape); the honest fallback, never a guess.
	ResyncStopUnknown ResyncStopCode = "unknown"
)

// BindingSummary reports how far connect's binding phase got. The
// device id, server, application and subject never enter the contract.
type BindingSummary struct {
	Status          BindStatus `json:"status"`
	ConsentRevision int64      `json:"consentRevision"`
}

// SchedulerSummary reports the scheduled-service installation.
type SchedulerSummary struct {
	Installed bool `json:"installed"`
}

// HistorySummary reports the history retransmission phase. Job ids and
// stop messages never enter the contract; Stop uses the closed
// ResyncStopCode vocabulary.
type HistorySummary struct {
	Ran             bool           `json:"ran"`
	DryRun          bool           `json:"dryRun"`
	Completed       bool           `json:"completed"`
	Uploads         int            `json:"uploads"`
	UploadedRecords int            `json:"uploadedRecords"`
	AcceptedRecords int            `json:"acceptedRecords"`
	RejectedRecords int            `json:"rejectedRecords"`
	Remaining       int            `json:"remaining"`
	Stop            ResyncStopCode `json:"stop"`
	// ConsentConfirmed reports whether the phase observed the live
	// consent revision (an unconfirmed phase is reported by the
	// incompleteness codes, never as success).
	ConsentConfirmed bool `json:"consentConfirmed"`
}

// RunSummary is the connect command's stable §6.5 result contract.
type RunSummary struct {
	Schema     int                   `json:"schema"`
	Command    string                `json:"command"`
	StopReason collection.StopReason `json:"stop_reason"`
	DurationMS int64                 `json:"durationMs"`
	Binding    BindingSummary        `json:"binding"`
	Scheduler  SchedulerSummary      `json:"scheduler"`
	Collection collection.Phases     `json:"collection"`
	History    HistorySummary        `json:"history"`
	// IncompleteCodes mirrors SyncResult.Incomplete with closed
	// low-cardinality codes, deduplicated and in evaluation order. A
	// run the sync judged incomplete always carries at least one code
	// (an unmapped reason degrades to unmapped_incomplete, never to an
	// empty list); a complete run always carries none; a code is only
	// ever reported for a reason that was actually recorded.
	IncompleteCodes []string `json:"incompleteCodes"`
}

// SummarizeRun builds the connect command's §6.5 verdict. err is the
// run error (nil on a complete run), ctxErr the run context's own
// state at return time (nil when still live). The verdict classifies
// from sentinels first; an otherwise-fatal error is refined from the
// structured sync state (budget, scope drift, pause) — never from
// message text. A zero Result (an early exit) reports not-attempted
// phases and the error's own verdict without fabrication.
func SummarizeRun(res Result, err, ctxErr error, durationMS int64) RunSummary {
	summary := RunSummary{
		Schema:     collection.ResultSchema,
		Command:    "connect",
		DurationMS: durationMS,
		Binding: BindingSummary{
			Status:          normalizeBindStatus(res.BindStatus),
			ConsentRevision: res.ConsentRevision,
		},
		Scheduler:       SchedulerSummary{Installed: res.InstalledService != ""},
		Collection:      collection.SummarizePhases(mergedCollection(res.Sync)),
		History:         summarizeHistory(res.Sync.Resync),
		IncompleteCodes: incompleteCodes(res.Sync),
	}
	summary.StopReason = connectStopReason(res, err, ctxErr)
	if summary.StopReason == collection.StopBusy {
		// The lock stopped the run before any work: the drain section
		// must not claim a drained queue over the zeroed counts.
		summary.Collection.Drain.Stop = collection.DrainStopNotRun
	}
	return summary
}

// SummarizeNotRun classifies a connect command that failed before its
// orchestration could start (flag validation, state directory
// resolution, cursor wiring): binding reports not_attempted, the
// collection and history sections report not_run, and the error's own
// verdict drives stop_reason. It never fabricates a binding or drain
// state.
func SummarizeNotRun(err error, durationMS int64) RunSummary {
	summary := SummarizeRun(Result{BindStatus: BindNotAttempted}, err, nil, durationMS)
	summary.Collection.Drain.Stop = collection.DrainStopNotRun
	if summary.StopReason == collection.StopComplete {
		// A nil-error not-run is the ambiguous partial verdict, never a
		// fabricated success.
		summary.StopReason = collection.StopPartial
	}
	return summary
}

// normalizeBindStatus maps an unset binding status to the honest
// "unknown" instead of forwarding an empty string.
func normalizeBindStatus(status BindStatus) BindStatus {
	switch status {
	case BindNotAttempted, BindFailed, BindBound, BindSkipped:
		return status
	default:
		return BindUnknownSummary
	}
}

// BindUnknownSummary is the summary-only binding fallback for a Result
// that never recorded how far binding got.
const BindUnknownSummary BindStatus = "unknown"

// SyncStopReason composes one Sync orchestration's verdict from the
// closed sets — the same classification SummarizeRun applies to a
// connect run. Sentinel classification comes first (busy, budget,
// cancellation, retry exhaustion) and a hard error ALWAYS stays fatal:
// only the honest incompleteness envelope (errors.Is(err,
// ErrSyncIncomplete)) may be refined from the structured sync state —
// the run-wide budget stop, an authorization drift, a pause, or an
// authorized source this device could not cover (partial). A nil error
// is complete except for the defensive uncovered-source check
// (evaluateIncomplete turns uncovered work into ErrSyncIncomplete, so a
// real nil-error run has none). Exported so the resync CLI's human
// rendering reuses exactly this verdict instead of inventing one.
func SyncStopReason(sync SyncResult, err, ctxErr error) collection.StopReason {
	reason, classified := collection.ClassifyRunError(err, ctxErr)
	if !classified {
		if collection.PendingCoverageConcerns(sync.Collection.GrantSync.Pending) > 0 ||
			collection.PendingCoverageConcerns(sync.Backlog.Result.GrantSync.Pending) > 0 {
			return collection.StopPartial
		}
		return collection.StopComplete
	}
	if reason != collection.StopFatalError {
		return reason
	}
	if !errors.Is(err, ErrSyncIncomplete) {
		// A hard phase error is a hard failure: never downgraded by the
		// structural refinements below.
		return collection.StopFatalError
	}
	switch {
	case sync.BudgetExhausted:
		return collection.StopBudgetExhausted
	case historyScopeUnconfirmed(sync), historyScopeMoved(sync), cursorFence(sync):
		return collection.StopScopeChanged
	case sync.Collection.GrantSync.Paused,
		sync.Resync.Stop == ResyncStopPaused,
		sync.Collection.Cursor.Outcome == cursorsync.RoundPaused,
		sync.Backlog.Result.Cursor.Outcome == cursorsync.RoundPaused:
		return collection.StopPaused
	case collection.PendingCoverageConcerns(sync.Collection.GrantSync.Pending) > 0,
		collection.PendingCoverageConcerns(sync.Backlog.Result.GrantSync.Pending) > 0,
		accountRoundDidNotRun(sync):
		// An authorized source this device could not cover — including an
		// account source whose local enable did not complete — is not a
		// failure, but never a claimed completion. Reporting it as fatal
		// used to turn a known, named reason into "an unexpected error
		// occurred", which is indistinguishable from a real crash.
		return collection.StopPartial
	default:
		return collection.StopFatalError
	}
}

// connectStopReason is SyncStopReason over the connect run's sync
// state; connect.Run's own Result carries nothing the verdict reads
// beyond it.
// accountRoundDidNotRun reports an authorized account source that never ran on
// this device (no permit, or the grant withheld it). Only that is the "source
// not covered" case, which is partial. A round that RAN and errored stays a
// hard failure, matching how `toktrail periodic` classifies the same state: a
// real pull failure must not be downgraded to "incomplete" because the command
// happened to be `connect`.
func accountRoundDidNotRun(sync SyncResult) bool {
	if !sync.accountIncomplete {
		return false
	}
	switch sync.Collection.Cursor.Outcome {
	case cursorsync.RoundNoPermit, cursorsync.RoundAuthWithheld:
		return true
	}
	return false
}

func connectStopReason(res Result, err, ctxErr error) collection.StopReason {
	return SyncStopReason(res.Sync, err, ctxErr)
}

// historyScopeUnconfirmed reports the history phase that ran without
// confirming the live consent scope (the structural facts behind
// evaluateIncomplete's unconfirmed-revision reason).
func historyScopeUnconfirmed(sync SyncResult) bool {
	r := sync.Resync
	return r.Ran && r.ConsentRevision <= 0 && sync.Collection.GrantSync.Active
}

// historyScopeMoved reports a consent revision that moved between the
// initial collection and the history phase or the backlog drain.
func historyScopeMoved(sync SyncResult) bool {
	collected := sync.Collection.GrantSync.ConsentRevision
	if !sync.Collection.GrantSync.Active || !sync.Resync.Ran {
		return false
	}
	if sync.Resync.ConsentRevision > 0 && sync.Resync.ConsentRevision != collected {
		return true
	}
	if sync.Backlog.Passes > 0 && sync.Backlog.Result.GrantSync.ConsentRevision != collected {
		return true
	}
	return false
}

// cursorFence reports an authorization-boundary drift recorded on
// either collection round's account source.
func cursorFence(sync SyncResult) bool {
	return sync.Collection.Cursor.Outcome == cursorsync.RoundFenceStop ||
		sync.Backlog.Result.Cursor.Outcome == cursorsync.RoundFenceStop
}

// mergedCollection folds the initial collection round and the backlog
// passes into one representative Result: counters add up, state-like
// fields (pending counts, stop codes, grant view) reflect the latest
// pass, and the account-source outcome merges conservatively (an error
// or fence stop is never erased by a later clean pass).
func mergedCollection(sync SyncResult) collection.Result {
	merged := sync.Collection
	backlog := sync.Backlog
	if backlog.Passes == 0 {
		return merged
	}
	pass := backlog.Result
	merged.ExportedBatches += pass.ExportedBatches
	merged.ExportedRecords += pass.ExportedRecords
	merged.SyncedBatches += pass.SyncedBatches
	merged.SyncedRecords += pass.SyncedRecords
	merged.AttemptedBatches += pass.AttemptedBatches
	merged.RejectedBatches += pass.RejectedBatches
	merged.RejectedRecords += pass.RejectedRecords
	merged.Recovered += pass.Recovered
	merged.Quarantined = pass.Quarantined
	merged.PendingRemaining = backlog.PendingRemaining
	merged.PendingCounted = pass.PendingCounted
	merged.DrainStop = pass.DrainStop
	merged.GrantOutcomes = append(merged.GrantOutcomes, pass.GrantOutcomes...)
	merged.GrantSync = pass.GrantSync

	merged.Cursor.PulledEvents += pass.Cursor.PulledEvents
	merged.Cursor.NewRecords += pass.Cursor.NewRecords
	merged.Cursor.ReplacedRecords += pass.Cursor.ReplacedRecords
	merged.Cursor.ReemittedRecords += pass.Cursor.ReemittedRecords
	merged.Cursor.SkippedUnchanged += pass.Cursor.SkippedUnchanged
	merged.Cursor.SkippedNoStableID += pass.Cursor.SkippedNoStableID
	merged.Cursor.ExportedBatches += pass.Cursor.ExportedBatches
	merged.Cursor.SyncedBatches += pass.Cursor.SyncedBatches
	merged.Cursor.SyncedRecords += pass.Cursor.SyncedRecords
	merged.Cursor.Ran = merged.Cursor.Ran || pass.Cursor.Ran
	merged.Cursor.PendingRemaining = backlog.CursorPendingRemaining
	merged.Cursor.PendingCounted = pass.Cursor.PendingCounted
	merged.Cursor.Outcome = mergeCursorOutcomeSummary(merged.Cursor.Outcome, pass.Cursor.Outcome)
	return merged
}

// mergeCursorOutcomeSummary keeps the conservative merge
// collection.rotateQueues applies: an error or a fence stop sticks, a
// pause sticks with pending work, and otherwise the latest outcome
// wins.
func mergeCursorOutcomeSummary(prev, next cursorsync.RoundOutcome) cursorsync.RoundOutcome {
	switch {
	case prev == cursorsync.RoundError || next == cursorsync.RoundError:
		return cursorsync.RoundError
	case prev == cursorsync.RoundFenceStop || next == cursorsync.RoundFenceStop:
		return cursorsync.RoundFenceStop
	case next == cursorsync.RoundAbsent:
		return prev
	default:
		return next
	}
}

// knownResyncStopCodes is the closed set of history stop codes a
// ResyncSummary can carry; anything else falls back to the honest
// summary-only "unknown" instead of forwarding an unvetted string.
var knownResyncStopCodes = map[ResyncStopCode]bool{
	ResyncStopCompleted:       true,
	ResyncStopBusy:            true,
	ResyncStopPaused:          true,
	ResyncStopBudget:          true,
	ResyncStopNothingEligible: true,
	ResyncStopFailed:          true,
	ResyncStopStopped:         true,
}

// summarizeHistory maps the retransmission summary onto the stable
// history block, deriving the summary-only not_run/unknown codes and
// validating the recorded code against the closed set.
func summarizeHistory(r ResyncSummary) HistorySummary {
	stop := r.Stop
	switch {
	case knownResyncStopCodes[stop]:
	case !r.Ran:
		stop = ResyncStopNotRun
	default:
		stop = ResyncStopUnknown
	}
	return HistorySummary{
		Ran:              r.Ran,
		DryRun:           r.DryRun,
		Completed:        r.Completed,
		Uploads:          r.Uploads,
		UploadedRecords:  r.UploadedRecords,
		AcceptedRecords:  r.AcceptedRecords,
		RejectedRecords:  r.RejectedRecords,
		Remaining:        r.Remaining,
		Stop:             stop,
		ConsentConfirmed: r.ConsentRevision > 0,
	}
}

// incompleteCodes derives the closed low-cardinality mirror of
// SyncResult.Incomplete from structure only. The codes are a fixed
// vocabulary; free-text reasons stay on the human path.
//
// The account-source verdict codes (no permit, authorization withheld,
// first sync still pending) key on the structural twin markers
// evaluateIncomplete sets at the exact reason-production points
// (accountIncomplete for the accountTools loop, firstSyncIncomplete
// for the CursorFirstSyncFailed reason) plus the cursor round outcome.
// The markers are what separate an owed verdict from a clean steady
// state: those cursor outcomes are two-sided, and a run made
// incomplete by OTHER reasons (budget, history) over an account round
// that produced no account reason must never report an account code.
// A recorded reason with no closed mapping degrades to the
// unmapped_incomplete fallback, so an incomplete run never carries an
// empty machine explanation.
func incompleteCodes(sync SyncResult) []string {
	codes := make([]string, 0, 8)
	seen := map[string]bool{}
	add := func(code string) {
		if !seen[code] {
			seen[code] = true
			codes = append(codes, code)
		}
	}

	for _, outcomes := range [][]collection.GrantOutcome{sync.Collection.GrantOutcomes, sync.Backlog.Result.GrantOutcomes} {
		for _, o := range outcomes {
			switch {
			case o.Fault():
				add("source_failed")
			case o.Code == collection.GrantNotAllowed:
				add("source_not_allowed")
			default:
				// Healthy (exported / no new records), an unclassified
				// zero code, or a future closed-set value: never a
				// fabricated failure code.
			}
		}
	}

	final := sync.Collection
	if sync.Backlog.Passes > 0 {
		final = sync.Backlog.Result
	}
	if final.GrantSync.Paused {
		add("paused")
	}
	if collection.PendingCoverageConcerns(sync.Collection.GrantSync.Pending) > 0 ||
		collection.PendingCoverageConcerns(sync.Backlog.Result.GrantSync.Pending) > 0 {
		add("source_uncovered")
	}
	if final.PendingRemaining > 0 || final.Cursor.PendingRemaining > 0 {
		add("pending_batches")
	}
	switch final.DrainStop {
	case collection.DrainStopPaused:
		add("drain_paused")
	case collection.DrainStopScope:
		add("drain_scope_changed")
	case collection.DrainStopFailed:
		add("drain_failed")
	case collection.DrainStopBounded:
		add("drain_bounded")
	case collection.DrainStopBudget:
		add("budget_exhausted")
	}
	if sync.BudgetExhausted {
		add("budget_exhausted")
	}

	cursorOutcome := sync.Collection.Cursor.Outcome
	if sync.Backlog.Passes > 0 {
		cursorOutcome = mergeCursorOutcomeSummary(cursorOutcome, sync.Backlog.Result.Cursor.Outcome)
	}
	switch cursorOutcome {
	case cursorsync.RoundError:
		add("account_error")
	case cursorsync.RoundFenceStop:
		add("account_scope_changed")
	case cursorsync.RoundPaused:
		add("account_paused")
	case cursorsync.RoundBounded:
		add("account_bounded")
	case cursorsync.RoundNoPermit:
		// No local permit exists, so the account round never ran: the
		// first-time enable was declined (or failed before any permit
		// existed) under an authorization that names the source. The
		// outcome alone cannot say whether the source was owed — a
		// never-enabled device under an authorization that does not
		// name it holds the same outcome as its clean steady state —
		// so the code keys on the marker evaluateIncomplete set when
		// the account reason was actually appended.
		if sync.accountIncomplete {
			add("account_no_permit")
		}
	case cursorsync.RoundAuthWithheld:
		// A permit exists but the current authorization withholds
		// collection before any work ran (a non-collectable permit
		// state, a grant scope that excludes the source, a revoked or
		// reassigned device). Keyed exactly like the no-permit
		// verdict: an owed withholding is an incompleteness; the same
		// verdict on a run that produced no account reason is an
		// authorization verdict, not a failure.
		if sync.accountIncomplete {
			add("account_auth_withheld")
		}
	}
	// A first-time enable whose first sync did not complete inside
	// this run's setup: the marker is set exactly when the
	// CursorFirstSyncFailed reason was appended, so a leftover
	// pending_first_sync permit from an earlier run — an unrelated
	// steady state another phase's failure made the run incomplete
	// over — never reads as this run's first-sync failure.
	if sync.firstSyncIncomplete {
		add("account_pending_first_sync")
	}
	// Dropped events sum across rounds, mirroring the incompleteness
	// evaluation.
	if skipped := sync.Collection.Cursor.SkippedNoStableID + sync.Backlog.Result.Cursor.SkippedNoStableID; skipped > 0 {
		add("account_skipped_unstable_id")
	}

	r := sync.Resync
	switch r.Stop {
	case ResyncStopBusy:
		add("history_busy")
	case ResyncStopPaused:
		add("history_paused")
	case ResyncStopBudget:
		add("history_budget_exhausted")
	case ResyncStopStopped:
		add("history_stopped")
	case ResyncStopFailed:
		add("history_failed")
	}
	if r.Ran && r.Remaining > 0 {
		add("history_remaining")
	}
	if r.Ran && !r.Completed && r.Stopped != "" && r.Stop == "" {
		add("history_stopped")
	}

	if historyScopeUnconfirmed(sync) {
		add("scope_unconfirmed")
	}
	if historyScopeMoved(sync) {
		add("scope_moved")
	}
	if len(sync.Incomplete) > 0 && len(codes) == 0 {
		// evaluateIncomplete recorded a reason the closed vocabulary
		// above does not map (a reason shape added since this mirror
		// was written): the honest fallback, never silence — an
		// incomplete run must always carry at least one code, and the
		// reason's free text never enters the machine JSON. Only the
		// reason COUNT is read here, never the strings.
		add("unmapped_incomplete")
	}
	return codes
}
