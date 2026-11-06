package connect

// Tests for the connect command's stable §6.5 summary contract: the
// single StopReason verdict (sentinels plus structured refinement,
// never text), the closed IncompleteCodes mirror, the backlog merge,
// and the JSON redaction guarantees.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/local/cursorsource"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/syncbudget"
)

func TestSummarizeRunVerdicts(t *testing.T) {
	cases := []struct {
		name string
		res  Result
		err  error
		want collection.StopReason
	}{
		{
			name: "complete run",
			res: Result{
				BindStatus: BindBound,
				Sync: SyncResult{
					Collection: collection.Result{
						GrantSync: collection.GrantSync{Active: true, Acked: true},
						Cursor:    cursorsync.Result{Ran: true, Outcome: cursorsync.RoundRan},
					},
					Resync: ResyncSummary{Ran: true, Completed: true, Stop: ResyncStopCompleted, ConsentRevision: 7},
				},
			},
			want: collection.StopComplete,
		},
		{
			name: "budget exhausted refinement",
			res: Result{
				BindStatus: BindBound,
				Sync: SyncResult{
					BudgetExhausted: true,
					Collection: collection.Result{
						GrantSync: collection.GrantSync{Active: true},
					},
				},
			},
			err:  fmt.Errorf("%w: pending batches remain", ErrSyncIncomplete),
			want: collection.StopBudgetExhausted,
		},
		{
			name: "budget sentinel wins directly",
			res:  Result{BindStatus: BindBound},
			err:  fmt.Errorf("initial collection stopped: %w", syncbudget.ErrTotalExhausted),
			want: collection.StopBudgetExhausted,
		},
		{
			name: "scope unconfirmed",
			res: Result{
				BindStatus: BindBound,
				Sync: SyncResult{
					Collection: collection.Result{
						GrantSync: collection.GrantSync{Active: true, ConsentRevision: 7},
					},
					Resync: ResyncSummary{Ran: true, Completed: true, ConsentRevision: 0},
				},
			},
			err:  fmt.Errorf("%w: could not confirm the live consent scope", ErrSyncIncomplete),
			want: collection.StopScopeChanged,
		},
		{
			name: "scope moved between phases",
			res: Result{
				BindStatus: BindBound,
				Sync: SyncResult{
					Collection: collection.Result{
						GrantSync: collection.GrantSync{Active: true, ConsentRevision: 7},
					},
					Resync: ResyncSummary{Ran: true, Completed: true, ConsentRevision: 9},
				},
			},
			err:  fmt.Errorf("%w: the consent scope moved", ErrSyncIncomplete),
			want: collection.StopScopeChanged,
		},
		{
			name: "cursor fence stop",
			res: Result{
				BindStatus: BindBound,
				Sync: SyncResult{
					Collection: collection.Result{
						GrantSync: collection.GrantSync{Active: true},
						Cursor:    cursorsync.Result{Ran: true, Outcome: cursorsync.RoundFenceStop},
					},
				},
			},
			err:  fmt.Errorf("%w: the account source stopped at an authorization boundary", ErrSyncIncomplete),
			want: collection.StopScopeChanged,
		},
		{
			name: "paused device",
			res: Result{
				BindStatus: BindBound,
				Sync: SyncResult{
					Collection: collection.Result{
						GrantSync: collection.GrantSync{Paused: true, Active: true},
					},
				},
			},
			err:  fmt.Errorf("%w: collection paused by the server", ErrSyncIncomplete),
			want: collection.StopPaused,
		},
		{
			name: "busy before any work",
			res:  Result{BindStatus: BindNotAttempted},
			err:  fmt.Errorf("periodic: %w", runlock.ErrBusy),
			want: collection.StopBusy,
		},
		{
			name: "bind failure",
			res: Result{
				BindStatus: BindFailed,
			},
			err:  errors.New("device bind failed: ticket rejected"),
			want: collection.StopFatalError,
		},
		{
			name: "generic incompleteness stays fatal",
			res: Result{
				BindStatus: BindBound,
				Sync: SyncResult{
					Collection: collection.Result{
						GrantSync: collection.GrantSync{Active: true},
						Cursor:    cursorsync.Result{Ran: true, Outcome: cursorsync.RoundError},
					},
				},
			},
			err:  fmt.Errorf("%w: the account source failed", ErrSyncIncomplete),
			want: collection.StopFatalError,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SummarizeRun(tc.res, tc.err, nil, 42)
			if got.StopReason != tc.want {
				t.Fatalf("SummarizeRun stopReason = %q, want %q", got.StopReason, tc.want)
			}
			if got.Schema != collection.ResultSchema || got.Command != "connect" {
				t.Fatalf("unexpected envelope: %+v", got)
			}
		})
	}
}

// TestSummarizeRunEarlyExitNeverFabricates pins the early-exit shape:
// a run that failed before binding reports not_attempted phases —
// binding not attempted, history not run — and the error's own verdict,
// never a fabricated bound/ran state.
func TestSummarizeRunEarlyExitNeverFabricates(t *testing.T) {
	got := SummarizeRun(Result{BindStatus: BindNotAttempted}, errors.New("connect config fetch failed"), nil, 5)
	if got.Binding.Status != BindNotAttempted {
		t.Fatalf("binding status = %q, want not_attempted", got.Binding.Status)
	}
	if got.History.Stop != ResyncStopNotRun || got.History.Ran {
		t.Fatalf("history must report not_run, got %+v", got.History)
	}
	if got.Scheduler.Installed {
		t.Fatalf("scheduler must not claim an installation")
	}
	if got.StopReason != collection.StopFatalError {
		t.Fatalf("stopReason = %q, want fatal_error", got.StopReason)
	}
	if got.Binding.Status == "" || got.History.Stop == "" {
		t.Fatalf("no empty enum values may leak: %+v", got)
	}
}

// TestSummarizeRunMergesBacklog pins the collection-section merge: the
// initial round's and the backlog passes' counters add up, the pending
// counts and stop codes reflect the latest pass, and a cursor error is
// never erased by a later clean pass.
func TestSummarizeRunMergesBacklog(t *testing.T) {
	res := Result{
		BindStatus: BindBound,
		Sync: SyncResult{
			Collection: collection.Result{
				SyncedBatches:    2,
				SyncedRecords:    20,
				PendingRemaining: 5,
				PendingCounted:   true,
				DrainStop:        collection.DrainStopBounded,
				Cursor:           cursorsync.Result{Outcome: cursorsync.RoundError, SyncedBatches: 1},
			},
			Backlog: BacklogSummary{
				Passes:                 3,
				PendingRemaining:       1,
				CursorPendingRemaining: 2,
				Result: collection.Result{
					SyncedBatches:  4,
					SyncedRecords:  40,
					PendingCounted: true,
					DrainStop:      collection.DrainStopPaused,
					Cursor:         cursorsync.Result{Outcome: cursorsync.RoundRan, SyncedBatches: 2, PendingRemaining: 2, PendingCounted: true},
				},
			},
		},
	}
	got := SummarizeRun(res, fmt.Errorf("%w: paused", ErrSyncIncomplete), nil, 1)
	if got.Collection.Drain.SyncedBatches != 6 || got.Collection.Drain.SyncedRecords != 60 {
		t.Fatalf("backlog totals must add up: %+v", got.Collection.Drain)
	}
	if got.Collection.Drain.PendingRemaining != 1 {
		t.Fatalf("the latest pass's pending count must win: %+v", got.Collection.Drain)
	}
	if got.Collection.Drain.Stop != collection.DrainStopPaused {
		t.Fatalf("the latest pass's stop code must win: %+v", got.Collection.Drain)
	}
	if got.Collection.Drain.Account.PendingRemaining != 2 {
		t.Fatalf("the backlog's cursor pending count must win: %+v", got.Collection.Drain.Account)
	}
	if got.Collection.Drain.Account.Outcome != cursorsync.RoundError {
		t.Fatalf("a cursor error must survive a later clean pass: %+v", got.Collection.Drain.Account)
	}
}

// TestSummarizeRunRedaction pins the JSON surface: a result stuffed
// with identifiers, paths, URLs and free text marshals to none of them,
// and the key set is exactly the schema-1 connect shape.
func TestSummarizeRunRedaction(t *testing.T) {
	res := Result{
		DeviceID:         "dev-secret-1234",
		ServerURL:        "https://server.example/api",
		ApplicationID:    "leaderboard-local",
		SubjectID:        "subject-secret-5678",
		InstalledService: "com.toktrail.user-secret-task",
		BindStatus:       BindBound,
		Sync: SyncResult{
			Collection: collection.Result{
				GrantSync: collection.GrantSync{
					// Inactive: the redaction fixture pins the fatal
					// verdict path, not the scope refinements.
					Active:       false,
					AllowedTools: []string{"Claude Code", "Server-Invented Tool"},
					Pending:      map[string]string{"Codex": "pending because https://evil.example/x"},
				},
				GrantOutcomes: []collection.GrantOutcome{
					{Source: "codex-jsonl", Input: "/Users/secret/codex", BatchID: "local-secret-batch", Code: collection.GrantExported, Exported: true},
					{Source: "bogus-source", Input: "/Users/secret/other", Skipped: "export preparation failed: /Users/secret/other boom", Code: collection.GrantExportFailed},
				},
				Cursor:           cursorsync.Result{Ran: true, Skipped: "failed: Get \"https://cursor.example\": 503", Outcome: cursorsync.RoundError},
				PendingRemaining: 2,
				DrainStopped:     "upload of batch local-secret-batch failed: 500",
				DrainStop:        collection.DrainStopFailed,
			},
			Resync: ResyncSummary{
				Ran:     true,
				JobID:   "job-secret-9012",
				Err:     "history failed: https://server.example boom",
				Stopped: "stopped at https://server.example",
				Stop:    ResyncStopFailed,
			},
			BudgetExhausted: false,
			Incomplete:      []string{"source codex-jsonl (/Users/secret/codex) did not complete: export preparation failed: https://evil.example"},
		},
	}
	got := SummarizeRun(res, errors.New("history retransmission failed: boom"), nil, 77)
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, fragment := range []string{
		"dev-secret-1234",
		"server.example",
		"subject-secret-5678",
		"leaderboard-local",
		"user-secret-task",
		"/Users/secret",
		"local-secret-batch",
		"job-secret-9012",
		"https://",
		"evil.example",
		"cursor.example",
		"Server-Invented Tool",
		"bogus-source",
		"export preparation failed",
		"upload of batch",
		"did not complete",
	} {
		if strings.Contains(s, fragment) {
			t.Fatalf("connect summary JSON must not contain %q: %s", fragment, s)
		}
	}
	if !strings.Contains(s, `"bound"`) || !strings.Contains(s, `"codex-jsonl"`) {
		t.Fatalf("registry-known values must survive: %s", s)
	}
	if !strings.Contains(s, `"installed":true`) {
		t.Fatalf("the installation fact must survive: %s", s)
	}

	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	assertConnectKeySet(t, decoded, []string{"schema", "command", "stop_reason", "durationMs", "binding", "scheduler", "collection", "history", "incompleteCodes"})
	assertConnectKeySet(t, decoded["binding"].(map[string]any), []string{"status", "consentRevision"})
	assertConnectKeySet(t, decoded["scheduler"].(map[string]any), []string{"installed"})
	assertConnectKeySet(t, decoded["history"].(map[string]any), []string{"ran", "dryRun", "completed", "uploads", "uploadedRecords", "acceptedRecords", "rejectedRecords", "remaining", "stop", "consentConfirmed"})
	if decoded["stop_reason"] != string(collection.StopFatalError) {
		t.Fatalf("the hard error must drive the verdict: %s", s)
	}
	for _, code := range got.IncompleteCodes {
		switch code {
		case "source_failed", "source_uncovered", "pending_batches", "drain_failed", "account_error", "history_failed":
		default:
			t.Fatalf("incomplete codes must stay in the closed vocabulary, got %q (%v)", code, got.IncompleteCodes)
		}
	}
}

// TestSummarizeRunIncompleteCodes pins the closed-code mirror of the
// incompleteness evaluation for a mixed stopped run.
func TestSummarizeRunIncompleteCodes(t *testing.T) {
	res := Result{
		BindStatus: BindBound,
		Sync: SyncResult{
			BudgetExhausted: true,
			Collection: collection.Result{
				GrantSync:        collection.GrantSync{Active: true, ConsentRevision: 7},
				PendingRemaining: 3,
				DrainStop:        collection.DrainStopBudget,
				Cursor:           cursorsync.Result{Outcome: cursorsync.RoundPaused, PendingRemaining: 1, SkippedNoStableID: 2},
				GrantOutcomes: []collection.GrantOutcome{
					{Source: "codex-jsonl", Code: collection.GrantNoNewRecords},
					{Source: "claude-code-jsonl", Code: collection.GrantInputInaccessible},
					{Source: "qwen-jsonl", Code: collection.GrantNotAllowed},
				},
			},
			Backlog: BacklogSummary{
				Passes:                 2,
				PendingRemaining:       1,
				CursorPendingRemaining: 1,
				Result: collection.Result{
					GrantSync: collection.GrantSync{Active: true, ConsentRevision: 7},
					DrainStop: collection.DrainStopBudget,
					Cursor:    cursorsync.Result{Outcome: cursorsync.RoundPaused, PendingRemaining: 1},
				},
			},
			Resync: ResyncSummary{Ran: true, Remaining: 4, Stop: ResyncStopBudget, ConsentRevision: 7},
		},
	}
	got := SummarizeRun(res, fmt.Errorf("%w: budget", ErrSyncIncomplete), nil, 9)
	want := []string{
		"source_failed",
		"source_not_allowed",
		"pending_batches",
		"budget_exhausted",
		"account_paused",
		"account_skipped_unstable_id",
		"history_budget_exhausted",
		"history_remaining",
	}
	if strings.Join(got.IncompleteCodes, ",") != strings.Join(want, ",") {
		t.Fatalf("incompleteCodes = %v, want %v", got.IncompleteCodes, want)
	}
	if got.StopReason != collection.StopBudgetExhausted {
		t.Fatalf("stopReason = %q, want budget_exhausted", got.StopReason)
	}
	if !got.History.ConsentConfirmed {
		t.Fatalf("a confirmed history revision must be reported: %+v", got.History)
	}
}

func assertConnectKeySet(t *testing.T, m map[string]any, want []string) {
	t.Helper()
	if len(m) != len(want) {
		t.Fatalf("key set mismatch: have %v, want %v", m, want)
	}
	for _, key := range want {
		if _, ok := m[key]; !ok {
			t.Fatalf("missing key %q in %v", key, m)
		}
	}
}

// TestSummarizeHistoryClosedSet pins the history stop validation: a
// recorded code outside the closed vocabulary falls back to the honest
// "unknown" instead of forwarding an unvetted string, and an unrun
// phase reports not_run.
func TestSummarizeHistoryClosedSet(t *testing.T) {
	foreign := summarizeHistory(ResyncSummary{Ran: true, Stop: ResyncStopCode("server_invented_code")})
	if foreign.Stop != ResyncStopUnknown {
		t.Fatalf("a foreign stop code must fall back to unknown, got %q", foreign.Stop)
	}
	notRun := summarizeHistory(ResyncSummary{})
	if notRun.Stop != ResyncStopNotRun {
		t.Fatalf("an unrun phase must report not_run, got %q", notRun.Stop)
	}
	known := summarizeHistory(ResyncSummary{Ran: true, Stop: ResyncStopBusy})
	if known.Stop != ResyncStopBusy {
		t.Fatalf("a known stop code must survive, got %q", known.Stop)
	}
}

// TestSummarizeNotRunNeverComplete pins F3 for connect: a not-run
// summary with a nil error never reads as complete.
func TestSummarizeNotRunNeverComplete(t *testing.T) {
	got := SummarizeNotRun(nil, 3)
	if got.StopReason != collection.StopPartial {
		t.Fatalf("SummarizeNotRun(nil) = %q, want partial", got.StopReason)
	}
	if got.Binding.Status != BindNotAttempted || got.Collection.Drain.Stop != collection.DrainStopNotRun {
		t.Fatalf("the not-run shape must stay honest: %+v", got)
	}
	if got2 := SummarizeNotRun(errors.New("wiring failed"), 3); got2.StopReason != collection.StopFatalError {
		t.Fatalf("an error keeps its verdict, got %q", got2.StopReason)
	}
}

// TestConnectStopReasonHardErrorNotDowngraded pins the review
// regression: a hard phase error keeps fatal_error even when the sync
// state carries uncovered-source concerns — only the ErrSyncIncomplete
// envelope may be refined to partial.
func TestConnectStopReasonHardErrorNotDowngraded(t *testing.T) {
	res := Result{
		BindStatus: BindBound,
		Sync: SyncResult{
			Collection: collection.Result{
				GrantSync: collection.GrantSync{
					Active: true,
					Pending: map[string]string{
						"Claude Code": "some future restriction format",
					},
				},
			},
		},
	}
	// A hard error (not the incompleteness envelope): fatal, always.
	hard := SummarizeRun(res, errors.New("history retransmission failed: boom"), nil, 1)
	if hard.StopReason != collection.StopFatalError {
		t.Fatalf("a hard error must stay fatal_error, got %q", hard.StopReason)
	}
	// The honest incompleteness envelope over the same state: partial.
	incomplete := SummarizeRun(res, fmt.Errorf("%w: uncovered sources", ErrSyncIncomplete), nil, 1)
	if incomplete.StopReason != collection.StopPartial {
		t.Fatalf("the incompleteness envelope with uncovered sources must be partial, got %q", incomplete.StopReason)
	}
	// A nil error over the same state never claims complete
	// (defensive: connect.Run turns uncovered work into the envelope).
	nilErr := SummarizeRun(res, nil, nil, 1)
	if nilErr.StopReason != collection.StopPartial {
		t.Fatalf("a nil error with uncovered sources must not claim complete, got %q", nilErr.StopReason)
	}
}

// TestConnectStopReasonNeverInstalledToolsComplete pins the
// missing-input reclassification on the connect verdict: an authorized
// tool whose default directory was never detected on this device is an
// observable pending state, not an uncovered source — the verdict may
// be complete (all executable local work done). An unclassifiable
// restriction still refuses completion.
func TestConnectStopReasonNeverInstalledToolsComplete(t *testing.T) {
	neverInstalled := Result{
		BindStatus: BindBound,
		Sync: SyncResult{
			Collection: collection.Result{
				GrantSync: collection.GrantSync{
					Active: true,
					Pending: map[string]string{
						"Claude Code": "default directory not found: /missing",
						"Codex":       "default directory not found: /also/missing",
					},
				},
			},
		},
	}
	if got := SummarizeRun(neverInstalled, nil, nil, 1); got.StopReason != collection.StopComplete {
		t.Fatalf("never-installed tools must not flip the verdict, got %q", got.StopReason)
	}
	// The observable fact survives in the phases: both tools are
	// counted as missing-input pending, never as covered or applied.
	phases := SummarizeRun(neverInstalled, nil, nil, 1)
	if phases.Collection.Scope.PendingMissingInput != 2 || phases.Collection.Scope.PendingTools != 2 {
		t.Fatalf("the pending missing-input facts must stay observable, got %+v", phases.Collection.Scope)
	}
}

// accountVerdictFixtures builds the account-source verdict shapes
// evaluateIncomplete flags but the outcome mirror previously dropped:
// a first-time enable the user declined (no permit exists, so the round
// ends RoundNoPermit), and a permit the live authorization withholds
// before any work ran (RoundAuthWithheld). Incomplete carries the
// free-text reasons Sync really records — the summary must count them,
// never forward them.
func accountVerdictFixtures() map[string]struct {
	res  Result
	want string
} {
	return map[string]struct {
		res  Result
		want string
	}{
		"declined first enable": {
			res: Result{
				BindStatus: BindBound,
				Sync: SyncResult{
					accountIncomplete: true,
					Collection: collection.Result{
						GrantSync: collection.GrantSync{
							Active:          true,
							ConsentRevision: 3,
							AllowedTools:    []string{"Cursor"},
						},
						Cursor: cursorsync.Result{
							Skipped: "no local cursor permit (run toktrail connect or toktrail cursor enable); ticket deadbeef at /Users/secret/state https://evil.example",
							Outcome: cursorsync.RoundNoPermit,
						},
					},
					Incomplete: []string{
						"account source Cursor did not run: no local cursor permit (run toktrail connect or toktrail cursor enable)",
					},
				},
			},
			want: "account_no_permit",
		},
		"authorization withheld the permit": {
			res: Result{
				BindStatus: BindBound,
				Sync: SyncResult{
					accountIncomplete: true,
					Collection: collection.Result{
						GrantSync: collection.GrantSync{
							Active:          true,
							ConsentRevision: 3,
							AllowedTools:    []string{"Cursor"},
						},
						Cursor: cursorsync.Result{
							Status:  cursorsource.StatusLoginExpired,
							Skipped: "permit paused: the Cursor desktop login expired; log into Cursor and re-confirm (credential at /Users/secret/.cursor) https://evil.example",
							Outcome: cursorsync.RoundAuthWithheld,
						},
					},
					Incomplete: []string{
						"account source Cursor did not run: permit paused: the Cursor desktop login expired; log into Cursor and re-confirm with toktrail cursor enable",
					},
				},
			},
			want: "account_auth_withheld",
		},
	}
}

// TestSummarizeRunAccountVerdictCodes pins the closed codes for the
// two account-source verdict classes evaluateIncomplete flags (an
// enable that did not complete, and a withheld permit) and the verdict
// they drive: an AUTHORIZED source this device could not cover is
// partial — incomplete, never a claimed completion and never a fatal
// error. Calling it fatal made a named, expected condition print
// "an unexpected error occurred", indistinguishable from a crash. The
// machine JSON still carries only the closed code, never the skip
// reason's paths, URLs or credentials.
func TestSummarizeRunAccountVerdictCodes(t *testing.T) {
	for name, tc := range accountVerdictFixtures() {
		t.Run(name, func(t *testing.T) {
			got := SummarizeRun(tc.res, fmt.Errorf("%w: the account source did not run", ErrSyncIncomplete), nil, 12)
			if got.StopReason != collection.StopPartial {
				t.Fatalf("stopReason = %q, want partial (an authorized source the device could not cover)", got.StopReason)
			}
			if strings.Join(got.IncompleteCodes, ",") != tc.want {
				t.Fatalf("incompleteCodes = %v, want exactly [%s]", got.IncompleteCodes, tc.want)
			}
			b, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			s := string(b)
			for _, fragment := range []string{
				"/Users/secret",
				"evil.example",
				"deadbeef",
				"no local cursor permit",
				"desktop login expired",
				"did not run",
			} {
				if strings.Contains(s, fragment) {
					t.Fatalf("the verdict code path must not leak %q into the machine JSON: %s", fragment, s)
				}
			}
			if !strings.Contains(s, `"incompleteCodes":["`+tc.want+`"]`) {
				t.Fatalf("the closed code must survive marshaling: %s", s)
			}
			var decoded map[string]any
			if err := json.Unmarshal(b, &decoded); err != nil {
				t.Fatal(err)
			}
			assertConnectKeySet(t, decoded, []string{"schema", "command", "stop_reason", "durationMs", "binding", "scheduler", "collection", "history", "incompleteCodes"})
		})
	}
}

// TestSummarizeRunFirstSyncPendingCode pins the first-sync class: the
// code keys on the firstSyncIncomplete marker evaluateIncomplete sets
// exactly when the CursorFirstSyncFailed reason was appended (this
// run's setup attempted the first-time enable and its first sync
// executed without completing). The permit's observed status alone
// never decides it: a leftover pending_first_sync permit from an
// earlier run is not this run's failure, and a first-sync failure
// co-reported with other phase failures keeps every code.
func TestSummarizeRunFirstSyncPendingCode(t *testing.T) {
	base := Result{
		BindStatus: BindBound,
		Sync: SyncResult{
			firstSyncIncomplete: true,
			Collection: collection.Result{
				GrantSync: collection.GrantSync{Active: true, ConsentRevision: 3},
				Cursor: cursorsync.Result{
					Ran:     true,
					Status:  cursorsource.StatusPendingFirstSync,
					Outcome: cursorsync.RoundRan,
					Skipped: "first sync failed: Get \"https://cursor.example/usage\": 503 (credential /Users/secret/.cursor)",
				},
			},
			Incomplete: []string{
				"account source Cursor did not complete its first sync in this run's setup: Get \"https://cursor.example/usage\": 503; the permit and its queue keep their state and the next run continues them",
			},
		},
	}
	got := SummarizeRun(base, fmt.Errorf("%w: the first sync did not complete", ErrSyncIncomplete), nil, 13)
	if got.StopReason != collection.StopFatalError {
		t.Fatalf("stopReason = %q, want fatal_error", got.StopReason)
	}
	if strings.Join(got.IncompleteCodes, ",") != "account_pending_first_sync" {
		t.Fatalf("incompleteCodes = %v, want exactly [account_pending_first_sync]", got.IncompleteCodes)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); strings.Contains(s, "cursor.example") || strings.Contains(s, "/Users/secret") || strings.Contains(s, "503") {
		t.Fatalf("the first-sync code path must not leak the failure detail into the machine JSON: %s", s)
	}

	// This run's setup never attempted a failed first sync (the permit
	// finished its first pull in an earlier run and only left batches
	// pending): the marker stays unset, so the pending code reports
	// alone — the first-sync code must not fire over a permit state
	// that is not this run's failure.
	completed := base
	completed.Sync.firstSyncIncomplete = false
	completed.Sync.Collection.Cursor = cursorsync.Result{
		Ran:                true,
		Status:             cursorsource.StatusActive,
		Outcome:            cursorsync.RoundRan,
		FirstSyncCompleted: true,
		PendingRemaining:   2,
		PendingCounted:     true,
	}
	completed.Sync.Incomplete = []string{"account source Cursor has 2 batch(es) still pending"}
	gotCompleted := SummarizeRun(completed, fmt.Errorf("%w: batches pending", ErrSyncIncomplete), nil, 13)
	if strings.Join(gotCompleted.IncompleteCodes, ",") != "pending_batches" {
		t.Fatalf("a finished first pull must not carry the first-sync code, got %v", gotCompleted.IncompleteCodes)
	}

	// The combined run: the first sync failed AND other phases fell
	// short (budget declined, history batches remain). Every class
	// keeps its own code — the first-sync code is never swallowed by
	// the other failures, and never swallows them.
	combined := base
	combined.Sync.BudgetExhausted = true
	combined.Sync.Collection.PendingRemaining = 1
	combined.Sync.Collection.DrainStop = collection.DrainStopBudget
	combined.Sync.Resync = ResyncSummary{Ran: true, Completed: false, Remaining: 3, Stop: ResyncStopStopped, ConsentRevision: 3}
	combined.Sync.Incomplete = []string{
		"account source Cursor did not complete its first sync in this run's setup: Get \"https://cursor.example/usage\": 503; the permit and its queue keep their state and the next run continues them",
		"1 outbox batch(es) and 0 cursor batch(es) are still pending; re-run connect, or let the scheduled collection continue them",
		"the run's shared sync POST budget declined further uploads before the authorization was fully covered",
		"3 history batch(es) remain un-retransmitted; re-run connect or toktrail resync --all to resume (the scheduled task does not continue a resync job)",
	}
	gotCombined := SummarizeRun(combined, fmt.Errorf("%w: first sync, budget and history", ErrSyncIncomplete), nil, 13)
	wantCombined := "pending_batches,budget_exhausted,account_pending_first_sync,history_stopped,history_remaining"
	if strings.Join(gotCombined.IncompleteCodes, ",") != wantCombined {
		t.Fatalf("combined failures must keep every class code, got %v, want [%s]", gotCombined.IncompleteCodes, wantCombined)
	}
	if gotCombined.StopReason != collection.StopBudgetExhausted {
		t.Fatalf("stopReason = %q, want budget_exhausted (exit semantics unchanged)", gotCombined.StopReason)
	}
}

// TestSummarizeRunAccountVerdictsCleanRunStaySilent pins the mirror's
// no-false-positive side: the very same cursor outcomes are the CLEAN
// steady state of a run whose authorization never owed the account
// source (a never-enabled device under an authorization that does not
// name it, a permit the live scope excludes, a leftover
// pending_first_sync permit nothing owes). With no recorded
// incompleteness reasons the summary stays silent — no code may dress a
// complete run as incomplete.
func TestSummarizeRunAccountVerdictsCleanRunStaySilent(t *testing.T) {
	grantView := collection.GrantSync{Active: true, ConsentRevision: 5, AllowedTools: []string{"Codex"}}
	cases := []struct {
		name   string
		cursor cursorsync.Result
	}{
		{
			name: "never enabled, authorization does not name the source",
			cursor: cursorsync.Result{
				Skipped: "no local cursor permit (run toktrail connect or toktrail cursor enable)",
				Outcome: cursorsync.RoundNoPermit,
			},
		},
		{
			name: "withheld permit the live scope excludes",
			cursor: cursorsync.Result{
				Status:  cursorsource.StatusLoginExpired,
				Skipped: "permit paused: the Cursor desktop login expired; log into Cursor and re-confirm with toktrail cursor enable",
				Outcome: cursorsync.RoundAuthWithheld,
			},
		},
		{
			name: "leftover pending_first_sync permit nothing owes",
			cursor: cursorsync.Result{
				Status:  cursorsource.StatusPendingFirstSync,
				Skipped: "cursor is not allowed by the effective server grant scope for this device",
				Outcome: cursorsync.RoundAuthWithheld,
			},
		},
		{
			name:   "healthy round",
			cursor: cursorsync.Result{Ran: true, Status: cursorsource.StatusActive, Outcome: cursorsync.RoundRan},
		},
		{
			name: "healthy drain-only round over the leftover permit",
			cursor: cursorsync.Result{
				Ran:     true,
				Status:  cursorsource.StatusPendingFirstSync,
				Outcome: cursorsync.RoundRan,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := Result{
				BindStatus: BindBound,
				Sync: SyncResult{
					Collection: collection.Result{
						GrantSync: grantView,
						Cursor:    tc.cursor,
					},
					// No recorded reasons: evaluateIncomplete judged the
					// run complete, so Sync returned a nil error.
					Incomplete: nil,
				},
			}
			got := SummarizeRun(res, nil, nil, 6)
			if got.StopReason != collection.StopComplete {
				t.Fatalf("stopReason = %q, want complete", got.StopReason)
			}
			if len(got.IncompleteCodes) != 0 {
				t.Fatalf("a complete run must carry no incomplete codes, got %v", got.IncompleteCodes)
			}
		})
	}
}

// TestSummarizeRunUnmappedReasonFallsBack pins the safety net: a
// recorded incompleteness reason the closed vocabulary does not map
// degrades to the honest unmapped_incomplete code — never to the empty
// list that once left --json reporting fatal_error with
// incompleteCodes=[]. A run whose reasons DO map keeps its mapped codes
// and never carries the fallback.
func TestSummarizeRunUnmappedReasonFallsBack(t *testing.T) {
	unmapped := Result{
		BindStatus: BindBound,
		Sync: SyncResult{
			Collection: collection.Result{
				GrantSync: collection.GrantSync{Active: true, ConsentRevision: 2},
			},
			// A reason shape outside today's mirror (for example the
			// no-enabled-grants verdict): structurally unmapped.
			Incomplete: []string{
				"no enabled source grants despite authorized tools; the device outbox was drained but no local source is scanning",
			},
		},
	}
	got := SummarizeRun(unmapped, fmt.Errorf("%w: no enabled source grants", ErrSyncIncomplete), nil, 4)
	if got.StopReason != collection.StopFatalError {
		t.Fatalf("stopReason = %q, want fatal_error", got.StopReason)
	}
	if strings.Join(got.IncompleteCodes, ",") != "unmapped_incomplete" {
		t.Fatalf("incompleteCodes = %v, want exactly [unmapped_incomplete]", got.IncompleteCodes)
	}

	mapped := Result{
		BindStatus: BindBound,
		Sync: SyncResult{
			BudgetExhausted: true,
			Collection: collection.Result{
				GrantSync:        collection.GrantSync{Active: true, ConsentRevision: 2},
				PendingRemaining: 1,
				DrainStop:        collection.DrainStopBudget,
			},
			Incomplete: []string{
				"1 outbox batch(es) and 0 cursor batch(es) are still pending; re-run connect, or let the scheduled collection continue them",
				"the run's shared sync POST budget declined further uploads before the authorization was fully covered",
			},
		},
	}
	gotMapped := SummarizeRun(mapped, fmt.Errorf("%w: budget", ErrSyncIncomplete), nil, 4)
	if strings.Join(gotMapped.IncompleteCodes, ",") != "pending_batches,budget_exhausted" {
		t.Fatalf("mapped reasons must keep their codes without the fallback, got %v", gotMapped.IncompleteCodes)
	}
}

// TestSummarizeRunAccountVerdictsNeverFabricate pins the attribution
// contract the outcome-alone mapping cannot hold: the account verdict
// codes may appear ONLY when evaluateIncomplete actually appended an
// account-source reason. A no-permit or withheld round that produced
// no account reason — the authorization never named the source, so
// the outcome is its clean steady state — must stay unreported even
// when OTHER reasons (budget, pending batches) make the run
// incomplete; a leftover pending_first_sync permit is likewise not
// this run's first-sync failure.
func TestSummarizeRunAccountVerdictsNeverFabricate(t *testing.T) {
	cases := []struct {
		name string
		res  Result
		want string
		stop collection.StopReason
	}{
		{
			name: "budget incomplete over an incidental no-permit round",
			res: Result{
				BindStatus: BindBound,
				Sync: SyncResult{
					BudgetExhausted: true,
					Collection: collection.Result{
						GrantSync:        collection.GrantSync{Active: true, ConsentRevision: 4, AllowedTools: []string{"Codex"}},
						PendingRemaining: 1,
						DrainStop:        collection.DrainStopBudget,
						Cursor: cursorsync.Result{
							Skipped: "no local cursor permit (run toktrail connect or toktrail cursor enable)",
							Outcome: cursorsync.RoundNoPermit,
						},
					},
					Incomplete: []string{
						"1 outbox batch(es) and 0 cursor batch(es) are still pending; re-run connect, or let the scheduled collection continue them",
						"the run's shared sync POST budget declined further uploads before the authorization was fully covered",
					},
				},
			},
			want: "pending_batches,budget_exhausted",
			stop: collection.StopBudgetExhausted,
		},
		{
			name: "history incomplete over an incidental no-permit round",
			res: Result{
				BindStatus: BindBound,
				Sync: SyncResult{
					Collection: collection.Result{
						GrantSync: collection.GrantSync{Active: true, ConsentRevision: 4, AllowedTools: []string{"Codex"}},
						Cursor: cursorsync.Result{
							Skipped: "no local cursor permit (run toktrail connect or toktrail cursor enable)",
							Outcome: cursorsync.RoundNoPermit,
						},
					},
					Resync:     ResyncSummary{Ran: true, Completed: false, Remaining: 3, Stop: ResyncStopStopped, ConsentRevision: 4},
					Incomplete: []string{"3 history batch(es) remain un-retransmitted; re-run connect or toktrail resync --all to resume (the scheduled task does not continue a resync job)"},
				},
			},
			want: "history_stopped,history_remaining",
			stop: collection.StopFatalError,
		},
		{
			name: "history incomplete over a leftover pending_first_sync permit",
			res: Result{
				BindStatus: BindBound,
				Sync: SyncResult{
					Collection: collection.Result{
						GrantSync: collection.GrantSync{Active: true, ConsentRevision: 4, AllowedTools: []string{"Codex"}},
						Cursor: cursorsync.Result{
							Ran:     true,
							Status:  cursorsource.StatusPendingFirstSync,
							Outcome: cursorsync.RoundRan,
						},
					},
					Resync:     ResyncSummary{Ran: true, Completed: false, Remaining: 3, Stop: ResyncStopStopped, ConsentRevision: 4},
					Incomplete: []string{"3 history batch(es) remain un-retransmitted; re-run connect or toktrail resync --all to resume (the scheduled task does not continue a resync job)"},
				},
			},
			want: "history_stopped,history_remaining",
			stop: collection.StopFatalError,
		},
		{
			name: "budget incomplete over a leftover pending_first_sync permit",
			res: Result{
				BindStatus: BindBound,
				Sync: SyncResult{
					BudgetExhausted: true,
					Collection: collection.Result{
						GrantSync:        collection.GrantSync{Active: true, ConsentRevision: 4, AllowedTools: []string{"Codex"}},
						PendingRemaining: 1,
						DrainStop:        collection.DrainStopBudget,
						Cursor: cursorsync.Result{
							Ran:     true,
							Status:  cursorsource.StatusPendingFirstSync,
							Outcome: cursorsync.RoundRan,
						},
					},
					Incomplete: []string{
						"1 outbox batch(es) and 0 cursor batch(es) are still pending; re-run connect, or let the scheduled collection continue them",
						"the run's shared sync POST budget declined further uploads before the authorization was fully covered",
					},
				},
			},
			want: "pending_batches,budget_exhausted",
			stop: collection.StopBudgetExhausted,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SummarizeRun(tc.res, fmt.Errorf("%w: incomplete", ErrSyncIncomplete), nil, 8)
			if got.StopReason != tc.stop {
				t.Fatalf("stopReason = %q, want %q", got.StopReason, tc.stop)
			}
			if strings.Join(got.IncompleteCodes, ",") != tc.want {
				t.Fatalf("incompleteCodes = %v, want [%s] (no fabricated account verdict code)", got.IncompleteCodes, tc.want)
			}
		})
	}
}

// A cursor round that RAN and failed (a pull error, a corrupt permit) is a hard
// failure, not "incomplete": `toktrail periodic` classifies the same state as
// fatal_error, and a monitoring rule keyed on stop_reason must not see a real
// fault as a soft gap. Only a round that never ran is partial.
func TestSummarizeFailedAccountRoundStaysFatal(t *testing.T) {
	res := Result{
		BindStatus: BindBound,
		Sync: SyncResult{
			accountIncomplete: true,
			Collection: collection.Result{
				Cursor: cursorsync.Result{
					Ran:     true,
					Outcome: cursorsync.RoundError,
					Skipped: "the Cursor usage query failed",
				},
			},
		},
	}
	got := SummarizeRun(res, fmt.Errorf("%w: account source Cursor failed", ErrSyncIncomplete), nil, 5)
	if got.StopReason != collection.StopFatalError {
		t.Fatalf("a failed account round must stay fatal, got %q", got.StopReason)
	}

	// The same marker with a round that never ran is the partial case.
	res.Sync.Collection.Cursor = cursorsync.Result{Outcome: cursorsync.RoundNoPermit, Skipped: "no local cursor permit"}
	got = SummarizeRun(res, fmt.Errorf("%w: account source Cursor did not run", ErrSyncIncomplete), nil, 5)
	if got.StopReason != collection.StopPartial {
		t.Fatalf("a round that never ran must be partial, got %q", got.StopReason)
	}
}
