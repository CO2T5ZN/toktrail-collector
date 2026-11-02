package collection

// Tests for the stable §6.5 summary contract: the closed StopReason
// classification (sentinels only, never text — including the
// client-timeout vs run-deadline distinction), the pending-observed
// guarantees (an uncounted queue never reads as empty), the partial
// verdicts (explicit partial modes, uncovered authorized sources,
// ambiguous not-runs), and the redaction guarantees of the JSON
// surface (canonical registry names only; no paths, ids, URLs,
// server-supplied spellings or free text).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/syncbudget"
	"toktrail-collector/internal/syncretry"
)

func TestClassifyRunErrorTable(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		ctxErr error
		want   StopReason
	}{
		{"busy", fmt.Errorf("periodic: %w", runlock.ErrBusy), nil, StopBusy},
		{"budget total", fmt.Errorf("stopped: %w", syncbudget.ErrTotalExhausted), nil, StopBudgetExhausted},
		{"budget deadline", fmt.Errorf("stopped: %w", syncbudget.ErrDeadlineExceeded), nil, StopBudgetExhausted},
		{"retry past deadline", fmt.Errorf("stopped: %w", syncretry.ErrRetryPastDeadline), nil, StopBudgetExhausted},
		{"run context deadline", errors.New("periodic incomplete: run timeout elapsed"), context.DeadlineExceeded, StopBudgetExhausted},
		{"client timeout without retries", fmt.Errorf("Get server: %w", context.DeadlineExceeded), nil, StopFatalError},
		{"retry exhausted", fmt.Errorf("upload: %w", syncretry.ErrRetryExhausted), nil, StopRetryExhausted},
		{"retry exhausted wrapping client timeout", fmt.Errorf("%w: last failure: %w", syncretry.ErrRetryExhausted, context.DeadlineExceeded), nil, StopRetryExhausted},
		{"cancelled", fmt.Errorf("stopped: %w", context.Canceled), nil, StopCancelled},
		{"hard failure", errors.New("device bind failed: boom"), nil, StopFatalError},
		{"rejected records", fmt.Errorf("%w: 3 records", ErrRecordsRejected), nil, StopFatalError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ClassifyRunError(tc.err, tc.ctxErr)
			if !ok {
				t.Fatalf("an error must classify, got ok=false")
			}
			if got != tc.want {
				t.Fatalf("ClassifyRunError = %q, want %q", got, tc.want)
			}
		})
	}
	if got, ok := ClassifyRunError(nil, nil); ok {
		t.Fatalf("a nil error must not classify, got %q", got)
	}
}

func TestSummarizeVerdicts(t *testing.T) {
	cases := []struct {
		name string
		res  Result
		err  error
		want StopReason
	}{
		{
			name: "complete",
			res: Result{
				GrantSync:        GrantSync{Active: true, Refreshed: true, Acked: true},
				Cursor:           cursorsync.Result{Ran: true, Outcome: cursorsync.RoundRan},
				SyncedBatches:    3,
				PendingRemaining: 0,
				PendingCounted:   true,
			},
			want: StopComplete,
		},
		{
			name: "complete with nothing owed for the account source",
			res: Result{
				Cursor:         cursorsync.Result{Outcome: cursorsync.RoundNoPermit},
				PendingCounted: true,
			},
			want: StopComplete,
		},
		{
			name: "paused device, nothing pending, keeps the historical exit zero",
			res: Result{
				GrantSync: GrantSync{Paused: true, Active: true},
				Skipped:   "server reports collection paused for this device (consent revision 9); no local reading or uploads this run",
			},
			want: StopPaused,
		},
		{
			name: "paused account round with pending batches",
			res: Result{
				Cursor:         cursorsync.Result{Ran: true, Outcome: cursorsync.RoundPaused, PendingRemaining: 2, PendingCounted: true},
				PendingCounted: true,
			},
			want: StopPaused,
		},
		{
			name: "paused account round with nothing pending",
			res: Result{
				Cursor:         cursorsync.Result{Ran: true, Outcome: cursorsync.RoundPaused},
				PendingCounted: true,
			},
			want: StopPaused,
		},
		{
			name: "cursor fence stop is a scope change",
			res: Result{
				Cursor:         cursorsync.Result{Ran: true, Outcome: cursorsync.RoundFenceStop},
				PendingCounted: true,
			},
			want: StopScopeChanged,
		},
		{
			name: "drain scope stop is a scope change",
			res: Result{
				DrainStop: DrainStopScope,
			},
			want: StopScopeChanged,
		},
		{
			name: "cursor round error",
			res: Result{
				Cursor: cursorsync.Result{Ran: true, Outcome: cursorsync.RoundError},
			},
			want: StopFatalError,
		},
		{
			name: "dropped events without a stable id",
			res: Result{
				Cursor: cursorsync.Result{Outcome: cursorsync.RoundRan, SkippedNoStableID: 4},
			},
			want: StopFatalError,
		},
		{
			name: "granted source input inaccessible is a fault",
			res: Result{
				GrantOutcomes: []GrantOutcome{{Source: "codex-jsonl", Code: GrantInputInaccessible}},
			},
			want: StopFatalError,
		},
		{
			name: "granted source export failed is a fault",
			res: Result{
				GrantOutcomes: []GrantOutcome{{Source: "codex-jsonl", Code: GrantExportFailed}},
			},
			want: StopFatalError,
		},
		{
			name: "granted source split failed is a fault",
			res: Result{
				GrantOutcomes: []GrantOutcome{{Source: "codex-jsonl", Code: GrantSplitFailed}},
			},
			want: StopFatalError,
		},
		{
			name: "server scope excluding a source is not a fault",
			res: Result{
				GrantOutcomes: []GrantOutcome{
					{Source: "codex-jsonl", Code: GrantNotAllowed},
					{Source: "claude-code-jsonl", Code: GrantNoNewRecords},
				},
				PendingCounted: true,
			},
			want: StopComplete,
		},
		{
			// A tool this device never installed is not executable work:
			// the never-detected default directory stays observable
			// (grant-ack pending, not_detected tool status, the summary's
			// pendingMissingInput counter) but never fails the round.
			name: "never-installed authorized tool is not a concern",
			res: Result{
				GrantSync: GrantSync{Pending: map[string]string{
					"Claude Code": "default directory not found: /Users/secret/missing",
				}},
				PendingCounted: true,
			},
			want: StopComplete,
		},
		{
			name: "unsupported and user-disabled pending tools are no concern",
			res: Result{
				GrantSync: GrantSync{Pending: map[string]string{
					"Kimi":        "unknown tool: Kimi",
					"Claude Code": "default-directory grant is manually disabled",
				}},
				PendingCounted: true,
			},
			want: StopComplete,
		},
		{
			name: "unmapped pending reason is conservatively uncovered",
			res: Result{
				GrantSync:      GrantSync{Pending: map[string]string{"Codex": "some future reason"}},
				PendingCounted: true,
			},
			want: StopPartial,
		},
		{
			name: "bounded device queue",
			res: Result{
				DrainStop:        DrainStopBounded,
				PendingRemaining: 2,
				PendingCounted:   true,
			},
			want: StopBounded,
		},
		{
			name: "bounded account queue",
			res: Result{
				Cursor: cursorsync.Result{Outcome: cursorsync.RoundBounded, PendingRemaining: 1, PendingCounted: true},
			},
			want: StopBounded,
		},
		{
			name: "budget decline error",
			res: Result{
				DrainStop:        DrainStopBudget,
				PendingRemaining: 1,
				PendingCounted:   true,
			},
			err:  fmt.Errorf("device batch b was stopped by the shared upload budget before its upload: %w", syncbudget.ErrTotalExhausted),
			want: StopBudgetExhausted,
		},
		{
			name: "recorded budget stop with a nil error (defensive)",
			res: Result{
				DrainStop:        DrainStopBudget,
				PendingRemaining: 1,
				PendingCounted:   true,
			},
			want: StopBudgetExhausted,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Summarize(tc.res, tc.err, nil, "periodic", 0)
			if got.StopReason != tc.want {
				t.Fatalf("Summarize stopReason = %q, want %q", got.StopReason, tc.want)
			}
			if got.Schema != ResultSchema || got.Command != "periodic" {
				t.Fatalf("unexpected envelope: %+v", got)
			}
		})
	}
}

// TestSummarizePartialMode pins the explicit partial mode (F5): a
// verdict that would read complete becomes partial, and every other
// classification (a budget stop here) stays identical.
func TestSummarizePartialMode(t *testing.T) {
	res := Result{
		PendingRemaining: 1,
		PendingCounted:   true,
		DrainStop:        DrainStopBudget,
	}
	if got := SummarizePartialMode(res, nil, nil, "periodic", 5); got.StopReason != StopBudgetExhausted {
		t.Fatalf("non-complete verdicts must pass through unchanged, got %q", got.StopReason)
	}
	clean := Result{PendingCounted: true}
	if got := SummarizePartialMode(clean, nil, nil, "periodic", 5); got.StopReason != StopPartial {
		t.Fatalf("a clean partial-mode run must report partial, got %q", got.StopReason)
	}
}

// TestSummarizeNotRunNeverComplete pins F3: a not-run summary with a
// nil error never reads as complete — it is the ambiguous partial
// verdict — while an error keeps its own classification.
func TestSummarizeNotRunNeverComplete(t *testing.T) {
	got := SummarizeNotRun(nil, "periodic", 1)
	if got.StopReason != StopPartial {
		t.Fatalf("SummarizeNotRun(nil) = %q, want partial", got.StopReason)
	}
	if got.Drain.Stop != DrainStopNotRun || got.Drain.PendingObserved {
		t.Fatalf("a not-run drain must report not_run and unobserved, got %+v", got.Drain)
	}
	if got2 := SummarizeNotRun(errors.New("wiring failed"), "periodic", 1); got2.StopReason != StopFatalError {
		t.Fatalf("an error keeps its verdict, got %q", got2.StopReason)
	}
}

// TestSummarizePhasesRedaction pins the JSON surface's redaction
// guarantees: the marshaled contract of a result deliberately stuffed
// with paths, batch ids, URLs, server-supplied tool-name spellings and
// free error text contains none of them — only closed enums, canonical
// registry names and counters — and its key set is exactly the
// schema-1 shape.
func TestSummarizePhasesRedaction(t *testing.T) {
	res := Result{
		GrantSync: GrantSync{
			Active: true,
			Acked:  true,
			// A server-supplied alias spelling, the canonical name, and
			// an invented tool: the alias must collapse onto the
			// canonical name, never appear verbatim.
			AllowedTools: []string{"claude code", "Claude Code", "Server-Invented Tool"},
			Pending: map[string]string{
				"Claude Code": "default directory not found: /Users/secret/missing",
				"Kimi":        "unknown tool: Kimi",
				"Qwen":        "default-directory grant is manually disabled",
				"Codex":       "reason with https://evil.example/path and /Users/secret",
			},
			Note: "note with https://evil.example and ticket deadbeefdeadbeef",
		},
		GrantOutcomes: []GrantOutcome{
			{
				Source:   "codex-jsonl",
				Input:    "/Users/secret/inputs/codex",
				Exported: true,
				BatchID:  "local-20261031T000000Z-00-cafecafe",
				Records:  42,
				Code:     GrantExported,
			},
			{
				Source:  "claude-code-jsonl",
				Input:   "/Users/secret/inputs/claude",
				Skipped: "export preparation failed: open /Users/secret/inputs/claude/x.jsonl: permission denied",
				Code:    GrantExportFailed,
			},
			{
				Source:  "not-a-registry-source",
				Input:   "/Users/secret/inputs/other",
				Skipped: "no new records since the last confirmed baselines",
				Code:    GrantNoNewRecords,
			},
		},
		Cursor: cursorsync.Result{
			Ran:     true,
			Skipped: "pull failed: Get \"https://cursor.example/api\": 503",
			Note:    "note https://cursor.example/api",
			Outcome: cursorsync.RoundError,
		},
		SyncedBatches:    1,
		SyncedRecords:    42,
		RejectedRecords:  3,
		PendingRemaining: 2,
		PendingCounted:   true,
		DrainStopped:     "upload of batch local-20261031T000000Z-00-cafecafe failed: 500 https://server.example",
		DrainStop:        DrainStopFailed,
		SyncedBatchIDs:   []string{"local-20261031T000000Z-00-cafecafe"},
	}

	summary := Summarize(res, nil, nil, "periodic", 1234)
	b, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)

	for _, fragment := range []string{
		"/Users/secret",
		"inputs/codex",
		"cafecafe",
		"local-20261031",
		"https://",
		"http://",
		"evil.example",
		"cursor.example",
		"server.example",
		"Server-Invented Tool",
		"not-a-registry-source",
		"deadbeef",
		"permission denied",
		"pull failed",
		"export preparation failed",
		"upload of batch",
		"reason with",
		"some future reason",
	} {
		if strings.Contains(got, fragment) {
			t.Fatalf("summary JSON must not contain %q: %s", fragment, got)
		}
	}

	// Registry-known CANONICAL names survive; the raw alias spelling is
	// dropped (the two server spellings collapse onto one entry).
	if !strings.Contains(got, `"allowedTools":["Claude Code"]`) {
		t.Fatalf("the alias spellings must collapse onto the canonical name: %s", got)
	}
	if strings.Contains(got, `"claude code"`) {
		t.Fatalf("the raw server spelling must never appear: %s", got)
	}
	if !strings.Contains(got, `"codex-jsonl"`) || !strings.Contains(got, `"claude-code-jsonl"`) {
		t.Fatalf("canonical source names must survive: %s", got)
	}
	// Unknown server/grant names are counted, never named.
	if !strings.Contains(got, `"unknownAllowedTools":1`) {
		t.Fatalf("the unknown server tool must be counted: %s", got)
	}
	if !strings.Contains(got, `"unknownSources":1`) {
		t.Fatalf("the unknown source must be counted: %s", got)
	}
	// Pending reasons classify onto the closed vocabulary: one
	// missing-input, one unsupported, one disabled, one unmapped.
	for _, want := range []string{
		`"pendingTools":4`,
		`"pendingMissingInput":1`,
		`"pendingUnsupported":1`,
		`"pendingDisabled":1`,
		`"pendingUnmapped":1`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("the pending classification %s must be reported: %s", want, got)
		}
	}
	if !strings.Contains(got, `"pendingObserved":true`) {
		t.Fatalf("the measured queue must report observed: %s", got)
	}

	// The key set is exactly the schema-1 shape (stable contract).
	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	assertKeySet(t, decoded, []string{"schema", "command", "stop_reason", "durationMs", "scope", "scan", "drain", "counts"})
	scope := decoded["scope"].(map[string]any)
	assertKeySet(t, scope, []string{"active", "paused", "refreshed", "acked", "consentRevision", "allowedTools", "unknownAllowedTools", "pendingTools", "pendingUnsupported", "pendingDisabled", "pendingMissingInput", "pendingUnmapped"})
	scan := decoded["scan"].(map[string]any)
	assertKeySet(t, scan, []string{"grants", "exportedBatches", "exportedRecords", "sources", "unknownSources", "account"})
	drain := decoded["drain"].(map[string]any)
	assertKeySet(t, drain, []string{"syncedBatches", "syncedRecords", "attemptedBatches", "rejectedBatches", "rejectedRecords", "recovered", "quarantined", "pendingRemaining", "pendingObserved", "stop", "account"})
	account := drain["account"].(map[string]any)
	assertKeySet(t, account, []string{"syncedBatches", "syncedRecords", "pendingRemaining", "pendingObserved", "outcome"})
	counts := decoded["counts"].(map[string]any)
	assertKeySet(t, counts, []string{"exportedBatches", "exportedRecords", "syncedBatches", "syncedRecords", "pendingBatches", "pendingObserved", "rejectedRecords", "recovered", "quarantined"})
	if decoded["stop_reason"] != string(StopFatalError) {
		t.Fatalf("the cursor round error must drive the verdict: %s", got)
	}
	if drain["stop"] != string(DrainStopFailed) {
		t.Fatalf("the drain stop code must survive: %s", got)
	}
}

// TestSummarizePhasesUnobservedPending pins F4: a queue that was never
// counted reports observed=false everywhere it appears — a zero count
// never implies an empty queue — and an uncounted drain stop is the
// honest unknown.
func TestSummarizePhasesUnobservedPending(t *testing.T) {
	// A zero Result (no round ran): nothing is measured and the drain
	// state is the honest indeterminate unknown — never a claimed
	// drained or empty queue. The real not-run producers (the round
	// constructors and SummarizeNotRun) carry the explicit not_run
	// code instead.
	res := Result{}
	summary := SummarizePhases(res)
	if summary.Drain.PendingObserved || summary.Drain.Account.PendingObserved || summary.Counts.PendingObserved {
		t.Fatalf("an unmeasured run must report observed=false: %+v", summary)
	}
	if summary.Drain.Stop != DrainStopUnknown {
		t.Fatalf("an indeterminate drain must report unknown, got %q", summary.Drain.Stop)
	}
	// The explicit not-run shape (what the round constructors leave on
	// a pre-drain exit and what SummarizeNotRun forces).
	if got := SummarizeNotRun(nil, "periodic", 1).Drain.Stop; got != DrainStopNotRun {
		t.Fatalf("the not-run shape must report not_run, got %q", got)
	}
	// A run that counted the device queue but never wired the account
	// source (drain-only): the device is observed, the account is not,
	// and the totals follow the stricter flag.
	res = Result{PendingRemaining: 3, PendingCounted: true}
	summary = SummarizePhases(res)
	if !summary.Drain.PendingObserved {
		t.Fatalf("the counted device queue must report observed=true: %+v", summary.Drain)
	}
	if summary.Drain.Account.PendingObserved || summary.Counts.PendingObserved {
		t.Fatalf("the unwired account queue must stay unobserved: %+v", summary)
	}
	if summary.Drain.Stop != DrainStopUnknown {
		t.Fatalf("pending batches without a recorded stop must read unknown, got %q", summary.Drain.Stop)
	}
}

// TestSummarizeDrainStopDerivation pins the summary-only drain stop
// values: drained only for a REALLY measured empty queue, unknown for
// an uncounted queue (never a claimed empty), and the recorded code
// verbatim.
func TestSummarizeDrainStopDerivation(t *testing.T) {
	cases := []struct {
		name string
		res  Result
		want DrainStopCode
	}{
		{"measured empty queue", Result{PendingCounted: true}, DrainStopDrained},
		{"uncounted empty queue", Result{}, DrainStopUnknown},
		{"recorded code", Result{DrainStop: DrainStopPaused, PendingRemaining: 1, PendingCounted: true}, DrainStopPaused},
		{"not run", Result{DrainStop: DrainStopNotRun, PendingRemaining: 3}, DrainStopNotRun},
		{"unrecorded measured remainder", Result{PendingRemaining: 2, PendingCounted: true}, DrainStopUnknown},
		{"foreign code value", Result{DrainStop: DrainStopCode("future_code"), PendingRemaining: 1, PendingCounted: true}, DrainStopUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := summarizeDrainStop(tc.res); got != tc.want {
				t.Fatalf("summarizeDrainStop = %q, want %q", got, tc.want)
			}
		})
	}
}

func assertKeySet(t *testing.T, m map[string]any, want []string) {
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

// TestSummarizeIncompleteRunEnvelope pins the envelope semantics: a
// command-layer incomplete exit wrapped in ErrIncompleteRun classifies
// from the structured result — partial for an authorized source the
// grant sync could not classify, paused for an incomplete account
// round — never the default fatal_error, while a plain error over the
// same state stays fatal. A never-detected default input is not a
// concern: the envelope over that state alone must not read partial.
func TestSummarizeIncompleteRunEnvelope(t *testing.T) {
	res := Result{
		GrantSync: GrantSync{Pending: map[string]string{
			"Claude Code": "some future restriction format",
		}},
		PendingCounted: true,
	}
	envelope := fmt.Errorf("%w: periodic incomplete: 1 authorized source(s) are not covered", ErrIncompleteRun)
	if got := Summarize(res, envelope, nil, "periodic", 1); got.StopReason != StopPartial {
		t.Fatalf("the envelope over an unclassifiable authorized source must be partial, got %q", got.StopReason)
	}
	neverInstalled := Result{
		GrantSync: GrantSync{Pending: map[string]string{
			"Claude Code": "default directory not found: /missing",
		}},
		PendingCounted: true,
	}
	if got := Summarize(neverInstalled, fmt.Errorf("%w: nothing owed", ErrIncompleteRun), nil, "periodic", 1); got.StopReason != StopComplete {
		t.Fatalf("a never-installed tool must not flip the envelope to partial, got %q", got.StopReason)
	}
	plain := errors.New("periodic incomplete: 1 authorized source(s) are not covered")
	if got := Summarize(res, plain, nil, "periodic", 1); got.StopReason != StopFatalError {
		t.Fatalf("a plain error keeps fatal_error, got %q", got.StopReason)
	}
	paused := Result{
		Cursor:         cursorsync.Result{Ran: true, Outcome: cursorsync.RoundPaused, PendingRemaining: 2, PendingCounted: true},
		PendingCounted: true,
	}
	if got := Summarize(paused, fmt.Errorf("%w: the account cursor source is paused", ErrIncompleteRun), nil, "periodic", 1); got.StopReason != StopPaused {
		t.Fatalf("the envelope over a paused account round must be paused, got %q", got.StopReason)
	}
}
