package connect

// display_test.go - tests for the connect/resync human display layer:
// the two-level verbosity routing, the coupled heartbeat (event-driven
// lines plus the fallback ticker for emitter-less phases), the prompt
// gating and its post-confirmation resumption, and the natural-language
// final results rendered from the closed-set summaries (observed gates,
// explicit unknowns, failure attention, no untrusted text ever echoed).
// Everything is synthetic (fake clocks, fake tick channels, in-memory
// sinks); no real state, credential or network is touched, and no test
// waits real seconds.

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/app/resync"
)

// gateSink is a prompt-aware heartbeat sink: while open is set (an
// interactive prompt holds the stream), heartbeat lines are dropped the
// same way the CLI's humanStream drops them.
type gateSink struct {
	mu    sync.Mutex
	open  bool
	lines []string
}

func (s *gateSink) Write(p []byte) (int, error) { return len(p), nil }

func (s *gateSink) WriteHeartbeatLine(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.open {
		return 0, nil
	}
	s.lines = append(s.lines, strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func (s *gateSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.lines)
}

func (s *gateSink) all() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.lines...)
}

func (s *gateSink) setOpen(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.open = v
}

// TestDisplayPhaseAndDetail pins the two verbosity levels: phase lines
// print in every mode, detail lines only under --verbose.
func TestDisplayPhaseAndDetail(t *testing.T) {
	var concise, verbose bytes.Buffer
	dc := newDisplay(&concise, false)
	dv := newDisplay(&verbose, true)
	dc.phase("phase line")
	dc.detail("detail line")
	dv.phase("phase line")
	dv.detail("detail line")
	if concise.String() != "phase line\n" {
		t.Fatalf("the concise display must carry phase lines only, got %q", concise.String())
	}
	if verbose.String() != "phase line\ndetail line\n" {
		t.Fatalf("the verbose display must carry both, got %q", verbose.String())
	}
}

// TestHeartbeatThrottleFakeClock: with a synthetic clock advanced in
// five-second steps, heartbeat events print exactly at the thirty-second
// thresholds - never every event, never a real wait.
func TestHeartbeatThrottleFakeClock(t *testing.T) {
	sink := &gateSink{}
	base := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := base
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	beat := HumanHeartbeat(sink, 0, now)
	for i := 1; i <= 13; i++ {
		mu.Lock()
		clock = base.Add(time.Duration(i*5) * time.Second)
		mu.Unlock()
		beat(collection.ProgressEvent{
			Kind: collection.ProgressHeartbeat, Stage: "drain",
			Duration: time.Duration(i*5) * time.Second, Counted: true, PendingBatches: 3,
		})
	}
	lines := sink.all()
	if len(lines) != 2 {
		t.Fatalf("events every 5s over 65s must print exactly the 30s and 60s lines, got %d: %v", len(lines), lines)
	}
	want := "Uploading queued batches: still working (30s elapsed; 3 batch(es) pending)."
	if lines[0] != want {
		t.Fatalf("line 0 = %q, want %q", lines[0], want)
	}
	// Non-heartbeat events never print.
	beat(collection.ProgressEvent{Kind: collection.ProgressStageEnd, Stage: "drain"})
	if sink.count() != 2 {
		t.Fatalf("non-heartbeat events must never print, got %d", sink.count())
	}
}

// TestHeartbeatOmitsUnobservedFields: an unmeasured duration and an
// uncounted queue are omitted entirely - never shown as zero.
func TestHeartbeatOmitsUnobservedFields(t *testing.T) {
	sink := &gateSink{}
	base := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := base
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	beat := HumanHeartbeat(sink, 30*time.Second, now)
	mu.Lock()
	clock = base.Add(35 * time.Second)
	mu.Unlock()
	beat(collection.ProgressEvent{Kind: collection.ProgressHeartbeat, Stage: "source_scan"})
	lines := sink.all()
	if len(lines) != 1 || lines[0] != "Scanning local sources: still working." {
		t.Fatalf("unobserved fields must be omitted, got %v", lines)
	}
}

// TestHeartbeatPromptGatingDropsAndResumes: while a prompt holds the
// stream open the lines are dropped; once the prompt's line is closed
// (the CLI's CompletePromptLine), the next threshold prints again - the
// confirmation wait never injects progress, and progress resumes after
// it without echoing any answer.
func TestHeartbeatPromptGatingDropsAndResumes(t *testing.T) {
	sink := &gateSink{}
	base := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := base
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	beat := HumanHeartbeat(sink, 30*time.Second, now)

	// The prompt opens (no newline follows); heartbeats through the
	// whole confirmation wait are dropped.
	sink.setOpen(true)
	for i := 1; i <= 8; i++ {
		mu.Lock()
		clock = base.Add(time.Duration(i*10) * time.Second)
		mu.Unlock()
		beat(collection.ProgressEvent{Kind: collection.ProgressHeartbeat, Stage: "cursor_sync", Duration: time.Duration(i*10) * time.Second})
	}
	if sink.count() != 0 {
		t.Fatalf("heartbeats must be dropped while the prompt waits on stdin, got %v", sink.all())
	}

	// The confirmation returned and the prompt line was closed: the
	// next threshold prints again (the long first sync that follows
	// stays visible).
	sink.setOpen(false)
	mu.Lock()
	clock = base.Add(85 * time.Second)
	mu.Unlock()
	beat(collection.ProgressEvent{Kind: collection.ProgressHeartbeat, Stage: "cursor_sync", Duration: 85 * time.Second})
	if sink.count() != 1 {
		t.Fatalf("heartbeats must resume after the prompt line closes, got %v", sink.all())
	}
}

// TestHeartbeatConcurrentEventCalls drives the adapter from many
// goroutines at once (the emitter contract serializes, but the adapter
// must also be safe if a caller does not). Run under -race.
func TestHeartbeatConcurrentEventCalls(t *testing.T) {
	sink := &gateSink{}
	base := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := base
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	beat := HumanHeartbeat(sink, time.Millisecond, now)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			mu.Lock()
			clock = base.Add(time.Duration(n) * time.Millisecond)
			mu.Unlock()
			beat(collection.ProgressEvent{Kind: collection.ProgressHeartbeat, Stage: "drain", Duration: time.Duration(n) * time.Millisecond, Counted: true, PendingBatches: n})
		}(i)
	}
	wg.Wait()
	if sink.count() == 0 {
		t.Fatal("the concurrent heartbeats must produce at least one line")
	}
}

// TestStartHeartbeatFallbackCoversEmitterlessPhases: the fallback ticker
// names the silent phases (no internal emitter exists). With events
// stopping at t=10 and a five-second tick, the fixed "Still working."
// appears at the first tick past the threshold (~t=40) - and the shared
// output throttle keeps an immediately following event line from
// doubling up.
func TestStartHeartbeatFallbackCoversEmitterlessPhases(t *testing.T) {
	sink := &gateSink{}
	base := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := base
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	tick := make(chan time.Time)
	events, stop := StartHeartbeat(sink, 30*time.Second, now, tick)
	defer stop()

	setClock := func(d time.Duration) { mu.Lock(); clock = base.Add(d); mu.Unlock() }
	// Events flow until t=10 (they also suppress the fallback).
	for _, at := range []time.Duration{5 * time.Second, 10 * time.Second} {
		setClock(at)
		events(collection.ProgressEvent{Kind: collection.ProgressHeartbeat, Stage: "drain", Duration: at})
	}
	if got := sink.count(); got != 0 {
		t.Fatalf("events before the threshold must not print, got %d", got)
	}
	// The phase goes silent; the five-second ticks keep coming.
	for _, at := range []time.Duration{15 * time.Second, 20 * time.Second, 25 * time.Second, 30 * time.Second, 35 * time.Second} {
		setClock(at)
		tick <- base.Add(at)
	}
	if got := sink.count(); got != 0 {
		t.Fatalf("the fallback must stay silent until no event arrived for the whole threshold, got %d", got)
	}
	// The decisive tick is a POSITIVE one and the last: once its
	// effect is observed, every earlier tick was already processed
	// (the loop is strictly sequential), so the exact-lines assertion
	// below is deterministic - no sleeps, no scheduler assumptions.
	setClock(40 * time.Second)
	tick <- base.Add(40 * time.Second)
	waitForCondition(t, func() bool { return sink.count() == 1 })
	lines := sink.all()
	if len(lines) != 1 || lines[0] != "Still working." {
		t.Fatalf("the fallback must print exactly the fixed line at ~t=40 (and nothing before it), got %v", lines)
	}
	// An event arriving right after the fallback line is throttled by
	// the SHARED stamp (never two lines back to back).
	setClock(41 * time.Second)
	events(collection.ProgressEvent{Kind: collection.ProgressHeartbeat, Stage: "drain", Duration: 41 * time.Second})
	if got := sink.count(); got != 1 {
		t.Fatalf("the shared output throttle must hold after the fallback line, got %d", got)
	}
	// Thirty seconds after the last output the event line prints again.
	setClock(72 * time.Second)
	events(collection.ProgressEvent{Kind: collection.ProgressHeartbeat, Stage: "drain", Duration: 72 * time.Second, Counted: true, PendingBatches: 2})
	lines = sink.all()
	if len(lines) != 2 || !strings.HasPrefix(lines[1], "Uploading queued batches: still working (") {
		t.Fatalf("the event line must resume after the shared threshold, got %v", lines)
	}
}

// waitForCondition polls cond with a deadline: the fallback goroutine
// processes ticks asynchronously, and this returns the moment cond
// holds (typically sub-millisecond) instead of sleeping on scheduler
// assumptions.
func waitForCondition(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			return // the caller's assertion reports the failure
		}
		time.Sleep(time.Millisecond)
	}
}

// TestStartHeartbeatFallbackPromptGatingAndResumption: while a prompt
// holds the stream open, fallback ticks are dropped AND the drop never
// counts as output - once the prompt's line is closed, the very next
// tick past the threshold prints (no extra interval of silence after
// the confirmation).
func TestStartHeartbeatFallbackPromptGatingAndResumption(t *testing.T) {
	sink := &gateSink{}
	base := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := base
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	tick := make(chan time.Time)
	_, stop := StartHeartbeat(sink, 30*time.Second, now, tick)
	defer stop()

	sink.setOpen(true) // the confirmation prompt opens; ticks drop
	for _, at := range []time.Duration{35 * time.Second, 40 * time.Second} {
		mu.Lock()
		clock = base.Add(at)
		mu.Unlock()
		tick <- base.Add(at)
	}
	// The prompt's line closes (the confirmation returned); the next
	// tick prints because the DROPPED ticks never advanced the stamp.
	sink.setOpen(false)
	mu.Lock()
	clock = base.Add(46 * time.Second)
	mu.Unlock()
	tick <- base.Add(46 * time.Second)
	waitForCondition(t, func() bool { return sink.count() == 1 })
	lines := sink.all()
	if len(lines) != 1 || lines[0] != "Still working." {
		t.Fatalf("the fallback must resume immediately after the prompt closes (drops never count as output), got %v", lines)
	}
}

// TestStartHeartbeatFallbackSilentWhileEventsFlow: while events keep
// arriving, the fallback never prints (the richer lines own the
// stream).
func TestStartHeartbeatFallbackSilentWhileEventsFlow(t *testing.T) {
	sink := &gateSink{}
	base := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := base
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	tick := make(chan time.Time)
	events, stop := StartHeartbeat(sink, 30*time.Second, now, tick)
	defer stop()
	for i := 1; i <= 12; i++ {
		at := time.Duration(i*5) * time.Second
		mu.Lock()
		clock = base.Add(at)
		mu.Unlock()
		events(collection.ProgressEvent{Kind: collection.ProgressQueue, Stage: "drain"})
		tick <- base.Add(at)
	}
	if sink.count() != 0 {
		t.Fatalf("a live event stream must suppress the fallback, got %v", sink.all())
	}
}

// TestStartHeartbeatStopIsIdempotentAndJoins: stop returns, is safe to
// call twice, and a closed tick channel ends the fallback cleanly.
func TestStartHeartbeatStopIsIdempotentAndJoins(t *testing.T) {
	sink := &gateSink{}
	tick := make(chan time.Time)
	_, stop := StartHeartbeat(sink, 30*time.Second, nil, tick)
	stop()
	stop() // idempotent
	close(tick)
	// No panic, no further output.
	if sink.count() != 0 {
		t.Fatalf("a stopped runner must print nothing, got %v", sink.all())
	}
}

// TestRenderRunSummaryCompleteFirstInstall: the clean default is two or
// three natural lines - verdict, one facts line - with no history
// section (nothing was retransmitted), no pending claim and no machine
// key=value.
func TestRenderRunSummaryCompleteFirstInstall(t *testing.T) {
	s := RunSummary{
		Schema: collection.ResultSchema, Command: "connect", StopReason: collection.StopComplete,
		Binding:   BindingSummary{Status: BindBound, ConsentRevision: 7},
		Scheduler: SchedulerSummary{Installed: true},
		Collection: collection.Phases{Counts: collection.CountSummary{
			SyncedBatches: 2, SyncedRecords: 80, PendingBatches: 0, PendingObserved: true,
		}},
		History: HistorySummary{Ran: true, Stop: ResyncStopCompleted, Uploads: 0, Remaining: 0},
	}
	var buf bytes.Buffer
	RenderRunSummary(&buf, s, false)
	out := buf.String()
	if !strings.Contains(out, "Connect result: completed for the current authorization; the server confirmed 2 batch(es) (80 record(s)).") {
		t.Fatalf("the verdict line must be scoped natural English with its facts, got:\n%s", out)
	}
	if !strings.Contains(out, "Connect result: completed for the current authorization; the server confirmed 2 batch(es) (80 record(s)).") {
		t.Fatalf("the verdict line carries the run's own facts in one natural line, got:\n%s", out)
	}
	for _, banned := range []string{"History retransmission", "pending", "stop_reason=", "incomplete", "Diagnostics", "consentRevision", "device bound"} {
		if strings.Contains(out, banned) {
			t.Fatalf("a clean first install must not carry %q (the setup phases already stated the binding once), got:\n%s", banned, out)
		}
	}
}

// TestRenderRunSummaryUnknownPending: a queue the incomplete run needed
// to report but never measured is stated as unknown - never silently
// dropped, never shown as zero.
func TestRenderRunSummaryUnknownPending(t *testing.T) {
	s := RunSummary{
		StopReason: collection.StopPartial,
		Binding:    BindingSummary{Status: BindBound},
		Collection: collection.Phases{Counts: collection.CountSummary{PendingObserved: false}},
	}
	var buf bytes.Buffer
	RenderRunSummary(&buf, s, false)
	out := buf.String()
	if !strings.Contains(out, "Pending batches: unknown (not measured this run).") {
		t.Fatalf("the unobserved queue must be named unknown, got:\n%s", out)
	}
	if strings.Contains(out, "pendingBatches=0") || strings.Contains(out, "0 batch(es) remain pending") {
		t.Fatalf("an unmeasured queue must never print a zero count, got:\n%s", out)
	}
}

// TestRenderRunSummaryPendingAdvicePerStopReason: the follow-up hint
// appears only where the stop reason guarantees it - a paused device or
// a moved scope never gets an automatic-continuation promise.
func TestRenderRunSummaryPendingAdvicePerStopReason(t *testing.T) {
	render := func(reason collection.StopReason) string {
		s := RunSummary{
			StopReason: reason,
			Binding:    BindingSummary{Status: BindBound},
			Collection: collection.Phases{Drain: collection.DrainSummary{PendingRemaining: 4, PendingObserved: true}},
		}
		var buf bytes.Buffer
		RenderRunSummary(&buf, s, false)
		return buf.String()
	}
	if out := render(collection.StopBudgetExhausted); !strings.Contains(out, "Device: 4 batch(es) remain pending.") || strings.Contains(out, "continues them") {
		t.Fatalf("a budget stop states the pending fact only (no unproven continuation claim), got:\n%s", out)
	}
	if out := render(collection.StopPaused); !strings.Contains(out, "Device: 4 batch(es) remain pending.") || strings.Contains(out, "continues them") {
		t.Fatalf("a paused device must state the pending count without a continuation promise, got:\n%s", out)
	}
	if out := render(collection.StopScopeChanged); !strings.Contains(out, "a new collection is required under the current authorization") {
		t.Fatalf("a scope change must point at the new collection, got:\n%s", out)
	}
}

// TestRenderRunSummaryHistoryAttention: the history section appears
// only when it needs attention - a real retransmission, a resumable
// stop, rejections - and names the manual resume boundary (the
// scheduled task does not continue a resync job). A nothing-eligible
// verdict and an empty first-install pass stay silent.
func TestRenderRunSummaryHistoryAttention(t *testing.T) {
	render := func(h HistorySummary) string {
		s := RunSummary{StopReason: collection.StopPartial, Binding: BindingSummary{Status: BindBound},
			Collection: collection.Phases{Counts: collection.CountSummary{PendingObserved: true}}, History: h}
		var buf bytes.Buffer
		RenderRunSummary(&buf, s, false)
		return buf.String()
	}
	stopped := render(HistorySummary{Ran: true, Stop: ResyncStopStopped, Remaining: 5})
	if !strings.Contains(stopped, "History retransmission: stopped early; resume it explicitly with toktrail resync --all when intended (the scheduled task does not continue a resync job).") ||
		!strings.Contains(stopped, "5 batch(es) remain un-retransmitted.") {
		t.Fatalf("a resumable stop must carry the explicit manual resume boundary, got:\n%s", stopped)
	}
	if out := render(HistorySummary{Ran: true, Stop: ResyncStopNothingEligible, Uploads: 0}); strings.Contains(out, "History retransmission") {
		t.Fatalf("a nothing-eligible verdict is a normal state, never an attention line, got:\n%s", out)
	}
	if out := render(HistorySummary{Ran: true, Stop: ResyncStopCompleted, Uploads: 0, Remaining: 0}); strings.Contains(out, "History retransmission") {
		t.Fatalf("an empty completed pass needs no attention line, got:\n%s", out)
	}
	if out := render(HistorySummary{Ran: true, Stop: ResyncStopCompleted, Uploads: 6, AcceptedRecords: 500, RejectedRecords: 3}); !strings.Contains(out, "6 batch(es) re-sent (500 record(s) accepted by the server)") || !strings.Contains(out, "The server rejected 3 record(s).") {
		t.Fatalf("a real retransmission must show the re-sent counts and the rejections, got:\n%s", out)
	}
}

// TestRenderRunSummaryFailureAttention: a non-complete verdict names up
// to three canonical sources with fixed closed reasons, folds the rest
// into a count, and surfaces the account round's closed outcome - never
// a path, a raw error or an unvetted name.
func TestRenderRunSummaryFailureAttention(t *testing.T) {
	s := RunSummary{
		StopReason: collection.StopFatalError,
		Binding:    BindingSummary{Status: BindBound},
		Collection: collection.Phases{
			Scan: collection.ScanSummary{Sources: []collection.GrantSourceStatus{
				{Source: "codex-jsonl", Status: collection.GrantInputInaccessible},
				{Source: "claude-code-jsonl", Status: collection.GrantExportFailed},
				{Source: "deepseek-harness", Status: collection.GrantSplitFailed},
				{Source: "workbuddy-jsonl", Status: collection.GrantInputInaccessible},
				{Source: "qwen-jsonl", Status: collection.GrantInputInaccessible},
				{Source: "kimi-cli-jsonl", Status: collection.GrantNoNewRecords},
			}},
			Drain: collection.DrainSummary{Account: collection.AccountDrainSummary{Outcome: cursorsync.RoundError}},
		},
	}
	var buf bytes.Buffer
	RenderRunSummary(&buf, s, false)
	out := buf.String()
	for _, want := range []string{
		"Source codex-jsonl: is unavailable (its input can no longer be read).",
		"Source claude-code-jsonl: failed to export its records.",
		"Source deepseek-harness: failed to split its export.",
		"2 more source(s) failed the same way.",
		"The account source failed this round; its queue keeps its state.",
		"Connect result: failed.",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the failure attention must carry %q, got:\n%s", want, out)
		}
	}
}

// TestRenderRunSummaryFailureAttentionHostileInputs: an attacker-controlled
// grant input and skip text never reach the output - only the canonical
// name and the closed reason render (end to end through SummarizeRun).
func TestRenderRunSummaryFailureAttentionHostileInputs(t *testing.T) {
	const attackerPath = "/Users/victim/.attacker/SECRETTOKEN-path"
	const attackerText = "attacker-error-SECRETTOKEN-xyz https://evil.example/steal?f=tok_9"
	res := Result{
		BindStatus: BindBound,
		Sync: SyncResult{Collection: collection.Result{
			GrantOutcomes: []collection.GrantOutcome{
				{Source: "codex-jsonl", Input: attackerPath, Skipped: attackerText, Code: collection.GrantInputInaccessible},
			},
		}},
	}
	summary := SummarizeRun(res, errors.New("boom "+attackerText), nil, 1)
	var buf bytes.Buffer
	RenderRunSummary(&buf, summary, false)
	out := buf.String()
	if !strings.Contains(out, "Source codex-jsonl: is unavailable (its input can no longer be read).") {
		t.Fatalf("the canonical source and closed reason must render, got:\n%s", out)
	}
	if strings.Contains(out, attackerPath) || strings.Contains(out, attackerText) || strings.Contains(out, "SECRETTOKEN") || strings.Contains(out, "evil.example") {
		t.Fatalf("attacker-controlled values must never reach the summary, got:\n%s", out)
	}
}

// TestPrintResyncPlanResumedOmitsUnobservedRecords: a resumed journal
// may hold real batches while its records total was never counted; the
// plan line then states the batch count only - the unknown record
// total is never presented as zero.
func TestPrintResyncPlanResumedOmitsUnobservedRecords(t *testing.T) {
	plan := resync.Plan{
		Resumed:        true,
		PlannedRecords: 0, // never counted on the resume path
		Batches:        []resync.PlannedBatch{{BatchID: "b-1"}, {BatchID: "b-2"}},
	}
	for _, verbose := range []bool{false, true} {
		var buf bytes.Buffer
		printResyncPlan(newDisplay(&buf, verbose), plan)
		out := buf.String()
		if !strings.Contains(out, "plan: resuming an unfinished retransmission job; 2 batch(es) remain in the plan.") {
			t.Fatalf("verbose=%t: the resumed plan must state the provable batch count, got:\n%s", verbose, out)
		}
		if strings.Contains(out, "0 record") {
			t.Fatalf("verbose=%t: an uncounted records total must never print as zero, got:\n%s", verbose, out)
		}
	}
}

// TestRenderRunSummaryCompletedWithRejections: resync.Run can COMPLETE
// a job whose receipts still carry rejected records; the completed
// verdict is then explicitly qualified and the history line carries the
// rejection count - never an unqualified success.
func TestRenderRunSummaryCompletedWithRejections(t *testing.T) {
	s := RunSummary{
		StopReason: collection.StopComplete,
		Binding:    BindingSummary{Status: BindBound},
		Collection: collection.Phases{Counts: collection.CountSummary{SyncedBatches: 2, SyncedRecords: 80, PendingObserved: true}},
		History:    HistorySummary{Ran: true, Stop: ResyncStopCompleted, Uploads: 6, AcceptedRecords: 500, RejectedRecords: 3},
	}
	var buf bytes.Buffer
	RenderRunSummary(&buf, s, false)
	out := buf.String()
	if !strings.Contains(out, "Connect result: processing completed for the current authorization; some records were rejected") {
		t.Fatalf("a completed run with rejections must qualify its verdict, got:\n%s", out)
	}
	if !strings.Contains(out, "History retransmission: 6 batch(es) re-sent (500 record(s) accepted by the server). The server rejected 3 record(s).") {
		t.Fatalf("the completed history line must carry the rejection count, got:\n%s", out)
	}
}

// TestRenderSyncResultCompletedWithRejections: the resync verdict twin.
func TestRenderSyncResultCompletedWithRejections(t *testing.T) {
	sync := SyncResult{Resync: ResyncSummary{Ran: true, Completed: true, Stop: ResyncStopCompleted, Uploads: 4, AcceptedRecords: 90, RejectedRecords: 2}}
	var buf bytes.Buffer
	RenderSyncResult(&buf, sync, nil, nil, false, false)
	out := buf.String()
	if !strings.Contains(out, "Resync result: processing completed for the current authorization; some records were rejected.") {
		t.Fatalf("a completed resync with rejections must qualify its verdict, got:\n%s", out)
	}
	if !strings.Contains(out, "The server rejected 2 record(s).") {
		t.Fatalf("the history line must carry the rejection count, got:\n%s", out)
	}
}

// TestRenderSyncResultInitialRoundHardErrorKeepsKnownPending: Sync
// returns early on an initial-collection hard error before any backlog
// pass exists; the initial round's own counted pending must still be
// reported, read from the same source as its observation gate.
func TestRenderSyncResultInitialRoundHardErrorKeepsKnownPending(t *testing.T) {
	sync := SyncResult{
		Collection: collection.Result{
			PendingCounted:   true,
			PendingRemaining: 2,
			Cursor: cursorsync.Result{
				Ran:              true,
				PendingCounted:   true,
				PendingRemaining: 1,
			},
		},
		Backlog: BacklogSummary{}, // Passes == 0: never populated
	}
	var buf bytes.Buffer
	RenderSyncResult(&buf, sync, errors.New("initial collection failed: boom"), nil, false, false)
	out := buf.String()
	if !strings.Contains(out, "Device: 2 batch(es) remain pending.") || !strings.Contains(out, "Account: 1 batch(es) remain pending.") {
		t.Fatalf("the initial round's known pending must be reported with its queue named, got:\n%s", out)
	}
	if strings.Contains(out, "unknown (not measured this run)") {
		t.Fatalf("measured queues must never read as unknown, got:\n%s", out)
	}
	if !strings.Contains(out, "Resync result: failed.") {
		t.Fatalf("the hard error keeps its verdict, got:\n%s", out)
	}
}

// TestRenderSyncResultPausedCursorCountsBeforePull: cursorsync's
// fail-closed pause path counts the durable account queue BEFORE the
// upstream pull and returns with Ran=false and a real count; the
// counted pending must be reported whatever Ran says.
func TestRenderSyncResultPausedCursorCountsBeforePull(t *testing.T) {
	sync := SyncResult{
		Collection: collection.Result{
			Cursor: cursorsync.Result{
				Ran:              false,
				Skipped:          "server reports collection paused",
				PendingCounted:   true,
				PendingRemaining: 3,
			},
		},
	}
	var buf bytes.Buffer
	RenderSyncResult(&buf, sync, nil, nil, false, false)
	out := buf.String()
	if !strings.Contains(out, "Account: 3 batch(es) remain pending.") {
		t.Fatalf("the counted account pending must be reported despite Ran=false, got:\n%s", out)
	}
	if strings.Contains(out, "Account-source batches pending: unknown") {
		t.Fatalf("a counted queue must never read as unknown, got:\n%s", out)
	}
}

// TestRenderRunSummaryKnownDevicePendingWithUnknownAccount: the merged
// Counts gate is true only when BOTH queues were measured; a known
// device count must never be swallowed by an unmeasured account queue,
// and the unmeasured account queue (whose round ran) is named unknown
// on its own line.
func TestRenderRunSummaryKnownDevicePendingWithUnknownAccount(t *testing.T) {
	s := RunSummary{
		StopReason: collection.StopPartial,
		Binding:    BindingSummary{Status: BindBound},
		Collection: collection.Phases{
			Scan:  collection.ScanSummary{Account: collection.AccountScanSummary{Ran: true}},
			Drain: collection.DrainSummary{PendingRemaining: 10, PendingObserved: true, Account: collection.AccountDrainSummary{PendingObserved: false}},
		},
	}
	var buf bytes.Buffer
	RenderRunSummary(&buf, s, false)
	out := buf.String()
	if !strings.Contains(out, "Device: 10 batch(es) remain pending.") {
		t.Fatalf("the known device pending must be reported with its queue named, got:\n%s", out)
	}
	if !strings.Contains(out, "Account-source batches pending: unknown (not measured this run).") {
		t.Fatalf("the unmeasured account queue must be named unknown on its own line, got:\n%s", out)
	}
	if strings.Contains(out, "Pending batches: unknown") {
		t.Fatalf("the measured device queue must not read as unknown, got:\n%s", out)
	}
}

// TestRenderRunSummaryVerboseDiagnostics: the closed-set codes are the
// verbose-only diagnostics.
func TestRenderRunSummaryVerboseDiagnostics(t *testing.T) {
	s := RunSummary{
		StopReason: collection.StopPartial, Binding: BindingSummary{Status: BindBound},
		Collection:      collection.Phases{Counts: collection.CountSummary{PendingObserved: true, PendingBatches: 2}},
		IncompleteCodes: []string{"pending_batches", "history_remaining"},
	}
	var buf bytes.Buffer
	RenderRunSummary(&buf, s, true)
	out := buf.String()
	if !strings.Contains(out, "Diagnostics: stop_reason=partial binding=bound") {
		t.Fatalf("verbose must carry the closed-set diagnostics, got:\n%s", out)
	}
	if !strings.Contains(out, "Diagnostics: incomplete codes=[pending_batches history_remaining]") {
		t.Fatalf("verbose must carry the closed incompleteness codes, got:\n%s", out)
	}
	var concise bytes.Buffer
	RenderRunSummary(&concise, s, false)
	if strings.Contains(concise.String(), "Diagnostics") {
		t.Fatalf("the concise default must not carry the diagnostics, got:\n%s", concise.String())
	}
}

// TestRenderSyncResultDryRunNeverClaimsComplete: a dry run renders the
// planned-only verdict with the unverified-scope limitation and never
// reaches the completion classification.
func TestRenderSyncResultDryRunNeverClaimsComplete(t *testing.T) {
	var buf bytes.Buffer
	RenderSyncResult(&buf, SyncResult{}, nil, nil, true, false)
	out := buf.String()
	if !strings.Contains(out, "Resync result: dry run - planned only; nothing was uploaded or changed, and the remote consent scope was not verified.") {
		t.Fatalf("the dry-run verdict must state its limitation, got:\n%s", out)
	}
	if strings.Contains(out, "completed") {
		t.Fatalf("a dry run must never claim completion, got:\n%s", out)
	}
}

// TestRenderSyncResultHardErrorFails: a hard error renders the failed
// verdict - never a completion, never the raw error text.
func TestRenderSyncResultHardErrorFails(t *testing.T) {
	var buf bytes.Buffer
	RenderSyncResult(&buf, SyncResult{}, errors.New("history retransmission failed: boom https://evil.example"), nil, false, false)
	out := buf.String()
	if !strings.Contains(out, "Resync result: failed.") {
		t.Fatalf("a hard error must render the failed verdict, got:\n%s", out)
	}
	if strings.Contains(out, "evil.example") || strings.Contains(out, "boom") {
		t.Fatalf("the raw error text must never be echoed, got:\n%s", out)
	}
}

// TestRenderSyncResultNothingEligibleIsNotAFailure: an authorization
// verdict with nothing eligible is a complete, normal outcome.
func TestRenderSyncResultNothingEligibleIsNotAFailure(t *testing.T) {
	sync := SyncResult{Resync: ResyncSummary{Ran: true, Completed: true, Stop: ResyncStopNothingEligible}}
	var buf bytes.Buffer
	RenderSyncResult(&buf, sync, nil, nil, false, false)
	out := buf.String()
	if !strings.Contains(out, "Resync result: completed for the current authorization.") {
		t.Fatalf("nothing-eligible is a complete authorization verdict, got:\n%s", out)
	}
	if strings.Contains(out, "failed") || strings.Contains(out, "History retransmission") {
		t.Fatalf("a clean nothing-eligible pass needs no attention, got:\n%s", out)
	}
}

// TestSyncStopReasonDelegatesToConnectStopReason: the exported verdict
// is exactly the classification SummarizeRun applies to a connect run.
func TestSyncStopReasonDelegatesToConnectStopReason(t *testing.T) {
	sync := SyncResult{
		BudgetExhausted: true,
		Resync:          ResyncSummary{Ran: true, Stop: ResyncStopBudget, Remaining: 2},
		Incomplete:      []string{"budget"},
	}
	// The honest incompleteness envelope, exactly as the Sync call
	// sites build it (the sentinel refinement reads errors.Is).
	err := fmt.Errorf("%w: the shared upload budget stopped the drain", ErrSyncIncomplete)
	if !errors.Is(err, ErrSyncIncomplete) {
		t.Fatal("the fixture must carry the incompleteness sentinel")
	}
	got := SyncStopReason(sync, err, nil)
	want := connectStopReason(Result{Sync: sync}, err, nil)
	if got != want || got != collection.StopBudgetExhausted {
		t.Fatalf("SyncStopReason = %s, want %s (connectStopReason said %s)", got, collection.StopBudgetExhausted, want)
	}
}

// TestProgressResyncDefaultGating: the per-batch history lines are
// verbose-only and never carry a batch id in any mode.
func TestProgressResyncDefaultGating(t *testing.T) {
	ev := resync.ProgressEvent{BatchID: "batch-SECRET-1", Outcome: "done", Uploaded: 1, Accepted: 5, Rejected: 0, Skipped: 0, Replay: false}

	var concise bytes.Buffer
	progressResyncOrDefault(nil, newDisplay(&concise, false))(ev)
	if concise.String() != "" {
		t.Fatalf("the concise default must not print per-batch lines, got %q", concise.String())
	}
	var verbose bytes.Buffer
	progressResyncOrDefault(nil, newDisplay(&verbose, true))(ev)
	out := verbose.String()
	if !strings.Contains(out, "history batch: done submitted=1 accepted=5") {
		t.Fatalf("verbose must show the sealed outcome and counts, got %q", out)
	}
	if strings.Contains(out, "batch-SECRET-1") {
		t.Fatalf("no mode may echo a batch id, got %q", out)
	}
}

// TestProgressOutcomeIsWhitelisted: a hostile outcome string (a hex
// ticket smuggled into the field) never prints verbatim in any mode;
// only the sealed vocabulary passes through.
func TestProgressOutcomeIsWhitelisted(t *testing.T) {
	ticket := strings.Repeat("f", 64)
	var buf bytes.Buffer
	progressResyncOrDefault(nil, newDisplay(&buf, true))(resync.ProgressEvent{
		BatchID: "b", Outcome: ticket, Uploaded: 1,
	})
	if strings.Contains(buf.String(), ticket) {
		t.Fatalf("a hostile outcome must never print verbatim, got %q", buf.String())
	}
	if !strings.Contains(buf.String(), "history batch: unknown submitted=1") {
		t.Fatalf("an unknown outcome degrades to the fixed label, got %q", buf.String())
	}
	var obuf bytes.Buffer
	progressOverrideOrDefault(nil, newDisplay(&obuf, true))(resync.OverrideProgressEvent{
		BatchID: "b", Outcome: "done", Records: 2,
	})
	if !strings.Contains(obuf.String(), "override batch: done records=2") {
		t.Fatalf("the sealed vocabulary passes through, got %q", obuf.String())
	}
}

// TestPrintResyncPlanPrivacy: the plan the user confirms carries the
// counts and the fixed coverage notes - never the server URL or the
// device id, in any mode.
func TestPrintResyncPlanPrivacy(t *testing.T) {
	plan := resync.Plan{
		ServerURL:      "https://attacker.example/collect?ticket=SECRETTOKEN",
		DeviceID:       "dev-SECRET-1",
		PlannedRecords: 42,
		Batches:        []resync.PlannedBatch{{BatchID: "b-1"}},
		CoverageNote:   "resync covers the device outbox (this collector's already-synced batches) only",
	}
	for _, verbose := range []bool{false, true} {
		var buf bytes.Buffer
		printResyncPlan(newDisplay(&buf, verbose), plan)
		out := buf.String()
		if strings.Contains(out, "attacker.example") || strings.Contains(out, "SECRETTOKEN") || strings.Contains(out, "dev-SECRET-1") {
			t.Fatalf("verbose=%t: the plan must never echo the target line, got:\n%s", verbose, out)
		}
		if !strings.Contains(out, "plan: 1 batch(es) (42 record(s)) to retransmit.") {
			t.Fatalf("verbose=%t: the one-line plan must render, got:\n%s", verbose, out)
		}
		if !strings.Contains(out, "History replay covers this device only; account history and quarantined records are excluded.") {
			t.Fatalf("verbose=%t: the short coverage line must render, got:\n%s", verbose, out)
		}
	}
}

// TestPrintResyncPlanEmptyIsSilentByDefault: a first install's
// automatic pass holds an empty plan - nothing to confirm, nothing to
// cover - so the default prints no plan or coverage text at all (a
// 300-character coverage note over an empty plan is noise); verbose
// keeps the record.
func TestPrintResyncPlanEmptyIsSilentByDefault(t *testing.T) {
	plan := resync.Plan{
		CoverageNote: "resync covers the device outbox (this collector's already-synced batches) only; independent account-source ledgers (such as cursor account history) and recoverable quarantine records are not included, and completion is not a claim of restoring anything beyond that ledger",
	}
	var concise bytes.Buffer
	printResyncPlan(newDisplay(&concise, false), plan)
	if concise.String() != "" {
		t.Fatalf("an empty plan must print nothing by default, got:\n%s", concise.String())
	}
	var verbose bytes.Buffer
	printResyncPlan(newDisplay(&verbose, true), plan)
	if !strings.Contains(verbose.String(), "plan: empty") || !strings.Contains(verbose.String(), "resync covers the device outbox") {
		t.Fatalf("verbose must keep the empty-plan record and the full note, got:\n%s", verbose.String())
	}
}

// TestPrintResyncPlanSnapshotRestrictionSummary: the PLAN's
// SnapshotRestricted marker drives the scope wording - a fresh
// restricted pass names its pre-run boundary, a resumed restricted job
// names its journal-frozen ORIGINAL snapshot (never this run's start),
// and an unrestricted pass stays device-only.
func TestPrintResyncPlanSnapshotRestrictionSummary(t *testing.T) {
	render := func(plan resync.Plan) string {
		var buf bytes.Buffer
		printResyncPlan(newDisplay(&buf, false), plan)
		return buf.String()
	}
	fresh := render(resync.Plan{SnapshotRestricted: true, PlannedRecords: 7, Batches: []resync.PlannedBatch{{BatchID: "b-1"}}})
	if !strings.Contains(fresh, "History replay covers this device only, and only the batches already synced before this run; batches synced during this run, account history and quarantined records are excluded.") {
		t.Fatalf("a fresh restricted pass must name its pre-run boundary, got:\n%s", fresh)
	}
	resumed := render(resync.Plan{SnapshotRestricted: true, Resumed: true, Batches: []resync.PlannedBatch{{BatchID: "b-1"}}})
	if !strings.Contains(resumed, "History replay covers this device only, limited to the job's original snapshot; account history and quarantined records are excluded.") {
		t.Fatalf("a resumed restricted job must name its original snapshot, got:\n%s", resumed)
	}
	if strings.Contains(resumed, "before this run") {
		t.Fatalf("a resumed job's snapshot may predate this run - never 'before this run', got:\n%s", resumed)
	}
	unrestricted := render(resync.Plan{PlannedRecords: 7, Batches: []resync.PlannedBatch{{BatchID: "b-1"}}})
	if !strings.Contains(unrestricted, "History replay covers this device only; account history and quarantined records are excluded.") || strings.Contains(unrestricted, "before this run") {
		t.Fatalf("an unrestricted pass stays device-only, got:\n%s", unrestricted)
	}
}

// TestConfirmResyncOrDefaultReadsPlanSnapshotMarker: connect's common
// shape wires NO explicit ResyncSnapshot (CaptureResyncSnapshot captures
// it later), and a resumed job's scope lives in its frozen journal - so
// the executed plan's OWN marker, never the option wiring, decides the
// coverage wording.
func TestConfirmResyncOrDefaultReadsPlanSnapshotMarker(t *testing.T) {
	var buf bytes.Buffer
	confirm := confirmResyncOrDefault(SyncOptions{}, newDisplay(&buf, false))
	if err := confirm(resync.Plan{SnapshotRestricted: true, PlannedRecords: 5, Batches: []resync.PlannedBatch{{BatchID: "b-1"}}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "only the batches already synced before this run") {
		t.Fatalf("the plan's marker must drive the restricted wording even with opt.ResyncSnapshot nil, got:\n%s", buf.String())
	}
	buf.Reset()
	if err := confirm(resync.Plan{SnapshotRestricted: true, Resumed: true, Batches: []resync.PlannedBatch{{BatchID: "b-1"}}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "limited to the job's original snapshot") {
		t.Fatalf("a resumed restricted job names its original snapshot, got:\n%s", buf.String())
	}
}

// TestPrintResyncSummaryNeverEchoesStopped: the stored stop text is
// never printed in any mode; the closed stop code and counts are the
// verbose detail, and the withheld/out-of-scope boundary stays a
// default line.
func TestPrintResyncSummaryNeverEchoesStopped(t *testing.T) {
	summary := ResyncSummary{
		Stop: ResyncStopStopped, Stopped: "upload failed: Get \"https://evil.example/ingest?f=SECRETTOKEN\": 503 /Users/victim/path",
		Remaining: 3, Blocked: 2, Uploads: 4,
	}
	for _, verbose := range []bool{false, true} {
		var buf bytes.Buffer
		printResyncSummary(newDisplay(&buf, verbose), summary)
		out := buf.String()
		if strings.Contains(out, "evil.example") || strings.Contains(out, "SECRETTOKEN") || strings.Contains(out, "/Users/victim") {
			t.Fatalf("verbose=%t: the stored stop text must never be echoed, got:\n%s", verbose, out)
		}
		if !strings.Contains(out, "some history was not retransmitted because it is outside the current authorization") {
			t.Fatalf("verbose=%t: the withheld boundary must stay visible, got:\n%s", verbose, out)
		}
	}
	var verbose bytes.Buffer
	printResyncSummary(newDisplay(&verbose, true), summary)
	if !strings.Contains(verbose.String(), "stop=stopped") {
		t.Fatalf("verbose must carry the closed stop code, got:\n%s", verbose.String())
	}
}

// TestBacklogStopPhrase: the drain stop renders behind closed phrases
// derived from structure, never the stored free text.
func TestBacklogStopPhrase(t *testing.T) {
	if got := backlogStopPhrase(SyncResult{BudgetExhausted: true}, nil, 10); got != "stopped at the shared sync budget" {
		t.Fatalf("budget stop = %q", got)
	}
	if got := backlogStopPhrase(SyncResult{Backlog: BacklogSummary{Passes: 10}}, nil, 10); got != "stopped at the backlog pass bound" {
		t.Fatalf("pass bound = %q", got)
	}
	if got := backlogStopPhrase(SyncResult{Backlog: BacklogSummary{Passes: 3}}, nil, 10); got != "stopped early (paused, restricted, or a pass made no progress)" {
		t.Fatalf("unclassified stop = %q", got)
	}
}

// hostileSchedulerRunner fails every command with hostile material in
// its error text (paths, URLs, tokens).
type hostileSchedulerRunner struct{}

func (hostileSchedulerRunner) Run(name string, args ...string) error {
	return fmt.Errorf("launchctl failed: SECRETTOKEN https://evil.example/steal?f=tok_9 /Users/victim/.attacker-path")
}

// TestSchedulerNotesSwallowHostileText: the scheduler package's own
// output (best-effort notes, dry-run plans) quotes raw command errors
// and full paths; the sink swallows them and keeps only the fact.
func TestSchedulerNotesSwallowHostileText(t *testing.T) {
	notes := &schedulerNotes{}
	if _, err := notes.Write([]byte("note: deactivate old service: Get \"https://evil.example/steal?f=SECRETTOKEN\": failed /Users/victim/.attacker-path")); err != nil {
		t.Fatal(err)
	}
	if !notes.seen {
		t.Fatal("the sink must record that a note occurred")
	}
	// The sink exposes no content at all: nothing to leak.
}

// TestConnectSchedulerNotesNeverLeakHostileRunnerText: a scheduler
// runner whose errors carry hostile material never gets that material
// into the human output - the best-effort notes are swallowed by the
// sink (rendered as the fixed safe note line when the install still
// succeeds), and hard failures leave through the error chain (wrapped
// with the closed-set phrase at the CLI).
func TestConnectSchedulerNotesNeverLeakHostileRunnerText(t *testing.T) {
	stateDir, homeDir, _, cfg := seed174Scenario(t)
	_, _, out := runSyncConnectWithOutput(t, cfg, stateDir, homeDir, strings.Repeat("8", 64), Options{
		Cursor:          budgetCursorWiring(&cursorBacklogPull{}, 5),
		SchedulerRunner: hostileSchedulerRunner{},
	})
	for _, banned := range []string{"SECRETTOKEN", "evil.example", "/Users/victim"} {
		if strings.Contains(out, banned) {
			t.Fatalf("the scheduler's hostile text must never reach the human output, got:\n%s", out)
		}
	}
}

// TestConnectSchedulerDryRunNeverClaimsEnabled: a DryRun connect only
// prepares the scheduler plan; the default line states exactly that and
// never claims an installation.
func TestConnectSchedulerDryRunNeverClaimsEnabled(t *testing.T) {
	stateDir, homeDir, _, cfg := seed174Scenario(t)
	_, err, out := runSyncConnectWithOutput(t, cfg, stateDir, homeDir, strings.Repeat("8", 64), Options{
		Cursor: budgetCursorWiring(&cursorBacklogPull{}, 5),
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("the dry-run connect must keep the run semantics: %v", err)
	}
	if !strings.Contains(out, "scheduled collection plan prepared (dry run; not installed)") {
		t.Fatalf("the dry-run line must state the plan without an installation claim, got:\n%s", out)
	}
	if strings.Contains(out, "scheduled collection enabled") {
		t.Fatalf("a dry run must never claim an enabled scheduler, got:\n%s", out)
	}
}

// TestToolCountSetDedupAndSummary: repeated tool names count once, and
// the merged line keeps every category distinct - an unsupported name
// is never "not installed", a confirmation-needing account source is
// neither.
func TestToolCountSetDedupAndSummary(t *testing.T) {
	var tc toolCountSet
	if !tc.counted("codex") || tc.counted("codex") {
		t.Fatal("a repeated tool name must count once")
	}
	tc.detected++
	tc.notDetected += 2
	tc.unsupported++
	tc.accountActive++
	tc.accountNotEnabled++
	tc.accountFirstSyncIncomplete++
	got := tc.summary()
	want := "1 detected, 2 not detected (skipped), 1 unsupported (skipped), 1 account source(s) active, 1 account source(s) not enabled (local confirmation or setup incomplete), 1 account source(s) enabled with first sync incomplete"
	if got != want {
		t.Fatalf("summary = %q, want %q", got, want)
	}
	var empty toolCountSet
	if empty.summary() != "" {
		t.Fatalf("an empty count set prints nothing, got %q", empty.summary())
	}
}
