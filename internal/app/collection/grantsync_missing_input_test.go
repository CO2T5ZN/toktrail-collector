package collection

// Regressions for the never-detected default-directory semantics: a
// server-allowed tool whose default directory was never present on
// this device is an optional skip — observable through the pending map
// (grant-ack applyState=pending with the missing_input closed code and
// the not_detected tool status) but never a coverage concern that
// fails the round. The honest-error half is pinned here too: a probe
// that fails for any reason OTHER than os.ErrNotExist (a permission
// error) must fail the grant sync, and an EXISTING enabled grant whose
// input path later disappears stays a scan fault — never a silent
// skip, and never a missing_input disguise.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toktrail-collector/internal/local/grants"
)

// missingInputTools filters a pending map down to the tools restricted
// by a never-detected default directory.
func missingInputTools(pending map[string]string) []string {
	var tools []string
	for tool, reason := range pending {
		if strings.HasPrefix(reason, "default directory not found:") {
			tools = append(tools, tool)
		}
	}
	return tools
}

// TestGrantSyncEightSelectedTwoInstalledCompletes pins the headline
// scenario end to end at the collection round level: the server
// authorizes eight local tools, this machine has only two of them
// installed. The two installed tools gain managed grants and are
// scanned; the six never-installed tools stay observable pending
// restrictions (grant-ack pending with the missing_input code,
// not_detected tool statuses, the summary's pendingMissingInput
// counter) — and the run's verdict is COMPLETE, not partial.
func TestGrantSyncEightSelectedTwoInstalledCompletes(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	// Eight authorized local tools (Cursor is account-network, Hermes
	// and OpenClaw left out only to keep the fixture at eight).
	server.setView(t, false, []string{
		"Codex", "Claude Code", "DeepSeek Harness", "WorkBuddy",
		"Qwen Code", "Kimi CLI", "Kimi Code", "ZCode",
	}, 61)
	bindDevice(t, stateDir, server.URL)
	home := t.TempDir()

	// Two tools are actually installed, with synthetic sessions so the
	// round proves real executable work.
	writeCodexSession(t, filepath.Join(home, ".codex", "sessions"), "rollout-8of2.jsonl",
		codexTokenCount("2026-10-26T04:00:00Z", 100, 0, 0, 50),
		codexTokenCount("2026-10-26T04:01:00Z", 160, 10, 0, 90))
	writeClaudeSession(t, filepath.Join(home, ".claude", "projects"), "session-8of2.jsonl",
		claudeLine(t, "2026-10-26T04:00:00Z", "sess-8of2", "msg-8of2", claudeUsage(30, 0, 0, 9)))

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home})
	if err != nil {
		t.Fatalf("a round with six never-installed optional tools must complete, got %v", err)
	}

	// The two installed tools were granted and collected.
	if len(res.GrantSync.AddedGrants) != 2 {
		t.Fatalf("exactly the two installed tools must gain managed grants, got %#v", res.GrantSync.AddedGrants)
	}
	if res.ExportedBatches != 2 || res.ExportedRecords != 2 {
		t.Fatalf("both installed tools must export their session, got batches=%d records=%d", res.ExportedBatches, res.ExportedRecords)
	}

	// The six never-installed tools stay observable pending
	// restrictions — with the exact historical reason text.
	if got := missingInputTools(res.GrantSync.Pending); len(got) != 6 {
		t.Fatalf("the six never-installed tools must be pending missing_input, got %#v (pending=%#v)", got, res.GrantSync.Pending)
	}

	// The grant-ack honestly reports the restricted application: the
	// revision is acknowledged as applyState=pending with one
	// missing_input closed code per never-installed tool.
	last := server.lastAckBody()
	if last.ApplyState != "pending" {
		t.Fatalf("a restricted revision must ack as pending, got %#v", last)
	}
	missingInput := 0
	for _, reason := range last.PendingReasons {
		if reason.Code == "missing_input" {
			missingInput++
		}
	}
	if missingInput != 6 {
		t.Fatalf("the ack must carry six missing_input codes, got %#v", last.PendingReasons)
	}

	// The server also saw one not_detected tool status per
	// never-installed tool (the probe-only report channel).
	notDetected := 0
	for _, report := range server.toolStatusReports() {
		if report.Status == "not_detected" && report.Detail == "default directory not found" {
			notDetected++
		}
	}
	if notDetected != 6 {
		t.Fatalf("the server must see six not_detected tool statuses, got %#v", server.toolStatusReports())
	}

	// The verdict: complete — every executable local work item ran,
	// and the never-installed tools are not coverage concerns.
	summary := Summarize(res, nil, nil, "periodic", 0)
	if summary.StopReason != StopComplete {
		t.Fatalf("stopReason = %q, want complete (phases: %+v)", summary.StopReason, summary.Phases)
	}
	if summary.Scope.PendingMissingInput != 6 || summary.Scope.PendingTools != 6 {
		t.Fatalf("the summary must keep the six missing-input facts observable, got %+v", summary.Scope)
	}

	// The scheduled-task judgment agrees: no incomplete exit is owed.
	if concerns := PendingCoverageConcerns(res.GrantSync.Pending); concerns != 0 {
		t.Fatalf("never-installed tools must not count as coverage concerns, got %d", concerns)
	}
}

// TestGrantSyncNeverInstalledRepeatsSteady pins the second round of the
// same state (the scheduled task's steady state): the six pending
// restrictions are reported again, no duplicate grants appear, and the
// verdict stays complete.
func TestGrantSyncNeverInstalledRepeatsSteady(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{
		"Codex", "Claude Code", "DeepSeek Harness", "WorkBuddy",
		"Qwen Code", "Kimi CLI", "Kimi Code", "ZCode",
	}, 61)
	bindDevice(t, stateDir, server.URL)
	home := t.TempDir()
	writeCodexSession(t, filepath.Join(home, ".codex", "sessions"), "rollout-steady.jsonl",
		codexTokenCount("2026-10-26T04:00:00Z", 100, 0, 0, 50))

	if _, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home}); err != nil {
		t.Fatal(err)
	}

	// Second round over the unchanged state.
	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home})
	if err != nil {
		t.Fatalf("the steady state must keep completing, got %v", err)
	}
	if got := missingInputTools(res.GrantSync.Pending); len(got) != 7 {
		t.Fatalf("the seven never-installed tools stay pending, got %#v", got)
	}
	if len(res.GrantSync.AddedGrants) != 0 {
		t.Fatalf("an unchanged state must not re-add grants, got %#v", res.GrantSync.AddedGrants)
	}
	summary := Summarize(res, nil, nil, "periodic", 0)
	if summary.StopReason != StopComplete {
		t.Fatalf("stopReason = %q, want complete on the repeated round", summary.StopReason)
	}
	enabled, err := grants.New(stateDir).Enabled()
	if err != nil {
		t.Fatal(err)
	}
	if len(enabled) != 1 {
		t.Fatalf("exactly one grant must exist after both rounds, got %#v", enabled)
	}
}

// TestGrantSyncProbePermissionErrorFailsClosed pins the honest-error
// half: a default-directory probe that fails with anything other than
// os.ErrNotExist — here an injected permission error on the tool's
// parent directory — must fail the grant sync instead of masquerading
// as an undetected tool.
//
// The permission error is injected through the per-instance
// Options.probeDefaultInput hook rather than a chmod-000 directory:
// chmod does not make a directory unreadable to its owner on Windows
// and is bypassed entirely under root, so a real-filesystem fault
// would make this test pass or fail depending on the runner. The
// injected PathError carries the same shape the real probe surfaces
// (errors.Is(err, os.ErrPermission)) and exercises the identical
// production classification. NOT covered here: an actual Windows ACL
// denial reaching the probe — the Go standard library cannot install
// deny ACLs, so that platform-specific wiring remains unverified.
func TestGrantSyncProbePermissionErrorFailsClosed(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Qwen Code"}, 62)
	bindDevice(t, stateDir, server.URL)
	home := t.TempDir()

	// The qwen tool's root directory exists with its projects child, as
	// it would on a machine where the directory became unreadable.
	qwenRoot := filepath.Join(home, ".qwen")
	if err := os.MkdirAll(filepath.Join(qwenRoot, "projects"), 0o700); err != nil {
		t.Fatal(err)
	}

	_, err := Run(t.Context(), Options{
		StateDir: stateDir,
		HomeDir:  home,
		probeDefaultInput: func(path string) (bool, error) {
			// The probe of ~/.qwen/projects fails with EACCES — the
			// same error the real probe surfaces for an unreadable
			// parent — never with os.ErrNotExist.
			return false, &fs.PathError{Op: "stat", Path: path, Err: os.ErrPermission}
		},
	})
	if err == nil {
		t.Fatal("a permission-denied default-directory probe must fail the run")
	}
	if !strings.Contains(err.Error(), "probe default directory for tool") || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("the probe error must surface verbatim, got %v", err)
	}
	// Nothing was disguised: no grant was added and no pending
	// missing-input restriction was recorded for the unreadable tool.
	enabled, lErr := grants.New(stateDir).Enabled()
	if lErr != nil {
		t.Fatal(lErr)
	}
	if len(enabled) != 0 {
		t.Fatalf("no grant may be added over an unreadable probe, got %#v", enabled)
	}
}

// TestGrantSyncExistingGrantPathDisappearedStaysFault pins the
// protection the reclassification must not weaken: a managed grant
// whose default directory existed when it was added, then vanished,
// keeps its enabled grant and is reported by the scan as an
// input-inaccessible FAULT — never skipped as an optional
// never-installed tool, and never moved into the pending missing-input
// map.
func TestGrantSyncExistingGrantPathDisappearedStaysFault(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Codex"}, 63)
	bindDevice(t, stateDir, server.URL)
	home := t.TempDir()

	// Round 1: the tool is installed, the managed grant is added.
	codexDir := filepath.Join(home, ".codex", "sessions")
	writeCodexSession(t, codexDir, "rollout-gone.jsonl",
		codexTokenCount("2026-10-26T04:00:00Z", 100, 0, 0, 50))
	if _, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home}); err != nil {
		t.Fatal(err)
	}
	enabled, err := grants.New(stateDir).Enabled()
	if err != nil {
		t.Fatal(err)
	}
	if len(enabled) != 1 || !enabled[0].Managed {
		t.Fatalf("round 1 must add the managed grant, got %#v", enabled)
	}

	// The tool is uninstalled: the granted path disappears.
	if err := os.RemoveAll(filepath.Join(home, ".codex")); err != nil {
		t.Fatal(err)
	}

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home})
	if err != nil {
		t.Fatalf("the scan reports the fault through the outcome, not a run error: %v", err)
	}
	// The grant is NOT reclassified as a never-installed pending tool.
	if got := missingInputTools(res.GrantSync.Pending); len(got) != 0 {
		t.Fatalf("an existing grant must never be disguised as missing_input, got %#v (pending=%#v)", got, res.GrantSync.Pending)
	}
	// The scan reported the honest fault.
	faults := 0
	for _, outcome := range res.GrantOutcomes {
		if outcome.Code == GrantInputInaccessible && strings.Contains(outcome.Skipped, "not accessible") {
			faults++
		}
	}
	if faults != 1 {
		t.Fatalf("the vanished input must be an input-inaccessible fault, got %#v", res.GrantOutcomes)
	}
	if summary := Summarize(res, nil, nil, "periodic", 0); summary.StopReason != StopFatalError {
		t.Fatalf("stopReason = %q, want fatal_error over a vanished granted input", summary.StopReason)
	}
	// And the grant stays enabled — the state is unchanged, only
	// reported.
	enabled, err = grants.New(stateDir).Enabled()
	if err != nil {
		t.Fatal(err)
	}
	if len(enabled) != 1 {
		t.Fatalf("the grant must stay recorded for the next round, got %#v", enabled)
	}
}

// TestGrantSyncCustomGrantCoversMissingDefaultDir pins the
// user-authored escape hatch: a tool whose default directory is absent
// but whose source has an enabled custom grant is no restriction at
// all — no pending entry, no concern.
func TestGrantSyncCustomGrantCoversMissingDefaultDir(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 64)
	bindDevice(t, stateDir, server.URL)
	home := t.TempDir()

	customDir := filepath.Join(home, "elsewhere", "claude")
	writeClaudeSession(t, customDir, "session-custom.jsonl",
		claudeLine(t, "2026-10-26T04:00:00Z", "sess-custom", "msg-custom", claudeUsage(10, 0, 0, 4)))
	enableGrant(t, stateDir, "claude-code-jsonl", customDir)

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.GrantSync.Pending) != 0 {
		t.Fatalf("a custom-granted source must not be pending, got %#v", res.GrantSync.Pending)
	}
	if res.ExportedBatches != 1 {
		t.Fatalf("the custom grant must be collected, got %+v", res.GrantOutcomes)
	}
	if summary := Summarize(res, nil, nil, "periodic", 0); summary.StopReason != StopComplete {
		t.Fatalf("stopReason = %q, want complete", summary.StopReason)
	}
}

// TestGrantSyncProbeNonDirectoryPathFailsClosed pins the shape rule of
// the default-directory probe: every registry default path is a
// directory (the sqlite sources' defaults are the directories holding
// the databases), so a regular file — or any non-directory node — at
// that path is a real local fault: the grant sync fails with an
// explicit error instead of reporting the tool as not detected.
func TestGrantSyncProbeNonDirectoryPathFailsClosed(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Qwen Code"}, 65)
	bindDevice(t, stateDir, server.URL)
	home := t.TempDir()

	// A regular file sits where the tool's default DIRECTORY belongs.
	qwenRoot := filepath.Join(home, ".qwen")
	if err := os.MkdirAll(qwenRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(qwenRoot, "projects"), []byte("not a directory\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home})
	if err == nil {
		t.Fatal("a non-directory default path must fail the run")
	}
	if !strings.Contains(err.Error(), "probe default directory for tool") || !strings.Contains(err.Error(), "exists but is not a directory") {
		t.Fatalf("the non-directory probe error must surface explicitly, got %v", err)
	}
	enabled, lErr := grants.New(stateDir).Enabled()
	if lErr != nil {
		t.Fatal(lErr)
	}
	if len(enabled) != 0 {
		t.Fatalf("no grant may be added over a non-directory default path, got %#v", enabled)
	}
}

// TestGrantSyncCustomFileGrantUnaffectedByProbeRules pins the
// no-collateral guarantee: the probe's directory requirement applies
// ONLY to a tool's default path. A user-authored grant pointing at a
// regular FILE (the jsonl sources scan a single file input just like a
// directory) keeps its historical ValidateInput treatment, is scanned
// normally, and — because it shares the tool's source — covers the
// missing default directory without any pending restriction.
func TestGrantSyncCustomFileGrantUnaffectedByProbeRules(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 66)
	bindDevice(t, stateDir, server.URL)
	home := t.TempDir()

	// A custom FILE grant: the granted input is the session file
	// itself, not a directory.
	sessionFile := writeClaudeSession(t, filepath.Join(home, "custom"), "session-file.jsonl",
		claudeLine(t, "2026-10-26T04:00:00Z", "sess-file", "msg-file", claudeUsage(10, 0, 0, 4)))
	enableGrant(t, stateDir, "claude-code-jsonl", sessionFile)

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home})
	if err != nil {
		t.Fatalf("a custom file grant must keep working: %v", err)
	}
	if len(res.GrantSync.Pending) != 0 {
		t.Fatalf("the same-source custom grant covers the tool; no pending restriction is owed, got %#v", res.GrantSync.Pending)
	}
	scanned := false
	for _, outcome := range res.GrantOutcomes {
		if outcome.Input == sessionFile && outcome.Code == GrantExported && outcome.Records == 1 {
			scanned = true
		}
	}
	if !scanned {
		t.Fatalf("the custom file grant must be scanned as before, got %#v", res.GrantOutcomes)
	}
	if summary := Summarize(res, nil, nil, "periodic", 0); summary.StopReason != StopComplete {
		t.Fatalf("stopReason = %q, want complete", summary.StopReason)
	}
}
