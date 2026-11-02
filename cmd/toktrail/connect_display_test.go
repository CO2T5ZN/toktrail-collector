package main

// connect_display_test.go - the connect/resync human display contract
// at the CLI level: the default output is concise English that never
// carries the connect/server URL, the device id, local paths, batch ids
// or the ticket (in any mode); --verbose adds detail but never a
// secret; flag parsing never echoes raw argument values; the human
// stream's prompt gating suppresses heartbeat lines while a
// confirmation waits on stdin and resumes once it returns; and the
// --json stream stays exactly one object. Everything is synthetic
// (temp dirs, httptest fakes, injected confirms); no real credential,
// state or network is touched.

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"toktrail-collector/internal/connect"
)

// displayConnectBase splits a connect URL into its server base (for
// leak assertions only; it is never printed by the command).
func displayConnectBase(t *testing.T, connectURL string) string {
	t.Helper()
	idx := strings.Index(connectURL, "/api/")
	if idx < 0 {
		t.Fatalf("test fixture URL has no /api/ prefix: %s", connectURL)
	}
	return connectURL[:idx]
}

// TestConnectDefaultOutputIsConciseAndPrivate: the default run shows
// the merged sources line, the brief phase lines and the natural final
// result - and never the server URL, the device id, the subject id,
// local paths, batch ids, the ticket or machine key=value counters.
func TestConnectDefaultOutputIsConciseAndPrivate(t *testing.T) {
	oldRunner := connectSchedulerRunner
	connectSchedulerRunner = mockSchedulerRunner{}
	defer func() { connectSchedulerRunner = oldRunner }()

	stateDir := t.TempDir()
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
	// Only the Codex default directory exists: Claude Code is not
	// installed (its normal skip), and the third name is unsupported.
	if err := os.MkdirAll(filepath.Join(homeDir, ".codex", "sessions"), 0o700); err != nil {
		t.Fatal(err)
	}
	connectURL := connectCLIServers(t, []string{"Codex", "Claude Code", "TotallyBogusTool"})
	ticket := connectURL[strings.LastIndex(connectURL, "#")+1:]
	serverBase := displayConnectBase(t, connectURL)

	var stdout, stderr bytes.Buffer
	err := runConnectIO([]string{"--state-dir", stateDir, connectURL}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("the mixed-install connect must complete (missing inputs are normal skips): %v\nstdout:\n%s", err, stdout.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "sources: 1 detected, 1 not detected (skipped), 1 unsupported (skipped)") {
		t.Fatalf("the merged sources line must carry the deduplicated category counts, got:\n%s", out)
	}
	if !strings.Contains(out, "Collecting local usage...") {
		t.Fatalf("the immediate phase start line must render, got:\n%s", out)
	}
	if !strings.Contains(out, "Connect result: completed for the current authorization") {
		t.Fatalf("the final verdict line must render, got:\n%s", out)
	}
	// The empty history plan prints nothing by default on a first
	// install: no plan line, no coverage note.
	if strings.Contains(out, "plan:") || strings.Contains(out, "History replay covers") {
		t.Fatalf("an empty automatic history plan must stay silent by default, got:\n%s", out)
	}
	for _, banned := range []string{
		serverBase, "127.0.0.1", ticket, "dev-json-cli-1", "sub-cli",
		homeDir, "detected directory", "not found; skipped",
		"exportedBatches=", "syncedBatches=", "stop_reason=", "backlog pass",
		"batch ", "Diagnostics",
	} {
		if strings.Contains(out, banned) || strings.Contains(stderr.String(), banned) {
			t.Fatalf("the default output must never carry %q, got:\nstdout:\n%s\nstderr:\n%s", banned, out, stderr.String())
		}
	}
}

// TestConnectVerboseShowsToolDetailWithoutSecrets: --verbose adds the
// per-tool directory lines (local paths are the user's own machine),
// but never the URL, the ticket or the device id.
func TestConnectVerboseShowsToolDetailWithoutSecrets(t *testing.T) {
	oldRunner := connectSchedulerRunner
	connectSchedulerRunner = mockSchedulerRunner{}
	defer func() { connectSchedulerRunner = oldRunner }()

	stateDir := t.TempDir()
	// A hostile HOME whose directory names carry ticket material: the
	// verbose per-tool lines must withhold the path in every mode.
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
	codexDir := filepath.Join(homeDir, ".codex", "sessions")
	if err := os.MkdirAll(codexDir, 0o700); err != nil {
		t.Fatal(err)
	}
	connectURL := connectCLIServers(t, []string{"Codex"})
	ticket := connectURL[strings.LastIndex(connectURL, "#")+1:]
	serverBase := displayConnectBase(t, connectURL)

	var stdout, stderr bytes.Buffer
	err := runConnectIO([]string{"--state-dir", stateDir, "--verbose", connectURL}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("the verbose connect must complete: %v\nstdout:\n%s", err, stdout.String())
	}
	out := stdout.String()
	if !strings.Contains(out, `tool "Codex": detected at its default location; authorized (local path withheld)`) {
		t.Fatalf("verbose must show the per-tool status line, got:\n%s", out)
	}
	for _, banned := range []string{serverBase, "127.0.0.1", ticket, "dev-json-cli-1", "sub-cli", homeDir, codexDir} {
		if strings.Contains(out, banned) || strings.Contains(stderr.String(), banned) {
			t.Fatalf("verbose must never carry %q, got:\n%s", banned, out)
		}
	}
}

// TestConnectFlagParseNeverEchoesRawValues: a failed flag parse returns
// the fixed safe error (chain preserved) and never echoes the raw
// argument value - a pasted value may carry a ticket, a URL or an
// absolute path. The --json usage-error semantics (one result object)
// survive.
func TestConnectFlagParseNeverEchoesRawValues(t *testing.T) {
	const secret = "BearerSECRETTOKEN1234567890"
	const secretPath = "/Users/victim/.attacker/SECRETTOKEN-path"
	// A syntactically valid LOOPBACK URL: the flag parse fails before
	// any request, and even a regression that fetched it would only
	// reach the loopback interface - never an external network.
	connectURL := "http://127.0.0.1:1/api/collector/connect#" + strings.Repeat("a", 64)

	err := runConnectIO([]string{"--max-total-batches=" + secret, connectURL}, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("an invalid flag value must fail")
	}
	// The CLI's real display text is displayErrorText (the chain keeps
	// its raw Error() verbatim by design - only the display is safe).
	if displayErrorText(err) != errConnectFlagValue.Error() {
		t.Fatalf("the failed parse must display the fixed safe text, got %q", displayErrorText(err))
	}
	if strings.Contains(displayErrorText(err), secret) {
		t.Fatalf("the raw value must never be echoed, got %q", displayErrorText(err))
	}

	err = runConnectIO([]string{"--state-dir", secretPath, "--no-such-flag"}, io.Discard, io.Discard)
	if err == nil || strings.Contains(err.Error(), secretPath) {
		t.Fatalf("an unknown flag must fail without echoing the raw path, got %v", err)
	}

	var stdout, stderr bytes.Buffer
	err = runConnectIO([]string{"--json", "--max-total-batches=" + secret, connectURL}, &stdout, &stderr)
	if err == nil {
		t.Fatal("the invalid value under --json must still fail")
	}
	decoded := decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != "fatal_error" {
		t.Fatalf("the usage-error object must keep its verdict, got %s", stdout.String())
	}
	if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
		t.Fatalf("the secret value must never reach any stream, got:\n%s\n%s", stdout.String(), stderr.String())
	}
}

// TestConnectHelpKeepsChainAndStaticUsage: -h prints the static usage
// (no environment-derived defaults) and returns an error whose chain
// still answers errors.Is(flag.ErrHelp).
func TestConnectHelpKeepsChainAndStaticUsage(t *testing.T) {
	t.Setenv("TOKTRAIL_HOME", "/Users/victim/.leaky-default")
	var stdout, stderr bytes.Buffer
	err := runConnectIO([]string{"-h"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("-h must keep the historical error exit")
	}
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("the ErrHelp chain must survive the safe wrapper, got %v", err)
	}
	if displayErrorText(err) != "help requested" {
		t.Fatalf("the help failure must display its fixed text, got %q", displayErrorText(err))
	}
	if !strings.Contains(stderr.String(), "usage: toktrail connect") {
		t.Fatalf("the static usage must print, got:\n%s", stderr.String())
	}
	if strings.Contains(stderr.String(), "/Users/victim/.leaky-default") {
		t.Fatalf("the usage must never print environment-derived defaults, got:\n%s", stderr.String())
	}
}

// TestConnectJSONStreamStaysSingleObject: under --json the human final
// summary moves to stderr; stdout carries exactly the one JSON object.
func TestConnectJSONStreamStaysSingleObject(t *testing.T) {
	oldRunner := connectSchedulerRunner
	connectSchedulerRunner = mockSchedulerRunner{}
	defer func() { connectSchedulerRunner = oldRunner }()

	stateDir := t.TempDir()
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
	if err := os.MkdirAll(filepath.Join(homeDir, ".codex", "sessions"), 0o700); err != nil {
		t.Fatal(err)
	}
	connectURL := connectCLIServers(t, []string{"Codex"})

	var stdout, stderr bytes.Buffer
	err := runConnectIO([]string{"--state-dir", stateDir, "--json", connectURL}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("the clean connect must keep its nil error: %v\nstderr:\n%s", err, stderr.String())
	}
	decoded := decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != "complete" {
		t.Fatalf("the JSON verdict must be unchanged, got %s", stdout.String())
	}
	if strings.Contains(stdout.String(), "Connect result:") {
		t.Fatalf("stdout must carry only the JSON object, got %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Connect result: completed for the current authorization.") {
		t.Fatalf("the human summary must move to stderr, got:\n%s", stderr.String())
	}
}

// TestHumanStreamPromptSuppressionAndResume: while a prompt holds the
// stream open (a write without a trailing newline - the command is
// waiting on stdin), heartbeat lines are dropped; CompletePromptLine
// closes the prompt's line (a newline only, the answer never echoed)
// and the heartbeat resumes.
func TestHumanStreamPromptSuppressionAndResume(t *testing.T) {
	var raw bytes.Buffer
	hs := newHumanStream(&raw)

	fmt.Fprint(hs, "Confirm? [y/N] ")
	if _, err := hs.WriteHeartbeatLine([]byte("Still working.\n")); err != nil {
		t.Fatal(err)
	}
	if raw.String() != "Confirm? [y/N] " {
		t.Fatalf("the heartbeat must be dropped while the prompt waits, got %q", raw.String())
	}

	hs.CompletePromptLine()
	if !strings.HasSuffix(raw.String(), "Confirm? [y/N] \n") {
		t.Fatalf("closing the prompt line must add only a newline, got %q", raw.String())
	}
	if n, err := hs.WriteHeartbeatLine([]byte("Still working.\n")); n == 0 || err != nil {
		t.Fatalf("the heartbeat must resume after the prompt closes, got (%d, %v)", n, err)
	}
	if !strings.HasSuffix(raw.String(), "Still working.\n") {
		t.Fatalf("the resumed heartbeat must print, got %q", raw.String())
	}
}

// TestHumanStreamConcurrentWritesStayLineWhole: prompts, phase lines
// and heartbeat lines written concurrently never interleave mid-line
// (the redirected, non-TTY log stays line-readable). Run under -race.
func TestHumanStreamConcurrentWritesStayLineWhole(t *testing.T) {
	var raw bytes.Buffer
	hs := newHumanStream(&raw)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if n%4 == 0 {
				fmt.Fprintf(hs, "phase line %d\n", n)
				return
			}
			if n%4 == 1 {
				_, _ = hs.WriteHeartbeatLine([]byte(fmt.Sprintf("Still working %d.\n", n)))
				return
			}
			if n%4 == 2 {
				fmt.Fprintf(hs, "prompt %d? [y/N] ", n)
				hs.CompletePromptLine()
				return
			}
			_, _ = hs.Write([]byte("write line\n"))
		}(i)
	}
	wg.Wait()
	for _, line := range strings.Split(raw.String(), "\n") {
		if line == "" {
			continue
		}
		// Every completed line must be exactly one of the written
		// shapes - never a mid-line interleave of two.
		ok := strings.HasPrefix(line, "phase line ") ||
			strings.HasPrefix(line, "Still working ") ||
			strings.HasPrefix(line, "prompt ") ||
			line == "write line"
		if !ok {
			t.Fatalf("an interleaved line leaked into the stream: %q (full: %q)", line, raw.String())
		}
	}
}

// TestCursorConfirmResumeRestoresHeartbeat: the wrapper closes the
// prompt's display line the moment the (possibly blocking)
// confirmation returns - answered, declined or failed - so the long
// first sync that follows stays visible; the answer itself is never
// echoed and nothing is auto-confirmed.
func TestCursorConfirmResumeRestoresHeartbeat(t *testing.T) {
	var raw bytes.Buffer
	hs := newHumanStream(&raw)

	block := make(chan struct{})
	base := func(notice string, out io.Writer) (bool, error) {
		fmt.Fprint(out, "Enable Cursor usage collection on this machine? [y/N] ")
		<-block // the user is thinking; the command waits on stdin
		return true, nil
	}
	wrapped := cursorConfirmResume(base, hs)

	var confirmed bool
	var confirmErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		confirmed, confirmErr = wrapped("notice", hs)
	}()

	// While the confirmation blocks, heartbeats are dropped.
	time.Sleep(10 * time.Millisecond)
	if _, err := hs.WriteHeartbeatLine([]byte("Still working.\n")); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw.String(), "Still working") {
		t.Fatalf("no heartbeat may interleave the waiting prompt, got %q", raw.String())
	}

	close(block)
	<-done
	if !confirmed || confirmErr != nil {
		t.Fatalf("the wrapper must pass the confirmation through, got (%t, %v)", confirmed, confirmErr)
	}
	if !strings.Contains(raw.String(), "Enable Cursor usage collection on this machine? [y/N] \n") {
		t.Fatalf("the prompt line must be closed with a newline only (no answer echoed), got %q", raw.String())
	}
	if n, _ := hs.WriteHeartbeatLine([]byte("Still working.\n")); n == 0 {
		t.Fatalf("the heartbeat must resume after the confirmation returns, got %q", raw.String())
	}
}

// TestCursorConfirmResumeNilStreamKeepsHook: without a gated stream the
// wrapper must not change the caller's hook at all - the base confirm
// runs and its answer flows through unchanged.
func TestCursorConfirmResumeNilStreamKeepsHook(t *testing.T) {
	called := false
	base := func(notice string, out io.Writer) (bool, error) {
		called = true
		return false, errors.New("declined by test")
	}
	confirmed, err := cursorConfirmResume(base, nil)("notice", io.Discard)
	if !called || confirmed || err == nil || err.Error() != "declined by test" {
		t.Fatalf("a nil stream must keep the hook's behavior untouched, got (%t, %v)", confirmed, err)
	}
}

// TestRunFailureDisplayText: the sentinel-refined safe display - a
// local permission denial and an unreachable network classify; the
// chain is preserved and everything else keeps the closed-set phrase.
func TestRunFailureDisplayText(t *testing.T) {
	if got := runFailureDisplayText(fmt.Errorf("probe default directory for tool %q: %w", "Codex", os.ErrPermission), "fallback"); got != "local source access denied; check the permissions of the affected directory" {
		t.Fatalf("a permission denial must classify (reason only - main's prefix carries the failure word), got %q", got)
	}
	dnsErr := &net.DNSError{Err: "no such host", Name: "server.example"}
	if got := runFailureDisplayText(fmt.Errorf("connect request failed: %w", dnsErr), "fallback"); got != "the server could not be reached; check connectivity and the server status" {
		t.Fatalf("a network failure must classify (reason only), got %q", got)
	}
	if got := runFailureDisplayText(errors.New("opaque"), "the closed-set phrase"); got != "the closed-set phrase" {
		t.Fatalf("unclassifiable errors keep the closed-set phrase, got %q", got)
	}
	// The wrapper keeps the chain for errors.Is.
	wrapped := safeDisplayError(fmt.Errorf("outer: %w", os.ErrPermission), "safe")
	if !errors.Is(wrapped, os.ErrPermission) {
		t.Fatal("errors.Is must survive the safe wrapper")
	}
}

// TestConnectFailureReasonPrintsOnce: the actionable reason lives ONLY
// on the failure line main renders (the returned error's safe display);
// the summary's own verdict stays brief, so a budget-stopped run never
// repeats the reason.
func TestConnectFailureReasonPrintsOnce(t *testing.T) {
	oldRunner := connectSchedulerRunner
	connectSchedulerRunner = mockSchedulerRunner{}
	defer func() { connectSchedulerRunner = oldRunner }()

	stateDir := t.TempDir()
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
	if err := os.MkdirAll(filepath.Join(homeDir, ".codex", "sessions"), 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		seedCLIDeviceBatch(t, stateDir, homeDir, fmt.Sprintf("dedup-budget-%d", i), fmt.Sprintf("dedup-key-%d", i), time.Duration(i)*time.Hour)
	}
	connectURL := connectCLIServers(t, []string{"Codex"})

	var stdout, stderr bytes.Buffer
	err := runConnectIO([]string{"--state-dir", stateDir, "--max-total-batches", "2", connectURL}, &stdout, &stderr)
	if err == nil || !errors.Is(err, connect.ErrSyncIncomplete) {
		t.Fatalf("the budget-capped connect must keep its incomplete error, got %v", err)
	}
	if !strings.Contains(stdout.String(), "Connect result: incomplete") {
		t.Fatalf("the summary verdict stays brief on the default human stream (stdout), got:\n%s", stdout.String())
	}
	combined := stdout.String() + stderr.String() + displayErrorText(err)
	if n := strings.Count(combined, "the upload budget was reached"); n != 1 {
		t.Fatalf("the budget reason must print exactly once, got %d:\nstdout:\n%s\nstderr:\n%s\ndisplay:\n%s", n, stdout.String(), stderr.String(), displayErrorText(err))
	}
}

// TestConnectFatalReasonPrintsOnce: a hard failure's reason also prints
// exactly once - on the failure line main renders - while the summary
// stays brief. The failing endpoint is a LOCAL loopback fake (a fixed
// error status): no external DNS or network is ever touched.
func TestConnectFatalReasonPrintsOnce(t *testing.T) {
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer broken.Close()
	connectURL := broken.URL + "/api/collector/connect#" + strings.Repeat("a", 64)

	var stdout, stderr bytes.Buffer
	err := runConnectIO([]string{"--state-dir", t.TempDir(), connectURL}, &stdout, &stderr)
	if err == nil {
		t.Fatal("a failing connect endpoint must fail the run")
	}
	// The default human stream is stdout (no --json): the summary and
	// the failure display both land there in production shape.
	if !strings.Contains(stdout.String(), "Connect result: failed.") {
		t.Fatalf("the summary verdict stays brief, got:\n%s", stdout.String())
	}
	// The failure display is the closed-set fatal phrase, exactly once
	// (main renders it behind its "connect failed:" prefix), and the
	// real streams never carry the fake's body, URL or ticket.
	if display := displayErrorText(err); display != "an unexpected error occurred" {
		t.Fatalf("the fatal display is the closed-set phrase, got %q", display)
	}
	combined := stdout.String() + stderr.String() + displayErrorText(err)
	if n := strings.Count(combined, "an unexpected error occurred"); n != 1 {
		t.Fatalf("the fatal reason must print exactly once, got %d:\n%s", n, combined)
	}
	for _, leaked := range []string{"internal error", broken.URL, strings.Repeat("a", 64)} {
		if strings.Contains(stdout.String(), leaked) || strings.Contains(stderr.String(), leaked) || strings.Contains(displayErrorText(err), leaked) {
			t.Fatalf("the fake's body, URL or ticket must never reach the display, got leaked %q:\nstdout:\n%s\nstderr:\n%s", leaked, stdout.String(), stderr.String())
		}
	}
}

// TestConnectStopReasonPhraseScopedCompletion pins the phrase contract
// the CLI error wrapping and the result line share.
func TestConnectStopReasonPhraseScopedCompletion(t *testing.T) {
	if got := connect.StopReasonPhrase("complete"); got != "completed for the current authorization" {
		t.Fatalf("the completion phrase is scoped, got %q", got)
	}
	if got := connect.StopReasonPhrase("budget_exhausted"); strings.Contains(got, "nothing was sent") || strings.Contains(got, "history job stays resumable") {
		t.Fatalf("the budget phrase must not over-assert, got %q", got)
	}
}
