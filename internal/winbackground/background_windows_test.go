//go:build windows

package winbackground

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// The Windows tests re-execute this test binary as the helper's
// collector child (os.Executable()): no network, no real credentials,
// and no separately built binary. The helper always launches
// `<exe> periodic --state-dir <dir>`; the fake collector ignores that
// argv and behaves per these environment variables, which the test sets
// before calling Run (the child inherits the test process environment).
const (
	childEnvSwitch     = "TOKTRAIL_WINBG_CHILD"
	childEnvExitCode   = "TOKTRAIL_WINBG_CHILD_EXIT_CODE"
	childEnvStdoutPad  = "TOKTRAIL_WINBG_CHILD_STDOUT_LINES"
	childEnvStderrPad  = "TOKTRAIL_WINBG_CHILD_STDERR_LINES"
	childEnvCheckStdin = "TOKTRAIL_WINBG_CHILD_CHECK_STDIN"
	childEnvSleep      = "TOKTRAIL_WINBG_CHILD_SLEEP"
	childEnvGrandchild = "TOKTRAIL_WINBG_CHILD_GRANDCHILD"
)

// childLineLen is the byte length of one fixture line (including newline).
const childLineLen = 64

// TestMain intercepts the re-executed fake collector before the testing
// framework parses the helper's argv (`periodic --state-dir ...`), which
// is not a valid test flag set.
func TestMain(m *testing.M) {
	if code, handled := runChildMode(); handled {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

// runChildMode implements the fake collector. It writes only to the
// helper-provided stdout/stderr pipes (never the testing framework) and
// exits with the requested code.
func runChildMode() (int, bool) {
	if os.Getenv(childEnvSwitch) == "" {
		return 0, false
	}
	// Echo the exact argv the helper launched us with; the subprocess
	// tests assert it, pinning the argument-array (never-shell) contract
	// from the child's side.
	fmt.Fprintf(os.Stdout, "CHILD-ARGV: %s\n", strings.Join(os.Args[1:], " "))
	if os.Getenv(childEnvCheckStdin) != "" {
		if _, err := io.ReadAll(os.Stdin); err != nil {
			fmt.Fprint(os.Stdout, "CHILD-STDIN: error\n")
		} else {
			// stdin is the NUL device: an immediate clean EOF.
			fmt.Fprint(os.Stdout, "CHILD-STDIN: closed\n")
		}
	}
	writeFixtureLines(os.Stdout, os.Getenv(childEnvStdoutPad), "O")
	writeFixtureLines(os.Stderr, os.Getenv(childEnvStderrPad), "E")
	if os.Getenv(childEnvGrandchild) != "" {
		// Spawn a grandchild that inherits this process's stdout/stderr
		// (the helper's pipes) and outlives it: it pins the pipes after
		// the root exits, which the helper must converge via the job.
		gc := exec.Command(os.Args[0])
		gc.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
		gc.Env = grandchildEnv()
		gc.Stdout = os.Stdout
		gc.Stderr = os.Stderr
		if err := gc.Start(); err != nil {
			fmt.Fprintln(os.Stderr, "GRANDCHILD-START-FAIL")
		} else {
			fmt.Fprintln(os.Stdout, "GRANDCHILD-STARTED")
		}
	}
	if d := os.Getenv(childEnvSleep); d != "" {
		if dur, err := time.ParseDuration(d); err == nil {
			fmt.Fprintln(os.Stdout, "CHILD-SLEEPING")
			time.Sleep(dur)
			fmt.Fprintln(os.Stdout, "CHILD-AFTER-SLEEP")
		}
	}
	code := 0
	if v := os.Getenv(childEnvExitCode); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			code = parsed
		}
	}
	return code, true
}

// writeFixtureLines writes fixed-size lines without controlling pipe chunking.
func writeFixtureLines(w io.Writer, count string, fill string) {
	n, err := strconv.Atoi(count)
	if err != nil || n <= 0 {
		return
	}
	pad := strings.Repeat(fill, 48)
	for i := 0; i < n; i++ {
		fmt.Fprintf(w, "CHILD-LINE %03d %s\n", i, pad)
	}
}

// grandchildEnv builds the grandchild's environment: the fake-collector
// switch plus a long sleep, with the grandchild request itself filtered
// out so the chain stops at one level.
func grandchildEnv() []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, childEnvGrandchild+"=") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, childEnvSleep+"=30s")
}

// testExecutable returns this test binary's absolute path, which plays
// the collector in the subprocess tests.
func testExecutable(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

// readStateLog reads one of the state directory's captured logs.
func readStateLog(t *testing.T, stateDir, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(stateDir, logsDirName, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestRunForwardsExitCodeAndCapturesStreams is the end-to-end contract:
// the helper launches the collector hidden with the exact periodic argv,
// stdin is the NUL device, both streams land in the right rotating
// logs, the lifecycle markers are recorded, and the collector's real
// exit code is forwarded untouched.
func TestRunForwardsExitCodeAndCapturesStreams(t *testing.T) {
	exe := testExecutable(t)
	state := t.TempDir()
	t.Setenv(childEnvSwitch, "1")
	t.Setenv(childEnvExitCode, "7")
	t.Setenv(childEnvStdoutPad, "3")
	t.Setenv(childEnvStderrPad, "2")
	t.Setenv(childEnvCheckStdin, "1")

	rc := Run([]string{"--collector", exe, "--state-dir", state})
	if rc != 7 {
		t.Fatalf("Run returned %d, want the collector's forwarded exit code 7", rc)
	}

	out := readStateLog(t, state, outLogName)
	errLog := readStateLog(t, state, errLogName)

	// Exact argv: an argument array through CreateProcess, never a
	// shell, and the collector subcommand contract
	// `periodic --state-dir <dir>`.
	if want := "CHILD-ARGV: periodic --state-dir " + state; !strings.Contains(out, want) {
		t.Fatalf("stdout log must record the exact collector argv %q, got:\n%s", want, out)
	}
	// stdin must be NUL: the child reads a clean immediate EOF.
	if !strings.Contains(out, "CHILD-STDIN: closed") {
		t.Fatalf("stdin must be the NUL device (immediate EOF), got:\n%s", out)
	}
	if n := strings.Count(out, "CHILD-LINE"); n != 3 {
		t.Fatalf("stdout log must hold the 3 stdout lines, got %d:\n%s", n, out)
	}
	if !strings.Contains(out, strings.Repeat("O", 48)) {
		t.Fatalf("stdout lines must carry the stdout filler, got:\n%s", out)
	}
	if n := strings.Count(errLog, "CHILD-LINE"); n != 2 {
		t.Fatalf("error log must hold the 2 stderr lines, got %d:\n%s", n, errLog)
	}
	if !strings.Contains(errLog, strings.Repeat("E", 48)) {
		t.Fatalf("error log must carry the stderr filler, got:\n%s", errLog)
	}
	// Lifecycle markers in the error log, with no raw arguments or
	// paths.
	if !strings.Contains(errLog, "collector started") || !strings.Contains(errLog, "collector finished exit=7") {
		t.Fatalf("error log must carry the started/finished lifecycle markers, got:\n%s", errLog)
	}
	if strings.Contains(errLog, exe) || strings.Contains(errLog, state) {
		t.Fatalf("lifecycle markers must not embed paths, got:\n%s", errLog)
	}
}

// TestRunForwardsTransientExitCode pins the atomic job binding from the
// scheduler-probe angle: a collector that exits immediately (here with
// code 7, the native scheduler probe shape) must still be captured and
// forwarded — never misreported as a helper launch failure because it
// died before a post-hoc job assignment could run.
func TestRunForwardsTransientExitCode(t *testing.T) {
	exe := testExecutable(t)
	state := t.TempDir()
	t.Setenv(childEnvSwitch, "1")
	t.Setenv(childEnvExitCode, "7")

	rc := Run([]string{"--collector", exe, "--state-dir", state})
	if rc != 7 {
		t.Fatalf("Run returned %d for a transient collector, want the forwarded exit code 7", rc)
	}
	if errLog := readStateLog(t, state, errLogName); !strings.Contains(errLog, "collector finished exit=7") {
		t.Fatalf("a transient run must still record its lifecycle, got:\n%s", errLog)
	}
}

// TestRunRotatesLogsWhileCollectorRuns pins bounded logging end to end:
// a collector that writes past the cap has its older output archived
// and dropped, while the newest window stays readable in the active log.
func TestRunRotatesLogsWhileCollectorRuns(t *testing.T) {
	oldMax := maxLogBytes
	maxLogBytes = 4 * childLineLen
	t.Cleanup(func() { maxLogBytes = oldMax })

	exe := testExecutable(t)
	state := t.TempDir()
	t.Setenv(childEnvSwitch, "1")
	t.Setenv(childEnvExitCode, "0")
	t.Setenv(childEnvStdoutPad, "30")

	rc := Run([]string{"--collector", exe, "--state-dir", state})
	if rc != ExitSuccess {
		t.Fatalf("Run returned %d, want the forwarded exit code 0", rc)
	}

	active := readStateLog(t, state, outLogName)
	archive := readStateLog(t, state, outLogName+rotatedSuffix)
	retained := archive + active
	if !strings.Contains(retained, "CHILD-LINE") {
		t.Fatalf("the retained log window must contain collector output: %q", retained)
	}
	bound := int64(4 * childLineLen)
	if int64(len(active)) > bound || int64(len(archive)) > bound {
		t.Fatalf("rotation must enforce its byte cap: active=%d archive=%d bound=%d", len(active), len(archive), bound)
	}
	if total := len(active) + len(archive); total >= 30*childLineLen {
		t.Fatalf("rotation must drop older output: %d of %d written bytes retained", total, 30*childLineLen)
	}
	if !strings.Contains(retained, "CHILD-LINE 029") {
		t.Fatalf("the newest output must survive across the retained window, got:\n%s", retained)
	}
}

// TestRunConvergesGrandchildrenHoldingThePipe pins the convergence
// contract: a grandchild that inherits the collector's stdout pipe and
// outlives the root must not hang the helper. The root's real exit code
// is captured first; closing the kill-on-close job then terminates the
// grandchild (job membership is inherited), which releases the pipe and
// lets the stream copiers finish.
func TestRunConvergesGrandchildrenHoldingThePipe(t *testing.T) {
	exe := testExecutable(t)
	state := t.TempDir()
	t.Setenv(childEnvSwitch, "1")
	t.Setenv(childEnvExitCode, "7")
	t.Setenv(childEnvGrandchild, "1")

	done := make(chan int, 1)
	go func() {
		done <- Run([]string{"--collector", exe, "--state-dir", state})
	}()
	var rc int
	select {
	case rc = <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Run hung waiting for a grandchild that holds the collector's pipe")
	}
	if rc != 7 {
		t.Fatalf("Run returned %d, want the root collector's forwarded exit code 7", rc)
	}
	out := readStateLog(t, state, outLogName)
	if !strings.Contains(out, "GRANDCHILD-STARTED") {
		t.Fatalf("the grandchild must have been spawned with the inherited pipe, got:\n%s", out)
	}
}

// TestJobTerminatesChildrenWhenHandleCloses pins the kill-on-close job
// semantics through the production spawn path: closing the helper's
// only job handle kills a bound, still-running child promptly — the
// guarantee that an aborted helper cannot leave an orphaned collector
// behind. Because the job binding happens at CreateProcess time
// (PROC_THREAD_ATTRIBUTE_JOB_LIST), there is no assignment step whose
// absence could leave the child unsupervised.
func TestJobTerminatesChildrenWhenHandleCloses(t *testing.T) {
	exe := testExecutable(t)
	state := t.TempDir()
	t.Setenv(childEnvSwitch, "1")
	t.Setenv(childEnvSleep, "30s")

	job, err := createKillOnCloseJob()
	if err != nil {
		t.Fatal(err)
	}
	child, err := startSupervisedCollector(job, options{collector: exe, stateDir: state})
	if err != nil {
		t.Fatalf("start supervised collector: %v", err)
	}

	started := time.Now()
	if err := windows.CloseHandle(job); err != nil {
		t.Fatalf("close job handle: %v", err)
	}
	_, err = child.wait()
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("closing the job handle must kill the child promptly, took %s", elapsed)
	}
	if err != nil {
		t.Fatalf("wait after job close: %v", err)
	}
	// Drain the child's captured stdout: the sleeping child must never
	// reach its post-sleep marker.
	output, _ := io.ReadAll(child.stdout)
	child.close()
	if strings.Contains(string(output), "CHILD-AFTER-SLEEP") {
		t.Fatal("the child outlived the closed job")
	}
}

// TestCollectorArgvAndFlagsContract pins the launch shape: the collector
// binary is addressed by exact path (never through a shell or PATH
// search) with the exact periodic argument array, and the creation
// flags keep the child console-free while enabling the extended
// startup info that carries the job binding.
func TestCollectorArgvAndFlagsContract(t *testing.T) {
	collector, state := backgroundFixtures(t)
	o := options{collector: collector, stateDir: state}

	wantArgv := []string{collector, "periodic", "--state-dir", state}
	if got := collectorArgv(o); !slices.Equal(got, wantArgv) {
		t.Fatalf("collector argv = %q, want %q", got, wantArgv)
	}
	if collectorCreationFlags&windows.CREATE_NO_WINDOW == 0 {
		t.Fatal("the collector must be created with CREATE_NO_WINDOW")
	}
	if collectorCreationFlags&windows.EXTENDED_STARTUPINFO_PRESENT == 0 {
		t.Fatal("the job-list attribute requires EXTENDED_STARTUPINFO_PRESENT")
	}
}

// TestRunRejectsSymlinkedLogPath pins the log hardening: a symlink in
// the log slot (or its archive slot) is refused rather than followed,
// so log writes cannot be redirected outside the state directory.
func TestRunRejectsSymlinkedLogPath(t *testing.T) {
	exe := testExecutable(t)
	state := t.TempDir()
	logsDir := filepath.Join(state, logsDirName)
	if err := os.MkdirAll(logsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "redirected.log")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(logsDir, outLogName)); err != nil {
		// Creating symlinks on Windows needs Developer Mode or
		// SeCreateSymbolicLinkPrivilege.
		if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.ERROR_PRIVILEGE_NOT_HELD) {
			t.Skipf("symlink creation not permitted: %v", err)
		}
		t.Fatal(err)
	}

	t.Setenv(childEnvSwitch, "1")
	t.Setenv(childEnvExitCode, "0")
	rc := Run([]string{"--collector", exe, "--state-dir", state})
	if rc != ExitLaunchFailure {
		t.Fatalf("a symlinked log path must fail closed with ExitLaunchFailure, got %d", rc)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal(err)
	}
}
