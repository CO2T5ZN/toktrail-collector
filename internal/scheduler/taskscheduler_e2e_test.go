package scheduler

// Real Windows Task Scheduler end-to-end test.
//
// It registers, queries, and deletes a real schtasks task through the
// production ExecRunner (no fakes), proving that the generated task XML
// is accepted by schtasks /Create /XML — the UTF-8 form previously failed
// with "unable to switch encoding" — and that the registered definition
// round-trips identity, state dir, principal, and interval.
//
// Gating:
//   - Windows only; every other platform skips.
//   - TOKTRAIL_WINDOWS_SCHEDULER_E2E=1 must be set explicitly, so normal
//     unit-test runs (`go test ./...`, cross-platform CI matrix) never
//     mutate the real scheduler. A dedicated Windows CI job opts in.
//
// Safety:
//   - The task name is unique per run: the identity is derived from a
//     fresh random temp state directory, so it can never collide with an
//     existing task; the test additionally refuses to run if a task with
//     that exact name already exists.
//   - Cleanup deletes only that exact task name (never a wildcard or
//     another task) and the private temp directory; production tasks and
//     other users' state are never touched.
//   - The scheduled command is a synthetic collector launched by the real
//     GUI helper. It reads only its explicit temporary state directory, records
//     whether a console exists, writes fixed log lines, and exits with code 7.
//     The test explicitly starts it and checks Task Scheduler's result; it
//     never binds, scans a user home, or uploads usage.
//   - schtasks must be on PATH; after the opt-in gates every failure
//     (missing schtasks, unqueryable store, registration, verification)
//     is a hard failure, never a skip, because the operator explicitly
//     asked for this test and a green skip would hide a broken setup.

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWindowsSchedulerNativeIntegration(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-only: real schtasks registration")
	}
	if os.Getenv("TOKTRAIL_WINDOWS_SCHEDULER_E2E") != "1" {
		t.Skip("set TOKTRAIL_WINDOWS_SCHEDULER_E2E=1 to run the real schtasks integration test")
	}
	if _, err := exec.LookPath("schtasks"); err != nil {
		t.Fatalf("schtasks is not available in this environment: %v", err)
	}

	// A unique-per-run root directory whose path contains spaces and
	// non-ASCII characters. TMP is what os.TempDir() resolves on Windows,
	// so pointing it here also puts the scratch XML handed to schtasks
	// behind spaces and non-ASCII characters, exercising the argument
	// array (no shell) path end to end.
	root, err := os.MkdirTemp(os.TempDir(), "TokTrail E2E 状态 目錄 ")
	if err != nil {
		t.Fatalf("create temp root: %v", err)
	}
	t.Setenv("TMP", root)
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	stateDir := filepath.Join(root, "état 目录 with spaces δ")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("create state dir: %v", err)
	}
	// A synthetic collector touches only this test's state directory. Run it
	// through the real GUI launcher to verify console, logs and exit status.
	binary := buildWindowsTaskProbe(t, root)
	cfg := TaskConfig{
		Platform: "windows",
		StateDir: stateDir,
		Binary:   binary,
		Interval: DefaultInterval,
		HomeDir:  filepath.Join(root, "home"),
	}

	plan, err := RenderInstall(cfg)
	if err != nil {
		t.Fatalf("render install plan: %v", err)
	}
	taskName := windowsTaskName(plan.TaskName)

	// Pre-check: the task name is unique per run, but never guess. If a
	// task with this exact name already exists, refuse to touch it
	// (install would force overwrite). If the store cannot be queried at
	// all, fail instead of mistaking "cannot query" for "does not exist"
	// (and instead of skipping: this run is explicitly opted in, so an
	// unusable scheduler is a real failure, never a green skip).
	if installed, _, qerr := IsInstalled(cfg); qerr != nil {
		t.Fatalf("cannot determine whether task %s exists; refusing to touch the scheduler: %v", taskName, qerr)
	} else if installed {
		t.Fatalf("refusing to run: task %s already exists", taskName)
	}

	// Last-resort cleanup: delete by the exact unique task name only, so
	// no existing task can ever be affected by a mid-test failure. The
	// only clean outcomes are a successful delete or a not-found delete;
	// any other delete failure is an error, because a failed follow-up
	// query does not prove deletion (it may be the same access failure),
	// so an unconfirmable state is reported too.
	t.Cleanup(func() {
		if derr := (ExecRunner{}).Run("schtasks", "/Delete", "/F", "/TN", taskName); derr != nil && !isTaskNotFound(derr) {
			if _, serr := (ExecRunner{}).RunOutput("schtasks", "/Query", "/TN", taskName); serr == nil {
				t.Errorf("cleanup: task %s leaked: delete failed: %v", taskName, derr)
			} else {
				t.Errorf("cleanup: cannot confirm task %s was deleted: delete failed: %v (follow-up query: %v)", taskName, derr, serr)
			}
		}
	})

	// 1. Real install: schtasks /Create /F /XML must accept the UTF-16LE
	// (BOM) task definition this package generates.
	if _, err := Install(InstallOptions{Config: cfg}); err != nil {
		t.Fatalf("real schtasks install failed: %v", err)
	}
	for _, file := range plan.Files {
		if _, serr := os.Stat(file.Path); !os.IsNotExist(serr) {
			t.Fatalf("scratch XML must be removed after a successful install: %s", file.Path)
		}
	}

	// 2. Real query: the task exists, passes the ownership check against
	// this identity and state dir, and the non-ASCII state dir survived
	// the UTF-16 round trip intact.
	installed, found, err := IsInstalled(cfg)
	if err != nil {
		t.Fatalf("IsInstalled after install: %v", err)
	}
	if !installed {
		t.Fatalf("task not reported as installed: %v", found)
	}
	xmlOut, err := (ExecRunner{}).RunOutput("schtasks", "/Query", "/TN", taskName, "/XML")
	if err != nil {
		t.Fatalf("query task XML: %v", err)
	}
	xmlText := decodeUTF16LEOrUTF8(xmlOut)
	// The registered XML carries the task name only in its schtasks form
	// (\TokTrailCollector-<hash>); the raw identity correspondence is
	// already proven by the ownership check inside IsInstalled above.
	for _, want := range []string{taskName, stateDir, formatWindowsInterval(cfg.Interval)} {
		if !strings.Contains(xmlText, want) {
			t.Fatalf("registered task XML is missing %q (encoding or content regression):\n%s", want, xmlText)
		}
	}
	// The principal must carry the non-empty, system-resolved identity.
	userID, err := windowsPrincipalUserID()
	if err != nil {
		t.Fatalf("resolve principal user identity: %v", err)
	}
	if !strings.Contains(xmlText, xmlEscape(userID)) {
		t.Fatalf("registered task XML is missing principal UserId %q:\n%s", userID, xmlText)
	}

	// 3. Execute the task: no console may be allocated, stdout/stderr must
	// be captured, and Task Scheduler must receive the child's exit code.
	runWindowsTaskProbe(t, cfg, taskName)

	// 4. Real uninstall: the task is gone from the store.
	if _, err := Uninstall(UninstallOptions{Config: cfg}); err != nil {
		t.Fatalf("real schtasks uninstall failed: %v", err)
	}
	if out, qerr := (ExecRunner{}).RunOutput("schtasks", "/Query", "/TN", taskName); qerr == nil {
		t.Fatalf("task %s is still queryable after uninstall (output: %q)", taskName, string(out))
	}
}
