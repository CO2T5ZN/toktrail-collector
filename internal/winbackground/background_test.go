package winbackground

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// backgroundFixtures returns an absolute path to an existing regular
// file (standing in for the collector executable) and an absolute
// existing state directory. The collector file's content is irrelevant:
// argument validation only stats it, and the non-Windows stub never
// executes anything.
func backgroundFixtures(t *testing.T) (collector, stateDir string) {
	t.Helper()
	stateDir = t.TempDir()
	collector = filepath.Join(t.TempDir(), "collector.exe")
	if err := os.WriteFile(collector, []byte("stub"), 0o755); err != nil {
		t.Fatal(err)
	}
	return collector, stateDir
}

// captureStderr runs f with os.Stderr swapped for a pipe and returns
// everything f wrote.
func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	f()
	os.Stderr = old
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestBinaryNameMatchesGUIHelperContract(t *testing.T) {
	if BinaryName != "toktrail-background.exe" {
		t.Fatalf("BinaryName = %q, want the GUI-built helper name", BinaryName)
	}
}

func TestParseOptionsAcceptsValidArguments(t *testing.T) {
	collector, stateDir := backgroundFixtures(t)
	o, err := parseOptions([]string{"--collector", collector, "--state-dir", stateDir})
	if err != nil {
		t.Fatalf("valid arguments rejected: %v", err)
	}
	if o.collector != collector || o.stateDir != stateDir {
		t.Fatalf("parsed options = %+v, want the given values", o)
	}
}

func TestParseOptionsRejectsInvalidArguments(t *testing.T) {
	collector, stateDir := backgroundFixtures(t)
	cases := []struct {
		name string
		args []string
	}{
		{"no arguments", nil},
		{"missing collector flag", []string{"--state-dir", stateDir}},
		{"missing state-dir flag", []string{"--collector", collector}},
		{"collector without value", []string{"--collector"}},
		{"state-dir without value", []string{"--collector", collector, "--state-dir"}},
		{"duplicate collector", []string{"--collector", collector, "--collector", collector, "--state-dir", stateDir}},
		{"duplicate state-dir", []string{"--collector", collector, "--state-dir", stateDir, "--state-dir", stateDir}},
		{"relative collector path", []string{"--collector", "collector.exe", "--state-dir", stateDir}},
		{"missing collector file", []string{"--collector", filepath.Join(stateDir, "missing.exe"), "--state-dir", stateDir}},
		{"collector is a directory", []string{"--collector", stateDir, "--state-dir", stateDir}},
		{"relative state dir", []string{"--collector", collector, "--state-dir", "state"}},
		{"missing state dir", []string{"--collector", collector, "--state-dir", filepath.Join(stateDir, "missing")}},
		{"state dir is a file", []string{"--collector", collector, "--state-dir", collector}},
		{"unknown flag", []string{"--collector", collector, "--state-dir", stateDir, "--extra"}},
		{"positional argument", []string{"extra", "--collector", collector, "--state-dir", stateDir}},
	}
	for _, tc := range cases {
		if _, err := parseOptions(tc.args); err == nil {
			t.Errorf("%s: parseOptions accepted invalid arguments %q", tc.name, tc.args)
		}
	}
}

// TestRunReportsUsageFailuresWithoutEchoingArguments pins the safe-
// failure contract: argument failures exit with ExitUsage, print the
// usage line, and never echo caller-controlled values (which could
// contain anything) into the captured stderr a GUI might log.
func TestRunReportsUsageFailuresWithoutEchoingArguments(t *testing.T) {
	const canary = "TOKTRAIL-CANARY-9f2c17"
	var stderr string
	rc := 0
	stderr = captureStderr(t, func() {
		rc = Run([]string{"--collector", canary, "--state-dir", canary})
	})
	if rc != ExitUsage {
		t.Fatalf("Run with a relative collector path returned %d, want ExitUsage", rc)
	}
	if strings.Contains(stderr, canary) {
		t.Fatalf("failure output echoed the argument value %q:\n%s", canary, stderr)
	}
	if !strings.Contains(stderr, "toktrail-background:") {
		t.Fatalf("failure output must carry the fixed helper prefix:\n%s", stderr)
	}
	if !strings.Contains(stderr, "usage:") {
		t.Fatalf("failure output must include the usage line:\n%s", stderr)
	}
}

// TestRunStubFailsClosedOffWindows pins the non-Windows stub: valid
// arguments produce the dedicated unsupported-OS exit code and a fixed
// phrase, so `go test ./...` and accidental invocations stay well
// defined. The real Windows path is covered by
// background_windows_test.go.
func TestRunStubFailsClosedOffWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("covered by the native Windows tests in background_windows_test.go")
	}
	collector, stateDir := backgroundFixtures(t)
	var stderr string
	rc := 0
	stderr = captureStderr(t, func() {
		rc = Run([]string{"--collector", collector, "--state-dir", stateDir})
	})
	if rc != ExitUnsupportedOS {
		t.Fatalf("non-Windows Run returned %d, want ExitUnsupportedOS", rc)
	}
	if !strings.Contains(stderr, "only runs on Windows") {
		t.Fatalf("non-Windows Run must state the platform limit, got:\n%s", stderr)
	}
}
