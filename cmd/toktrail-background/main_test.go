package main

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"toktrail-collector/internal/winbackground"
)

// captureStdout runs f with os.Stdout swapped for a pipe and returns
// everything f wrote.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	f()
	os.Stdout = old
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestRunVersionFlag pins the GUI's probe contract: --version alone
// exits 0 and prints the helper's identity plus the ldflags-injected
// version (the default build says "dev").
func TestRunVersionFlag(t *testing.T) {
	var out string
	rc := 0
	out = captureStdout(t, func() {
		rc = run([]string{"--version"})
	})
	if rc != 0 {
		t.Fatalf("--version must exit 0, got %d", rc)
	}
	if want := "toktrail-background dev\n"; out != want {
		t.Fatalf("--version output = %q, want %q", out, want)
	}
}

// TestRunVersionSubcommand accepts the subcommand spelling used by the
// main collector binary.
func TestRunVersionSubcommand(t *testing.T) {
	var out string
	rc := 0
	out = captureStdout(t, func() {
		rc = run([]string{"version"})
	})
	if rc != 0 {
		t.Fatalf("version must exit 0, got %d", rc)
	}
	if want := "toktrail-background dev\n"; out != want {
		t.Fatalf("version output = %q, want %q", out, want)
	}
}

// TestRunRejectsUnknownArguments pins that unknown flags never start
// anything: they fall through to winbackground.Run's usage failure.
func TestRunRejectsUnknownArguments(t *testing.T) {
	if rc := run([]string{"--unexpected"}); rc != winbackground.ExitUsage {
		t.Fatalf("unknown flag must exit %d, got %d", winbackground.ExitUsage, rc)
	}
}

// TestRunDelegatesToBackgroundRun pins the delegation: everything that
// is not --version reaches winbackground.Run. Only checked off Windows,
// where a valid invocation would start a real collector; the Windows
// package tests cover the supervised run itself.
func TestRunDelegatesToBackgroundRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("covered by internal/winbackground's native Windows tests")
	}
	collector := filepath.Join(t.TempDir(), "collector.exe")
	if err := os.WriteFile(collector, []byte("stub"), 0o755); err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	rc := run([]string{"--collector", collector, "--state-dir", state})
	if rc != winbackground.ExitUnsupportedOS {
		t.Fatalf("delegated run must surface the stub exit code %d, got %d",
			winbackground.ExitUnsupportedOS, rc)
	}
}
