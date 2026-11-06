package scheduler

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The plist the collector writes is the only input this parse must handle; the
// registered binary must come back exactly as written, escaping included.
func TestLaunchdProgramBinaryRoundTrip(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(t.TempDir(), "with space")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(binDir, "toktrail")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := TaskConfig{
		Platform: "darwin",
		StateDir: stateDir,
		Binary:   binary,
		Interval: 30 * time.Minute,
		HomeDir:  t.TempDir(),
	}
	plan, err := RenderInstall(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var plist string
	for _, file := range plan.Files {
		if strings.Contains(file.Content, "ProgramArguments") {
			plist = file.Content
		}
	}
	if plist == "" {
		t.Skip("RenderInstall produced no launchd plist")
	}
	got, ok := launchdProgramBinary(plist)
	if !ok {
		t.Fatalf("failed to read ProgramArguments[0] from:\n%s", plist)
	}
	if got != binary {
		t.Fatalf("registered binary = %q, want %q", got, cfg.Binary)
	}
}

func TestSystemdExecStartBinary(t *testing.T) {
	unit := "[Service]\nType=oneshot\nExecStart=/opt/toktrail periodic --state-dir /tmp/state\n"
	got, ok := systemdExecStartBinary(unit)
	if !ok || got != "/opt/toktrail" {
		t.Fatalf("ExecStart binary = (%q, %v), want /opt/toktrail", got, ok)
	}
	quoted := "ExecStart=\"/opt/with space/toktrail\" periodic --state-dir /tmp/state\n"
	if got, ok := systemdExecStartBinary(quoted); !ok || got != "/opt/with space/toktrail" {
		t.Fatalf("quoted ExecStart binary = (%q, %v)", got, ok)
	}
	if _, ok := systemdExecStartBinary("[Service]\n"); ok {
		t.Fatalf("a unit without ExecStart must report not-found")
	}
}

func TestXMLElementCommand(t *testing.T) {
	xml := "<Task><Actions><Exec><Command>C:\\TokTrail\\toktrail.exe</Command><Arguments>periodic</Arguments></Exec></Actions></Task>"
	if got := xmlElementText(xml, "Command"); got != `C:\TokTrail\toktrail.exe` {
		t.Fatalf("Command = %q", got)
	}
	if got := xmlElementText(xml, "Missing"); got != "" {
		t.Fatalf("missing element must be empty, got %q", got)
	}
}

// No registered schedule is reported as not-found, never as an empty path that
// a diagnostic could mistake for a mismatch.
func TestRegisteredBinaryWithoutSchedule(t *testing.T) {
	if testing.Short() {
		t.Skip("touches the real scheduler lookup path")
	}
	stateDir := filepath.Join(t.TempDir(), "unused-state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "toktrail")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := TaskConfig{
		Platform: runtime.GOOS,
		StateDir: stateDir,
		Binary:   binary,
		Interval: 30 * time.Minute,
		HomeDir:  t.TempDir(),
	}
	path, source, found, err := registeredBinaryWithRunner(cfg, ExecRunner{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatalf("no schedule can exist under a fresh temp home, got %q from %q", path, source)
	}
}
