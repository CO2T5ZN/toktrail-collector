//go:build windows

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/scheduler"
)

// This opt-in test runs a real collector against local synthetic servers and
// registers only the task derived from its unique temporary state directory.
func TestWindowsConnectNativeIntegration(t *testing.T) {
	if os.Getenv("TOKTRAIL_WINDOWS_CONNECT_E2E") != "1" {
		t.Skip("set TOKTRAIL_WINDOWS_CONNECT_E2E=1 to run the native integration test")
	}
	root := filepath.Join(t.TempDir(), "space \u6d4b\u8bd5")
	home := filepath.Join(root, "home")
	state := filepath.Join(root, "state")
	input := filepath.Join(home, ".codex", "sessions")
	for _, dir := range []string{home, state, input} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(root, "toktrail.exe")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build collector: %v\n%s", err, out)
	}
	cfg := scheduler.TaskConfig{Platform: "windows", StateDir: state, HomeDir: home, Binary: binary, Interval: scheduler.DefaultInterval}
	installed, _, err := scheduler.IsInstalled(cfg)
	if err != nil || installed {
		t.Fatalf("refusing to overwrite an existing or unqueryable task: installed=%v err=%v", installed, err)
	}
	identity, err := scheduler.TaskIdentity(state)
	if err != nil {
		t.Fatal(err)
	}
	taskName := "\\TokTrailCollector-" + strings.TrimPrefix(identity, "toktrail-collector-")
	t.Cleanup(func() {
		present, _, queryErr := scheduler.IsInstalled(cfg)
		if queryErr != nil {
			t.Errorf("query temporary task during cleanup: %v", queryErr)
			return
		}
		if present {
			if out, err := exec.Command("schtasks", "/Delete", "/F", "/TN", taskName).CombinedOutput(); err != nil {
				t.Errorf("delete temporary task: %v\n%s", err, out)
			}
		}
	})
	url := connectCLIServers(t, []string{"Codex"})
	cmd := exec.CommandContext(ctx, binary, "connect", "--state-dir", state, "--json", url)
	cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home, "TOKTRAIL_HOME="+state)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			t.Fatalf("collector connect: %v\n%s", err, exitErr.Stderr)
		}
		t.Fatalf("collector connect: %v", err)
	}
	var result struct {
		StopReason string `json:"stop_reason"`
	}
	if err := json.Unmarshal(out, &result); err != nil || result.StopReason != "complete" {
		t.Fatalf("unexpected connect result %q: %v", out, err)
	}
	enabled, err := grants.New(state).Enabled()
	if err != nil || len(enabled) != 1 || filepath.Clean(enabled[0].Input) != filepath.Clean(input) {
		t.Fatalf("unexpected synthetic grants: %#v, %v", enabled, err)
	}
	installed, _, err = scheduler.IsInstalled(cfg)
	if err != nil || !installed {
		t.Fatalf("connect did not register its task: installed=%v err=%v", installed, err)
	}
}
