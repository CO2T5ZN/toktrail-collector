//go:build windows

package scheduler

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Use the actual Task Scheduler COM defaults without registering any task.
// This keeps Windows' normalization in the ordinary native suite instead of
// only discovering it behind the real-registration integration gate.
func TestWindowsPrincipalCOMDefaultWithoutRegistration(t *testing.T) {
	userID, err := windowsPrincipalUserID()
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	identity, err := TaskIdentity(state)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	text := renderWindowsTaskXML(windowsTaskName(identity), userID, executable, state, DefaultInterval)
	text = strings.Replace(text, "<RunLevel>LeastPrivilege</RunLevel>", "", 1)
	// PowerShell single-quoted strings preserve XML literally; doubled quotes
	// escape the only script delimiter. The program is then UTF-16LE encoded.
	literal := "'" + strings.ReplaceAll(text, "'", "''") + "'"
	script := "$ErrorActionPreference='Stop'; $service=New-Object -ComObject 'Schedule.Service'; $service.Connect(); $definition=$service.NewTask(0); $definition.XmlText=" + literal + "; if ($definition.Principal.RunLevel -ne 0) { throw 'omitted RunLevel did not default to LUA' }; $encoding=New-Object System.Text.UTF8Encoding($false); $bytes=$encoding.GetBytes([string]$definition.XmlText); $stream=[Console]::OpenStandardOutput(); $stream.Write($bytes,0,$bytes.Length); $stream.Flush()"
	encoded := base64.StdEncoding.EncodeToString(encodeUTF16LEWithBOM(script)[2:])
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded)
	configureSchedulerCommand(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("COM default normalization failed: %v\n%s", err, out)
	}
	_, doc, err := parseWindowsTask(string(out), state)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsRefreshPrincipal(doc, userID); err != nil {
		t.Fatalf("COM's least-privilege default must be accepted: %v", err)
	}
}
