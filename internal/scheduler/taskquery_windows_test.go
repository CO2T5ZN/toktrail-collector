//go:build windows

package scheduler

import (
	"context"
	"encoding/base64"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestSchedulerXMLQueryUsesHiddenUnicodeBridge(t *testing.T) {
	name := `\TokTrailCollector-0123456789abcdef`
	cmd := schedulerOutputCommand("schtasks", "/Query", "/TN", name, "/XML")
	configureSchedulerCommand(cmd)
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.HideWindow || cmd.SysProcAttr.CreationFlags&0x08000000 == 0 {
		t.Fatal("query bridge must remain windowless")
	}
	if len(cmd.Args) != 8 || cmd.Args[6] != "-EncodedCommand" {
		t.Fatalf("unexpected query bridge arguments: %q", cmd.Args)
	}
	encoded, err := base64.StdEncoding.DecodeString(cmd.Args[7])
	if err != nil {
		t.Fatal(err)
	}
	script := decodeUTF16LEOrUTF8(encoded)
	if !strings.Contains(script, "$folder.GetTask('TokTrailCollector-0123456789abcdef')") || !strings.Contains(script, "[string]$task.Xml") {
		t.Fatal("bridge must read the exact validated task's Unicode XML")
	}
}

// Exercise the actual PowerShell stdout writer under CREATE_NO_WINDOW, without
// touching the task store. A native command's OEM code page must not truncate
// or replace Unicode state paths, regardless of the parent console encoding.
func TestSchedulerXMLBridgePreservesUnicodeWithoutConsole(t *testing.T) {
	payload := `<?xml version="1.0" encoding="UTF-16"?><Task><Description>C:\Users\RUNNER~1\目录 测试 é δ 😀 &amp; path</Description></Task>`
	script, err := windowsTaskQueryScript(`\TokTrailCollector-0123456789abcdef`)
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(script, "  $service =")
	end := strings.Index(script, "  $encoding =")
	if start < 0 || end <= start {
		t.Fatal("query bridge boundaries missing")
	}
	// Replace only COM lookup with a synthetic Unicode BSTR-like .NET string.
	// The exact production byte encoder and writer remain unchanged.
	script = script[:start] + "  $task = [pscustomobject]@{ Xml = '" + payload + "' }\n" + script[end:]
	encoded := base64.StdEncoding.EncodeToString(encodeUTF16LEWithBOM(script)[2:])
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded)
	configureSchedulerCommand(cmd)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("Unicode bridge execution failed: %v", err)
	}
	if !utf8.Valid(out) || string(out) != payload {
		t.Fatalf("windowless Unicode output was transcoded: %q", out)
	}
}

func TestSchedulerQueryMissingTaskIsNotLocalized(t *testing.T) {
	// This name is derived from a private temporary state. Reading a missing
	// task is safe and must neither register a task nor depend on its locale.
	identity, err := TaskIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, err = (ExecRunner{}).RunOutput("schtasks", "/Query", "/TN", windowsTaskName(identity), "/XML")
	if !errors.Is(err, errWindowsTaskMissing) {
		t.Fatalf("missing task must use the COM HRESULT sentinel, got %v", err)
	}
}
