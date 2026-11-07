package scheduler

import (
	"errors"
	"strings"
	"testing"
)

func TestWindowsTaskQueryUsesAuthoritativeUnicodeXML(t *testing.T) {
	name := `\TokTrailCollector-0123456789abcdef`
	script, err := windowsTaskQueryScript(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Schedule.Service", "$folder.GetTask('" + strings.TrimPrefix(name, `\`) + "')", "[string]$task.Xml", "System.Text.UTF8Encoding($false)", "[Console]::OpenStandardOutput()", "$stdout.Write($bytes, 0, $bytes.Length)", "-2147024894", "exit 44", "exit 45"} {
		if !strings.Contains(script, want) {
			t.Fatalf("query script missing %q", want)
		}
	}
	for _, unsafe := range []string{"schtasks", "Out-File", "Write-Output", "Invoke-Expression", "RegisterTask", "DeleteTask"} {
		if strings.Contains(script, unsafe) {
			t.Fatalf("query bridge must only read task XML and write raw UTF-8, found %q", unsafe)
		}
	}
	if !isTaskNotFound(errWindowsTaskMissing) || isTaskNotFound(errors.New("scheduled task XML query failed")) {
		t.Fatal("task absence and inaccessible/unqueryable task must stay distinct")
	}
}

func TestWindowsTaskQueryRejectsScriptInjection(t *testing.T) {
	for _, name := range []string{"", `\OtherTask`, `\TokTrailCollector-0123456789abcdeg`, `\TokTrailCollector-0123456789abcdef';throw 'bad`, `\TokTrailCollector-0123456789abcdef\other`, "\\TokTrailCollector-0123456789abcdef\n"} {
		if _, err := windowsTaskQueryScript(name); err == nil {
			t.Fatalf("unsafe task name accepted: %q", name)
		}
	}
}

func TestWindowsTaskOwnershipUsesDecodedFields(t *testing.T) {
	cfg, original := legacyWindowsTask(t)
	identity, _ := TaskIdentity(cfg.StateDir)
	encoded := strings.NewReplacer("&apos;", "&#39;", "&amp;", "&#x26;").Replace(original)
	if _, err := checkedWindowsTask(encoded, identity, cfg.StateDir); err != nil {
		t.Fatalf("equivalent XML entities must not invalidate task ownership: %v", err)
	}
	// The real Task Scheduler reserializes XML; no raw substring requirement
	// should reject an equivalent entity encoding of the same path.
	for _, fault := range []string{"uri", "exec path", "transcoded path", "trailing document"} {
		t.Run(fault, func(t *testing.T) {
			bad := original
			switch fault {
			case "uri":
				bad = strings.Replace(original, "<URI>"+xmlEscape(windowsTaskName(identity))+"</URI>", "<URI>\\Foreign</URI>", 1)
			case "exec path":
				start := strings.Index(bad, "<Arguments>")
				end := strings.Index(bad[start:], "</Arguments>") + start
				bad = bad[:start] + "<Arguments>periodic --state-dir \"foreign state\"" + bad[end:]
			case "transcoded path":
				bad = strings.ReplaceAll(original, xmlEscape(cfg.StateDir), "?irreversibly-lost-path?")
			case "trailing document":
				bad += "<Task/>"
			}
			if _, err := checkedWindowsTask(bad, identity, cfg.StateDir); err == nil {
				t.Fatalf("ownership must reject %s", fault)
			}
		})
	}
}

func TestWindowsQueryEncodingRoundTripUnicode(t *testing.T) {
	text := `<?xml version="1.0" encoding="UTF-16"?><Task><Description>C:\Users\RUNNER~1\目录 测试 é δ 😀 &amp; data</Description></Task>`
	for _, input := range [][]byte{[]byte(text), encodeUTF16LEWithBOM(text), encodeUTF16LEWithBOM(text)[2:]} {
		if got := decodeUTF16LEOrUTF8(input); got != text {
			t.Fatalf("Unicode task XML corrupted: %q", got)
		}
	}
}
