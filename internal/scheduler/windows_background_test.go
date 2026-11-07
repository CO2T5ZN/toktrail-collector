package scheduler

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type refreshTaskRunner struct {
	xml       string
	creates   int
	failFirst bool
	calls     []string
}

func (r *refreshTaskRunner) Run(name string, args ...string) error {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if len(args) == 0 || args[0] != "/Create" {
		return errors.New("unexpected mutation")
	}
	var path string
	for i := range args {
		if args[i] == "/XML" && i+1 < len(args) {
			path = args[i+1]
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	r.xml = decodeUTF16LEOrUTF8(raw)
	r.creates++
	if r.failFirst && r.creates == 1 {
		return errors.New("synthetic registration failure")
	}
	return nil
}
func (r *refreshTaskRunner) RunOutput(name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	return []byte(r.xml), nil
}

func legacyWindowsTask(t *testing.T) (TaskConfig, string) {
	t.Helper()
	cfg, _, _ := testConfig(t)
	cfg.Platform = "windows"
	cfg.Interval = 7 * time.Minute
	if err := os.WriteFile(WindowsBackgroundPath(cfg.Binary), []byte("synthetic GUI launcher"), 0o700); err != nil {
		t.Fatal(err)
	}
	identity, _ := TaskIdentity(cfg.StateDir)
	user, _ := windowsPrincipalUserID()
	text := renderWindowsTaskXML(windowsTaskName(identity), user, cfg.Binary, cfg.StateDir, cfg.Interval)
	start := strings.Index(text, "<Exec>")
	end := strings.Index(text, "</Exec>") + len("</Exec>")
	legacy := "<Exec><Command>" + xmlEscape(cfg.Binary) + "</Command><Arguments>periodic --state-dir " + xmlEscape(windowsQuoteArg(cfg.StateDir)) + "</Arguments></Exec>"
	return cfg, text[:start] + legacy + text[end:]
}

func TestWindowsTaskRefreshPreservesTaskAndState(t *testing.T) {
	cfg, original := legacyWindowsTask(t)
	stateFile := filepath.Join(cfg.StateDir, "grants.json")
	const sentinel = "synthetic unchanged grant state"
	if err := os.WriteFile(stateFile, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &refreshTaskRunner{xml: original}
	info, err := RefreshWindows(InstallOptions{Config: cfg, Runner: runner})
	if err != nil || !info.Background || runner.creates != 1 {
		t.Fatalf("refresh = %+v err=%v creates=%d", info, err, runner.creates)
	}
	// Compare everything outside the one Exec action byte-for-byte.
	stripExec := func(s string) string {
		a := strings.Index(s, "<Exec>")
		b := strings.Index(s, "</Exec>") + len("</Exec>")
		return s[:a] + s[b:]
	}
	if stripExec(original) != stripExec(runner.xml) {
		t.Fatal("refresh changed the principal, trigger, settings or identity")
	}
	if !strings.Contains(runner.xml, "<Interval>PT7M</Interval>") {
		t.Fatal("custom interval was not preserved")
	}
	path, _, found, err := registeredBinaryWithRunner(cfg, runner)
	if err != nil || !found || path != cfg.Binary {
		t.Fatalf("doctor collector identity = %q found=%t err=%v", path, found, err)
	}
	if _, err := RefreshWindows(InstallOptions{Config: cfg, Runner: runner}); err != nil || runner.creates != 1 {
		t.Fatalf("refresh must be idempotent: creates=%d err=%v", runner.creates, err)
	}
	raw, err := os.ReadFile(stateFile)
	if err != nil || string(raw) != sentinel {
		t.Fatalf("grant state changed: %q %v", raw, err)
	}
}

func TestWindowsTaskRefreshRestoresOriginalOnFailure(t *testing.T) {
	cfg, original := legacyWindowsTask(t)
	runner := &refreshTaskRunner{xml: original, failFirst: true}
	_, err := RefreshWindows(InstallOptions{Config: cfg, Runner: runner})
	if err == nil || !strings.Contains(err.Error(), "original definition was restored") || runner.xml != original || runner.creates != 2 {
		t.Fatalf("restoration failed: creates=%d err=%v", runner.creates, err)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "/Delete") {
			t.Fatal("refresh must never delete the original task")
		}
	}
}

func TestWindowsTaskRefreshDryRunAndOwnership(t *testing.T) {
	t.Run("dry run", func(t *testing.T) {
		cfg, original := legacyWindowsTask(t)
		runner := &refreshTaskRunner{xml: original}
		var out bytes.Buffer
		if _, err := RefreshWindows(InstallOptions{Config: cfg, Runner: runner, DryRun: true, Out: &out}); err != nil {
			t.Fatal(err)
		}
		if runner.creates != 0 || !strings.Contains(out.String(), WindowsBackgroundBinary) {
			t.Fatal("dry run must print the background action without mutation")
		}
	})
	for _, fault := range []string{"state", "principal", "binary", "launcher"} {
		t.Run(fault, func(t *testing.T) {
			cfg, original := legacyWindowsTask(t)
			runner := &refreshTaskRunner{xml: original}
			switch fault {
			case "state":
				runner.xml = strings.ReplaceAll(original, xmlEscape(cfg.StateDir), xmlEscape(t.TempDir()))
			case "principal":
				runner.xml = strings.ReplaceAll(original, "<LogonType>InteractiveToken</LogonType>", "<LogonType>S4U</LogonType>")
			case "binary":
				runner.xml = strings.ReplaceAll(original, xmlEscape(cfg.Binary), xmlEscape(cfg.Binary+".other"))
			case "launcher":
				// Use a different install directory with no helper; leave the
				// existing task pointing to that same collector for this case.
				binary := filepath.Join(t.TempDir(), "toktrail.exe")
				if err := os.WriteFile(binary, []byte("synthetic collector"), 0o700); err != nil {
					t.Fatal(err)
				}
				runner.xml = strings.ReplaceAll(original, xmlEscape(cfg.Binary), xmlEscape(binary))
				cfg.Binary = binary
			}
			if _, err := RefreshWindows(InstallOptions{Config: cfg, Runner: runner}); err == nil || runner.creates != 0 {
				t.Fatalf("unsafe refresh must fail before mutation: err=%v creates=%d", err, runner.creates)
			}
		})
	}
}

func TestWindowsBackgroundArgumentRoundTrip(t *testing.T) {
	for _, arg := range []string{"", "plain", `C:\path with spaces\`, `C:\with\"quote`, "Unicode 测试 & 'path'", `C:\slashes\\and spaces\\`} {
		got, err := splitWindowsArguments(windowsQuoteArg(arg))
		if err != nil || len(got) != 1 || got[0] != arg {
			t.Fatalf("argument %q round-trip = %#v err=%v", arg, got, err)
		}
	}
	if _, err := splitWindowsArguments(`"unterminated`); err == nil {
		t.Fatal("unterminated task argument must fail")
	}
}
