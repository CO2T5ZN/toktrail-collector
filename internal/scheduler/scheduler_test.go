package scheduler

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// recordingRunner records every command it is asked to run and can be
// primed to fail or return output for specific command names.
type recordingRunner struct {
	runs    []string
	failers map[string]error
	outputs map[string][]byte
}

func (r *recordingRunner) Run(name string, args ...string) error {
	_, err := r.RunOutput(name, args...)
	return err
}

func (r *recordingRunner) RunOutput(name string, args ...string) ([]byte, error) {
	line := name
	if len(args) > 0 {
		line += " " + strings.Join(args, " ")
	}
	r.runs = append(r.runs, line)
	if r.failers != nil {
		if err, ok := r.failers[name]; ok {
			return nil, err
		}
	}
	if r.outputs != nil {
		if out, ok := r.outputs[line]; ok {
			return out, nil
		}
		if out, ok := r.outputs[name]; ok {
			return out, nil
		}
	}
	return nil, nil
}

// failingRunner fails every command; used for uninstall tolerance tests.
type failingRunner struct{ runs []string }

func (r *failingRunner) Run(name string, args ...string) error {
	_, err := r.RunOutput(name, args...)
	return err
}

func (r *failingRunner) RunOutput(name string, args ...string) ([]byte, error) {
	r.runs = append(r.runs, name)
	return nil, errors.New("command unavailable")
}

// testConfig builds a valid TaskConfig rooted at temp paths so tests never
// touch the real home directory. It also pins the Windows principal
// identity so tests that simulate the Windows renderer render the same
// task definition on every platform.
func testConfig(t *testing.T) (TaskConfig, string, string) {
	t.Helper()
	stubWindowsPrincipalUser(t, "S-1-5-21-1000000000-1000000000-1000000000-1001")
	root := t.TempDir()
	stateDir := filepath.Join(root, "state dir with spaces & 'quotes'")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "bin", "toktrail-collector")
	if err := os.MkdirAll(filepath.Dir(binary), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return TaskConfig{
		Platform: runtime.GOOS,
		StateDir: stateDir,
		Binary:   binary,
		Interval: DefaultInterval,
		HomeDir:  filepath.Join(root, "home"),
	}, root, stateDir
}

// stubWindowsPrincipalUser installs a deterministic Windows principal
// identity for tests that simulate the Windows renderer, which cannot
// resolve a real Windows account SID on non-Windows hosts. The production
// resolver is restored afterwards.
func stubWindowsPrincipalUser(t *testing.T, id string) {
	t.Helper()
	orig := windowsPrincipalUserID
	windowsPrincipalUserID = func() (string, error) { return id, nil }
	t.Cleanup(func() { windowsPrincipalUserID = orig })
}

// parseXMLText checks that text is well-formed XML. The Windows task XML
// declares UTF-16 (its on-disk encoding) while the in-memory text is
// UTF-8, so a pass-through CharsetReader is installed: this validates
// document structure, not the on-disk byte encoding (encodeFileContent
// covers that).
func parseXMLText(text string) error {
	dec := xml.NewDecoder(strings.NewReader(text))
	dec.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	var doc any
	return dec.Decode(&doc)
}

func planOrFatal(t *testing.T, cfg TaskConfig) Plan {
	t.Helper()
	plan, err := RenderInstall(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// ---------------------------------------------------------------------------
// identity
// ---------------------------------------------------------------------------

func TestTaskIdentityDeterministicAndDistinct(t *testing.T) {
	a, err := TaskIdentity("/tmp/a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := TaskIdentity("/tmp/b")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("expected distinct identities, got %s twice", a)
	}
	if !strings.HasPrefix(a, "toktrail-collector-") {
		t.Fatalf("unexpected identity prefix: %s", a)
	}
	again, err := TaskIdentity("/tmp/a")
	if err != nil || again != a {
		t.Fatalf("identity not deterministic: %s vs %s (%v)", a, again, err)
	}
}

// ---------------------------------------------------------------------------
// renderers
// ---------------------------------------------------------------------------

func TestLaunchdPlistParsesAsXMLAndEscapesMetacharacters(t *testing.T) {
	cfg, _, stateDir := testConfig(t)
	cfg.Platform = "darwin"
	plan := planOrFatal(t, cfg)
	if len(plan.Files) != 1 {
		t.Fatalf("expected one plist file, got %#v", plan.Files)
	}
	plist := plan.Files[0]
	if plist.Path != filepath.Join(cfg.HomeDir, "Library", "LaunchAgents", plan.TaskName+".plist") {
		t.Fatalf("unexpected plist path: %s", plist.Path)
	}
	// The whole document must parse as XML even with metacharacters in
	// the state directory path.
	var doc any
	if err := xml.Unmarshal([]byte(plist.Content), &doc); err != nil {
		t.Fatalf("plist does not parse as XML: %v\n%s", err, plist.Content)
	}
	if !strings.Contains(plist.Content, xmlEscape(stateDir)) {
		t.Fatal("state dir missing from plist")
	}
	if !strings.Contains(plist.Content, "<key>Label</key>\n\t<string>"+plan.TaskName+"</string>") {
		t.Fatal("label missing from plist")
	}
	if !strings.Contains(plist.Content, "<false/>") {
		t.Fatal("RunAtLoad must be false so nothing runs at install time")
	}
	if !strings.Contains(plist.Content, fmt.Sprintf("<integer>%d</integer>", int(DefaultInterval/time.Second))) {
		t.Fatal("StartInterval missing")
	}
	// Program arguments must be separate strings, not a shell line.
	if strings.Contains(plist.Content, "periodic --state-dir") {
		t.Fatal("program arguments must be encoded as separate array items")
	}
}

func TestSystemdUnitsEscapeStateDirWithSpacesAndMetacharacters(t *testing.T) {
	cfg, _, stateDir := testConfig(t)
	cfg.Platform = "linux"
	plan := planOrFatal(t, cfg)
	if len(plan.Files) != 2 {
		t.Fatalf("expected service+timer files, got %#v", plan.Files)
	}
	var service, timer string
	for _, file := range plan.Files {
		switch filepath.Ext(file.Path) {
		case ".service":
			service = file.Content
		case ".timer":
			timer = file.Content
		}
	}
	if service == "" || timer == "" {
		t.Fatalf("missing units: service=%q timer=%q", service, timer)
	}
	if !strings.Contains(service, "Type=oneshot") {
		t.Fatal("service must be oneshot (complete-exit)")
	}
	if !strings.Contains(service, plan.TaskName) {
		t.Fatal("service must carry the task identity for owned-file checks")
	}
	if !strings.Contains(service, stateDir) {
		t.Fatal("service must carry the state dir marker for owned-file checks")
	}
	// ExecStart with a spaced path must be quoted, never shell-escaped.
	quoted := systemdEscapeArg(stateDir)
	if !strings.Contains(service, "ExecStart="+systemdEscapeArg(cfg.Binary)+" periodic --state-dir "+quoted) {
		t.Fatalf("unexpected ExecStart in:\n%s", service)
	}
	if strings.Contains(service, "\\ ") {
		t.Fatal("ExecStart must use systemd quoting, not shell backslash escaping")
	}
	if !strings.Contains(timer, "Unit="+plan.TaskName+".service") {
		t.Fatal("timer must target the service unit")
	}
	if !strings.Contains(timer, "OnUnitActiveSec=30m") {
		t.Fatal("timer must repeat at the configured interval")
	}
	unitDir := filepath.Join(cfg.HomeDir, ".config", "systemd", "user")
	for _, path := range plan.RemoveFiles {
		if !strings.HasPrefix(path, unitDir) {
			t.Fatalf("remove path outside user unit dir: %s", path)
		}
	}
}

func TestWindowsTaskXMLParsesAndQuotesStateDir(t *testing.T) {
	cfg, _, stateDir := testConfig(t)
	cfg.Platform = "windows"
	plan := planOrFatal(t, cfg)
	if len(plan.Files) != 1 || !plan.Files[0].Temp {
		t.Fatalf("windows plan must write exactly one scratch (Temp) XML file: %#v", plan.Files)
	}
	file := plan.Files[0]
	// The whole document must parse as XML even with metacharacters in
	// the state directory path.
	if err := parseXMLText(file.Content); err != nil {
		t.Fatalf("task XML does not parse: %v\n%s", err, file.Content)
	}
	if len(plan.RemoveFiles) != 0 {
		t.Fatalf("windows plan must not own persistent files: %#v", plan.RemoveFiles)
	}
	if !strings.Contains(file.Content, "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>") {
		t.Fatal("overlapping instances must be refused by policy as well as the process lock")
	}
	// On disk the XML must be UTF-16LE with a BOM and a matching
	// declaration: schtasks /Create /XML rejects UTF-8 task definitions
	// with "unable to switch encoding", while UTF-16LE + BOM is the form
	// schtasks itself exports via /Query /XML.
	if file.Encoding != EncodingUTF16LE {
		t.Fatalf("windows task XML must be written as UTF-16LE, got encoding %q", file.Encoding)
	}
	data, err := encodeFileContent(file)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 2 || data[0] != 0xFF || data[1] != 0xFE {
		t.Fatal("encoded task XML must start with a UTF-16LE BOM (FF FE)")
	}
	if round := decodeUTF16LEOrUTF8(data); round != file.Content {
		t.Fatalf("UTF-16LE encoding must round-trip the content exactly;\nround:\n%s", round)
	}
	if !strings.HasPrefix(file.Content, `<?xml version="1.0" encoding="UTF-16"?>`) {
		t.Fatalf("declaration must match the UTF-16 on-disk encoding:\n%s", file.Content)
	}
	// The principal must name a concrete account: the schema types UserId
	// as nonEmptyString, and LogonType is only meaningful with a UserId.
	if strings.Contains(file.Content, "<UserId></UserId>") {
		t.Fatal("empty UserId element is invalid per the Task Scheduler schema (nonEmptyString)")
	}
	if !strings.Contains(file.Content, "<UserId>S-1-5-21-1000000000-1000000000-1000000000-1001</UserId>") {
		t.Fatalf("principal must carry the resolved user id:\n%s", file.Content)
	}
	if !strings.Contains(file.Content, "<LogonType>InteractiveToken</LogonType>") {
		t.Fatal("principal must keep the interactive-token (no stored credentials) semantics")
	}
	if !strings.Contains(file.Content, "<RunLevel>LeastPrivilege</RunLevel>") {
		t.Fatal("principal must keep least-privilege semantics")
	}
	// Repetition intervals are xs:duration values with uppercase
	// designators; the schema bounds them to PT1M..P31D.
	if !strings.Contains(file.Content, "<Interval>PT30M</Interval>") {
		t.Fatalf("repetition interval must be an uppercase-designator duration (PT30M):\n%s", file.Content)
	}
	if !strings.Contains(file.Content, xmlEscape(stateDir)) {
		t.Fatal("state dir missing from task XML")
	}
	// The schtasks command must pass the XML file and task name as
	// separate argv entries.
	cmd := plan.Commands[0]
	if cmd.Name != "schtasks" {
		t.Fatalf("expected schtasks, got %#v", cmd)
	}
	for _, arg := range cmd.Args {
		if strings.Contains(arg, " && ") || strings.Contains(arg, "|") || strings.HasPrefix(arg, "\"") {
			t.Fatalf("schtasks args must be literal argv entries, got %q", arg)
		}
	}
	if !containsArg(cmd.Args, "/XML") || !containsArg(cmd.Args, "/TN") {
		t.Fatalf("schtasks must use /XML and /TN, got %#v", cmd.Args)
	}
}

func TestWindowsTaskXMLEncodingStaysUTF8Elsewhere(t *testing.T) {
	// Non-Windows plans and the zero encoding keep the exact UTF-8 bytes
	// of the content on disk (other platforms' behavior is unchanged).
	cfg, _, _ := testConfig(t)
	cfg.Platform = "darwin"
	plan := planOrFatal(t, cfg)
	if plan.Files[0].Encoding != "" && plan.Files[0].Encoding != EncodingUTF8 {
		t.Fatalf("launchd plist must keep the default UTF-8 encoding, got %q", plan.Files[0].Encoding)
	}
	data, err := encodeFileContent(plan.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != plan.Files[0].Content {
		t.Fatal("UTF-8 encoding must be byte-identical to the content")
	}
	// An unknown encoding must fail closed before any bytes are written.
	_, err = encodeFileContent(FileWrite{Path: "x", Content: "x", Encoding: "latin-1"})
	if err == nil {
		t.Fatal("unsupported file encoding must fail closed")
	}
}

func TestFormatWindowsIntervalUppercaseDurationDesignators(t *testing.T) {
	cases := map[time.Duration]string{
		MinInterval:            "PT1M",
		DefaultInterval:        "PT30M",
		90 * time.Second:       "PT1M", // sub-minute remainder keeps the historical truncation
		7 * 24 * time.Hour:     "PT10080M",
		windowsMaxTaskInterval: "PT44640M",
	}
	for in, want := range cases {
		if got := formatWindowsInterval(in); got != want {
			t.Errorf("formatWindowsInterval(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestWindowsIntervalRangeFailsClosed(t *testing.T) {
	cfg, _, _ := testConfig(t)
	cfg.Platform = "windows"
	cfg.Interval = windowsMaxTaskInterval + time.Minute
	runner := &recordingRunner{}
	if _, err := RenderInstall(cfg); err == nil {
		t.Fatal("expected render to fail closed for an interval above the Task Scheduler maximum of 31 days")
	}
	if _, err := Install(InstallOptions{Config: cfg, Runner: runner}); err == nil {
		t.Fatal("expected install to fail closed for an out-of-range interval")
	}
	if len(runner.runs) != 0 {
		t.Fatalf("no command may run for an out-of-range interval: %v", runner.runs)
	}
	// In-range non-whole-minute intervals keep the historical truncation
	// behavior (90s schedules as PT1M) instead of newly failing.
	cfg.Interval = 90 * time.Second
	plan, err := RenderInstall(cfg)
	if err != nil {
		t.Fatalf("in-range non-whole-minute interval must keep rendering: %v", err)
	}
	if !strings.Contains(plan.Files[0].Content, "<Interval>PT1M</Interval>") {
		t.Fatalf("sub-minute remainder must truncate to whole minutes:\n%s", plan.Files[0].Content)
	}
}

func TestWindowsPrincipalResolutionFailsClosed(t *testing.T) {
	cfg, _, _ := testConfig(t)
	cfg.Platform = "windows"
	orig := windowsPrincipalUserID
	t.Cleanup(func() { windowsPrincipalUserID = orig })
	// A resolver failure must abort the render before any file or command.
	windowsPrincipalUserID = func() (string, error) { return "", errors.New("no process token") }
	runner := &recordingRunner{}
	if _, err := RenderInstall(cfg); err == nil {
		t.Fatal("expected render to fail when the principal identity cannot be resolved")
	}
	if _, err := Install(InstallOptions{Config: cfg, Runner: runner}); err == nil {
		t.Fatal("expected install to fail when the principal identity cannot be resolved")
	}
	if len(runner.runs) != 0 {
		t.Fatalf("no command may run without a principal identity: %v", runner.runs)
	}
	// An empty identity violates the schema's nonEmptyString UserId and
	// must also fail closed.
	windowsPrincipalUserID = func() (string, error) { return "  ", nil }
	if _, err := RenderInstall(cfg); err == nil {
		t.Fatal("expected render to fail on an empty principal identity")
	}
	// Uninstall never renders XML, so it must keep working without an
	// identity (uninstalling must never be blocked by principal issues).
	if _, err := RenderUninstall(cfg); err != nil {
		t.Fatalf("uninstall must not need the principal identity: %v", err)
	}
}

func containsArg(args []string, target string) bool {
	for _, arg := range args {
		if arg == target {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// validation
// ---------------------------------------------------------------------------

func TestValidateRejectsBadConfigsBeforeAnyMutation(t *testing.T) {
	cfg, _, _ := testConfig(t)
	cases := map[string]func(*TaskConfig){
		"relative state dir": func(c *TaskConfig) { c.StateDir = "relative/state" },
		"missing state dir":  func(c *TaskConfig) { c.StateDir = filepath.Join(t.TempDir(), "absent") },
		"relative binary":    func(c *TaskConfig) { c.Binary = "toktrail" },
		"missing binary":     func(c *TaskConfig) { c.Binary = filepath.Join(t.TempDir(), "nope") },
		"short interval":     func(c *TaskConfig) { c.Interval = 30 * time.Second },
		"unknown platform":   func(c *TaskConfig) { c.Platform = "plan9" },
		"missing home":       func(c *TaskConfig) { c.HomeDir = "" },
		"relative home":      func(c *TaskConfig) { c.HomeDir = "home" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			mutated := cfg
			mutate(&mutated)
			if err := mutated.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
			// Install must refuse before writing anything.
			runner := &recordingRunner{}
			_, err := Install(InstallOptions{Config: mutated, Runner: runner})
			if err == nil {
				t.Fatal("expected install to fail")
			}
			if len(runner.runs) != 0 {
				t.Fatalf("no command may run on validation failure: %v", runner.runs)
			}
			// And no file may exist anywhere under the fake home.
			homeEntries, readErr := os.ReadDir(cfg.HomeDir)
			if readErr == nil && len(homeEntries) > 0 {
				t.Fatalf("validation failure left files in home: %v", homeEntries)
			}
		})
	}
}

func TestPlanPathValidationRefusesEscapes(t *testing.T) {
	cfg, _, _ := testConfig(t)
	cfg.Platform = "darwin"
	plan, err := RenderInstall(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// A hostile plan writing outside the scheduler base must be refused
	// before any file is touched.
	plan.Files = append(plan.Files, FileWrite{Path: filepath.Join(cfg.HomeDir, "..", "escape.txt"), Content: "x", Mode: 0o600})
	if err := validatePlanPaths(plan); err == nil {
		t.Fatal("expected write-path validation to refuse the escape")
	}
	// And on windows the scratch file must stay inside the temp base.
	winCfg := cfg
	winCfg.Platform = "windows"
	winPlan, err := RenderInstall(winCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePlanPaths(winPlan); err != nil {
		t.Fatalf("windows scratch file must be inside temp dir: %v", err)
	}
}

// ---------------------------------------------------------------------------
// install success / rollback / idempotent uninstall
// ---------------------------------------------------------------------------

func installOrFatal(t *testing.T, cfg TaskConfig, runner *recordingRunner) Plan {
	t.Helper()
	plan, err := Install(InstallOptions{Config: cfg, Runner: runner})
	if err != nil {
		t.Fatalf("install failed: %v", err)
	}
	return plan
}

func TestInstallWritesFilesAndRunsCommandsInOrder(t *testing.T) {
	cfg, _, _ := testConfig(t)
	cfg.Platform = "linux"
	runner := &recordingRunner{}
	plan := installOrFatal(t, cfg, runner)

	for _, dir := range plan.EnsureDirs {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			t.Fatalf("ensure dir missing: %s (%v)", dir, err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
			t.Fatalf("ensure dir must be 0700, got %#o", info.Mode().Perm())
		}
	}
	for _, file := range plan.Files {
		info, err := os.Stat(file.Path)
		if err != nil || info.IsDir() {
			t.Fatalf("file missing after install: %s (%v)", file.Path, err)
		}
	}
	if len(runner.runs) < 2 {
		t.Fatalf("expected systemctl commands to run, got %v", runner.runs)
	}
	for _, line := range runner.runs {
		if !strings.HasPrefix(line, "systemctl --user ") {
			t.Fatalf("unexpected command on linux: %s", line)
		}
	}
	if !strings.Contains(strings.Join(runner.runs, "\n"), "daemon-reload") {
		t.Fatal("expected daemon-reload before enable")
	}

	// Re-install must be idempotent: same runner succeeds again.
	installOrFatal(t, cfg, &recordingRunner{})
}

func TestInstallCommandFailureRollsBackFiles(t *testing.T) {
	cfg, _, _ := testConfig(t)
	cfg.Platform = "darwin"
	runner := &recordingRunner{failers: map[string]error{"launchctl": errors.New("bootstrap refused")}}
	_, err := Install(InstallOptions{Config: cfg, Runner: runner})
	if err == nil || !strings.Contains(err.Error(), "register") && !strings.Contains(err.Error(), "bootstrap") {
		t.Fatalf("expected install failure, got %v", err)
	}
	// Every owned file must be gone after rollback.
	plan, _ := RenderInstall(cfg)
	for _, file := range plan.Files {
		if _, statErr := os.Stat(file.Path); !os.IsNotExist(statErr) {
			t.Fatalf("file survived rollback: %s", file.Path)
		}
	}
	// Undo commands (best-effort bootout) must have been attempted.
	sawUndo := false
	for _, line := range runner.runs {
		if strings.Contains(line, "bootout") {
			sawUndo = true
		}
	}
	if !sawUndo {
		t.Fatalf("rollback did not run undo commands: %v", runner.runs)
	}
}

func TestInstallWindowsCleansUpTempXML(t *testing.T) {
	cfg, _, _ := testConfig(t)
	cfg.Platform = "windows"
	plan := installOrFatal(t, cfg, &recordingRunner{})
	for _, file := range plan.Files {
		if !file.Temp {
			continue
		}
		if _, err := os.Stat(file.Path); !os.IsNotExist(err) {
			t.Fatalf("temp XML must be deleted after success: %s", file.Path)
		}
	}
}

func TestInstallWindowsDeletesTempXMLEvenOnFailure(t *testing.T) {
	cfg, _, _ := testConfig(t)
	cfg.Platform = "windows"
	runner := &recordingRunner{failers: map[string]error{"schtasks": errors.New("registration refused")}}
	_, err := Install(InstallOptions{Config: cfg, Runner: runner})
	if err == nil {
		t.Fatal("expected install failure")
	}
	plan, _ := RenderInstall(cfg)
	for _, file := range plan.Files {
		if _, statErr := os.Stat(file.Path); !os.IsNotExist(statErr) {
			t.Fatalf("temp XML survived failed install: %s", file.Path)
		}
	}
}

// captureXMLRunner captures the on-disk bytes of the scratch XML at the
// moment schtasks /Create runs, proving the file handed to schtasks is
// UTF-16LE with a BOM (not the readable UTF-8 text kept in memory).
type captureXMLRunner struct {
	recordingRunner
	xmlPath  string
	captured []byte
	sawFile  bool
}

func (r *captureXMLRunner) Run(name string, args ...string) error {
	_, err := r.RunOutput(name, args...)
	return err
}

func (r *captureXMLRunner) RunOutput(name string, args ...string) ([]byte, error) {
	if name == "schtasks" && containsArg(args, "/Create") {
		if data, err := os.ReadFile(r.xmlPath); err == nil {
			r.sawFile = true
			r.captured = data
		}
	}
	return r.recordingRunner.RunOutput(name, args...)
}

func TestInstallWritesWindowsXMLAsUTF16LEOnDisk(t *testing.T) {
	cfg, _, _ := testConfig(t)
	cfg.Platform = "windows"
	plan := planOrFatal(t, cfg)
	runner := &captureXMLRunner{xmlPath: plan.Files[0].Path}
	if _, err := Install(InstallOptions{Config: cfg, Runner: runner}); err != nil {
		t.Fatalf("install failed: %v", err)
	}
	if !runner.sawFile {
		t.Fatal("schtasks /Create must run while the scratch XML exists on disk")
	}
	if len(runner.captured) < 2 || runner.captured[0] != 0xFF || runner.captured[1] != 0xFE {
		head := runner.captured
		if len(head) > 4 {
			head = head[:4]
		}
		t.Fatalf("scratch XML on disk must start with a UTF-16LE BOM (FF FE), got % X", head)
	}
	if decoded := decodeUTF16LEOrUTF8(runner.captured); decoded != plan.Files[0].Content {
		t.Fatal("scratch XML on disk must be exactly the UTF-16LE encoding of the rendered definition")
	}
}

func TestUninstallIdempotentAndToleratesCommandErrors(t *testing.T) {
	cfg, _, _ := testConfig(t)
	cfg.Platform = "linux"
	installOrFatal(t, cfg, &recordingRunner{})
	runner := &failingRunner{}
	if _, err := Uninstall(UninstallOptions{Config: cfg, Runner: runner}); err != nil {
		t.Fatalf("uninstall must tolerate command errors, got %v", err)
	}
	if len(runner.runs) == 0 {
		t.Fatal("deactivate commands must still be attempted")
	}
	plan, _ := RenderUninstall(cfg)
	for _, path := range plan.RemoveFiles {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatalf("owned file not removed: %s", path)
		}
	}
	// Uninstalling again with everything missing must stay a success.
	if _, err := Uninstall(UninstallOptions{Config: cfg, Runner: &recordingRunner{}}); err != nil {
		t.Fatalf("idempotent uninstall failed: %v", err)
	}
}

// plistAtBootoutRunner records whether the plist file still exists at the
// moment the launchctl bootout runs, proving the deactivate command runs
// before the owned file is removed.
type plistAtBootoutRunner struct {
	recordingRunner
	plist              string
	ranBootout         bool
	sawPlistAtBootout  bool
	bootoutServiceArgs []string
}

func (r *plistAtBootoutRunner) Run(name string, args ...string) error {
	_, err := r.RunOutput(name, args...)
	return err
}

func (r *plistAtBootoutRunner) RunOutput(name string, args ...string) ([]byte, error) {
	if name == "launchctl" && len(args) > 0 && args[0] == "bootout" {
		r.ranBootout = true
		r.bootoutServiceArgs = args
		if _, statErr := os.Stat(r.plist); statErr == nil {
			r.sawPlistAtBootout = true
		}
	}
	return r.recordingRunner.RunOutput(name, args...)
}

func TestRenderUninstallLaunchdBootoutUsesExactServiceTarget(t *testing.T) {
	cfg, _, _ := testConfig(t)
	cfg.Platform = "darwin"
	plan, err := RenderUninstall(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.UninstallCommands) != 1 {
		t.Fatalf("expected exactly one uninstall command, got %#v", plan.UninstallCommands)
	}
	cmd := plan.UninstallCommands[0]
	if cmd.Name != "launchctl" {
		t.Fatalf("expected launchctl, got %s", cmd.Name)
	}
	want := fmt.Sprintf("gui/%d/%s", os.Getuid(), plan.TaskName)
	if len(cmd.Args) != 2 || cmd.Args[0] != "bootout" || cmd.Args[1] != want {
		t.Fatalf("bootout must take the exact service-target %q as a single argument, got %#v", want, cmd.Args)
	}
	// The label must never be passed as a separate operand: launchctl
	// bootout rejects unknown extra arguments.
	for _, arg := range cmd.Args {
		if arg == plan.TaskName {
			t.Fatalf("label must be embedded in the service-target, not passed separately: %#v", cmd.Args)
		}
	}
	// The install plan's uninstall path must target the same form.
	installPlan := planOrFatal(t, cfg)
	for _, c := range installPlan.UninstallCommands {
		if c.Name != "launchctl" || len(c.Args) < 2 || c.Args[0] != "bootout" {
			continue
		}
		if !containsArg(c.Args, want) {
			t.Fatalf("install plan uninstall commands must also target %q, got %#v", want, c.Args)
		}
	}
}

func TestLaunchdUninstallDeactivatesBeforeRemovingPlist(t *testing.T) {
	cfg, _, _ := testConfig(t)
	cfg.Platform = "darwin"
	// Simulated install: fake runner, files land in the temp home only.
	plan := installOrFatal(t, cfg, &recordingRunner{})
	plistPath := filepath.Join(cfg.HomeDir, "Library", "LaunchAgents", plan.TaskName+".plist")
	if _, statErr := os.Stat(plistPath); statErr != nil {
		t.Fatalf("simulated install must write the plist: %v", statErr)
	}

	runner := &plistAtBootoutRunner{plist: plistPath}
	if _, err := Uninstall(UninstallOptions{Config: cfg, Runner: runner}); err != nil {
		t.Fatalf("uninstall failed: %v", err)
	}
	if !runner.ranBootout {
		t.Fatalf("uninstall must attempt the launchctl bootout deactivate command: %v", runner.runs)
	}
	if !runner.sawPlistAtBootout {
		t.Fatal("bootout must run while the plist still exists (deactivate before remove)")
	}
	if _, statErr := os.Stat(plistPath); !os.IsNotExist(statErr) {
		t.Fatalf("plist must be removed by uninstall: %v", statErr)
	}
	// The executed bootout must have used the exact service-target.
	want := fmt.Sprintf("gui/%d/%s", os.Getuid(), plan.TaskName)
	if len(runner.bootoutServiceArgs) != 2 || runner.bootoutServiceArgs[1] != want {
		t.Fatalf("executed bootout must target %q exactly, got %#v", want, runner.bootoutServiceArgs)
	}
	// Uninstall must stay idempotent once everything is gone.
	if _, err := Uninstall(UninstallOptions{Config: cfg, Runner: &recordingRunner{}}); err != nil {
		t.Fatalf("idempotent uninstall failed: %v", err)
	}
}

func TestUninstallRefusesForeignFiles(t *testing.T) {
	cfg, _, _ := testConfig(t)
	cfg.Platform = "darwin"
	plan := planOrFatal(t, cfg)
	if err := os.MkdirAll(filepath.Dir(plan.Files[0].Path), 0o700); err != nil {
		t.Fatal(err)
	}
	// Foreign content without identity or marker must never be removed.
	foreign := plan.Files[0].Path
	if err := os.WriteFile(foreign, []byte("<?xml version=\"1.0\"?><plist><dict><key>Label</key><string>com.apple.SomethingElse</string></dict></plist>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Uninstall(UninstallOptions{Config: cfg, Runner: &recordingRunner{}}); err == nil {
		t.Fatal("uninstall must refuse to remove a foreign file")
	}
	if _, statErr := os.Stat(foreign); statErr != nil {
		t.Fatal("foreign file must survive")
	}

	// Content with identity but a foreign marker (different state dir)
	// must also be refused. The plist stores the marker XML-escaped, so
	// swap the escaped form.
	hijacked := strings.ReplaceAll(plan.Files[0].Content, xmlEscape(plan.Marker), xmlEscape("/some/other/state dir"))
	if err := os.WriteFile(foreign, []byte(hijacked), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Uninstall(UninstallOptions{Config: cfg, Runner: &recordingRunner{}}); err == nil {
		t.Fatal("uninstall must refuse to remove a file for another state dir")
	}
	if _, statErr := os.Stat(foreign); statErr != nil {
		t.Fatal("foreign-marker file must survive")
	}
}

func TestUninstallWindowsRunsDeactivateWithoutFiles(t *testing.T) {
	cfg, _, _ := testConfig(t)
	cfg.Platform = "windows"
	runner := &recordingRunner{}
	if _, err := Uninstall(UninstallOptions{Config: cfg, Runner: runner}); err != nil {
		t.Fatalf("windows uninstall failed: %v", err)
	}
	sawDelete := false
	for _, line := range runner.runs {
		if strings.Contains(line, "/Delete") {
			sawDelete = true
		}
	}
	if !sawDelete {
		t.Fatalf("windows uninstall must always run the deactivate command: %v", runner.runs)
	}
}

func TestUninstallRefusesRemovePathsOutsideBase(t *testing.T) {
	cfg, _, _ := testConfig(t)
	cfg.Platform = "linux"
	// A hostile plan that wants to remove a file outside the unit dir
	// must be refused before any command runs.
	victim := filepath.Join(t.TempDir(), "important.txt")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := RenderUninstall(cfg)
	if err != nil {
		t.Fatal(err)
	}
	plan.RemoveFiles = append(plan.RemoveFiles, victim)
	runner := &recordingRunner{}
	if err := validateRemovePaths(plan); err == nil {
		t.Fatal("expected path validation to refuse")
	}
	_ = runner
}

// ---------------------------------------------------------------------------
// IsInstalled / OwnedFileCheck / WritePlan
// ---------------------------------------------------------------------------

func TestIsInstalledAndOwnedFileCheck(t *testing.T) {
	cfg, _, _ := testConfig(t)
	cfg.Platform = "darwin"
	installed, files, err := IsInstalled(cfg)
	if err != nil || installed {
		t.Fatalf("expected not installed: %v %v", installed, err)
	}
	plan := installOrFatal(t, cfg, &recordingRunner{})
	installed, files, err = IsInstalled(cfg)
	if err != nil || !installed {
		t.Fatalf("expected installed after install: %v %v", installed, err)
	}
	if len(files) != 1 {
		t.Fatalf("expected the plist to be found: %v", files)
	}
	if err := OwnedFileCheck(files[0], plan.TaskName, plan.Marker); err != nil {
		t.Fatalf("installed file must pass the owned-file check: %v", err)
	}
	if err := OwnedFileCheck(files[0], "toktrail-collector-other", plan.Marker); err == nil {
		t.Fatal("foreign identity must fail the owned-file check")
	}
	if err := OwnedFileCheck(files[0], plan.TaskName, "/other/state"); err == nil {
		t.Fatal("foreign marker must fail the owned-file check")
	}
}

func TestIsInstalledAndOwnedFileCheckWindows(t *testing.T) {
	cfg, _, _ := testConfig(t)
	cfg.Platform = "windows"

	// 1. Missing task (runner returns error indicating task not found)
	notFoundRunner := &recordingRunner{
		failers: map[string]error{
			"schtasks": &commandError{err: errors.New("exit status 1"), name: "schtasks", output: "ERROR: The system cannot find the file specified."},
		},
	}
	installed, _, err := IsInstalledWithRunner(cfg, notFoundRunner)
	if err != nil || installed {
		t.Fatalf("expected not installed when schtasks returns not found: installed=%v, err=%v", installed, err)
	}

	plan, err := RenderInstall(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Installed task with UTF-8 XML output
	utf8Runner := &recordingRunner{
		outputs: map[string][]byte{
			"schtasks": []byte(plan.Files[0].Content),
		},
	}
	taskName := windowsTaskName(plan.TaskName)
	installed, files, err := IsInstalledWithRunner(cfg, utf8Runner)
	if err != nil || !installed {
		t.Fatalf("expected installed with UTF-8 schtasks output: %v %v", installed, err)
	}
	if len(files) != 1 || files[0] != "schtasks:"+taskName {
		t.Fatalf("expected schtasks task to be reported: %v", files)
	}

	// 3. Installed task with UTF-16LE (with BOM) XML output
	utf16LE := encodeUTF16LEWithBOM(plan.Files[0].Content)
	utf16Runner := &recordingRunner{
		outputs: map[string][]byte{
			"schtasks": utf16LE,
		},
	}
	installed, files, err = IsInstalledWithRunner(cfg, utf16Runner)
	if err != nil || !installed {
		t.Fatalf("expected installed with UTF-16LE schtasks output: %v %v", installed, err)
	}
	if len(files) != 1 || files[0] != "schtasks:"+taskName {
		t.Fatalf("expected schtasks task to be reported: %v", files)
	}

	// 4. Foreign task XML output (wrong state dir / identity)
	foreignRunner := &recordingRunner{
		outputs: map[string][]byte{
			"schtasks": []byte("<Task><Description>foreign task</Description></Task>"),
		},
	}
	installed, _, err = IsInstalledWithRunner(cfg, foreignRunner)
	if installed || err == nil {
		t.Fatalf("expected foreign task query to fail ownership check: installed=%v, err=%v", installed, err)
	}

	// 5. Access denied error must surface as a query failure error, not absent
	accessDeniedRunner := &recordingRunner{
		failers: map[string]error{
			"schtasks": &commandError{err: errors.New("exit status 1"), name: "schtasks", output: "ERROR: Access is denied."},
		},
	}
	installed, _, err = IsInstalledWithRunner(cfg, accessDeniedRunner)
	if installed || err == nil {
		t.Fatalf("access denied must return a query failure error: installed=%v, err=%v", installed, err)
	}

	// 6. Malformed odd-length UTF-16 output must fail ownership check without panic
	malformedRunner := &recordingRunner{
		outputs: map[string][]byte{
			"schtasks": {0xFF, 0xFE, 'A', 0x00, 'B'},
		},
	}
	installed, _, err = IsInstalledWithRunner(cfg, malformedRunner)
	if installed || err == nil {
		t.Fatalf("malformed UTF-16 output must fail ownership check without panic: installed=%v, err=%v", installed, err)
	}
}

func TestWritePlanIsSafeDryRun(t *testing.T) {
	cfg, _, _ := testConfig(t)
	cfg.Platform = "windows"
	plan, err := RenderInstall(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := WritePlan(&out, plan, "install"); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.Contains(text, "platform=windows") || !strings.Contains(text, "schtasks") {
		t.Fatalf("unexpected dry-run output:\n%s", text)
	}
	if !strings.Contains(text, plan.Files[0].Content) {
		t.Fatal("dry-run must show the full file contents for review")
	}
	// Dry-run install must not create anything.
	if _, err := Install(InstallOptions{Config: cfg, Runner: &recordingRunner{}, DryRun: true, Out: io.Discard}); err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(plan.Files[0].Path); !os.IsNotExist(statErr) {
		t.Fatal("dry-run must not write the XML file")
	}
}

// ---------------------------------------------------------------------------
// escape helpers
// ---------------------------------------------------------------------------

func TestSystemdEscapeArg(t *testing.T) {
	cases := map[string]string{
		"/plain/path":         "/plain/path",
		"":                    `""`,
		"/dir with space":     `"/dir with space"`,
		`/dir'quote`:          `"/dir'quote"`,
		`/dir"dquote`:         `"/dir\"dquote"`,
		`C:\path with spaces`: `"C:\\path with spaces"`,
	}
	for input, expected := range cases {
		if got := systemdEscapeArg(input); got != expected {
			t.Errorf("systemdEscapeArg(%q) = %q, want %q", input, got, expected)
		}
	}
	if got := systemdEscapeArg("bad\x02control"); strings.ContainsRune(got, '\x02') {
		t.Errorf("control characters must be stripped, got %q", got)
	}
}

func TestWindowsQuoteArg(t *testing.T) {
	if got := windowsQuoteArg(`C:\Program Files\toktrail`); got != `"C:\Program Files\toktrail"` {
		t.Fatalf("unexpected windows quoting: %q", got)
	}
	if got := windowsQuoteArg(`C:\plain`); got != `C:\plain` {
		t.Fatalf("plain paths must stay unquoted: %q", got)
	}
	if got := windowsQuoteArg(`C:\weird"quote`); got != `"C:\weird\"quote"` {
		t.Fatalf("embedded quotes must be escaped, got %q", got)
	}
}

func TestXMLEscape(t *testing.T) {
	out := xmlEscape(`<>&"'` + "plain")
	// The raw markup characters must be gone; & survives only as part of
	// the entity names themselves.
	if strings.ContainsAny(out, "<>\"'") {
		t.Fatalf("entities not escaped: %q", out)
	}
	if !strings.Contains(out, "&lt;") || !strings.Contains(out, "&amp;") || !strings.Contains(out, "&quot;") || !strings.Contains(out, "&apos;") {
		t.Fatalf("unexpected escape output: %q", out)
	}
	if xmlEscape("ctrl\x01char") != "ctrlchar" {
		t.Fatal("control characters must be stripped")
	}
}
