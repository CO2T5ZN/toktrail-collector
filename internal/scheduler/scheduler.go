// Package scheduler renders, installs, and uninstalls the collector's
// per-user scheduled collection task for macOS launchd (user LaunchAgent),
// Linux user systemd (unit + timer), and Windows Task Scheduler (schtasks
// with a generated XML definition).
//
// Design constraints (see docs/SCHEDULING.md):
//   - User scope only: no root, no system-level daemons, no other users.
//   - Deterministic task identity per absolute state directory, so several
//     state directories can coexist on one machine without collision.
//   - The scheduled command is the complete-exit entry
//     `toktrail periodic --state-dir <dir>`: no daemon is kept running.
//   - All commands are executed through argument arrays (exec.Command /
//     injectable Runner), never through a shell; XML/unit values are
//     escaped with proper escaping helpers. Paths with spaces and XML
//     metacharacters are safe by construction.
//   - The Windows task XML is written to disk as UTF-16LE with a BOM and
//     a matching encoding="UTF-16" declaration, because schtasks
//     /Create /XML rejects UTF-8 definitions with "unable to switch
//     encoding"; unix files stay UTF-8 and dry runs display readable
//     UTF-8 text either way.
//   - Everything is validated before any scheduler file is mutated;
//     a failed install rolls back every file it wrote (fail closed, no
//     partial install survives).
//   - Uninstall is idempotent and only removes files this package owns:
//     each candidate file must be a regular file inside the user scheduler
//     directory and must contain both the task identity and the state-dir
//     marker before it is deleted.
//   - Installing the service never binds a device, never scans, and never
//     runs a collection; binding and the first collection stay explicit.
package scheduler

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
)

// DefaultInterval is the approved default scheduling period.
const DefaultInterval = 30 * time.Minute

// MinInterval guards against pathological schedules hammering the machine.
const MinInterval = time.Minute

// Runner executes an external command with an argument array. Production
// uses ExecRunner; tests inject fakes so no real host jobs are created.
type Runner interface {
	Run(name string, args ...string) error
}

// OutputRunner is an optional extension to Runner for commands whose
// stdout output is needed (e.g. schtasks /Query /XML).
type OutputRunner interface {
	Runner
	RunOutput(name string, args ...string) ([]byte, error)
}

// ExecRunner runs commands without a shell.
type ExecRunner struct{}

func (ExecRunner) Run(name string, args ...string) error { return runCommand(name, args...) }

func (ExecRunner) RunOutput(name string, args ...string) ([]byte, error) {
	cmd := schedulerOutputCommand(name, args...)
	configureSchedulerCommand(cmd)
	// Keep diagnostic stderr separate from XML stdout: mixing a warning
	// into an otherwise valid task document corrupts its encoding/content.
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		err = schedulerOutputError(name, args, err)
		if errors.Is(err, errWindowsTaskMissing) {
			return nil, err
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(string(out))
		}
		if msg == "" {
			return nil, err
		}
		if len(msg) > 400 {
			msg = msg[:400] + "..."
		}
		return nil, &commandError{err: err, name: name, output: msg}
	}
	return out, nil
}

func runCommandOutput(runner Runner, name string, args ...string) ([]byte, error) {
	if runner == nil {
		runner = ExecRunner{}
	}
	if or, ok := runner.(OutputRunner); ok {
		return or.RunOutput(name, args...)
	}
	return nil, fmt.Errorf("runner %T does not implement OutputRunner", runner)
}

// TaskConfig describes the scheduled task to render.
type TaskConfig struct {
	// Platform selects the renderer: "darwin", "linux", "windows". Tests
	// override it; production passes runtime.GOOS.
	Platform string
	// StateDir is the collector state directory; it is part of the task
	// identity and passed to the periodic entry. Must be absolute.
	StateDir string
	// Binary is the absolute path of the collector executable the task
	// invokes.
	Binary string
	// Interval is the scheduling period (>= MinInterval).
	Interval time.Duration
	// HomeDir is the user's home directory the user-scope scheduler paths
	// are derived from. Required and must be absolute on all platforms so
	// tests and dry runs never target the real home.
	HomeDir string
}

// Plan is a fully rendered, validated install or uninstall description.
// Dry-run mode prints it without touching the system.
type Plan struct {
	Platform string
	TaskName string
	// HomeDir is the user home directory the rendered paths are based on.
	HomeDir string
	// Marker is the absolute state directory that must appear in every
	// scheduler-owned file for this task (owned-path validation).
	Marker string
	// EnsureDirs are created at install time before files are written (for
	// example the scheduler log directory inside the state dir).
	EnsureDirs []string
	// Files are created at install time (already rendered and escaped).
	Files []FileWrite
	// Commands run after the files are written, in order.
	Commands []Command
	// UndoCommands run when a command fails; written files are also removed.
	UndoCommands []Command
	// UninstallCommands run at uninstall time before file removal.
	UninstallCommands []Command
	// PostRemoveCommands run at uninstall time after file removal (for
	// example a systemd daemon-reload), best effort.
	PostRemoveCommands []Command
	// RemoveFiles lists scheduler-owned files to delete at uninstall time.
	RemoveFiles []string
}

type FileWrite struct {
	Path    string
	Content string
	// Mode is the file permission used on unix platforms.
	Mode os.FileMode
	// Temp marks scratch files (for example the Windows task XML handed to
	// schtasks) that are deleted after the commands succeed.
	Temp bool
	// Encoding selects how Content is encoded on disk. The zero value
	// writes the content as raw UTF-8 bytes (launchd plists, systemd
	// units); EncodingUTF16LE writes the Windows task XML in the form
	// schtasks requires. Content itself always stays readable UTF-8 so
	// dry runs (WritePlan) display it.
	Encoding FileEncoding
}

// FileEncoding selects the on-disk byte encoding of a planned file write.
type FileEncoding string

const (
	// EncodingUTF8 (also the zero value) writes the content as raw UTF-8
	// bytes. All unix scheduler files use it.
	EncodingUTF8 FileEncoding = "utf-8"
	// EncodingUTF16LE writes a UTF-16LE byte-order mark (0xFF 0xFE)
	// followed by the text encoded as UTF-16LE code units. Windows
	// schtasks /Create /XML rejects task definitions saved as UTF-8 with
	// "unable to switch encoding" and accepts the UTF-16LE + BOM form it
	// exports itself via `schtasks /Query /XML`, so the Windows task XML
	// must use this encoding and declare encoding="UTF-16".
	EncodingUTF16LE FileEncoding = "utf-16le"
)

type Command struct {
	Name    string
	Args    []string
	Purpose string
	// BestEffort commands may fail without failing the install (for
	// example unloading a job that is not loaded during reinstall).
	BestEffort bool
}

// TaskIdentity derives the deterministic task identity from the absolute
// state directory. The same state dir always maps to the same identity;
// different state dirs map to different identities.
func TaskIdentity(stateDir string) (string, error) {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return "", errors.New("collector state directory is required")
	}
	abs, err := filepath.Abs(stateDir)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(filepath.Clean(abs)))
	return "toktrail-collector-" + hex.EncodeToString(sum[:])[:16], nil
}

// StateDirMarker returns the absolute state directory that must appear in
// every scheduler-owned file; uninstall refuses to delete files without it.
func StateDirMarker(stateDir string) (string, error) {
	abs, err := filepath.Abs(strings.TrimSpace(stateDir))
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

// Validate checks a TaskConfig before anything is rendered or mutated.
func (c TaskConfig) Validate() error {
	switch c.Platform {
	case "darwin", "linux", "windows":
	default:
		return fmt.Errorf("unsupported platform %q (this build runs on %s)", c.Platform, runtime.GOOS)
	}
	marker, err := StateDirMarker(c.StateDir)
	if err != nil {
		return err
	}
	info, err := os.Stat(marker)
	if err != nil {
		return fmt.Errorf("state directory %q is not accessible: %w", marker, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("state directory %q is not a directory", marker)
	}
	bin := strings.TrimSpace(c.Binary)
	if bin == "" {
		return errors.New("collector binary path is required")
	}
	if !filepath.IsAbs(bin) {
		return fmt.Errorf("collector binary %q must be an absolute path", bin)
	}
	binInfo, err := os.Stat(bin)
	if err != nil {
		return fmt.Errorf("collector binary %q is not accessible: %w", bin, err)
	}
	if binInfo.IsDir() {
		return fmt.Errorf("collector binary %q is a directory", bin)
	}
	if c.Interval < MinInterval {
		return fmt.Errorf("interval %s is below the minimum %s", c.Interval, MinInterval)
	}
	home := strings.TrimSpace(c.HomeDir)
	if home == "" {
		return errors.New("user home directory is required for user-scope scheduler paths")
	}
	if !filepath.IsAbs(home) {
		return fmt.Errorf("user home directory %q must be absolute", home)
	}
	return nil
}

// RenderInstall renders the install plan (files + activation commands).
func RenderInstall(cfg TaskConfig) (Plan, error) {
	if err := cfg.Validate(); err != nil {
		return Plan{}, err
	}
	identity, err := TaskIdentity(cfg.StateDir)
	if err != nil {
		return Plan{}, err
	}
	marker, err := StateDirMarker(cfg.StateDir)
	if err != nil {
		return Plan{}, err
	}
	base := Plan{Platform: cfg.Platform, TaskName: identity, Marker: marker, HomeDir: cfg.HomeDir}
	switch cfg.Platform {
	case "darwin":
		return renderLaunchdInstall(cfg, base)
	case "linux":
		return renderSystemdInstall(cfg, base)
	case "windows":
		return renderTaskSchedulerInstall(cfg, base)
	}
	return Plan{}, fmt.Errorf("unsupported platform %q", cfg.Platform)
}

// RenderUninstall renders the uninstall plan (deactivation commands + owned
// files to remove). It does not mutate anything.
func RenderUninstall(cfg TaskConfig) (Plan, error) {
	if err := cfg.Validate(); err != nil {
		return Plan{}, err
	}
	identity, err := TaskIdentity(cfg.StateDir)
	if err != nil {
		return Plan{}, err
	}
	marker, err := StateDirMarker(cfg.StateDir)
	if err != nil {
		return Plan{}, err
	}
	base := Plan{Platform: cfg.Platform, TaskName: identity, Marker: marker, HomeDir: cfg.HomeDir}
	switch cfg.Platform {
	case "darwin":
		return renderLaunchdUninstall(cfg, base)
	case "linux":
		return renderSystemdUninstall(cfg, base)
	case "windows":
		return renderTaskSchedulerUninstall(cfg, base)
	}
	return Plan{}, fmt.Errorf("unsupported platform %q", cfg.Platform)
}

// InstallOptions controls an install run.
type InstallOptions struct {
	Config TaskConfig
	Runner Runner
	// DryRun writes the rendered plan to Out instead of mutating anything.
	DryRun bool
	Out    io.Writer
}

// UninstallOptions controls an uninstall run.
type UninstallOptions struct {
	Config TaskConfig
	Runner Runner
	DryRun bool
	Out    io.Writer
}

// Install validates, renders, writes files, and activates the task. On any
// failure after the first mutation it rolls back (undo commands + removal
// of every file it wrote) and returns the error: no partial install
// survives.
func Install(opt InstallOptions) (Plan, error) {
	plan, err := RenderInstall(opt.Config)
	if err != nil {
		return plan, err
	}
	if err := validatePlanPaths(plan); err != nil {
		return plan, err
	}
	if opt.DryRun {
		return plan, WritePlan(opt.Out, plan, "install")
	}
	runner := opt.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	if opt.Config.Platform == "windows" {
		switch runner.(type) {
		case ExecRunner, *ExecRunner:
			if err := validateBackgroundLauncher(opt.Config.Binary); err != nil {
				return plan, err
			}
		}
	}
	for _, dir := range plan.EnsureDirs {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			rollback(runner, plan, nil)
			return plan, fmt.Errorf("create %s: %w", dir, err)
		}
	}
	var written []string
	for _, file := range plan.Files {
		if err := writeFile(file); err != nil {
			rollback(runner, plan, written)
			return plan, err
		}
		written = append(written, file.Path)
	}
	for _, cmd := range plan.Commands {
		if err := runner.Run(cmd.Name, cmd.Args...); err != nil {
			if cmd.BestEffort {
				fmt.Fprintf(discardIfNil(opt.Out), "note: %s: %v (continuing)\n", cmd.Purpose, err)
				continue
			}
			rollback(runner, plan, written)
			return plan, fmt.Errorf("%s: %w", cmd.Purpose, err)
		}
	}
	// Scratch files (Windows task XML) are removed once activation
	// succeeded; rollback already removed them on failure.
	for _, file := range plan.Files {
		if file.Temp {
			if err := os.Remove(file.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return plan, fmt.Errorf("clean up %s: %w", file.Path, err)
			}
		}
	}
	return plan, nil
}

// Uninstall deactivates and removes the task. It is idempotent: absent
// files are a no-op. Deactivation command failures are tolerated (the job
// may not be loaded), but every file removal is validated: a file is only
// deleted when it is a regular file inside the user scheduler directory
// whose content references both the task identity and the state-dir marker.
func Uninstall(opt UninstallOptions) (Plan, error) {
	plan, err := RenderUninstall(opt.Config)
	if err != nil {
		return plan, err
	}
	if err := validateRemovePaths(plan); err != nil {
		return plan, err
	}
	if opt.DryRun {
		return plan, WritePlan(opt.Out, plan, "uninstall")
	}
	runner := opt.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	// On unix the owned files are the source of truth: when none exist
	// there is nothing registered under this identity, so the deactivation
	// commands are skipped (they would only report "not found"). On
	// Windows the task store is not file-based, so the delete command runs
	// regardless and its failure is tolerated when nothing was registered.
	runDeactivate := plan.Platform == "windows"
	for _, path := range plan.RemoveFiles {
		if _, err := os.Stat(path); err == nil {
			runDeactivate = true
			break
		}
	}
	if runDeactivate {
		for _, cmd := range plan.UninstallCommands {
			if err := runner.Run(cmd.Name, cmd.Args...); err != nil {
				fmt.Fprintf(discardIfNil(opt.Out), "note: %s: %v (continuing with file removal)\n", cmd.Purpose, err)
			}
		}
	}
	for _, path := range plan.RemoveFiles {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return plan, fmt.Errorf("inspect %s: %w", path, err)
		}
		if err := OwnedFileCheck(path, plan.TaskName, plan.Marker); err != nil {
			return plan, fmt.Errorf("refusing to remove: %w", err)
		}
		if err := os.Remove(path); err != nil {
			return plan, fmt.Errorf("remove %s: %w", path, err)
		}
	}
	for _, cmd := range plan.PostRemoveCommands {
		if err := runner.Run(cmd.Name, cmd.Args...); err != nil {
			fmt.Fprintf(discardIfNil(opt.Out), "note: %s: %v\n", cmd.Purpose, err)
		}
	}
	return plan, nil
}

func discardIfNil(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}

// rollback reverses a partial install: written files are removed and undo
// commands run, best effort.
func rollback(runner Runner, plan Plan, written []string) {
	for i := len(written) - 1; i >= 0; i-- {
		_ = os.Remove(written[i])
	}
	for _, cmd := range plan.UndoCommands {
		_ = runner.Run(cmd.Name, cmd.Args...)
	}
}

func writeFile(file FileWrite) error {
	// Fail closed on an unsupported encoding before touching the disk.
	data, err := encodeFileContent(file)
	if err != nil {
		return err
	}
	dir := filepath.Dir(file.Path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	mode := file.Mode
	if mode == 0 {
		mode = 0o644
	}
	tmp := file.Path + ".toktrail-tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, file.Path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install %s: %w", file.Path, err)
	}
	return nil
}

// encodeFileContent renders a planned file's disk bytes. The default (and
// every unix scheduler file) is the raw UTF-8 bytes of the content; the
// Windows task XML is encoded UTF-16LE with a BOM because that is the
// only encoding schtasks /Create /XML accepts for task definitions.
func encodeFileContent(file FileWrite) ([]byte, error) {
	switch file.Encoding {
	case "", EncodingUTF8:
		return []byte(file.Content), nil
	case EncodingUTF16LE:
		return encodeUTF16LEWithBOM(file.Content), nil
	default:
		return nil, fmt.Errorf("write %s: unsupported file encoding %q", file.Path, file.Encoding)
	}
}

// validatePlanPaths ensures every file the plan writes stays inside the
// platform's user scheduler directory. It is defense in depth against
// renderer bugs. On Windows there is no file base (the task store is
// managed by schtasks); only the scratch XML must live in the system temp
// directory.
func validatePlanPaths(plan Plan) error {
	base, fileBase, err := schedulerBases(plan.Platform, plan)
	if err != nil {
		return err
	}
	for _, file := range plan.Files {
		target := base
		if target == "" {
			target = fileBase
		}
		if target == "" {
			continue
		}
		if !withinDir(target, file.Path) {
			return fmt.Errorf("refusing to write %s outside %s", file.Path, target)
		}
	}
	return nil
}

// validateRemovePaths ensures removal candidates stay inside the user
// scheduler directory.
func validateRemovePaths(plan Plan) error {
	base, _, err := schedulerBases(plan.Platform, plan)
	if err != nil {
		return err
	}
	if base == "" {
		return nil
	}
	for _, path := range plan.RemoveFiles {
		if !withinDir(base, path) {
			return fmt.Errorf("refusing to remove %s outside %s", path, base)
		}
	}
	return nil
}

// schedulerBases returns the user scheduler file base for the platform
// (empty on windows) and the scratch-file base (system temp dir on
// windows, empty elsewhere).
func schedulerBases(platform string, plan Plan) (base, scratch string, err error) {
	switch platform {
	case "darwin":
		return filepath.Join(homeDirOf(plan), "Library", "LaunchAgents"), "", nil
	case "linux":
		return filepath.Join(homeDirOf(plan), ".config", "systemd", "user"), "", nil
	case "windows":
		return "", os.TempDir(), nil
	}
	return "", "", fmt.Errorf("unsupported platform %q", platform)
}

func homeDirOf(plan Plan) string { return plan.HomeDir }

func withinDir(base, path string) bool {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "."
}

// WritePlan prints a rendered plan for dry-run or reporting. It writes no
// secrets: only paths, intervals, file contents, and command arrays.
func WritePlan(out io.Writer, plan Plan, action string) error {
	if out == nil {
		return nil
	}
	fmt.Fprintf(out, "dry-run %s: platform=%s task=%s\n", action, plan.Platform, plan.TaskName)
	fmt.Fprintf(out, "state-dir=%s\n", plan.Marker)
	for _, dir := range plan.EnsureDirs {
		fmt.Fprintf(out, "ensure dir: %s\n", dir)
	}
	if len(plan.Files) > 0 {
		fmt.Fprintf(out, "files:\n")
		for _, file := range plan.Files {
			fmt.Fprintf(out, "  write %s\n", file.Path)
		}
	}
	if len(plan.Commands) > 0 {
		fmt.Fprintf(out, "commands:\n")
		for _, cmd := range plan.Commands {
			fmt.Fprintf(out, "  %s\n", commandString(cmd))
		}
	}
	if len(plan.UninstallCommands) > 0 {
		fmt.Fprintf(out, "uninstall commands:\n")
		for _, cmd := range plan.UninstallCommands {
			fmt.Fprintf(out, "  %s\n", commandString(cmd))
		}
	}
	if len(plan.RemoveFiles) > 0 {
		fmt.Fprintf(out, "remove:\n")
		for _, path := range plan.RemoveFiles {
			fmt.Fprintf(out, "  %s\n", path)
		}
	}
	for _, file := range plan.Files {
		fmt.Fprintf(out, "--- %s ---\n%s\n", file.Path, file.Content)
	}
	return nil
}

// commandString renders a command for dry-run display only; commands are
// always executed as argument arrays, never through this string.
func commandString(cmd Command) string {
	parts := []string{cmd.Name}
	for _, arg := range cmd.Args {
		parts = append(parts, quoteForDisplay(arg))
	}
	return strings.Join(parts, " ")
}

func quoteForDisplay(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// IsInstalled reports whether the scheduler task or scheduler-owned files
// for this config currently exist (used by diagnostics; performs no mutation).
func IsInstalled(cfg TaskConfig) (bool, []string, error) {
	return IsInstalledWithRunner(cfg, ExecRunner{})
}

// IsInstalledWithRunner reports whether the scheduler task or scheduler-owned
// files for this config currently exist using the provided command runner.
func IsInstalledWithRunner(cfg TaskConfig, runner Runner) (bool, []string, error) {
	plan, err := RenderUninstall(cfg)
	if err != nil {
		return false, nil, err
	}
	if err := validateRemovePaths(plan); err != nil {
		return false, nil, err
	}
	var found []string
	for _, path := range plan.RemoveFiles {
		if _, err := os.Stat(path); err == nil {
			found = append(found, path)
		}
	}
	if cfg.Platform == "windows" {
		taskName := windowsTaskName(plan.TaskName)
		out, err := runCommandOutput(runner, "schtasks", "/Query", "/TN", taskName, "/XML")
		if err != nil {
			if isTaskNotFound(err) {
				return false, nil, nil
			}
			return false, nil, fmt.Errorf("windows scheduled task query failed: %w", err)
		}
		xmlText := decodeUTF16LEOrUTF8(out)
		if _, err := checkedWindowsTask(xmlText, plan.TaskName, plan.Marker); err != nil {
			return false, nil, fmt.Errorf("scheduled task %s ownership check failed: %w", taskName, err)
		}
		found = append(found, "schtasks:"+taskName)
	}
	return len(found) > 0, found, nil
}

func decodeUTF16LEOrUTF8(b []byte) string {
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		b = b[2:]
		u16 := make([]uint16, len(b)/2)
		for i := 0; i < len(u16); i++ {
			u16[i] = uint16(b[2*i]) | (uint16(b[2*i+1]) << 8)
		}
		return string(utf16.Decode(u16))
	}
	if len(b) >= 4 && (b[1] == 0x00 || b[3] == 0x00) {
		u16 := make([]uint16, len(b)/2)
		for i := 0; i < len(u16); i++ {
			u16[i] = uint16(b[2*i]) | (uint16(b[2*i+1]) << 8)
		}
		return string(utf16.Decode(u16))
	}
	return string(b)
}

// encodeUTF16LEWithBOM encodes text as UTF-16LE with a byte-order mark —
// the encoding Windows schtasks produces for task XML via /Query /XML and
// the only one it reliably accepts for /Create /XML (a UTF-8 file fails
// with "unable to switch encoding"). It is the inverse of
// decodeUTF16LEOrUTF8 for well-formed input.
func encodeUTF16LEWithBOM(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	b := make([]byte, 2+2*len(u16))
	b[0] = 0xFF
	b[1] = 0xFE
	for i, v := range u16 {
		b[2+2*i] = byte(v)
		b[3+2*i] = byte(v >> 8)
	}
	return b
}

func isTaskNotFound(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errWindowsTaskMissing) {
		return true
	}
	var cmdErr *commandError
	if errors.As(err, &cmdErr) {
		out := strings.ToLower(cmdErr.output)
		if strings.Contains(out, "cannot find") ||
			strings.Contains(out, "does not exist") ||
			strings.Contains(out, "no tasks") ||
			strings.Contains(out, "not found") {
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "cannot find") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "no tasks") ||
		strings.Contains(msg, "not found")
}

// OwnedFileCheck validates that a file on disk belongs to this task: it
// must contain both the task identity and the state-dir marker.
func OwnedFileCheck(path, identity, marker string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := OwnedFileCheckText(string(content), identity, marker); err != nil {
		return fmt.Errorf("%s %w", path, err)
	}
	return nil
}

// OwnedFileCheckText validates that text content belongs to this task: it
// must contain both the task identity and the state-dir marker.
func OwnedFileCheckText(text, identity, marker string) error {
	if !strings.Contains(text, identity) && !strings.Contains(text, windowsTaskName(identity)) {
		return fmt.Errorf("does not reference task identity %s", identity)
	}
	// XML-backed files (launchd plist, windows task XML) store the state
	// dir with entity escaping, so accept the raw or the escaped form.
	if !strings.Contains(text, marker) && !strings.Contains(text, xmlEscape(marker)) {
		return fmt.Errorf("does not reference state directory %s", marker)
	}
	return nil
}
