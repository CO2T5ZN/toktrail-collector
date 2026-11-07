// Package diagnostic implements the local-only privacy report
// (`toktrail privacy`) and the local health check (`toktrail doctor`).
//
// Privacy never touches the network: it scans only the explicitly granted
// sources/inputs (or a source+input given explicitly for the invocation)
// and reports what a future upload would contain. Doctor is local by
// default too; the only network it can perform is the explicit
// `--check-server` option, which reuses the existing status command
// (fresh server consent preflight, no secrets in output).
package diagnostic

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	statuscmd "toktrail-collector/internal/app/status"
	"toktrail-collector/internal/local/exportcommit"
	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/local/scanledger"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/scheduler"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/pipeline"
)

// ---------------------------------------------------------------------------
// privacy
// ---------------------------------------------------------------------------

type PrivacyOptions struct {
	StateDir string
	// Source and Input narrow the report to one explicit source+input.
	// When empty, every enabled grant is reported.
	Source string
	Input  string
}

type PrivacyReport struct {
	// Source, Input describe what was inspected.
	Source string
	Input  string
	// RecordCount, ValidRecords, InvalidRecords, Quarantined mirror the
	// adapter's local scan summary.
	RecordCount    int
	ValidRecords   int
	InvalidRecords int
	Quarantined    int
	// UploadSafeRecords is the number of records that would be included
	// in an export/upload under the current token filters.
	UploadSafeRecords int
	// TokensInclude/TokensExclude are the configured token filters, when
	// present.
	TokensInclude *uint64
	TokensExclude *uint64
	// Tools lists tool usage counts in the scanned window.
	Tools map[string]int
	// Earliest/Latest bound the occurred-at range of the scanned records.
	Earliest *time.Time
	Latest   *time.Time
	// OutboxPending counts staged-but-not-yet-uploaded batches in the
	// local outbox (what could still leave the device).
	OutboxPending int
	// OutboxPendingRecords counts records across those pending batches.
	OutboxPendingRecords int
}

// Privacy produces one local-only report per inspected source+input. It
// performs no network access and no state mutation.
func Privacy(opt PrivacyOptions) ([]PrivacyReport, error) {
	stateDir := strings.TrimSpace(opt.StateDir)
	if stateDir == "" {
		return nil, errors.New("collector state directory is required")
	}
	var targets []grants.Grant
	if opt.Source != "" || opt.Input != "" {
		if opt.Source == "" || opt.Input == "" {
			return nil, errors.New("privacy: --source and --input must be given together")
		}
		if err := grants.ValidateGrant(opt.Source, opt.Input); err != nil {
			return nil, err
		}
		if err := grants.ValidateInput(opt.Input); err != nil {
			return nil, err
		}
		targets = []grants.Grant{{Source: opt.Source, Input: filepath.Clean(opt.Input), Enabled: true}}
	} else {
		grants, err := grants.New(stateDir).Enabled()
		if err != nil {
			return nil, err
		}
		targets = grants
	}

	pendingBatches, pendingRecords, err := pendingSummary(stateDir)
	if err != nil {
		return nil, err
	}

	var reports []PrivacyReport
	for _, grant := range targets {
		scan, err := pipeline.Scan(adapter.Options{
			Source:   grant.Source,
			Input:    grant.Input,
			StateDir: stateDir,
		})
		report := PrivacyReport{
			Source:               grant.Source,
			Input:                grant.Input,
			RecordCount:          scan.RecordCount,
			ValidRecords:         scan.ValidRecords,
			InvalidRecords:       scan.InvalidRecords,
			Quarantined:          scan.Quarantined,
			UploadSafeRecords:    scan.ValidRecords,
			TokensInclude:        scan.TokensInclude,
			TokensExclude:        scan.TokensExclude,
			Tools:                scan.Tools,
			Earliest:             scan.EarliestOccurredAt,
			Latest:               scan.LatestOccurredAt,
			OutboxPending:        pendingBatches,
			OutboxPendingRecords: pendingRecords,
		}
		if err != nil {
			return nil, fmt.Errorf("scan %s %s: %w", grant.Source, grant.Input, err)
		}
		reports = append(reports, report)
	}
	if opt.Source == "" && opt.Input == "" {
		queued, err := cursorPrivacy(stateDir)
		if err != nil {
			return nil, err
		}
		if queued != nil {
			reports = append(reports, *queued)
		}
	}
	return reports, nil
}

func pendingSummary(stateDir string) (batches, records int, err error) {
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		return 0, 0, err
	}
	for _, batch := range out.Batches {
		if batch.Status == outbox.StatusPending {
			batches++
			records += batch.RecordCount
		}
	}
	return batches, records, nil
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

type DoctorOptions struct {
	StateDir string
	// CheckServer performs the only possible network operation: the
	// existing status command's device self check. It is opt-in.
	CheckServer bool
	ServerURL   string
	HTTPClient  *http.Client
	// Binary is the executable path used for scheduler task inspection.
	Binary string
	// Version is the running collector's build version ("" when unknown).
	Version string
	// LookPath resolves a bare command name to a path (defaults to
	// exec.LookPath; injectable for tests). It answers "which copy would a
	// shell start?" independently of the running binary.
	LookPath func(string) (string, error)
	// HomeDir is the user home directory for scheduler path resolution.
	HomeDir string
	// Runner is an optional command runner for scheduler inspection (used in tests).
	Runner scheduler.Runner
}

type CheckStatus string

const (
	CheckOK      CheckStatus = "ok"
	CheckWarn    CheckStatus = "warn"
	CheckFail    CheckStatus = "fail"
	CheckSkipped CheckStatus = "skipped"
)

type Check struct {
	Name   string
	Status CheckStatus
	Detail string
}

type DoctorReport struct {
	StateDir string
	Checks   []Check
	// TaskInstalled and TaskFiles describe the scheduler task for this
	// state directory.
	TaskInstalled bool
	TaskFiles     []string
}

// Failed reports whether any check failed (as opposed to warnings).
func (r DoctorReport) Failed() bool {
	for _, c := range r.Checks {
		if c.Status == CheckFail {
			return true
		}
	}
	return false
}

// Doctor runs local health checks. Nothing here prompts, sends messages,
// or prints secrets. Network happens only when opt.CheckServer is set.
// scanCacheCheck reports the incremental-scan state: how many sources have a
// committed scan ledger, and whether the known-record cache exists. Both are
// accelerators — a missing one only costs a full re-read — so this never
// fails a doctor run.
// binaryIdentityCheck compares the running binary with the schedule's
// registered binary and with the copy a shell would start.
//
//   - fail when the schedule starts a different binary than the one running:
//     an upgrade of the running copy does not affect scheduled runs;
//   - warn when PATH resolves to yet another copy (two installations), which
//     makes `toktrail ...` from a shell hit a different build than the
//     scheduler;
//   - ok otherwise, naming the version so support can see it at a glance.
func binaryIdentityCheck(opt DoctorOptions) Check {
	current := strings.TrimSpace(opt.Binary)
	if current == "" {
		return Check{Name: "binary", Status: CheckSkipped, Detail: "running binary path unknown; identity check skipped"}
	}
	currentResolved := resolvePath(current)
	version := strings.TrimSpace(opt.Version)
	versionLabel := "version unknown"
	if version != "" {
		versionLabel = "version " + version
	}

	lookPath := opt.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	pathCopy := ""
	if found, err := lookPath("toktrail"); err == nil {
		pathCopy = found
	}

	cfg := scheduler.TaskConfig{
		Platform: platformOf(),
		StateDir: strings.TrimSpace(opt.StateDir),
		Binary:   current,
		Interval: scheduler.DefaultInterval,
		HomeDir:  opt.HomeDir,
	}
	registered := ""
	source := ""
	registerErr := error(nil)
	if path, src, found, err := scheduler.RegisteredBinary(cfg); err != nil {
		// "Could not read the registration" is not "no registration": saying
		// nothing would report a healthy install that cannot be verified.
		registerErr = err
	} else if found {
		registered, source = path, src
	}
	if registerErr != nil {
		return Check{
			Name:   "binary",
			Status: CheckWarn,
			Detail: fmt.Sprintf("%s (%s); the scheduled task could not be inspected, so the schedule's binary is unverified", current, versionLabel),
		}
	}

	switch {
	case registered != "" && resolvePath(registered) != currentResolved:
		return Check{
			Name:   "binary",
			Status: CheckFail,
			Detail: fmt.Sprintf("the schedule starts %s (from %s), but this command is %s (%s); upgrading this copy would not affect scheduled runs - upgrade or reinstall the scheduled path, or re-register the schedule with `toktrail service install`", registered, source, current, versionLabel),
		}
	case pathCopy != "" && resolvePath(pathCopy) != currentResolved:
		return Check{
			Name:   "binary",
			Status: CheckWarn,
			Detail: fmt.Sprintf("PATH resolves `toktrail` to %s while this command is %s (%s); two installations exist, so a shell command and the scheduled run may use different builds", pathCopy, current, versionLabel),
		}
	case registered != "":
		return Check{
			Name:   "binary",
			Status: CheckOK,
			Detail: fmt.Sprintf("%s (%s); the schedule starts this same binary", current, versionLabel),
		}
	default:
		return Check{
			Name:   "binary",
			Status: CheckOK,
			Detail: fmt.Sprintf("%s (%s); no scheduled task to compare against", current, versionLabel),
		}
	}
}

// resolvePath makes two spellings of one file comparable (absolute, symlinks
// resolved). An unresolvable path falls back to its cleaned form so the
// comparison still happens; a resolution difference alone must never turn a
// healthy install into a failure.
func resolvePath(path string) string {
	clean := filepath.Clean(path)
	if abs, err := filepath.Abs(clean); err == nil {
		clean = abs
	}
	if resolved, err := filepath.EvalSymlinks(clean); err == nil {
		return resolved
	}
	return clean
}

func backgroundTaskCheck(info scheduler.WindowsTaskInfo, inspectErr error, stateDir string) Check {
	check := Check{Name: "background"}
	switch {
	case inspectErr != nil:
		check.Status, check.Detail = CheckWarn, "scheduled background action could not be verified"
	case !info.Registered:
		check.Status, check.Detail = CheckSkipped, "no scheduled task to inspect"
	case !info.Background:
		check.Status, check.Detail = CheckWarn, "the legacy scheduled task opens a console; run `toktrail service refresh` to migrate it without changing grants or binding"
	default:
		file, err := os.Lstat(info.Launcher)
		if err != nil || !file.Mode().IsRegular() {
			check.Status, check.Detail = CheckFail, "the scheduled background launcher is missing or is not a regular file; reinstall the complete Windows release"
		} else {
			check.Status, check.Detail = CheckOK, "windowless launch configured; logs in "+filepath.Join(stateDir, "logs")
		}
	}
	return check
}

func scanCacheCheck(stateDir string) Check {
	sources := []string{
		adapter.CodexJSONLSource,
		adapter.ClaudeCodeJSONLSource,
		adapter.DeepSeekHarnessSource,
	}
	trackedSources, trackedFiles := 0, 0
	for _, source := range sources {
		states, existed, err := scanledger.New(stateDir).Load(source)
		if err != nil || !existed {
			continue
		}
		trackedSources++
		trackedFiles += len(states)
	}
	if trackedSources == 0 {
		return Check{Name: "scan-cache", Status: CheckOK, Detail: "no incremental scan state yet; the first collection run records it, and later runs skip unchanged history"}
	}
	return Check{
		Name:   "scan-cache",
		Status: CheckOK,
		Detail: fmt.Sprintf("%d source(s) with committed scan state covering %d file(s); unchanged history is skipped", trackedSources, trackedFiles),
	}
}

func Doctor(opt DoctorOptions) (DoctorReport, error) {
	stateDir := strings.TrimSpace(opt.StateDir)
	if stateDir == "" {
		return DoctorReport{}, errors.New("collector state directory is required")
	}
	report := DoctorReport{StateDir: stateDir}
	add := func(name string, status CheckStatus, format string, args ...any) {
		report.Checks = append(report.Checks, Check{Name: name, Status: status, Detail: fmt.Sprintf(format, args...)})
	}

	// 1. Device binding + consent state (local read only).
	st, err := statedir.New(stateDir).Load()
	if err != nil {
		add("state", CheckFail, "device state unreadable: %v", err)
		return report, nil
	}
	add("state", CheckOK, "state directory present, version=%s", stateDir)
	if st.DeviceID == "" || st.DeviceSecret == "" {
		add("binding", CheckWarn, "device is not bound; scheduled collection drains nothing until `toktrail bind` succeeds")
	} else {
		add("binding", CheckOK, "device bound (device id %s)", st.DeviceID)
	}
	if st.Revoked {
		add("consent", CheckFail, "device is revoked on the server; uploads are refused until rebind")
	} else if !st.UploadAuthorized {
		add("consent", CheckWarn, "upload consent is not authorized; pending batches stay local")
	} else {
		add("consent", CheckOK, "upload consent authorized (revision %d)", st.ConsentRevision)
	}

	// Cursor diagnostics inspect only TokTrail-owned permission/queue files.
	cursorCheck, cursorActive := cursorDoctor(stateDir)
	if cursorCheck.Status != CheckSkipped {
		report.Checks = append(report.Checks, cursorCheck)
	}

	// Incremental-scan state: after the first run, unchanged history files
	// are skipped. Reporting it makes an upgrade verifiable — a state
	// directory that has never run has none, and one that has run shows the
	// files it covers.
	report.Checks = append(report.Checks, scanCacheCheck(stateDir))

	// 2. Local-file grants (Cursor account sources do not use grants.json).
	enabledGrants, err := grants.New(stateDir).Enabled()
	if err != nil {
		add("grants", CheckFail, "sources config unreadable: %v", err)
	} else if len(enabledGrants) == 0 && cursorActive {
		add("grants", CheckOK, "no local-file grants; Cursor uses its separate account-source permit")
	} else if len(enabledGrants) == 0 {
		add("grants", CheckWarn, "no enabled source grants; the periodic run collects nothing (enable with `toktrail sources enable`)")
	} else {
		ok := true
		for _, grant := range enabledGrants {
			if err := grants.ValidateInput(grant.Input); err != nil {
				add("grant "+grant.Source, CheckFail, "input %s not accessible: %v", grant.Input, err)
				ok = false
			}
		}
		if ok {
			add("grants", CheckOK, "%d enabled source grant(s)", len(enabledGrants))
		}
	}

	// 3. Pending export transaction (WAL journal).
	if journalExists(stateDir) {
		add("export-journal", CheckWarn, "an export transaction is mid-commit; the next run recovers it automatically")
	} else {
		add("export-journal", CheckOK, "no pending export transaction")
	}

	// 4. Outbox + quarantine.
	pendingBatches, pendingRecords, err := pendingSummary(stateDir)
	if err != nil {
		add("outbox", CheckFail, "outbox unreadable: %v", err)
	} else if pendingBatches == 0 {
		add("outbox", CheckOK, "no pending batches")
	} else {
		add("outbox", CheckOK, "%d pending batch(es), %d record(s) awaiting upload", pendingBatches, pendingRecords)
	}
	quarantined, err := quarantine.New(stateDir).Load()
	if err != nil {
		add("quarantine", CheckFail, "quarantine store unreadable: %v", err)
	} else if len(quarantined) == 0 {
		add("quarantine", CheckOK, "no quarantined records")
	} else {
		add("quarantine", CheckWarn, "%d quarantined record group(s); `toktrail sync` attempts recovery under the live scope", len(quarantined))
	}

	// 5. Scheduler task (local file inspection only).
	home := strings.TrimSpace(opt.HomeDir)
	if home == "" {
		add("scheduler", CheckSkipped, "home directory unknown; task inspection skipped")
	} else if strings.TrimSpace(opt.Binary) == "" {
		add("scheduler", CheckSkipped, "binary path unknown; task inspection skipped")
	} else {
		cfg := scheduler.TaskConfig{
			Platform: platformOf(),
			StateDir: stateDir,
			Binary:   opt.Binary,
			Interval: scheduler.DefaultInterval,
			HomeDir:  home,
		}
		installed, files, err := scheduler.IsInstalledWithRunner(cfg, opt.Runner)
		if err != nil {
			add("scheduler", CheckWarn, "task inspection failed: %v", err)
		} else if installed {
			report.TaskInstalled = true
			report.TaskFiles = files
			add("scheduler", CheckOK, "scheduled task installed (%s)", strings.Join(files, ", "))
		} else {
			add("scheduler", CheckWarn, "no scheduled task for this state directory (`toktrail service install`)")
		}
	}

	// 5b. Version and installation identity. An upgrade replaces the binary at
	// ONE path; if the schedule starts a different copy (a second install, an
	// older PATH copy, a symlink target that moved), the upgrade silently does
	// nothing for the scheduled runs. Compare the three paths that matter and
	// say which is which instead of leaving "I upgraded but nothing changed".
	report.Checks = append(report.Checks, binaryIdentityCheck(opt))
	if platformOf() == "windows" && strings.TrimSpace(opt.Binary) != "" {
		info, inspectErr := scheduler.WindowsTaskStatus(scheduler.TaskConfig{
			Platform: "windows", StateDir: stateDir, Binary: opt.Binary,
			HomeDir: opt.HomeDir, Interval: scheduler.DefaultInterval,
		})
		report.Checks = append(report.Checks, backgroundTaskCheck(info, inspectErr, stateDir))
	}

	// 6. Optional server check (the only network path, explicit opt-in).
	if opt.CheckServer {
		client := opt.HTTPClient
		if client == nil {
			client = &http.Client{Timeout: 15 * time.Second}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		result, err := statuscmd.Run(ctx, statedir.New(stateDir), statuscmd.Options{
			ServerURL:  opt.ServerURL,
			HTTPClient: client,
		})
		cancel()
		if err != nil {
			add("server", CheckFail, "server check failed: %v", err)
		} else {
			add("server", CheckOK, "server reachable, uploadAuthorized=%t", result.State.UploadAuthorized)
		}
	} else {
		add("server", CheckSkipped, "server check skipped (pass --check-server for the only networked check)")
	}

	return report, nil
}

func journalExists(stateDir string) bool {
	// The export WAL journal file exists only mid-transaction; its
	// presence after a crash is recovered by the next command.
	info, err := os.Stat(exportcommit.JournalPath(stateDir))
	return err == nil && !info.IsDir()
}

func platformOf() string { return runtime.GOOS }
