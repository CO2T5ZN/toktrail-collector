package scheduler

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// windowsTaskName returns the schtasks task name for this identity. The
// leading backslash places it in the task root folder.
func windowsTaskName(identity string) string {
	return "\\" + "TokTrailCollector-" + strings.TrimPrefix(identity, "toktrail-collector-")
}

// windowsMaxTaskInterval is the upper bound the Task Scheduler schema
// places on the Repetition Interval element (P31D); the lower bound is
// MinInterval (PT1M). See
// https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-interval-repetitiontype-element
const windowsMaxTaskInterval = 31 * 24 * time.Hour

// validateWindowsInterval fails closed when the configured interval cannot
// be expressed as a schema-valid Repetition Interval value (the element is
// an xs:duration bounded to PT1M..P31D). The schema granularity is whole
// minutes, so sub-minute remainders of in-range intervals keep the
// historical truncation behavior of formatWindowsInterval instead of
// failing (90s still schedules as PT1M).
func validateWindowsInterval(d time.Duration) error {
	if d < MinInterval {
		return fmt.Errorf("interval %s is below the Windows Task Scheduler minimum of %s", d, MinInterval)
	}
	if d > windowsMaxTaskInterval {
		return fmt.Errorf("interval %s exceeds the Windows Task Scheduler maximum of %s", d, windowsMaxTaskInterval)
	}
	return nil
}

// renderTaskSchedulerInstall renders a schtasks-based per-user task. The
// task definition is written as XML (properly escaped) to a scratch file
// and registered with `schtasks /Create /F /XML <file> /TN <name>` using
// an argument array — no shell, no string concatenation into a command
// line, so paths with spaces and metacharacters are safe.
func renderTaskSchedulerInstall(cfg TaskConfig, plan Plan) (Plan, error) {
	if err := validateWindowsInterval(cfg.Interval); err != nil {
		return plan, err
	}
	// The principal must name a concrete account: the Task Scheduler
	// schema types UserId as nonEmptyString, and LogonType is only
	// meaningful together with a UserId. Resolve the current user's
	// identity from the operating system (never the forgeable
	// USERNAME/USERDOMAIN environment variables) and fail closed when it
	// is unavailable, so no invalid definition is ever written.
	userID, err := windowsPrincipalUserID()
	if err != nil {
		return plan, err
	}
	if strings.TrimSpace(userID) == "" {
		return plan, errors.New("windows task principal user id resolved to an empty value")
	}
	taskName := windowsTaskName(plan.TaskName)
	xmlPath := filepath.Join(os.TempDir(), plan.TaskName+".task.xml")
	plan.Files = []FileWrite{{
		Path:     xmlPath,
		Mode:     0o600,
		Temp:     true,
		Content:  renderWindowsTaskXML(taskName, userID, cfg.Binary, plan.Marker, cfg.Interval),
		Encoding: EncodingUTF16LE,
	}}
	plan.Commands = []Command{
		{
			Name:    "schtasks",
			Args:    []string{"/Create", "/F", "/XML", xmlPath, "/TN", taskName},
			Purpose: "register the Task Scheduler task for the current user",
		},
	}
	plan.UndoCommands = []Command{
		{
			Name:       "schtasks",
			Args:       []string{"/Delete", "/F", "/TN", taskName},
			Purpose:    "delete the partially registered task",
			BestEffort: true,
		},
	}
	plan.UninstallCommands = []Command{
		{
			Name:       "schtasks",
			Args:       []string{"/Delete", "/F", "/TN", taskName},
			Purpose:    "delete the Task Scheduler task",
			BestEffort: true,
		},
	}
	// The task itself lives in the OS task store, not in files we own, so
	// there is nothing to remove from disk.
	plan.RemoveFiles = nil
	return plan, nil
}

func renderTaskSchedulerUninstall(cfg TaskConfig, plan Plan) (Plan, error) {
	taskName := windowsTaskName(plan.TaskName)
	plan.UninstallCommands = []Command{
		{
			Name:       "schtasks",
			Args:       []string{"/Delete", "/F", "/TN", taskName},
			Purpose:    "delete the Task Scheduler task",
			BestEffort: true,
		},
	}
	return plan, nil
}

// renderWindowsTaskXML writes the Task Scheduler 1.2 definition. The task
// runs the complete-exit `periodic` command for the current interactive
// user (LeastPrivilege), repeats every interval, and lets the collector's
// own process lock refuse overlapping instances (IgnoreNew policy).
//
// The returned text is readable UTF-8 for dry-run display; on disk it is
// written as UTF-16LE with a byte-order mark (see EncodingUTF16LE), and
// the declaration below says UTF-16 to match those bytes. schtasks
// /Create /XML rejects task definitions saved as UTF-8 with "unable to
// switch encoding" and accepts the UTF-16LE + BOM form that schtasks
// itself exports via `schtasks /Query /XML`, so declaration, BOM, and
// byte encoding must stay consistent.
//
// userID is the account identity for the principal, resolved from the
// operating system by the caller. The Task Scheduler schema types UserId
// as nonEmptyString (an explicit empty element is invalid), and
// LogonType is only meaningful together with a UserId, so the caller
// fails closed on an empty identity. InteractiveToken keeps the
// no-stored-credentials, only-while-logged-on semantics of a per-user
// task.
func renderWindowsTaskXML(taskName, userID, binary, stateDir string, interval time.Duration) string {
	arguments := windowsBackgroundArguments(binary, stateDir)
	launcher := WindowsBackgroundPath(binary)
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-16"?>` + "\n")
	b.WriteString(`<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">` + "\n")
	b.WriteString("  <RegistrationInfo>\n")
	b.WriteString("    <Description>")
	b.WriteString(xmlEscape("TokTrail collector scheduled collection (user, complete-exit) for state directory " + stateDir))
	b.WriteString("</Description>\n")
	b.WriteString("    <URI>")
	b.WriteString(xmlEscape(taskName))
	b.WriteString("</URI>\n")
	b.WriteString("    <Author>TokTrail collector</Author>\n")
	b.WriteString("  </RegistrationInfo>\n")
	b.WriteString("  <Triggers>\n")
	b.WriteString("    <TimeTrigger>\n")
	b.WriteString("      <Repetition>\n")
	b.WriteString("        <Interval>")
	b.WriteString(xmlEscape(formatWindowsInterval(interval)))
	b.WriteString("</Interval>\n")
	b.WriteString("        <StopAtDurationEnd>false</StopAtDurationEnd>\n")
	b.WriteString("      </Repetition>\n")
	b.WriteString("      <StartBoundary>2020-01-01T00:00:00</StartBoundary>\n")
	b.WriteString("      <Enabled>true</Enabled>\n")
	b.WriteString("    </TimeTrigger>\n")
	b.WriteString("  </Triggers>\n")
	b.WriteString("  <Principals>\n")
	b.WriteString("    <Principal id=\"Author\">\n")
	b.WriteString("      <UserId>")
	b.WriteString(xmlEscape(userID))
	b.WriteString("</UserId>\n")
	b.WriteString("      <LogonType>InteractiveToken</LogonType>\n")
	b.WriteString("      <RunLevel>LeastPrivilege</RunLevel>\n")
	b.WriteString("    </Principal>\n")
	b.WriteString("  </Principals>\n")
	b.WriteString("  <Settings>\n")
	b.WriteString("    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n")
	b.WriteString("    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n")
	b.WriteString("    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n")
	b.WriteString("    <AllowHardTerminate>true</AllowHardTerminate>\n")
	b.WriteString("    <StartWhenAvailable>false</StartWhenAvailable>\n")
	b.WriteString("    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n")
	b.WriteString("    <AllowStartOnDemand>true</AllowStartOnDemand>\n")
	b.WriteString("    <Enabled>true</Enabled>\n")
	b.WriteString("    <Hidden>false</Hidden>\n")
	b.WriteString("    <RunOnlyIfIdle>false</RunOnlyIfIdle>\n")
	b.WriteString("    <WakeToRun>false</WakeToRun>\n")
	b.WriteString("    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>\n")
	b.WriteString("    <Priority>7</Priority>\n")
	b.WriteString("  </Settings>\n")
	b.WriteString("  <Actions Context=\"Author\">\n")
	b.WriteString("    <Exec>\n")
	b.WriteString("      <Command>")
	b.WriteString(xmlEscape(launcher))
	b.WriteString("</Command>\n")
	b.WriteString("      <Arguments>")
	b.WriteString(xmlEscape(arguments))
	b.WriteString("</Arguments>\n")
	b.WriteString("    </Exec>\n")
	b.WriteString("  </Actions>\n")
	b.WriteString("</Task>\n")
	return b.String()
}

// formatWindowsInterval renders an interval as an ISO 8601 duration for
// the Task Scheduler Repetition/Interval element (minutes granularity).
// The xs:duration designators are uppercase (P31DT23H59M style); the
// schema documents PT1M as the minimum and P31D as the maximum, and
// sub-minute remainders of in-range intervals truncate (90s -> PT1M).
func formatWindowsInterval(d time.Duration) string {
	minutes := int64(d / time.Minute)
	return fmt.Sprintf("PT%dM", minutes)
}
