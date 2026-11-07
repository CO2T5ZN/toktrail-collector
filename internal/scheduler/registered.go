package scheduler

// Reading back what the scheduler actually invokes.
//
// Why this exists: an upgrade replaces the binary at one path. If the
// scheduler entry invokes a different path (a second installation, a symlink,
// an older copy on PATH), the upgrade silently does nothing for the scheduled
// runs. Answering "which binary does the scheduler start?" turns that from a
// mystery into a checkable fact.
//
// The answer comes from the registration the collector itself wrote, never
// from PATH: a launchd plist's ProgramArguments[0], a systemd unit's
// ExecStart, or a Task Scheduler task's <Command>.

import (
	"errors"
	"os"
	"strings"
)

// RegisteredBinary reports the binary path the installed schedule starts.
//
// found is false when no schedule is registered for this configuration (the
// caller must not report a mismatch). source names where the answer came from
// so a diagnostic can quote it (for example the plist path).
func RegisteredBinary(cfg TaskConfig) (path string, source string, found bool, err error) {
	return registeredBinaryWithRunner(cfg, ExecRunner{})
}

func registeredBinaryWithRunner(cfg TaskConfig, runner Runner) (string, string, bool, error) {
	plan, err := RenderUninstall(cfg)
	if err != nil {
		return "", "", false, err
	}
	if err := validateRemovePaths(plan); err != nil {
		return "", "", false, err
	}
	switch cfg.Platform {
	case "windows":
		info, _, err := readWindowsTask(cfg, runner)
		if err != nil {
			return "", "", false, err
		}
		if !info.Registered {
			return "", "", false, nil
		}
		return info.Collector, "schtasks:" + windowsTaskName(plan.TaskName), true, nil
	default:
		for _, file := range plan.RemoveFiles {
			raw, readErr := os.ReadFile(file)
			if errors.Is(readErr, os.ErrNotExist) {
				continue
			}
			if readErr != nil {
				return "", "", false, readErr
			}
			text := string(raw)
			if cfg.Platform == "linux" {
				if value, ok := systemdExecStartBinary(text); ok {
					return value, file, true, nil
				}
				continue
			}
			if value, ok := launchdProgramBinary(text); ok {
				return value, file, true, nil
			}
		}
		return "", "", false, nil
	}
}

// launchdProgramBinary extracts ProgramArguments[0] from a rendered plist.
// The collector writes this file itself, so the parse only needs to handle its
// own exact shape: a ProgramArguments array whose first string is the binary.
func launchdProgramBinary(text string) (string, bool) {
	idx := strings.Index(text, "<key>ProgramArguments</key>")
	if idx < 0 {
		return "", false
	}
	rest := text[idx:]
	arrayStart := strings.Index(rest, "<array>")
	if arrayStart < 0 {
		return "", false
	}
	rest = rest[arrayStart+len("<array>"):]
	arrayEnd := strings.Index(rest, "</array>")
	if arrayEnd < 0 {
		return "", false
	}
	rest = rest[:arrayEnd]
	open := strings.Index(rest, "<string>")
	closeIdx := strings.Index(rest, "</string>")
	if open < 0 || closeIdx < open {
		return "", false
	}
	return unescapePlistString(rest[open+len("<string>") : closeIdx]), true
}

// systemdExecStartBinary extracts the command word of ExecStart.
func systemdExecStartBinary(text string) (string, bool) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ExecStart=") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "ExecStart="))
		value = strings.TrimPrefix(value, "-") // systemd's ignore-exit prefix
		if value == "" {
			return "", false
		}
		return systemdUnescapeArg(firstSystemdWord(value)), true
	}
	return "", false
}

// firstSystemdWord returns the first whitespace-separated token, honoring
// double quotes the way the writer escapes them.
func firstSystemdWord(value string) string {
	if strings.HasPrefix(value, `"`) {
		if end := strings.Index(value[1:], `"`); end >= 0 {
			return value[:end+2]
		}
	}
	if idx := strings.IndexAny(value, " \t"); idx >= 0 {
		return value[:idx]
	}
	return value
}

func systemdUnescapeArg(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
		value = value[1 : len(value)-1]
	}
	value = strings.ReplaceAll(value, `\"`, `"`)
	value = strings.ReplaceAll(value, `\\`, `\`)
	return value
}

func unescapePlistString(value string) string {
	value = strings.ReplaceAll(value, `\"`, `"`)
	value = strings.ReplaceAll(value, `\\`, `\`)
	return value
}

// xmlElementText returns the text of the first <name>...</name> element.
func xmlElementText(text, name string) string {
	open := strings.Index(text, "<"+name+">")
	if open < 0 {
		return ""
	}
	rest := text[open+len(name)+2:]
	end := strings.Index(rest, "</"+name+">")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:end])
}
