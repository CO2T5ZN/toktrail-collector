//go:build windows

package scheduler

import (
	"encoding/base64"
	"os/exec"
)

// schedulerOutputCommand isolates XML retrieval from schtasks' locale-dependent
// stdout. Keep the existing runner API for deterministic tests, but production
// reads the authoritative Unicode task definition through Task Scheduler COM.
func schedulerOutputCommand(name string, args ...string) *exec.Cmd {
	if name == "schtasks" && len(args) == 4 && args[0] == "/Query" && args[1] == "/TN" && args[3] == "/XML" {
		if script, err := windowsTaskQueryScript(args[2]); err == nil {
			// -EncodedCommand is UTF-16LE base64, without a BOM. The decoded
			// program only contains a validated fixed-format ASCII task name.
			encoded := base64.StdEncoding.EncodeToString(encodeUTF16LEWithBOM(script)[2:])
			return exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded)
		}
	}
	return exec.Command(name, args...)
}

func schedulerOutputError(name string, args []string, err error) error {
	if name == "schtasks" && len(args) == 4 && args[0] == "/Query" && args[1] == "/TN" && args[3] == "/XML" {
		if _, validErr := windowsTaskQueryScript(args[2]); validErr == nil {
			if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == windowsTaskMissingExit {
				return errWindowsTaskMissing
			}
		}
	}
	return err
}
