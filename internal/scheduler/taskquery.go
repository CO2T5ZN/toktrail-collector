package scheduler

import (
	"errors"
	"fmt"
	"strings"
)

// These private statuses belong to our PowerShell query bridge, not schtasks
// or arbitrary process exit codes. Missing tasks are classified from COM's
// HRESULT, never localized command output.
const (
	windowsTaskMissingExit     = 44
	windowsTaskQueryFailedExit = 45
)

var errWindowsTaskMissing = errors.New("windows scheduled task not found")

// Windows command-line tools may encode redirected XML through the active
// OEM/ANSI code page, irreversibly replacing characters not in that page.
// Retrieve the original Unicode BSTR from Task Scheduler and write explicit
// UTF-8 bytes to stdout instead. This query never registers or edits a task.
func windowsTaskQueryScript(taskName string) (string, error) {
	const prefix = `\TokTrailCollector-`
	if !strings.HasPrefix(taskName, prefix) || len(taskName) != len(prefix)+16 {
		return "", errors.New("invalid collector task name")
	}
	for _, c := range taskName[len(prefix):] {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return "", errors.New("invalid collector task identity")
		}
	}
	// Only the fixed ASCII task name is inserted into PowerShell source.
	// Source paths, endpoint URLs and credentials are never script text.
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
try {
  $service = New-Object -ComObject 'Schedule.Service'
  $service.Connect()
  $folder = $service.GetFolder('\')
  $task = $folder.GetTask('%s')
  $encoding = New-Object System.Text.UTF8Encoding($false)
  $bytes = $encoding.GetBytes([string]$task.Xml)
  $stdout = [Console]::OpenStandardOutput()
  $stdout.Write($bytes, 0, $bytes.Length)
  $stdout.Flush()
} catch {
  $failure = $_.Exception
  while ($null -ne $failure) {
    if ($failure.HResult -eq -2147024894) { exit %d }
    $failure = $failure.InnerException
  }
  [Console]::Error.WriteLine('scheduled task XML query failed')
  exit %d
}
`, strings.TrimPrefix(taskName, `\`), windowsTaskMissingExit, windowsTaskQueryFailedExit), nil
}
