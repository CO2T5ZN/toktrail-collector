package scheduler

import (
	"bytes"
	"os/exec"
)

// Structured stdout (task XML or a numeric task result) must never include
// diagnostic stderr. Windows PowerShell may emit CLIXML initialization progress
// on stderr even when the command succeeds.
func captureSchedulerOutput(cmd *exec.Cmd) (stdout, stderr []byte, err error) {
	var diagnostic bytes.Buffer
	cmd.Stderr = &diagnostic
	stdout, err = cmd.Output()
	return stdout, diagnostic.Bytes(), err
}
