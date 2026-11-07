package scheduler

import (
	"os/exec"
	"strings"
)

// runCommand executes a command with an argument array, never through a
// shell. Output is captured for the error message only; it never contains
// credentials because no secret is ever passed as an argument.
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	configureSchedulerCommand(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return err
		}
		if len(msg) > 400 {
			msg = msg[:400] + "..."
		}
		return &commandError{err: err, name: name, output: msg}
	}
	return nil
}

type commandError struct {
	err    error
	name   string
	output string
}

func (e *commandError) Error() string {
	return e.err.Error() + ": " + e.output
}

func (e *commandError) Unwrap() error { return e.err }
