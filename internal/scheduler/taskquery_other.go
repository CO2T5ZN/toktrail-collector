//go:build !windows

package scheduler

import "os/exec"

func schedulerOutputCommand(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}
func schedulerOutputError(_ string, _ []string, err error) error { return err }
