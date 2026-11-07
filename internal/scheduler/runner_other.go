//go:build !windows

package scheduler

import "os/exec"

func configureSchedulerCommand(cmd *exec.Cmd) {}
