//go:build windows

package scheduler

import (
	"os/exec"
	"syscall"
)

func configureSchedulerCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}
