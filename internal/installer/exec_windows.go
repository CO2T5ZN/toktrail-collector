//go:build windows

package installer

import (
	"os/exec"
	"syscall"
)

// hideConsoleWindow keeps a version probe of an installed binary from
// flashing a console window when the installer runs from a GUI context.
func hideConsoleWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}
