//go:build !windows

package installer

import "os/exec"

// hideConsoleWindow is a no-op outside Windows: there is no console window
// to hide when probing an installed binary for its version.
func hideConsoleWindow(*exec.Cmd) {}
