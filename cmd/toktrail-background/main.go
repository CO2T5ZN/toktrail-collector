// Command toktrail-background is the Windows background helper for the
// TokTrail GUI (built as toktrail-background.exe; see
// internal/winbackground.BinaryName).
//
// It runs the collector's periodic entry hidden (no console window, no
// message boxes), appends its stdout/stderr to the state directory's
// rotating logs (<state-dir>/logs/periodic.out.log and periodic.err.log),
// keeps it inside a kill-on-close Windows Job Object so no orphaned
// collector survives an aborted helper, and forwards the collector's real
// exit code. It never runs anything through a shell. See
// internal/winbackground for the full contract; the mainline owns the
// scheduling and release integration.
//
// Usage:
//
//	toktrail-background --collector <absolute collector exe path> --state-dir <absolute existing state directory>
//	toktrail-background --version
package main

import (
	"fmt"
	"os"

	"toktrail-collector/internal/winbackground"
)

// version is injected at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

// run is the testable entry: it answers --version locally (so the GUI
// can probe the helper without a state directory) and delegates
// everything else to winbackground.Run, whose return value is the
// process exit code.
func run(args []string) int {
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		fmt.Println("toktrail-background", version)
		return 0
	}
	return winbackground.Run(args)
}
