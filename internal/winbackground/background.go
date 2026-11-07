// Package winbackground implements the Windows background helper that
// the TokTrail GUI builds as toktrail-background.exe (BinaryName).
//
// The helper exists because a windowed GUI application cannot run the
// collector's periodic entry directly without side effects it must never
// cause: a console flash, an orphaned child after a GUI crash, and lost
// output. The helper is a small, single-purpose supervisor:
//
//   - It accepts exactly two flags, --collector <absolute path to the
//     collector executable> and --state-dir <absolute path to an existing
//     state directory>, and runs
//     `<collector> periodic --state-dir <state-dir>` through an argument
//     array — never through a shell, so paths with spaces and
//     metacharacters are safe by construction.
//   - On Windows the collector is started with CREATE_NO_WINDOW (and a
//     hidden window), so it can never flash a console or show UI; its
//     stdin is the NUL device; its stdout and stderr are appended to
//     <state-dir>/logs/periodic.out.log and periodic.err.log, each with
//     size-limited rotation (one archived generation per stream).
//   - On Windows the collector is placed in a Job Object created with
//     JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE and the helper holds the only
//     job handle, so an aborted helper (GUI crash, logoff, taskkill)
//     cannot leave an orphaned collector behind. If the child cannot be
//     assigned to the job it is terminated and the helper fails — it
//     never reports a success it could not supervise.
//   - The helper waits for the collector's real exit code and forwards
//     it. Its own failures use the dedicated exit codes below with fixed
//     safe phrases that never embed paths, command lines, or raw system
//     error text, so nothing credential-bearing can leak into logs.
//   - On non-Windows platforms Run is a stub returning
//     ExitUnsupportedOS. The helper is a Windows-only integration; the
//     stub keeps `go test ./...` and cross-compilation well-defined.
//
// The mainline owns scheduling and release integration: the GUI build
// produces the helper under the name below and launches it hidden.
package winbackground

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// BinaryName is the file name the GUI build produces for this helper.
// It is the single source of truth shared with the GUI integration and
// the release pipeline.
const BinaryName = "toktrail-background.exe"

// Exit codes returned by Run. The collector's own exit codes (its CLI
// exits 0 or 1 today) are forwarded verbatim, so the helper keeps a
// disjoint range for its own failures; callers can therefore tell a
// forwarded collector result apart from a helper failure.
const (
	// ExitSuccess reports that the collector ran and exited 0.
	ExitSuccess = 0
	// ExitUsage reports invalid helper arguments; nothing was started.
	ExitUsage = 2
	// ExitLaunchFailure reports that the helper could not start,
	// supervise, or observe the collector. A child that could not be
	// placed under supervision is terminated first: never a fake success.
	ExitLaunchFailure = 3
	// ExitUnsupportedOS reports a Run call on a non-Windows platform.
	ExitUnsupportedOS = 4
)

// usageLine is the fixed help text printed with argument failures.
const usageLine = "usage: " + BinaryName + " --collector <absolute collector exe path> --state-dir <absolute existing state directory>"

// Log layout inside the state directory. The file names match the
// scheduled-collection log contract so a state directory looks the same
// whether a run was launched by the OS scheduler or by the GUI helper.
const (
	logsDirName = "logs"
	outLogName  = "periodic.out.log"
	errLogName  = "periodic.err.log"
)

// options holds the validated helper arguments.
type options struct {
	collector string
	stateDir  string
}

// parseOptions parses and validates the helper argument list (os.Args[1:]
// shape). Every returned error is a fixed phrase: it names the violated
// contract but never echoes the offending value, so argument text (which
// the caller controls and which could contain anything) never reaches a
// log line.
func parseOptions(args []string) (options, error) {
	var o options
	seenCollector := false
	seenStateDir := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--collector":
			if i+1 >= len(args) {
				return o, errors.New("--collector requires a value")
			}
			if seenCollector {
				return o, errors.New("--collector must be passed exactly once")
			}
			o.collector = args[i+1]
			seenCollector = true
			i++
		case "--state-dir":
			if i+1 >= len(args) {
				return o, errors.New("--state-dir requires a value")
			}
			if seenStateDir {
				return o, errors.New("--state-dir must be passed exactly once")
			}
			o.stateDir = args[i+1]
			seenStateDir = true
			i++
		default:
			return o, errors.New("unexpected argument")
		}
	}
	if !seenCollector {
		return o, errors.New("--collector is required")
	}
	if !seenStateDir {
		return o, errors.New("--state-dir is required")
	}
	if err := validateCollectorPath(o.collector); err != nil {
		return o, err
	}
	if err := validateStateDir(o.stateDir); err != nil {
		return o, err
	}
	return o, nil
}

// validateCollectorPath requires an absolute path to an existing regular
// file. Requiring the absolute path keeps the spawned command independent
// of the helper's working directory; requiring an existing regular file
// fails closed before any child exists (a directory or a missing binary
// is a caller bug, not something to retry).
func validateCollectorPath(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("--collector must be an absolute path")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("--collector must point to an existing executable file")
	}
	return nil
}

// validateStateDir requires an absolute path to an existing directory:
// the state directory owns the logs the helper appends to, so a missing
// or relative directory is a caller bug, not something the helper creates
// on its own.
func validateStateDir(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("--state-dir must be an absolute path")
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return errors.New("--state-dir must point to an existing directory")
	}
	return nil
}

// Run executes the helper for args (os.Args[1:] shape, without the
// program name) and returns the process exit code: the collector's real
// exit code on Windows, or one of the helper's own codes above. Bad
// input never panics; every failure path emits a fixed-phrase
// diagnostic on stderr.
func Run(args []string) int {
	o, err := parseOptions(args)
	if err != nil {
		reportFailure(err.Error())
		fmt.Fprintln(os.Stderr, usageLine)
		return ExitUsage
	}
	return runCollector(o)
}

// logLine renders one fixed safe phrase — a failure diagnostic or a
// lifecycle marker — in the same shape the collector CLI uses for its
// long-lived appended error logs. phrase must always be a fixed literal
// (plus, for lifecycle markers, the run's numeric exit code); callers
// never interpolate paths, command lines, or raw system error text into
// it.
func logLine(phrase string) string {
	return fmt.Sprintf("[%s] toktrail-background: %s\n", time.Now().Format("2006-01-02 15:04:05"), phrase)
}

// reportFailure writes one fixed safe diagnostic to the helper's own
// stderr. Write errors are ignored: under a windowed (no-console) build
// stderr is an invalid handle, and the exit code already carries the
// failure.
func reportFailure(phrase string) {
	fmt.Fprint(os.Stderr, logLine(phrase))
}
