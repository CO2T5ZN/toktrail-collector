//go:build !windows

package winbackground

// runCollector is the non-Windows stub. The helper is a Windows-only
// integration (the GUI launches it to supervise a hidden collector), so
// on every other platform it fails fast with a fixed phrase instead of
// pretending to supervise anything. This keeps `go test ./...` and any
// accidental non-Windows invocation well-defined.
func runCollector(o options) int {
	reportFailure("this helper only runs on Windows")
	return ExitUnsupportedOS
}
