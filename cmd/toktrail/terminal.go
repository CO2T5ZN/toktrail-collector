package main

import (
	"io"
	"os"

	"toktrail-collector/internal/console"
)

// isTerminalWriter reports whether w is an output stream that may
// render in-place terminal output (carriage return + ANSI erase-line).
// Only a real *os.File can be one; buffers and serialized wrappers
// used by tests are never terminals, so they take the quiet log path.
//
// Being a terminal is necessary but, on Windows, not sufficient: the
// heartbeat's in-place line rewrites with "\r\x1b[K" only render
// correctly when the console interprets VT sequences. On a legacy
// Windows console those bytes print as literal text ("[ K" garbage).
// The check therefore also requires the console to support (or accept)
// ENABLE_VIRTUAL_TERMINAL_PROCESSING; when it does not, this returns
// false and callers fall back to plain one-line log output.
//
// Unix behavior is unchanged: a character device is enough. Redirected
// output is false on every platform. This is purely an OUTPUT-stream
// decision — whether the user can answer a confirmation prompt is a
// separate input-stream question owned by internal/console's prompt
// code and is deliberately not consulted here.
func isTerminalWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return console.SupportsANSI(f)
}
