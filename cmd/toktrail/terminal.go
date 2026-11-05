package main

import (
	"io"
	"os"

	"toktrail-collector/internal/console"
)

// isTerminalWriter reports whether w is attached to a terminal. Only a
// real *os.File can be one; buffers and serialized wrappers used by tests
// are never terminals, so they take the quiet log path.
func isTerminalWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return console.IsTerminal(f)
}
