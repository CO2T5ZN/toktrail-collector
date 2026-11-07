// ANSI output capability detection.
//
// This file is deliberately separate from the confirmation-prompt code
// in prompt.go: the two answer different questions. The prompt asks
// "can the USER answer us" (an input-stream property, see
// openAnswerSource and CONIN$), while SupportsANSI asks "can THIS
// OUTPUT STREAM safely render ANSI control sequences" (an output-stream
// property). A run may have one without the other — a piped stdout
// under an interactive terminal, or a real console whose answer stream
// is redirected — so neither decision may be derived from the other.

package console

import "os"

// SupportsANSI reports whether f is an output stream on which in-place
// ANSI rendering (carriage return + erase-line, "\r\x1b[K") may be
// used.
//
// Semantics per platform:
//
//   - Unix: f is a terminal (character device). Unix terminals
//     interpret ANSI sequences natively, so the historical behavior is
//     preserved unchanged.
//
//   - Windows: f must be a console screen buffer whose
//     ENABLE_VIRTUAL_TERMINAL_PROCESSING mode can be confirmed. Legacy
//     consoles that reject the mode (or already lack it) return false
//     so callers fall back to plain one-line log output instead of
//     leaking the literal text "[ K" into the console.
//
// Redirected output (pipes, files) is always false on every platform,
// and so is any non-file writer.
//
// The Windows probe may SET the console mode (it enables VT processing
// when it is off); that is a one-bit, additive, per-run setting on the
// process's own screen buffer and is the standard way a console
// program opts into ANSI. Nothing else is read or written.
func SupportsANSI(f *os.File) bool {
	if f == nil {
		return false
	}
	return vtSupported(f)
}
