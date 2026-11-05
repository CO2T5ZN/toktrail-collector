//go:build darwin || linux

package console

import (
	"errors"
	"io"
	"os"
)

// openAnswerSource opens the controlling terminal for one confirmation.
//
// The controlling terminal is preferred because the documented install
// runs as `curl … | sh -s -- …`: the collector then inherits the script
// pipeline as stdin, and reading it yields EOF (or, under incrementally
// parsing shells, the next script line). /dev/tty always refers to the
// user's terminal and is unaffected by shell redirections.
//
// stdin is accepted only when it is itself a character device, i.e. the
// user really is answering at a terminal; a pipe, a regular file or a
// closed stream is refused so no program text can be mistaken for an
// answer.
func openAnswerSource() (io.ReadCloser, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err == nil {
		return f, nil
	}
	if IsTerminal(os.Stdin) {
		return io.NopCloser(os.Stdin), nil
	}
	return nil, errors.New("no controlling terminal")
}

// isCharDevice reports whether info describes a character device (the
// POSIX terminal test).
func isCharDevice(info os.FileInfo) bool {
	return info.Mode()&os.ModeCharDevice != 0
}
