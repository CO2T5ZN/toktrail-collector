//go:build windows

package console

import (
	"errors"
	"io"
	"os"
)

// openAnswerSource opens the console input for one confirmation.
//
// The Windows install path downloads the script to a file and runs
// `powershell -File`, so stdin is not carrying a program there; CONIN$ is
// still preferred so that a redirected or piped stdin cannot be mistaken
// for an answer. stdin is accepted only when it is a character device.
func openAnswerSource() (io.ReadCloser, error) {
	f, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err == nil {
		return f, nil
	}
	if IsTerminal(os.Stdin) {
		return io.NopCloser(os.Stdin), nil
	}
	return nil, errors.New("no console input")
}

// isCharDevice reports whether info describes a character device (the
// Windows console test).
func isCharDevice(info os.FileInfo) bool {
	return info.Mode()&os.ModeCharDevice != 0
}
