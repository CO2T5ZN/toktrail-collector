// Package console owns the collector's interactive-confirmation input
// handling: which stream an answer is read from, how it is bounded, and
// how a missing terminal is reported.
//
// Why it exists: confirmation prompts used to read os.Stdin directly.
// Under the documented one-line install (`curl … | sh -s -- --connect …`)
// the collector inherits the script pipeline as stdin, so a prompt wrote
// its question to the terminal and then read either EOF or — under shells
// that parse the script incrementally — the following script line. The
// answer source must therefore be the controlling terminal, never a
// stream that may be carrying a program.
package console

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ErrNoInteractiveTerminal reports that no readable controlling terminal
// exists (a headless run, a scheduler, or a pipe-only environment). It is
// distinct from a declined answer: callers must surface "not confirmed"
// and the manual follow-up command instead of pretending the user said no.
var ErrNoInteractiveTerminal = errors.New("no interactive terminal available")

// maxAnswerBytes bounds one answer line: a confirmation is a few bytes,
// and an over-long line is refused without being echoed (an answer read
// from a mis-attached stream may quote arbitrary program text).
const maxAnswerBytes = 64

// AnswerSource opens the stream a confirmation answer is read from. The
// production value prefers the controlling terminal and falls back to
// stdin only when stdin itself is a character device. Tests replace it to
// drive answers deterministically; the returned reader is closed by
// Confirm.
var AnswerSource = func() (io.ReadCloser, error) { return openAnswerSource() }

// IsTerminal reports whether f is attached to a terminal. It is used to
// decide between in-place progress rendering and quiet log output, and to
// refuse a non-terminal answer stream.
func IsTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return isCharDevice(info)
}

// Confirm writes the fixed question to out and reads one answer line.
//
// Semantics (deliberately conservative):
//   - only an explicit "y" or "yes" (case-insensitive, surrounding
//     whitespace ignored) confirms;
//   - any other non-empty answer declines (false, nil);
//   - an empty line declines (false, nil) — the prompt's own [y/N]
//     default;
//   - EOF before any answer is ErrNoInteractiveTerminal, never a decline:
//     a stream that ran dry proves nothing about the user's intent;
//   - no terminal source at all is ErrNoInteractiveTerminal.
//
// Nothing here defaults to confirming, and no environment variable can
// bypass the prompt: --replace-state and the credential flags are the only
// explicit non-interactive channels, and each grants exactly its own
// action.
func Confirm(out io.Writer, question string) (bool, error) {
	if out == nil {
		out = io.Discard
	}
	fmt.Fprint(out, question)
	source, err := AnswerSource()
	if err != nil {
		return false, ErrNoInteractiveTerminal
	}
	defer source.Close()
	line, err := readBoundedLine(source, maxAnswerBytes)
	if err != nil {
		if errors.Is(err, io.EOF) {
			// The stream ran dry without an answer: no terminal, or a
			// source that closed. Either way nothing about the user's
			// intent is known.
			return false, ErrNoInteractiveTerminal
		}
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

// readBoundedLine reads one line, at most max bytes (plus the newline). An
// over-long line is an error; the content read is never included in the
// error (it may quote anything the wrong stream carries).
func readBoundedLine(r io.Reader, max int) (string, error) {
	br := bufio.NewReader(io.LimitReader(r, int64(max)+1))
	line, err := br.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	if len(line) > max {
		return "", fmt.Errorf("input exceeds %d bytes and was refused", max)
	}
	return line, nil
}
