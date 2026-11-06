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
	"unicode/utf16"
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
	raw, err := readBoundedLine(source, maxAnswerBytes)
	// A line without a trailing newline is still an answer: a console that
	// delivers "y" and then EOF (or closes after the answer) returns the bytes
	// together with io.EOF. Only a stream that produced NOTHING is "no answer".
	if err != nil && len(raw) == 0 {
		if errors.Is(err, io.EOF) {
			// The stream ran dry without an answer: no terminal, or a
			// source that closed. Either way nothing about the user's
			// intent is known.
			return false, ErrNoInteractiveTerminal
		}
		// Any other read failure is reported as its own class. It used to
		// surface as "not confirmed", which reads exactly like a decline -
		// a Windows console answered "y" and the run reported the user had
		// declined, sending them to a manual command for no reason.
		return false, fmt.Errorf("%w: %v", ErrAnswerUnreadable, err)
	}
	switch normalizeAnswer(raw) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

// ErrAnswerUnreadable reports that an answer stream existed but could not be
// read to a decision (an I/O failure, or an over-long line). It is distinct
// from a decline so callers never tell a user they said no when the program
// could not hear them.
var ErrAnswerUnreadable = errors.New("the confirmation answer could not be read")

// normalizeAnswer turns the bytes a terminal produced into the word the user
// typed.
//
// Terminals disagree about how a line arrives: unix ends it with LF, Windows
// with CRLF, a console handle may deliver UTF-16LE (every other byte zero), and
// a read may be NUL padded. Comparing the raw text made a typed "y" decline on
// Windows. NULs, a BOM and control characters are therefore dropped before the
// compare; anything left that is not "y"/"yes" still declines.
func normalizeAnswer(raw []byte) string {
	decoded := decodeIfUTF16(raw)
	var b strings.Builder
	for _, r := range decoded {
		switch {
		case r == 0, r == '\ufeff':
			continue
		case r < 0x20, r == 0x7f: // CR, LF, TAB, DEL and friends
			continue
		default:
			b.WriteRune(r)
		}
	}
	return strings.ToLower(strings.TrimSpace(b.String()))
}

// decodeIfUTF16 decodes a byte slice that is obviously UTF-16 (a BOM, or a
// NUL-heavy ASCII pattern) and returns it unchanged otherwise.
func decodeIfUTF16(raw []byte) string {
	if len(raw) >= 2 {
		if raw[0] == 0xff && raw[1] == 0xfe {
			return decodeUTF16(raw[2:], false)
		}
		if raw[0] == 0xfe && raw[1] == 0xff {
			return decodeUTF16(raw[2:], true)
		}
	}
	// Only a byte sequence where EVERY odd byte is NUL and every even byte is
	// printable ASCII is treated as UTF-16LE. A looser rule (a few NULs) would
	// mis-read a NUL-padded ANSI answer such as "y\0\r\n" as UTF-16 and turn a
	// confirmation into a decline.
	if len(raw) >= 4 && len(raw)%2 == 0 {
		pairs := len(raw) / 2
		asciiPairs := 0
		for i := 0; i+1 < len(raw); i += 2 {
			if raw[i+1] == 0 && raw[i] >= 0x20 && raw[i] < 0x7f {
				asciiPairs++
			}
		}
		if asciiPairs == pairs {
			return decodeUTF16(raw, false)
		}
	}
	return string(raw)
}

func decodeUTF16(raw []byte, bigEndian bool) string {
	if len(raw)%2 != 0 {
		raw = raw[:len(raw)-1]
	}
	units := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		if bigEndian {
			units = append(units, uint16(raw[i])<<8|uint16(raw[i+1]))
		} else {
			units = append(units, uint16(raw[i+1])<<8|uint16(raw[i]))
		}
	}
	return string(utf16.Decode(units))
}

// readBoundedLine reads one line, at most max bytes INCLUDING its terminator.
// An over-long line is an error; the content read is never included in the
// error (it may quote anything the wrong stream carries).
func readBoundedLine(r io.Reader, max int) ([]byte, error) {
	br := bufio.NewReader(io.LimitReader(r, int64(max)+1))
	line, err := br.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return nil, err
	}
	if len(line) > max {
		return nil, fmt.Errorf("input exceeds %d bytes and was refused", max)
	}
	return line, nil
}
