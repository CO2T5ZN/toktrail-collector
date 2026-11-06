package console

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// withAnswerSource installs a deterministic answer source for one test.
func withAnswerSource(t *testing.T, answer string, openErr error) {
	t.Helper()
	old := AnswerSource
	AnswerSource = func() (io.ReadCloser, error) {
		if openErr != nil {
			return nil, openErr
		}
		return io.NopCloser(strings.NewReader(answer)), nil
	}
	t.Cleanup(func() { AnswerSource = old })
}

// Only an explicit yes confirms; everything else declines, and the
// question is written to the caller's stream exactly once.
func TestConfirmAnswerSemantics(t *testing.T) {
	confirmed := []string{"y\n", "Y\n", "yes\n", "YES\n", "  y  \n", "yes\r\n"}
	for _, answer := range confirmed {
		withAnswerSource(t, answer, nil)
		var out strings.Builder
		got, err := Confirm(&out, "Proceed? [y/N] ")
		if err != nil || !got {
			t.Fatalf("answer %q must confirm, got (%v, %v)", answer, got, err)
		}
		if out.String() != "Proceed? [y/N] " {
			t.Fatalf("the question must be written once, got %q", out.String())
		}
	}
	declined := []string{"n\n", "no\n", "\n", "maybe\n", "0\n"}
	for _, answer := range declined {
		withAnswerSource(t, answer, nil)
		got, err := Confirm(io.Discard, "Proceed? ")
		if err != nil || got {
			t.Fatalf("answer %q must decline without an error, got (%v, %v)", answer, got, err)
		}
	}
}

// A source that runs dry is "no terminal", never a decline: the caller
// must be able to report "not confirmed" and offer the manual command.
func TestConfirmEOFIsNoTerminalNotDecline(t *testing.T) {
	withAnswerSource(t, "", nil)
	got, err := Confirm(io.Discard, "Proceed? ")
	if got || !errors.Is(err, ErrNoInteractiveTerminal) {
		t.Fatalf("EOF must be ErrNoInteractiveTerminal, got (%v, %v)", got, err)
	}
}

// A host without any answer source is the same "no terminal" case.
func TestConfirmMissingTerminal(t *testing.T) {
	withAnswerSource(t, "", errors.New("no controlling terminal"))
	got, err := Confirm(io.Discard, "Proceed? ")
	if got || !errors.Is(err, ErrNoInteractiveTerminal) {
		t.Fatalf("a missing terminal must be ErrNoInteractiveTerminal, got (%v, %v)", got, err)
	}
}

// An over-long answer (a mis-attached stream carrying program text) is
// refused with its own error, never reported as a terminal failure and
// never echoed.
func TestConfirmRefusesOverlongAnswer(t *testing.T) {
	withAnswerSource(t, strings.Repeat("y", maxAnswerBytes+1)+"\n", nil)
	got, err := Confirm(io.Discard, "Proceed? ")
	if got || err == nil || errors.Is(err, ErrNoInteractiveTerminal) {
		t.Fatalf("an over-long answer must be a refusal, got (%v, %v)", got, err)
	}
	if strings.Contains(err.Error(), "yyyy") {
		t.Fatalf("the refusal must not echo the answer: %v", err)
	}
}

// Terminals deliver a line differently: unix LF, Windows CRLF, a console handle
// UTF-16LE (every other byte zero), sometimes NUL padded. All of them must be
// understood as the word the user typed — comparing raw bytes made a typed "y"
// decline on Windows.
func TestConfirmAcceptsEveryTerminalLineEncoding(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		want bool
	}{
		{name: "unix LF", raw: []byte("y\n"), want: true},
		{name: "windows CRLF", raw: []byte("y\r\n"), want: true},
		{name: "windows CRLF yes", raw: []byte("YES\r\n"), want: true},
		{name: "utf16le CRLF", raw: []byte{'y', 0, '\r', 0, '\n', 0}, want: true},
		{name: "utf16le BOM", raw: append([]byte{0xff, 0xfe}, []byte{'y', 0, '\r', 0, '\n', 0}...), want: true},
		{name: "utf16be yes", raw: append([]byte{0xfe, 0xff}, []byte{0, 'y', 0, 'e', 0, 's', 0, '\r', 0, '\n'}...), want: true},
		{name: "nul padded", raw: []byte("y\x00\x00\x00\n"), want: true},
		{name: "spaces around", raw: []byte("  y  \r\n"), want: true},
		{name: "explicit no", raw: []byte("n\r\n"), want: false},
		{name: "empty line", raw: []byte("\r\n"), want: false},
		{name: "garbage", raw: []byte("\x00\x00\x00\r\n"), want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withRawAnswerSource(t, tc.raw)
			got, err := Confirm(io.Discard, "Proceed? ")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("answer %q confirmed=%v, want %v (normalized %q)",
					tc.raw, got, tc.want, normalizeAnswer(tc.raw))
			}
		})
	}
}

// withRawAnswerSource installs an answer source that returns exact bytes.
func withRawAnswerSource(t *testing.T, raw []byte) {
	t.Helper()
	old := AnswerSource
	AnswerSource = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(raw)), nil
	}
	t.Cleanup(func() { AnswerSource = old })
}

// A read failure is its own class, never a decline: reporting "the user said
// no" when the program could not hear them sends them chasing a command they
// do not need.
func TestConfirmReadFailureIsNotADecline(t *testing.T) {
	old := AnswerSource
	AnswerSource = func() (io.ReadCloser, error) {
		return io.NopCloser(failingReader{}), nil
	}
	t.Cleanup(func() { AnswerSource = old })

	confirmed, err := Confirm(io.Discard, "Proceed? ")
	if confirmed {
		t.Fatalf("a failed read must not confirm")
	}
	if err == nil || !errors.Is(err, ErrAnswerUnreadable) {
		t.Fatalf("a failed read must be ErrAnswerUnreadable, got %v", err)
	}
	if errors.Is(err, ErrNoInteractiveTerminal) {
		t.Fatalf("a failed read must not be reported as a missing terminal")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("console read failed") }

// On Windows the answer may arrive as a console line that carries the CRLF in
// UTF-16LE form; the same bytes must never be read as "not yes". This is the
// exact shape a Windows console produced when a typed "y" was reported as a
// decline.
func TestConfirmWindowsConsoleLineShapes(t *testing.T) {
	shapes := [][]byte{
		{'y', 0, '\r', 0, '\n', 0},          // UTF-16LE "y\r\n"
		{'\r', 0, '\n', 0, 'y', 0, '\r', 0}, // stray leading newline, then "y"
	}
	for _, raw := range shapes {
		withRawAnswerSource(t, raw)
		if _, err := Confirm(io.Discard, "Proceed? "); err != nil {
			t.Fatalf("shape %q: unexpected error %v", raw, err)
		}
	}
	// A leading empty line is an empty answer (decline), never a crash.
	withRawAnswerSource(t, []byte{'\r', 0, '\n', 0})
	got, err := Confirm(io.Discard, "Proceed? ")
	if err != nil || got {
		t.Fatalf("an empty console line must decline without error, got (%v, %v)", got, err)
	}
}
