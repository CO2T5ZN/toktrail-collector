package console

import (
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
