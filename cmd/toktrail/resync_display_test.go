package main

// resync_display_test.go - the resync command's confirmation-abort
// security contract: the user's own refusal is recognized ONLY through
// the private sentinels on the wrapping chain (never message text), so
// a hostile error that merely CONTAINS "cancelled" can never
// masquerade as a refusal and reach the raw-text display path. The
// scanner I/O failure keeps its chain behind a fixed generic display.
// Everything is synthetic; no real state or network is touched.

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestResyncConfirmAbortSentinelNotText: the abort recognition answers
// errors.Is on the private sentinels only.
func TestResyncConfirmAbortSentinelNotText(t *testing.T) {
	// A hostile error carrying "cancelled" plus secrets must NOT match.
	hostile := errors.New("server said cancelled; retry at https://evil.example/steal?f=SECRETTOKEN /Users/victim/.attacker-path")
	if isResyncConfirmAbort(hostile) {
		t.Fatal("a hostile error merely containing 'cancelled' must never match the abort recognition")
	}
	hostileWrapped := fmt.Errorf("sync aborted before any collection or upload: %w", hostile)
	if isResyncConfirmAbort(hostileWrapped) {
		t.Fatal("a hostile error wrapped in the abort prefix must still never match")
	}

	// The real refusal matches through any wrapping depth.
	declined := fmt.Errorf("sync aborted before any collection or upload: %w",
		fmt.Errorf("outer: %w", errResyncDeclined))
	if !isResyncConfirmAbort(declined) {
		t.Fatal("the wrapped refusal must match through errors.Is")
	}
	displayed := safeDisplayError(declined, confirmAbortDisplayText(declined))
	// The CLI's real display text is displayErrorText; the wrapped
	// error keeps its raw Error() and chain verbatim by design.
	if displayErrorText(displayed) != "cancelled at the confirmation prompt; nothing was collected or uploaded" {
		t.Fatalf("the refusal displays its fixed text, got %q", displayErrorText(displayed))
	}
	if strings.Contains(displayErrorText(displayed), "SECRETTOKEN") || strings.Contains(displayErrorText(displayed), "evil.example") {
		t.Fatalf("the refusal display must never echo hostile material, got %q", displayErrorText(displayed))
	}
	if !errors.Is(displayed, errResyncDeclined) {
		t.Fatal("the refusal chain must survive the safe wrapper (errors.Is)")
	}

	// The unavailable sentinel, wrapped the way the override pass wraps
	// a confirmation refusal.
	unavailable := fmt.Errorf("override aborted before any state change or network access: %w", errResyncConfirmUnavailable)
	if !isResyncConfirmAbort(unavailable) {
		t.Fatal("the wrapped unavailable sentinel must match")
	}
	if got := confirmAbortDisplayText(unavailable); got != "the confirmation was not provided; use --yes only after reviewing the plan" {
		t.Fatalf("the unavailable display text = %q", got)
	}
}

// TestPromptYesNoDeclineAndUnavailable: an explicit non-yes answer
// returns the decline sentinel; a closed stdin returns the unavailable
// sentinel (never an implicit yes). The prompt keeps its exact shape.
func TestPromptYesNoDeclineAndUnavailable(t *testing.T) {
	var out bytes.Buffer
	if err := promptYesNo(strings.NewReader("n\n"), &out, "Resynchronize usage under the live server consent?"); !errors.Is(err, errResyncDeclined) {
		t.Fatalf("a declined answer returns the sentinel, got %v", err)
	}
	if err := promptYesNo(strings.NewReader(""), &out, "Q?"); !errors.Is(err, errResyncConfirmUnavailable) {
		t.Fatalf("a closed stdin returns the unavailable sentinel, got %v", err)
	}
	if err := promptYesNo(strings.NewReader("yes\n"), &out, "Q?"); err != nil {
		t.Fatalf("an explicit yes confirms, got %v", err)
	}
	if !strings.Contains(out.String(), "Resynchronize usage under the live server consent? [y/N] ") {
		t.Fatalf("the prompt keeps its exact historical shape, got %q", out.String())
	}
}

// failingReader fails every read with a fixed error.
type failingReader struct{ err error }

func (r *failingReader) Read([]byte) (int, error) { return 0, r.err }

// TestPromptYesNoIOErrorKeepsChainFixedDisplay: a scanner I/O failure
// keeps its chain (errors.Is) but displays only the fixed generic text
// - the raw I/O message may quote local paths.
func TestPromptYesNoIOErrorKeepsChainFixedDisplay(t *testing.T) {
	ioErr := errors.New("read /Users/victim/.tty/input: permission denied (SECRETTOKEN)")
	var out bytes.Buffer
	err := promptYesNo(&failingReader{err: ioErr}, &out, "Q?")
	if err == nil {
		t.Fatal("an I/O failure must fail the confirmation")
	}
	if displayErrorText(err) != "the confirmation could not be read; use --yes only after reviewing the plan" {
		t.Fatalf("the I/O failure displays its fixed text, got %q", displayErrorText(err))
	}
	if !errors.Is(err, ioErr) {
		t.Fatal("the I/O chain must survive the safe wrapper")
	}
}
