//go:build windows

package console

// Windows-native tests for the ANSI capability probe.
//
// The full decision table of ansiFromConsoleMode is exercised with a
// fake enable function, so no real console is required. The live-probe
// tests below cover the non-console branches (pipes, files — they run
// headless) and, when stdout happens to be attached to a console, the
// real enable path; otherwise they skip rather than demanding an
// interactive terminal.

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The decision table: the VT bit already set allows ANSI without
// touching the mode; an unset bit allows it only when enabling
// succeeds, and a failing enable (legacy console) refuses it so the
// literal "[ K" leak can never happen.
func TestANSIFromConsoleMode(t *testing.T) {
	called := 0
	enable := func(next uint32) error {
		called++
		if next&enableVirtualTerminalProcessing == 0 {
			t.Fatalf("enable must be asked to set the VT bit, got mode %#x", next)
		}
		return nil
	}

	if !ansiFromConsoleMode(enableVirtualTerminalProcessing|0x0001, enable) {
		t.Fatal("a console with the VT bit already set must be accepted")
	}
	if called != 0 {
		t.Fatal("an already-enabled console must not trigger a mode change")
	}

	if !ansiFromConsoleMode(0x0001, enable) {
		t.Fatal("a console that accepts the VT bit must be accepted")
	}
	if called != 1 {
		t.Fatalf("enable must be called exactly once, got %d", called)
	}

	err := errors.New("legacy console")
	failing := func(uint32) error { return err }
	if ansiFromConsoleMode(0x0001, failing) {
		t.Fatal("a console that rejects the VT bit must be refused (plain log path)")
	}

	if ansiFromConsoleMode(0x0001, nil) {
		t.Fatal("no enable function means the VT bit cannot be turned on: refused")
	}
}

// Non-console handles (pipes, regular files) are redirected output on
// Windows: GetConsoleMode refuses them, so SupportsANSI must answer
// false without touching anything. These branches run without any
// console attached.
func TestSupportsANSIRefusesNonConsoleHandles(t *testing.T) {
	if SupportsANSI(nil) {
		t.Fatal("nil is not an ANSI stream")
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()
	if SupportsANSI(w) {
		t.Fatal("the write end of a pipe is redirected output, not a console")
	}
	if SupportsANSI(r) {
		t.Fatal("the read end of a pipe is not a console")
	}

	f, err := os.Create(filepath.Join(t.TempDir(), "redirect.log"))
	if err != nil {
		t.Fatalf("os.Create: %v", err)
	}
	defer f.Close()
	if SupportsANSI(f) {
		t.Fatal("a regular file is redirected output, not a console")
	}
}

// When stdout IS a console, SupportsANSI must leave the VT bit on and
// answer exactly accordingly. The original mode is restored so the
// test leaves the environment as it found it. Skipped when stdout is
// redirected (CI, test wrappers): the redirected branch is covered
// above.
func TestSupportsANSIOnRealConsole(t *testing.T) {
	handle := syscall.Handle(os.Stdout.Fd())
	var before uint32
	if err := getConsoleMode(handle, &before); err != nil {
		t.Skip("stdout is not attached to a console; skipping the live console branch")
	}
	t.Cleanup(func() {
		_ = setConsoleMode(handle, before)
	})

	got := SupportsANSI(os.Stdout)

	var after uint32
	if err := getConsoleMode(handle, &after); err != nil {
		t.Fatalf("re-reading the console mode failed: %v", err)
	}
	if got != (after&enableVirtualTerminalProcessing != 0) {
		t.Fatalf("SupportsANSI must agree with the VT bit: got %v, mode %#x", got, after)
	}
}
