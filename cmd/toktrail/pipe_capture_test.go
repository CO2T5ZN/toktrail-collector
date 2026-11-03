package main

// Stdout/stderr capture for CLI tests through real OS pipes.
//
// The kernel buffer behind an OS pipe is small (64 KiB on Linux and
// macOS, and only 4 KiB for the anonymous pipes os.Pipe creates on
// Windows). A captured command can easily write more than that —
// printHelp alone emits ~7 KiB — and a write to a full pipe blocks
// until a reader drains it. Capturing by writing first and reading
// only after the command returned therefore deadlocks any output
// larger than the buffer (TestPrintHelpIncludesConnect hung exactly
// like that on Windows). Every capture here drains the pipe
// concurrently for the whole duration of the captured command, so
// writes of any size keep flowing.
//
// Cleanup discipline: once os.Stdout/os.Stderr are swapped, EVERY exit
// path restores them — the captured fn returning, fn panicking (the
// panic propagates to the caller; restoration happens while the stack
// unwinds), and fn calling t.Fatal (runtime.Goexit, which likewise
// runs deferred functions). Without the deferred restoration, a single
// failing or panicking capture would leave the whole package's
// os.Stdout pointing at a dead pipe and silently swallow every later
// test's output. TestCapturePipedRestoresStreamsOnPanic pins this.

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"
)

// captureStdoutPiped runs fn with os.Stdout replaced by a fresh pipe
// and returns everything fn wrote plus fn's error. A drain goroutine
// reads the pipe from before fn starts until the write end closes.
func captureStdoutPiped(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		// Nothing was opened or swapped yet, so failing here is safe.
		t.Fatal(err)
	}
	os.Stdout = w
	drained := drainPipe(r)
	// Panic/Goexit safety net: restores the stream and closes the write
	// end while the stack unwinds. On the normal path below this runs
	// after the explicit restore+close and is redundant but harmless
	// (a second (*os.File).Close only returns ErrClosed).
	defer func() {
		os.Stdout = old
		_ = w.Close()
	}()
	fnErr := fn()
	// Normal path: restore before closing so nothing ever writes to a
	// closed pipe, and close before receiving so the drain goroutine
	// sees EOF and can deliver its result.
	os.Stdout = old
	_ = w.Close()
	return <-drained, fnErr
}

// captureStdoutStderrPiped is captureStdoutPiped for both standard
// streams at once (progress-json events go to stderr).
func captureStdoutStderrPiped(t *testing.T, fn func() error) (string, string, error) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, err := os.Pipe()
	if err != nil {
		// Nothing was opened or swapped yet, so failing here is safe.
		t.Fatal(err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		// The first pipe is already open: close both of its ends so
		// this failure path leaks no descriptors. Nothing was swapped
		// yet, so failing here is still safe.
		_ = rOut.Close()
		_ = wOut.Close()
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = wOut, wErr
	drainedOut := drainPipe(rOut)
	drainedErr := drainPipe(rErr)
	// Panic/Goexit safety net, mirroring captureStdoutPiped.
	defer func() {
		os.Stdout, os.Stderr = oldOut, oldErr
		_ = wOut.Close()
		_ = wErr.Close()
	}()
	fnErr := fn()
	os.Stdout, os.Stderr = oldOut, oldErr
	_ = wOut.Close()
	_ = wErr.Close()
	return <-drainedOut, <-drainedErr, fnErr
}

// drainPipe copies everything readable from r into a buffer and
// delivers the result on the returned channel once r reaches EOF (the
// write end was closed). It must be started BEFORE the captured
// command runs; closing r after EOF keeps the descriptor from leaking.
// The channel is buffered so the goroutine also exits cleanly on the
// panic/Goexit paths, where no receiver ever reads the result.
func drainPipe(r *os.File) <-chan string {
	drained := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		_ = r.Close()
		drained <- buf.String()
	}()
	return drained
}

// TestCapturePipedRestoresStreamsOnPanic pins the cleanup contract of
// both capture helpers: a captured command that panics must not take
// the process-global standard streams with it. The panic propagates to
// the caller (the helpers never swallow it), and the deferred cleanup
// restores os.Stdout (and os.Stderr for the dual capture) BEFORE the
// unwinding reaches the test — otherwise every later write from the
// testing framework and the remaining tests would land on a dead pipe.
func TestCapturePipedRestoresStreamsOnPanic(t *testing.T) {
	realOut, realErr := os.Stdout, os.Stderr

	t.Run("stdout_only", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("the captured fn's panic must propagate to the caller, not be swallowed")
			}
			if os.Stdout != realOut {
				t.Fatalf("os.Stdout must be restored before the panic reaches the test: got %v, want %v", os.Stdout, realOut)
			}
			if os.Stderr != realErr {
				t.Fatalf("the stdout-only capture must leave os.Stderr untouched: got %v, want %v", os.Stderr, realErr)
			}
		}()
		_, _ = captureStdoutPiped(t, func() error {
			fmt.Fprint(os.Stdout, "line before the panic")
			panic("synthetic stdout-capture panic")
		})
	})

	t.Run("stdout_and_stderr", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("the captured fn's panic must propagate to the caller, not be swallowed")
			}
			if os.Stdout != realOut || os.Stderr != realErr {
				t.Fatalf("both streams must be restored before the panic reaches the test: got out=%v err=%v, want out=%v err=%v",
					os.Stdout, os.Stderr, realOut, realErr)
			}
		}()
		_, _, _ = captureStdoutStderrPiped(t, func() error {
			fmt.Fprint(os.Stdout, "stdout before the panic")
			fmt.Fprint(os.Stderr, "stderr before the panic")
			panic("synthetic dual-capture panic")
		})
	})

	// Both subtests above restored the streams; writing through them
	// now must reach the real streams (the testing framework's own
	// failure reporting depends on exactly this).
	if os.Stdout != realOut || os.Stderr != realErr {
		t.Fatalf("standard streams must be intact after the recovered panics: got out=%v err=%v", os.Stdout, os.Stderr)
	}
}
