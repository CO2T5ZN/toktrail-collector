package main

// Terminal-capability gating for the manual CLI's human output.
//
// isTerminalWriter decides between in-place terminal rendering
// (carriage return + ANSI erase-line) and plain one-line log output.
// These are the cross-platform invariants:
//
//   - a writer that is not an *os.File (test buffers, serialized
//     wrappers) is never a terminal;
//   - redirected *os.File streams (pipes, regular files) are never
//     ANSI-capable on any platform — the Windows probe's
//     GetConsoleMode fails on them exactly like the Unix character
//     device test does;
//   - a stream isTerminalWriter rejects must never receive terminal
//     control characters from the heartbeat, including on the platform
//     whose console cannot interpret them (the legacy-Windows "[ K"
//     leak).
//
// The stdin-confirmation capability of internal/console is a separate
// question and is intentionally not probed here.

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/app/collection"
)

// Non-file writers are never ANSI-capable: buffers and wrappers used
// by tests and by serialized writers take the quiet log path.
func TestIsTerminalWriterRejectsNonFileWriters(t *testing.T) {
	var buf bytes.Buffer
	if isTerminalWriter(&buf) {
		t.Fatal("a bytes.Buffer is not a terminal")
	}
	if isTerminalWriter(nopWriter{}) {
		t.Fatal("a custom io.Writer is not a terminal")
	}
	if isTerminalWriter(io.Discard) {
		t.Fatal("io.Discard is not a terminal")
	}
	if isTerminalWriter(nil) {
		t.Fatal("nil is not a terminal")
	}
}

// A redirected pipe is a real *os.File, so the *os.File type check
// alone must not pass it: on Unix a pipe is not a character device,
// on Windows GetConsoleMode refuses the pipe handle. Either way no
// ANSI may be rendered into it.
func TestIsTerminalWriterRejectsPipedFile(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()
	if isTerminalWriter(w) {
		t.Fatal("the write end of a pipe is redirected output, not an ANSI terminal")
	}
	if isTerminalWriter(r) {
		t.Fatal("the read end of a pipe is not an ANSI terminal")
	}
}

// A regular file is redirected output on every platform.
func TestIsTerminalWriterRejectsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "redirect.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("os.Create: %v", err)
	}
	defer f.Close()
	if isTerminalWriter(f) {
		t.Fatal("a regular log file is redirected output, not an ANSI terminal")
	}
}

// A closed file still answers false rather than panicking.
func TestIsTerminalWriterRejectsClosedFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "closed*.log")
	if err != nil {
		t.Fatalf("os.CreateTemp: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if isTerminalWriter(f) {
		t.Fatal("a closed file is not an ANSI terminal")
	}
}

// The heartbeat wired through isTerminalWriter must not leak terminal
// control characters into a stream it rejected. This is the regression
// for the legacy-Windows manual-CLI display, where "\r\x1b[K" printed
// as literal "[ K" text: whatever the platform, a rejected stream
// takes the plain log path at every heartbeat interval.
func TestHeartbeatGatedByIsTerminalWriterEmitsNoControlCharacters(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	cur := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	now := func() time.Time { return cur }
	hb := newPeriodicHumanHeartbeatFor(w, cur, now, isTerminalWriter(w))
	defer hb.Close()

	// Advance past every rendering interval the heartbeat has: the
	// 30-second throttle points and the quiet path's low-frequency
	// stall notice.
	for i := 0; i < 12; i++ {
		cur = cur.Add(1 * time.Minute)
		hb.handle(collection.ProgressEvent{
			Kind:           collection.ProgressHeartbeat,
			Stage:          "drain",
			Counted:        true,
			PendingBatches: 2,
			RecordsCounted: true,
			PendingRecords: 7,
		})
	}
	_ = w.Close()

	var got bytes.Buffer
	if _, err := io.Copy(&got, r); err != nil {
		t.Fatalf("drain pipe: %v", err)
	}
	out := got.String()
	if strings.Contains(out, "\x1b[") || strings.Contains(out, "\r") {
		t.Fatalf("a stream isTerminalWriter rejected must never receive terminal control characters, got %q", out)
	}
	if !strings.Contains(out, "Still running:") {
		t.Fatalf("the plain log path must still report progress, got %q", out)
	}
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }
