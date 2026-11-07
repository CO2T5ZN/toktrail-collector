package main

// Windows-specific tests for isTerminalWriter.
//
// The interesting branch — a console that either has or rejects
// ENABLE_VIRTUAL_TERMINAL_PROCESSING — needs the kernel32 console
// API, so these tests are Windows-native. They never REQUIRE an
// interactive terminal: the redirected/non-console branches are
// covered by the platform-neutral terminal_test.go, and the console
// branch below skips when stdout is not attached to a console (CI,
// `go test -exec` wrappers). What it does assert, whenever a console
// IS present, is the core invariant of the fix: ANSI rendering is
// allowed exactly when VT processing is (or can be) enabled, the
// probe only ever flips that one bit, and repeated probes agree.

import (
	"os"
	"syscall"
	"testing"
	"unsafe"
)

// testEnableVT mirrors ENABLE_VIRTUAL_TERMINAL_PROCESSING.
const testEnableVT uint32 = 0x0004

var (
	testKernel32       = syscall.NewLazyDLL("kernel32.dll")
	testGetConsoleMode = testKernel32.NewProc("GetConsoleMode")
)

// testConsoleMode reads the current mode flags of f's handle. The
// second return is false when the handle is not a console.
func testConsoleMode(f *os.File) (uint32, bool) {
	var mode uint32
	ret, _, _ := testGetConsoleMode.Call(
		uintptr(f.Fd()),
		uintptr(unsafe.Pointer(&mode)),
	)
	if ret == 0 {
		return 0, false
	}
	return mode, true
}

// On a real console the gate must equal the VT bit: isTerminalWriter
// may answer true only after ENABLE_VIRTUAL_TERMINAL_PROCESSING is on,
// and must answer false when the console refuses it (a legacy console
// would otherwise print "\r\x1b[K" as literal "[ K" text).
func TestIsTerminalWriterWindowsConsoleVTGating(t *testing.T) {
	before, isConsole := testConsoleMode(os.Stdout)
	if !isConsole {
		t.Skip("stdout is not attached to a console; the console branch needs a real (legacy or VT) console")
	}

	got := isTerminalWriter(os.Stdout)

	after, ok := testConsoleMode(os.Stdout)
	if !ok {
		t.Fatal("the console disappeared between probes")
	}
	beforeVT := before&testEnableVT != 0
	afterVT := after&testEnableVT != 0

	switch {
	case beforeVT:
		// Already enabled: accepted with no mode change at all.
		if !got {
			t.Fatalf("a console that already had VT processing enabled must be accepted (mode %#x)", before)
		}
		if after != before {
			t.Fatalf("an already-enabled console must not have its mode touched: before %#x after %#x", before, after)
		}
	case got:
		// Accepted by enabling the bit now.
		if !afterVT {
			t.Fatalf("isTerminalWriter accepted the console but the VT bit is not enabled (mode %#x)", after)
		}
	default:
		// Refused: the console rejected the mode. The bit must remain
		// off (a failed SetConsoleMode leaves the previous flags).
		if afterVT {
			t.Fatalf("isTerminalWriter refused the console but the VT bit is enabled (mode %#x)", after)
		}
		if after != before {
			t.Fatalf("a refused console must not have its mode touched: before %#x after %#x", before, after)
		}
	}

	// The probe is a pure read-or-enable of the VT bit: no other flag
	// may change, and a second probe must agree with the first.
	if after&^testEnableVT != before&^testEnableVT {
		t.Fatalf("the probe must only change the VT bit: before %#x after %#x", before, after)
	}
	if again := isTerminalWriter(os.Stdout); again != got {
		t.Fatalf("repeated probes must agree: first %v then %v", got, again)
	}
}

// With no console attached at all (redirected stdout, a service
// context), the probe must simply refuse non-console handles rather
// than failing: pipes and files answer false on the Windows probe
// path, mirroring the redirect handling of other platforms.
func TestIsTerminalWriterWindowsWithoutConsole(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()
	if isTerminalWriter(w) {
		t.Fatal("a pipe handle is not a console and must be refused")
	}
	f, err := os.CreateTemp(t.TempDir(), "noconsole*.log")
	if err != nil {
		t.Fatalf("os.CreateTemp: %v", err)
	}
	defer f.Close()
	if isTerminalWriter(f) {
		t.Fatal("a regular file handle is not a console and must be refused")
	}
}
