//go:build windows

package console

import (
	"os"
	"syscall"
	"unsafe"
)

// enableVirtualTerminalProcessing is the console mode bit
// ENABLE_VIRTUAL_TERMINAL_PROCESSING <consoleapi.h>: when set, the
// console interprets ANSI/VT escape sequences instead of printing them
// as literal text.
const enableVirtualTerminalProcessing uint32 = 0x0004

// The kernel32 console-mode entry points, resolved lazily so the file
// builds everywhere Windows does. The standard library alone is used
// (no golang.org/x/sys dependency) to keep the vendored module set of
// this project untouched.
var (
	kernel32DLL        = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode = kernel32DLL.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32DLL.NewProc("SetConsoleMode")
)

// getConsoleMode reads the current mode flags of a console handle. It
// fails for non-console handles (pipes, files, closed handles), which
// is how redirected output is detected on Windows.
func getConsoleMode(handle syscall.Handle, mode *uint32) error {
	ret, _, err := procGetConsoleMode.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(mode)),
	)
	if ret == 0 {
		return err
	}
	return nil
}

// setConsoleMode replaces the mode flags of a console handle.
func setConsoleMode(handle syscall.Handle, mode uint32) error {
	ret, _, err := procSetConsoleMode.Call(
		uintptr(handle),
		uintptr(mode),
	)
	if ret == 0 {
		return err
	}
	return nil
}

// vtSupported is the Windows probe: the handle must be a console
// screen buffer that either already has, or accepts,
// ENABLE_VIRTUAL_TERMINAL_PROCESSING. A legacy console that rejects
// the mode returns false, so callers render plain log lines rather
// than leaking escape-sequence text like "[ K".
//
// The probe is otherwise read-only: only the VT bit is ever set, and
// only when it was off. If SetConsoleMode fails the console's mode is
// unchanged (a failed mode change leaves the previous flags in place).
func vtSupported(f *os.File) bool {
	handle := syscall.Handle(f.Fd())
	var mode uint32
	if err := getConsoleMode(handle, &mode); err != nil {
		// Not a console (redirected output) or an unreadable mode:
		// no ANSI rendering either way.
		return false
	}
	return ansiFromConsoleMode(mode, func(next uint32) error {
		return setConsoleMode(handle, next)
	})
}

// ansiFromConsoleMode decides ANSI support from a console's current
// mode flags plus an enable function that attempts to turn VT
// processing on. It exists as a separate step so the decision itself
// is unit-testable without a real console.
//
//   - the VT bit already set: allowed, nothing is changed;
//   - the bit unset and enabling it succeeds: allowed;
//   - the bit unset and enabling it fails (legacy console): refused —
//     the caller must take the plain-log path so no literal "[ K"
//     reaches the user.
func ansiFromConsoleMode(mode uint32, enable func(uint32) error) bool {
	if mode&enableVirtualTerminalProcessing != 0 {
		return true
	}
	if enable == nil {
		return false
	}
	if err := enable(mode | enableVirtualTerminalProcessing); err != nil {
		return false
	}
	return true
}
