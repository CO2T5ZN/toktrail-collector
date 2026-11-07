//go:build darwin || linux

package console

import "os"

// vtSupported is the Unix probe: a terminal is a character device, and
// Unix terminals interpret ANSI sequences natively. Redirected pipes
// and regular files are not character devices and are refused, exactly
// as before this helper existed.
func vtSupported(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return isCharDevice(info)
}
