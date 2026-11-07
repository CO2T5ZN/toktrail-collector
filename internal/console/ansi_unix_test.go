//go:build darwin || linux

package console

// Unix-side tests for SupportsANSI: the probe is the historical
// character-device terminal test, so redirected output (pipes, files)
// and non-files stay refused while Unix behavior is otherwise
// unchanged. Whether a test process's own stdin/stdout is a terminal
// is environment-dependent, so no assertion is made about them.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSupportsANSIUnixRefusesNonTerminals(t *testing.T) {
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
		t.Fatal("the write end of a pipe is redirected output, not a terminal")
	}
	if SupportsANSI(r) {
		t.Fatal("the read end of a pipe is not a terminal")
	}
	f, err := os.Create(filepath.Join(t.TempDir(), "redirect.log"))
	if err != nil {
		t.Fatalf("os.Create: %v", err)
	}
	defer f.Close()
	if SupportsANSI(f) {
		t.Fatal("a regular file is redirected output, not a terminal")
	}
}
