//go:build darwin || linux

package console

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ptyChildEnv marks the re-executed test binary as the confirmation probe.
const ptyChildEnv = "TOKTRAIL_CONSOLE_PTY_CHILD"

// TestConfirmPTYChild is the probe: when re-executed under a real pseudo
// terminal it runs one confirmation and reports the outcome on stdout. It does
// nothing during a normal test run.
func TestConfirmPTYChild(t *testing.T) {
	if os.Getenv(ptyChildEnv) != "1" {
		t.Skip("probe process only")
	}
	confirmed, err := Confirm(os.Stdout, "Enable Cursor usage collection on this machine? [y/N] ")
	switch {
	case err != nil:
		fmt.Printf("result=error err=%v\n", err)
	case confirmed:
		fmt.Println("result=confirmed")
	default:
		fmt.Println("result=declined")
	}
}

// runUnderPTY re-executes this test binary's probe under a real pseudo
// terminal and feeds it the given input. `script` is present on macOS and Linux;
// it allocates a pty for the child and forwards stdin to it, which is the exact
// situation the confirmation must handle.
func runUnderPTY(t *testing.T, input string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test binary: %v", err)
	}
	var cmd *exec.Cmd
	probeArgs := []string{"-test.run=TestConfirmPTYChild", "-test.v=false"}
	if runtime.GOOS == "darwin" {
		cmd = exec.Command("/usr/bin/script", append([]string{"-q", "/dev/null", self}, probeArgs...)...)
	} else {
		cmd = exec.Command("script", "-q", "-c", strings.Join(append([]string{self}, probeArgs...), " "), "/dev/null")
	}
	cmd.Env = append(os.Environ(), ptyChildEnv+"=1")
	// Feed the answer through a pipe that stays open: `script` forwards its
	// stdin to the pty, and closing it immediately would deliver EOF to the
	// terminal before the child reads (which looks exactly like "no terminal",
	// the very case the code distinguishes).
	reader, writer := io.Pipe()
	cmd.Stdin = reader
	go func() {
		_, _ = writer.Write([]byte(input))
		time.Sleep(1500 * time.Millisecond)
		_ = writer.Close()
	}()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("pty probe failed: %v\n%s", err, out)
	}
	return string(out)
}

// The whole point of the /dev/tty work: under a real terminal, a typed answer
// reaches the confirmation even though the process's stdin is a pipe. The
// probe's stdin is the pty here, so this pins that `y` confirms and `n`
// declines — not that a value was guessed.
func TestConfirmReadsAnswerFromRealTerminal(t *testing.T) {
	out := runUnderPTY(t, "y\n")
	if !strings.Contains(out, "result=confirmed") {
		t.Fatalf("a typed \"y\" on a real terminal must confirm, got:\n%s", out)
	}
	if !strings.Contains(out, "Enable Cursor usage collection on this machine?") {
		t.Fatalf("the question must be shown on the terminal, got:\n%s", out)
	}

	out = runUnderPTY(t, "n\n")
	if !strings.Contains(out, "result=declined") {
		t.Fatalf("a typed \"n\" must decline, got:\n%s", out)
	}
}
