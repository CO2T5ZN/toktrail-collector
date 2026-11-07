package scheduler

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const structuredOutput = `<?xml version="1.0" encoding="UTF-8"?><Task><Description>目录 测试 é</Description></Task>`
const diagnosticOutput = "#< CLIXML\n<Objs>synthetic PowerShell diagnostic</Objs>\n"

// Re-execute only this hermetic helper, never a real task or user state.
func TestSchedulerStructuredOutputProcess(t *testing.T) {
	if os.Getenv("TOKTRAIL_TEST_STRUCTURED_OUTPUT") != "1" {
		return
	}
	fmt.Fprint(os.Stderr, diagnosticOutput)
	fmt.Fprint(os.Stdout, structuredOutput)
	if os.Getenv("TOKTRAIL_TEST_STRUCTURED_FAILURE") == "1" {
		os.Exit(9)
	}
	os.Exit(0)
}

func TestCaptureSchedulerOutputSeparatesDiagnostics(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, fail := range []bool{false, true} {
		name := "success with stderr"
		if fail {
			name = "failure with stderr"
		}
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command(executable, "-test.run=^TestSchedulerStructuredOutputProcess$")
			cmd.Env = append(os.Environ(), "TOKTRAIL_TEST_STRUCTURED_OUTPUT=1")
			if fail {
				cmd.Env = append(cmd.Env, "TOKTRAIL_TEST_STRUCTURED_FAILURE=1")
			}
			configureSchedulerCommand(cmd)
			out, stderr, err := captureSchedulerOutput(cmd)
			if string(out) != structuredOutput || string(stderr) != diagnosticOutput {
				t.Fatalf("streams must stay independent: stdout=%q stderr=%q", out, stderr)
			}
			if (err != nil) != fail {
				t.Fatalf("failure status lost: %v", err)
			}
			if fail {
				exit, ok := err.(*exec.ExitError)
				if !ok || exit.ExitCode() != 9 {
					t.Fatalf("exit code changed: %v", err)
				}
			}
			if strings.Contains(string(out), "CLIXML") {
				t.Fatal("diagnostics contaminated XML output")
			}
		})
	}
}
