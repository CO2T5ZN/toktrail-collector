//go:build windows

package winbackground

import (
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunStopsWhenLogStreamFails(t *testing.T) {
	exe, state := testExecutable(t), t.TempDir()
	t.Setenv(childEnvSwitch, "1")
	t.Setenv(childEnvStdoutPad, "100000") // would fill the pipe if the child survived
	original := copyStream
	controls := make(chan func(), 1)
	copyStream = func(dst io.Writer, src io.Reader, stop func()) error {
		if log, ok := dst.(*rotatingLog); ok && filepath.Base(log.path) == outLogName {
			controls <- stop
			return original(rejectedLogWriter{}, src, stop)
		}
		return original(dst, src, stop)
	}
	t.Cleanup(func() { copyStream = original })
	done := make(chan int, 1)
	go func() { done <- Run([]string{"--collector", exe, "--state-dir", state}) }()
	select {
	case rc := <-done:
		if rc != ExitLaunchFailure {
			t.Fatalf("failed capture returned %d, want helper failure", rc)
		}
	case <-time.After(10 * time.Second):
		// Terminate the test's own supervision job even if a future
		// regression stops calling the failure callback itself.
		select {
		case stop := <-controls:
			stop()
		default:
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
		t.Fatal("log stream failure left the collector blocked on its pipe")
	}
	log := readStateLog(t, state, errLogName)
	if !strings.Contains(log, "failed to capture the collector output") || strings.Contains(log, "collector finished exit=") {
		t.Fatalf("capture failure must be explicit and must not claim completion: %s", log)
	}
}
