package winbackground

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

type rejectedLogWriter struct{}

func (rejectedLogWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestCopyCollectorStreamStopsOnWriteFailure(t *testing.T) {
	stopped := false
	err := copyCollectorStream(rejectedLogWriter{}, strings.NewReader("synthetic output"), func() { stopped = true })
	if !errors.Is(err, io.ErrClosedPipe) || !stopped {
		t.Fatalf("write failure did not stop supervision: err=%v stopped=%t", err, stopped)
	}
}

func TestCopyCollectorStreamCleanEOFDoesNotStop(t *testing.T) {
	var out bytes.Buffer
	stopped := false
	err := copyCollectorStream(&out, strings.NewReader("synthetic output"), func() { stopped = true })
	if err != nil || stopped || out.String() != "synthetic output" {
		t.Fatalf("clean stream changed: output=%q err=%v stopped=%t", out.String(), err, stopped)
	}
}
