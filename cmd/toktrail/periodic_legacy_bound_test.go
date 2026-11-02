package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestPeriodicContextDeadlineReportsIncomplete(t *testing.T) {
	dir, server := budgetCLIFixture(t)
	args := []string{"--state-dir", dir, "--server", server.URL, "--drain-only", "--sync-timeout=1ns", "--verbose"}
	out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
	if err == nil || !strings.Contains(err.Error(), "periodic incomplete") || !strings.Contains(out, "incomplete: the periodic run timeout") {
		t.Fatalf("deadline must report incomplete: err=%v stdout=%s", err, out)
	}
}

func TestPeriodicNonPositiveLegacyBoundWithSharedTotal(t *testing.T) {
	for _, limit := range []int{0, -1} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			dir, server := budgetCLIFixture(t)
			for i := 4; i <= 7; i++ {
				writePeriodicDrainPendingBatch(t, dir, fmt.Sprintf("legacy-zero-%d", i), 1)
			}
			args := []string{"--state-dir", dir, "--server", server.URL, "--drain-only", fmt.Sprintf("--max-batches=%d", limit), "--max-total-batches=20", "--verbose"}
			out, err := capturePeriodicStdout(t, func() error { return runPeriodic(args) })
			if err != nil || server.ingest.Load() != 5 || !strings.Contains(out, "pendingRemaining=2") {
				t.Fatalf("non-positive legacy bound must fall back to 5: err=%v posts=%d stdout=%s", err, server.ingest.Load(), out)
			}
		})
	}
}
