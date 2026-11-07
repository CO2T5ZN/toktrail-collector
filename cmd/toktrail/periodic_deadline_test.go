package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/syncretry"
)

func TestPeriodicRunTimedOut(t *testing.T) {
	deadline := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name          string
		err, ctxErr   error
		deadline, now time.Time
		want          bool
	}{
		{"retry at deadline before context timer", syncretry.ErrRetryPastDeadline, nil, deadline, deadline, true},
		{"wrapped retry after deadline before context timer", fmt.Errorf("preflight: %w", syncretry.ErrRetryPastDeadline), nil, deadline, deadline.Add(time.Nanosecond), true},
		{"context error at deadline before context timer", context.DeadlineExceeded, nil, deadline, deadline, true},
		{"context timer already fired", context.DeadlineExceeded, context.DeadlineExceeded, deadline, deadline, true},
		{"next retry does not fit future deadline", syncretry.ErrRetryPastDeadline, nil, deadline, deadline.Add(-time.Nanosecond), false},
		{"client timeout with run time remaining", context.DeadlineExceeded, nil, deadline, deadline.Add(-time.Second), false},
		{"unrelated error after deadline", errors.New("synthetic local failure"), nil, deadline, deadline.Add(time.Second), false},
		{"cancelled context", context.Canceled, context.Canceled, deadline, deadline, false},
		{"retry after explicit cancellation", syncretry.ErrRetryPastDeadline, context.Canceled, deadline, deadline, false},
		{"no known run deadline", syncretry.ErrRetryPastDeadline, nil, time.Time{}, deadline, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := periodicRunTimedOut(tc.err, tc.ctxErr, tc.deadline, tc.now); got != tc.want {
				t.Fatalf("timeout = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestPeriodicDeadlineJSON(t *testing.T) {
	dir, server := budgetCLIFixture(t)
	var stdout, stderr bytes.Buffer
	err := runPeriodicIO([]string{"--state-dir", dir, "--server", server.URL, "--drain-only", "--sync-timeout=1ns", "--json", "--verbose"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "periodic incomplete: run timeout") {
		t.Fatalf("deadline must report incomplete: %v\n%s", err, stderr.String())
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, syncretry.ErrRetryPastDeadline) {
		t.Fatalf("deadline error chain lost its cause: %v", err)
	}
	decoded := decodeSingleJSONLine(t, stdout.String())
	if decoded["stop_reason"] != string(collection.StopBudgetExhausted) {
		t.Fatalf("deadline JSON verdict = %v, want budget_exhausted", decoded["stop_reason"])
	}
	if !strings.Contains(stderr.String(), "incomplete: the periodic run timeout") {
		t.Fatalf("human deadline diagnosis missing: %s", stderr.String())
	}
}

func TestPeriodicRetryPastFutureDeadlineDisplay(t *testing.T) {
	text := periodicRunErrorSafeText(syncretry.ErrRetryPastDeadline, nil)
	if !strings.Contains(text, "periodic incomplete") || !strings.Contains(text, "next retry cannot fit") || strings.Contains(text, "elapsed") {
		t.Fatalf("a retry that cannot fit a future deadline must not claim time elapsed: %s", text)
	}
}
