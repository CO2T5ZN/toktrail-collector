package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"toktrail-collector/internal/connect"
	"toktrail-collector/internal/syncbudget"
	"toktrail-collector/internal/syncretry"
)

// The ownership fail-closed refusals must surface actionable guidance
// instead of the generic fatal phrase: the display layer maps each
// sentinel to one fixed, path-free instruction (the detailed error text
// embeds server-controlled identifiers and is never displayed).
func TestConnectOwnershipRefusalsDisplayGuidance(t *testing.T) {
	sentinels := []error{
		connect.ErrStateAuthorizationMismatch,
		connect.ErrStateOwnershipMismatch,
		connect.ErrUnboundSyncedHistory,
		connect.ErrRebindIdentityChange,
	}
	for _, sentinel := range sentinels {
		wrapped := fmt.Errorf("run failed: %w: detailed text with server=%s subjectId=%s", sentinel, "https://example", "sub-1")
		got := runFailureDisplayText(wrapped, "an unexpected error occurred")
		if !strings.Contains(got, "cannot be reused") || !strings.Contains(got, "--state-dir") {
			t.Fatalf("sentinel %v must map to the state-directory guidance, got: %q", sentinel, got)
		}
		if !strings.Contains(got, "--replace-state") {
			t.Fatalf("the guidance must mention the --replace-state override, got: %q", got)
		}
		if strings.Contains(got, "https://example") || strings.Contains(got, "sub-1") {
			t.Fatalf("the guidance must not echo server-controlled identifiers, got: %q", got)
		}
		if got == "an unexpected error occurred" {
			t.Fatalf("sentinel %v must not degrade to the generic phrase", sentinel)
		}
	}
	// Unrelated errors keep the closed-set fallback.
	if got := runFailureDisplayText(errors.New("opaque"), "an unexpected error occurred"); got != "an unexpected error occurred" {
		t.Fatalf("unrelated errors keep the fallback phrase, got: %q", got)
	}
}

// --replace-state pre-confirms the replacement without reading stdin,
// printing the fixed notice and the forced-by line; without the flag the
// wiring is the interactive prompt (never nil, never auto-confirming).
func TestStateReplaceConfirmForForcedAndInteractive(t *testing.T) {
	forced := stateReplaceConfirmFor(true, nil)
	out := &strings.Builder{}
	confirmed, err := forced("notice-text", out)
	if err != nil || !confirmed {
		t.Fatalf("--replace-state must pre-confirm, got (%v, %v)", confirmed, err)
	}
	if !strings.Contains(out.String(), "notice-text") || !strings.Contains(out.String(), "forced by --replace-state") {
		t.Fatalf("the forced confirmation must print the notice and the forced-by line, got: %q", out.String())
	}
	interactive := stateReplaceConfirmFor(false, nil)
	if interactive == nil {
		t.Fatal("without the flag the interactive prompt must be wired, not nil")
	}
}

// netErrorProbe is a minimal net.Error for classification tests.
type netErrorProbe struct {
	msg     string
	timeout bool
}

func (e netErrorProbe) Error() string   { return e.msg }
func (e netErrorProbe) Timeout() bool   { return e.timeout }
func (e netErrorProbe) Temporary() bool { return e.timeout }

// The run's own deadline is not a network fault: the device may be
// perfectly reachable, and telling the user to check connectivity sent
// them to debug a healthy server. Every deadline shape maps to the
// time-limit wording, and only genuine transport failures map to the
// unreachable wording.
func TestRunFailureDisplayTextClassifiesDeadlineAndNetwork(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"run context deadline", fmt.Errorf("sync: %w", context.DeadlineExceeded), "time limit was reached"},
		{"shared budget deadline", fmt.Errorf("drain: %w", syncbudget.ErrDeadlineExceeded), "time limit was reached"},
		{"retry past deadline", fmt.Errorf("upload: %w", syncretry.ErrRetryPastDeadline), "time limit was reached"},
		{"single request timeout", fmt.Errorf("post: %w", netErrorProbe{msg: "i/o timeout", timeout: true}), "request timed out"},
		{"dial failure", fmt.Errorf("post: %w", netErrorProbe{msg: "connection refused"}), "could not be reached"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runFailureDisplayText(tc.err, "generic fallback")
			if !strings.Contains(got, tc.want) {
				t.Fatalf("classification = %q, want it to contain %q", got, tc.want)
			}
			if tc.want == "time limit was reached" && strings.Contains(got, "could not be reached") {
				t.Fatalf("a run deadline must never be reported as an unreachable server: %q", got)
			}
		})
	}
	// An unclassified error keeps the closed-set fallback.
	if got := runFailureDisplayText(errors.New("opaque"), "generic fallback"); got != "generic fallback" {
		t.Fatalf("unclassified errors keep the fallback, got %q", got)
	}
}
