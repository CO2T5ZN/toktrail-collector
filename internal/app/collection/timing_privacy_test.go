package collection

import (
	"errors"
	"strings"
	"testing"
)

func TestProgressEventsDoNotExposePathsOrErrorDetails(t *testing.T) {
	var events []ProgressEvent
	progress := func(event ProgressEvent) { events = append(events, event) }
	start, wall := startProgress(progress, "source_scan", "codex-jsonl", "/private/session-secret")
	endProgress(progress, "source_scan", "codex-jsonl", "/private/session-secret", start, wall, errors.New("token=private-secret"), ProgressEvent{})
	if len(events) != 2 {
		t.Fatalf("expected start and end events, got %d", len(events))
	}
	for _, event := range events {
		if event.Input != "" || strings.Contains(event.Err, "private-secret") {
			t.Fatalf("progress exposed sensitive detail: %+v", event)
		}
	}
	if events[1].Err != "stage failed" {
		t.Fatalf("expected generic failure marker, got %q", events[1].Err)
	}
}
