package main

import (
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/app/collection"
)

// A terminal renders one in-place status line: no newline per update, a
// carriage return + clear before each rewrite, and a final newline so the
// summary starts on its own line.
func TestPeriodicHeartbeatInPlaceOnTerminal(t *testing.T) {
	cur := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	now := func() time.Time { return cur }
	var out strings.Builder
	hb := newPeriodicHumanHeartbeatFor(&out, cur, now, true)

	hb.handle(collection.ProgressEvent{Kind: collection.ProgressHeartbeat, Stage: "source_scan"})
	if out.String() != "" {
		t.Fatalf("nothing may render before the interval elapses, got %q", out.String())
	}
	cur = cur.Add(6 * time.Second)
	hb.handle(collection.ProgressEvent{Kind: collection.ProgressHeartbeat, Stage: "source_scan", Counted: true, PendingBatches: 3, RecordsCounted: true, PendingRecords: 900})
	first := out.String()
	if !strings.Contains(first, "\r\x1b[K") {
		t.Fatalf("an in-place update must rewrite the same line, got %q", first)
	}
	if strings.Contains(first, "\n") {
		t.Fatalf("an in-place update must not emit a newline, got %q", first)
	}
	if !strings.Contains(first, "scanning the granted sources") || !strings.Contains(first, "3 batches pending (900 records)") {
		t.Fatalf("the in-place line carries the closed-set stage and gated counts, got %q", first)
	}
	if strings.Contains(first, "2026-11-05") {
		t.Fatalf("the in-place line omits the timestamp (it is continuously visible), got %q", first)
	}
	hb.Close()
	if !strings.HasSuffix(out.String(), "\n") {
		t.Fatalf("Close must terminate the line, got %q", out.String())
	}
	// Close is idempotent.
	before := out.String()
	hb.Close()
	if out.String() != before {
		t.Fatalf("a second Close must not write again, got %q", out.String())
	}
}

// A redirected stream (scheduled-task log, CI, pipe) gets no periodic
// chatter: only a low-frequency stall notice, on its own line.
func TestPeriodicHeartbeatQuietOnRedirectedStream(t *testing.T) {
	cur := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	now := func() time.Time { return cur }
	var out strings.Builder
	hb := newPeriodicHumanHeartbeatFor(&out, cur, now, false)

	cur = cur.Add(30 * time.Second)
	hb.handle(collection.ProgressEvent{Kind: collection.ProgressHeartbeat, Stage: "drain"})
	cur = cur.Add(5 * time.Minute)
	hb.handle(collection.ProgressEvent{Kind: collection.ProgressHeartbeat, Stage: "drain"})
	if out.String() != "" {
		t.Fatalf("a redirected stream must not log 30s heartbeats, got %q", out.String())
	}
	cur = cur.Add(6 * time.Minute)
	hb.handle(collection.ProgressEvent{Kind: collection.ProgressHeartbeat, Stage: "drain", Counted: true, PendingBatches: 4, RecordsCounted: true, PendingRecords: 8})
	got := out.String()
	if !strings.Contains(got, "Still running:") || !strings.Contains(got, "4 batches pending (8 records)") {
		t.Fatalf("the low-frequency stall notice must still report progress, got %q", got)
	}
	if strings.Contains(got, "\r") || strings.Contains(got, "\x1b[") {
		t.Fatalf("a redirected log must carry no terminal control characters, got %q", got)
	}
	if !strings.HasSuffix(got, "\n") {
		t.Fatalf("the stall notice must be its own line, got %q", got)
	}
}

// A non-terminal human stream drops heartbeat lines instead of filling
// the log, while phase output and the final summary are untouched.
func TestHumanStreamQuietDropsHeartbeats(t *testing.T) {
	var buf strings.Builder
	hs := newHumanStream(&buf)
	hs.quiet = true
	if _, err := hs.Write([]byte("connected to server; device bound\n")); err != nil {
		t.Fatal(err)
	}
	n, err := hs.WriteHeartbeatLine([]byte("Scanning local sources: still working (2s elapsed).\n"))
	if err != nil || n == 0 {
		t.Fatalf("a dropped heartbeat still reports success, got (%d, %v)", n, err)
	}
	if strings.Contains(buf.String(), "still working") {
		t.Fatalf("the heartbeat must not reach a non-terminal stream, got %q", buf.String())
	}
	if !strings.Contains(buf.String(), "device bound") {
		t.Fatalf("phase output must still render, got %q", buf.String())
	}

	// A terminal stream keeps the heartbeat.
	var live strings.Builder
	liveHS := newHumanStream(&live)
	if _, err := liveHS.WriteHeartbeatLine([]byte("Scanning local sources: still working (2s elapsed).\n")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(live.String(), "still working") {
		t.Fatalf("a terminal keeps heartbeat lines, got %q", live.String())
	}
}
