package main

// CLI-boundary tests for the unified progress stream: the JSONL writer's
// gated keys (an unmeasured duration, an unknown receipt or an unknown
// queue field never appears as a zero value), the serialized writer's
// line integrity under concurrency, and the stream contract of the real
// entry points (--json keeps stdout a single object; progress events
// live only on stderr, distinguishable per line by the
// "type":"collection_progress" discriminator; the default output stays
// untouched). Everything is synthetic tempdir state and httptest fakes.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/statedir"
)

// enableProgressCLIGrant enables an idle claude-code-jsonl grant so the
// periodic run has a granted source whose scan is empty (the drain path
// still runs and emits its stream).
func enableProgressCLIGrant(t *testing.T, stateDir string) {
	t.Helper()
	sessions := filepath.Join(t.TempDir(), "sessions")
	if err := os.MkdirAll(sessions, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := grants.New(stateDir).Enable("claude-code-jsonl", sessions); err != nil {
		t.Fatal(err)
	}
}

func decodeProgressLine(t *testing.T, line string) map[string]any {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("invalid progress JSONL %q: %v", line, err)
	}
	if got["type"] != "collection_progress" {
		t.Fatalf("every progress line must carry the type discriminator: %q", line)
	}
	return got
}

// The historical stage/count key set is byte-identical to the
// pre-extension writer — existing consumers keep parsing.
func TestWriteCollectionProgressJSONStageEventKeySetUnchanged(t *testing.T) {
	var buf bytes.Buffer
	writeCollectionProgressJSON(&buf)(collection.ProgressEvent{
		Kind:             collection.ProgressStageEnd,
		Stage:            "drain",
		StartedAt:        time.Date(2026, 10, 30, 1, 2, 3, 0, time.UTC),
		EndedAt:          time.Date(2026, 10, 30, 1, 2, 4, 0, time.UTC),
		Duration:         time.Second,
		SyncedBatches:    2,
		SyncedRecords:    1000,
		PendingRemaining: 3,
	})
	got := decodeProgressLine(t, strings.TrimSpace(buf.String()))
	for _, key := range []string{"type", "kind", "stage", "source", "input", "startedAt", "endedAt", "durationMs", "error", "exportedBatches", "exportedRecords", "syncedBatches", "syncedRecords", "pendingRemaining"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("the historical key %q must stay present: %#v", key, got)
		}
	}
	for _, key := range []string{"queue", "attempt", "result", "pendingBatches", "counted", "samples"} {
		if _, ok := got[key]; ok {
			t.Fatalf("a stage event must not carry the new-kind keys: %q in %#v", key, got)
		}
	}
}

// A device-shaped batch event: every gated field appears only behind
// its gate; the account wait phase never masquerades as an http
// duration; an unseen receipt never appears as zero counts.
func TestWriteCollectionProgressJSONBatchGates(t *testing.T) {
	var buf bytes.Buffer
	write := writeCollectionProgressJSON(&buf)

	// Device shape: acked attempt, everything measured.
	write(collection.ProgressEvent{
		Kind:            collection.ProgressBatch,
		Queue:           collection.ProgressQueueDevice,
		Attempt:         2,
		AttemptStage:    "ack",
		Result:          "acked",
		Prepare:         10 * time.Millisecond,
		SelfCheck:       5 * time.Millisecond,
		HTTP:            100 * time.Millisecond,
		ACK:             7 * time.Millisecond,
		InterAttempt:    time.Second,
		PrepareMeasured: true, SelfCheckMeasured: true, HTTPMeasured: true, ACKMeasured: true, InterAttemptMeasured: true,
		PayloadBytes:           2048,
		PayloadBytesKnown:      true,
		AcceptedRecords:        5,
		ReceiptObserved:        true,
		BatchReplay:            true,
		FirstBatchConfirmation: collection.FirstBatchConfirmationYes,
		Origin:                 collection.OriginUnknown,
	})
	got := decodeProgressLine(t, lastLine(t, &buf))
	for key, want := range map[string]any{
		"queue": collection.ProgressQueueDevice, "attempt": float64(2),
		"attemptStage": "ack", "result": "acked",
		"prepareMs": float64(10), "selfCheckMs": float64(5), "httpMs": float64(100), "ackMs": float64(7),
		"interAttemptMs": float64(1000), "payloadBytes": float64(2048),
		"acceptedRecords": float64(5), "batchReplay": true,
		"firstBatchConfirmation": collection.FirstBatchConfirmationYes, "origin": collection.OriginUnknown,
	} {
		if got[key] != want {
			t.Fatalf("key %q must be %v, got %#v", key, want, got[key])
		}
	}

	// Account wait phase: the spacing is the inter-attempt delay, never
	// an http duration; no httpMs key may appear.
	buf.Reset()
	write(collection.ProgressEvent{
		Kind:                   collection.ProgressBatch,
		Queue:                  collection.ProgressQueueCursor,
		Phase:                  "wait",
		Result:                 "ok",
		Attempt:                2,
		InterAttempt:           1500 * time.Millisecond,
		InterAttemptMeasured:   true,
		FirstBatchConfirmation: collection.FirstBatchConfirmationNo,
	})
	got = decodeProgressLine(t, lastLine(t, &buf))
	if got["phase"] != "wait" || got["interAttemptMs"] != float64(1500) {
		t.Fatalf("the wait phase must carry its spacing: %#v", got)
	}
	if _, ok := got["httpMs"]; ok {
		t.Fatalf("a wait phase must never report an http duration: %#v", got)
	}
	if _, ok := got["durationMs"]; ok {
		t.Fatalf("a wait event times no phase of its own: %#v", got)
	}

	// An unseen receipt: no accepted/rejected/replay keys at all.
	buf.Reset()
	write(collection.ProgressEvent{
		Kind:          collection.ProgressBatch,
		Queue:         collection.ProgressQueueCursor,
		Phase:         "http",
		Result:        "failed",
		Attempt:       1,
		Duration:      time.Second,
		DurationKnown: true,
	})
	got = decodeProgressLine(t, lastLine(t, &buf))
	for _, key := range []string{"acceptedRecords", "rejectedRecords", "batchReplay", "payloadBytes"} {
		if _, ok := got[key]; ok {
			t.Fatalf("an unseen receipt must not carry %q: %#v", key, got)
		}
	}
}

// Queue snapshots and heartbeats emit their gated fields only.
func TestWriteCollectionProgressJSONQueueAndHeartbeatGates(t *testing.T) {
	var buf bytes.Buffer
	write := writeCollectionProgressJSON(&buf)

	// Unknown bytes and records: the keys stay absent, the flags say why.
	write(collection.ProgressEvent{
		Kind:           collection.ProgressQueue,
		Queue:          collection.ProgressQueueDevice,
		PendingBatches: 4,
		Counted:        true,
		RecordsCounted: false,
	})
	got := decodeProgressLine(t, lastLine(t, &buf))
	if got["counted"] != true || got["recordsCounted"] != false || got["pendingBatches"] != float64(4) {
		t.Fatalf("the queue flags must be explicit: %#v", got)
	}
	for _, key := range []string{"pendingRecords", "pendingBytes", "oldestPendingAgeMs"} {
		if _, ok := got[key]; ok {
			t.Fatalf("an unknown field must stay absent: %q in %#v", key, got)
		}
	}

	// An UNREAD queue (Counted false): pendingBatches itself stays
	// absent — a bare zero would read as a really empty queue.
	buf.Reset()
	write(collection.ProgressEvent{
		Kind:  collection.ProgressQueue,
		Queue: collection.ProgressQueueDevice,
	})
	got = decodeProgressLine(t, lastLine(t, &buf))
	if got["counted"] != false {
		t.Fatalf("the counted flag must state the unknown: %#v", got)
	}
	if _, ok := got["pendingBatches"]; ok {
		t.Fatalf("an unread queue must not state a batch count: %#v", got)
	}

	// A KNOWN empty queue states zero explicitly.
	buf.Reset()
	write(collection.ProgressEvent{
		Kind:           collection.ProgressQueue,
		Queue:          collection.ProgressQueueDevice,
		Counted:        true,
		RecordsCounted: true,
		BytesCounted:   true,
	})
	got = decodeProgressLine(t, lastLine(t, &buf))
	if got["pendingBatches"] != float64(0) || got["pendingRecords"] != float64(0) || got["pendingBytes"] != float64(0) {
		t.Fatalf("a known empty queue observes zeros: %#v", got)
	}

	// A heartbeat with an unknown aggregate omits pendingBatches too.
	buf.Reset()
	write(collection.ProgressEvent{
		Kind:  collection.ProgressHeartbeat,
		Stage: "drain",
	})
	got = decodeProgressLine(t, lastLine(t, &buf))
	if _, ok := got["pendingBatches"]; ok {
		t.Fatalf("an uncounted heartbeat aggregate must not state a batch count: %#v", got)
	}
	if got["counted"] != false {
		t.Fatalf("the heartbeat must state why the count is absent: %#v", got)
	}

	// A heartbeat without samples carries no rate and no ETA.
	buf.Reset()
	write(collection.ProgressEvent{
		Kind:     collection.ProgressHeartbeat,
		Stage:    "source_scan",
		Duration: 5 * time.Second,
		Samples:  0,
		Counted:  true,
	})
	got = decodeProgressLine(t, lastLine(t, &buf))
	if _, ok := got["processingRateRecPerSec"]; ok {
		t.Fatalf("no samples means no rate: %#v", got)
	}
	if _, ok := got["etaMs"]; ok {
		t.Fatalf("no samples means no ETA: %#v", got)
	}

	// Samples alone do not license a rate: a drain that never started
	// (or whose observation window has no positive elapsed time) never
	// computed one — a bare zero must not masquerade as a measurement.
	buf.Reset()
	write(collection.ProgressEvent{
		Kind:    collection.ProgressHeartbeat,
		Stage:   "history",
		Samples: 4,
		Counted: true,
	})
	got = decodeProgressLine(t, lastLine(t, &buf))
	if got["samples"] != float64(4) {
		t.Fatalf("the sample count itself is a fact: %#v", got)
	}
	if _, ok := got["processingRateRecPerSec"]; ok {
		t.Fatalf("an uncomputed rate must stay absent even with samples: %#v", got)
	}

	// A computed heartbeat carries the processing rate and the ETA.
	buf.Reset()
	write(collection.ProgressEvent{
		Kind:                       collection.ProgressHeartbeat,
		Stage:                      "drain",
		Duration:                   5 * time.Second,
		Samples:                    3,
		Counted:                    true,
		RecordsCounted:             true,
		PendingBatches:             6,
		PendingRecords:             600,
		RateKnown:                  true,
		ProcessingRateRecPerSec:    10,
		Eta:                        60 * time.Second,
		EtaKnown:                   true,
		FirstBatchConfirmedBatches: 3,
	})
	got = decodeProgressLine(t, lastLine(t, &buf))
	if got["processingRateRecPerSec"] != float64(10) || got["etaMs"] != float64(60000) {
		t.Fatalf("a sampled heartbeat must carry rate and ETA: %#v", got)
	}
	if got["firstBatchConfirmedBatches"] != float64(3) {
		t.Fatalf("the batch-granularity counter must ride along: %#v", got)
	}
}

func lastLine(t *testing.T, buf *bytes.Buffer) string {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) == 0 {
		t.Fatalf("no progress line was written")
	}
	return lines[len(lines)-1]
}

// The serialized writer keeps every line intact under concurrent
// writers (run under -race: unsynchronized writes race here).
func TestSerializedWriterKeepsLinesIntactUnderConcurrency(t *testing.T) {
	var raw bytes.Buffer
	w := newSerializedWriter(&raw)
	const writers, lines = 4, 100
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < lines; j++ {
				fmt.Fprintf(w, "{\"writer\":%d,\"line\":%d,\"padding\":\"%s\"}\n", id, j, strings.Repeat("x", 64))
			}
		}(i)
	}
	wg.Wait()
	out := raw.String()
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var decoded struct {
			Writer  int    `json:"writer"`
			Line    int    `json:"line"`
			Padding string `json:"padding"`
		}
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Fatalf("a serialized line must stay parseable, got %q: %v", line, err)
		}
		if len(decoded.Padding) != 64 {
			t.Fatalf("a serialized line must stay intact, got padding %d", len(decoded.Padding))
		}
	}
}

// The heartbeat's attemptInFlight key appears only when the flow's
// Begin/End hooks are accurate — an untracked flow omits the key
// entirely (unknown), never a defaulted false.
func TestWriteCollectionProgressJSONAttemptInFlightGate(t *testing.T) {
	var buf bytes.Buffer
	write := writeCollectionProgressJSON(&buf)

	// Untracked (enable/history-shaped): the key stays absent.
	write(collection.ProgressEvent{Kind: collection.ProgressHeartbeat, Stage: "cursor_sync"})
	got := decodeProgressLine(t, lastLine(t, &buf))
	if _, ok := got["attemptInFlight"]; ok {
		t.Fatalf("an untracked attempt status must stay absent: %#v", got)
	}

	// Tracked and in flight: the key states true with its elapsed time.
	buf.Reset()
	write(collection.ProgressEvent{
		Kind:                 collection.ProgressHeartbeat,
		Stage:                "drain",
		AttemptInFlightKnown: true,
		AttemptInFlight:      true,
		AttemptElapsed:       2 * time.Second,
	})
	got = decodeProgressLine(t, lastLine(t, &buf))
	if got["attemptInFlight"] != true || got["attemptElapsedMs"] != float64(2000) {
		t.Fatalf("a tracked in-flight attempt must be stated: %#v", got)
	}

	// Tracked and idle: a known false is legitimate.
	buf.Reset()
	write(collection.ProgressEvent{
		Kind:                 collection.ProgressHeartbeat,
		Stage:                "drain",
		AttemptInFlightKnown: true,
	})
	got = decodeProgressLine(t, lastLine(t, &buf))
	if got["attemptInFlight"] != false {
		t.Fatalf("a tracked idle status is a stated false: %#v", got)
	}
	if _, ok := got["attemptElapsedMs"]; ok {
		t.Fatalf("an idle attempt has no elapsed time: %#v", got)
	}
}

// The shared stderr sink completes an open human line before a progress
// event: an interactive prompt without a newline stays visible and
// inputtable on its own line, and every progress event occupies its own
// per-line parseable line — while ticks keep firing past the "blocked
// stdin" window. Run under -race.
func TestSerializedWriterPromptKeepsProgressLinesParseable(t *testing.T) {
	var raw bytes.Buffer
	sink := newSerializedWriter(&raw)

	// The interactive prompt: deliberately no trailing newline, and it
	// stays open across more than one tick interval (a blocked stdin).
	promptDone := make(chan struct{})
	go func() {
		defer close(promptDone)
		fmt.Fprint(sink, "确认是否启用 Cursor 账户来源? [y/N] ")
		// Hold the open line across the tick window.
		time.Sleep(50 * time.Millisecond)
	}()

	// Heartbeat-style progress lines keep arriving while the prompt is
	// open (several "tick intervals").
	var wg sync.WaitGroup
	lines := make(chan string, 32)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			time.Sleep(time.Duration(n) * time.Millisecond)
			ev := map[string]any{"type": "collection_progress", "kind": "heartbeat", "n": n}
			b, _ := json.Marshal(ev)
			sink.WriteProgressLine(append(b, '\n'))
			lines <- string(b)
		}(i)
	}
	wg.Wait()
	<-promptDone
	close(lines)

	// The prompt text must survive intact on its own line.
	out := raw.String()
	if !strings.Contains(out, "确认是否启用 Cursor 账户来源? [y/N] ") {
		t.Fatalf("the prompt must stay visible, got %q", out)
	}
	// Every progress event must be per-line parseable with its type.
	sent := 0
	for range lines {
		sent++
	}
	if sent != 8 {
		t.Fatalf("all eight progress lines must have been written, got %d", sent)
	}
	progressLines := 0
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || !strings.HasPrefix(trimmed, "{") {
			continue
		}
		var probe map[string]any
		if err := json.Unmarshal([]byte(trimmed), &probe); err != nil {
			t.Fatalf("a progress line must stay parseable, got %q: %v", line, err)
		}
		if probe["type"] != "collection_progress" {
			t.Fatalf("a JSON line must be a progress event: %q", line)
		}
		progressLines++
	}
	if progressLines != 8 {
		t.Fatalf("every progress line must be standalone, got %d of 8 in:\n%s", progressLines, out)
	}
}

// The real periodic entry with --json + --progress-json: stdout carries
// exactly one JSON object; the progress events live only on stderr, one
// per line, each parseable with the type discriminator; human text on
// stderr never claims to be a progress event. Without --progress-json
// no progress line appears on either stream.
func TestRunPeriodicJSONAndProgressJSONStreams(t *testing.T) {
	stateDir := t.TempDir()
	server := newPeriodicDrainFakeServer(t)
	if err := statedir.New(stateDir).Save(statedir.DeviceState{
		ServerURL:    server.URL,
		DeviceID:     "dev-drain-1",
		DeviceSecret: periodicDrainSecret,
	}); err != nil {
		t.Fatal(err)
	}
	writePeriodicDrainPendingBatch(t, stateDir, "progress-cli-1", 1)
	writePeriodicDrainPendingBatch(t, stateDir, "progress-cli-2", 1)
	enableProgressCLIGrant(t, stateDir)

	args := []string{
		"--state-dir", stateDir,
		"--server", server.URL,
		"--sync-timeout", "30s",
		"--json",
		"--progress-json",
	}
	out, stderr, err := capturePeriodicStdoutAndStderr(t, func() error { return runPeriodic(args) })
	if err != nil {
		t.Fatalf("the drain run must succeed: %v", err)
	}

	// stdout: exactly one JSON object (the §6.5 result), no progress.
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		t.Fatalf("stdout must carry the result object")
	}
	if strings.Count(trimmed, "\n") != 0 {
		t.Fatalf("stdout must be exactly one line, got %q", trimmed)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(trimmed), &result); err != nil {
		t.Fatalf("stdout must be one JSON object: %v", err)
	}
	if _, ok := result["stop_reason"]; !ok {
		t.Fatalf("the result object must carry stop_reason: %#v", result)
	}

	// stderr: every line either parses as a progress event or is human
	// text; the two batch events and the queue snapshots must appear.
	progressLines := 0
	var sawBatch, sawQueue, sawHeartbeat bool
	for _, line := range strings.Split(stderr, "\n") {
		if strings.TrimSpace(line) == "" || !strings.HasPrefix(strings.TrimSpace(line), "{") {
			continue
		}
		var probe map[string]any
		if err := json.Unmarshal([]byte(line), &probe); err != nil {
			t.Fatalf("a JSON-looking stderr line must parse: %q: %v", line, err)
		}
		if probe["type"] != "collection_progress" {
			t.Fatalf("a JSON stderr line must be a progress event: %q", line)
		}
		progressLines++
		switch probe["kind"] {
		case "batch":
			sawBatch = true
		case "queue":
			sawQueue = true
		case "heartbeat":
			sawHeartbeat = true
		}
	}
	if progressLines == 0 || !sawBatch || !sawQueue || !sawHeartbeat {
		t.Fatalf("the stream must carry batch, queue and heartbeat events (lines=%d batch=%v queue=%v hb=%v)",
			progressLines, sawBatch, sawQueue, sawHeartbeat)
	}

	// Without --progress-json neither stream carries a progress line.
	stateDir2 := t.TempDir()
	if err := statedir.New(stateDir2).Save(statedir.DeviceState{
		ServerURL:    server.URL,
		DeviceID:     "dev-drain-1",
		DeviceSecret: periodicDrainSecret,
	}); err != nil {
		t.Fatal(err)
	}
	writePeriodicDrainPendingBatch(t, stateDir2, "progress-cli-off-1", 1)
	enableProgressCLIGrant(t, stateDir2)
	out2, stderr2, err2 := capturePeriodicStdoutAndStderr(t, func() error {
		return runPeriodic([]string{"--state-dir", stateDir2, "--server", server.URL, "--sync-timeout", "30s"})
	})
	if err2 != nil {
		t.Fatalf("the plain run must succeed: %v", err2)
	}
	if strings.Contains(out2, "collection_progress") || strings.Contains(stderr2, "collection_progress") {
		t.Fatalf("progress must stay off without --progress-json")
	}
}
