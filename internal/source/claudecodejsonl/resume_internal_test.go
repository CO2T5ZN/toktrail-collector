package claudecodejsonl

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"toktrail-collector/internal/local/scanledger"
	"toktrail-collector/internal/source/adapter"
)

// assistantLine renders one Claude Code assistant line carrying usage.
func assistantLine(t *testing.T, ts, sessionID, messageID string, in, cacheRead, cacheWrite, out uint64, model string) string {
	t.Helper()
	usage := fmt.Sprintf(`{"input_tokens":%d,"cache_read_input_tokens":%d,"cache_creation_input_tokens":%d,"output_tokens":%d}`,
		in, cacheRead, cacheWrite, out)
	msg := fmt.Sprintf(`{"id":%q,"usage":%s}`, messageID, usage)
	if model != "" {
		msg = fmt.Sprintf(`{"id":%q,"model":%q,"usage":%s}`, messageID, model, usage)
	}
	return fmt.Sprintf(`{"type":"assistant","timestamp":%q,"sessionId":%q,"message":%s}`, ts, sessionID, msg)
}

func writeClaudeFile(t *testing.T, dir, name string, lines ...string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	body := ""
	for _, line := range lines {
		body += line + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// commitStatesFor writes the committed scan ledger the collection would write
// after a successful export.
func commitStatesFor(t *testing.T, stateDir, input string) map[string]scanledger.FileState {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(input, "*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]scanledger.FileState{}
	for _, path := range paths {
		state, derr := scanledger.Digest(path)
		if derr != nil {
			t.Fatal(derr)
		}
		states[path] = state
	}
	if err := scanledger.New(stateDir).Save(adapter.ClaudeCodeJSONLSource, states); err != nil {
		t.Fatal(err)
	}
	return states
}

// multiFileFixture covers the hard cases: a later file's newer snapshot wins,
// an older snapshot must not, an equal-timestamp tie keeps the first
// representative, and a second message is spread across two files.
func multiFileFixture(t *testing.T) string {
	t.Helper()
	input := filepath.Join(t.TempDir(), "projects")
	writeClaudeFile(t, input, "a.jsonl",
		assistantLine(t, "2026-10-20T01:00:00Z", "s1", "m1", 10, 0, 0, 5, "claude-sonnet-4-6"),
		assistantLine(t, "2026-10-20T03:00:00Z", "s1", "m2", 20, 0, 0, 7, "claude-sonnet-4-6"),
	)
	writeClaudeFile(t, input, "b.jsonl",
		assistantLine(t, "2026-10-20T02:00:00Z", "s2", "m1", 15, 0, 0, 6, "claude-sonnet-4-6"),
		assistantLine(t, "2026-10-20T03:00:00Z", "s2", "m2", 20, 0, 0, 7, "claude-sonnet-4-6"),
	)
	writeClaudeFile(t, input, "c.jsonl",
		assistantLine(t, "2026-10-20T00:00:00Z", "s3", "m1", 12, 0, 0, 5, "claude-sonnet-4-6"),
	)
	return input
}

func scanFull(t *testing.T, input string) ([]claudeCodeMessage, []adapter.LineIssue, int) {
	t.Helper()
	messages, issues, quarantined, err := loadClaudeCodeMessages(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	return messages, issues, quarantined
}

func scanResuming(t *testing.T, input, stateDir string) ([]claudeCodeMessage, []adapter.LineIssue, int) {
	t.Helper()
	messages, issues, quarantined, _, err := loadClaudeCodeMessagesResuming(context.Background(), input, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	return messages, issues, quarantined
}

// A cache hit must reproduce the full scan exactly: the cache stores each
// file's observations in order and replays them, so the cross-file merge sees
// the identical sequence.
func TestClaudeResumeMatchesFullScan(t *testing.T) {
	input := multiFileFixture(t)
	stateDir := t.TempDir()

	wantMessages, wantIssues, wantQuarantined := scanFull(t, input)

	// First resumable scan: everything parsed, cache written.
	gotMessages, gotIssues, gotQuarantined := scanResuming(t, input, stateDir)
	if !reflect.DeepEqual(gotMessages, wantMessages) {
		t.Fatalf("first resumable scan differs from the full scan:\n got %#v\nwant %#v", gotMessages, wantMessages)
	}

	// Commit the files, then scan again: this run is served from the cache.
	commitStatesFor(t, stateDir, input)
	cachedMessages, cachedIssues, cachedQuarantined := scanResuming(t, input, stateDir)
	if !reflect.DeepEqual(cachedMessages, wantMessages) {
		t.Fatalf("cache-served scan differs from the full scan:\n got %#v\nwant %#v", cachedMessages, wantMessages)
	}
	if !reflect.DeepEqual(cachedIssues, wantIssues) || cachedQuarantined != wantQuarantined {
		t.Fatalf("diagnostics differ: issues %#v/%#v quarantined %d/%d", cachedIssues, wantIssues, cachedQuarantined, wantQuarantined)
	}
	if gotQuarantined != wantQuarantined || !reflect.DeepEqual(gotIssues, wantIssues) {
		t.Fatalf("first-scan diagnostics differ: %#v vs %#v", gotIssues, wantIssues)
	}
}

// A changed file is re-parsed, and the merged result follows the new
// snapshots — while the unchanged files keep being served from the cache.
func TestClaudeResumeReparsesChangedFile(t *testing.T) {
	input := multiFileFixture(t)
	stateDir := t.TempDir()
	scanResuming(t, input, stateDir)
	commitStatesFor(t, stateDir, input)

	// A newer snapshot of m1 arrives in a fresh file.
	writeClaudeFile(t, input, "d.jsonl",
		assistantLine(t, "2026-10-20T09:00:00Z", "s4", "m1", 40, 0, 0, 9, "claude-sonnet-4-6"),
	)
	wantMessages, _, _ := scanFull(t, input)
	gotMessages, _, _ := scanResuming(t, input, stateDir)
	if !reflect.DeepEqual(gotMessages, wantMessages) {
		t.Fatalf("incremental scan after a new snapshot differs:\n got %#v\nwant %#v", gotMessages, wantMessages)
	}
	for _, message := range gotMessages {
		if message.ID == "m1" && (message.Usage.Input == nil || *message.Usage.Input != 40) {
			t.Fatalf("the newest snapshot must win, got %#v", message.Usage)
		}
	}
}

// The cache is only valid for files whose digests are in the committed scan
// ledger: with no committed state the loader must still read the files.
func TestClaudeResumeNeedsCommittedState(t *testing.T) {
	input := multiFileFixture(t)
	stateDir := t.TempDir()
	scanResuming(t, input, stateDir) // writes the cache, commits nothing

	// Rewrite one file's content without committing: the new content must be
	// observed, so the cache cannot be trusted on its own.
	writeClaudeFile(t, input, "c.jsonl",
		assistantLine(t, "2026-10-20T11:00:00Z", "s3", "m1", 99, 0, 0, 5, "claude-sonnet-4-6"),
	)
	gotMessages, _, _ := scanResuming(t, input, stateDir)
	wantMessages, _, _ := scanFull(t, input)
	if !reflect.DeepEqual(gotMessages, wantMessages) {
		t.Fatalf("uncommitted changes must be re-read:\n got %#v\nwant %#v", gotMessages, wantMessages)
	}
	found := false
	for _, message := range gotMessages {
		if message.ID == "m1" && message.Usage.Input != nil && *message.Usage.Input == 99 {
			found = true
		}
	}
	if !found {
		t.Fatalf("the rewritten snapshot was not observed: %#v", gotMessages)
	}
}

// The scan states a resumable scan reports are exactly the files it saw, so
// the caller can persist them after its commit.
func TestClaudeResumeReportsScanStates(t *testing.T) {
	input := multiFileFixture(t)
	stateDir := t.TempDir()
	_, _, _, states, err := loadClaudeCodeMessagesResuming(context.Background(), input, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 3 {
		t.Fatalf("states = %#v, want one per file", states)
	}
	cutoff := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for path, state := range states {
		if state.Digest == "" || state.Size == 0 {
			t.Fatalf("state for %s is incomplete: %#v", path, state)
		}
		if state.ModTimeNS < cutoff.UnixNano() {
			t.Fatalf("state for %s has no mtime: %#v", path, state)
		}
	}
}

// The reason the cache stores observations instead of a folded per-file
// state: a file may repeat the same usage at two timestamps, and only the
// later one decides the winner once another file's snapshot is in play.
// Folding the file first would discard that later timestamp.
func TestClaudeResumeKeepsLaterTimestampOfRepeatedUsage(t *testing.T) {
	input := filepath.Join(t.TempDir(), "projects")
	writeClaudeFile(t, input, "x.jsonl",
		assistantLine(t, "2026-10-20T00:00:50Z", "sx", "m9", 10, 0, 0, 1, "claude-sonnet-4-6"),
	)
	writeClaudeFile(t, input, "y.jsonl",
		assistantLine(t, "2026-10-20T00:00:10Z", "sy", "m9", 20, 0, 0, 2, "claude-sonnet-4-6"),
		assistantLine(t, "2026-10-20T00:01:00Z", "sy", "m9", 20, 0, 0, 2, "claude-sonnet-4-6"),
	)
	stateDir := t.TempDir()
	scanResuming(t, input, stateDir)
	commitStatesFor(t, stateDir, input)

	wantMessages, _, _ := scanFull(t, input)
	gotMessages, _, _ := scanResuming(t, input, stateDir)
	if !reflect.DeepEqual(gotMessages, wantMessages) {
		t.Fatalf("cache-served merge differs from the full scan:\n got %#v\nwant %#v", gotMessages, wantMessages)
	}
	// The 20-token snapshot is newer everywhere; its later timestamp must
	// survive the merge.
	for _, message := range gotMessages {
		if message.ID != "m9" {
			continue
		}
		if message.Usage.Input == nil || *message.Usage.Input != 20 {
			t.Fatalf("usage = %#v, want the 20-token snapshot", message.Usage)
		}
		if !message.Timestamp.Equal(time.Date(2026, 10, 20, 0, 1, 0, 0, time.UTC)) {
			t.Fatalf("timestamp = %v, want the later 00:01:00 observation", message.Timestamp)
		}
	}
}
