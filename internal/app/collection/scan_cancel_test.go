package collection

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/progress"
)

func TestCanceledSourceScanDoesNotCommitExport(t *testing.T) {
	dir := t.TempDir()
	sessions := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, sessions, "session.jsonl", claudeLine(t, "2026-10-21T04:00:00Z", "session", "message", claudeUsage(10, 0, 0, 5)))
	enableGrant(t, dir, "claude-code-jsonl", sessions)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := Run(ctx, Options{StateDir: dir, Progress: func(event ProgressEvent) {
		if event.Kind == ProgressStageStart && event.Stage == "source_scan" {
			cancel()
		}
	}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected scan cancellation, got %+v, %v", result, err)
	}
	ledger, err := outbox.New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(ledger.Batches) != 0 || result.ExportedBatches != 0 {
		t.Fatalf("cancelled scan committed batches: %+v, %+v", ledger.Batches, result)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "batches"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("cancelled scan wrote batch files: %v", entries)
	}
	store := progress.New(dir)
	for _, path := range []string{store.Path(), store.MessageProgressPath()} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("cancelled scan unexpectedly wrote progress: %s err=%v", path, err)
		}
	}
}
