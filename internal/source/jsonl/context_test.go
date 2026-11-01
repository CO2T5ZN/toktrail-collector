package jsonl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestContextCancellationStopsFileAndLineScan(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(file, []byte("first\nsecond\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := FilesContext(ctx, dir, Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("directory scan: expected cancellation, got %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	calls := 0
	err := WalkLinesContext(ctx, file, func(Line) error {
		calls++
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("line scan: expected cancellation after one line, got calls=%d err=%v", calls, err)
	}
}
