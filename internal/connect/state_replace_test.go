package connect

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"toktrail-collector/internal/local/statedir"
)

var archiveTestNow = time.Date(2026, 11, 4, 11, 30, 0, 0, time.UTC)

// archiveStateContents moves every entry except the kept names, leaves
// the kept names at their original paths, and reports the archive path.
func TestArchiveStateContentsMovesAllButKeptNames(t *testing.T) {
	stateDir := t.TempDir()
	touch(t, stateDir, "device.json")
	touch(t, stateDir, "outbox.json")
	if err := os.MkdirAll(filepath.Join(stateDir, "batches"), 0o700); err != nil {
		t.Fatal(err)
	}
	touch(t, filepath.Join(stateDir, "batches"), "batch-1.json")
	touch(t, stateDir, stateLockFileName)

	archive, err := archiveStateContents(stateDir, map[string]bool{stateLockFileName: true}, archiveTestNow)
	if err != nil {
		t.Fatal(err)
	}
	wantArchive := filepath.Join(filepath.Dir(stateDir), filepath.Base(stateDir)+".replaced-20261104-113000")
	if archive != wantArchive {
		t.Fatalf("archive path = %q, want %q", archive, wantArchive)
	}
	// Kept names survive at the original path.
	if _, err := os.Stat(filepath.Join(stateDir, stateLockFileName)); err != nil {
		t.Fatalf("the lock file must stay at its original path: %v", err)
	}
	// Everything else moved.
	for _, name := range []string{"device.json", "outbox.json", "batches"} {
		if _, err := os.Stat(filepath.Join(stateDir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s must have left the state directory", name)
		}
		if _, err := os.Stat(filepath.Join(archive, name)); err != nil {
			t.Fatalf("%s must exist in the archive: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(archive, "batches", "batch-1.json")); err != nil {
		t.Fatalf("nested archive content must survive: %v", err)
	}
}

// A timestamp collision appends a numeric suffix instead of sharing or
// overwriting the existing archive.
func TestArchiveStateContentsCollisionSuffix(t *testing.T) {
	parent := t.TempDir()
	stateDir := filepath.Join(parent, "st")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	touch(t, stateDir, "device.json")
	first, err := archiveStateContents(stateDir, nil, archiveTestNow)
	if err != nil {
		t.Fatal(err)
	}
	touch(t, stateDir, "device.json")
	second, err := archiveStateContents(stateDir, nil, archiveTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if second != first+"-1" {
		t.Fatalf("collision must append -1: first=%q second=%q", first, second)
	}
	if _, err := os.Stat(filepath.Join(first, "device.json")); err != nil {
		t.Fatalf("the first archive must keep its content: %v", err)
	}
}

// An empty state directory produces no archive litter and reports no
// path.
func TestArchiveStateContentsEmptyStateLeavesNoLitter(t *testing.T) {
	parent := t.TempDir()
	stateDir := filepath.Join(parent, "st")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	archive, err := archiveStateContents(stateDir, nil, archiveTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if archive != "" {
		t.Fatalf("an empty state must report no archive path, got %q", archive)
	}
	got, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name() != "st" {
		t.Fatalf("no archive directory may remain in the parent, got %d entries", len(got))
	}
}

// The post-bind replacement keeps BOTH the lock file and the freshly
// bound device state at their original paths.
func TestArchiveStateContentsKeepsDeviceStateForRebind(t *testing.T) {
	stateDir := t.TempDir()
	deviceStateName := filepath.Base(statedir.New(stateDir).Path())
	touch(t, stateDir, deviceStateName)
	touch(t, stateDir, "outbox.json")
	touch(t, stateDir, stateLockFileName)

	archive, err := archiveStateContents(stateDir, map[string]bool{stateLockFileName: true, deviceStateName: true}, archiveTestNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{stateLockFileName, deviceStateName} {
		if _, err := os.Stat(filepath.Join(stateDir, name)); err != nil {
			t.Fatalf("%s must stay: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(archive, deviceStateName)); !os.IsNotExist(err) {
		t.Fatalf("the device state must not be archived twice")
	}
	if _, err := os.Stat(filepath.Join(archive, "outbox.json")); err != nil {
		t.Fatalf("the outbox must be archived: %v", err)
	}
}

func touch(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}
