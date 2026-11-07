package winbackground

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// writeLog reads a log file, failing the test on any I/O error.
func readLog(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestRotatingLogAppendsAcrossWritesAndReopens pins the append contract:
// a scheduled run's history must survive across writes and across helper
// processes (each run reopens the same file).
func TestRotatingLogAppendsAcrossWritesAndReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), outLogName)
	l, err := openRotating(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Write([]byte("first line\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Write([]byte("second line\n")); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if got := readLog(t, path); got != "first line\nsecond line\n" {
		t.Fatalf("appended content = %q, want both lines", got)
	}
	// A reopened writer keeps appending instead of truncating history.
	l2, err := openRotating(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l2.Write([]byte("third line\n")); err != nil {
		t.Fatal(err)
	}
	if err := l2.Close(); err != nil {
		t.Fatal(err)
	}
	if got := readLog(t, path); got != "first line\nsecond line\nthird line\n" {
		t.Fatalf("reopened content = %q, want all three lines", got)
	}
}

// TestRotatingLogRotatesAtCapAndKeepsOneGeneration pins the size cap:
// once the active file reaches maxBytes, the next write archives the
// active file to <name>.1 (replacing any older generation) and continues
// in a fresh active file.
func TestRotatingLogRotatesAtCapAndKeepsOneGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), outLogName)
	const max = int64(32)
	const chunk = "12345678" // 8 bytes; the cap is reached after 4 chunks
	l, err := openRotating(path, max)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := l.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	// Writes 1-4 fill the active file to the cap; write 5 rotates first,
	// so the archive holds exactly the first four chunks and the active
	// file holds writes 5 and 6.
	if got := readLog(t, path); got != strings.Repeat(chunk, 2) {
		t.Fatalf("active file after rotation = %q, want the last two chunks", got)
	}
	if got := readLog(t, path+rotatedSuffix); got != strings.Repeat(chunk, 4) {
		t.Fatalf("archived generation = %q, want the first four chunks", got)
	}
}

// TestRotatingLogSecondRotationReplacesGeneration pins the single-
// generation bound: rotating twice must leave the middle window in the
// archive, not both old windows.
func TestRotatingLogSecondRotationReplacesGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), outLogName)
	const max = int64(32)
	l, err := openRotating(path, max)
	if err != nil {
		t.Fatal(err)
	}
	chunks := make([]string, 12)
	for i := range chunks {
		chunks[i] = string(rune('a'+i)) + "2345678" // 8 distinct bytes + filler
	}
	for _, c := range chunks {
		if _, err := l.Write([]byte(c)); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	wantArchive := strings.Join(chunks[4:8], "")
	wantActive := strings.Join(chunks[8:12], "")
	if got := readLog(t, path); got != wantActive {
		t.Fatalf("active file = %q, want %q", got, wantActive)
	}
	if got := readLog(t, path+rotatedSuffix); got != wantArchive {
		t.Fatalf("archived generation = %q, want %q", got, wantArchive)
	}
}

// TestRotatingLogOpenRotatesOversizedExistingFile pins the reopen
// behavior: an existing log already at the cap is archived immediately,
// so a long-lived state directory cannot keep growing a full log.
func TestRotatingLogOpenRotatesOversizedExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), outLogName)
	old := strings.Repeat("x", 100)
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := openRotating(path, 32)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Write([]byte("new run\n")); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if got := readLog(t, path); got != "new run\n" {
		t.Fatalf("active file = %q, want only the new run", got)
	}
	if got := readLog(t, path+rotatedSuffix); got != old {
		t.Fatalf("archived generation = %q, want the oversized previous content", got)
	}
}

// One io.Copy packet may contain many lines; its size must not control rotation.
func TestRotatingLogSplitsLargeWritesAtCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), outLogName)
	log, err := openRotating(path, 32)
	if err != nil {
		t.Fatal(err)
	}
	payload := strings.Repeat("0123456789", 20)
	if n, err := log.Write([]byte(payload)); err != nil || n != len(payload) {
		t.Fatalf("large write: n=%d err=%v", n, err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	active, archive := readLog(t, path), readLog(t, path+rotatedSuffix)
	if len(active) > 32 || len(archive) > 32 {
		t.Fatalf("large write exceeded cap: active=%d archive=%d", len(active), len(archive))
	}
	retained := archive + active
	if retained != payload[len(payload)-len(retained):] {
		t.Fatal("rotation did not retain the newest output bytes in order")
	}
}

func TestRotatingLogBoundsTotalDiskUse(t *testing.T) {
	path := filepath.Join(t.TempDir(), outLogName)
	const max = int64(64)
	const chunkLen = 16
	l, err := openRotating(path, max)
	if err != nil {
		t.Fatal(err)
	}
	chunk := strings.Repeat("z", chunkLen)
	for i := 0; i < 40; i++ { // 640 bytes total through a 64-byte cap
		if _, err := l.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	active := readLog(t, path)
	archive := readLog(t, path+rotatedSuffix)
	if int64(len(active)) > max+chunkLen {
		t.Fatalf("active file retained %d bytes, want at most max+one chunk", len(active))
	}
	if int64(len(archive)) > max+chunkLen {
		t.Fatalf("archive retained %d bytes, want at most max+one chunk", len(archive))
	}
	if total := len(active) + len(archive); total >= 40*chunkLen {
		t.Fatalf("rotation must bound disk use: %d of %d written bytes retained", total, 40*chunkLen)
	}
}

// TestRotatingLogConcurrentWritesAreAtomic pins the mutex contract used
// on Windows, where the child's stderr copier goroutine and the helper's
// own failure notes can write the same stream: every byte must land and
// writes must not interleave inside a line.
func TestRotatingLogConcurrentWritesAreAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), errLogName)
	l, err := openRotating(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	const writers = 8
	const lines = 50
	const lineLen = 32
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			line := strings.Repeat(string(rune('A'+w)), lineLen)
			for i := 0; i < lines; i++ {
				if _, err := l.Write([]byte(line + "\n")); err != nil {
					t.Errorf("concurrent write: %v", err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	got := readLog(t, path)
	if int64(len(got)) != writers*lines*(lineLen+1) {
		t.Fatalf("retained %d bytes, want %d: writes were lost", len(got), writers*lines*(lineLen+1))
	}
	for w := 0; w < writers; w++ {
		letter := string(rune('A' + w))
		if n := strings.Count(got, letter); n != lines*lineLen {
			t.Fatalf("writer %d lost bytes: %d of %d", w, n, lines*lineLen)
		}
	}
}

// TestRotatingLogRejectsInvalidCapAndClosedWrites pins the error
// contract: a non-positive cap fails at open, and writes after Close
// report an error instead of silently dropping data.
func TestRotatingLogRejectsInvalidCapAndClosedWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), outLogName)
	if _, err := openRotating(path, 0); err == nil {
		t.Fatal("openRotating must reject a non-positive size cap")
	}
	l, err := openRotating(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Write([]byte("data\n")); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Write([]byte("after close\n")); err == nil {
		t.Fatal("writes after Close must fail")
	}
}

// TestRotatingLogRejectsNonRegularPaths pins the log hardening: a
// directory (or any non-regular file) in the log slot or the archive
// slot is refused rather than followed or clobbered, so log writes
// cannot be redirected outside the state directory.
func TestRotatingLogRejectsNonRegularPaths(t *testing.T) {
	if _, err := openRotating(t.TempDir(), 1<<20); err == nil {
		t.Fatal("openRotating must reject a directory in the log slot")
	}
	// A regular log at its cap whose archive slot is a directory must
	// refuse to rotate (at open time) instead of clobbering it.
	dir := t.TempDir()
	path := filepath.Join(dir, "periodic.out.log")
	if err := os.WriteFile(path, []byte("xx"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+rotatedSuffix, 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := openRotating(path, 1)
	if err == nil {
		l.Close()
		t.Fatal("rotation into a directory archive slot must fail")
	}
}

// TestRotatingLogRejectsSymlinkedPaths pins the symlink half of the
// hardening: a symlinked log path is refused rather than followed.
func TestRotatingLogRejectsSymlinkedPaths(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "redirected.log")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, outLogName)
	if err := os.Symlink(target, link); err != nil {
		// Windows needs Developer Mode or SeCreateSymbolicLinkPrivilege.
		t.Skipf("symlink creation not permitted: %v", err)
	}
	if _, err := openRotating(link, 1<<20); err == nil {
		t.Fatal("openRotating must reject a symlinked log path")
	}
}
