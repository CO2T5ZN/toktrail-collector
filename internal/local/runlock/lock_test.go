package runlock

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestExclusiveLockAndIndependentDirectories(t *testing.T) {
	dir := t.TempDir()
	first, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := Acquire(dir); !errors.Is(err, ErrBusy) {
		if second != nil {
			second.Close()
		}
		t.Fatalf("same directory must be busy: %v", err)
	}
	other, err := Acquire(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	other.Close()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	reopened.Close()
	if _, err := os.Stat(filepath.Join(dir, ".collector.lock")); err != nil {
		t.Fatalf("lock inode must remain after close: %v", err)
	}
}

func TestLockProcessHelper(t *testing.T) {
	mode := os.Getenv("TOKTRAIL_LOCK_HELPER")
	if mode == "" {
		return
	}
	lock, err := Acquire(os.Getenv("TOKTRAIL_LOCK_DIRECTORY"))
	if errors.Is(err, ErrBusy) {
		os.Exit(23)
	}
	if err != nil {
		os.Exit(24)
	}
	_ = lock // deliberately rely on OS process-exit cleanup
	if mode == "hold" {
		os.Stdout.WriteString("locked\n")
		<-time.After(30 * time.Second)
		os.Exit(25)
	}
	os.Exit(0)
}

func lockHelper(t *testing.T, dir, mode string) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestLockProcessHelper$")
	cmd.Env = append(os.Environ(), "TOKTRAIL_LOCK_HELPER="+mode, "TOKTRAIL_LOCK_DIRECTORY="+dir)
	return cmd
}

func TestAnotherProcessCannotEnterAndNormalExitReleasesLock(t *testing.T) {
	dir := t.TempDir()
	lock, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := lockHelper(t, dir, "probe").Run(); err == nil {
		t.Fatal("other process entered locked directory")
	} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 23 {
		t.Fatalf("expected busy exit 23, got %v", err)
	}
	lock.Close()
	if err := lockHelper(t, dir, "probe").Run(); err != nil {
		t.Fatal(err)
	}
	// The child intentionally exited without Close; ownership must be gone.
	reopened, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	reopened.Close()
}

func TestKilledProcessReleasesLock(t *testing.T) {
	dir := t.TempDir()
	cmd := lockHelper(t, dir, "hold")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "locked\n" {
		t.Fatalf("child not ready: %q, %v", line, err)
	}
	if lock, err := Acquire(dir); !errors.Is(err, ErrBusy) {
		if lock != nil {
			lock.Close()
		}
		t.Fatalf("child lock must be busy: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("killed helper unexpectedly succeeded")
	}
	reopened, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	reopened.Close()
}

// TestValidateLiveLock verifies the positive contract: a lock acquired
// for a directory validates against exactly that directory.
func TestValidateLiveLock(t *testing.T) {
	dir := t.TempDir()
	other := t.TempDir()
	lock, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := lock.Validate(dir); err != nil {
		t.Fatalf("a live lock for this directory must validate: %v", err)
	}
	// The same lock must NOT validate against a different directory,
	// even one whose lock file exists.
	otherLock, err := Acquire(other)
	if err != nil {
		t.Fatal(err)
	}
	defer otherLock.Close()
	if err := lock.Validate(other); err == nil {
		t.Fatal("a lock for another directory must not validate")
	}
}

// TestValidateNilLock verifies the fail-closed contract for a nil handle.
func TestValidateNilLock(t *testing.T) {
	var lock *Lock
	if err := lock.Validate(t.TempDir()); err == nil {
		t.Fatal("a nil lock must not validate")
	}
}

// TestValidateClosedLockFailsEvenWhenAnotherHolderOccupies pins the hole
// a lock-contention probe cannot close: after the caller releases its
// lock, Validate must keep failing EVEN WHEN another holder now occupies
// the directory (busy content alone must never read as "the caller holds
// the lock"). A copied Lock value whose original was closed fails the
// same way through its stale file handle.
func TestValidateClosedLockFailsEvenWhenAnotherHolderOccupies(t *testing.T) {
	dir := t.TempDir()
	lock, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	staleCopy := *lock
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	// Another holder now occupies the directory's lock.
	other, err := Acquire(dir)
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	defer other.Close()

	if err := lock.Validate(dir); err == nil {
		t.Fatal("a closed lock must not validate, even with another holder occupying the directory")
	}
	if err := staleCopy.Validate(dir); err == nil {
		t.Fatal("a copied lock value whose original was closed must not validate")
	}
	// The live holder of the same directory still validates.
	if err := other.Validate(dir); err != nil {
		t.Fatalf("the occupying holder must validate: %v", err)
	}
}

// TestValidateReplacedLockFileFails covers the replaced-inode case: when
// the lock file is deleted and recreated while a handle stays open, the
// stale flock no longer serializes against new acquirers, so Validate
// must refuse the handle. (Not runnable on Windows: an open byte-range
// locked file cannot be deleted there.)
func TestValidateReplacedLockFileFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("deleting an open locked file is not possible on Windows")
	}
	dir := t.TempDir()
	lock, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := os.Remove(filepath.Join(dir, ".collector.lock")); err != nil {
		t.Fatal(err)
	}
	// A new acquirer creates a fresh lock file at the same path and
	// locks it; the stale handle's flock is on the unlinked inode.
	fresh, err := Acquire(dir)
	if err != nil {
		t.Fatalf("acquire the replacement lock file: %v", err)
	}
	defer fresh.Close()
	if err := lock.Validate(dir); err == nil {
		t.Fatal("a lock whose file was replaced under it must not validate")
	}
	if err := fresh.Validate(dir); err != nil {
		t.Fatalf("the replacement lock must validate: %v", err)
	}
}
