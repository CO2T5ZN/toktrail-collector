// Package runlock serializes CLI access to a collector state directory.
// Locks are held by the operating system and released when the process exits,
// including after a crash. The lock file remains in place to keep its inode
// stable across successive owners.
package runlock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var ErrBusy = errors.New("collector state is in use by another process; retry after it exits")

// lockFileName is the fixed lock file name inside a state directory.
// Acquire and Validate must agree on it; it stays unexported so callers
// cannot address the lock file directly.
const lockFileName = ".collector.lock"

type Lock struct{ file *os.File }

func Acquire(dir string) (*Lock, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("collector state directory is required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create collector state directory: %w", err)
	}
	name := filepath.Join(dir, lockFileName)
	if info, err := os.Lstat(name); err == nil {
		if !info.Mode().IsRegular() {
			return nil, errors.New("collector lock must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect collector lock: %w", err)
	}
	file, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open collector lock: %w", err)
	}
	if err = lockFile(file); err != nil {
		file.Close()
		return nil, err
	}
	return &Lock{file: file}, nil
}

func (lock *Lock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	file := lock.file
	lock.file = nil
	unlockErr := unlockFile(file)
	closeErr := file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

// Validate reports whether lock is a live lock on exactly dir's lock
// file. It exists for already-held-lock entry points (callers that run
// work under a lock they acquired themselves) so they can verify the
// handed-over handle before touching any state, WITHOUT probing the
// directory: a probe (attempting a second Acquire and reading ErrBusy)
// cannot distinguish "the caller holds the lock" from "another process
// does", and would let a foreign or already-closed lock pass whenever
// anyone else happens to hold the directory — breaking single-writer
// safety exactly when it matters.
//
// Checks, in order:
//   - the handle is non-nil and not closed: Close nils it, and a copied
//     Lock value whose original was closed fails the handle Stat below
//     with "file already closed";
//   - dir's lock file exists and is the SAME FILE (same inode / file
//     index, via os.SameFile) the handle was acquired on. A lock from a
//     different state directory fails here, and so does a lock whose
//     file was deleted and recreated under it — such a flock serializes
//     against a stale inode and no longer protects dir.
//
// Because Lock values are opaque and can only come from Acquire, and
// Close is the only release path (it drops the handle), a passing
// Validate means the lock was acquired on this directory's lock file and
// has not been released.
//
// Concurrency: the caller must not Close the lock concurrently with
// Validate (or with work performed under the lock); Close is the release
// path and is single-threaded per lock by contract.
func (lock *Lock) Validate(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return errors.New("collector state directory is required")
	}
	if lock == nil || lock.file == nil {
		return errors.New("the collector state lock is not held: the lock is nil or already closed")
	}
	// Stat through the held handle proves it is still open without
	// touching the directory's lock state.
	held, err := lock.file.Stat()
	if err != nil {
		return fmt.Errorf("the collector state lock is not held (its file handle is closed): %w", err)
	}
	current, err := os.Stat(filepath.Join(dir, lockFileName))
	if err != nil {
		return fmt.Errorf("inspect the collector lock of %s: %w", dir, err)
	}
	if !os.SameFile(current, held) {
		return fmt.Errorf("the supplied collector state lock does not belong to %s (a different state directory, or its lock file was replaced)", dir)
	}
	return nil
}
