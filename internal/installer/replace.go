package installer

// Staged multi-file replacement, used when a release carries the Windows
// GUI helper next to the collector binary. The single-file install path
// (every unix release, and helper-less windows releases) keeps using
// atomicInstall in install.go; only helper-carrying installs go through
// this machinery, because two files must move as one unit.
//
// The commit protocol:
//
//  1. STAGE: copy each verified source file into the target directory
//     under a fresh temp name, re-verifying size and SHA-256 while
//     streaming. Nothing in the install directory is touched until every
//     staged copy passed verification.
//  2. BACK UP: copy each existing target to a fresh temp name beside it,
//     so a mid-commit failure can restore the exact old content.
//  3. COMMIT: rename each staged file onto its target (a single atomic
//     rename per file, exactly like the single-file install path). If any
//     rename fails, every already-replaced target is restored from its
//     backup and the temp files are removed, so a handled failure leaves
//     the previous files in place instead of a mix of the new and old
//     release. When a restore itself fails, its backup copy is KEPT and
//     the returned error names its local path, so the old file is never
//     lost and can be repaired manually.
//
// Crash semantics: this is NOT crash-atomic. Each individual rename is
// atomic, but a process crash or power loss between the two renames can
// leave one file new and the other old. The guarantees above cover
// failures the process observes and reports; nothing here survives a hard
// kill mid-commit.
//
// Symlinks and other non-regular files at a target name are rejected
// before anything is staged: links a user placed in the install directory
// are never overwritten.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"toktrail-collector/internal/distribution"
)

// osRename is the rename seam of the multi-file commit path, so tests can
// inject a replacement failure and exercise the rollback.
var osRename = os.Rename

// placement is one staged file about to replace its target.
type placement struct {
	staged string // verified temp copy inside the target directory
	target string // final path inside the target directory
	backup string // copy of the old file ("" when the target did not exist)
	hadOld bool
}

// stageVerifiedFile copies src into the directory of target under a fresh
// temp name, verifying the copy's size and SHA-256 while streaming. The
// staged file holds the exact bytes that will later be renamed onto
// target.
func stageVerifiedFile(src, target, wantSha string, wantSize int64) (string, error) {
	if !hex64.MatchString(wantSha) {
		return "", errors.New("expected staged sha256 is not 64 hex characters")
	}
	if wantSize <= 0 || wantSize > distribution.MaxBinarySize {
		return "", fmt.Errorf("expected staged size %d out of bounds", wantSize)
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".toktrail-install-*")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	if err := copyFileVerified(src, name, executableMode, wantSha, wantSize); err != nil {
		os.Remove(name)
		return "", err
	}
	if err := os.Chmod(name, executableMode); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

// backupExisting copies the current regular file at target to a fresh temp
// name beside it. The backup is a fresh copy (not the live file), so it can
// always be removed again, even while the original executable is running.
func backupExisting(target string) (string, error) {
	info, err := os.Lstat(target)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", target)
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".toktrail-backup-*")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	if err := copyFileMode(target, name, executableMode); err != nil {
		os.Remove(name)
		return "", err
	}
	got, err := os.Stat(name)
	if err != nil {
		os.Remove(name)
		return "", err
	}
	if got.Size() != info.Size() {
		os.Remove(name)
		return "", fmt.Errorf("backup of %s is %d bytes, original is %d", target, got.Size(), info.Size())
	}
	return name, nil
}

// cleanupPlacements removes the staged and backup temp files of a prepare
// phase that did not reach commit.
func cleanupPlacements(placements []placement) {
	for _, p := range placements {
		if p.staged != "" {
			os.Remove(p.staged)
		}
		if p.backup != "" {
			os.Remove(p.backup)
		}
	}
}

// commitPlacements renames every staged file onto its target. On any
// handled failure it rolls the install directory back to the previous
// state: replaced targets are restored from their backups, newly created
// targets are removed, and the temp files are cleaned up. A backup whose
// restore fails is preserved on disk and its path is returned in the
// error, because at that point it is the only remaining copy of the old
// file; deleting it would lose the user's previous version. This is not
// crash-atomic (see the file comment).
func commitPlacements(placements []placement) (err error) {
	placed := 0
	defer func() {
		if err == nil {
			// Success: drop the rollback copies. They are fresh copies,
			// not the live executables, so removal cannot be blocked by a
			// running process; a failure here is a real filesystem
			// problem and must not pass silently.
			for _, p := range placements {
				if p.hadOld {
					if rmErr := os.Remove(p.backup); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
						err = fmt.Errorf("replaced %s but could not remove rollback copy %s: %w (the installation itself succeeded; remove the file manually)", p.target, p.backup, rmErr)
					}
				}
			}
			return
		}
		var problems []string
		// Restore every target that was already replaced. Backups whose
		// restore fails are recorded and never deleted below.
		restoreFailed := make(map[string]bool)
		for i := 0; i < placed; i++ {
			p := placements[i]
			if p.hadOld {
				if rbErr := osRename(p.backup, p.target); rbErr != nil {
					restoreFailed[p.backup] = true
					problems = append(problems, fmt.Sprintf(
						"restore %s from the backup failed: %v (the old file was preserved at %s - recover it manually before retrying)",
						p.target, rbErr, p.backup))
				}
			} else if rmErr := os.Remove(p.target); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				problems = append(problems, fmt.Sprintf("remove newly installed %s: %v", p.target, rmErr))
			}
		}
		// Remove the staged temps and the backups of targets that were
		// never touched (their old files are still in place). Backups
		// whose restore failed are kept.
		for _, p := range placements {
			if rmErr := os.Remove(p.staged); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				problems = append(problems, fmt.Sprintf("remove staged %s: %v", p.staged, rmErr))
			}
			if p.hadOld && !restoreFailed[p.backup] {
				if _, statErr := os.Lstat(p.backup); statErr == nil {
					if rmErr := os.Remove(p.backup); rmErr != nil {
						problems = append(problems, fmt.Sprintf("remove rollback copy %s: %v", p.backup, rmErr))
					}
				}
			}
		}
		if len(problems) > 0 {
			err = fmt.Errorf("%w; rolling back left residues, resolve manually: %s", err, strings.Join(problems, "; "))
		}
	}()
	for i := range placements {
		p := placements[i]
		if err := osRename(p.staged, p.target); err != nil {
			if runtime.GOOS == "windows" {
				// Fail closed with an actionable hint, mirroring the
				// single-file path; the deferred rollback restores every
				// already-replaced target.
				return fmt.Errorf("replace %s: %w (the existing file may be running; stop scheduled toktrail tasks and retry)", p.target, err)
			}
			return fmt.Errorf("replace %s: %w", p.target, err)
		}
		placed++
	}
	return nil
}

// copyFileVerified copies srcPath to dstPath, verifying the byte size and
// SHA-256 of the copy while streaming. It is the staging half of
// verify-then-install: the bytes that will be renamed onto a target are
// checked again after the copy, not only after the archive extraction.
func copyFileVerified(srcPath, dstPath string, mode os.FileMode, wantSha string, wantSize int64) error {
	if wantSize <= 0 || wantSize > distribution.MaxBinarySize {
		return fmt.Errorf("expected size %d out of bounds", wantSize)
	}
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	h := sha256.New()
	buf := make([]byte, 64<<10)
	var total int64
	for {
		n, rerr := in.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > wantSize {
				out.Close()
				return fmt.Errorf("file is larger than expected %d bytes", wantSize)
			}
			if _, werr := out.Write(buf[:n]); werr != nil {
				out.Close()
				return werr
			}
			h.Write(buf[:n])
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			out.Close()
			return rerr
		}
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if total != wantSize {
		return fmt.Errorf("file is %d bytes, expected %d", total, wantSize)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantSha {
		return fmt.Errorf("file sha256 %s, expected %s", got, wantSha)
	}
	return nil
}
