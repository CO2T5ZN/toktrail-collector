package connect

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// stateLockFileName must stay in sync with the run lock file
// (internal/local/runlock). archiveStateContents deliberately skips it:
// this run holds its flock on that inode at that path, and keeping the
// file in place means every concurrent process keeps contending on the
// SAME lock — no window where two runs hold "the" state lock on
// different inodes.
const stateLockFileName = ".collector.lock"

// stateReplaceNotice is the closed-set confirmation notice the
// state-replacement escape hatch shows before archiving. It names the
// situation and the consequence in fixed wording only: never the
// server/application/subject identifiers the refusal details carry
// (those are server-controlled strings and stay out of every human
// display).
const stateReplaceNotice = "this machine already has TokTrail data bound to a different account or device than this connect link authorizes; replacing it archives the existing local data (nothing is retransmitted to the new authorization, so usage cannot be counted twice) and starts fresh under this link"

// archiveStateContents moves every entry of stateDir EXCEPT the kept
// names into a fresh timestamped sibling directory
// (<stateDir>.replaced-<yyyymmdd-hhmmss>[-N]) and returns its path.
// The kept names survive at their original paths (the run lock file,
// and for a post-bind replacement the freshly bound device state).
//
// Semantics:
//   - same-parent renames only (one filesystem, no copy);
//   - the archive directory is created exclusively (os.Mkdir), with a
//     -N suffix on a timestamp collision, so two replacements never
//     share an archive;
//   - a mid-archive rename failure rolls every already-moved entry back
//     to its original path (best effort) and removes the archive
//     directory, so a failed replacement leaves the state intact;
//   - an empty state directory (nothing to move) removes the just-created
//     archive directory and returns "" — no litter, and the caller can
//     skip reporting an archive path.
func archiveStateContents(stateDir string, keep map[string]bool, at time.Time) (string, error) {
	parent := filepath.Dir(stateDir)
	base := filepath.Base(stateDir)
	if parent == base || base == "." || base == string(filepath.Separator) {
		return "", fmt.Errorf("invalid state directory path")
	}
	stem := filepath.Join(parent, base+".replaced-"+at.Format("20060102-150405"))
	var archive string
	for i := 0; ; i++ {
		candidate := stem
		if i > 0 {
			candidate = fmt.Sprintf("%s-%d", stem, i)
		}
		err := os.Mkdir(candidate, 0o700)
		if err == nil {
			archive = candidate
			break
		}
		if !os.IsExist(err) {
			return "", err
		}
	}
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		_ = os.Remove(archive)
		return "", err
	}
	var moved []string
	rollback := func() {
		for i := len(moved) - 1; i >= 0; i-- {
			_ = os.Rename(moved[i], filepath.Join(stateDir, filepath.Base(moved[i])))
		}
		_ = os.Remove(archive)
	}
	for _, entry := range entries {
		name := entry.Name()
		if keep[name] {
			continue
		}
		src := filepath.Join(stateDir, name)
		dst := filepath.Join(archive, name)
		if err := os.Rename(src, dst); err != nil {
			rollback()
			return "", err
		}
		moved = append(moved, dst)
	}
	if len(moved) == 0 {
		if err := os.Remove(archive); err != nil && !os.IsNotExist(err) {
			return "", err
		}
		return "", nil
	}
	return archive, nil
}
