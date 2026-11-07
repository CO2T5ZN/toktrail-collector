package installer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"toktrail-collector/internal/distribution"
)

// InstallOptions configures a verify-then-install run.
type InstallOptions struct {
	// BaseURL is the release download/update endpoint (http/https/file).
	// It is deliberately unrelated to any toktrail-server upload endpoint.
	BaseURL string
	// DistDir installs from a local dist directory instead of a URL.
	DistDir string
	// Version is the exact version to install; it must match the manifest.
	Version string
	// PubKeyPath is an explicit path to the pinned public key PEM.
	PubKeyPath string
	// InstallDir receives the binary.
	InstallDir string
	// AllowDowngrade permits installing an older version than the
	// currently installed one (refused by default).
	AllowDowngrade bool
	// NoReplace refuses to touch an existing binary (no-clobber mode).
	NoReplace bool
	// KeepOld keeps the previous binary at <target>.previous on replace.
	KeepOld bool
	// SkipSelfCheck disables the check that the running toktrail-release
	// binary matches the signed manifest entry. Only appropriate when
	// running a locally compiled tool against an official release.
	SkipSelfCheck bool
	// OS/Arch override the runtime platform (used by tests).
	OS   string
	Arch string
}

// InstallResult reports a successful installation.
type InstallResult struct {
	Version     string
	Platform    string
	BinaryPath  string
	Replaced    bool
	KeptOldPath string
	// BackgroundBinaryPath is the installed Windows GUI helper
	// (toktrail-background.exe), empty when the release carries no
	// helper. When set, the helper was verified against the signed
	// manifest and replaced together with the collector binary.
	BackgroundBinaryPath string
}

// Install verifies a release end-to-end and installs exactly one file: the
// collector binary. It never reads or writes collector state, upload
// consent, or scheduler registration, and never contacts the upload
// endpoint. Every verification step fails closed.
func Install(opts InstallOptions) (*InstallResult, error) {
	if opts.BaseURL == "" && opts.DistDir == "" {
		return nil, errors.New("either -base-url or -dist-dir is required")
	}
	if opts.BaseURL != "" && opts.DistDir != "" {
		return nil, errors.New("-base-url and -dist-dir are mutually exclusive")
	}
	if opts.Version == "" {
		return nil, errors.New("-version is required (the installer never guesses which release to install)")
	}
	wantVer, err := distribution.ParseVersion(opts.Version)
	if err != nil {
		return nil, fmt.Errorf("-version: %w", err)
	}
	osName, arch := opts.OS, opts.Arch
	if osName == "" {
		osName = runtime.GOOS
	}
	if arch == "" {
		arch = runtime.GOARCH
	}

	// 1. Trust root: an explicit, independently trusted public key.
	pubs, err := distribution.LoadPublicKeysPEM(opts.PubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("trust root: %w", err)
	}

	// 2. Manifest + detached signature, fetched bounded.
	manifestBytes, err := readReleaseFile(opts.DistDir, opts.BaseURL, distribution.ManifestFileName, distribution.MaxManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	sig, err := readReleaseFile(opts.DistDir, opts.BaseURL, distribution.ManifestSignatureFileName, distribution.SignatureSize)
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	if len(sig) != distribution.SignatureSize {
		return nil, fmt.Errorf("signature: %d bytes, want %d", len(sig), distribution.SignatureSize)
	}

	// 3. Signature check before any parsing or file write.
	if err := distribution.VerifyDetachedAny(pubs, manifestBytes, sig); err != nil {
		return nil, fmt.Errorf("signature verification: %w", err)
	}

	// 4. Strict manifest validation.
	m, err := distribution.ParseManifest(manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m.Version != opts.Version {
		return nil, fmt.Errorf("manifest version %s does not match requested version %s", m.Version, opts.Version)
	}

	// 5. Platform check.
	art, err := m.FindArtifact(osName, arch)
	if err != nil {
		return nil, err
	}

	// 6. Self-check: the running installer binary must match the signed
	// manifest, so a swapped tool cannot ride on a pinned key.
	if !opts.SkipSelfCheck {
		selfExe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("locate running binary: %w", err)
		}
		selfSha, _, err := distribution.SHA256File(selfExe)
		if err != nil {
			return nil, fmt.Errorf("hash running binary: %w", err)
		}
		if selfSha != art.InstallerBinarySha256 {
			return nil, fmt.Errorf("running installer binary does not match the signed manifest for %s/%s (use -skip-self-check only when running a locally compiled tool against an official release)", osName, arch)
		}
	}

	// 7. Download the archive with the manifest's exact size bound and
	//    verify its hash before touching the install directory.
	archiveBytes, err := readReleaseFile(opts.DistDir, opts.BaseURL, art.Archive, art.ArchiveSize)
	if err != nil {
		return nil, fmt.Errorf("archive: %w", err)
	}
	if int64(len(archiveBytes)) != art.ArchiveSize {
		return nil, fmt.Errorf("archive: %d bytes, manifest says %d", len(archiveBytes), art.ArchiveSize)
	}
	if got := distribution.SHA256Bytes(archiveBytes); got != art.ArchiveSha256 {
		return nil, fmt.Errorf("archive sha256 %s, manifest says %s", got, art.ArchiveSha256)
	}

	// 8. Extract only the named binary entry, verifying size and hash
	//    while streaming; traversal and symlink entries are rejected.
	tmpDir, err := os.MkdirTemp("", "toktrail-install-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)
	archivePath := filepath.Join(tmpDir, "archive"+distribution.ArchiveExt(art.OS))
	if err := os.WriteFile(archivePath, archiveBytes, 0o600); err != nil {
		return nil, err
	}
	binPath := filepath.Join(tmpDir, art.Binary)
	if err := ExtractBinaryEntry(archivePath, art.Binary, binPath, art.BinarySize, art.BinarySha256); err != nil {
		return nil, fmt.Errorf("extract binary: %w", err)
	}

	// 8b. When the signed manifest describes the Windows GUI helper
	// (strictly all-or-nothing, Windows-only, fixed name - enforced by
	// ParseManifest), extract it from the same archive with its own size
	// and hash checks. The archive validation pass rejects symlink and
	// traversal entries for every member, helper included.
	var helperPath string
	if art.BackgroundBinary != "" {
		helperPath = filepath.Join(tmpDir, art.BackgroundBinary)
		if err := ExtractBinaryEntry(archivePath, art.BackgroundBinary, helperPath, art.BackgroundBinarySize, art.BackgroundBinarySha256); err != nil {
			return nil, fmt.Errorf("extract background helper: %w", err)
		}
	}

	// 9. Install atomically.
	if opts.InstallDir == "" {
		return nil, errors.New("-install-dir is required")
	}
	if err := os.MkdirAll(opts.InstallDir, 0o755); err != nil {
		return nil, fmt.Errorf("create install dir: %w", err)
	}
	target := filepath.Join(opts.InstallDir, art.Binary)
	res := &InstallResult{Version: m.Version, Platform: osName + "/" + arch, BinaryPath: target}

	// A helper-less release (every unix platform, and windows releases
	// predating the helper) keeps the original single-file install path,
	// byte for byte.
	if art.BackgroundBinary == "" {
		if _, err := os.Lstat(target); err == nil {
			if opts.NoReplace {
				return nil, fmt.Errorf("target %s already exists and -no-replace is set (no-clobber mode)", target)
			}
			res.Replaced = true
			// Downgrade protection: ask the installed binary for its version.
			if cur, verr := installedVersion(target); verr == nil {
				if curVer, perr := distribution.ParseVersion(cur); perr == nil {
					if c := distribution.CompareVersions(curVer, wantVer); c > 0 && !opts.AllowDowngrade {
						return nil, fmt.Errorf("refusing to downgrade from installed %s to %s (pass -allow-downgrade to override)", cur, opts.Version)
					}
				}
			}
			if opts.KeepOld {
				old := target + previousBinarySuffix
				if err := keepPrevious(target, old); err != nil {
					return nil, fmt.Errorf("keep old binary: %w", err)
				}
				res.KeptOldPath = old
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("inspect target: %w", err)
		}

		if err := atomicInstall(binPath, target); err != nil {
			return nil, fmt.Errorf("install: %w", err)
		}
		return res, nil
	}

	// 9b. Helper-carrying install (Windows): both executables are staged
	// next to their targets and then replaced together. A handled
	// failure at any point restores the old files; if a restore itself
	// fails, the backup copy is kept and its path is reported in the
	// error. The two renames are not crash-atomic: a hard kill between
	// them can leave one file new and the other old (see replace.go).
	// The collector keeps its downgrade protection and KeepOld
	// semantics; the helper follows the collector's decision (it is
	// never executed for a version probe).
	helperTarget := filepath.Join(opts.InstallDir, art.BackgroundBinary)
	for _, t := range []string{target, helperTarget} {
		if info, lerr := os.Lstat(t); lerr == nil {
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("%s exists and is not a regular file; links placed in the install directory are never overwritten - remove or rename it first", t)
			}
		} else if !errors.Is(lerr, os.ErrNotExist) {
			return nil, fmt.Errorf("inspect target: %w", lerr)
		}
	}
	if opts.NoReplace {
		for _, t := range []string{target, helperTarget} {
			if _, lerr := os.Lstat(t); lerr == nil {
				return nil, fmt.Errorf("target %s already exists and -no-replace is set (no-clobber mode)", t)
			}
		}
	}
	if _, err := os.Lstat(target); err == nil {
		res.Replaced = true
		// Downgrade protection: ask the installed binary for its version.
		if cur, verr := installedVersion(target); verr == nil {
			if curVer, perr := distribution.ParseVersion(cur); perr == nil {
				if c := distribution.CompareVersions(curVer, wantVer); c > 0 && !opts.AllowDowngrade {
					return nil, fmt.Errorf("refusing to downgrade from installed %s to %s (pass -allow-downgrade to override)", cur, opts.Version)
				}
			}
		}
		if opts.KeepOld {
			old := target + previousBinarySuffix
			if err := keepPrevious(target, old); err != nil {
				return nil, fmt.Errorf("keep old binary: %w", err)
			}
			res.KeptOldPath = old
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect target: %w", err)
	}

	if err := installCollectorAndHelper(binPath, helperPath, target, helperTarget, art); err != nil {
		return nil, fmt.Errorf("install: %w", err)
	}
	res.BackgroundBinaryPath = helperTarget
	return res, nil
}

// installCollectorAndHelper places the collector binary and the Windows
// GUI helper as one unit: both files are staged beside their targets
// (re-verified while copying), existing targets are backed up, and the
// staged files are then renamed into place. If any rename fails, every
// already-replaced target is restored from its backup, so a failed install
// leaves the previous files in place instead of a new/old mix.
func installCollectorAndHelper(collectorSrc, helperSrc, collectorTarget, helperTarget string, art *distribution.Artifact) error {
	items := []struct {
		src      string
		target   string
		wantSha  string
		wantSize int64
	}{
		{collectorSrc, collectorTarget, art.BinarySha256, art.BinarySize},
		{helperSrc, helperTarget, art.BackgroundBinarySha256, art.BackgroundBinarySize},
	}
	var placements []placement
	// Stage first: nothing in the install directory is touched until every
	// staged copy passed verification.
	for _, it := range items {
		staged, err := stageVerifiedFile(it.src, it.target, it.wantSha, it.wantSize)
		if err != nil {
			cleanupPlacements(placements)
			return fmt.Errorf("stage %s: %w", filepath.Base(it.target), err)
		}
		placements = append(placements, placement{staged: staged, target: it.target})
	}
	// Back up existing targets so a mid-commit failure can restore them.
	for i := range placements {
		p := &placements[i]
		if _, err := os.Lstat(p.target); err == nil {
			backup, berr := backupExisting(p.target)
			if berr != nil {
				cleanupPlacements(placements)
				return fmt.Errorf("back up %s: %w", p.target, berr)
			}
			p.backup, p.hadOld = backup, true
		} else if !errors.Is(err, os.ErrNotExist) {
			cleanupPlacements(placements)
			return fmt.Errorf("inspect target: %w", err)
		}
	}
	return commitPlacements(placements)
}

// VerifyOptions configures standalone verification of release files.
type VerifyOptions struct {
	ManifestPath    string
	SignaturePath   string
	PubKeyPath      string
	DistDir         string // optional: verify every referenced file on disk
	ExpectedVersion string
	OS              string // optional: require an artifact for this platform
	Arch            string
}

// Verify checks a manifest signature (and optionally every artifact file in
// DistDir). It fails closed on any inconsistency.
func Verify(opts VerifyOptions) (*distribution.Manifest, error) {
	pubs, err := distribution.LoadPublicKeysPEM(opts.PubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("trust root: %w", err)
	}
	manifestBytes, err := distribution.ReadBoundedFile(opts.ManifestPath, distribution.MaxManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	sig, err := distribution.ReadBoundedFile(opts.SignaturePath, distribution.SignatureSize)
	if err != nil {
		return nil, fmt.Errorf("read signature: %w", err)
	}
	if len(sig) != distribution.SignatureSize {
		return nil, fmt.Errorf("signature: %d bytes, want %d", len(sig), distribution.SignatureSize)
	}
	if err := distribution.VerifyDetachedAny(pubs, manifestBytes, sig); err != nil {
		return nil, fmt.Errorf("signature verification: %w", err)
	}
	m, err := distribution.ParseManifest(manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if opts.ExpectedVersion != "" {
		if _, err := distribution.ParseVersion(opts.ExpectedVersion); err != nil {
			return nil, fmt.Errorf("expected version: %w", err)
		}
		if m.Version != opts.ExpectedVersion {
			return nil, fmt.Errorf("manifest version %s does not match expected %s", m.Version, opts.ExpectedVersion)
		}
	}
	if opts.OS != "" || opts.Arch != "" {
		if opts.OS == "" || opts.Arch == "" {
			return nil, errors.New("-platform requires both os and arch")
		}
		if _, err := m.FindArtifact(opts.OS, opts.Arch); err != nil {
			return nil, err
		}
	}
	if opts.DistDir != "" {
		if err := verifyDistFiles(m, opts.DistDir); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func verifyDistFiles(m *distribution.Manifest, distDir string) error {
	type distCheck struct {
		name string
		path string
		sha  string
		size int64
	}
	for i := range m.Artifacts {
		a := &m.Artifacts[i]
		checks := []distCheck{
			{"archive", filepath.Join(distDir, a.Archive), a.ArchiveSha256, a.ArchiveSize},
			{"collector binary", filepath.Join(distDir, distribution.CollectorRawBinaryName(m.Version, a.OS, a.Arch)), a.BinarySha256, a.BinarySize},
			{"installer binary", filepath.Join(distDir, a.InstallerBinary), a.InstallerBinarySha256, a.InstallerBinarySize},
		}
		// A helper-carrying artifact must also ship its versioned helper
		// input; the archive hash above covers the packed copy.
		if a.BackgroundBinary != "" {
			checks = append(checks, distCheck{
				"background helper",
				filepath.Join(distDir, distribution.BackgroundRawBinaryName(m.Version, a.OS, a.Arch)),
				a.BackgroundBinarySha256,
				a.BackgroundBinarySize,
			})
		}
		for _, c := range checks {
			sha, size, err := distribution.SHA256File(c.path)
			if err != nil {
				return fmt.Errorf("verify %s/%s %s: %w", a.OS, a.Arch, c.name, err)
			}
			if size != c.size {
				return fmt.Errorf("verify %s/%s %s: size %d, manifest says %d", a.OS, a.Arch, c.name, size, c.size)
			}
			if sha != c.sha {
				return fmt.Errorf("verify %s/%s %s: sha256 %s, manifest says %s", a.OS, a.Arch, c.name, sha, c.sha)
			}
		}
	}
	return nil
}

func installedVersion(binPath string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, "version")
	// Never flash a console window when the installer runs from a GUI
	// context (e.g. alongside the Windows GUI helper).
	hideConsoleWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "toktrail" && strings.HasPrefix(fields[1], "v") {
			return fields[1], nil
		}
	}
	return "", fmt.Errorf("could not parse version output")
}

func atomicInstall(srcPath, targetPath string) error {
	dir := filepath.Dir(targetPath)
	tmp, err := os.CreateTemp(dir, ".toktrail-install-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmpName)
		}
	}()
	if err := copyFileMode(srcPath, tmpName, executableMode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, executableMode); err != nil {
		return err
	}
	if err := os.Rename(tmpName, targetPath); err != nil {
		if runtime.GOOS == "windows" {
			// Fail closed with an actionable hint; never retry or
			// fall back to a non-atomic replacement.
			return fmt.Errorf("replace %s: %w (the existing binary may be running; stop scheduled toktrail tasks and retry)", targetPath, err)
		}
		return err
	}
	ok = true
	return nil
}

// previousBinarySuffix names the kept copy of the replaced binary.
const previousBinarySuffix = ".previous"

// keepPrevious preserves the current binary at dst (target+".previous") by
// writing a fresh copy and renaming it into place, so a failed or partial
// copy cannot corrupt an existing rollback copy. An existing regular file
// at dst is replaced atomically; anything else must have been rejected by
// the caller.
func keepPrevious(srcPath, dstPath string) error {
	dir := filepath.Dir(dstPath)
	tmp, err := os.CreateTemp(dir, ".toktrail-previous-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmpName)
		}
	}()
	if err := copyFileMode(srcPath, tmpName, executableMode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, executableMode); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dstPath); err != nil {
		if runtime.GOOS == "windows" {
			return fmt.Errorf("replace %s: %w (the previous binary may be running; stop scheduled toktrail tasks and retry)", dstPath, err)
		}
		return err
	}
	ok = true
	return nil
}

func copyFileMode(srcPath, dstPath string, mode os.FileMode) error {
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
