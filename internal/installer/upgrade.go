package installer

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"toktrail-collector/internal/distribution"
)

// lookPath is the PATH-discovery seam for finding the existing binary.
// It is a package variable so tests can make discovery deterministic.
var lookPath = exec.LookPath

// UpgradeOptions configures an in-place upgrade run. The trust and download
// model is identical to InstallOptions; the differences are discovery and
// stricter preconditions, because an upgrade must only ever replace an
// existing installation at its original path.
type UpgradeOptions struct {
	// BaseURL is the release download/update endpoint (http/https/file),
	// deliberately unrelated to any toktrail-server upload endpoint.
	BaseURL string
	// DistDir upgrades from a local dist directory instead of a URL.
	DistDir string
	// Version is the exact target version; it must match the manifest.
	// There is no "latest" resolution: the version always comes from a
	// trusted source such as release notes.
	Version string
	// PubKeyPath is an explicit path to the pinned public key PEM.
	PubKeyPath string
	// InstallDir optionally names the directory holding the existing
	// binary. When empty, the existing binary is discovered on PATH.
	// Pass the directory the scheduler actually invokes if that differs
	// from what PATH resolves to.
	InstallDir string
	// AllowDowngrade permits installing an older or equal version than
	// the currently installed one (refused by default).
	AllowDowngrade bool
	// KeepOld keeps the previous binary at <target>.previous. The upgrade
	// command enables it by default; the copy is overwritten on each
	// upgrade, forming a one-step rollback chain.
	KeepOld bool
	// SkipSelfCheck disables the check that the running installer binary
	// matches the signed manifest entry. Only appropriate when running a
	// locally compiled tool against an official release.
	SkipSelfCheck bool
	// OS/Arch override the runtime platform (used by tests).
	OS   string
	Arch string
}

// UpgradeResult reports a successful in-place upgrade.
type UpgradeResult struct {
	// FromVersion is the version the replaced binary reported via
	// "toktrail version"; always set on success.
	FromVersion string
	Version     string
	Platform    string
	BinaryPath  string
	KeptOldPath string
	// BackgroundBinaryPath is the upgraded Windows GUI helper
	// (toktrail-background.exe), empty when the release carries no
	// helper. It is placed next to the collector binary through the same
	// verified pipeline.
	BackgroundBinaryPath string
	// DiscoveredViaPATH is true when the upgraded binary was found by
	// PATH lookup rather than an explicit -install-dir. The caller should
	// not claim the whole device was upgraded: a scheduler may invoke a
	// different path than the first match on PATH.
	DiscoveredViaPATH bool
}

// Upgrade performs an explicit, verified, in-place upgrade of an existing
// collector installation. It reuses the exact trust pipeline of Install and
// changes at most three files: the collector binary at its original absolute
// path, the Windows GUI helper (toktrail-background.exe) beside it when the
// release carries one, and <binary>.previous when KeepOld is set.
//
// On Windows a helper-carrying release replaces the collector and the
// helper as one unit: both are staged and verified first, and a failure
// restores the previous files instead of leaving a new/old mix.
//
// It never re-runs connect or bind, never reads or writes collector state
// (grants, cursors, outbox, export journal), never inspects or rewrites
// scheduler registration, and never contacts the upload endpoint. In
// particular it never registers, re-registers or refreshes the background
// helper service or any scheduled task: migrating an existing registration
// to a newly installed helper is an explicit step owned by the collector
// binary's own CLI (service refresh), never a side effect of an upgrade.
// Because the binary path is unchanged, an existing scheduler entry that
// invokes this exact path keeps working without re-registration; when the
// target is discovered via PATH, callers must not assume that path is the
// one the scheduler invokes - with multiple installations or symlinks, pass
// the scheduler's actual directory as -install-dir.
//
// There is no automatic rollback: a failed upgrade leaves the previous
// binary in place (verification happens before replacement), and the kept
// .previous copy is an unverified convenience snapshot, not a promise of a
// safe rollback. A verified rollback means stopping scheduled runs and
// reinstalling the previous signed release with install -allow-downgrade.
func Upgrade(opts UpgradeOptions) (*UpgradeResult, error) {
	// 1. Source options follow the same rules as install.
	if opts.BaseURL == "" && opts.DistDir == "" {
		return nil, errors.New("either -base-url or -dist-dir is required")
	}
	if opts.BaseURL != "" && opts.DistDir != "" {
		return nil, errors.New("-base-url and -dist-dir are mutually exclusive")
	}
	if opts.Version == "" {
		return nil, errors.New("-version is required (there is no \"latest\" channel; take the version from trusted release notes)")
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
	binName := distribution.CollectorBinaryName + distribution.BinaryExt(osName)

	// 2. Discover the existing installation; an upgrade never creates one.
	target, viaPATH, err := discoverExistingBinary(binName, opts.InstallDir)
	if err != nil {
		return nil, err
	}

	// 3. The existing binary must identify itself, so we never replace an
	// unknown file and can enforce version direction.
	cur, err := installedVersion(target)
	if err != nil {
		return nil, fmt.Errorf("cannot determine the version of the existing binary at %s (it must be a toktrail collector binary that supports \"toktrail version\"); refusing to upgrade an unknown file - resolve the conflict manually or use the install command", target)
	}
	curVer, err := distribution.ParseVersion(cur)
	if err != nil {
		return nil, fmt.Errorf("existing binary at %s reports non-semver version %q: %w", target, cur, err)
	}
	switch distribution.CompareVersions(curVer, wantVer) {
	case 0:
		if !opts.AllowDowngrade {
			return nil, fmt.Errorf("already at %s; nothing to upgrade (pass -allow-downgrade to force a reinstall)", opts.Version)
		}
	case 1:
		if !opts.AllowDowngrade {
			return nil, fmt.Errorf("refusing to downgrade from installed %s to %s (pass -allow-downgrade to override)", cur, opts.Version)
		}
	}

	// 4. Conflict pre-check for the rollback copy, so an unusable
	// .previous path fails with a clear error before any download.
	if opts.KeepOld {
		prev := target + previousBinarySuffix
		if info, err := os.Lstat(prev); err == nil {
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("%s exists and is not a regular file; remove or rename it before upgrading", prev)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("inspect %s: %w", prev, err)
		}
	}

	// 5. Delegate to the verified install pipeline. The target file name
	// is the canonical one by construction, so the original absolute path
	// is reused and the atomic replace happens exactly there.
	res, err := Install(InstallOptions{
		BaseURL:        opts.BaseURL,
		DistDir:        opts.DistDir,
		Version:        opts.Version,
		PubKeyPath:     opts.PubKeyPath,
		InstallDir:     filepath.Dir(target),
		AllowDowngrade: opts.AllowDowngrade,
		KeepOld:        opts.KeepOld,
		SkipSelfCheck:  opts.SkipSelfCheck,
		OS:             osName,
		Arch:           arch,
	})
	if err != nil {
		return nil, err
	}
	return &UpgradeResult{
		FromVersion:          cur,
		Version:              res.Version,
		Platform:             res.Platform,
		BinaryPath:           res.BinaryPath,
		KeptOldPath:          res.KeptOldPath,
		BackgroundBinaryPath: res.BackgroundBinaryPath,
		DiscoveredViaPATH:    viaPATH,
	}, nil
}

// discoverExistingBinary locates the binary an upgrade may replace. With
// installDir set it must already contain the canonical binary name.
// Otherwise the binary is looked up on PATH, which only finds the first
// match and may not be what a scheduler invokes. Symlinks are resolved to
// the real file so the original install location is upgraded and links keep
// working; the resolved name must be canonical, otherwise the release would
// install a second file instead of replacing this one.
func discoverExistingBinary(binName, installDir string) (string, bool, error) {
	var found string
	viaPATH := false
	if installDir != "" {
		found = filepath.Join(installDir, binName)
	} else {
		p, err := lookPath(binName)
		if err != nil {
			return "", false, fmt.Errorf("no existing %s binary found on PATH; an upgrade only replaces an existing installation (use the install command for a fresh install, or pass -install-dir with the directory your scheduler actually invokes)", binName)
		}
		found = p
		viaPATH = true
	}
	if _, err := os.Lstat(found); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, fmt.Errorf("no existing %s binary at %s; an upgrade only replaces an existing installation (use the install command for a fresh install)", binName, found)
		}
		return "", false, fmt.Errorf("inspect existing binary: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(found)
	if err != nil {
		return "", false, fmt.Errorf("resolve existing binary path %s: %w", found, err)
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return "", false, fmt.Errorf("resolve existing binary path %s: %w", found, err)
	}
	if filepath.Base(abs) != binName {
		return "", false, fmt.Errorf("existing binary resolves to %s, whose file name is not the canonical %q the release installs; refusing to create a second file - resolve the conflict manually", abs, binName)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", false, fmt.Errorf("inspect existing binary: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", false, fmt.Errorf("existing path %s is not a regular file; refusing to upgrade", abs)
	}
	return abs, viaPATH, nil
}
