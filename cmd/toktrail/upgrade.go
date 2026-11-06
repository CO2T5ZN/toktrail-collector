package main

// toktrail upgrade: a first-class, self-service upgrade for an existing
// installation.
//
// Why this exists at all: replacing the binary was already possible, but only
// through the bootstrap script or the release tool, so a user had to go back to
// the website to copy a command. Two things were worse than inconvenient:
//
//   - the release tool discovers the existing binary on PATH, and a machine with
//     two installations can end up upgrading the copy nothing runs;
//   - there was no way to ask "am I current?" from the machine itself.
//
// This command fixes both: it targets the directory of the binary that is
// actually running (so `toktrail upgrade` from the scheduled binary upgrades
// that binary), and it answers the version question without changing anything.
//
// Trust is unchanged and never silently weakened: an upgrade is signature
// verified against a pinned public key. The key comes from --pubkey, from
// TOKTRAIL_RELEASE_PUBKEY (a path, or inline PEM text), or from the key pinned
// into this build at release time. With no trust root the command refuses to
// install anything and says how to proceed; it never falls back to "no
// verification".

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"toktrail-collector/internal/distribution"
	"toktrail-collector/internal/installer"
)

// releasePubKeyB64 carries the release public key pinned at build time (base64
// of the PEM text, so the linker flag stays a single token). Release builds set
// it from the same key the bootstrap scripts pin; a source build leaves it
// empty, and `upgrade` then requires an explicit trust root.
var releasePubKeyB64 = ""

const upgradeUsage = `usage: toktrail upgrade [--check] [--to VERSION] [--install-dir DIR] [--pubkey FILE]
                       [--allow-downgrade] [--base-url URL] [--dist-dir DIR]

  --check              report the installed and available versions; changes nothing
  --to VERSION         exact version to upgrade to (no "latest" channel)
  --install-dir DIR    directory holding the binary to replace
                       (default: the directory of the running binary)
  --pubkey FILE        pinned public key PEM that verifies the release
                       (default: $TOKTRAIL_RELEASE_PUBKEY, else the key pinned
                       into this build)
  --allow-downgrade    permit an older or equal target version
  --base-url URL       release download root (default: the official release for
                       the target version)
  --dist-dir DIR       upgrade from a local release directory instead of a URL
  --json               print the result as one JSON object
  --skip-self-check    upgrade even though this collector is not the released
                       binary for this platform (locally built or modified)

An upgrade replaces exactly one file: the collector binary at its original path
(keeping the previous copy as <binary>.previous). It never re-runs connect or
bind, never reads or writes collector state, grants or the outbox, and never
touches scheduler registration.`

func runUpgrade(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	fs.SetOutput(stderr)
	check := fs.Bool("check", false, "report the installed and available versions; change nothing")
	target := fs.String("to", "", "exact version to upgrade to (no \"latest\" channel)")
	installDir := fs.String("install-dir", "", "directory holding the binary to replace (default: the directory of the running binary)")
	pubkey := fs.String("pubkey", "", "pinned public key PEM that verifies the release")
	allowDowngrade := fs.Bool("allow-downgrade", false, "permit an older or equal target version")
	baseURL := fs.String("base-url", "", "release download root (default: the official release for the target version)")
	distDir := fs.String("dist-dir", "", "upgrade from a local release directory instead of a URL")
	jsonOut := fs.Bool("json", false, "print the result as one JSON object")
	skipSelfCheck := fs.Bool("skip-self-check", false, "upgrade even though this collector is not the released binary for this platform (locally built or modified)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return safeDisplayError(errors.New("unexpected argument"), "unexpected argument (see --help)")
	}

	currentVersion := strings.TrimSpace(version)
	currentPlatform := currentOS() + "/" + currentArch()

	// The trust root: explicit flag, environment, or the key pinned into this
	// build. Only public material; a missing root disables installation, never
	// verification.
	keyPath, keyCleanup, anchorSource, keyErr := resolveUpgradeTrustRoot(*pubkey)
	if keyCleanup != nil {
		defer keyCleanup()
	}

	if *check {
		return runUpgradeCheck(upgradeCheckInput{
			current:  currentVersion,
			platform: currentPlatform,
			target:   strings.TrimSpace(*target),
			baseURL:  strings.TrimSpace(*baseURL),
			distDir:  strings.TrimSpace(*distDir),
			keyPath:  keyPath,
			anchor:   anchorSource,
			keyErr:   keyErr,
			jsonOut:  *jsonOut,
		}, stdout)
	}

	if keyErr != nil {
		// The refusal text is fixed and value-free; it names the three ways to
		// supply a trust root without echoing a path.
		return keyErr
	}
	to := strings.TrimSpace(*target)
	if to == "" {
		return errors.New("--to VERSION is required (run `toktrail upgrade --check` first; there is no \"latest\" channel)")
	}
	if _, err := distribution.ParseVersion(to); err != nil {
		return safeDisplayError(err, "--to must be a release version such as v0.6.0")
	}
	if strings.TrimSpace(*distDir) == "" && strings.TrimSpace(*baseURL) == "" {
		*baseURL = installer.DefaultBaseURL(to)
	}

	// Replace the binary that is actually running, never "whatever PATH finds".
	dir := strings.TrimSpace(*installDir)
	if dir == "" {
		exe, err := os.Executable()
		if err != nil {
			return safeDisplayError(err, "could not locate the running binary; pass --install-dir")
		}
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		dir = filepath.Dir(exe)
		if dir == "." || dir == "" {
			return errors.New("cannot determine the running binary's directory; pass --install-dir")
		}
	}

	// Prove this collector is the released binary before it replaces itself.
	// The release tool performs the same check against the installer entry; the
	// collector is not that entry, so it verifies its own bytes against the
	// manifest's collector binary instead. A locally built or modified binary
	// must say so explicitly rather than silently upgrading itself.
	if !*skipSelfCheck {
		manifest, checkErr := installer.CheckRelease(installer.CheckOptions{
			BaseURL:    *baseURL,
			DistDir:    strings.TrimSpace(*distDir),
			PubKeyPath: keyPath,
		})
		if checkErr != nil {
			return safeDisplayError(checkErr, "the release manifest could not be verified; the upgrade was not attempted")
		}
		exe, exeErr := os.Executable()
		if exeErr != nil {
			return safeDisplayError(exeErr, "could not locate the running binary to verify it")
		}
		if resolved, resolveErr := filepath.EvalSymlinks(exe); resolveErr == nil {
			exe = resolved
		}
		installedHash, _, hashErr := distribution.SHA256File(exe)
		if hashErr != nil {
			return safeDisplayError(hashErr, "could not hash the running binary to verify it")
		}
		if !manifest.HasArtifact || manifest.BinarySHA256 == "" {
			return errors.New("this release has no collector binary for this platform")
		}
		if !strings.EqualFold(installedHash, manifest.BinarySHA256) {
			return errors.New("this collector is not the released binary for this platform (built from source or modified), so it will not replace itself; rerun the official install script with --upgrade, or pass --skip-self-check if you really mean it")
		}
	}

	result, err := installer.Upgrade(installer.UpgradeOptions{
		BaseURL:        *baseURL,
		DistDir:        *distDir,
		Version:        to,
		PubKeyPath:     keyPath,
		InstallDir:     dir,
		AllowDowngrade: *allowDowngrade,
		KeepOld:        true,
		// The identity of the running binary was verified above against the
		// collector entry; the installer's own check compares against the
		// release-tool entry, which does not describe this binary.
		SkipSelfCheck: true,
	})
	if err != nil {
		return safeDisplayError(err, "the upgrade could not be completed; the previous binary is still in place")
	}
	if *jsonOut {
		return writeUpgradeJSON(stdout, map[string]any{
			"from":      result.FromVersion,
			"to":        result.Version,
			"platform":  result.Platform,
			"binary":    result.BinaryPath,
			"keptOld":   result.KeptOldPath,
			"trustRoot": anchorSource,
		})
	}
	fmt.Fprintf(stdout, "upgraded toktrail %s -> %s (%s)\n", result.FromVersion, result.Version, result.Platform)
	fmt.Fprintf(stdout, "  binary: %s\n", result.BinaryPath)
	if result.KeptOldPath != "" {
		fmt.Fprintf(stdout, "  previous copy: %s (unverified convenience copy; to roll back, reinstall the previous signed release with upgrade --to %s --allow-downgrade)\n", result.KeptOldPath, result.FromVersion)
	}
	fmt.Fprintf(stdout, "  release verified with the %s trust root\n", anchorSource)
	fmt.Fprintln(stdout, "note: nothing else changed - no state, grants or outbox, no upload consent, no connect, no scheduler registration")
	fmt.Fprintln(stdout, "note: confirm with `toktrail doctor` (the scan-cache line shows the new scan state) and `toktrail periodic --verbose`")
	return nil
}

// upgradeCheckInput is everything a --check run needs.
type upgradeCheckInput struct {
	current  string
	platform string
	target   string
	baseURL  string
	distDir  string
	keyPath  string
	anchor   string
	keyErr   error
	jsonOut  bool
}

func runUpgradeCheck(in upgradeCheckInput, stdout io.Writer) error {
	versionToCheck := in.target
	base := in.baseURL
	distDir := in.distDir
	switch {
	case versionToCheck != "":
		// An explicit target needs no lookup.
		if _, err := distribution.ParseVersion(versionToCheck); err != nil {
			return safeDisplayError(err, "version must be a release version such as v0.6.0")
		}
		if distDir == "" && base == "" {
			base = installer.DefaultBaseURL(versionToCheck)
		}
	case distDir != "" || base != "":
		// A local dist directory or an explicit mirror already names the
		// release: its manifest carries the version, so no external lookup is
		// needed (and none should be attempted).
	default:
		// Nothing names a release yet, so ask where "latest" points. That is
		// metadata only: the version is still reported as unverified until a
		// signed manifest proves it.
		latest, err := resolveLatestReleaseTag()
		if err != nil {
			// The lookup's own text is value-free (no URL, no path), so the
			// composed message stays display-safe while naming the way out.
			return fmt.Errorf("could not determine the latest release version: %v; pass --to VERSION, or --dist-dir/--base-url for an explicit release", err)
		}
		versionToCheck = latest
		base = installer.DefaultBaseURL(versionToCheck)
	}
	result, err := installer.CheckRelease(installer.CheckOptions{
		BaseURL:    base,
		DistDir:    distDir,
		PubKeyPath: in.keyPath,
	})
	if err != nil {
		return safeDisplayError(err, "the release could not be checked (network, mirror or signature problem)")
	}

	if versionToCheck != "" && result.Version != versionToCheck {
		return fmt.Errorf("the release manifest reports %s but %s was requested", result.Version, versionToCheck)
	}
	upToDate := in.current != "" && result.Version == in.current
	if in.jsonOut {
		return writeUpgradeJSON(stdout, map[string]any{
			"current":     in.current,
			"available":   result.Version,
			"verified":    result.Verified,
			"hasArtifact": result.HasArtifact,
			"platform":    result.Platform,
			"upToDate":    upToDate,
			"trustRoot":   anchorLabel(in.anchor, in.keyErr),
		})
	}
	fmt.Fprintf(stdout, "installed: %s (%s)\n", displayVersion(in.current), in.platform)
	fmt.Fprintf(stdout, "available: %s (%s)\n", result.Version, result.Platform)
	if result.Verified {
		fmt.Fprintf(stdout, "  manifest signature verified with the %s trust root\n", in.anchor)
	} else {
		fmt.Fprintln(stdout, "  warning: no pinned public key available, so this version is UNVERIFIED metadata (an upgrade still verifies the release before replacing anything)")
	}
	if !result.HasArtifact {
		fmt.Fprintf(stdout, "  warning: release %s has no artifact for %s; nothing to install on this machine\n", result.Version, result.Platform)
	}
	// A development build has no release identity: it cannot verify itself
	// against a manifest entry, so suggesting "upgrade --to" would send the
	// user into a refusal. Say what is true instead.
	_, versionErr := distribution.ParseVersion(in.current)
	switch {
	case upToDate:
		fmt.Fprintln(stdout, "up to date")
	case in.current == "" || versionErr != nil:
		fmt.Fprintf(stdout, "this is a development build (%s): it reports no release version and cannot replace itself;\ninstall the released binary with the official install script to use `toktrail upgrade`\n", displayVersion(in.current))
	default:
		fmt.Fprintf(stdout, "run `toktrail upgrade --to %s` to upgrade\n", result.Version)
	}
	return nil
}

// resolveUpgradeTrustRoot returns a path to the pinned public key and where it
// came from. A key error is reported as a refusal when an upgrade is attempted.
func resolveUpgradeTrustRoot(explicit string) (path string, cleanup func(), source string, err error) {
	if trimmed := strings.TrimSpace(explicit); trimmed != "" {
		if _, statErr := os.Stat(trimmed); statErr != nil {
			return "", nil, "flag", safeDisplayError(statErr, "--pubkey does not name a readable file")
		}
		return trimmed, nil, "--pubkey", nil
	}
	if fromEnv := strings.TrimSpace(os.Getenv("TOKTRAIL_RELEASE_PUBKEY")); fromEnv != "" {
		if strings.Contains(fromEnv, "-----BEGIN") {
			path, cleanup, err := installer.WriteTempPublicKey(fromEnv)
			return path, cleanup, "TOKTRAIL_RELEASE_PUBKEY", err
		}
		if _, statErr := os.Stat(fromEnv); statErr != nil {
			return "", nil, "TOKTRAIL_RELEASE_PUBKEY", safeDisplayError(statErr, "TOKTRAIL_RELEASE_PUBKEY does not name a readable file")
		}
		return fromEnv, nil, "TOKTRAIL_RELEASE_PUBKEY", nil
	}
	if strings.TrimSpace(releasePubKeyB64) != "" {
		pemText, decodeErr := decodeBase64String(releasePubKeyB64)
		if decodeErr != nil {
			return "", nil, "built-in", fmt.Errorf("built-in release key is corrupt: %w", decodeErr)
		}
		path, cleanup, writeErr := installer.WriteTempPublicKey(pemText)
		return path, cleanup, "built-in", writeErr
	}
	return "", nil, "", errors.New("no pinned public key: this build carries none, so an upgrade cannot be verified. Run the official install script with --upgrade (it pins the key), or pass --pubkey with the public key you trust, or set TOKTRAIL_RELEASE_PUBKEY to that file")
}

func anchorLabel(source string, keyErr error) string {
	if keyErr != nil || source == "" {
		return "none"
	}
	return source
}

func displayVersion(v string) string {
	if strings.TrimSpace(v) == "" {
		return "unknown"
	}
	return v
}
