// Command toktrail-installer verifies and installs toktrail-collector releases.
// It verifies the cryptographic manifest, checks all hashes and platform
// requirements, and atomically places the collector binary.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"toktrail-collector/internal/installer"
)

// version is injected at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `toktrail-installer - verify and install toktrail-collector releases

Usage:
  toktrail-installer install -base-url <download-root> -version <v> -pubkey <pub.pem> -install-dir <dir>
                             [-allow-downgrade] [-no-replace] [-keep-old] [-skip-self-check]
                             (or: -dist-dir <dir> instead of -base-url, for local files)
  toktrail-installer upgrade -base-url <download-root> -version <v> -pubkey <pub.pem>
                             [-install-dir <dir>] [-allow-downgrade] [-keep-old=true] [-skip-self-check]
                             (or: -dist-dir <dir> instead of -base-url, for local files)
  toktrail-installer verify  -manifest <manifest.json> -signature <manifest.json.sig> -pubkey <pub.pem>
                             [-dist-dir <dir>] [-version <v>] [-platform <os>/<arch>]
  toktrail-installer version

Trust model: verification always requires an explicitly pinned public key
(-pubkey). Missing trust root, invalid signature, malformed manifest,
hash/size mismatch, unsupported platform, or version mismatch all abort
before anything is installed. The installer only places release binaries:
it never changes upload consent, collector state, or scheduler
registration, and never contacts the upload (sync) endpoint.

Windows GUI helper: a release may carry toktrail-background.exe inside the
platform archive (manifest fields backgroundBinary/backgroundBinarySha256/
backgroundBinarySize, strictly all-or-nothing, Windows-only, fixed name).
When present, the helper is verified against the signed manifest and
installed or replaced together with toktrail.exe as one unit: both files
are staged and verified first, and a handled failure restores the previous
files instead of leaving a new/old mix. Releases without the helper (all
unix releases, and windows releases predating it) install exactly as
before. Compatibility: the manifest is shared by all platforms, so once
any windows artifact carries the helper fields, the whole manifest is
rejected by every older client on every platform - including older
darwin/linux collectors running their builtin "toktrail upgrade", not just
older Windows installers. Machines running any older client must first
bootstrap the new installer via a helper-carrying release's bootstrap
scripts (install-<version>.sh on unix, install-<version>.ps1 on Windows;
both pin and verify the matching toktrail-release binary) before
installing or upgrading to that release. The strictness is deliberate:
lenient parsing would let an old client silently ignore a helper it
cannot verify.

upgrade replaces only an existing toktrail binary, in place, at its
original path: the directory given with -install-dir, or the first match
on PATH when omitted. It refuses a missing, non-regular or unidentifiable
existing binary, refuses same-version and downgrade targets unless
-allow-downgrade is set, and keeps the previous binary as <binary>.previous
by default (disable with -keep-old=false). A helper-carrying release also
replaces toktrail-background.exe next to the collector through the same
verified pipeline; it never touches scheduled tasks, services or user
state - migrating an existing registration to the new helper is an
explicit step owned by the collector CLI (toktrail service refresh), never
a side effect of an upgrade. There is no "latest" channel:
-version is always an exact version from trusted release notes. There is
no automatic rollback: .previous is an unverified snapshot, and a verified
rollback means stopping scheduled runs and reinstalling the previous signed
release with install -allow-downgrade. When the target is found via PATH,
only that path was upgraded - if a scheduler invokes a different path,
rerun with -install-dir pointing at the scheduler's directory.`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	// If invoked directly with flags (e.g. -version ... -install-dir ...), treat as install.
	if strings.HasPrefix(cmd, "-") {
		cmd = "install"
		args = os.Args[1:]
	}

	var err error
	switch cmd {
	case "install":
		err = runInstall(args)
	case "upgrade":
		err = runUpgrade(args)
	case "verify":
		err = runVerify(args)
	case "version":
		fmt.Printf("toktrail-installer %s\n", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s\n", cmd, usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "toktrail-installer %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func runInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	baseURL := fs.String("base-url", "", "release download/update endpoint root (http/https/file)")
	distDir := fs.String("dist-dir", "", "install from a local dist directory instead of a URL")
	ver := fs.String("version", "", "exact version to install (required)")
	pubkey := fs.String("pubkey", "", "pinned public key PEM (required trust root)")
	installDir := fs.String("install-dir", "", "directory to install the binary into (required)")
	allowDowngrade := fs.Bool("allow-downgrade", false, "allow installing an older version than currently installed")
	noReplace := fs.Bool("no-replace", false, "refuse to replace an existing binary (no-clobber)")
	keepOld := fs.Bool("keep-old", false, "keep the previous binary as <binary>.previous")
	skipSelfCheck := fs.Bool("skip-self-check", false, "skip check that this tool matches the signed manifest (only for locally compiled tools)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	res, err := installer.Install(installer.InstallOptions{
		BaseURL:        *baseURL,
		DistDir:        *distDir,
		Version:        *ver,
		PubKeyPath:     *pubkey,
		InstallDir:     *installDir,
		AllowDowngrade: *allowDowngrade,
		NoReplace:      *noReplace,
		KeepOld:        *keepOld,
		SkipSelfCheck:  *skipSelfCheck,
	})
	if err != nil {
		return err
	}

	action := "installed"
	if res.Replaced {
		action = "replaced"
	}
	fmt.Printf("%s toktrail %s (%s) at %s\n", action, res.Version, res.Platform, res.BinaryPath)
	if res.BackgroundBinaryPath != "" {
		fmt.Printf("installed windows gui helper %s (verified against the signed manifest)\n", res.BackgroundBinaryPath)
	}
	if res.KeptOldPath != "" {
		fmt.Printf("previous binary kept at %s\n", res.KeptOldPath)
	}
	fmt.Println("note: nothing else was changed - no state, no upload consent, no scheduler registration")
	return nil
}

func runUpgrade(args []string) error {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	baseURL := fs.String("base-url", "", "release download/update endpoint root (http/https/file)")
	distDir := fs.String("dist-dir", "", "upgrade from a local dist directory instead of a URL")
	ver := fs.String("version", "", "exact version to upgrade to (required; there is no \"latest\" channel)")
	pubkey := fs.String("pubkey", "", "pinned public key PEM (required trust root)")
	installDir := fs.String("install-dir", "", "directory holding the existing binary (default: discover it on PATH)")
	allowDowngrade := fs.Bool("allow-downgrade", false, "allow upgrading to an older or equal version (reinstall)")
	keepOld := fs.Bool("keep-old", true, "keep the previous binary as <binary>.previous (overwritten on each upgrade)")
	skipSelfCheck := fs.Bool("skip-self-check", false, "skip check that this tool matches the signed manifest (only for locally compiled tools)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	res, err := installer.Upgrade(installer.UpgradeOptions{
		BaseURL:        *baseURL,
		DistDir:        *distDir,
		Version:        *ver,
		PubKeyPath:     *pubkey,
		InstallDir:     *installDir,
		AllowDowngrade: *allowDowngrade,
		KeepOld:        *keepOld,
		SkipSelfCheck:  *skipSelfCheck,
	})
	if err != nil {
		return err
	}

	fmt.Printf("upgraded toktrail %s -> %s (%s) at %s\n", res.FromVersion, res.Version, res.Platform, res.BinaryPath)
	if res.BackgroundBinaryPath != "" {
		fmt.Printf("upgraded windows gui helper %s (verified against the signed manifest)\n", res.BackgroundBinaryPath)
	}
	if res.KeptOldPath != "" {
		fmt.Printf("previous binary kept at %s (unverified copy; to roll back, stop scheduled runs and restore it, or reinstall the previous signed release with install -allow-downgrade)\n", res.KeptOldPath)
	}
	if res.DiscoveredViaPATH {
		fmt.Printf("note: the target was found via PATH; only %s was upgraded - if a scheduler invokes a different path, rerun with -install-dir pointing at the scheduler's directory\n", res.BinaryPath)
	}
	fmt.Println("note: nothing else was changed - no state, grants or outbox, no upload consent, no connect, no scheduler registration")
	if res.BackgroundBinaryPath != "" {
		fmt.Println("note: to migrate an existing background service or scheduled task to the new helper, run the collector's explicit 'toktrail service refresh' command")
	}
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	manifest := fs.String("manifest", "", "path to manifest.json (required)")
	signature := fs.String("signature", "", "path to manifest.json.sig (required)")
	pubkey := fs.String("pubkey", "", "path to pinned public key PEM (required)")
	distDir := fs.String("dist-dir", "", "verify every artifact on disk in this directory against the manifest")
	ver := fs.String("version", "", "require this exact version in the manifest")
	platform := fs.String("platform", "", "require an artifact for os/arch, e.g. darwin/arm64")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *manifest == "" || *signature == "" || *pubkey == "" {
		return fmt.Errorf("-manifest, -signature and -pubkey are required")
	}

	opts := installer.VerifyOptions{
		ManifestPath:    *manifest,
		SignaturePath:   *signature,
		PubKeyPath:      *pubkey,
		DistDir:         *distDir,
		ExpectedVersion: *ver,
	}
	if *platform != "" {
		parts := strings.Split(*platform, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("-platform must be <os>/<arch>, e.g. darwin/arm64")
		}
		opts.OS, opts.Arch = parts[0], parts[1]
	}

	m, err := installer.Verify(opts)
	if err != nil {
		return err
	}

	fmt.Printf("OK: %s %s, %d platform(s)", m.Product, m.Version, len(m.Artifacts))
	if *distDir != "" {
		fmt.Printf(", all artifact files verified against the signed manifest")
	}
	fmt.Println()
	for _, a := range m.Artifacts {
		fmt.Printf("  %s/%s %s\n", a.OS, a.Arch, a.Archive)
	}
	return nil
}
