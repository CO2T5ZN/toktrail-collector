package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"toktrail-collector/internal/distribution"
	"toktrail-collector/internal/installer"
	"toktrail-collector/internal/source/registry"
)

// TestEndToEndRelease exercises the full pipeline against real go builds:
// keygen -> build all 6 platforms via scripts/release.sh -> verify the whole dist
// (manifest, artifacts, and the signed capabilities metadata) -> install via
// the generated bootstrap script (file:// base URL) -> run the installed
// collector. It is slow (12 cross-compiles) and therefore gated behind
// TOKTRAIL_RELEASE_E2E=1.
func TestEndToEndRelease(t *testing.T) {
	if os.Getenv("TOKTRAIL_RELEASE_E2E") != "1" {
		t.Skip("set TOKTRAIL_RELEASE_E2E=1 to run the slow end-to-end release test")
	}
	if runtime.GOOS == "windows" {
		t.Skip("bootstrap script execution test is POSIX-only")
	}

	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	version := "v0.1.0-test.1"

	// 1. Key generation with an explicitly labeled TEST key.
	keyPath := filepath.Join(work, "TEST-release-key.pem")
	priv, pub, err := distribution.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := distribution.WritePrivateKeyPEM(keyPath, priv); err != nil {
		t.Fatal(err)
	}
	pubPEM, err := distribution.PublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	pinPath := filepath.Join(work, "pinned-pub.pem")
	if err := os.WriteFile(pinPath, []byte(pubPEM), 0o644); err != nil {
		t.Fatal(err)
	}

	// 2. Build release via scripts/release.sh
	distRoot := filepath.Join(work, "dist")
	releaseScript := filepath.Join(repoRoot, "scripts", "release.sh")
	buildCmd := exec.Command("sh", releaseScript, "build", version, "--dist", distRoot, "--key", keyPath)
	buildCmd.Dir = repoRoot
	buildCmd.Env = append(os.Environ(), "GOPROXY=off", "GOCACHE="+filepath.Join(repoRoot, ".gocache"))
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("scripts/release.sh failed: %v\n%s", err, out)
	}

	distDir := filepath.Join(distRoot, version)
	manifestPath := filepath.Join(distDir, distribution.ManifestFileName)
	sigPath := filepath.Join(distDir, distribution.ManifestSignatureFileName)

	// 3. Verify the whole dist directory against the pinned key.
	m, err := installer.Verify(installer.VerifyOptions{
		ManifestPath:    manifestPath,
		SignaturePath:   sigPath,
		PubKeyPath:      pinPath,
		DistDir:         distDir,
		ExpectedVersion: version,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(m.Artifacts) != len(distribution.ReleasePlatforms) {
		t.Fatalf("built %d artifacts, want %d", len(m.Artifacts), len(distribution.ReleasePlatforms))
	}

	// 3a. Windows releases must carry the GUI helper: release.sh fails
	// closed when the helper source is missing, so a successful build
	// implies the helper was built, packed and signed.
	for i := range m.Artifacts {
		a := &m.Artifacts[i]
		if a.OS != "windows" {
			if a.BackgroundBinary != "" {
				t.Fatalf("%s/%s must not carry background fields", a.OS, a.Arch)
			}
			continue
		}
		if a.BackgroundBinary != "toktrail-background.exe" {
			t.Fatalf("windows/%s has no background helper in the manifest", a.Arch)
		}
		helperRaw := filepath.Join(distDir, distribution.BackgroundRawBinaryName(version, a.OS, a.Arch))
		sha, size, err := distribution.SHA256File(helperRaw)
		if err != nil {
			t.Fatalf("helper dist file for windows/%s: %v", a.Arch, err)
		}
		if sha != a.BackgroundBinarySha256 || size != a.BackgroundBinarySize {
			t.Fatalf("helper dist file for windows/%s does not match the manifest", a.Arch)
		}
		// The helper must be extractable from the signed archive with the
		// manifest's hash and size.
		out := filepath.Join(t.TempDir(), "toktrail-background.exe")
		if err := installer.ExtractBinaryEntry(filepath.Join(distDir, a.Archive), a.BackgroundBinary, out, a.BackgroundBinarySize, a.BackgroundBinarySha256); err != nil {
			t.Fatalf("extract helper from %s: %v", a.Archive, err)
		}
	}

	// 3b. Verify the signed capabilities metadata shipped with the release:
	// content matches the registry compiled into this same source tree, the
	// raw 64-byte Ed25519 signature verifies against the pinned key, and the
	// document is bound to the release version. This is the same check the
	// release workflow performs via "go run ./tools/release verify-capabilities".
	capsPath := filepath.Join(distDir, CapabilitiesFileName)
	capsSigPath := filepath.Join(distDir, CapabilitiesSignatureFileName)
	caps, err := VerifyCapabilities(VerifyCapabilitiesOptions{
		CapabilitiesPath: capsPath,
		SignaturePath:    capsSigPath,
		PubKeyPath:       pinPath,
		ExpectedVersion:  version,
	})
	if err != nil {
		t.Fatalf("VerifyCapabilities: %v", err)
	}
	specs := registry.SupportedTools()
	if len(caps.Tools) != len(specs) {
		t.Fatalf("capabilities tools length = %d, want %d", len(caps.Tools), len(specs))
	}
	for i, spec := range specs {
		if caps.Tools[i] != spec.Tool {
			t.Errorf("capabilities tools[%d] = %q, want %q", i, caps.Tools[i], spec.Tool)
		}
	}
	// Exercise the CLI subcommand used by the release workflow end to end.
	verifyCmd := exec.Command("go", "run", "./tools/release", "verify-capabilities",
		"-capabilities", capsPath,
		"-signature", capsSigPath,
		"-pubkey", pinPath,
		"-version", version)
	verifyCmd.Dir = repoRoot
	verifyCmd.Env = append(os.Environ(), "GOPROXY=off", "GOCACHE="+filepath.Join(repoRoot, ".gocache"))
	if out, err := verifyCmd.CombinedOutput(); err != nil {
		t.Fatalf("tools/release verify-capabilities failed: %v\n%s", err, out)
	}

	// 4. Install via the generated bootstrap script with a file:// base URL.
	installDir := filepath.Join(work, "install-target")
	scriptPath := filepath.Join(distDir, "install-"+version+".sh")
	cmd := exec.Command("sh", scriptPath, "file://"+distDir, installDir)
	// The generated installer offers to add its directory to the shell profile
	// (defaulting to yes when there is no terminal to ask). A hermetic HOME keeps
	// that write inside the test's work directory instead of the developer's real
	// ~/.zshrc - this is the release manager's own verification run.
	e2eHome := filepath.Join(work, "home")
	if err := os.MkdirAll(e2eHome, 0o700); err != nil {
		t.Fatalf("create sandboxed HOME: %v", err)
	}
	cmd.Env = append(os.Environ(), "HOME="+e2eHome, "TOKTRAIL_HOME="+filepath.Join(e2eHome, "state"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bootstrap script failed: %v\n%s", err, out)
	}

	// 5. The installed collector must run and report the release version.
	installed := filepath.Join(installDir, "toktrail")
	out, err := exec.Command(installed, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("installed toktrail failed: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "toktrail "+version {
		t.Errorf("installed toktrail reports %q, want %q", strings.TrimSpace(string(out)), "toktrail "+version)
	}

	// 6. A second run must refuse to clobber in no-clobber mode via the
	//    underlying installer (the script itself always replaces).
	tool := distribution.InstallerBinaryName(version, runtime.GOOS, runtime.GOARCH)
	toolPath := filepath.Join(distDir, tool)
	if out, err := exec.Command(toolPath, "install",
		"-base-url", "file://"+distDir,
		"-version", version,
		"-pubkey", pinPath,
		"-install-dir", installDir,
		"-no-replace",
	).CombinedOutput(); err == nil {
		t.Fatalf("second install with -no-replace succeeded\n%s", out)
	}

	// 7. In-place upgrade, same version: must fail closed without
	//    -allow-downgrade, leaving the binary untouched.
	upEnv := append(os.Environ(), "PATH="+installDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	upgRefuse := exec.Command(toolPath, "upgrade",
		"-base-url", "file://"+distDir,
		"-version", version,
		"-pubkey", pinPath,
	)
	upgRefuse.Env = upEnv
	if out, err := upgRefuse.CombinedOutput(); err == nil {
		t.Fatalf("same-version upgrade without -allow-downgrade succeeded\n%s", out)
	} else if !strings.Contains(string(out), "already at") {
		t.Fatalf("same-version upgrade should explain the refusal, got: %s", out)
	}

	// 8. In-place upgrade with -allow-downgrade reinstalls at the original
	//    path (PATH discovery), keeps .previous, and the binary still runs.
	upgRun := exec.Command(toolPath, "upgrade",
		"-base-url", "file://"+distDir,
		"-version", version,
		"-pubkey", pinPath,
		"-allow-downgrade",
	)
	upgRun.Env = upEnv
	if out, err := upgRun.CombinedOutput(); err != nil {
		t.Fatalf("upgrade with -allow-downgrade failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(installed + ".previous"); err != nil {
		t.Fatalf("expected the previous binary to be kept: %v", err)
	}
	out, err = exec.Command(installed, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("upgraded toktrail failed: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "toktrail "+version {
		t.Errorf("upgraded toktrail reports %q, want %q", strings.TrimSpace(string(out)), "toktrail "+version)
	}
	prev, err := exec.Command(installed+".previous", "version").CombinedOutput()
	if err != nil {
		t.Fatalf("kept .previous binary failed: %v\n%s", err, prev)
	}
	if strings.TrimSpace(string(prev)) != "toktrail "+version {
		t.Errorf("kept .previous reports %q, want %q", strings.TrimSpace(string(prev)), "toktrail "+version)
	}

	// 9. Bootstrap script --upgrade also fails closed on the same version
	//    and must leave the installed binary untouched.
	scriptUpg := exec.Command("sh", scriptPath, "file://"+distDir, "--upgrade")
	scriptUpg.Env = upEnv
	if out, err := scriptUpg.CombinedOutput(); err == nil {
		t.Fatalf("bootstrap --upgrade on the same version succeeded\n%s", out)
	}
	out, err = exec.Command(installed, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("toktrail failed after refused script upgrade: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "toktrail "+version {
		t.Errorf("toktrail reports %q after refused script upgrade, want %q", strings.TrimSpace(string(out)), "toktrail "+version)
	}
}
