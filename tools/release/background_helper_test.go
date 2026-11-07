package main

// Tests for assembling and publishing releases that carry the Windows GUI
// helper (toktrail-background.exe): the helper is packed into the windows
// archives and fully described in the signed manifest, a console-subsystem
// (plain go build) helper is rejected, helper-less fixtures keep assembling
// exactly as before, and a tampered helper is caught by the dist verifier.

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toktrail-collector/internal/distribution"
	"toktrail-collector/internal/installer"
)

// fakePEBytes returns a minimal PE image carrying the given optional-header
// subsystem value (2 = WINDOWS_GUI, 3 = console). It exercises exactly the
// header fields verifyWindowsGUISubsystem parses.
func fakePEBytes(subsystem uint16) []byte {
	buf := make([]byte, 0x200)
	copy(buf, "MZ")
	binary.LittleEndian.PutUint32(buf[0x3c:], 0x80) // e_lfanew
	pe := 0x80
	copy(buf[pe:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(buf[pe+4:], 0x8664) // Machine AMD64
	binary.LittleEndian.PutUint16(buf[pe+20:], 0xf0)  // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(buf[pe+24:], 0x20b) // PE32+ magic
	binary.LittleEndian.PutUint16(buf[pe+24+68:], subsystem)
	return buf
}

// mustReadFile reads a test fixture file or fails the test.
func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// createFakeBackgroundHelpers writes fake GUI-subsystem helper inputs for
// the given platforms into dir.
func createFakeBackgroundHelpers(t *testing.T, dir, version string, platforms []distribution.Platform) {
	t.Helper()
	for _, p := range platforms {
		name := distribution.BackgroundRawBinaryName(version, p.OS, p.Arch)
		if err := os.WriteFile(filepath.Join(dir, name), fakePEBytes(2), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVerifyWindowsGUISubsystem(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	gui := write("gui.exe", fakePEBytes(2))
	if err := verifyWindowsGUISubsystem(gui); err != nil {
		t.Errorf("GUI subsystem rejected: %v", err)
	}
	cui := write("cui.exe", fakePEBytes(3))
	err := verifyWindowsGUISubsystem(cui)
	if err == nil {
		t.Fatal("console subsystem accepted")
	}
	if !strings.Contains(err.Error(), "-H=windowsgui") {
		t.Errorf("error should explain the windowsgui requirement: %v", err)
	}
	if err := verifyWindowsGUISubsystem(write("garbage.exe", []byte("not a pe"))); err == nil {
		t.Fatal("non-PE input accepted")
	}
	if err := verifyWindowsGUISubsystem(write("truncated.exe", fakePEBytes(2)[:100])); err == nil {
		t.Fatal("truncated PE accepted")
	}
}

// TestAssemblePacksBackgroundHelper verifies the unsigned assembly of a
// release whose windows platforms carry the helper: only windows artifacts
// gain the three manifest fields, both entries are extractable from the
// zip with the manifest's hashes, and unix archives stay single-entry.
func TestAssemblePacksBackgroundHelper(t *testing.T) {
	dir := t.TempDir()
	ver := "v0.1.0"
	platforms := distribution.ReleasePlatforms
	createFakePlatformBinaries(t, dir, ver, platforms)
	createFakeBackgroundHelpers(t, dir, ver, []distribution.Platform{
		{OS: "windows", Arch: "amd64"},
		{OS: "windows", Arch: "arm64"},
	})

	if err := runAssemble([]string{"-version", ver, "-dist-dir", dir}); err != nil {
		t.Fatalf("assemble: %v", err)
	}

	m, err := distribution.ParseManifest(mustReadFile(t, filepath.Join(dir, distribution.ManifestFileName)))
	if err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	helperCount := 0
	for i := range m.Artifacts {
		a := &m.Artifacts[i]
		if a.OS == "windows" {
			helperCount++
			if a.BackgroundBinary != "toktrail-background.exe" {
				t.Errorf("windows %s: backgroundBinary = %q", a.Arch, a.BackgroundBinary)
			}
			if len(a.BackgroundBinarySha256) != 64 || a.BackgroundBinarySize != int64(len(fakePEBytes(2))) {
				t.Errorf("windows %s: helper sha/size mismatch: %q %d", a.Arch, a.BackgroundBinarySha256, a.BackgroundBinarySize)
			}
			// Both entries must be extractable with the manifest's values.
			archivePath := filepath.Join(dir, a.Archive)
			for _, entry := range []struct {
				name string
				sha  string
				size int64
			}{
				{a.Binary, a.BinarySha256, a.BinarySize},
				{a.BackgroundBinary, a.BackgroundBinarySha256, a.BackgroundBinarySize},
			} {
				out := filepath.Join(t.TempDir(), entry.name)
				if err := installer.ExtractBinaryEntry(archivePath, entry.name, out, entry.size, entry.sha); err != nil {
					t.Errorf("extract %s from %s: %v", entry.name, a.Archive, err)
				}
			}
		} else {
			if a.BackgroundBinary != "" || a.BackgroundBinarySha256 != "" || a.BackgroundBinarySize != 0 {
				t.Errorf("%s/%s must not carry background fields", a.OS, a.Arch)
			}
		}
	}
	if helperCount != 2 {
		t.Fatalf("expected 2 windows artifacts, got %d", helperCount)
	}
}

// TestAssembleSignedBackgroundHelperChainInstalls is the end-to-end signed
// chain: assemble with a real key, verify the whole dist against the pinned
// public key, and install through the internal installer - both the
// collector and the helper land in the install directory.
func TestAssembleSignedBackgroundHelperChainInstalls(t *testing.T) {
	dir := t.TempDir()
	ver := "v1.2.3"
	createFakePlatformBinaries(t, dir, ver, distribution.ReleasePlatforms)
	createFakeBackgroundHelpers(t, dir, ver, []distribution.Platform{
		{OS: "windows", Arch: "amd64"},
		{OS: "windows", Arch: "arm64"},
	})

	priv, pub, err := distribution.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "priv.pem")
	if err := distribution.WritePrivateKeyPEM(keyPath, priv); err != nil {
		t.Fatal(err)
	}
	pubPEM, err := distribution.PublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(pubPath, []byte(pubPEM), 0o644); err != nil {
		t.Fatal(err)
	}

	// Make the windows/amd64 installer input the running test binary so
	// the installer self-check passes with the real pipeline.
	selfExe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, distribution.InstallerBinaryName(ver, "windows", "amd64")), mustReadFile(t, selfExe), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := runAssemble([]string{"-version", ver, "-dist-dir", dir, "-key", keyPath}); err != nil {
		t.Fatalf("assemble: %v", err)
	}

	if _, err := installer.Verify(installer.VerifyOptions{
		ManifestPath:    filepath.Join(dir, distribution.ManifestFileName),
		SignaturePath:   filepath.Join(dir, distribution.ManifestSignatureFileName),
		PubKeyPath:      pubPath,
		DistDir:         dir,
		ExpectedVersion: ver,
	}); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	installDir := filepath.Join(t.TempDir(), "bin")
	res, err := installer.Install(installer.InstallOptions{
		DistDir:    dir,
		Version:    ver,
		PubKeyPath: pubPath,
		InstallDir: installDir,
		OS:         "windows",
		Arch:       "amd64",
	})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	wantHelper := string(fakePEBytes(2))
	if got := mustReadFile(t, res.BackgroundBinaryPath); string(got) != wantHelper {
		t.Errorf("installed helper content mismatch (%d bytes)", len(got))
	}
	if got := mustReadFile(t, res.BinaryPath); string(got) != "fake collector windows-amd64" {
		t.Errorf("installed collector content mismatch: %q", got)
	}
}

func TestAssembleRejectsConsoleBackgroundHelper(t *testing.T) {
	dir := t.TempDir()
	ver := "v0.1.0"
	createFakePlatformBinaries(t, dir, ver, distribution.ReleasePlatforms)
	// A plain `go build` helper is a console-subsystem executable.
	if err := os.WriteFile(filepath.Join(dir, distribution.BackgroundRawBinaryName(ver, "windows", "amd64")), fakePEBytes(3), 0o755); err != nil {
		t.Fatal(err)
	}
	err := runAssemble([]string{"-version", ver, "-dist-dir", dir})
	if err == nil {
		t.Fatal("console-subsystem helper accepted")
	}
	if !strings.Contains(err.Error(), "-H=windowsgui") {
		t.Errorf("error should name the windowsgui requirement: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, distribution.ManifestFileName)); statErr == nil {
		t.Error("manifest must not be written when the helper is rejected")
	}
}

func TestAssembleRejectsNonPEBackgroundHelper(t *testing.T) {
	dir := t.TempDir()
	ver := "v0.1.0"
	createFakePlatformBinaries(t, dir, ver, distribution.ReleasePlatforms)
	if err := os.WriteFile(filepath.Join(dir, distribution.BackgroundRawBinaryName(ver, "windows", "arm64")), []byte("definitely not an executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := runAssemble([]string{"-version", ver, "-dist-dir", dir}); err == nil {
		t.Fatal("non-PE helper accepted")
	}
}

func TestAssembleRejectsUnixBackgroundHelper(t *testing.T) {
	dir := t.TempDir()
	ver := "v0.1.0"
	createFakePlatformBinaries(t, dir, ver, distribution.ReleasePlatforms)
	if err := os.WriteFile(filepath.Join(dir, distribution.BackgroundRawBinaryName(ver, "darwin", "amd64")), fakePEBytes(2), 0o755); err != nil {
		t.Fatal(err)
	}
	err := runAssemble([]string{"-version", ver, "-dist-dir", dir})
	if err == nil {
		t.Fatal("unix helper input accepted")
	}
	if !strings.Contains(err.Error(), "Windows-only") {
		t.Errorf("error should state the helper is Windows-only: %v", err)
	}
}

// TestAssembleBackgroundHelperTamperRejectedByVerify corrupts the helper
// input after a signed assembly: the standalone dist verifier must reject
// the release before anything is published or installed.
func TestAssembleBackgroundHelperTamperRejectedByVerify(t *testing.T) {
	dir := t.TempDir()
	ver := "v1.2.3"
	createFakePlatformBinaries(t, dir, ver, distribution.ReleasePlatforms)
	createFakeBackgroundHelpers(t, dir, ver, []distribution.Platform{
		{OS: "windows", Arch: "amd64"},
		{OS: "windows", Arch: "arm64"},
	})
	priv, pub, err := distribution.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "priv.pem")
	if err := distribution.WritePrivateKeyPEM(keyPath, priv); err != nil {
		t.Fatal(err)
	}
	pubPEM, err := distribution.PublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(pubPath, []byte(pubPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runAssemble([]string{"-version", ver, "-dist-dir", dir, "-key", keyPath}); err != nil {
		t.Fatalf("assemble: %v", err)
	}

	helperRaw := filepath.Join(dir, distribution.BackgroundRawBinaryName(ver, "windows", "amd64"))
	if err := os.WriteFile(helperRaw, append(fakePEBytes(2), 'X'), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = installer.Verify(installer.VerifyOptions{
		ManifestPath:  filepath.Join(dir, distribution.ManifestFileName),
		SignaturePath: filepath.Join(dir, distribution.ManifestSignatureFileName),
		PubKeyPath:    pubPath,
		DistDir:       dir,
	})
	if err == nil {
		t.Fatal("verify accepted a tampered background helper")
	}
	if !strings.Contains(err.Error(), "background helper") {
		t.Errorf("error should name the background helper: %v", err)
	}
}

// TestReleaseScriptBuildsWindowsBackgroundHelper pins the build
// orchestration contract of scripts/release.sh: the helper is built first
// for windows targets with the windowsgui subsystem and the main.version
// linker variable, under the versioned dist-layout name, and a missing
// helper source fails the windows build instead of silently shipping a
// helper-less release.
func TestReleaseScriptBuildsWindowsBackgroundHelper(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "scripts", "release.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	for _, want := range []string{
		"./cmd/toktrail-background",
		"-H=windowsgui -s -w -X main.version=$version",
		"toktrail-background-$version-$build_os-$build_arch$extension",
		"refusing to build a windows release without the GUI helper",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("scripts/release.sh must contain %q", want)
		}
	}
	// The helper build must be gated on the windows target only.
	helperGate := `if [ "$build_os" = windows ]; then`
	if !strings.Contains(script, helperGate) {
		t.Errorf("scripts/release.sh must gate the helper build on windows targets")
	}
}
