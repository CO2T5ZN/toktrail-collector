package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toktrail-collector/internal/distribution"
)

// withReportedVersion pins the build's reported version for one test (the test
// binary itself reports "dev").
func withReportedVersion(t *testing.T, v string) {
	t.Helper()
	previous := version
	version = v
	t.Cleanup(func() { version = previous })
}

// signedRelease builds a dist directory with a signed manifest for one version,
// plus the public key PEM, so upgrade paths can be exercised end to end without
// a network.
func signedRelease(t *testing.T, version string) (distDir, pubKeyPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	distDir = t.TempDir()
	manifest := distribution.Manifest{
		Schema:      distribution.ManifestSchema,
		Product:     distribution.ProductName,
		Version:     version,
		GeneratedAt: "2026-11-05T00:00:00Z",
		Artifacts:   []distribution.Artifact{testArtifact(version, currentOS(), currentArch())},
	}
	payload, err := manifest.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(distDir, distribution.ManifestFileName), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, payload)
	if err := os.WriteFile(filepath.Join(distDir, distribution.ManifestSignatureFileName), sig, 0o600); err != nil {
		t.Fatal(err)
	}
	pemText, err := distribution.PublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyPath = filepath.Join(t.TempDir(), "release-public.pem")
	if err := os.WriteFile(pubKeyPath, []byte(pemText), 0o600); err != nil {
		t.Fatal(err)
	}
	return distDir, pubKeyPath
}

// testArtifact builds one well-formed artifact entry (the check path only needs
// the manifest to be valid, not the files to exist).
func testArtifact(version, osName, arch string) distribution.Artifact {
	hash := strings.Repeat("a", 64)
	binary := distribution.CollectorBinaryName
	if osName == "windows" {
		binary += ".exe"
	}
	return distribution.Artifact{
		OS:                    osName,
		Arch:                  arch,
		Binary:                binary,
		BinarySha256:          hash,
		BinarySize:            1024,
		Archive:               distribution.CollectorArchiveName(version, osName, arch),
		ArchiveSha256:         hash,
		ArchiveSize:           1024,
		InstallerBinary:       distribution.InstallerBinaryName(version, osName, arch),
		InstallerBinarySha256: hash,
		InstallerBinarySize:   1024,
	}
}

// A check with a pinned key verifies the manifest and reports the version; it
// must not need the network when a local dist directory is given.
func TestUpgradeCheckVerifiedFromDistDir(t *testing.T) {
	withReportedVersion(t, "v0.5.1")
	distDir, pubKeyPath := signedRelease(t, "v0.6.0")
	var out bytes.Buffer
	err := runUpgrade([]string{"--check", "--dist-dir", distDir, "--pubkey", pubKeyPath}, &out, &out)
	if err != nil {
		t.Fatalf("check failed: %v\n%s", err, out.String())
	}
	text := out.String()
	if !strings.Contains(text, "available: v0.6.0") {
		t.Fatalf("check must report the available version:\n%s", text)
	}
	if !strings.Contains(text, "manifest signature verified") {
		t.Fatalf("check must say the signature was verified with a pinned key:\n%s", text)
	}
	if !strings.Contains(text, "--to v0.6.0") {
		t.Fatalf("check must name the exact upgrade command:\n%s", text)
	}
}

// Without any trust root the check still answers (metadata), but says clearly
// that the version is unverified — and an upgrade refuses outright.
func TestUpgradeCheckWithoutTrustRootIsUnverifiedAndUpgradeRefuses(t *testing.T) {
	distDir, _ := signedRelease(t, "v0.6.0")
	t.Setenv("TOKTRAIL_RELEASE_PUBKEY", "")
	previous := releasePubKeyB64
	releasePubKeyB64 = ""
	t.Cleanup(func() { releasePubKeyB64 = previous })

	var out bytes.Buffer
	if err := runUpgrade([]string{"--check", "--dist-dir", distDir}, &out, &out); err != nil {
		t.Fatalf("check failed: %v\n%s", err, out.String())
	}
	text := out.String()
	if !strings.Contains(text, "UNVERIFIED") {
		t.Fatalf("a check without a trust root must label the version unverified:\n%s", text)
	}

	out.Reset()
	err := runUpgrade([]string{"--to", "v0.6.0", "--dist-dir", distDir, "--install-dir", t.TempDir()}, &out, &out)
	if err == nil {
		t.Fatalf("an upgrade without a trust root must be refused:\n%s", out.String())
	}
	if !strings.Contains(err.Error(), "no pinned public key") {
		t.Fatalf("the refusal must name the missing trust root, got: %v", err)
	}
	if !strings.Contains(err.Error(), "install script with --upgrade") {
		t.Fatalf("the refusal must offer the script alternative, got: %v", err)
	}
}

// The build-pinned key (base64 of the PEM) makes a source-less installation
// able to verify, exactly as a release build would.
func TestUpgradeUsesBuiltInTrustRoot(t *testing.T) {
	distDir, pubKeyPath := signedRelease(t, "v0.6.0")
	pemBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	previous := releasePubKeyB64
	releasePubKeyB64 = base64.StdEncoding.EncodeToString(pemBytes)
	t.Cleanup(func() { releasePubKeyB64 = previous })
	t.Setenv("TOKTRAIL_RELEASE_PUBKEY", "")

	var out bytes.Buffer
	if err := runUpgrade([]string{"--check", "--dist-dir", distDir}, &out, &out); err != nil {
		t.Fatalf("check failed: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "built-in trust root") {
		t.Fatalf("the built-in key must be used and named:\n%s", out.String())
	}
}

// --check without --to resolves the latest tag and validates it strictly.
func TestUpgradeCheckResolvesLatestTag(t *testing.T) {
	distDir, pubKeyPath := signedRelease(t, "v0.6.0")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/lich0821/toktrail-collector/releases/latest" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"tag_name":"v0.6.0"}`))
	}))
	defer server.Close()
	previousBase := releaseLatestAPIBase
	releaseLatestAPIBase = server.URL
	t.Cleanup(func() { releaseLatestAPIBase = previousBase })

	var out bytes.Buffer
	if err := runUpgrade([]string{"--check", "--dist-dir", distDir, "--pubkey", pubKeyPath}, &out, &out); err != nil {
		t.Fatalf("check failed: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "available: v0.6.0") {
		t.Fatalf("the latest tag must be checked against the release:\n%s", out.String())
	}

	// A non-release tag must be refused rather than turned into an install.
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"nightly"}`))
	})
	out.Reset()
	err := runUpgrade([]string{"--check", "--dist-dir", distDir, "--pubkey", pubKeyPath}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "not a release version") {
		t.Fatalf("an invalid latest tag must be refused, got %v", err)
	}
}

// A collector that is not the released binary for its platform must refuse to
// replace itself: upgrading a locally built or modified binary from a release
// is never what the user meant, and silently doing it would destroy their
// build. The escape hatch exists and must be explicit.
func TestUpgradeRefusesToReplaceANonReleaseBinary(t *testing.T) {
	distDir, pubKeyPath := signedRelease(t, "v0.6.0")
	targetDir := t.TempDir()
	target := filepath.Join(targetDir, "toktrail")
	if err := os.WriteFile(target, []byte("#!/bin/sh\necho toktrail v0.5.1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := runUpgrade([]string{"--to", "v0.6.0", "--dist-dir", distDir, "--pubkey", pubKeyPath, "--install-dir", targetDir}, &out, &out)
	if err == nil {
		t.Fatalf("a non-release binary must not replace itself:\n%s", out.String())
	}
	if !strings.Contains(err.Error(), "not the released binary") {
		t.Fatalf("the refusal must explain the identity check, got: %v", err)
	}
	if !strings.Contains(err.Error(), "--skip-self-check") {
		t.Fatalf("the refusal must name the escape hatch, got: %v", err)
	}
	// Nothing was replaced.
	if raw, readErr := os.ReadFile(target); readErr != nil || !bytes.Contains(raw, []byte("v0.5.1")) {
		t.Fatalf("the target binary must be untouched, got %q (err %v)", raw, readErr)
	}
}

// A development build must not be told to run an upgrade it would refuse.
func TestUpgradeCheckExplainsDevelopmentBuilds(t *testing.T) {
	withReportedVersion(t, "dev")
	distDir, pubKeyPath := signedRelease(t, "v0.6.0")
	var out bytes.Buffer
	if err := runUpgrade([]string{"--check", "--dist-dir", distDir, "--pubkey", pubKeyPath}, &out, &out); err != nil {
		t.Fatalf("check failed: %v\n%s", err, out.String())
	}
	text := out.String()
	if !strings.Contains(text, "development build") {
		t.Fatalf("a build without a release version must say so:\n%s", text)
	}
	if strings.Contains(text, "run `toktrail upgrade --to") {
		t.Fatalf("a development build must not be told to upgrade itself:\n%s", text)
	}
}
