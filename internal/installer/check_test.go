package installer

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toktrail-collector/internal/distribution"
)

// releaseFixture writes a signed manifest (plus its public key) into a temp
// dist directory and returns the directory and key path.
func releaseFixture(t *testing.T, version string, withArtifactFor [2]string) (distDir, pubKeyPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifact := distribution.Artifact{
		OS:                    withArtifactFor[0],
		Arch:                  withArtifactFor[1],
		Binary:                distribution.CollectorBinaryName,
		BinarySha256:          strings.Repeat("b", 64),
		BinarySize:            2048,
		Archive:               distribution.CollectorArchiveName(version, withArtifactFor[0], withArtifactFor[1]),
		ArchiveSha256:         strings.Repeat("a", 64),
		ArchiveSize:           2048,
		InstallerBinary:       distribution.InstallerBinaryName(version, withArtifactFor[0], withArtifactFor[1]),
		InstallerBinarySha256: strings.Repeat("c", 64),
		InstallerBinarySize:   2048,
	}
	manifest := distribution.Manifest{
		Schema:      distribution.ManifestSchema,
		Product:     distribution.ProductName,
		Version:     version,
		GeneratedAt: "2026-11-05T00:00:00Z",
		Artifacts:   []distribution.Artifact{artifact},
	}
	payload, err := manifest.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	distDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(distDir, distribution.ManifestFileName), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(distDir, distribution.ManifestSignatureFileName), ed25519.Sign(priv, payload), 0o600); err != nil {
		t.Fatal(err)
	}
	pemText, err := distribution.PublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyPath = filepath.Join(t.TempDir(), "pub.pem")
	if err := os.WriteFile(pubKeyPath, []byte(pemText), 0o600); err != nil {
		t.Fatal(err)
	}
	return distDir, pubKeyPath
}

func TestCheckReleaseVerifiesWithPinnedKey(t *testing.T) {
	distDir, pubKeyPath := releaseFixture(t, "v0.6.0", [2]string{"darwin", "arm64"})
	result, err := CheckRelease(CheckOptions{DistDir: distDir, PubKeyPath: pubKeyPath, OS: "darwin", Arch: "arm64"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Verified || result.Version != "v0.6.0" || !result.HasArtifact {
		t.Fatalf("result = %+v, want a verified v0.6.0 with an artifact", result)
	}
	if result.BinarySHA256 != strings.Repeat("b", 64) {
		t.Fatalf("the result must carry the released binary hash, got %q", result.BinarySHA256)
	}
}

// Without a key the version is reported but explicitly not verified: callers
// must be able to tell the two apart.
func TestCheckReleaseWithoutKeyIsUnverified(t *testing.T) {
	distDir, _ := releaseFixture(t, "v0.6.0", [2]string{"linux", "amd64"})
	result, err := CheckRelease(CheckOptions{DistDir: distDir, OS: "linux", Arch: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verified {
		t.Fatalf("a check without a trust root must not claim verification")
	}
	if result.Version != "v0.6.0" {
		t.Fatalf("version = %q", result.Version)
	}
}

// A release without an artifact for the queried platform is reported, not
// silently treated as installable.
func TestCheckReleaseMissingArtifact(t *testing.T) {
	distDir, pubKeyPath := releaseFixture(t, "v0.6.0", [2]string{"darwin", "arm64"})
	result, err := CheckRelease(CheckOptions{DistDir: distDir, PubKeyPath: pubKeyPath, OS: "linux", Arch: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if result.HasArtifact {
		t.Fatalf("linux/amd64 has no artifact in this release, got %+v", result)
	}
}

// A manifest signed by another key must fail closed.
func TestCheckReleaseRejectsForeignSignature(t *testing.T) {
	distDir, _ := releaseFixture(t, "v0.6.0", [2]string{"darwin", "arm64"})
	otherDir, otherKey := releaseFixture(t, "v0.6.1", [2]string{"darwin", "arm64"})
	_ = otherDir
	if _, err := CheckRelease(CheckOptions{DistDir: distDir, PubKeyPath: otherKey, OS: "darwin", Arch: "arm64"}); err == nil {
		t.Fatal("a manifest signed by a different key must be rejected")
	}
}

// A mirror URL carrying a query string must not be hand-joined: the check has to
// resolve files exactly like the install does, or it silently reads a different
// path than the one the installer would use.
func TestCheckReleaseRejectsAQueryStringBaseURL(t *testing.T) {
	distDir, _ := releaseFixture(t, "v0.6.0", [2]string{"darwin", "arm64"})
	if _, err := CheckRelease(CheckOptions{BaseURL: "https://example.invalid/releases?token=1", OS: "darwin", Arch: "arm64"}); err == nil {
		t.Fatal("a base URL with a query string must be refused rather than mis-joined")
	}
	// The dist-directory path still works.
	if _, err := CheckRelease(CheckOptions{DistDir: distDir, OS: "darwin", Arch: "arm64"}); err != nil {
		t.Fatalf("dist-dir check failed: %v", err)
	}
}
