package installer

// Checking for a newer release without installing anything.
//
// This is the read-only half of `toktrail upgrade`. It answers "is there a
// newer version, and does my platform have an artifact for it?" and nothing
// more: no download of archives, no replacement, no state change.
//
// Trust: when a pinned public key is supplied the manifest signature is
// verified before its version is believed, and the result says so. Without a
// key the version is reported as UNVERIFIED metadata - useful for a "a newer
// release exists" hint, never as the basis of an install decision.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"toktrail-collector/internal/distribution"
)

// CheckOptions configures a release availability check.
type CheckOptions struct {
	// BaseURL is the release download root (http/https/file).
	BaseURL string
	// DistDir reads the manifest from a local directory instead.
	DistDir string
	// PubKeyPath is the pinned trust root. Empty means the version is
	// reported without signature verification (Verified=false).
	PubKeyPath string
	// OS/Arch override the target platform (tests).
	OS   string
	Arch string
}

// CheckResult reports what a check found.
type CheckResult struct {
	// Version is the manifest's release version.
	Version string
	// Verified is true only when the manifest signature was checked
	// against a pinned key.
	Verified bool
	// HasArtifact reports whether the target platform has an artifact in
	// this release.
	HasArtifact bool
	// Platform is the platform the artifact question was asked for.
	Platform string
	// BinarySHA256 is the released collector binary's hash for Platform,
	// empty when the release has no artifact for it. It lets a caller verify
	// that the binary it is about to replace is the released one.
	BinarySHA256 string
}

// CheckRelease fetches (and, when possible, verifies) the release manifest for
// a base URL or dist directory.
func CheckRelease(opts CheckOptions) (*CheckResult, error) {
	goos := opts.OS
	arch := opts.Arch
	if goos == "" {
		goos = runtime.GOOS
	}
	if arch == "" {
		arch = runtime.GOARCH
	}
	manifestPath := ""
	var manifestBytes []byte
	var err error
	if strings.TrimSpace(opts.DistDir) != "" {
		manifestPath = filepath.Join(opts.DistDir, distribution.ManifestFileName)
		manifestBytes, err = distribution.ReadBoundedFile(manifestPath, distribution.MaxManifestBytes)
		if err != nil {
			return nil, fmt.Errorf("read manifest: %w", err)
		}
	} else {
		base := strings.TrimRight(strings.TrimSpace(opts.BaseURL), "/")
		if base == "" {
			return nil, errors.New("a release base URL (or a local dist directory) is required")
		}
		manifestBytes, err = Fetch(base+"/"+distribution.ManifestFileName, distribution.MaxManifestBytes)
		if err != nil {
			return nil, fmt.Errorf("fetch release manifest: %w", err)
		}
	}

	var manifest *distribution.Manifest
	verified := false
	if strings.TrimSpace(opts.PubKeyPath) != "" {
		pubs, keyErr := distribution.LoadPublicKeysPEM(opts.PubKeyPath)
		if keyErr != nil {
			return nil, fmt.Errorf("trust root: %w", keyErr)
		}
		var sigBytes []byte
		if manifestPath != "" {
			sigBytes, err = distribution.ReadBoundedFile(filepath.Join(filepath.Dir(manifestPath), distribution.ManifestSignatureFileName), distribution.SignatureSize)
		} else {
			sigBytes, err = Fetch(strings.TrimRight(opts.BaseURL, "/")+"/"+distribution.ManifestSignatureFileName, distribution.SignatureSize)
		}
		if err != nil {
			return nil, fmt.Errorf("read manifest signature: %w", err)
		}
		if len(sigBytes) != distribution.SignatureSize {
			return nil, fmt.Errorf("manifest signature: %d bytes, want %d", len(sigBytes), distribution.SignatureSize)
		}
		if err := distribution.VerifyDetachedAny(pubs, manifestBytes, sigBytes); err != nil {
			return nil, fmt.Errorf("signature verification: %w", err)
		}
		verified = true
	}
	manifest, err = distribution.ParseManifest(manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	artifact, artifactErr := manifest.FindArtifact(goos, arch)
	result := &CheckResult{
		Version:     manifest.Version,
		Verified:    verified,
		HasArtifact: artifactErr == nil,
		Platform:    goos + "/" + arch,
	}
	if artifactErr == nil {
		result.BinarySHA256 = artifact.BinarySha256
	}
	return result, nil
}

// DefaultBaseURL is the official download root for one exact version.
func DefaultBaseURL(version string) string {
	return "https://github.com/lich0821/toktrail-collector/releases/download/" + strings.TrimSpace(version)
}

// WriteTempPublicKey materializes an inline PEM trust root so the existing
// verification path (which takes a path) can use it. The caller removes the
// file; it contains only public material.
func WriteTempPublicKey(pemText string) (path string, cleanup func(), err error) {
	pemText = strings.TrimSpace(pemText)
	if pemText == "" {
		return "", nil, errors.New("empty public key")
	}
	file, err := os.CreateTemp("", "toktrail-pub-*.pem")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { _ = os.Remove(file.Name()) }
	if _, err := file.WriteString(pemText + "\n"); err != nil {
		file.Close()
		cleanup()
		return "", nil, err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return file.Name(), cleanup, nil
}
