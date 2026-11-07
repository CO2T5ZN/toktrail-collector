package distribution

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

const (
	// ManifestSchema is the only manifest schema this code accepts.
	ManifestSchema = 1
	// ProductName identifies the product a manifest describes.
	ProductName = "toktrail-collector"
	// ManifestFileName is the canonical release manifest filename.
	ManifestFileName = "manifest.json"
	// ManifestSignatureFileName is the detached Ed25519 signature of the manifest.
	ManifestSignatureFileName = "manifest.json.sig"
	// CollectorBinaryName / InstallerBinaryName are the only binary names
	// a manifest may reference, chosen by target OS.
	CollectorBinaryName       = "toktrail"
	InstallerBinaryNamePrefix = "toktrail-release"
	// BackgroundBinaryName is the base name of the optional Windows GUI
	// helper. Inside archives and after installation it always appears as
	// BackgroundBinaryName + ".exe" ("toktrail-background.exe"): the name
	// is fixed by the manifest validator, never negotiated.
	BackgroundBinaryName = "toktrail-background"

	MaxManifestBytes = 1 << 20 // 1 MiB
	MaxArtifacts     = 64
	MaxNameLen       = 128
	// MaxBinarySize bounds any single artifact we will hash or extract,
	// defending against decompression bombs and oversized downloads.
	MaxBinarySize = 1 << 28 // 256 MiB
)

var (
	supportedOS   = map[string]bool{"darwin": true, "linux": true, "windows": true}
	supportedArch = map[string]bool{"amd64": true, "arm64": true}
	// SafeFileNameRegex allows only bare file names: no separators, no "..",
	// no whitespace, bounded length. This is the path-traversal defense
	// for every file name that arrives from a manifest or archive.
	SafeFileNameRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	hex64             = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// IsSafeFileName validates that a file name is a safe, bare file name without
// traversal elements, separators, whitespace, or invalid characters.
func IsSafeFileName(name string) bool {
	return SafeFileNameRegex.MatchString(name) && !strings.Contains(name, "..") && len(name) <= MaxNameLen
}

// Artifact describes the release files for one platform.
type Artifact struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
	// Binary is the collector binary name inside the archive
	// ("toktrail" or "toktrail.exe").
	Binary string `json:"binary"`
	// BinarySha256 / BinarySize describe the extracted binary.
	BinarySha256 string `json:"binarySha256"`
	BinarySize   int64  `json:"binarySize"`
	// Archive is the archive file name (tar.gz on unix, zip on windows).
	Archive       string `json:"archive"`
	ArchiveSha256 string `json:"archiveSha256"`
	ArchiveSize   int64  `json:"archiveSize"`
	// InstallerBinary / InstallerBinarySha256 / InstallerBinarySize
	// describe the standalone toktrail-release binary for this platform,
	// used by the bootstrap install scripts and the installer self-check.
	InstallerBinary       string `json:"installerBinary"`
	InstallerBinarySha256 string `json:"installerBinarySha256"`
	InstallerBinarySize   int64  `json:"installerBinarySize"`
	// BackgroundBinary / BackgroundBinarySha256 / BackgroundBinarySize
	// describe the optional Windows GUI helper (toktrail-background.exe)
	// carried inside the SAME archive as the collector binary, with the
	// fixed entry name BackgroundBinaryName + ".exe". The three fields are
	// strictly all-or-nothing: a helper is either fully described (name,
	// hash and size) or entirely absent, and it may only appear on a
	// windows artifact.
	//
	// BOOTSTRAP / UPGRADE COMPATIBILITY (schema stays 1): these fields are
	// optional and omitted entirely when a release carries no helper, so
	// manifests produced before this extension keep parsing and installing
	// unchanged. The reverse direction does NOT hold: manifests that DO
	// carry the fields are rejected by older clients, whose strict parser
	// (DisallowUnknownFields) fails closed on the unknown backgroundBinary*
	// keys. One manifest describes ALL platforms, so a single windows
	// artifact with helper fields makes the whole document unreadable for
	// every older client on every platform - including older darwin/linux
	// collectors running their builtin `toktrail upgrade`, not just older
	// Windows installers. A helper-carrying release therefore requires
	// clients built from this code or newer on ALL platforms: existing
	// machines must first bootstrap the new installer via that release's
	// bootstrap scripts (install-<version>.sh and install-<version>.ps1,
	// which pin and verify the new toktrail-release binary per platform)
	// before they can install or upgrade to a helper-carrying release.
	// The strictness is deliberate: lenient unknown-field parsing would
	// let an old client silently ignore the helper it cannot verify.
	// Publish helper-carrying releases only together with the matching
	// bootstrap scripts for every platform.
	BackgroundBinary       string `json:"backgroundBinary,omitempty"`
	BackgroundBinarySha256 string `json:"backgroundBinarySha256,omitempty"`
	BackgroundBinarySize   int64  `json:"backgroundBinarySize,omitempty"`
}

// Manifest is the signed release manifest. Field set is closed: unknown
// fields, wrong types, or trailing data are all rejected.
type Manifest struct {
	Schema      int        `json:"schema"`
	Product     string     `json:"product"`
	Version     string     `json:"version"`
	GeneratedAt string     `json:"generatedAt"`
	Artifacts   []Artifact `json:"artifacts"`
}

// ParseManifest strictly parses and validates manifest bytes.
// It fails closed on: oversized input, malformed JSON, unknown fields,
// trailing data, wrong schema/product, invalid version or timestamp,
// duplicate platforms, unsupported platforms, unsafe file names,
// malformed hashes, and non-positive or oversized lengths.
func ParseManifest(data []byte) (*Manifest, error) {
	if int64(len(data)) > MaxManifestBytes {
		return nil, fmt.Errorf("manifest is %d bytes, exceeds limit %d", len(data), MaxManifestBytes)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("manifest is empty")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest JSON: %w", err)
	}
	// Reject trailing content after the first JSON value.
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("manifest has trailing data after JSON object")
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Manifest) validate() error {
	if m.Schema != ManifestSchema {
		return fmt.Errorf("manifest schema %d, want %d", m.Schema, ManifestSchema)
	}
	if m.Product != ProductName {
		return fmt.Errorf("manifest product %q, want %q", m.Product, ProductName)
	}
	if _, err := ParseVersion(m.Version); err != nil {
		return fmt.Errorf("manifest version: %w", err)
	}
	if _, err := time.Parse(time.RFC3339, m.GeneratedAt); err != nil {
		return fmt.Errorf("manifest generatedAt is not RFC3339: %w", err)
	}
	if len(m.Artifacts) == 0 {
		return errors.New("manifest has no artifacts")
	}
	if len(m.Artifacts) > MaxArtifacts {
		return fmt.Errorf("manifest has %d artifacts, exceeds limit %d", len(m.Artifacts), MaxArtifacts)
	}
	seen := make(map[string]bool, len(m.Artifacts))
	for i := range m.Artifacts {
		a := &m.Artifacts[i]
		if err := validateArtifact(m.Version, a); err != nil {
			return fmt.Errorf("artifact[%d] %s/%s: %w", i, a.OS, a.Arch, err)
		}
		key := a.OS + "/" + a.Arch
		if seen[key] {
			return fmt.Errorf("duplicate artifact for %s", key)
		}
		seen[key] = true
	}
	return nil
}

func validateArtifact(version string, a *Artifact) error {
	if !supportedOS[a.OS] {
		return fmt.Errorf("unsupported os %q", a.OS)
	}
	if !supportedArch[a.Arch] {
		return fmt.Errorf("unsupported arch %q", a.Arch)
	}
	wantBinary := CollectorBinaryName
	if a.OS == "windows" {
		wantBinary += ".exe"
	}
	if a.Binary != wantBinary {
		return fmt.Errorf("binary name %q, want %q", a.Binary, wantBinary)
	}
	// The standalone installer file name is fully derived from the
	// versioned dist layout; anything else is rejected.
	wantInstaller := InstallerBinaryName(version, a.OS, a.Arch)
	if a.InstallerBinary != wantInstaller {
		return fmt.Errorf("installerBinary name %q, want %q", a.InstallerBinary, wantInstaller)
	}
	for name, val := range map[string]string{
		"binarySha256":          a.BinarySha256,
		"archiveSha256":         a.ArchiveSha256,
		"installerBinarySha256": a.InstallerBinarySha256,
	} {
		if !hex64.MatchString(val) {
			return fmt.Errorf("%s %q is not 64 lowercase hex characters", name, val)
		}
	}
	for name, val := range map[string]string{
		"archive":         a.Archive,
		"installerBinary": a.InstallerBinary,
	} {
		if !IsSafeFileName(val) {
			return fmt.Errorf("%s %q is not a safe bare file name (path separators, '..', or invalid characters are rejected)", name, val)
		}
	}
	wantSuffix := ".tar.gz"
	if a.OS == "windows" {
		wantSuffix = ".zip"
	}
	if !strings.HasSuffix(a.Archive, wantSuffix) {
		return fmt.Errorf("archive %q must end with %q for os %q", a.Archive, wantSuffix, a.OS)
	}
	for name, val := range map[string]int64{
		"binarySize":          a.BinarySize,
		"archiveSize":         a.ArchiveSize,
		"installerBinarySize": a.InstallerBinarySize,
	} {
		if val <= 0 {
			return fmt.Errorf("%s must be positive, got %d", name, val)
		}
		if val > MaxBinarySize {
			return fmt.Errorf("%s %d exceeds limit %d", name, val, MaxBinarySize)
		}
	}
	// Optional Windows GUI helper: strictly all-or-nothing, Windows-only,
	// fixed entry name. An artifact without the fields keeps the exact
	// pre-extension schema-1 semantics.
	if a.BackgroundBinary == "" && a.BackgroundBinarySha256 == "" && a.BackgroundBinarySize == 0 {
		return nil
	}
	if a.OS != "windows" {
		return fmt.Errorf("backgroundBinary fields are only allowed on windows artifacts (the GUI helper is Windows-only), found on %s", a.OS)
	}
	// The helper entry name inside the archive is fixed, exactly like the
	// collector binary name: anything else is rejected.
	if want := BackgroundBinaryName + ".exe"; a.BackgroundBinary != want {
		return fmt.Errorf("backgroundBinary name %q, want the fixed name %q", a.BackgroundBinary, want)
	}
	if !hex64.MatchString(a.BackgroundBinarySha256) {
		return fmt.Errorf("backgroundBinarySha256 %q is not 64 lowercase hex characters", a.BackgroundBinarySha256)
	}
	if a.BackgroundBinarySize <= 0 {
		return fmt.Errorf("backgroundBinarySize must be positive, got %d", a.BackgroundBinarySize)
	}
	if a.BackgroundBinarySize > MaxBinarySize {
		return fmt.Errorf("backgroundBinarySize %d exceeds limit %d", a.BackgroundBinarySize, MaxBinarySize)
	}
	return nil
}

// FindArtifact returns the artifact for an os/arch pair, or a fail-closed
// error listing the platforms the manifest actually provides.
func (m *Manifest) FindArtifact(osName, arch string) (*Artifact, error) {
	for i := range m.Artifacts {
		a := &m.Artifacts[i]
		if a.OS == osName && a.Arch == arch {
			return a, nil
		}
	}
	var have []string
	for _, a := range m.Artifacts {
		have = append(have, a.OS+"/"+a.Arch)
	}
	return nil, fmt.Errorf("no artifact for platform %s/%s; manifest provides: %s", osName, arch, strings.Join(have, ", "))
}

// Marshal renders the manifest deterministically (no HTML escaping of
// characters like <> in file names is expected, but keep output stable).
func (m *Manifest) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
