package distribution

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func validManifest(t *testing.T) *Manifest {
	t.Helper()
	bin, _ := time.Now().UTC().MarshalText()
	_ = bin
	return &Manifest{
		Schema:      ManifestSchema,
		Product:     ProductName,
		Version:     "v0.1.0",
		GeneratedAt: "2025-01-02T03:04:05Z",
		Artifacts: []Artifact{
			{
				OS: "darwin", Arch: "arm64",
				Binary: "toktrail", BinarySha256: strings.Repeat("a", 64), BinarySize: 1234,
				Archive: "toktrail-v0.1.0-darwin-arm64.tar.gz", ArchiveSha256: strings.Repeat("b", 64), ArchiveSize: 2345,
				InstallerBinary: "toktrail-release-v0.1.0-darwin-arm64", InstallerBinarySha256: strings.Repeat("c", 64), InstallerBinarySize: 3456,
			},
			{
				OS: "windows", Arch: "amd64",
				Binary: "toktrail.exe", BinarySha256: strings.Repeat("d", 64), BinarySize: 1234,
				Archive: "toktrail-v0.1.0-windows-amd64.zip", ArchiveSha256: strings.Repeat("e", 64), ArchiveSize: 2345,
				InstallerBinary: "toktrail-release-v0.1.0-windows-amd64.exe", InstallerBinarySha256: strings.Repeat("f", 64), InstallerBinarySize: 3456,
			},
		},
	}
}

func marshalManifest(t *testing.T, m *Manifest) []byte {
	t.Helper()
	data, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseManifestValid(t *testing.T) {
	m := validManifest(t)
	if _, err := ParseManifest(marshalManifest(t, m)); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	art, err := m.FindArtifact("darwin", "arm64")
	if err != nil || art.OS != "darwin" {
		t.Fatalf("FindArtifact: %v %v", art, err)
	}
	if _, err := m.FindArtifact("plan9", "arm64"); err == nil {
		t.Error("FindArtifact accepted unsupported platform")
	}
}

// TestParseManifestBackgroundHelper covers the optional Windows GUI helper
// fields: a fully described windows helper parses, the fields are strictly
// all-or-nothing, windows-only, and the entry name is fixed.
func TestParseManifestBackgroundHelper(t *testing.T) {
	withHelper := func(m *Manifest) *Manifest {
		m.Artifacts[1].BackgroundBinary = "toktrail-background.exe"
		m.Artifacts[1].BackgroundBinarySha256 = strings.Repeat("9", 64)
		m.Artifacts[1].BackgroundBinarySize = 4567
		return m
	}
	if _, err := ParseManifest(marshalManifest(t, withHelper(validManifest(t)))); err != nil {
		t.Fatalf("windows artifact with a fully described helper rejected: %v", err)
	}

	mutations := map[string]func(m *Manifest){
		"unix artifact": func(m *Manifest) {
			m.Artifacts[0].BackgroundBinary = "toktrail-background.exe"
			m.Artifacts[0].BackgroundBinarySha256 = strings.Repeat("9", 64)
			m.Artifacts[0].BackgroundBinarySize = 4567
		},
		"only name": func(m *Manifest) { m.Artifacts[1].BackgroundBinary = "toktrail-background.exe" },
		"only sha": func(m *Manifest) {
			m.Artifacts[1].BackgroundBinarySha256 = strings.Repeat("9", 64)
		},
		"only size": func(m *Manifest) {
			m.Artifacts[1].BackgroundBinarySize = 4567
		},
		"name and sha only": func(m *Manifest) {
			m.Artifacts[1].BackgroundBinary = "toktrail-background.exe"
			m.Artifacts[1].BackgroundBinarySha256 = strings.Repeat("9", 64)
		},
		"name and size only": func(m *Manifest) {
			m.Artifacts[1].BackgroundBinary = "toktrail-background.exe"
			m.Artifacts[1].BackgroundBinarySize = 4567
		},
		"sha and size only": func(m *Manifest) {
			m.Artifacts[1].BackgroundBinarySha256 = strings.Repeat("9", 64)
			m.Artifacts[1].BackgroundBinarySize = 4567
		},
		"wrong name": func(m *Manifest) {
			m.Artifacts[1].BackgroundBinary = "helper.exe"
			m.Artifacts[1].BackgroundBinarySha256 = strings.Repeat("9", 64)
			m.Artifacts[1].BackgroundBinarySize = 4567
		},
		"traversal name": func(m *Manifest) {
			m.Artifacts[1].BackgroundBinary = "../../toktrail-background.exe"
			m.Artifacts[1].BackgroundBinarySha256 = strings.Repeat("9", 64)
			m.Artifacts[1].BackgroundBinarySize = 4567
		},
		"bad sha": func(m *Manifest) {
			m.Artifacts[1].BackgroundBinary = "toktrail-background.exe"
			m.Artifacts[1].BackgroundBinarySha256 = "XYZ"
			m.Artifacts[1].BackgroundBinarySize = 4567
		},
		"upper sha": func(m *Manifest) {
			m.Artifacts[1].BackgroundBinary = "toktrail-background.exe"
			m.Artifacts[1].BackgroundBinarySha256 = strings.Repeat("9", 63) + "A"
			m.Artifacts[1].BackgroundBinarySize = 4567
		},
		"zero size": func(m *Manifest) {
			m.Artifacts[1].BackgroundBinary = "toktrail-background.exe"
			m.Artifacts[1].BackgroundBinarySha256 = strings.Repeat("9", 64)
			m.Artifacts[1].BackgroundBinarySize = 0
		},
		"huge size": func(m *Manifest) {
			m.Artifacts[1].BackgroundBinary = "toktrail-background.exe"
			m.Artifacts[1].BackgroundBinarySha256 = strings.Repeat("9", 64)
			m.Artifacts[1].BackgroundBinarySize = MaxBinarySize + 1
		},
	}
	for name, mutate := range mutations {
		m := validManifest(t)
		mutate(m)
		if _, err := ParseManifest(marshalManifest(t, m)); err == nil {
			t.Errorf("helper mutation %q accepted", name)
		}
	}
}

func TestParseManifestRejectsMalformed(t *testing.T) {
	base := validManifest(t)
	good := string(marshalManifest(t, base))

	// Unknown top-level field.
	if _, err := ParseManifest([]byte(strings.Replace(good, `"schema": 1`, `"schema": 1, "extra": true`, 1))); err == nil {
		t.Error("unknown field accepted")
	}
	// Unknown artifact field.
	if _, err := ParseManifest([]byte(strings.Replace(good, `"archiveSize"`, `"archiveSizeX"`, 1))); err == nil {
		t.Error("unknown artifact field accepted")
	}
	// Trailing data.
	if _, err := ParseManifest([]byte(good + "garbage")); err == nil {
		t.Error("trailing data accepted")
	}
	if _, err := ParseManifest([]byte(good + "{}")); err == nil {
		t.Error("trailing JSON object accepted")
	}
	// Truncated.
	if _, err := ParseManifest([]byte(good[:len(good)/2])); err == nil {
		t.Error("truncated JSON accepted")
	}
	// Empty / whitespace.
	if _, err := ParseManifest([]byte("")); err == nil {
		t.Error("empty manifest accepted")
	}
	if _, err := ParseManifest([]byte("   \n ")); err == nil {
		t.Error("whitespace manifest accepted")
	}
	// Oversized.
	if _, err := ParseManifest([]byte(strings.Repeat(" ", MaxManifestBytes+1))); err == nil {
		t.Error("oversized manifest accepted")
	}

	mutations := map[string]func(m *Manifest){
		"schema":        func(m *Manifest) { m.Schema = 2 },
		"product":       func(m *Manifest) { m.Product = "other-product" },
		"version":       func(m *Manifest) { m.Version = "not-semver" },
		"generatedAt":   func(m *Manifest) { m.GeneratedAt = "yesterday" },
		"no artifacts":  func(m *Manifest) { m.Artifacts = nil },
		"bad os":        func(m *Manifest) { m.Artifacts[0].OS = "plan9" },
		"bad arch":      func(m *Manifest) { m.Artifacts[0].Arch = "riscv" },
		"dup platform":  func(m *Manifest) { m.Artifacts[1].OS, m.Artifacts[1].Arch = "darwin", "arm64" },
		"bad binary":    func(m *Manifest) { m.Artifacts[0].Binary = "evil" },
		"bad hash":      func(m *Manifest) { m.Artifacts[0].BinarySha256 = "XYZ" },
		"upper hash":    func(m *Manifest) { m.Artifacts[0].BinarySha256 = strings.Repeat("A", 64) },
		"zero size":     func(m *Manifest) { m.Artifacts[0].BinarySize = 0 },
		"huge size":     func(m *Manifest) { m.Artifacts[0].BinarySize = MaxBinarySize + 1 },
		"traversal":     func(m *Manifest) { m.Artifacts[0].Archive = "../../evil.tar.gz" },
		"abs path":      func(m *Manifest) { m.Artifacts[0].Archive = "/etc/evil.tar.gz" },
		"subdir path":   func(m *Manifest) { m.Artifacts[0].Archive = "sub/dir/evil.tar.gz" },
		"zip for unix":  func(m *Manifest) { m.Artifacts[0].Archive = "toktrail-v0.1.0-darwin-arm64.zip" },
		"targz for win": func(m *Manifest) { m.Artifacts[1].Archive = "toktrail-v0.1.0-windows-amd64.tar.gz" },
		"win binary":    func(m *Manifest) { m.Artifacts[0].Binary = "toktrail.exe" },
		"space in name": func(m *Manifest) { m.Artifacts[0].Archive = "evil name.tar.gz" },
	}
	for name, mutate := range mutations {
		m := validManifest(t)
		mutate(m)
		if _, err := ParseManifest(marshalManifest(t, m)); err == nil {
			t.Errorf("manifest mutation %q accepted", name)
		}
	}
}

func TestParseManifestTooManyArtifacts(t *testing.T) {
	m := validManifest(t)
	m.Artifacts = make([]Artifact, MaxArtifacts+1)
	for i := range m.Artifacts {
		m.Artifacts[i] = Artifact{
			OS: "linux", Arch: "amd64",
			Binary: "toktrail", BinarySha256: strings.Repeat("a", 64), BinarySize: 1,
			Archive: "a.tar.gz", ArchiveSha256: strings.Repeat("b", 64), ArchiveSize: 1,
			InstallerBinary: "i", InstallerBinarySha256: strings.Repeat("c", 64), InstallerBinarySize: 1,
		}
	}
	// Size guard first: this also must fail because of duplicate platforms,
	// but the artifact-count cap is covered by the oversize error.
	if _, err := ParseManifest(marshalManifest(t, m)); err == nil {
		t.Error("oversized artifact list accepted")
	}
}

func TestParseManifestTypeConfusion(t *testing.T) {
	good := string(marshalManifest(t, validManifest(t)))
	if _, err := ParseManifest([]byte(strings.Replace(good, `"binarySize": 1234`, `"binarySize": "1234"`, 1))); err == nil {
		t.Error("string size accepted")
	}
	if _, err := ParseManifest([]byte(strings.Replace(good, `"schema": 1`, `"schema": "1"`, 1))); err == nil {
		t.Error("string schema accepted")
	}
}

func TestManifestJSONFieldNames(t *testing.T) {
	m := validManifest(t)
	data, err := json.Marshal(m.Artifacts[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"os"`, `"arch"`, `"binary"`, `"binarySha256"`, `"binarySize"`,
		`"archive"`, `"archiveSha256"`, `"archiveSize"`,
		`"installerBinary"`, `"installerBinarySha256"`, `"installerBinarySize"`,
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("artifact JSON missing field %s", want)
		}
	}
	// The helper fields marshal with exactly these names, and are omitted
	// entirely from artifacts without a helper so a helper-less manifest
	// stays byte-compatible with the pre-extension schema 1.
	if strings.Contains(string(data), "backgroundBinary") {
		t.Errorf("helper-less artifact must not marshal background fields, got %s", data)
	}
	helperData, err := json.Marshal(withBackgroundHelper(validManifest(t)).Artifacts[1])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"backgroundBinary"`, `"backgroundBinarySha256"`, `"backgroundBinarySize"`,
	} {
		if !strings.Contains(string(helperData), want) {
			t.Errorf("helper artifact JSON missing field %s: %s", want, helperData)
		}
	}
}

// withBackgroundHelper fully describes the Windows GUI helper on the
// manifest's windows artifact (index 1 of validManifest's artifacts).
func withBackgroundHelper(m *Manifest) *Manifest {
	m.Artifacts[1].BackgroundBinary = BackgroundHelperEntryName()
	m.Artifacts[1].BackgroundBinarySha256 = strings.Repeat("9", 64)
	m.Artifacts[1].BackgroundBinarySize = 4567
	return m
}

// TestParseManifestRejectsUnknownBackgroundFields pins the bootstrap
// compatibility property from the other side: a parser that does not know
// the optional helper fields must reject a manifest that carries them,
// exactly like every released installer older than the helper extension.
// Machines running such an installer must first bootstrap the new
// toktrail-release binary (e.g. via the new release's bootstrap script)
// before a helper-carrying release installs or upgrades.
func TestParseManifestRejectsUnknownBackgroundFields(t *testing.T) {
	data := marshalManifest(t, withBackgroundHelper(validManifest(t)))
	if _, err := ParseManifest(data); err != nil {
		t.Fatalf("current parser must accept the helper fields: %v", err)
	}

	// A strict decoder whose artifact struct predates the extension,
	// using the same decoding rules ParseManifest uses.
	type legacyArtifact struct {
		OS                    string `json:"os"`
		Arch                  string `json:"arch"`
		Binary                string `json:"binary"`
		BinarySha256          string `json:"binarySha256"`
		BinarySize            int64  `json:"binarySize"`
		Archive               string `json:"archive"`
		ArchiveSha256         string `json:"archiveSha256"`
		ArchiveSize           int64  `json:"archiveSize"`
		InstallerBinary       string `json:"installerBinary"`
		InstallerBinarySha256 string `json:"installerBinarySha256"`
		InstallerBinarySize   int64  `json:"installerBinarySize"`
	}
	type legacyManifest struct {
		Schema      int              `json:"schema"`
		Product     string           `json:"product"`
		Version     string           `json:"version"`
		GeneratedAt string           `json:"generatedAt"`
		Artifacts   []legacyArtifact `json:"artifacts"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var lm legacyManifest
	if err := dec.Decode(&lm); err == nil {
		t.Fatal("a strict parser without helper support accepted a helper-carrying manifest")
	}

	// The same legacy parser must still accept a helper-less manifest:
	// releases without the helper stay installable everywhere.
	legacyData := marshalManifest(t, validManifest(t))
	dec2 := json.NewDecoder(bytes.NewReader(legacyData))
	dec2.DisallowUnknownFields()
	var lm2 legacyManifest
	if err := dec2.Decode(&lm2); err != nil {
		t.Fatalf("legacy parser must accept helper-less manifest: %v", err)
	}
}
