package installer

// Tests for helper-carrying (Windows) installs: the collector binary and
// the GUI helper are verified, staged and replaced as one unit, a failure
// rolls the install directory back to the old files, and links in the
// install directory are never overwritten. Helper-less manifests keep the
// original single-file behavior.

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/distribution"
)

// newFakeDistWindows builds a fake signed dist for windows/amd64. When
// helperContent is non-empty the archive carries the GUI helper
// (toktrail-background.exe) and the manifest fully describes it; otherwise
// the dist has the exact pre-extension helper-less shape.
func newFakeDistWindows(t *testing.T, version, binContent, helperContent string) *fakeDist {
	t.Helper()
	dir := t.TempDir()
	fd := &fakeDist{version: version, distDir: dir, versionDir: filepath.Join(dir, version), binContent: binContent}
	if err := os.MkdirAll(fd.versionDir, 0o755); err != nil {
		t.Fatal(err)
	}

	priv, pub, err := distribution.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fd.priv = priv
	pubPEM, err := distribution.PublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	fd.pubPath = filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(fd.pubPath, []byte(pubPEM), 0o644); err != nil {
		t.Fatal(err)
	}

	const osName, arch = "windows", "amd64"
	const ext = ".exe"
	binPath := filepath.Join(fd.versionDir, "toktrail"+ext)
	if err := os.WriteFile(binPath, []byte(fd.binContent), 0o755); err != nil {
		t.Fatal(err)
	}
	fd.binSha, fd.binSize, err = distribution.SHA256File(binPath)
	if err != nil {
		t.Fatal(err)
	}
	rawPath := filepath.Join(fd.versionDir, distribution.CollectorRawBinaryName(version, osName, arch))
	if err := os.WriteFile(rawPath, []byte(fd.binContent), 0o755); err != nil {
		t.Fatal(err)
	}

	selfExe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	selfSha, selfSize, err := distribution.SHA256File(selfExe)
	if err != nil {
		t.Fatal(err)
	}

	art := distribution.Artifact{
		OS:                    osName,
		Arch:                  arch,
		Binary:                "toktrail" + ext,
		BinarySha256:          fd.binSha,
		BinarySize:            fd.binSize,
		InstallerBinary:       distribution.InstallerBinaryName(version, osName, arch),
		InstallerBinarySha256: selfSha,
		InstallerBinarySize:   selfSize,
	}

	zipEntries := []zipEntry{{name: "toktrail" + ext, content: fd.binContent}}
	if helperContent != "" {
		helperEntry := distribution.BackgroundHelperEntryName()
		helperRaw := distribution.BackgroundRawBinaryName(version, osName, arch)
		helperPath := filepath.Join(fd.versionDir, helperRaw)
		if err := os.WriteFile(helperPath, []byte(helperContent), 0o755); err != nil {
			t.Fatal(err)
		}
		helperSha, helperSize, err := distribution.SHA256File(helperPath)
		if err != nil {
			t.Fatal(err)
		}
		art.BackgroundBinary = helperEntry
		art.BackgroundBinarySha256 = helperSha
		art.BackgroundBinarySize = helperSize
		zipEntries = append(zipEntries, zipEntry{name: helperEntry, content: helperContent})
	}

	archiveName := distribution.CollectorArchiveName(version, osName, arch)
	archivePath := filepath.Join(fd.versionDir, archiveName)
	if err := buildZip(archivePath, zipEntries); err != nil {
		t.Fatal(err)
	}
	arcSha, arcSize, err := distribution.SHA256File(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	art.Archive = archiveName
	art.ArchiveSha256 = arcSha
	art.ArchiveSize = arcSize

	if err := os.WriteFile(filepath.Join(fd.versionDir, art.InstallerBinary), mustReadFile(t, selfExe), 0o755); err != nil {
		t.Fatal(err)
	}

	m := &distribution.Manifest{
		Schema:      distribution.ManifestSchema,
		Product:     distribution.ProductName,
		Version:     version,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Artifacts:   []distribution.Artifact{art},
	}
	manifestBytes, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fd.versionDir, distribution.ManifestFileName), manifestBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	sig, err := distribution.SignDetached(priv, manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fd.versionDir, distribution.ManifestSignatureFileName), sig, 0o644); err != nil {
		t.Fatal(err)
	}
	return fd
}

// helperInstallOpts returns install options targeting the fake windows/amd64
// artifact of fd, regardless of the host platform.
func (fd *fakeDist) helperInstallOpts(t *testing.T) InstallOptions {
	t.Helper()
	return InstallOptions{
		DistDir:    fd.versionDir,
		Version:    fd.version,
		PubKeyPath: fd.pubPath,
		InstallDir: filepath.Join(t.TempDir(), "bin"),
		OS:         "windows",
		Arch:       "amd64",
	}
}

// withRename overrides the rename seam of the multi-file commit path for
// one test, so a replacement failure can be injected deterministically.
func withRename(t *testing.T, fn func(oldpath, newpath string) error) {
	t.Helper()
	old := osRename
	osRename = fn
	t.Cleanup(func() { osRename = old })
}

func writeOldScriptExe(t *testing.T, dir, version string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "toktrail.exe"), []byte(fakeVersionScript(version)), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestInstallWithBackgroundHelperFresh(t *testing.T) {
	fd := newFakeDistWindows(t, "v0.2.0", "fake collector v0.2.0", "fake gui helper v0.2.0")
	res, err := Install(fd.helperInstallOpts(t))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.Replaced {
		t.Error("fresh install must not report a replacement")
	}
	if want := filepath.Join(filepath.Dir(res.BinaryPath), "toktrail-background.exe"); res.BackgroundBinaryPath != want {
		t.Errorf("BackgroundBinaryPath = %s, want %s", res.BackgroundBinaryPath, want)
	}
	if got := readOrFail(t, res.BinaryPath); got != "fake collector v0.2.0" {
		t.Errorf("collector content = %q", got)
	}
	if got := readOrFail(t, res.BackgroundBinaryPath); got != "fake gui helper v0.2.0" {
		t.Errorf("helper content = %q", got)
	}
	if runtime.GOOS != "windows" {
		for _, p := range []string{res.BinaryPath, res.BackgroundBinaryPath} {
			info, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm()&0o111 == 0 {
				t.Errorf("installed file %s not executable: %v", p, info.Mode())
			}
		}
	}
	// Exactly the two release files exist in the install directory.
	entries, err := os.ReadDir(filepath.Dir(res.BinaryPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("install dir has unexpected entries: %v", names)
	}
}

func TestInstallWithBackgroundHelperReplacesBoth(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake existing binary is a POSIX shell script")
	}
	opts := newFakeDistWindows(t, "v0.2.0", fakeVersionScript("v0.2.0"), "fake gui helper v0.2.0").helperInstallOpts(t)
	writeOldScriptExe(t, opts.InstallDir, "v0.1.0")
	if err := os.WriteFile(filepath.Join(opts.InstallDir, "toktrail-background.exe"), []byte("old gui helper"), 0o755); err != nil {
		t.Fatal(err)
	}
	opts.KeepOld = true

	res, err := Install(opts)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.Replaced {
		t.Error("expected replacement")
	}
	if got := readOrFail(t, res.BinaryPath); got != fakeVersionScript("v0.2.0") {
		t.Errorf("collector not replaced: %q", got)
	}
	if got := readOrFail(t, res.BackgroundBinaryPath); got != "fake gui helper v0.2.0" {
		t.Errorf("helper not replaced: %q", got)
	}
	if got := readOrFail(t, res.KeptOldPath); got != fakeVersionScript("v0.1.0") {
		t.Errorf(".previous = %q, want the old collector", got)
	}
	// toktrail.exe, toktrail-background.exe, toktrail.exe.previous.
	entries, err := os.ReadDir(opts.InstallDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("install dir has unexpected entries: %v", names)
	}
}

// TestInstallWithBackgroundHelperRollbackRestoresOldFiles injects a rename
// failure for the helper: the collector that was already replaced must be
// restored from its backup, the helper must keep its old content, and no
// staged or backup temp files may remain.
func TestInstallWithBackgroundHelperRollbackRestoresOldFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake existing binary is a POSIX shell script")
	}
	opts := newFakeDistWindows(t, "v0.2.0", fakeVersionScript("v0.2.0"), "fake gui helper v0.2.0").helperInstallOpts(t)
	writeOldScriptExe(t, opts.InstallDir, "v0.1.0")
	if err := os.WriteFile(filepath.Join(opts.InstallDir, "toktrail-background.exe"), []byte("old gui helper"), 0o755); err != nil {
		t.Fatal(err)
	}

	withRename(t, func(oldpath, newpath string) error {
		if filepath.Base(newpath) == "toktrail-background.exe" {
			return errors.New("synthetic replace failure")
		}
		return os.Rename(oldpath, newpath)
	})

	_, err := Install(opts)
	if err == nil {
		t.Fatal("install succeeded despite the helper replace failure")
	}
	if !strings.Contains(err.Error(), "toktrail-background.exe") {
		t.Errorf("error should name the failed replacement: %v", err)
	}
	if got := readOrFail(t, filepath.Join(opts.InstallDir, "toktrail.exe")); got != fakeVersionScript("v0.1.0") {
		t.Errorf("collector was not rolled back to the old file: %q", got)
	}
	if got := readOrFail(t, filepath.Join(opts.InstallDir, "toktrail-background.exe")); got != "old gui helper" {
		t.Errorf("helper was not left at its old content: %q", got)
	}
	entries, err := os.ReadDir(opts.InstallDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("rollback left temp files behind: %v", names)
	}
}

// TestInstallWithBackgroundHelperFailedRollbackKeepsBackup injects a
// second failure into the rollback itself: the collector was already
// replaced and its restore rename fails. The backup copy of the old
// collector must be PRESERVED on disk (it is the only remaining copy of
// the old file) and the error must name its local path.
func TestInstallWithBackgroundHelperFailedRollbackKeepsBackup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake existing binary is a POSIX shell script")
	}
	opts := newFakeDistWindows(t, "v0.2.0", fakeVersionScript("v0.2.0"), "fake gui helper v0.2.0").helperInstallOpts(t)
	writeOldScriptExe(t, opts.InstallDir, "v0.1.0")
	if err := os.WriteFile(filepath.Join(opts.InstallDir, "toktrail-background.exe"), []byte("old gui helper"), 0o755); err != nil {
		t.Fatal(err)
	}

	withRename(t, func(oldpath, newpath string) error {
		switch {
		case filepath.Base(newpath) == "toktrail-background.exe":
			// The helper replacement fails, triggering the rollback.
			return errors.New("synthetic helper replace failure")
		case strings.HasPrefix(filepath.Base(oldpath), ".toktrail-backup-"):
			// The restore of the already-replaced collector fails too.
			return errors.New("synthetic restore failure")
		}
		return os.Rename(oldpath, newpath)
	})

	_, err := Install(opts)
	if err == nil {
		t.Fatal("install succeeded despite the helper replace failure")
	}
	if !strings.Contains(err.Error(), "preserved at") {
		t.Errorf("error must name the preserved backup path: %v", err)
	}

	// Exactly one backup copy must remain, holding the old collector.
	matches, globErr := filepath.Glob(filepath.Join(opts.InstallDir, ".toktrail-backup-*"))
	if globErr != nil {
		t.Fatal(globErr)
	}
	if len(matches) != 1 {
		t.Fatalf("expected exactly one preserved backup, got %v", matches)
	}
	if got := readOrFail(t, matches[0]); got != fakeVersionScript("v0.1.0") {
		t.Errorf("preserved backup does not hold the old collector: %q", got)
	}
	// The degraded state is documented, not hidden: the collector target
	// holds the new file (restore failed) and the helper kept its old
	// content (never replaced). No other residues remain.
	if got := readOrFail(t, filepath.Join(opts.InstallDir, "toktrail.exe")); got != fakeVersionScript("v0.2.0") {
		t.Errorf("collector target should hold the new file after the failed restore: %q", got)
	}
	if got := readOrFail(t, filepath.Join(opts.InstallDir, "toktrail-background.exe")); got != "old gui helper" {
		t.Errorf("helper must keep its old content: %q", got)
	}
	entries, err := os.ReadDir(opts.InstallDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("expected the two targets plus one preserved backup, got %v", names)
	}
}

// TestInstallWithBackgroundHelperRefusesTamperedHelper rebuilds the archive
// with helper bytes that do not match the signed manifest: the install must
// fail during extraction, before anything is written.
func TestInstallWithBackgroundHelperRefusesTamperedHelper(t *testing.T) {
	fd := newFakeDistWindows(t, "v0.2.0", "fake collector v0.2.0", "fake gui helper v0.2.0")
	archivePath := filepath.Join(fd.versionDir, distribution.CollectorArchiveName(fd.version, "windows", "amd64"))
	if err := buildZip(archivePath, []zipEntry{
		{name: "toktrail.exe", content: "fake collector v0.2.0"},
		{name: "toktrail-background.exe", content: "tampered gui helper"},
	}); err != nil {
		t.Fatal(err)
	}
	// The archive hash must match the manifest again for the failure to be
	// attributable to the helper entry itself.
	mPath := filepath.Join(fd.versionDir, distribution.ManifestFileName)
	m, err := distribution.ParseManifest(mustReadFile(t, mPath))
	if err != nil {
		t.Fatal(err)
	}
	arcSha, arcSize, err := distribution.SHA256File(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	m.Artifacts[0].ArchiveSha256 = arcSha
	m.Artifacts[0].ArchiveSize = arcSize
	data, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := distribution.SignDetached(fd.priv, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fd.versionDir, distribution.ManifestSignatureFileName), sig, 0o644); err != nil {
		t.Fatal(err)
	}

	opts := fd.helperInstallOpts(t)
	if _, err := Install(opts); err == nil {
		t.Fatal("tampered helper installed")
	} else if !strings.Contains(err.Error(), "background helper") {
		t.Errorf("error should name the helper: %v", err)
	}
	if _, err := os.Lstat(opts.InstallDir); !os.IsNotExist(err) {
		t.Errorf("failed install must not create the install directory: %v", err)
	}
}

func TestInstallWithBackgroundHelperRefusesMissingHelperEntry(t *testing.T) {
	fd := newFakeDistWindows(t, "v0.2.0", "fake collector v0.2.0", "fake gui helper v0.2.0")
	archivePath := filepath.Join(fd.versionDir, distribution.CollectorArchiveName(fd.version, "windows", "amd64"))
	if err := buildZip(archivePath, []zipEntry{
		{name: "toktrail.exe", content: "fake collector v0.2.0"},
	}); err != nil {
		t.Fatal(err)
	}
	mPath := filepath.Join(fd.versionDir, distribution.ManifestFileName)
	m, err := distribution.ParseManifest(mustReadFile(t, mPath))
	if err != nil {
		t.Fatal(err)
	}
	arcSha, arcSize, err := distribution.SHA256File(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	m.Artifacts[0].ArchiveSha256 = arcSha
	m.Artifacts[0].ArchiveSize = arcSize
	data, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := distribution.SignDetached(fd.priv, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fd.versionDir, distribution.ManifestSignatureFileName), sig, 0o644); err != nil {
		t.Fatal(err)
	}

	opts := fd.helperInstallOpts(t)
	if _, err := Install(opts); err == nil {
		t.Fatal("manifest describing a helper the archive does not carry was installed")
	}
}

// TestInstallWithBackgroundHelperNeverOverwritesLinks covers links in the
// install directory: neither the collector nor the helper target may be a
// symlink; the install refuses and the link is left intact.
func TestInstallWithBackgroundHelperNeverOverwritesLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on Windows")
	}
	for _, target := range []string{"toktrail.exe", "toktrail-background.exe"} {
		t.Run(target, func(t *testing.T) {
			fd := newFakeDistWindows(t, "v0.2.0", "fake collector v0.2.0", "fake gui helper v0.2.0")
			opts := fd.helperInstallOpts(t)
			if err := os.MkdirAll(opts.InstallDir, 0o755); err != nil {
				t.Fatal(err)
			}
			real := filepath.Join(t.TempDir(), "real-file")
			if err := os.WriteFile(real, []byte("user file"), 0o644); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(opts.InstallDir, target)
			if err := os.Symlink(real, link); err != nil {
				t.Fatal(err)
			}

			if _, err := Install(opts); err == nil {
				t.Fatal("install accepted a symlink target")
			} else if !strings.Contains(err.Error(), "never overwritten") {
				t.Errorf("error should explain the link refusal: %v", err)
			}
			if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
				t.Errorf("the symlink must remain a symlink: %v", err)
			}
			if got := readOrFail(t, real); got != "user file" {
				t.Errorf("the link target must be untouched, got %q", got)
			}
			entries, err := os.ReadDir(opts.InstallDir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name() != target {
				names := make([]string, len(entries))
				for i, e := range entries {
					names[i] = e.Name()
				}
				t.Fatalf("refusal must leave the install dir untouched, got %v", names)
			}
		})
	}
}

func TestInstallWithBackgroundHelperNoReplace(t *testing.T) {
	fd := newFakeDistWindows(t, "v0.2.0", "fake collector v0.2.0", "fake gui helper v0.2.0")
	for _, tc := range []struct {
		name   string
		create []string
	}{
		{"existing collector", []string{"toktrail.exe"}},
		{"existing helper", []string{"toktrail-background.exe"}},
		{"both", []string{"toktrail.exe", "toktrail-background.exe"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := fd.helperInstallOpts(t)
			if err := os.MkdirAll(opts.InstallDir, 0o755); err != nil {
				t.Fatal(err)
			}
			for _, name := range tc.create {
				if err := os.WriteFile(filepath.Join(opts.InstallDir, name), []byte("existing "+name), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			opts.NoReplace = true
			if _, err := Install(opts); err == nil {
				t.Fatal("no-clobber mode replaced existing files")
			} else if !strings.Contains(err.Error(), "-no-replace") {
				t.Errorf("error should mention -no-replace: %v", err)
			}
			for _, name := range tc.create {
				if got := readOrFail(t, filepath.Join(opts.InstallDir, name)); got != "existing "+name {
					t.Errorf("%s was touched: %q", name, got)
				}
			}
		})
	}
}

// TestInstallHelperlessWindowsManifestKeepsSingleFileBehavior pins the
// compatibility requirement: a windows manifest without helper fields
// installs exactly one file through the original single-file path.
func TestInstallHelperlessWindowsManifestKeepsSingleFileBehavior(t *testing.T) {
	fd := newFakeDistWindows(t, "v0.2.0", "fake collector v0.2.0", "")
	res, err := Install(fd.helperInstallOpts(t))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.BackgroundBinaryPath != "" {
		t.Errorf("BackgroundBinaryPath = %s, want empty", res.BackgroundBinaryPath)
	}
	if got := readOrFail(t, res.BinaryPath); got != "fake collector v0.2.0" {
		t.Errorf("collector content = %q", got)
	}
	entries, err := os.ReadDir(filepath.Dir(res.BinaryPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "toktrail.exe" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("helper-less install must place exactly one file, got %v", names)
	}
}

func TestVerifyDistDirWithBackgroundHelper(t *testing.T) {
	fd := newFakeDistWindows(t, "v0.3.0", "fake collector v0.3.0", "fake gui helper v0.3.0")
	verify := func() error {
		_, err := Verify(VerifyOptions{
			ManifestPath:  filepath.Join(fd.versionDir, distribution.ManifestFileName),
			SignaturePath: filepath.Join(fd.versionDir, distribution.ManifestSignatureFileName),
			PubKeyPath:    fd.pubPath,
			DistDir:       fd.versionDir,
		})
		return err
	}
	if err := verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	helperRaw := filepath.Join(fd.versionDir, distribution.BackgroundRawBinaryName("v0.3.0", "windows", "amd64"))
	if err := os.WriteFile(helperRaw, []byte("corrupted helper"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := verify()
	if err == nil {
		t.Fatal("verify accepted a corrupted background helper")
	}
	if !strings.Contains(err.Error(), "background helper") {
		t.Errorf("error should name the background helper: %v", err)
	}
}

// TestUpgradeWindowsHelperReplacesCollectorAndHelper runs the upgrade
// pipeline against a helper-carrying manifest: the discovered collector is
// replaced in place and the helper lands beside it through the same
// verified pipeline. No scheduled task or user state exists in this
// fixture, pinning that the upgrade itself never touches anything else.
func TestUpgradeWindowsHelperReplacesCollectorAndHelper(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake existing binary is a POSIX shell script")
	}
	binDir := t.TempDir()
	writeOldScriptExe(t, binDir, "v0.1.0")
	fd := newFakeDistWindows(t, "v0.2.0", fakeVersionScript("v0.2.0"), "fake gui helper v0.2.0")

	res, err := Upgrade(UpgradeOptions{
		DistDir:    fd.versionDir,
		Version:    "v0.2.0",
		PubKeyPath: fd.pubPath,
		InstallDir: binDir,
		KeepOld:    true,
		OS:         "windows",
		Arch:       "amd64",
	})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if res.FromVersion != "v0.1.0" || res.Version != "v0.2.0" {
		t.Errorf("unexpected result: %+v", res)
	}
	collector := canonicalPath(t, filepath.Join(binDir, "toktrail.exe"))
	helper := canonicalPath(t, filepath.Join(binDir, "toktrail-background.exe"))
	if res.BinaryPath != collector || res.BackgroundBinaryPath != helper {
		t.Errorf("paths = %s / %s, want %s / %s", res.BinaryPath, res.BackgroundBinaryPath, collector, helper)
	}
	if got := readOrFail(t, collector); got != fakeVersionScript("v0.2.0") {
		t.Errorf("collector not upgraded: %q", got)
	}
	if got := readOrFail(t, helper); got != "fake gui helper v0.2.0" {
		t.Errorf("helper not installed: %q", got)
	}
	if got := readOrFail(t, res.KeptOldPath); got != fakeVersionScript("v0.1.0") {
		t.Errorf(".previous = %q", got)
	}
	entries, err := os.ReadDir(binDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("upgrade changed more than the release files: %v", names)
	}
}

func TestStageVerifiedFileRejectsMismatch(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("content"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "sub", "toktrail-background.exe")
	if _, err := stageVerifiedFile(src, target, sha256Hex("other"), 7); err == nil {
		t.Fatal("staging accepted a hash mismatch")
	}
	if _, err := stageVerifiedFile(src, target, sha256Hex("content"), 8); err == nil {
		t.Fatal("staging accepted a size mismatch")
	}
	// A failed staging must not leave temp files behind.
	entries, err := os.ReadDir(filepath.Join(dir, "sub"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("failed staging left files behind: %v", names)
	}
	staged, err := stageVerifiedFile(src, target, sha256Hex("content"), 7)
	if err != nil {
		t.Fatalf("correct staging failed: %v", err)
	}
	defer os.Remove(staged)
	if got := readOrFail(t, staged); got != "content" {
		t.Errorf("staged content = %q", got)
	}
}
