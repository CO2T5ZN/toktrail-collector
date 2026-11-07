package distribution

import (
	"fmt"
	"runtime"
)

// Platform describes an OS/Arch target tuple.
type Platform struct {
	OS   string
	Arch string
}

// ReleasePlatforms is the canonical matrix of supported release targets.
var ReleasePlatforms = []Platform{
	{OS: "darwin", Arch: "amd64"},
	{OS: "darwin", Arch: "arm64"},
	{OS: "linux", Arch: "amd64"},
	{OS: "linux", Arch: "arm64"},
	{OS: "windows", Arch: "amd64"},
	{OS: "windows", Arch: "arm64"},
}

// BinaryExt returns the OS-specific executable extension.
func BinaryExt(osName string) string {
	if osName == "windows" {
		return ".exe"
	}
	return ""
}

// ArchiveExt returns the OS-specific archive extension (.zip for windows, .tar.gz for unix).
func ArchiveExt(osName string) string {
	if osName == "windows" {
		return ".zip"
	}
	return ".tar.gz"
}

// CollectorArchiveName returns the canonical archive file name for a release.
func CollectorArchiveName(version, osName, arch string) string {
	return fmt.Sprintf("toktrail-%s-%s-%s%s", version, osName, arch, ArchiveExt(osName))
}

// InstallerBinaryName returns the canonical installer binary name for a release.
// Pinned for backwards compatibility to toktrail-release-<version>-<os>-<arch>.
func InstallerBinaryName(version, osName, arch string) string {
	return fmt.Sprintf("toktrail-release-%s-%s-%s%s", version, osName, arch, BinaryExt(osName))
}

// CollectorRawBinaryName returns the uncompressed binary name for a release.
func CollectorRawBinaryName(version, osName, arch string) string {
	return fmt.Sprintf("toktrail-%s-%s-%s%s", version, osName, arch, BinaryExt(osName))
}

// BackgroundHelperEntryName returns the fixed name of the Windows GUI
// helper inside release archives and after installation. It is identical
// for every version and platform the manifest validator allows.
func BackgroundHelperEntryName() string {
	return BackgroundBinaryName + ".exe"
}

// BackgroundRawBinaryName returns the versioned dist-layout file name of
// the Windows GUI helper produced by scripts/release.sh
// (toktrail-background-<version>-windows-<arch>.exe). The assembler packs
// it into the platform archive under the fixed entry name above.
func BackgroundRawBinaryName(version, osName, arch string) string {
	return fmt.Sprintf("%s-%s-%s-%s%s", BackgroundBinaryName, version, osName, arch, BinaryExt(osName))
}

// RuntimePlatform returns the GOOS and GOARCH of the current process.
func RuntimePlatform() (string, string) {
	return runtime.GOOS, runtime.GOARCH
}
