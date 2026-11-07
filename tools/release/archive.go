package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strings"

	"toktrail-collector/internal/distribution"
)

const executableMode = 0o755

// ArchiveEntry is one file packed into a release archive.
type ArchiveEntry struct {
	// Name is the entry name inside the archive (bare, safe file name).
	Name string
	// SrcPath is the source file on disk.
	SrcPath string
}

// CreateArchive packs srcPath into dstPath under entryName.
// Unix platforms get a reproducible tar.gz; windows gets a zip.
// Both embed the executable mode bit for the binary.
func CreateArchive(dstPath, srcPath, entryName string) error {
	return CreateArchiveEntries(dstPath, []ArchiveEntry{{Name: entryName, SrcPath: srcPath}})
}

// CreateArchiveEntries packs one or more entries into dstPath. Windows
// archives (zip) may carry the collector binary plus the optional GUI
// helper (toktrail-background.exe); entry names must be unique, safe bare
// file names. Like CreateArchive it never overwrites an existing archive.
func CreateArchiveEntries(dstPath string, entries []ArchiveEntry) error {
	if len(entries) == 0 {
		return fmt.Errorf("archive %s needs at least one entry", dstPath)
	}
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		if !distribution.IsSafeFileName(e.Name) {
			return fmt.Errorf("archive entry name %q is not a safe bare file name", e.Name)
		}
		if seen[e.Name] {
			return fmt.Errorf("duplicate archive entry name %q", e.Name)
		}
		seen[e.Name] = true
		if info, err := os.Stat(e.SrcPath); err != nil {
			return fmt.Errorf("archive entry %q source %s: %w", e.Name, e.SrcPath, err)
		} else if info.IsDir() {
			return fmt.Errorf("archive entry %q source %s is a directory", e.Name, e.SrcPath)
		}
	}
	switch {
	case strings.HasSuffix(dstPath, ".zip"):
		return createZipEntries(dstPath, entries)
	case strings.HasSuffix(dstPath, ".tar.gz"):
		return createTarGzEntries(dstPath, entries)
	default:
		return fmt.Errorf("archive path %q must end with .tar.gz or .zip", dstPath)
	}
}

func createTarGzEntries(dstPath string, entries []ArchiveEntry) error {
	out, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	gz := gzip.NewWriter(out)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	for _, e := range entries {
		in, err := os.Open(e.SrcPath)
		if err != nil {
			return err
		}
		info, err := in.Stat()
		if err != nil {
			in.Close()
			return err
		}
		// Zero ModTime and USTAR format keep archives byte-reproducible.
		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     e.Name,
			Size:     info.Size(),
			Mode:     executableMode,
			Format:   tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			in.Close()
			return err
		}
		if _, err := io.Copy(tw, in); err != nil {
			in.Close()
			return err
		}
		if err := in.Close(); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return out.Close()
}

func createZipEntries(dstPath string, entries []ArchiveEntry) error {
	out, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	zw := zip.NewWriter(out)
	defer zw.Close()
	for _, e := range entries {
		in, err := os.Open(e.SrcPath)
		if err != nil {
			return err
		}
		hdr := &zip.FileHeader{Name: e.Name, Method: zip.Deflate}
		hdr.SetMode(executableMode)
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			in.Close()
			return err
		}
		if _, err := io.Copy(w, in); err != nil {
			in.Close()
			return err
		}
		if err := in.Close(); err != nil {
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return out.Close()
}
