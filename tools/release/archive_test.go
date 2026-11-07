package main

import (
	"os"
	"path/filepath"
	"testing"

	"toktrail-collector/internal/distribution"
	"toktrail-collector/internal/installer"
)

func writeTestFile(t *testing.T, path, content string) (sha string, size int64) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	s, n, err := distribution.SHA256File(path)
	if err != nil {
		t.Fatal(err)
	}
	return s, n
}

func TestCreateArchiveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "toktrail")
	content := "#!/bin/sh\necho collector\n"
	sha, size := writeTestFile(t, src, content)

	// tar.gz round trip.
	tgz := filepath.Join(dir, "out.tar.gz")
	if err := CreateArchive(tgz, src, "toktrail"); err != nil {
		t.Fatalf("CreateArchive tar.gz: %v", err)
	}
	out := filepath.Join(dir, "extracted")
	if err := installer.ExtractBinaryEntry(tgz, "toktrail", out, size, sha); err != nil {
		t.Fatalf("ExtractBinaryEntry tar.gz: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Errorf("tar.gz round trip content mismatch")
	}

	// zip round trip.
	zp := filepath.Join(dir, "out.zip")
	if err := CreateArchive(zp, src, "toktrail"); err != nil {
		t.Fatalf("CreateArchive zip: %v", err)
	}
	out2 := filepath.Join(dir, "extracted-zip")
	if err := installer.ExtractBinaryEntry(zp, "toktrail", out2, size, sha); err != nil {
		t.Fatalf("ExtractBinaryEntry zip: %v", err)
	}
	got2, err := os.ReadFile(out2)
	if err != nil {
		t.Fatal(err)
	}
	if string(got2) != content {
		t.Errorf("zip round trip content mismatch")
	}

	// No-clobber: creating the same archive path twice must fail.
	if err := CreateArchive(tgz, src, "toktrail"); err == nil {
		t.Error("second CreateArchive to same path succeeded; want no-clobber")
	}
}

// TestCreateArchiveEntriesRoundTrip covers the multi-entry form used for
// windows archives carrying the collector plus the GUI helper.
func TestCreateArchiveEntriesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	collector := filepath.Join(dir, "toktrail.exe")
	helper := filepath.Join(dir, "toktrail-background.exe")
	collectorContent := "fake collector"
	helperContent := "fake gui helper"
	collectorSha, collectorSize := writeTestFile(t, collector, collectorContent)
	helperSha, helperSize := writeTestFile(t, helper, helperContent)

	entries := []ArchiveEntry{
		{Name: "toktrail.exe", SrcPath: collector},
		{Name: "toktrail-background.exe", SrcPath: helper},
	}
	zp := filepath.Join(dir, "out.zip")
	if err := CreateArchiveEntries(zp, entries); err != nil {
		t.Fatalf("CreateArchiveEntries zip: %v", err)
	}
	for _, e := range []struct {
		name string
		sha  string
		size int64
	}{
		{"toktrail.exe", collectorSha, collectorSize},
		{"toktrail-background.exe", helperSha, helperSize},
	} {
		out := filepath.Join(dir, "extracted-"+e.name)
		if err := installer.ExtractBinaryEntry(zp, e.name, out, e.size, e.sha); err != nil {
			t.Fatalf("ExtractBinaryEntry %s: %v", e.name, err)
		}
	}

	// Duplicate entry names and empty entry lists are refused.
	if err := CreateArchiveEntries(filepath.Join(dir, "dup.zip"), []ArchiveEntry{
		{Name: "toktrail.exe", SrcPath: collector},
		{Name: "toktrail.exe", SrcPath: helper},
	}); err == nil {
		t.Error("duplicate entry names accepted")
	}
	if err := CreateArchiveEntries(filepath.Join(dir, "empty.zip"), nil); err == nil {
		t.Error("empty entry list accepted")
	}
	if err := CreateArchiveEntries(filepath.Join(dir, "unsafe.zip"), []ArchiveEntry{
		{Name: "../toktrail.exe", SrcPath: collector},
	}); err == nil {
		t.Error("unsafe entry name accepted")
	}
}
