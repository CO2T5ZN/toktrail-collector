package sqlitecancel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The deterministic regression for the vendored driver's cancellation fix
// runs inside the vendored package itself, via `go test -overlay`:
//
//  1. A copy of vendor/modernc.org/sqlite/sqlite.go is made in a temporary
//     directory and a test hook call is injected right after the rows
//     handover in the SQLITE_ROW branch of (*stmt).query (after
//     `pstmt = 0`, when r owns the statement handle).
//  2. A virtual package file declaring the hook variable and a virtual
//     same-package test file are added to the vendored package through the
//     same overlay. The production vendor tree is never modified.
//  3. The inner test sets the hook to `cancel(); atomic.StoreInt32(&done,
//     1)`, which deterministically drives the deferred cancellation branch
//     of (*stmt).query while the freshly created rows are alive — no
//     goroutine-scheduling race, no sleep. It then proves the rows were
//     closed: with the fix, the driver finalizes the statement and a second
//     connection with busy_timeout=0 can write; without the fix (pristine
//     v1.38.2) the paused SELECT keeps a shared lock and the write fails
//     with SQLITE_BUSY. On Windows the leaked handle would also keep the
//     database file from being deleted.
//
// This wrapper runs everything with the local toolchain in vendor mode, so
// it needs no network access and runs automatically as part of the plain
// `go test ./...` suite on every platform.
//
// Old-version must fail: with the vendor patch removed the inner test
// fails (blocked write). Patched vendor: the inner test passes.
const (
	hookVarFile  = "zz_toktrail_hook.go"
	hookTestFile = "zz_toktrail_cancel_test.go"

	hookVarSource = `package sqlite

// toktrailQueryCancelTestHook exists only in the -overlay copy of this
// package used by the deterministic cancellation regression in
// internal/sqlitecancel. It is nil in the real build; the real vendor tree
// never contains this file.
var toktrailQueryCancelTestHook func(done *int32)
`

	// The injection anchor is the rows handover of the SQLITE_ROW branch in
	// (*stmt).query: newRows(...) with live rows, followed by the ownership
	// transfer `pstmt = 0`. The `allocs, false` argument makes this site
	// unique in the file.
	handoverNeedle = "if r, err = newRows(s.c, pstmt, allocs, false); err != nil {\n" +
		"\t\t\t\t\treturn err\n" +
		"\t\t\t\t}\n" +
		"\n" +
		"\t\t\t\tpstmt = 0\n" +
		"\t\t\t\treturn nil\n"
	handoverReplacement = "if r, err = newRows(s.c, pstmt, allocs, false); err != nil {\n" +
		"\t\t\t\t\treturn err\n" +
		"\t\t\t\t}\n" +
		"\n" +
		"\t\t\t\tpstmt = 0\n" +
		"\t\t\t\tif toktrailQueryCancelTestHook != nil {\n" +
		"\t\t\t\t\ttoktrailQueryCancelTestHook(&done)\n" +
		"\t\t\t\t}\n" +
		"\t\t\t\treturn nil\n"

	innerTest = `package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// TestToktrailQueryCancelClosesRows deterministically drives the deferred
// cancellation branch of (*stmt).query while freshly created rows are
// alive (the injected hook cancels the context and sets done right after
// the rows take ownership of the statement), and then requires that the
// rows were closed.
func TestToktrailQueryCancelClosesRows(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	toktrailQueryCancelTestHook = func(done *int32) {
		cancel()
		atomic.StoreInt32(done, 1)
	}
	defer func() { toktrailQueryCancelTestHook = nil }()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "det.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE t(v); INSERT INTO t VALUES (1)"); err != nil {
		t.Fatal(err)
	}

	rows, err := db.QueryContext(ctx, "SELECT v FROM t")
	if err == nil {
		rows.Close()
		t.Fatal("expected context.Canceled from the driven cancellation branch")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	// The cancelled query's rows must have been closed by the driver: the
	// paused SELECT keeps a shared lock while its statement is unfinalized,
	// so this write fails with SQLITE_BUSY (busy_timeout=0) on a leak.
	db2, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	db2.SetMaxOpenConns(1)
	if _, err := db2.Exec("PRAGMA busy_timeout=0"); err != nil {
		t.Fatal(err)
	}
	if _, err := db2.Exec("UPDATE t SET v = v + 1"); err != nil {
		t.Fatalf("driver leaked the cancelled query's rows: an unfinalized statement still holds a shared lock, second-connection write blocked: %v", err)
	}

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db2.Close(); err != nil {
		t.Fatal(err)
	}
	// Deleting the file must succeed on every platform once all statements
	// are finalized: on Windows a leaked open handle keeps the file locked;
	// elsewhere a failure still must not be hidden.
	if err := os.Remove(dbPath); err != nil {
		t.Fatalf("database file not removable after cancelled query (on Windows a leaked open handle keeps the file locked): %v", err)
	}
	t.Log("database file removed cleanly after cancelled query")
}
`
)

// injectHandoverHook accepts either Git LF or Windows CRLF checkouts. The
// normalized copy is used only by the test overlay; the vendor file is intact.
func injectHandoverHook(src []byte) ([]byte, error) {
	src = bytes.ReplaceAll(src, []byte("\r\n"), []byte("\n"))
	if n := bytes.Count(src, []byte(handoverNeedle)); n != 1 {
		return nil, fmt.Errorf("expected exactly one SQLITE_ROW rows-handover site in %s, found %d; the vendored driver changed shape and the overlay hook anchor must be updated", vendoredSqlite, n)
	}
	return bytes.Replace(src, []byte(handoverNeedle), []byte(handoverReplacement), 1), nil
}

func TestInjectHandoverHookLineEndings(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  []byte
	}{
		{"LF", []byte(handoverNeedle)},
		{"CRLF", bytes.ReplaceAll([]byte(handoverNeedle), []byte("\n"), []byte("\r\n"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := injectHandoverHook(tc.src)
			if err != nil || !bytes.Equal(got, []byte(handoverReplacement)) {
				t.Fatalf("hook injection failed: %v, got %q", err, got)
			}
		})
	}
	for _, src := range [][]byte{nil, []byte(handoverNeedle + handoverNeedle)} {
		if _, err := injectHandoverHook(src); err == nil {
			t.Fatal("missing or ambiguous handover site must fail")
		}
	}
}

// TestQueryCancelOverlayDeterministic builds the overlay copy of the
// vendored driver and runs the deterministic in-package regression with
// `go test -overlay`. It fails when the vendored driver either lost the
// cancellation-branch rows fix (inner test observes the leak) or changed
// shape so the hook can no longer be injected (fail-closed).
func TestQueryCancelOverlayDeterministic(t *testing.T) {
	repoRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		t.Fatal(err)
	}

	vendored := filepath.Join(repoRoot, vendoredSqlite)
	orig, err := os.ReadFile(vendored)
	if err != nil {
		t.Fatalf("reading %s: %v", vendoredSqlite, err)
	}
	for _, tc := range []struct {
		name string
		src  []byte
	}{
		{"LF", bytes.ReplaceAll(orig, []byte("\r\n"), []byte("\n"))},
		{"CRLF", bytes.ReplaceAll(bytes.ReplaceAll(orig, []byte("\r\n"), []byte("\n")), []byte("\n"), []byte("\r\n"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runQueryCancelOverlay(t, repoRoot, tc.src)
		})
	}
}

func runQueryCancelOverlay(t *testing.T, repoRoot string, src []byte) {
	t.Helper()
	hooked, err := injectHandoverHook(src)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	sqliteGo := filepath.ToSlash(filepath.Join(dir, "sqlite.go"))
	hookGo := filepath.ToSlash(filepath.Join(dir, hookVarFile))
	testGo := filepath.ToSlash(filepath.Join(dir, hookTestFile))
	for path, content := range map[string]string{
		sqliteGo: string(hooked),
		hookGo:   hookVarSource,
		testGo:   innerTest,
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	overlay := map[string]map[string]string{"Replace": {
		"vendor/modernc.org/sqlite/sqlite.go":       sqliteGo,
		"vendor/modernc.org/sqlite/" + hookVarFile:  hookGo,
		"vendor/modernc.org/sqlite/" + hookTestFile: testGo,
	}}
	overlayPath := filepath.ToSlash(filepath.Join(dir, "overlay.json"))
	overlayJSON, err := json.Marshal(overlay)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overlayPath, overlayJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go toolchain not available for the overlay regression: %v", err)
	}

	// Hard bound for the inner run (build + test). The outer CI suites use
	// a 3m per-binary timeout on Windows, so stay well below it; every
	// dependency is a build-cache hit because only the overlaid sqlite
	// package recompiles.
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, goTool, "test",
		"-mod=vendor",
		"-overlay", overlayPath,
		"-count=1", "-v",
		"-run", "^TestToktrailQueryCancelClosesRows$",
		"modernc.org/sqlite",
	)
	cmd.Dir = repoRoot
	// Hermetic: the inner run works purely from the vendor tree; forbid any
	// network or toolchain fetch so it can never hang on module access.
	// -mod=vendor is passed explicitly as an argument so it also wins over
	// a GOFLAGS=-mod=mod environment, keeping the overlaid vendored driver
	// in use everywhere.
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOTOOLCHAIN=local")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("deterministic overlay regression FAILED (vendored driver leaks rows on cancelled query, or the overlay run broke):\n%s\nerror: %v", out, err)
	}
	// Guard against a void success: `go test` exits 0 with "testing:
	// warning: no tests to run" when the -run pattern stops matching, so
	// require the inner PASS line explicitly.
	if !bytes.Contains(out, []byte("--- PASS: TestToktrailQueryCancelClosesRows")) {
		t.Fatalf("deterministic overlay regression did not actually run (no PASS line for TestToktrailQueryCancelClosesRows in output):\n%s", out)
	}
	t.Logf("deterministic overlay regression passed:\n%s", out)
}
