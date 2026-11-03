package sqlitecancel

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	// Paths are relative to this package's directory (internal/sqlitecancel).
	repoRoot        = "../.."
	vendoredSqlite  = "vendor/modernc.org/sqlite/sqlite.go"
	vendoredModules = "vendor/modules.txt"

	pinnedSqliteVersion = "v1.38.2"
)

// nodeString renders an AST node back to source text for exact comparisons.
func nodeString(fset *token.FileSet, n ast.Node) string {
	var sb strings.Builder
	if err := printer.Fprint(&sb, fset, n); err != nil {
		return ""
	}
	return sb.String()
}

// vendoredSqliteVersion extracts the modernc.org/sqlite version recorded by
// `go mod vendor` in vendor/modules.txt.
func vendoredSqliteVersion(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, vendoredModules))
	if err != nil {
		t.Fatalf("reading %s: %v", vendoredModules, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "# modernc.org/sqlite "); ok {
			return strings.TrimSpace(after)
		}
	}
	t.Fatalf("modernc.org/sqlite not found in %s", vendoredModules)
	return ""
}

// findStmtQueryDefer locates the deferred function literal of
// (*stmt).query in the parsed file.
func findStmtQueryDefer(t *testing.T, f *ast.File, fset *token.FileSet) *ast.FuncLit {
	t.Helper()
	var query *ast.FuncDecl
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "query" || fd.Recv == nil || len(fd.Recv.List) != 1 {
			continue
		}
		star, ok := fd.Recv.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		if id, ok := star.X.(*ast.Ident); ok && id.Name == "stmt" {
			query = fd
			break
		}
	}
	if query == nil {
		t.Fatalf("func (*stmt) query not found in %s", vendoredSqlite)
	}

	var deferred *ast.FuncLit
	ast.Inspect(query.Body, func(n ast.Node) bool {
		if deferred != nil {
			return false
		}
		d, ok := n.(*ast.DeferStmt)
		if !ok {
			return true
		}
		call, ok := d.Call.Fun.(*ast.FuncLit)
		if !ok {
			return true
		}
		deferred = call
		return false
	})
	if deferred == nil {
		t.Fatalf("deferred function literal not found in (*stmt).query in %s", vendoredSqlite)
	}
	return deferred
}

// TestVendoredSqliteQueryCancelBranchClosesRows is the source-level
// anti-regression gate for the vendored driver patch. It fails when the
// deferred cancellation branch of (*stmt).query no longer closes the rows
// before discarding them, which happens when `go mod vendor` rewrites
// vendor/modernc.org/sqlite from the pristine v1.38.2 module.
//
// Recovery: scripts/vendor-patch-modernc-sqlite.sh apply
func TestVendoredSqliteQueryCancelBranchClosesRows(t *testing.T) {
	version := vendoredSqliteVersion(t)
	if version != pinnedSqliteVersion {
		// Fail closed: an unexpected version may be a downgrade or a
		// version without the fix. The source gate only encodes the shape
		// of the patched v1.38.2, so it cannot judge other versions.
		// Whoever upgrades the dependency must verify the new version
		// carries the fix (upstream >= v1.40.1 does), then update or
		// replace this gate, drop the vendor patch and its script.
		t.Fatalf("vendored modernc.org/sqlite is %s, but this source gate only validates the patched %s. "+
			"Fail-closed: verify the upgraded driver closes rows on canceled contexts (upstream >= v1.40.1, tag d33e568), "+
			"then update or replace TestVendoredSqliteQueryCancelBranchClosesRows and remove "+
			"docs/vendor-patches/modernc-sqlite-v1.38.2-close-rows-on-canceled-context.patch and scripts/vendor-patch-modernc-sqlite.sh.",
			version, pinnedSqliteVersion)
	}

	data, err := os.ReadFile(filepath.Join(repoRoot, vendoredSqlite))
	if err != nil {
		t.Fatalf("reading %s: %v", vendoredSqlite, err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, vendoredSqlite, data, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", vendoredSqlite, err)
	}

	deferred := findStmtQueryDefer(t, f, fset)

	// Find the cancellation branch: the if statement guarded by
	// `ctx != nil && atomic.LoadInt32(&done) != 0`.
	var cancelBranch *ast.IfStmt
	ast.Inspect(deferred.Body, func(n ast.Node) bool {
		if cancelBranch != nil {
			return false
		}
		ifs, ok := n.(*ast.IfStmt)
		if !ok || ifs.Else == nil {
			return true
		}
		if strings.Contains(nodeString(fset, ifs.Cond), "atomic.LoadInt32(&done) != 0") {
			cancelBranch = ifs
			return false
		}
		return true
	})
	if cancelBranch == nil {
		t.Fatalf("cancellation branch (`atomic.LoadInt32(&done) != 0`) not found in the deferred function of (*stmt).query in %s.\n"+
			"The vendored driver does not match the expected patched v1.38.2 source.\n"+
			"Re-apply the patch: scripts/vendor-patch-modernc-sqlite.sh apply", vendoredSqlite)
	}

	// The branch body must be:
	//
	//	if r != nil {
	//		r.Close()
	//	}
	//	r, err = nil, ctx.Err()
	//
	// i.e. the rows are closed before being overwritten with nil. Anything
	// else is either the pristine v1.38.2 source (leak) or an unexpected
	// upstream change.
	body := cancelBranch.Body.List
	if len(body) < 2 {
		t.Fatalf("cancellation branch of (*stmt).query has %d statements, want >= 2 (close-if + nil assignment); "+
			"the vendored driver appears to be pristine v1.38.2. Re-apply the patch: scripts/vendor-patch-modernc-sqlite.sh apply", len(body))
	}

	closeIf, ok := body[0].(*ast.IfStmt)
	if !ok {
		t.Fatalf("first statement of the cancellation branch is %T, want *ast.IfStmt (`if r != nil { r.Close() }`); "+
			"the vendored driver appears to be pristine v1.38.2. Re-apply the patch: scripts/vendor-patch-modernc-sqlite.sh apply", body[0])
	}
	if got := nodeString(fset, closeIf.Cond); got != "r != nil" {
		t.Fatalf("close guard condition is %q, want %q", got, "r != nil")
	}
	closedBeforeAssign := false
	for _, stmt := range closeIf.Body.List {
		expr, ok := stmt.(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, ok := expr.X.(*ast.CallExpr)
		if !ok {
			continue
		}
		if nodeString(fset, call) == "r.Close()" {
			closedBeforeAssign = true
		}
	}
	if !closedBeforeAssign {
		t.Fatalf("`r.Close()` call not found inside `if r != nil` in the cancellation branch of (*stmt).query in %s", vendoredSqlite)
	}

	// The nil assignment must come after the close guard: `r, err = nil, ctx.Err()`.
	foundAssign := false
	for _, stmt := range body[1:] {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 2 {
			continue
		}
		if nodeString(fset, assign.Lhs[0]) == "r" &&
			nodeString(fset, assign.Lhs[1]) == "err" &&
			nodeString(fset, assign.Rhs[0]) == "nil" &&
			strings.HasPrefix(nodeString(fset, assign.Rhs[1]), "ctx.Err()") {
			foundAssign = true
			break
		}
	}
	if !foundAssign {
		t.Fatalf("`r, err = nil, ctx.Err()` assignment not found after the close guard in the cancellation branch of (*stmt).query in %s", vendoredSqlite)
	}

	// Guard the pristine shape too: an assignment to r directly at the top of
	// the branch (without the preceding close guard) must not be accepted,
	// which is already implied by the body[0] type check above.
	t.Logf("OK: %s carries the cancellation-branch rows fix (r closed before discard) for modernc.org/sqlite %s", vendoredSqlite, version)
}
