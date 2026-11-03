package zcodesqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"toktrail-collector/internal/source/adapter"
)

// Load cancellation coverage. The SQL scan runs through database/sql and the
// modernc.org/sqlite driver, so unlike the JSONL loaders its row loop cannot
// be steered by a purely synthetic Err()-flipping scope: readDB derives the
// per-database 30-second timeout scope from the caller's context, and that
// derivation only propagates a cancellation through a real Done() channel.
// The tests below therefore combine three deterministic mechanisms, none of
// which sleeps or races a timer across an oversized fixture:
//
//   - a pre-cancelled / pre-expired scope for the entry checkpoint,
//   - the cancelAfterContext sweep over every context check Load itself
//     performs (entry, one per database file, one per assembled record),
//     reusing the helper from history_cancellation_test.go, and
//   - the package's test-only scanQueryHook / scanRowHook injection points,
//     which fire a real context.WithCancel scope exactly when the scan
//     reaches a chosen checkpoint (after the schema probe, or at a specific
//     row). Because cancel() cascades synchronously through cancelCtx
//     children, the next ctx.Err() check in the row loop deterministically
//     observes context.Canceled.
//
// Every hook-using test also proves the database file is immediately
// renamable and deletable after Load returns (see assertDBFileReleased):
// on Windows an unclosed SQLite handle fails both with a sharing
// violation, so this is the handle-leak canary for mid-scan cancellation.
// These tests never run in parallel and always restore both hooks to nil
// via t.Cleanup; the hook closures only touch test-owned state.

// setScanHooks installs the package's test-only scan hooks and guarantees
// they are restored to their production value (nil) when the test ends.
func setScanHooks(t *testing.T, query func(context.Context), row func(context.Context)) {
	t.Helper()
	if scanQueryHook != nil || scanRowHook != nil {
		t.Fatalf("scan hooks must not be installed concurrently: query installed=%t row installed=%t", scanQueryHook != nil, scanRowHook != nil)
	}
	scanQueryHook, scanRowHook = query, row
	t.Cleanup(func() { scanQueryHook, scanRowHook = nil, nil })
}

// zcodeLoadFixture builds fileCount synthetic ZCode model_usage databases
// with rowCount usage rows each, under one granted directory.
func zcodeLoadFixture(t *testing.T, fileCount, rowCount int) (root string, paths []string) {
	t.Helper()
	root = t.TempDir()
	for f := 0; f < fileCount; f++ {
		path := filepath.Join(root, fmt.Sprintf("shard-%d.sqlite", f))
		makeZcodeDB(t, path)
		for i := 0; i < rowCount; i++ {
			insertZcodeUsage(t, path, fmt.Sprintf("row-%d-%d", f, i), "glm-5.2", int64(1790000001000+i), 100, 30, 5, 20)
		}
		paths = append(paths, path)
	}
	return root, paths
}

// zcodeLoadWith runs one adapter load under the given scope.
func zcodeLoadWith(ctx context.Context, input string) (adapter.LoadResult, error) {
	return Adapter().Load(adapter.Options{Source: adapter.ZCodeSQLiteSource, Input: input, Context: ctx})
}

func assertZcodeContextCanceled(t *testing.T, err error) {
	t.Helper()
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled load must surface context.Canceled, got err=%v", err)
	}
}

func assertZcodeNoPartialResult(t *testing.T, res adapter.LoadResult) {
	t.Helper()
	if len(res.Records) != 0 || len(res.Issues) != 0 || res.Quarantined != 0 || len(res.MessageUpdates) != 0 {
		t.Fatalf("cancelled load must not return a partial result: %#v", res)
	}
}

// assertDBFileReleased proves the scan left no open handle on the database:
// immediately after Load returns the file must be renamable and deletable.
// On Windows an unclosed SQLite handle makes both operations fail with a
// sharing violation, so this is the handle-leak canary for the read-only
// scan; on POSIX it still proves the file is gone after Remove. It also
// fails if the scan left SQLite sidecar files (-wal/-shm/-journal) beside
// the database, which a mode=ro&immutable=1 scan must never create. A
// failure here is reported as-is: no retry, no skip.
func assertDBFileReleased(t *testing.T, path string) {
	t.Helper()
	renamed := path + ".released"
	if err := os.Rename(path, renamed); err != nil {
		t.Fatalf("database must be renamable immediately after Load returns (on Windows a sharing violation means a leaked handle): %v", err)
	}
	if err := os.Remove(renamed); err != nil {
		t.Fatalf("database must be deletable immediately after Load returns: %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("list database directory: %v", err)
	}
	base := filepath.Base(path)
	for _, entry := range entries {
		for _, suffix := range []string{"-wal", "-shm", "-journal"} {
			if entry.Name() == base+suffix {
				t.Fatalf("read-only scan must not create SQLite sidecar file %s", entry.Name())
			}
		}
	}
}

// deadlineMidScanContext is a test double for a scan scope whose per-database
// deadline expires mid-iteration. It implements the context contract (Done is
// a real channel; Err is non-nil exactly once Done has closed) so the
// context.WithTimeout scope readDB derives from it propagates the expiry
// exactly like a real timer firing — but at a test-chosen checkpoint and
// without waiting on wall time.
type deadlineMidScanContext struct {
	context.Context
	done chan struct{}
	once sync.Once
}

func newDeadlineMidScanContext() *deadlineMidScanContext {
	return &deadlineMidScanContext{Context: context.Background(), done: make(chan struct{})}
}

func (c *deadlineMidScanContext) Done() <-chan struct{} { return c.done }

func (c *deadlineMidScanContext) Err() error {
	select {
	case <-c.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

// expire flips the scope to DeadlineExceeded. It is idempotent and safe to
// call from a scan hook.
func (c *deadlineMidScanContext) expire() {
	c.once.Do(func() { close(c.done) })
}

// TestSQLiteLoadPreCancelledSurfacesContextError pins the entry checkpoint:
// an already-cancelled scope fails the load before any database is opened,
// with no partial result.
func TestSQLiteLoadPreCancelledSurfacesContextError(t *testing.T) {
	root, _ := zcodeLoadFixture(t, 1, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := zcodeLoadWith(ctx, root)
	assertZcodeContextCanceled(t, err)
	assertZcodeNoPartialResult(t, res)
}

// TestSQLiteLoadExpiredDeadlineSurfacesDeadlineExceeded pins the same entry
// checkpoint for a real, already-expired deadline scope.
func TestSQLiteLoadExpiredDeadlineSurfacesDeadlineExceeded(t *testing.T) {
	root, _ := zcodeLoadFixture(t, 1, 1)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Minute))
	defer cancel()

	res, err := zcodeLoadWith(ctx, root)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired deadline must surface context.DeadlineExceeded, got err=%v", err)
	}
	assertZcodeNoPartialResult(t, res)
}

// TestSQLiteLoadCancellationSweepDiscardsPartialResult cancels at every
// context check Load performs on the caller's scope: a complete run with a
// never-cancelling counting scope measures the total (entry, one per
// database file, one per assembled record), then each prefix length either
// completes with exactly the baseline result or fails with context.Canceled
// and a fully empty result — never a prefix of the scan.
func TestSQLiteLoadCancellationSweepDiscardsPartialResult(t *testing.T) {
	root, _ := zcodeLoadFixture(t, 2, 3)

	probe := &cancelAfterContext{Context: context.Background(), cancelAfter: math.MaxInt}
	baseline, err := zcodeLoadWith(probe, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.Records) != 6 {
		t.Fatalf("synthetic baseline must hold six records, got %d", len(baseline.Records))
	}
	total := probe.calls
	if total < 8 {
		t.Fatalf("synthetic load is too small to exercise mid-load cancellation: %d checks", total)
	}

	for k := 1; k <= 2*total; k++ {
		res, err := zcodeLoadWith(&cancelAfterContext{Context: context.Background(), cancelAfter: k}, root)
		switch {
		case err == nil:
			if !reflect.DeepEqual(res, baseline) {
				t.Fatalf("uncancelled load (k=%d) must equal the baseline result:\n%#v\n%#v", k, res, baseline)
			}
		default:
			assertZcodeContextCanceled(t, err)
			assertZcodeNoPartialResult(t, res)
		}
	}

	// The halfway check lands after record assembly has started (mid file
	// for this input), proving a cancellation arriving between two records
	// never leaks a half-built result.
	mid := &cancelAfterContext{Context: context.Background(), cancelAfter: total / 2}
	res, err := zcodeLoadWith(mid, root)
	assertZcodeContextCanceled(t, err)
	assertZcodeNoPartialResult(t, res)
}

// TestSQLiteLoadQueryPhaseCancellationDiscardsPartialResult pins the query
// boundary checkpoint: the scope is cancelled after the schema probe but
// immediately BEFORE the main model_usage query is issued, so the query
// call itself must fail fast with the context error, row iteration must
// never start, and the database file must already be releasable when Load
// returns. This does NOT cover a cancellation arriving while the driver is
// already executing a query mid-flight; that belongs to the driver layer.
func TestSQLiteLoadQueryPhaseCancellationDiscardsPartialResult(t *testing.T) {
	_, paths := zcodeLoadFixture(t, 1, 2)
	ctx, cancel := context.WithCancel(context.Background())
	queryCalls, rowCalls := 0, 0
	setScanHooks(t,
		func(context.Context) { queryCalls++; cancel() },
		func(context.Context) { rowCalls++ })

	res, err := zcodeLoadWith(ctx, paths[0])
	assertZcodeContextCanceled(t, err)
	assertZcodeNoPartialResult(t, res)
	if queryCalls != 1 {
		t.Fatalf("query hook must fire exactly once at the query boundary, got %d calls", queryCalls)
	}
	if rowCalls != 0 {
		t.Fatalf("cancelled query must never start row iteration, got %d row hooks", rowCalls)
	}
	assertDBFileReleased(t, paths[0])
}

// TestSQLiteLoadRowIterationCancellationDiscardsPartialResult pins the row
// checkpoint: the scope is cancelled exactly at the third row iteration,
// after rows.Next() has already delivered three rows — so row processing
// has provably started — yet the load must fail with the context error and
// discard every observation scanned so far, and the database file must be
// immediately renamable and deletable after return.
func TestSQLiteLoadRowIterationCancellationDiscardsPartialResult(t *testing.T) {
	const rowCount = 4
	const cancelAtRow = 3
	_, paths := zcodeLoadFixture(t, 1, rowCount)
	ctx, cancel := context.WithCancel(context.Background())
	hookCalls := 0
	setScanHooks(t, nil, func(context.Context) {
		hookCalls++
		if hookCalls == cancelAtRow {
			cancel()
		}
	})

	res, err := zcodeLoadWith(ctx, paths[0])
	assertZcodeContextCanceled(t, err)
	assertZcodeNoPartialResult(t, res)
	if hookCalls != cancelAtRow {
		t.Fatalf("row iteration must have started and stopped exactly at row %d, got %d iterations", cancelAtRow, hookCalls)
	}
	assertDBFileReleased(t, paths[0])
}

// TestSQLiteLoadDeadlineMidScanDiscardsPartialResult pins the mid-scan
// deadline: a scope whose deadline flips at the first row iteration (after
// rows.Next() has delivered a row, proving iteration started) must make the
// load fail with context.DeadlineExceeded, discard every observation, and
// release the database file. The handshake waits for the derived scan scope
// to observe the expiry, so the outcome never races the propagation.
func TestSQLiteLoadDeadlineMidScanDiscardsPartialResult(t *testing.T) {
	_, paths := zcodeLoadFixture(t, 1, 3)
	deadline := newDeadlineMidScanContext()
	hookCalls := 0
	setScanHooks(t, nil, func(scanCtx context.Context) {
		hookCalls++
		deadline.expire()
		<-scanCtx.Done()
	})

	res, err := zcodeLoadWith(deadline, paths[0])
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("mid-scan deadline must surface context.DeadlineExceeded, got err=%v", err)
	}
	assertZcodeNoPartialResult(t, res)
	if hookCalls < 1 {
		t.Fatalf("deadline must fire after row iteration started, got %d iterations", hookCalls)
	}
	assertDBFileReleased(t, paths[0])
}

// TestSQLiteCancellationReleasesDatabase is the Windows stress entry point:
// a load cancelled mid row-iteration must leave the database file
// immediately renamable and deletable, with no retry loop and no skip. CI
// runs this exact name with -count=50 on Windows, where a leaked SQLite
// handle makes the rename/delete assertions fail with a sharing violation.
func TestSQLiteCancellationReleasesDatabase(t *testing.T) {
	const rowCount = 4
	const cancelAtRow = 2
	_, paths := zcodeLoadFixture(t, 1, rowCount)
	ctx, cancel := context.WithCancel(context.Background())
	hookCalls := 0
	setScanHooks(t, nil, func(context.Context) {
		hookCalls++
		if hookCalls == cancelAtRow {
			cancel()
		}
	})

	res, err := zcodeLoadWith(ctx, paths[0])
	assertZcodeContextCanceled(t, err)
	assertZcodeNoPartialResult(t, res)
	if hookCalls != cancelAtRow {
		t.Fatalf("row iteration must have started and stopped exactly at row %d, got %d iterations", cancelAtRow, hookCalls)
	}
	assertDBFileReleased(t, paths[0])
}

// TestSQLiteLoadReleasesDatabaseFileAfterReturn proves resource release on
// the normal and error paths: after a successful multi-database load, after
// a missing-table failure, and after a mid-iteration row-parse failure,
// every database file must be immediately renamable and deletable and leave
// no sidecar files.
func TestSQLiteLoadReleasesDatabaseFileAfterReturn(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		root, paths := zcodeLoadFixture(t, 2, 2)
		res, err := zcodeLoadWith(context.Background(), root)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Records) != 4 {
			t.Fatalf("baseline load must return four records, got %d", len(res.Records))
		}
		for _, path := range paths {
			assertDBFileReleased(t, path)
		}
	})
	t.Run("missing model_usage", func(t *testing.T) {
		root := t.TempDir()
		dbPath := filepath.Join(root, "db.sqlite")
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatal(err)
		}
		db, err := sql.Open("sqlite", dbPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`CREATE TABLE other (id TEXT)`); err != nil {
			db.Close()
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}

		_, err = zcodeLoadWith(context.Background(), root)
		if err == nil || !strings.Contains(err.Error(), "model_usage") {
			t.Fatalf("expected missing model_usage error, got %v", err)
		}
		assertDBFileReleased(t, dbPath)
	})
	t.Run("invalid row", func(t *testing.T) {
		_, paths := zcodeLoadFixture(t, 1, 1)
		dbPath := paths[0]
		// Cache tokens above input_tokens cannot be reconciled, so the
		// scan fails after the query has started iterating rows.
		insertZcodeUsage(t, dbPath, "row-invalid", "glm-5.2", 1790000005000, 10, 30, 5, 20)

		_, err := zcodeLoadWith(context.Background(), dbPath)
		if err == nil || !strings.Contains(err.Error(), "cache tokens exceeding") {
			t.Fatalf("expected cache overflow error, got %v", err)
		}
		assertDBFileReleased(t, dbPath)
	})
}
