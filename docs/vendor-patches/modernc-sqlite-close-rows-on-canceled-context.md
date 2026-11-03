# Vendor patch: modernc.org/sqlite — close rows on canceled context

- **Module:** `modernc.org/sqlite` (vendored)
- **Pinned version:** v1.38.2 (`vendor/modules.txt`)
- **Patch file:** `modernc-sqlite-v1.38.2-close-rows-on-canceled-context.patch`
- **Apply/verify:** `scripts/vendor-patch-modernc-sqlite.sh apply|verify`
- **Regression suite:** `internal/sqlitecancel` (runs in plain `go test ./...`)

## Problem

In `(*stmt).query` (vendor/modernc.org/sqlite/sqlite.go), the deferred
cancellation branch of a query executed with a cancellable context was:

```go
defer func() {
    if ctx != nil && atomic.LoadInt32(&done) != 0 {
        r, err = nil, ctx.Err()
    } else if r == nil && err == nil {
        r, err = newRows(s.c, pstmt, allocs, true)
    }
    ...
}()
```

When the context is canceled after the query created rows (`r != nil`) but
before `(*stmt).query` returned — reachable for any query whose statement
loop is still running when `interruptOnDone` flips `done` — the branch
overwrote `r` with `nil` without closing it. The dropped `*rows` owns:

- `pstmt`: a `sqlite3_stmt` handle that is never finalized. On Windows the
  unfinalized statement keeps the database file open, so deleting the file
  fails until process exit.
- `allocs`: libc allocations holding the bound statement arguments, never
  freed.

Because every `newRows` success site immediately executes `pstmt = 0`
(ownership of the handle and the allocs moves to the `*rows`), the leaked
statement is invisible to the deferred `if pstmt != 0 { finalize }` cleanup,
which only ever sees the statement currently being processed.

## Fix (upstream-identical)

The patch is byte-identical to the upstream fix released in
modernc.org/sqlite **v1.40.1** (gitlab.com/cznic/sqlite tag `d33e568`,
"close_rows_on_canceled_context"; the same code is present in the
module-cache copy of v1.47.0, `stmt.go` deferred cleanup). It closes the
rows before discarding them:

```go
defer func() {
    if ctx != nil && atomic.LoadInt32(&done) != 0 {
        if r != nil {
            r.Close()
        }
        r, err = nil, ctx.Err()
    } else if r == nil && err == nil {
        r, err = newRows(s.c, pstmt, allocs, true)
    }
    ...
}()
```

Upstream did not touch `(*stmt).exec` in that commit; `exec`'s `r` is a
`driver.Result` with no `Close`, and its bound allocations are freed by the
inner function's own defer. This patch changes nothing else.

## Why the patch is safe (defer order, ownership, double-finalize)

- **Distinct handles.** The rows' `pstmt` and the local `pstmt` variable
  never alias: every successful `newRows` call is followed by `pstmt = 0`,
  transferring the handle to the rows. The same deferred function's
  `if pstmt != 0 { finalize }` therefore only finalizes the statement
  currently being prepared/stepped, never the rows' statement. Calling
  `r.Close()` (which finalizes `r.pstmt`) cannot double-finalize.
- **Distinct allocations.** After ownership moves to the rows, the local
  `allocs` variable is reassigned by the next statement's `bind`. The
  deferred cleanup never frees `allocs` (in `query`), and `rows.Close()`
  frees exactly the allocations the rows own. No double-free.
- **Exclusive close sites.** The other `r.Close()` call sites in the
  statement loop close the *previous* rows immediately before replacing
  them with new rows, and `newRows` closes and nils itself on error via its
  own defer. The deferred cancellation branch is therefore the only closer
  for rows that reach it, and it nils `r` right after closing.
- **No lock cycle.** The interrupt goroutine may concurrently hold the
  connection mutex (`conn.interrupt`); `rows.Close()` calls
  `sqlite3_finalize` on a FULLMUTEX connection and takes no Go-level lock.

## Known upstream behavior outside this patch's scope (not runtime-verified)

By code reading of both v1.38.2 and v1.47.0: in the multi-statement loop,
the error returns (`return nil, err` after a failed prepare/step of a later
statement) also drop an already-created `r` without closing it — with or
without cancellation. Upstream retains this shape in v1.47.0. This patch
intentionally matches the upstream v1.40.1 fix exactly and does not alter
those paths. This assessment is from source analysis only and has **not**
been verified at runtime.

## Reproduce / verify

```sh
# After any 'go mod vendor' (which wipes the patch):
scripts/vendor-patch-modernc-sqlite.sh apply     # re-apply + go build + regression test
scripts/vendor-patch-modernc-sqlite.sh verify    # read-only check

# Regression suite (already part of 'go test ./...'):
go test ./internal/sqlitecancel -count=1 -v
```

`internal/sqlitecancel` contains two gates, both part of plain
`go test ./...` (Linux/macOS/Windows, no extra CI command, no network):

1. `TestVendoredSqliteQueryCancelBranchClosesRows` — parses the vendored
   source (AST) and fails when the cancellation branch no longer closes the
   rows, e.g. after a bare `go mod vendor`. Fails closed on any vendored
   version other than the pinned v1.38.2.
2. `TestQueryCancelOverlayDeterministic` — deterministic behavioural
   regression via `go test -overlay`: builds a temporary overlay copy of
   the vendored package with a hook injected right after the rows handover
   (`newRows` succeeds, `pstmt = 0`) in the SQLITE_ROW branch of
   `(*stmt).query, plus a virtual same-package test file, and runs it with
   the local toolchain in vendor mode. The hook does
   `cancel(); atomic.StoreInt32(&done, 1)`, which synchronously drives the
   deferred cancellation branch while the freshly created rows are alive —
   no scheduling race and no sleeps. The inner test then proves the rows
   were closed: a second connection with `busy_timeout=0` must be able to
   write (an unfinalized paused SELECT holds a shared lock and fails with
   SQLITE_BUSY on a leak), and on Windows the database file must be
   deletable after all connections close. The production vendor tree is
   never modified by the overlay.

Bidirectional validation performed locally:

- Pristine v1.38.2 (patch temporarily stripped): the overlay test fails
  with `driver leaked the cancelled query's rows: an unfinalized
  statement still holds a shared lock, second-connection write blocked:
  database is locked (5) (SQLITE_BUSY)` and the AST gate fails with a
  re-apply hint.
- Patched vendor (current tree): both gates pass.

## Upgrade path

When network access allows moving to modernc.org/sqlite >= v1.40.1 (with
its matching `modernc.org/libc` and `golang.org/x/sys` requirements), the
fix arrives natively. The upgrade is NOT automatic for the regression
gates and requires manual steps:

1. Verify the new vendored version actually closes rows on cancelled
   contexts (upstream >= v1.40.1, tag d33e568; check the deferred cleanup
   of `(*stmt).query` in the new source shape).
2. Update `internal/sqlitecancel`: the version gate
   (`TestVendoredSqliteQueryCancelBranchClosesRows` fails closed on any
   version other than the pinned v1.38.2), its AST expectations for the
   new source shape (the fix moved to `stmt.go` in newer versions), and
   the overlay hook anchor in `TestQueryCancelOverlayDeterministic`
   (injection site and needle). The overlay behavioural check itself
   stays valid as long as the anchor is updated.
3. Delete `docs/vendor-patches/modernc-sqlite-v1.38.2-close-rows-on-canceled-context.patch`
   and `scripts/vendor-patch-modernc-sqlite.sh`, and re-run
   `go test ./internal/sqlitecancel -count=1` plus the full suite.

## Provenance

- Upstream fix: v1.40.1, gitlab.com/cznic/sqlite tag `d33e568`
  ("close_rows_on_canceled_context"); referenced by
  lightninglabs/taproot-assets#2314.
- Local verification of the fix text: module-cache copy of
  modernc.org/sqlite v1.47.0 `stmt.go` (deferred cleanup of `(*stmt).query`).
- v1.38.2 vendor tree confirmed byte-identical to the pristine module
  before patching.
