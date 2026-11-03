// Package sqlitecancel holds the driver-level regression suite for the
// vendored modernc.org/sqlite driver (v1.38.2) cancellation fix.
//
// Background: modernc.org/sqlite v1.38.2 discards the driver rows (r) of a
// query executed with a cancellable context without closing them whenever
// the context is cancelled after the query already created rows but before
// (*stmt).query returned, leaking the unfinalized sqlite3_stmt handle and
// the bound-parameter allocations. On Windows the leaked statement keeps
// the database file open, which makes file deletion fail until process
// exit. The local vendor patch documented in docs/vendor-patches/ applies
// the upstream fix (introduced upstream in v1.40.1, tag d33e568
// "close_rows_on_canceled_context"): the deferred cancellation branch of
// (*stmt).query closes r before overwriting it with nil.
//
// This package contains two gates that both run in the regular
// `go test ./...` suite (vendor directories are ignored by ./..., so the
// tests must live in the repository tree):
//
//   - TestVendoredSqliteQueryCancelBranchClosesRows parses the vendored
//     driver source (AST gate) and fails when the cancellation-branch fix
//     is missing — for example after someone re-runs `go mod vendor`
//     without re-applying the patch (see
//     scripts/vendor-patch-modernc-sqlite.sh). It fails closed on any
//     vendored version other than the pinned v1.38.2.
//
//   - TestQueryCancelOverlayDeterministic runs a deterministic behavioural
//     regression inside the vendored package via `go test -overlay` (the
//     production vendor tree is never modified): a hook injected right
//     after the rows handover in the SQLITE_ROW branch cancels the context
//     and sets the done flag, synchronously driving the deferred
//     cancellation branch of (*stmt).query while the freshly created rows
//     are alive — no scheduling race, no sleeps, no network. The inner
//     test then proves the rows were closed by writing from a second
//     connection with busy_timeout=0 (an unfinalized paused SELECT keeps a
//     shared lock and fails the write with SQLITE_BUSY) and, on Windows,
//     by requiring the database file to be deletable after all
//     connections are closed.
//
// Bidirectional validation: on pristine v1.38.2 both gates fail (the
// overlay test reports the SQLITE_BUSY leak; the AST gate reports the
// missing fix); with the patch applied both pass.
package sqlitecancel
