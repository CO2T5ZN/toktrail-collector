#!/usr/bin/env bash
# Re-apply and verify the vendored modernc.org/sqlite cancellation patch.
#
# The repository vendors modernc.org/sqlite v1.38.2, which leaks the driver
# rows of a cancelled query (the deferred cancellation branch of
# (*stmt).query overwrites r with nil without closing it). Upstream fixed
# this in v1.40.1 (gitlab.com/cznic/sqlite tag d33e568,
# "close_rows_on_canceled_context"), which is itself Go 1.24 compatible.
# This repository carries the same change as a vendor patch because the
# current build environment cannot reach module sources (proxy.golang.org
# connection timeout, goproxy.cn 403), so the v1.40.1 module and its full
# matching dependency set cannot be fetched to redo go mod tidy/vendor.
# Prefer the real upgrade once module sources are reachable; see the
# upgrade-path section of
# docs/vendor-patches/modernc-sqlite-close-rows-on-canceled-context.md.
#
# `go mod vendor` rewrites vendor/modernc.org/sqlite from the pristine
# module and silently drops the patch. Run this script afterwards:
#
#   scripts/vendor-patch-modernc-sqlite.sh apply    # re-apply + build + test
#   scripts/vendor-patch-modernc-sqlite.sh verify   # read-only CI gate
#
# 'apply' is idempotent (re-running on an already patched tree is a no-op)
# and fails automatically when the patch does not apply cleanly. The
# regression suite in internal/sqlitecancel also fails in plain
# `go test ./...` when the patch is missing, on every platform, without
# needing this script.
set -euo pipefail

cd "$(dirname "$0")/.."

PATCH="docs/vendor-patches/modernc-sqlite-v1.38.2-close-rows-on-canceled-context.patch"
TARGET="vendor/modernc.org/sqlite/sqlite.go"
MODE="${1:-verify}"

patch_applied() {
    # `git apply --check --reverse` succeeds exactly when the tree already
    # carries the patch.
    git apply --check --reverse "$PATCH" >/dev/null 2>&1
}

case "$MODE" in
verify)
    if patch_applied; then
        echo "OK: $TARGET carries the close-rows-on-canceled-context patch."
    else
        echo "FAIL: patch not detected on $TARGET." >&2
        echo "Run: scripts/vendor-patch-modernc-sqlite.sh apply" >&2
        exit 1
    fi
    ;;
apply)
    if patch_applied; then
        echo "Patch already applied to $TARGET."
    else
        if [ ! -f "$TARGET" ]; then
            echo "FAIL: $TARGET missing; run 'go mod vendor' first." >&2
            exit 1
        fi
        git apply "$PATCH"
        echo "Patch applied to $TARGET."
    fi
    go build ./...
    go test ./internal/sqlitecancel -count=1
    echo "OK: build and regression suite passed with the patch applied."
    ;;
*)
    echo "usage: $0 [apply|verify]" >&2
    exit 2
    ;;
esac
