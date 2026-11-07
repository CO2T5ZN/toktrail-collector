#!/bin/sh
# Local CI preflight, intentionally tied to the workflow's pinned toolchain.
# Native Windows gates are handled by check-ci.ps1, never claimed by this script.
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"
go_bin=${TOKTRAIL_GO:-go}
expected=go1.24.13
actual=$("$go_bin" env GOVERSION)
if [ "$actual" != "$expected" ]; then
  printf 'CI toolchain mismatch: got %s, need %s. Set TOKTRAIL_GO to the matching go executable.\n' "$actual" "$expected" >&2
  exit 1
fi
export GOPROXY=off GOTOOLCHAIN=local
"$go_bin" version
"$go_bin" vet ./...
"$go_bin" test ./... -count=1
"$go_bin" test ./internal/scheduler ./internal/syncclient ./internal/syncretry -count=50 -shuffle=on
"$go_bin" test -race ./internal/scheduler ./internal/syncclient ./internal/syncretry -count=1
# Cross-compilation is explicitly not native Windows acceptance.
GOOS=windows GOARCH=amd64 "$go_bin" vet ./...
GOOS=windows GOARCH=amd64 "$go_bin" build ./...
GOOS=windows GOARCH=arm64 "$go_bin" build ./...
# Pin the same compiler in the subprocess release builder, not just this shell.
case "$go_bin" in
  /*) release_go=$go_bin ;;
  *) release_go=$(command -v "$go_bin") ;;
esac
GO="$release_go" TOKTRAIL_RELEASE_E2E=1 "$go_bin" test ./tools/release -run '^TestEndToEndRelease$' -count=1 -v
printf '\nPASS: local pinned-toolchain preflight; NOT RUN: native Windows scheduler/connect/smoke.\n'
