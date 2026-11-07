#!/bin/sh
# Build orchestration only. Protocol, signing and installation stay in Go.
set -eu

usage() {
  echo 'Usage: sh scripts/release.sh [build|build-target|assemble] VERSION [OS ARCH] [--dist ROOT] [--key PEM] [--go EXE]' >&2
  exit 2
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_dir"
mode=build
case "${1:-}" in
  build|build-target|assemble) mode=$1; shift ;;
esac
[ "$#" -gt 0 ] || usage
version=$1
shift
target_os=
target_arch=
if [ "$mode" = build-target ]; then
  [ "$#" -ge 2 ] || usage
  target_os=$1
  target_arch=$2
  shift 2
  case "$target_os/$target_arch" in
    darwin/amd64|darwin/arm64|linux/amd64|linux/arm64|windows/amd64|windows/arm64) ;;
    *) echo 'Unsupported target platform' >&2; exit 2 ;;
  esac
fi
dist_root=dist
key_path=
go_bin=${GO:-go}
while [ "$#" -gt 0 ]; do
  [ "$#" -ge 2 ] || usage
  [ -n "$2" ] || usage
  case "$1" in
    --dist) dist_root=$2 ;;
    --key) key_path=$2 ;;
    --go) go_bin=$2 ;;
    *) usage ;;
  esac
  shift 2
done
[ -n "$dist_root" ] && [ -n "$go_bin" ] || usage
if [ "$mode" = build-target ] && [ -n "$key_path" ]; then
  echo 'build-target does not accept a signing key; sign only in assemble' >&2
  exit 2
fi
# Validate before interpolating the version into a path or linker flags.
"$go_bin" run ./tools/release validate-version -version "$version"
mkdir -p -- "$dist_root"
dist_root=$(CDPATH= cd -- "$dist_root" && pwd)
dist_dir=$dist_root/$version
if [ "$mode" != assemble ]; then
  if ! mkdir "$dist_dir"; then
    echo 'Release directory already exists or cannot be created; use a fresh version/output root' >&2
    exit 1
  fi
fi

build_target() {
  build_os=$1
  build_arch=$2
  extension=
  if [ "$build_os" = windows ]; then extension=.exe; fi
  echo "Building $build_os/$build_arch"
  # Windows releases bundle the GUI helper (toktrail-background.exe) next to
  # the collector inside the platform archive. It is built FIRST, as a
  # windowed-subsystem binary (-H=windowsgui: no console window at runtime),
  # stripped like every release binary, with the same main.version linker
  # variable. The dist file keeps the versioned layout
  # toktrail-background-VERSION-windows-ARCH.exe; the assembler packs it into
  # the zip under the fixed archive entry name toktrail-background.exe and
  # verifies its PE subsystem is WINDOWS_GUI (a plain console go build is
  # rejected there as well).
  # Fail closed when the helper source is missing: a formal Windows release
  # must never silently ship without the helper.
  if [ "$build_os" = windows ]; then
    if [ ! -d ./cmd/toktrail-background ]; then
      echo "release: cmd/toktrail-background is missing; refusing to build a windows release without the GUI helper" >&2
      exit 1
    fi
    GOOS=$build_os GOARCH=$build_arch CGO_ENABLED=0 "$go_bin" build -trimpath \
      -ldflags "-H=windowsgui -s -w -X main.version=$version" \
      -o "$dist_dir/toktrail-background-$version-$build_os-$build_arch$extension" ./cmd/toktrail-background
  fi
  # Pin the release public key into the collector binary so `toktrail upgrade`
  # can verify a release on a machine that has no copy of the key. The value is
  # base64 of the PEM text: a linker flag is one token, and the key is public
  # material. Set TOKTRAIL_RELEASE_PUBKEY to the same pin the bootstrap scripts
  # use; when it is unset the binary carries no anchor and `upgrade` requires an
  # explicit --pubkey (never an unverified install).
  upgrade_ldflags=
  if [ -n "${TOKTRAIL_RELEASE_PUBKEY:-}" ]; then
    if [ -f "${TOKTRAIL_RELEASE_PUBKEY}" ]; then
      upgrade_ldflags=" -X main.releasePubKeyB64=$(base64 < "${TOKTRAIL_RELEASE_PUBKEY}" | tr -d '\n')"
    else
      # Fail loudly: a silently anchor-less release ships a binary whose
      # `toktrail upgrade` can only ever refuse, and nobody notices until a user
      # reports it.
      echo "release: TOKTRAIL_RELEASE_PUBKEY is set but $TOKTRAIL_RELEASE_PUBKEY is not a readable file" >&2
      exit 1
    fi
  fi
  GOOS=$build_os GOARCH=$build_arch CGO_ENABLED=0 "$go_bin" build -trimpath \
    -ldflags "-s -w -X main.version=$version$upgrade_ldflags" \
    -o "$dist_dir/toktrail-$version-$build_os-$build_arch$extension" ./cmd/toktrail
  # Retain the schema-1 filename for existing bootstrap consumers.
  GOOS=$build_os GOARCH=$build_arch CGO_ENABLED=0 "$go_bin" build -trimpath \
    -ldflags "-s -w -X main.version=$version" \
    -o "$dist_dir/toktrail-release-$version-$build_os-$build_arch$extension" ./cmd/toktrail-installer
}

case "$mode" in
  build-target)
    build_target "$target_os" "$target_arch"
    exit 0
    ;;
  build)
    for build_os in darwin linux windows; do
      for build_arch in amd64 arm64; do
        build_target "$build_os" "$build_arch"
      done
    done
    ;;
esac
if [ -n "$key_path" ]; then
  "$go_bin" run ./tools/release assemble -version "$version" -dist-dir "$dist_dir" -key "$key_path"
else
  "$go_bin" run ./tools/release assemble -version "$version" -dist-dir "$dist_dir"
fi
