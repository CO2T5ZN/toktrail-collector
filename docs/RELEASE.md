# TokTrail Collector release and installation

The collector repository owns its distribution protocol, installer and release tooling. Build and publication orchestration live in shell and GitHub Actions. Cryptographic signing uses standard-library Ed25519 and artifact hashes use SHA-256. The collector additionally vendors pure-Go zstd and SQLite dependencies for offline builds; Cursor authentication does not require a system sqlite3 executable or cgo.

## Ownership

| Location | Responsibility |
| --- | --- |
| `.github/workflows/ci.yml` | Linux/macOS/Windows vet and tests; native Windows gate (structured test logs, Task Scheduler and connect integration, smoke script); signed-release E2E with a temporary test key |
| `.github/workflows/release.yml` | Tag validation, Linux tests and signed E2E, native Windows gate on the tagged commit, six-target build matrix, protected signing, verification and automatic GitHub Release publication |
| `scripts/release.sh` | Shared local/CI build entry point; cross-compilation and assembly orchestration |
| `tools/release` | Consume built binaries, create deterministic archives, assemble/sign the manifest, emit and sign the version-bound capabilities metadata, and render pinned bootstrap scripts |
| `tools/release/templates` | Reviewable POSIX and PowerShell bootstrap templates, embedded by the assembly tool |
| `internal/distribution` | Strict manifest, version, signature, hash and artifact naming protocol |
| `internal/installer` | Bounded downloads, verification, safe extraction, downgrade checks, binary replacement and in-place upgrade |
| `cmd/toktrail-installer` | User-facing installation and verification CLI |
| `cmd/toktrail-release` | Maintainer keygen/sign/verify commands and compatibility for existing build/install commands |

There is one build implementation in `scripts/release.sh`. The legacy `toktrail-release build` command delegates to it and requires a source checkout and a POSIX shell (Git Bash is suitable on Windows). The assembler does not invoke the Go compiler. The user installer does not depend on the maintainer tools. A separate release repository is unnecessary for the current product.

## Trust and compatibility

Each version has a schema-1 `manifest.json` describing six platform artifacts, exact sizes and hashes. Its raw bytes are signed; `manifest.json.sig` is a detached 64-byte Ed25519 signature. Versions, manifest fields, artifact filenames, bootstrap arguments and install flags remain compatible with existing setup/download consumers.

Each version additionally ships a signed `capabilities.json`. New releases emit the closed schema-2 shape `{schema:2, product:"toktrail-collector", version, tools:[string], sources:[{tool,source,mode,protocol}]}`. Cursor declares `mode:"account-network"` and `protocol:1`; local sources declare `mode:"local"`. Readers retain compatibility with published schema-1 documents `{schema:1, product, version, tools}`, but a legacy tool name alone cannot enable account-network collection. Unknown fields, trailing data, wrong schema/product or an invalid version are rejected. The tool/source lists come from the compiled registry, and the document is generated once for all platforms of the release. `capabilities.json.sig` is a detached raw 64-byte Ed25519 signature over the exact document bytes, verified against the same pinned public key as the manifest. The manifest format is unchanged. Deploy schema-2-aware website consumers and compatible account-source Server/projection support before pinning a Cursor-capable release and enabling its website gate.

The installer executable is built from `cmd/toktrail-installer`, but its published filename remains `toktrail-release-<version>-<os>-<arch>[.exe]`. This preserves existing manifest and bootstrap consumers. The maintainer command is built separately from `cmd/toktrail-release` when needed.

Verification requires an explicit trusted public key via `-pubkey`. Obtain it independently of an untrusted download mirror. Unknown manifest fields, trailing JSON, invalid sizes/hashes, duplicate or unsupported platforms, unsafe filenames, invalid signatures and version mismatches fail closed. Every downloaded archive and extracted binary is checked against the signed size and SHA-256. The installer also checks its own executable hash against the manifest.

The installer only replaces the collector binary. Binding, read grants, scheduling and first upload remain explicit collector commands. The existing web setup command chains these operations after successful installation. Download hosting is independent of the upload endpoint.

## Keys

Generate a key in an explicitly chosen private location:

```sh
GOCACHE="$PWD/.gocache" GOPROXY=off go run ./cmd/toktrail-release keygen \
  -out .release-keys/release-2026.pem
```

The private PKCS#8 PEM file is created with mode `0600` on POSIX systems, without overwriting an existing file. Windows mode bits do not establish NTFS ACL protection; keep the private key in a user-restricted location. The public key is printed to stdout. Private keys must not be committed or logged. Pin files may contain multiple public keys during rotation; empty/unparsable pins and private-key PEM blocks used as pins are rejected.

### Backup, loss and rotation

Keep an encrypted recovery copy of the private key in a password manager or secret vault, plus an independently stored encrypted offline backup. Keep the public key and its fingerprint separately so a restored private key can be checked against the established trust root. Back up the actual key, not just its path or public key. Test restoration with a disposable signed message before depending on the backup; never print the private key in CI logs.

If only the developer computer is lost, the `release` environment secret can continue signing in GitHub Actions. GitHub does not offer a supported plaintext export of Actions secrets. Restore local signing from the independent backup; do not add a workflow that exposes the secret to logs or artifacts to recover it. If every private-key copy, including the CI secret, is unavailable, the old public key cannot recover it and future releases must use a new key. Previously signed releases remain verifiable with their original public key.

For a planned rotation, generate a new key, distribute its public pin through an independently trusted channel, then update `TOKTRAIL_RELEASE_PRIVATE_KEY` and `TOKTRAIL_RELEASE_PUBLIC_KEY` together before releasing a new version. Explicit `-pubkey` files support overlapping old/new public keys for transition; newly assembled bootstrap scripts pin the signing key used for that release. Existing bootstrap scripts keep their original key, artifact hashes and version: they do not automatically learn a replacement key. Update the web setup site's verified bootstrap files and selected release version as part of the rollout. Retain old public keys for historical verification; do not rewrite or re-sign an already published version.

If the key may have been stolen rather than simply lost, treat it as compromised: stop its use, rotate the secret and trusted pins, and notify users through an established trusted channel. The current protocol has no automatic key revocation or automatic trusted-key rotation service. Remove compromised keys from pins used to authorize future installations; a valid old signature alone cannot establish that an artifact predates the compromise.


## Local release

From the collector repository root, use the build orchestration script:

```sh
GOCACHE="$PWD/.gocache" GOPROXY=off sh scripts/release.sh v0.1.0 \
  --dist dist --key /trusted/path/release.pem
```

The script creates a fresh `dist/v0.1.0/`, builds twelve binaries for darwin/linux/windows × amd64/arm64, then runs the metadata assembler. It refuses an existing version directory; a failed build leaves its partial directory for inspection. Use a fresh output root for a retry. Cross-compilation uses `CGO_ENABLED=0`, `-trimpath` and `-ldflags "-s -w -X main.version=<version>"`. The Go executable can be selected with `--go /path/to/go`; environment settings such as `GOPROXY` and `GOCACHE` are inherited.

```text
dist/v0.1.0/
  toktrail-v0.1.0-<os>-<arch>[.exe]         raw collector
  toktrail-release-v0.1.0-<os>-<arch>[.exe] standalone installer/verifier
  toktrail-v0.1.0-<os>-<arch>.tar.gz|.zip   collector archive
  manifest.json                           strict signed metadata
  manifest.json.sig                       detached signature
  capabilities.json                       version-bound tool capability statement
  capabilities.json.sig                   detached signature (same key as the manifest)
  install-v0.1.0.sh                        pinned POSIX bootstrap
  install-v0.1.0.ps1                       pinned PowerShell bootstrap
```

Archive creation uses stable metadata (including zero timestamps for USTAR tar archives). This does not guarantee identical Go binaries across different compiler versions. A build without `--key` emits unsigned archives, a manifest and an unsigned `capabilities.json`, without signatures or bootstrap scripts. The legacy `toktrail-release sign -manifest ... -key ...` can sign the manifest separately; it does not generate bootstrap scripts. Use the signed assembly flow to obtain a complete installation release.

The matrix workflow uses the same entry point in two phases:

```sh
# Each matrix runner has a fresh dist root and builds one pair.
sh scripts/release.sh build-target v0.1.0 linux amd64 --dist dist

# After merging all six runners' raw artifacts into dist/v0.1.0:
sh scripts/release.sh assemble v0.1.0 --dist dist --key /trusted/path/release.pem
```

Assembly validates all six targets and refuses existing release metadata. It does not build missing binaries. Assembly also generates the single `capabilities.json` (plus its signature when a key is given) from the one tool registry, so the matrix produces exactly one shared capability statement per version rather than per-platform variants. Legacy builds using the maintainer command delegate to the same script:

```sh
go run ./cmd/toktrail-release build -version v0.1.0 -dist dist -repo . -key /trusted/path/release.pem
```

This command requires a source checkout and a POSIX shell. The recommended approach is to use `scripts/release.sh` directly.

### Pre-release verification

Before pushing a release tag, verify on a real Windows machine (PowerShell 7)
what the release workflow's `windows-check` job will enforce on the tagged
commit — the same gate every pull request already runs:

```powershell
$env:GOPROXY = 'off'
go vet ./...
go test ./... -count=1
$env:TOKTRAIL_WINDOWS_SCHEDULER_E2E = '1'
go test ./internal/scheduler -run '^TestWindowsSchedulerNativeIntegration$' -count=1 -v
Remove-Item Env:TOKTRAIL_WINDOWS_SCHEDULER_E2E
$env:TOKTRAIL_WINDOWS_CONNECT_E2E = '1'
go test ./cmd/toktrail -run '^TestWindowsConnectNativeIntegration$' -count=1 -v
Remove-Item Env:TOKTRAIL_WINDOWS_CONNECT_E2E
go test ./internal/source/hermessqlite ./internal/source/openclawsqlite ./internal/source/zcodesqlite -run '^TestSQLiteCancellationReleasesDatabase$' -count=50 -timeout=5m -v
pwsh -File scripts/windows-smoke.ps1
```

Each command must exit zero, and the two integration runs and the sqlite
stress run must actually run their named test (not skip; the stress run must
produce 50 top-level passes per package). Also run the Linux-side checks that the `check`
job enforces — `go vet ./...`, `go test ./... -count=1`, and the
`TOKTRAIL_RELEASE_E2E=1` signed-chain test from
[CONTRIBUTING](../CONTRIBUTING.md) — then perform the local release build
above. CI re-runs all of this on the tagged commit; verifying first avoids
burning a tag on a gate failure. Workflow operation details, including
failure-diagnostics artifacts and the pinned Go patch version, are in
[CI and release gates](CI.md).

## GitHub release configuration

Workflows are active when this collector directory is the Git repository root, matching the existing CI arrangement. GitHub does not execute a nested project's workflows from the larger local workspace.

Configure the repository's protected `release` environment with:

- Secret `TOKTRAIL_RELEASE_PRIVATE_KEY`: private Ed25519 PEM used only in the signing job. Configure required reviewers on the environment to enforce manual approval; the workflow's environment reference alone does not enforce it.
- Variable `TOKTRAIL_RELEASE_PUBLIC_KEY`: independently configured trusted public-key PEM used to verify the assembled release. Public keys may be published in the repository; the verifier's trusted pin must be established independently of the downloaded release.
- Environment reviewers and tag/deployment restrictions appropriate to the repository. Use repository settings to restrict which team can approve releases.

Push a valid version tag such as `v0.1.0`. The workflow validates it with the shared Go version parser, runs vet, tests and signed E2E with a temporary test key, and runs the full native Windows gate (`windows-check`: the complete test suite on `windows-2025`, the real Task Scheduler and connect integration tests, the sqlite cancel-resource stress — 50 repetitions of `TestSQLiteCancellationReleasesDatabase` in each of the three SQLite source packages — and `scripts/windows-smoke.ps1`) on the tagged commit. The five gate steps collect results independently: one failing gate does not skip the others, so a rejected tag shows every failing gate at once, and any single failure fails `windows-check`. `build` starts only after both `check` and `windows-check` pass, then builds six platform pairs in parallel. Build jobs have read-only repository permissions and receive no signing key. The final signing job (with manual approval when required reviewers are configured) assembles/signs using the private key and verifies every artifact against the independently pinned public key, then automatically publishes the GitHub Release. Only that job has `contents: write` permission. There is no second manual draft-publish step. Tags with a SemVer prerelease suffix (for example `v0.4.0-rc.1`) are published with `--prerelease --latest=false`; stable releases omit an explicit Latest flag and may become Latest on publication, including when publishing an older maintenance version. A stable release selected as Latest is discovered by the website's install and upgrade flow, so finish any mirror synchronization and operator review before approving the release environment. `gh release create` uploads assets while the release is a draft and publishes only after uploads succeed; if a run fails partway, inspect any remaining draft and assets before retrying. Existing releases are not silently overwritten on rerun.

The workflows assume `.github/workflows/` is at the repository root. When `toktrail-collector` is split into an independent Git repository, move `.github/workflows/ci.yml` and `.github/workflows/release.yml` from this directory to the repository root for GitHub to execute them.

Signing keys are written to permission-restricted temporary files outside the artifact directory and removed on step exit. Build artifacts contain only raw binaries; final GitHub Release assets contain archives, raw binaries, manifest, signature, capabilities metadata with its signature, and pinned bootstrap scripts. The CI environment passes `GOPROXY=off` to validate offline buildability.

## Verification and installation

Verify before publishing or after mirroring:

```sh
go run ./cmd/toktrail-release verify \
  -manifest dist/v0.1.0/manifest.json \
  -signature dist/v0.1.0/manifest.json.sig \
  -pubkey /trusted/path/public.pem -version v0.1.0 \
  -dist-dir dist/v0.1.0
```

`verify` is read-only. Omitting `-dist-dir` checks the signature and manifest only. `-platform darwin/arm64` additionally requires that platform.

Verify the signed capabilities metadata the same way (the release workflow runs this exact command before publishing):

```sh
go run ./tools/release verify-capabilities \
  -capabilities dist/v0.1.0/capabilities.json \
  -signature dist/v0.1.0/capabilities.json.sig \
  -pubkey /trusted/path/public.pem -version v0.1.0
```

`verify-capabilities` is read-only and fails closed on a bad signature, a malformed document (unknown fields, trailing data, wrong schema/product), an unexpected tool name, or a version mismatch. The pinned public key may contain several `PUBLIC KEY` blocks for rotation, exactly like manifest verification.

Bootstrap scripts embed the trusted public key and each installer binary's SHA-256. Obtain the script through a trusted channel; downloading script and pins from the same untrusted mirror cannot establish trust.

Both scripts default `BASE_URL`/`-BaseUrl` to the official GitHub release download root for the pinned version (`https://github.com/lich0821/toktrail-collector/releases/download/<version>`) and default `INSTALL_DIR`/`-InstallDir` to `$HOME/.toktrail/bin` (`$env:USERPROFILE\.toktrail\bin` on Windows), so the common case needs no arguments:

```sh
# After obtaining the versioned script through a trusted channel:
sh install-v0.1.0.sh
```

```powershell
./install-v0.1.0.ps1
```

The positional `BASE_URL [INSTALL_DIR]` form (POSIX) and `-BaseUrl`/`-InstallDir` flags (PowerShell) still work for mirrors, air-gapped installs, or test harnesses that pass a `file://` root:

```sh
sh install-v0.1.0.sh https://downloads.example.invalid/toktrail/v0.1.0 "$HOME/.local/bin"
```

```powershell
./install-v0.1.0.ps1 -BaseUrl 'https://downloads.example.invalid/toktrail/v0.1.0' -InstallDir "$HOME/.local/bin"
```

The `.invalid` host above is a placeholder for a custom mirror; it is not the default. A public production download host beyond the default GitHub release root is still operator configuration when one is needed.

### `--connect` / `-ConnectUrl`: bootstrap-then-connect in one step

Both bootstrap scripts accept an optional one-time connect link. When given, the script runs the just-installed `toktrail connect <link>` immediately after a successful binary install, using the absolute path of the binary it just placed:

```sh
sh install-v0.1.0.sh --connect '<ONE_TIME_CONNECT_LINK>'
# or, with an explicit mirror/install dir:
sh install-v0.1.0.sh https://downloads.example.invalid/toktrail/v0.1.0 "$HOME/.local/bin" --connect '<ONE_TIME_CONNECT_LINK>'
```

```powershell
./install-v0.1.0.ps1 -ConnectUrl '<ONE_TIME_CONNECT_LINK>'
```

Standard input and confirmations: the documented invocation pipes the script into a shell (`curl … | sh -s -- …`), so the script's own stdin carries the script text. The emitted script therefore never hands that pipeline to the collector: the `connect` step runs with its standard input redirected from the controlling terminal when one can be opened, and from `/dev/null` otherwise. A confirmation prompt (the Cursor first-time local enable, the local state replacement) reads the terminal, not stdin; with no terminal it reports that it could not confirm and names the manual command, and it never treats EOF or script text as an answer. Never add a step that lets a child inherit the script pipeline's stdin: a child that reads it consumes the remaining script lines.

This is the same "install only replaces the binary; follow-up operations are explicit collector commands" boundary described above, applied to the `curl | sh` bootstrap path: the script does not parse, validate, or evaluate the link (no `eval`/`Invoke-Expression`); it is passed through verbatim as a single argument to `toktrail connect`, which owns link parsing and the bind call. The script treats `connect` as a strictly separate step: a failing `install` call aborts before `connect` ever runs, and a failing `connect` call propagates its exit code as the script's own exit code even though the binary installation itself already succeeded (the binary is not rolled back). `--connect`/`-ConnectUrl` reject a missing or empty value, and the scripts reject unknown flags or extra positional arguments outright rather than silently ignoring them.

Direct installation with an official installer executable supports:

```sh
./toktrail-release-v0.1.0-linux-amd64 install \
  -base-url https://downloads.example.invalid/toktrail/v0.1.0 \
  -version v0.1.0 -pubkey /trusted/path/public.pem -install-dir "$HOME/.local/bin"
```

Use `-dist-dir` instead of `-base-url` for local artifacts. Both together are rejected. Default replacement refuses downgrades; `-allow-downgrade` explicitly permits one. `-no-replace` refuses an existing binary; `-keep-old` retains the previous binary. Extraction rejects path traversal and symlinks and enforces size limits. Downloads have timeouts and bounded reads; errors redact URL credentials and queries. `-skip-self-check` is only for a locally compiled verifier/installer whose hash cannot equal the published artifact. It does not bypass manifest signature, archive or binary checks.

## In-place upgrade

An upgrade is an install with discovery and stricter preconditions. It reuses the exact trust pipeline of `install` — pinned public key, detached manifest signature, strict manifest parsing, exact platform artifact, installer self-check, archive and binary SHA-256 — and changes at most two files: the collector binary at its original absolute path and `<binary>.previous`.

With the standalone installer of the **target** version:

```sh
./toktrail-release-v0.2.0-linux-amd64 upgrade \
  -base-url https://downloads.example.invalid/toktrail/v0.2.0 \
  -version v0.2.0 -pubkey /trusted/path/public.pem
```

Or through the target version's bootstrap script, which then runs the same pinned installer subcommand:

```sh
sh install-v0.2.0.sh --upgrade          # POSIX
./install-v0.2.0.ps1 -Upgrade           # PowerShell
```

Behavior and preconditions (all fail closed, before anything is downloaded or replaced):

- **Original path reuse.** The upgraded binary keeps its original absolute path. With `-install-dir` (script: an explicit `INSTALL_DIR`/`-InstallDir`) that directory must already contain the canonical `toktrail`/`toktrail.exe`. Otherwise the first match on `PATH` is used, with symlinks resolved to the real file; the resolved file name must be canonical, or the upgrade refuses rather than installing a second file. The bootstrap scripts pass no default install directory in upgrade mode, so the pinned installer performs the PATH discovery. Because the absolute path is unchanged, an existing scheduler entry invoking that exact path keeps working without re-registration.
- **PATH discovery is not a device-wide claim.** `PATH` only finds the first match; with multiple installations, symlinks or a binary not on `PATH`, the scheduler may invoke a different path. The upgrade output names the exact path it replaced. If a scheduled task invokes another path, rerun with `-install-dir` pointing at the scheduler's directory. The upgrade never inspects or rewrites scheduler registration to find or fix this.
- **Identifiability.** The existing file must be a regular file and must identify itself via `toktrail version`. An unidentifiable or unknown file is refused; use `install` (or resolve the conflict manually) instead.
- **Version direction.** The target must be newer than the installed version. Same-version reinstalls and downgrades require an explicit `-allow-downgrade`.
- **Previous binary.** The upgrade commands keep the replaced binary at `<binary>.previous` by default (`-keep-old=false` disables). Each upgrade overwrites it with the then-current binary — a one-step chain, not a history. The copy is written atomically (temporary file plus rename) so a failed copy cannot corrupt an existing one. `.previous` must be a regular file if it exists; anything else is a refused conflict.
- **Windows file locks.** Replacing a running executable fails closed with an error asking you to stop scheduled toktrail tasks and retry; there is no retry loop and no fallback to a non-atomic replacement. On POSIX, a running process keeps its old image until it exits, so the next scheduled run picks up the new binary.

Boundaries — what an upgrade deliberately does **not** do:

- It never re-runs `connect` or `bind` (the bootstrap script rejects `--upgrade`/`-Upgrade` combined with `--connect`/`-ConnectUrl`), never reads or writes collector state (grants, cursors, outbox, export journal), never changes upload consent, and never touches scheduler registration. Re-connection is never needed: binding and grants live outside the binary path and survive the replacement.
- There is **no automatic rollback** and no health check of the new binary. A failed upgrade leaves the previous binary in place because every verification happens before the atomic replace. `<binary>.previous` is an unverified convenience snapshot — the old binary has no known trusted signature at that point, so restoring it is a manual recovery step, not a promise of a safe rollback. The verified rollback procedure is: stop scheduled and manual runs, then reinstall the previous **signed** release with `install -allow-downgrade` (and its trusted public key), then confirm with `toktrail version`.
- There is **no "latest" channel**. `-version` is always an exact SemVer taken from trusted release notes; the tool never resolves an alias, so it cannot be tricked into fetching an unintended version.
- State compatibility between versions follows each version's own rules (for example the RC.2 legacy-consent notes below); consult the release notes before upgrading across them. The installer does not validate state schemas.

## Validation and local preview

```sh
gofmt -l cmd internal tools
GOCACHE="$PWD/.gocache" GOPROXY=off go vet ./...
GOCACHE="$PWD/.gocache" GOPROXY=off go test ./... -count=1
GOCACHE="$PWD/.gocache" GOPROXY=off TOKTRAIL_RELEASE_E2E=1 \
  go test ./tools/release -run '^TestEndToEndRelease$' -count=1 -v
```

The gated E2E builds all six pairs using the real shell entry point, signs with an ephemeral test key, verifies all artifacts plus the signed capabilities metadata (through the same `verify-capabilities` subcommand the workflow uses), executes the host bootstrap script, checks the installed version and verifies no-clobber behavior. Cross-compilation does not certify native runtime behavior on the other platforms. CI also runs ordinary tests on Linux, macOS and Windows. macOS notarization, Windows code signing and public deployment remain separate operator tasks.

The workspace's `scripts/dev/local-release.mjs` uses the shared shell entry point and fingerprints `cmd`, `internal`, `tools`, `scripts` and `go.mod`. Cached signed artifacts are preserved; changed source requires a preview version bump. This refactor does not rebuild or replace the running preview release or installed collector.

## RC.2 legacy source grants

RC.2 restores compatibility with preview collectors that stored version-1 grants in `sources.json`. Read-only source listing and diagnostics read that file only when `grants.json` is absent. An existing current file remains authoritative, including empty or fully disabled configurations; malformed or unreadable current files do not trigger legacy fallback.

The first `periodic`, `sources enable`, or `sources disable` operation migrates legacy grants under the existing state-directory process lock. Migration validates the legacy schema, source IDs and absolute paths, preserving grant order, paths, enabled flags and timestamps without requiring inputs to remain accessible. It writes a private temporary file, flushes/closes it and atomically publishes `grants.json` with an exclusive hard link. An existing or concurrently published current file is never replaced. Filesystems without hard-link support return an error and stop the operation before collection or network access. On POSIX systems the new file is mode `0600`; Windows mode bits do not establish NTFS ACL protection.

Migration retains `sources.json` unchanged and does not alter device binding, scheduler configuration, cursors, message baselines, batches or outbox entries. Later consent edits are written to `grants.json` only. Do not run preview and RC.2 collectors alternately against the same state directory: a preview binary reads the retained legacy consent and cannot see later RC.2 revocations. Before any rollback, stop scheduled/manual runs, back up both consent files and state, and reconcile the legacy file to the effective current consent, including disabled entries or an explicitly empty grant list. Restart only after verifying the preview binary sees that reconciled consent. Merely replacing the executable is not a consent-safe rollback.

Regression tests cover read-only fallback, current-file precedence, failed or competing publication, lock rejection, and isolated periodic collection with Codex and Claude Code fixtures. They exercise initial upload, acknowledged historical state and repeated idle runs. This is controlled local evidence, not acceptance of a live-device upgrade or native runtime behavior on all release platforms.

