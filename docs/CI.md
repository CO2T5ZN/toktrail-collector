# CI and release gates

This document describes what the two GitHub Actions workflows check, how to
operate them, and what to run locally to mirror them. It complements
[RELEASE.md](RELEASE.md), which owns the signing and publication protocol.
Workflows are active only when this directory is the Git repository root;
inside the larger monorepo workspace they are inert documentation.

## What runs where

### CI (`ci.yml`) — every push to `master`, every pull request, manual dispatch

| Check name (branch protection) | Job | Runner |
| --- | --- | --- |
| `Vet + test (ubuntu-latest)` | `test` | ubuntu-latest |
| `Vet + test (macos-latest)` | `test` | macos-latest |
| `Vet + test (windows-latest)` | `test` | windows-2025 |
| `Release end-to-end (Linux, temporary TEST key)` | `release-e2e` | ubuntu-latest |

All jobs use `contents: read` only and read no repository secret. The matrix
job `name` (`Vet + test (<os>)`) and the matrix OS list are stable check
names referenced by branch protection — **do not rename them**. Windows gate
steps were added inside the existing matrix job precisely so required-check
configuration keeps working; every pull request therefore runs the full
Windows gate without any settings change.

Every leg runs `go vet ./...` and the full `go test ./... -count=1` with
`GOPROXY=off` and no module cache, so the vendored offline build path is what
CI validates. The `release-e2e` job runs the signed-release chain test with a
temporary TEST key (`TOKTRAIL_RELEASE_E2E=1`); it needs no production secret.

### The Windows gate

The Windows leg of the `test` job runs these steps in order:

1. `go vet` and the full suite as `go test ./... -count=1 -timeout=3m -v -json`, teed to
   `windows-test-output.jsonl` (structured failure log).
2. **Scheduler native integration**: `TOKTRAIL_WINDOWS_SCHEDULER_E2E=1` +
   `go test ./internal/scheduler -run '^TestWindowsSchedulerNativeIntegration$' -count=1 -v`.
   The test registers, queries, and removes a real per-user Task Scheduler task
   on the runner; it does not trigger the task.
3. **Connect native integration**: `TOKTRAIL_WINDOWS_CONNECT_E2E=1` +
   `go test ./cmd/toktrail -run '^TestWindowsConnectNativeIntegration$' -count=1 -v`.
4. **Smoke**: `pwsh -File scripts/windows-smoke.ps1`. A missing script fails
   the gate by design; there is no silent skip.
5. On failure: diagnostics preparation and artifact upload (below).

Design rules for these steps, enforced by review:

- **Raw exit codes.** PowerShell pipelines (`Tee-Object`) do not fail a step by
  themselves, so every step ends with an explicit
  `if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }` guard. The step result is
  always the underlying command's exit code.
- **No vacuous passes.** `go test -run` exits 0 when the pattern matches no
  test. The integration steps parse the `-json` event stream and require
  exactly one `pass` event for the exact test name; a skip, a mistyped name,
  or an unmatched pattern fails the gate with an `::error::` annotation.
- **Opt-in gates.** The env gates (`TOKTRAIL_WINDOWS_SCHEDULER_E2E`,
  `TOKTRAIL_WINDOWS_CONNECT_E2E`) are step-scoped, so the plain full suite
  stays hermetic: those tests skip themselves when the gate is absent.

### Failure diagnostics artifact

When any Windows step fails, the job uploads
`windows-test-diagnostics-<run_id>-<attempt>` (7-day retention) containing
only `windows-test-output.jsonl`, `windows-scheduler-e2e.jsonl`,
`windows-connect-e2e.jsonl`, and a `DIAGNOSTICS-README.txt`. The README
documents the sensitivity policy: the tests use synthetic fixtures in
temporary runner directories, no secrets or user state are expected, and
known credential shapes (GitHub tokens, AWS key ids, PEM private-key headers)
are redacted before upload as defense in depth. Nothing from the workspace,
caches, or state directories is uploaded. `go test -json` lines can be
inspected directly or filtered, e.g. with
`jq -r 'select(.Action=="fail") | [.Package,.Test] | @tsv'`.

### Release (`release.yml`) — every `v*` tag

Job chain: `check` (tag validation, Linux vet + full tests, signed-release
E2E) and `windows-check` (the native Windows gate, identical to the CI one)
run independently → `build` (six OS/arch pairs, read-only, no signing key) → `publish`
(protected `release` environment, `contents: write`, signing key and public
pin). `build` requires **both** `check` and `windows-check`, so no artifact is
built or published unless every gate passed on the exact tagged commit — the
same Windows gate every pull request runs.

Keep `windows-check` in sync with the Windows leg of the CI `test` job: the
steps are intentionally duplicated (byte-identical apart from the artifact
README wording) rather than shared through a composite action, so each
workflow stays readable top to bottom. When editing one, edit the other in
the same change.

## Operating the workflows

- **Go version.** Both workflows pin `GO_VERSION` (currently `1.24.13`, the
  final 1.24 patch release) at the workflow `env` level and pass it to every
  `actions/setup-go` step. Bump it deliberately in both files together with
  the `go.mod` language version; a patch bump is a normal review item, a
  minor bump must also update `go.mod`. The pin makes builds reproducible and
  avoids surprise toolchain changes under a floating `1.24`.
- **Runners.** `ubuntu-latest`, `macos-latest` (arm64), and `windows-2025`
  (x64). The Windows matrix entry remains named `windows-latest` to preserve
  the existing required-check name; the selected OS version is pinned but its
  runner image and preinstalled tools can still update. macOS minutes cost 10× and Windows 2× the
  Linux rate on private repositories; the added Windows gate steps are the
  price of native coverage and are the only significant cost delta of this
  design. The `test` job timeout is 30 minutes and `windows-check` is 40;
  these are caps, not billed minimums.
- **Concurrency.** CI cancels superseded runs per ref; release runs never
  cancel a publishing flow in progress.
- **Permissions.** Workflow-level `contents: read`. Only the `publish` job
  elevates to `contents: write` behind the protected `release` environment.
  No CI job and no Windows gate step reads `secrets.*` or `vars.*`; the
  workflows therefore work on any fork or fresh repository without secret
  provisioning.
- **Re-running.** Re-run the failed jobs only; artifacts carry the run
  attempt in their name, so re-runs do not collide.

## Local equivalents

Run from the repository root. CI uses `GOPROXY=off` with the committed
`vendor/` tree; do the same locally to validate the offline path:

```sh
gofmt -l cmd internal tools
GOPROXY=off go vet ./...
GOPROXY=off go test ./... -count=1
```

On Windows (PowerShell 7), the full local gate mirroring CI:

```powershell
$env:GOPROXY = 'off'
go vet ./...
go test ./... -count=1 -timeout=3m -v -json 2>&1 | Tee-Object -FilePath windows-test-output.jsonl
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Real Task Scheduler integration (registers/removes a real per-user task):
$env:TOKTRAIL_WINDOWS_SCHEDULER_E2E = '1'
go test ./internal/scheduler -run '^TestWindowsSchedulerNativeIntegration$' -count=1 -v
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Remove-Item Env:TOKTRAIL_WINDOWS_SCHEDULER_E2E

# Real connect flow integration:
$env:TOKTRAIL_WINDOWS_CONNECT_E2E = '1'
go test ./cmd/toktrail -run '^TestWindowsConnectNativeIntegration$' -count=1 -v
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Remove-Item Env:TOKTRAIL_WINDOWS_CONNECT_E2E

# Smoke script (same entry point CI uses):
pwsh -File scripts/windows-smoke.ps1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
```

Without the env gates the integration tests skip, which is the correct
hermetic default for quick local runs — CI is what enforces that they
actually run and pass (see the no-vacuous-pass rule above).

A separate experimental ACL check applies and restores a deny ACL on a unique
temporary directory. Run it on an NTFS-backed Windows machine:

```powershell
$env:TOKTRAIL_WINDOWS_ACL_E2E = '1'
go test ./internal/connect -run '^TestConnectProbeWindowsACLDenyFailsClosed$' -count=1 -v
Remove-Item Env:TOKTRAIL_WINDOWS_ACL_E2E
```

It is not yet part of the required CI gate and must be validated on a real
Windows runner before relying on its result.
