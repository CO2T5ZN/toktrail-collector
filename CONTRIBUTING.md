# Contributing to TokTrail Collector

Thank you for contributing. This repository contains a local-first usage collector, so privacy and fail-closed behavior are part of the product contract, not optional implementation details.

## Development setup

Requirements:

- Go 1.24 or newer.
- No third-party Go modules are currently required.

Run the standard checks from the repository root:

```sh
gofmt -l cmd internal tools
GOCACHE="$PWD/.gocache" GOPROXY=off go test ./...
GOCACHE="$PWD/.gocache" GOPROXY=off go vet ./...
```

The release end-to-end test is slower and must be enabled explicitly:

```sh
GOCACHE="$PWD/.gocache" GOPROXY=off TOKTRAIL_RELEASE_E2E=1 go test ./tools/release/ -run '^TestEndToEndRelease$' -count=1 -v
```

### Local Windows testing

CI runs the full gate on `windows-2025` for every pull request: the whole
test suite, the real Task Scheduler and connect integration tests behind
env gates, and `scripts/windows-smoke.ps1`. To mirror it in PowerShell 7:

```powershell
$env:GOPROXY = 'off'
go vet ./...
go test ./... -count=1

# Real Task Scheduler integration; registers and removes a real per-user task.
$env:TOKTRAIL_WINDOWS_SCHEDULER_E2E = '1'
go test ./internal/scheduler -run '^TestWindowsSchedulerNativeIntegration$' -count=1 -v
Remove-Item Env:TOKTRAIL_WINDOWS_SCHEDULER_E2E

# Real connect flow integration.
$env:TOKTRAIL_WINDOWS_CONNECT_E2E = '1'
go test ./cmd/toktrail -run '^TestWindowsConnectNativeIntegration$' -count=1 -v
Remove-Item Env:TOKTRAIL_WINDOWS_CONNECT_E2E

pwsh -File scripts/windows-smoke.ps1
```

Without the env gates these integration tests skip locally; CI additionally
verifies they really ran and passed (an unmatched `-run` pattern alone fails
the gate). See [CI and release gates](docs/CI.md) for the full workflow
documentation, including failure-diagnostics artifacts and the pinned Go
version.

## Architecture

Read [Architecture and adapter extension](docs/ARCHITECTURE.md) before adding a source. Parsers and their fixtures belong to the source package. Shared orchestration must use registry descriptors rather than switch on source identifiers.

## Privacy requirements

Adapters and sync code must preserve these invariants:

- Do not upload prompts or message bodies.
- Do not upload raw session IDs or message IDs.
- Do not upload absolute local paths.
- Preserve each source's recorded model identifier without a public allowlist, including local route aliases. Report missing or ambiguous attribution as `unknown`; reject malformed identifiers. Do not infer backend identities or add gateway metadata. Public disclosure is controlled by the leaderboard.
- Unknown token counters must stay unknown; do not silently coerce unknown values to zero.
- Uploads must happen only after device binding and a fresh server-side consent preflight.
- Local read grants, upload consent, and public leaderboard consent remain separate.

Tests should use synthetic fixtures. Never commit real user session files, device state, bind tickets, release keys, or production service credentials.

## Coding guidelines

- Keep comments and engineering documents in English unless a document is intentionally bilingual.
- Prefer explicit validation and fail-closed behavior.
- Keep local-first commands usable without a TokTrail account.
- Keep release and installer code deterministic and auditable.
- Avoid new dependencies unless they are clearly justified.

## Pull request checklist

Before opening a pull request, verify:

- [ ] `gofmt -l` returns no files.
- [ ] `go test ./...` passes.
- [ ] `go vet ./...` passes.
- [ ] No secrets, real logs, local state, release keys, or cache directories are included.
- [ ] New adapters include privacy projection tests.
- [ ] Changes to release logic include manifest, archive, or installer tests as appropriate.
- [ ] Changes touching scheduler, connect, or Windows behavior were run through the local Windows gate above (CI will run them on `windows-2025` for every pull request, including `scripts/windows-smoke.ps1`, which must exist and pass).
- [ ] Documentation is updated when behavior or command-line flags change.

## Release artifacts

Do not commit generated release artifacts, signing keys, local binaries, or Go build caches. The repository `.gitignore` excludes the expected local paths, including `.gocache/`, `.gotmp/`, `bin/`, `dist/`, `.local/`, `.release-keys/`, logs, and local environment files.
