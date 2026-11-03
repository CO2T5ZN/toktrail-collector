# Scheduled collection (`toktrail periodic` and `toktrail service`)

This document describes the collector's periodic entry and the user-scope
service integration for macOS (launchd), Linux (systemd user timer), and
Windows (Task Scheduler). Everything here is local-first: no scheduler file
is written without an explicit command, and no network access happens
without an explicit consent path.

## What the scheduled task runs

The installed task runs exactly:

```
<toktrail binary> periodic --state-dir <absolute state dir>
```

Nothing else is on the command line: no server URL and no secrets. The
server endpoint is resolved at runtime from the bound device state, so a
server move after install requires no task change. The task is a
complete-exit job: each run collects, exports, drains a bounded number of
pending batches, and exits. The interval (default 30 minutes) controls when
the OS starts the next run; `RunAtLoad` is false, so the first run happens
at the first interval after install/load, not immediately.

## Explicit-grant collection model

`toktrail periodic` never scans by default. The only inputs it touches are
the grants recorded in `grants.json` (`toktrail sources enable
--source <id> --input <abs path>`). The existing manual commands
(`scan`, `preview`, `export`) are unchanged and remain explicit
source+input selection; they never read `grants.json`.

Zero enabled grants means the run collects nothing, performs no network
request at all, and exits cleanly. A grant whose input has disappeared
since it was recorded is skipped with a reason; it does not fail the run.

Granting a local read (sources enable / scheduled collection) is
independent of upload consent. Upload still requires a bound device, and
every drain re-checks the server's fresh consent state via the existing
`syncclient` preflight (`GET /v1/devices/self`) before any upload. If
consent was revoked, batches stay in the local outbox. Quarantine and
reorganization recovery remain on the explicit `toktrail sync` command.

## One run, one lock

The periodic run acquires the existing `internal/local/runlock` process lock
for the whole run, before any validation, collection, or network use. If
another collector process holds the lock the run fails fast with the
existing busy error and touches nothing.

## Run order and failure behavior

1. Acquire the process lock (fail fast when busy).
2. Load enabled grants; zero grants → no-op exit with no network.
3. For each grant: validate the input is accessible; then prepare an
   export via the `internal/source/pipeline` path, commit it through the
   existing `exportcommit` WAL (crash-safe, replay-idempotent), which
   stages the batch in the local outbox.
4. Drain the outbox: upload at most `--max-batches` (default 5) pending
   batches per run using the existing `syncclient`, with the server's
   fresh-consent preflight intact. A failed upload stops the drain, leaves
   the batch pending, and reports the stop reason; the next scheduled run
   continues.
5. For mapped tools, report successful uploads and completed empty scans
   through `POST /v1/devices/tool-status`, after a fresh device/consent
   preflight. Empty scans send `no_new_records` without creating a usage
   batch or advancing usage baselines/ACKs. Missing or unreadable granted
   inputs do not qualify as completed empty scans. Empty-scan reporting
   waits until the pending outbox is fully drained. Receipt errors surface
   to the caller; HTTP 404/405 is tolerated for older servers.
6. Release the lock.

No secrets ever appear in command lines, rendered scheduler files, plan
output, or logs.

## Service install and uninstall

`toktrail service install --state-dir <dir> --grant <source>=<abs input>
[--grant ...] [--interval 30m] [--dry-run]`

- Requires at least one explicit `--grant`; grants are validated and
  written (under the state process lock) **before** any scheduler file is
  touched, so a bad grant fails closed with no partial install.
- `--dry-run` prints the full plan — every file with its complete content
  and every command — and writes nothing.
- Task identity is deterministic per absolute state directory
  (`toktrail-collector-<hash>`), so multiple state directories can each
  have their own task, and reinstalling over an existing task is a
  no-op-safe refresh.
- User scope only: launchd `~/Library/LaunchAgents`, systemd user units
  `~/.config/systemd/user`, Windows Task Scheduler under the current
  user. No root, no system-wide daemons, no implicit install during
  `bind` or package install.
- Paths with spaces and XML/shell metacharacters are quoted safely using
  XML/argument APIs, never shell string interpolation.

`toktrail service uninstall --state-dir <dir> [--dry-run]`

- Idempotent: missing files are tolerated.
- Fail-closed path validation: every removed file must live inside the
  platform's expected base directory **and** carry this task's identity
  and this state directory's marker; foreign or hijacked files are
  refused.
- Deactivation command failures are tolerated; file removal is refused,
  not guessed, when ownership cannot be proven.

## Sources and plugins visibility

- `toktrail sources list|enable|disable` manages the local grant config
  read by `periodic`. Enabling/disabling a source only affects scheduled
  collection; manual commands keep requiring explicit `--source` and
  `--input`.
- `toktrail plugins list` shows the compiled-in source adapters and their
  capabilities. Plugins are compile-time only; there is no plugin
  download or dynamic loading.

## Local diagnostics

- `toktrail privacy [--state-dir <dir> | --source <id> --input <path>]`
  is local-only: it scans the granted (or explicitly named) input and
  reports record counts, token filter windows, tool usage, time bounds,
  and how much is still staged in the outbox. It never touches the
  network and never prints message content or secrets.
- `toktrail doctor [--state-dir <dir>] [--check-server]` performs local
  health checks (binding, consent flags, grants, WAL journal, outbox,
  quarantine, scheduler task files). `--check-server` is the only
  networked check and reuses the existing status command's consent
  preflight. It never prompts, sends messages, or prints secrets.

## Tested coverage — and what is not tested here

Covered by automated tests (temp directories, injected runners, and
`httptest` servers only; **no default test run installs, modifies, or removes
any real host scheduler job**. Opt-in Windows scheduler and connect integration
checks may register temporary tasks on a disposable runner or an explicitly
configured developer machine:

- Rendered launchd plists, systemd service/timer units, and Windows Task
  XML: content, quoting, and path escaping, including paths with spaces
  and XML/shell metacharacters.
- Install/uninstall planning: dry-run plans, owned-path validation
  refusal for foreign files, idempotent uninstall with missing files,
  fail-closed partial install, disabled-source and error paths.
- End-to-end `periodic` behavior against a local test server: lock
  refusal with zero network, zero-grant no-op with zero network, missing
  input skip, collect → WAL commit → bounded drain, second run over
  unchanged input exporting nothing and reporting `no_new_records` without
  replaying usage, upload-failure
  stop with pending retention, unbound-device drain refusal.

Not verified here and required before production rollout on each platform:

1. **Native runtime verification** of the rendered units/jobs on real
   macOS launchd, Linux systemd user timers, and Windows Task Scheduler,
   including actual execution and per-user session behavior. On Windows,
   `TestWindowsSchedulerNativeIntegration` (gated by
   `TOKTRAIL_WINDOWS_SCHEDULER_E2E=1`) registers, queries, and removes a real
   per-user task on the `windows-2025` CI runner. The connect integration
   also registers a real task, but neither test triggers the scheduled task.
   Actual execution and logon behavior remain rollout prerequisites; see
   [CI and release gates](CI.md). macOS and Linux native runtime verification
   also remain external prerequisites.
2. Real-platform quoting behavior beyond the API-level guarantees (for
   example, `schtasks`/`Register-ScheduledTask` argument passing for the
   exact production binary path).
3. Long-run behavior of `OnUnitActiveSec` drift, `AccuracySec`, and
   Windows repetition intervals under sleep/wake cycles.

These are external prerequisites, not gaps in the rendering or plan
logic tested above.
