# Upgrading an existing collector

Replacing the binary is the whole upgrade. Nothing in the state directory has
to be migrated, moved, or deleted, and no re-binding or re-authorization is
needed.

## What changed on disk

The collector now keeps three kinds of accelerator files next to the existing
state. All of them are derived data: deleting any of them costs one full
re-read, never data.

| File | Purpose | If deleted |
|---|---|---|
| `scan-ledger-<source>.json` | per source file: the content digest that was already exported | the next run re-reads and re-parses that source's history once |
| `known-records-<source>.jsonl` | the dedupe baseline (recordKey → canonical record) the export filter compares against | the next run rebuilds it from the outbox batch files |
| `claude-observations-<root>.json` | per Claude session file: its usage lines in order | the next run re-reads those session files |

None of them is authoritative. The outbox batches, the quarantine store, the
message baselines and the override ledger stay the source of truth, and every
cache is validated against them:

- a cached baseline is used only when its per-batch content digests still match
  the batch files the outbox points at;
- a source file is skipped only when its current content digest matches, **and**
  that digest is in the scan ledger that is advanced only after a successful
  export commit;
- an unknown cache version, a corrupt line or a missing file means "re-read",
  never "assume nothing changed".

## First run after the upgrade

The first run behaves exactly like the previous version: it reads the full
history once, exports whatever is new, and records the scan state. The run
after that skips every unchanged file. On a multi-gigabyte Codex history the
difference is measured in seconds instead of a full re-parse; on a machine that
was repeatedly hitting the old two-minute window this is what makes a run reach
its first export commit at all.

## How to upgrade

```sh
toktrail upgrade --check        # what is installed, what the latest release is
toktrail upgrade --to v0.6.0    # verify and replace this installation in place
```

`upgrade` replaces exactly one file (the binary that is running, with the
previous copy kept as `<binary>.previous`) and refuses to run without a pinned
public key, so it never installs an unverified release. It also refuses when the
running binary is not the released artifact for this platform (a source build or
a locally modified binary), unless `--skip-self-check` says so explicitly. `toktrail doctor`'s
`binary` line confirms afterwards that the schedule starts the same binary that
was upgraded; its `scan-cache` line confirms the new scan state exists.

## Verifying the upgrade took effect

```
toktrail doctor
```

The `scan-cache` line reports `no incremental scan state yet` before the first
run and `N source(s) with committed scan state covering M file(s)` afterwards.
It is informational: a state directory that has never run is not a problem.

## What not to do

- Do not delete or edit files inside the state directory to "reset" collection.
  `toktrail resync --all --replace-existing` is the supported way to re-state
  already-uploaded history, and `toktrail connect` handles an ownership
  mismatch by archiving the old state (nothing is retransmitted).
- An out-of-band edit of a batch file is detected: the known-record cache is
  invalidated and the baseline is rebuilt from the file's current bytes. If the
  edited content then disagrees with the source history, the run fails closed
  rather than silently overwriting.
