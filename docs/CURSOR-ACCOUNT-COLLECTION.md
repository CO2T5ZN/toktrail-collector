# Cursor account collection

Cursor is an account-network source (`cursor-dashboard-api`), not a local conversation-log adapter. The collector reuses the user's existing Cursor desktop login and calls Cursor's personal dashboard usage API directly. Cursor credentials never go to the TokTrail server.

## First connection

Select Cursor in the website's collection scope. That grant IS the authorization: the collector prints what it is about to do (read the desktop login on this machine, query the account directly, upload sanitized usage only, whole-account scope) and then verifies the existing session, enables the server account source and performs its first synchronization. There is no second local prompt — asking again in the terminal re-asked a question the user had already answered in the browser, and a headless install could not answer it at all. No additional Cursor login is required when the desktop session is usable.

The website states that consenting to Cursor means reading this machine's Cursor desktop login; the terminal notice restates it at the moment of the read.

For an already bound device:

```sh
toktrail cursor enable
toktrail cursor status
toktrail cursor sync
toktrail cursor logout
```

`enable` performs the first (or account-switch) enable without prompting when the website grant already covers the tool; a switch to a different Cursor account still asks. It does not log the user into Cursor or install a Cursor extension. Cursor is not represented by a `--grant source=directory` entry and does not expand local-file grants.

The website grant and the local permit are separate records with separate lifetimes, and both must exist for collection to run. Removing either prevents the corresponding collection/upload activity. One Cursor account source designates one executor device; another device cannot seize that role through `enable`. Use the website's explicit reassignment action to transfer collection.

## Data and credentials

The SQLite provider queries only Cursor authentication entries in `ItemTable`, never chat/workspace tables. It does not copy the database. The login token is kept in memory and used only for requests to the fixed Cursor HTTPS origin. Redirects are rejected. Token-bearing errors are redacted without retaining the secret-bearing cause.

The collector uploads only pseudonymous event identities, revisions, time, model and token counts plus protocol metadata. It does not upload Cursor tokens, cookies, email, raw account or conversation IDs, original responses, charges or subscription details. These are account-wide statistics; the executor's computer is not necessarily where the usage happened.

Token rotation with an unchanged canonical account identity continues automatically. A different Cursor account pauses collection until the operator confirms the switch locally (`toktrail cursor enable` in a terminal, or the `connect` run that detects it): one account's history and incremental caches must not silently continue under another. This is the only remaining local question, and it exists to prevent mixing accounts, not to re-ask a consent the website already gave.

For an already active permit, the manual fallback is `toktrail cursor sync --token-stdin`. If desktop authentication cannot be read and the permit is new or expired, use `toktrail cursor enable --token-stdin --confirm-local`: both flags are required so permission is explicit and separate from credential input. A server grant is still required. Supply the token through a protected pipe or file for that process only; interactive terminal input is refused to avoid echoing it. The token is not saved as a plaintext configuration field or command-line argument. The enable process reuses its one in-memory credential for verification and the first sync, then exits. Normal periodic tasks continue using the desktop login provider.

## SQLite read-only limitation

SQLite WAL mode can create journal/index sidecars even with `mode=ro`. To prevent modification of Cursor's directory, the provider uses immutable reads for WAL-mode databases. This reads checkpointed database contents and ignores uncheckpointed WAL changes.

An established login usually exists in the main database. A newly created or rotated login that is still only in the WAL may be unavailable or stale until Cursor checkpoints it. If login detection fails immediately after signing in, close Cursor normally and retry; TokTrail does not force a checkpoint, alter Cursor permissions, or write its files. Keychain-only credential layouts are not claimed as supported by this SQLite provider.

## Synchronization and counting

The personal usage endpoint exposes stable `usageEventId` values. A repeated row can be a cumulative snapshot of an existing event, not a new request. TokTrail never adds these snapshots together.

- Within one response, identified duplicate snapshots are collapsed. Rows without stable IDs are not guessed into another event.
- Across successful pulls, changed events replace the prior fact using account event revision semantics, including downward corrections.
- Event identities are scoped to the TokTrail subject and stable Cursor account identity. They survive device takeover and source recreation while retained facts exist.
- Missing counters remain unknown. Invalid, negative, fractional or overflowing counters fail parsing. Fees are never converted into token estimates.
- Pagination has bounded pages, bytes and time. A short page alone is not completion when the server may clamp the requested page size. A failed/incomplete pull does not advance its watermark.
- Durable source batches are separate from device-local batches and are sent only to `/v1/ingest/source-batches`, with the live consent revision and source fence.
- Batch files are immutable, validated again before upload and retried with their original event revisions. Rejected records do not constitute a full acknowledgment.

## Deployment

Deploy the compatible Server and account-aware projection first. Publish and pin a Collector release whose signed capabilities describe Cursor as `account-network` with protocol version 1. Then enable the website's `TOKTRAIL_CURSOR_SOURCE=1` gate. Old schema-1 release capabilities remain readable, but a tool name alone is not proof that the binary supports this account protocol.

Do not enable Cursor on a website that still projects every usage fact by device identity. Account facts must fold by subject and event key, remain independent of executor-device deletion, and participate in snapshots, reconciliation and subject deletion.

This integration uses an undocumented personal dashboard protocol; failures after an upstream change must surface as an incompatible source, not silently as zero usage. Compatibility claims should distinguish mock-tested protocol behavior, successful cross-compilation and actual native Cursor-version validation.

## References

Protocol research and synthetic fixtures: `references/cursor-protocol/` at the workspace root. Primary upstream reference: `junhoyeo/tokscale` pinned commit `39ecb83ab045a300c6f502f9c9319acf5c80e764`, especially `crates/tokscale-cli/src/cursor.rs` and `crates/tokscale-core/src/sessions/cursor.rs`. The implementation tightens parsing, data retention and pagination behavior instead of copying permissive coercions or raw-response caches.
