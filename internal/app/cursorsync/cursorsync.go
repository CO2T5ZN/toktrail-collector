// Package cursorsync orchestrates the account-level Cursor source:
// first-time local enable (confirmation + server enable call), periodic
// pull/normalize/upload through a dedicated cursor outbox, and logout.
//
// It reuses the bound device credentials and the server consent preflight
// (GET /v1/devices/self), but never the device-batch upload path: cursor
// records travel only to /v1/ingest/source-batches with the source fence.
//
// Identity: the account identity and the session cookie are derived ONLY
// by api.VerifySession (which validates the credential live against
// Cursor and returns the canonical "user_…" account id). Nothing here
// parses JWTs or assembles cookies itself, and auth.AccountHint (an
// unverified hint) is never used for identity or authorization.
//
// Privacy invariants: the Cursor access token, the account identity and
// the raw upstream responses exist only in memory for the duration of one
// sync; they never reach the license file, the outbox, logs, diagnostics,
// or uploads. The license stores only the pseudonymous account-match
// digest (identity.MatchAccount) and pull/upload watermarks.
package cursorsync

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"toktrail-collector/internal/cursor/accountsource"
	"toktrail-collector/internal/cursor/api"
	"toktrail-collector/internal/cursor/auth"
	"toktrail-collector/internal/cursor/identity"
	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/cursor/sourcebatch"
	"toktrail-collector/internal/cursor/usage"
	"toktrail-collector/internal/local/cursoroutbox"
	"toktrail-collector/internal/local/cursorsource"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncbudget"
	synccmd "toktrail-collector/internal/syncclient"
	"toktrail-collector/internal/syncretry"
)

// PullOverlap re-pulls a bounded recent window before the watermark so
// late upstream backfill and corrections arrive (engineering parameter;
// not a correctness guarantee — upstream may correct even later).
const PullOverlap = time.Hour

// DefaultMaxBatches bounds one run's upload drain per phase.
const DefaultMaxBatches = 5

// maxNextRevision mirrors the protocol ceiling for event revisions
// (2^53-1); a license seeded above it cannot produce valid records.
const maxNextRevision = int64(1)<<53 - 1

// errUploadBoundaryChanged is the retry preflight's conservative stop for
// authorization drift that has no sourcebatch sentinel: the effective tool
// scope narrowed without a consent bump, or the live device self view
// could not be re-fetched at all. drain stops the round on it exactly
// like the sentinel drifts — the pending batch is never dropped and the
// authorization boundary is never widened, re-derived or bypassed.
var errUploadBoundaryChanged = errors.New("cursor upload authorization boundary changed or could not be re-verified")

// VerifyFunc validates one Cursor credential end to end through the
// pinned-host API client (api.Client.VerifySession) and returns the
// canonical account id plus the live session token. The CLI wires the
// real client; tests inject fakes. An expired or invalid login surfaces
// as an error wrapping api.ErrSessionExpired.
type VerifyFunc func(ctx context.Context, accessToken string) (api.VerifyResult, error)

// PullFunc fetches the collapsed usage snapshots for the fixed [from, to)
// window using the verified session token. The CLI wires the real
// internal/cursor/api client (host allowlisting, redirect refusal,
// body/page/event/duration budgets, per-response snapshot collapse);
// tests inject fakes.
type PullFunc func(ctx context.Context, sessionToken string, from, to time.Time) ([]api.UsageEvent, error)

// ConfirmFunc asks the user for the first-time local confirmation. It
// receives the notice text and the output writer; it returns whether the
// user confirmed. The default implementation prompts on the terminal;
// tests inject fakes.
type ConfirmFunc func(notice string, out io.Writer) (bool, error)

// EnableNotice is the first-time confirmation notice (account scope,
// credential reading, and the upload boundary).
const EnableNotice = "TokTrail 将在本机读取 Cursor 桌面登录凭据，并直接向 Cursor 查询该账号的用量；仅上传脱敏后的用量记录（不包含 Cursor 登录凭据、邮箱或对话内容）。统计范围为整个 Cursor 账号（可能包含其他电脑上的使用）。"

// Options configures one sync or enable run.
type Options struct {
	StateDir   string
	ServerURL  string
	HTTPClient *http.Client
	// Auth reads the Cursor desktop login credential on demand.
	Auth auth.Provider
	// Verify validates the credential and derives the canonical account
	// identity plus session token (api.Client.VerifySession).
	Verify VerifyFunc
	// Pull fetches upstream usage events (see PullFunc).
	Pull PullFunc
	// Now overrides the clock for tests.
	Now func() time.Time
	// MaxBatches bounds the upload drain per phase (default 5).
	MaxBatches int
	// Out receives progress output; nil discards.
	Out io.Writer
	// ForceResync forces one full-range recovery round (reinstall
	// recovery): the pull covers the whole currently authorized window
	// (like the daily reconciliation, but unconditional) and unchanged
	// events are re-emitted — not skipped — as records whose fresh
	// revision dominates both the local and the server-delivered
	// nextRevision (and stays strictly above each event's cached
	// revision), so the server replaces them instead of going stale.
	//
	// Safety: the persistent event cache is never cleared (it keeps its
	// dedupe and revision memory; re-emitted entries merely restage at
	// the fresh revision) and the revision memory is never reset — it
	// stays the folded max(local, server) and only ever advances. Pending
	// batches in the durable outbox drain first with their immutable
	// revisions and are never dropped; a failed round keeps the
	// watermark, the cache and every pending batch exactly like a normal
	// round. The round still runs under the full authorization preflight
	// (fresh self view, scope, consent, source state) — forcing never
	// bypasses any permission.
	//
	// The effect lasts exactly one round: later rounds skip unchanged
	// events again unless they force again.
	//
	// Reporting: a fully successful forced round sets no Note (the count
	// travels in Result.ReemittedRecords alone) so success receipts keyed
	// on an empty Note keep flowing.
	ForceResync bool
	// Budget, when set, bounds the real cursor source-batch ingest POSTs
	// of this run. It is threaded through Sync and DrainPendingLocked
	// into every sourcebatch upload, sharing one run-wide budget with the
	// other queues (device, ...) of the same run. A decline stops the
	// round before the POST — nothing is acknowledged or dropped, the
	// batch stays pending and the next run resumes it. A granted attempt
	// is never refunded, even when the POST itself fails. Nil keeps the
	// unconditional upload behavior exactly as before.
	Budget *syncbudget.Budget
	// Retry, when set, opts this run's cursor source-batch uploads into a
	// bounded retry policy (internal/syncretry). Transient failures —
	// network-shaped transport errors while the run context is still
	// live, HTTP 429/500/502/503/504 whose business code is absent or
	// known transient (honoring the server's Retry-After as a wait floor
	// against the policy's run deadline), and 2xx answers whose receipt
	// was lost or truncated in transit — are retried with the SAME batch
	// id, the SAME immutable outbox bytes and the SAME authorization
	// boundary (source fence, consent revision, device credentials).
	// Before every retry the device self view is re-read and the boundary
	// re-verified (source instance, fence, state, consent, device
	// permissions, effective scope); anything that moved — or a self view
	// that cannot be re-fetched — stops the round conservatively, never
	// widening or bypassing the authorization. Each real POST reserves
	// the shared Budget on its own and persists its own MarkAttempt; a
	// full acknowledgment is written at most once, after the retry loop
	// ends. Nil (the default) keeps the historical single-attempt
	// behavior exactly: no retry, no retry markers, no preflight.
	Retry *syncretry.Policy
	// Progress, when set, receives sanitized per-batch upload events
	// (BatchProgress) for the cursor source-batch attempts of this run:
	// every real POST attempt (with the trusted receipt counts when a
	// strictly-validated receipt arrived), the retry preflight and the
	// inter-attempt spacing of retried batches, and exactly one terminal
	// outcome event per uploaded batch (acknowledged, rejected, paused,
	// stopped or failed). Events are closed facts only — no URLs, paths,
	// credentials, identifiers or raw error text — and purely
	// observational: no control flow, accounting, budget, retry or
	// acknowledgment decision reads them. Nil (the default) keeps every
	// round byte-for-byte on its historical path: no events, no clock
	// reads, no behavior change of any kind.
	Progress func(BatchProgress)
	// ProgressClock overrides the clock used ONLY for progress-event
	// timing (BatchProgress.Duration and InterAttemptDelay). It is
	// deliberately separate from Now: Now drives business state
	// (watermarks, attempt accounting, retry deadlines), so progress
	// observation must never read it — an extra read could perturb an
	// injected clock and Now is not guaranteed monotonic. Nil uses the
	// real clock (time.Now, durations via its monotonic reading). With
	// Progress nil no clock is read at all, so wiring this field alone
	// changes nothing.
	ProgressClock func() time.Time
}

// BatchPhase is the sealed phase one BatchProgress event reports. The
// set is closed: consumers may switch on it exhaustively.
type BatchPhase string

const (
	// BatchPhasePreflight: the per-attempt retry preflight — the
	// authorization-boundary re-verification (verifyUploadBoundary)
	// that re-reads the live device self view before every retry
	// attempt of a batch. It runs inside attempts after the first and
	// only there; the round-start preflight is round-scoped and never
	// part of the per-batch event stream.
	BatchPhasePreflight BatchPhase = "preflight"
	// BatchPhaseWait: the spacing before a retried attempt. Fired at
	// the start of every attempt after the first, carrying
	// InterAttemptDelay (see BatchProgress.InterAttemptDelay).
	BatchPhaseWait BatchPhase = "wait"
	// BatchPhaseHTTP: one real ingest POST attempt of a batch — and
	// only a real one: a pre-POST refusal (local validation or a
	// declined shared budget) never emits an http event, because no
	// request was handed to the transport.
	BatchPhaseHTTP BatchPhase = "http"
	// BatchPhaseOutcome: the terminal event of one batch upload.
	// Exactly one fires per uploaded batch (see BatchResult).
	BatchPhaseOutcome BatchPhase = "outcome"
)

// BatchResult is the sealed outcome of the phase a BatchProgress event
// reports. The set is closed: consumers may switch on it exhaustively.
type BatchResult string

const (
	// BatchResultOK: the phase completed normally — the preflight
	// passed, the wait elapsed, or the POST call returned a
	// strictly-validated receipt (whose counts may still carry
	// rejections; the terminal outcome event classifies those).
	BatchResultOK BatchResult = "ok"
	// BatchResultFailed: the phase or the batch failed with an actual
	// error — a POST attempt without a valid receipt, retry exhaustion,
	// a declined shared budget, a failed durable write.
	BatchResultFailed BatchResult = "failed"
	// BatchResultStopped: an authorization-boundary drift stopped the
	// upload conservatively (fence, consent, source state/designation,
	// device authorization or effective scope).
	BatchResultStopped BatchResult = "stopped"
	// BatchResultPaused: the server-side source paused under the
	// upload; the batch stays queued.
	BatchResultPaused BatchResult = "paused"
	// BatchResultAcknowledged (terminal): the batch is durably
	// acknowledged locally (the outbox MarkSynced write succeeded);
	// Duration then measures that write.
	BatchResultAcknowledged BatchResult = "acknowledged"
	// BatchResultRejected (terminal): a strictly-validated receipt
	// reported one or more rejected records; the batch stays pending.
	BatchResultRejected BatchResult = "rejected"
)

// BatchProgress is one sanitized per-batch upload event for the Cursor
// account source (Options.Progress). It is a closed, batch-granularity
// schema — deliberately coarse:
//
//   - No URLs, paths, credentials, identifiers (no batch, device,
//     source or account ids) and no raw error text ever travel; the
//     only strings are the sealed Phase and Result enums. Nothing here
//     is record-level: per-record rejection details stay out (the
//     Result/Skipped surfaces keep them), so an event never claims
//     record-level reporting that does not exist.
//   - Correlation is positional, not by id: events between two
//     terminal (Phase=outcome) events belong to one batch upload, and
//     every uploaded batch emits exactly ONE terminal event. A batch
//     whose upload never began (an unreadable queue or batch bytes)
//     emits nothing.
//   - Trusted fields only: receipt-derived counts are set solely after
//     strict receipt validation (ReceiptKnown); every field that cannot
//     be determined keeps its zero value — unknown is never faked as a
//     fact (zero counts never claim the server accepted or rejected
//     zero records).
type BatchProgress struct {
	// Phase is the sealed phase this event reports.
	Phase BatchPhase
	// Result is the sealed outcome of that phase (terminal results only
	// appear on Phase=outcome events).
	Result BatchResult
	// Attempt is the 1-based attempt number within this batch's upload
	// (1 = the initial POST, > 1 = policy retries); 0 on terminal
	// outcome events, which belong to the batch as a whole.
	Attempt int
	// Duration is the phase's duration on the observation clock
	// (Options.ProgressClock, real monotonic time by default). It is
	// known only when the phase event actually fires: the http duration
	// spans the WHOLE PostBatch call — local re-validation, the optional
	// budget reservation, the request/response round trip and receipt
	// decoding/validation — not pure network time; the preflight
	// duration spans the boundary re-verification including its self
	// GET; on the acknowledged terminal it is the durable local
	// acknowledgment write. A frozen injected observation clock
	// legitimately measures zero for real I/O.
	Duration time.Duration
	// InterAttemptDelay is the observed spacing between the previous
	// attempt's completion and this attempt's start (wait events only,
	// attempts after the first). Under the real clock it comprises the
	// retry policy's wait — backoff or the server's Retry-After floor —
	// plus minor scheduling; it is deliberately NOT labeled a backoff:
	// it is an observed spacing, not the policy's computed value, and
	// the retry preflight and durable attempt accounting (which run
	// inside the attempts) are excluded from it.
	InterAttemptDelay time.Duration
	// PayloadBytes is the size in bytes of the batch's immutable
	// encoded payload in play for this event. Planned/attempted volume
	// only: the collector cannot observe how many bytes actually left
	// the machine, so this is never a claim of bytes sent or delivered.
	PayloadBytes int
	// ReceiptKnown reports whether AcceptedRecords/RejectedRecords and
	// Replay carry the strictly-validated server receipt's values. It
	// is set only after the receipt passed strict validation; every
	// outcome without one (transport failure, non-2xx answer, invalid
	// receipt, preflight stop, budget decline) leaves it false — those
	// items are unknown, never reported as zero facts.
	ReceiptKnown bool
	// AcceptedRecords/RejectedRecords mirror the strictly-validated
	// receipt (trusted only when ReceiptKnown is true).
	AcceptedRecords int
	RejectedRecords int
	// Replay is the receipt's batch-level replay flag: the server
	// answered a re-send of a batch id it had already stored durably.
	// It is batch-granularity and says nothing about local
	// acknowledgment counting — a replay receipt may well be the FIRST
	// local acknowledgment of that batch (a receipt lost in transit,
	// proven by the re-send).
	Replay bool
}

// batchReporter gates every BatchProgress emission on a non-nil
// Options.Progress. Constructed per upload/drain call, it is fully
// inert without a callback — no clock reads, no invocations — so a nil
// Progress keeps the round byte-for-byte on its historical path. All
// timing goes through the observation clock (Options.ProgressClock,
// real time by default), never the business Options.Now.
type batchReporter struct {
	progress func(BatchProgress)
	clock    func() time.Time
}

// newBatchReporter wires the reporter for one run's Options. Without a
// Progress callback it returns the zero (inert) reporter.
func newBatchReporter(opt Options) batchReporter {
	if opt.Progress == nil {
		return batchReporter{}
	}
	clock := opt.ProgressClock
	if clock == nil {
		clock = time.Now
	}
	return batchReporter{progress: opt.Progress, clock: clock}
}

// active reports whether events (and clock reads) happen at all.
func (r batchReporter) active() bool { return r.progress != nil }

// emit delivers one event; a no-op when inactive.
func (r batchReporter) emit(p BatchProgress) {
	if r.progress != nil {
		r.progress(p)
	}
}

// now reads the observation clock (zero time when inactive, so an
// inactive reporter never touches any clock).
func (r batchReporter) now() time.Time {
	if r.progress == nil {
		return time.Time{}
	}
	return r.clock()
}

// since measures the observation-clock span from a now() mark.
func (r batchReporter) since(start time.Time) time.Duration {
	if r.progress == nil || start.IsZero() {
		return 0
	}
	return r.clock().Sub(start)
}

// emitHTTP reports one real POST attempt of a batch from the upload
// client's sanitized per-call facts. It fires only when the request was
// actually handed to the transport (facts.Attempted): a pre-POST
// refusal — local validation or a declined shared budget — never
// counts as an attempt. Receipt counts travel only when the receipt
// passed strict validation (facts.ValidReceipt); otherwise they stay
// unknown. started marks the observation-clock instant the whole
// PostBatch call began (the duration spans local checks, the optional
// budget reservation, the round trip and receipt validation — not pure
// network time).
func (r batchReporter) emitHTTP(attempt int, started time.Time, facts sourcebatch.PostProgress) {
	if r.progress == nil || !facts.Attempted {
		return
	}
	result := BatchResultFailed
	if facts.ValidReceipt {
		result = BatchResultOK
	}
	r.emit(BatchProgress{
		Phase:           BatchPhaseHTTP,
		Result:          result,
		Attempt:         attempt,
		Duration:        r.since(started),
		PayloadBytes:    facts.PayloadBytes,
		ReceiptKnown:    facts.ValidReceipt,
		AcceptedRecords: facts.AcceptedRecords,
		RejectedRecords: facts.RejectedRecords,
		Replay:          facts.Replay,
	})
}

// emitOutcome reports a batch's one terminal outcome event. payloadBytes
// is the batch's immutable encoded size (planned/attempted volume).
// receiptKnown is set only when receipt passed strict validation and
// carries the durable-acknowledgment write's observation-clock mark for
// the acknowledged result (zero otherwise: no other terminal measures a
// phase of its own).
func (r batchReporter) emitOutcome(result BatchResult, ackStarted time.Time, payloadBytes int, receipt cursoroutbox.Receipt, receiptKnown bool) {
	if r.progress == nil {
		return
	}
	p := BatchProgress{
		Phase:        BatchPhaseOutcome,
		Result:       result,
		PayloadBytes: payloadBytes,
	}
	if receiptKnown {
		p.ReceiptKnown = true
		p.AcceptedRecords = receipt.AcceptedRecords
		p.RejectedRecords = receipt.RejectedRecords
		p.Replay = receipt.Replay
	}
	if !ackStarted.IsZero() {
		p.Duration = r.since(ackStarted)
	}
	r.emit(p)
}

// batchPreflightResult classifies a failed retry preflight
// (verifyUploadBoundary error) onto the sealed event result set with
// the same sentinel mapping drain uses, so a preflight event and the
// terminal outcome event never disagree. The error itself never
// travels into any event.
func batchPreflightResult(err error) BatchResult {
	switch {
	case errors.Is(err, sourcebatch.ErrSourcePaused):
		return BatchResultPaused
	case errors.Is(err, sourcebatch.ErrFenceStale),
		errors.Is(err, sourcebatch.ErrSourceDeleted),
		errors.Is(err, sourcebatch.ErrStaleRevision),
		errors.Is(err, sourcebatch.ErrConsentStale),
		errors.Is(err, sourcebatch.ErrDeviceUnauthorized),
		errors.Is(err, errUploadBoundaryChanged):
		return BatchResultStopped
	default:
		return BatchResultFailed
	}
}

// Gate is the effective collection policy for one run, supplied by the
// periodic grant sync (or unrestricted on direct CLI runs, where the
// live self view fetched inside Sync governs). AllowedTools nil/empty
// means unrestricted.
type Gate struct {
	Paused       bool
	AllowedTools []string
	HistoryFrom  *time.Time
}

func (g Gate) cursorAllowed() bool {
	if g.Paused {
		return false
	}
	if len(g.AllowedTools) == 0 {
		return true
	}
	for _, t := range g.AllowedTools {
		if strings.TrimSpace(t) == cursorsource.ToolName {
			return true
		}
	}
	return false
}

// RoundOutcome classifies how one cursor round ended, structurally
// (plan §6.5: a partial completion must never read as success). The
// human-readable Skipped/Note diagnostics stay unchanged for operators;
// callers that judge completeness read this field instead of matching
// message text. The classes deliberately separate an authorization
// VERDICT observed before any work ran (RoundAuthWithheld,
// RoundNoPermit) from an authorization DRIFT that stopped a round
// already in flight (RoundFenceStop).
type RoundOutcome string

const (
	// RoundAbsent means no round ran at all (a zero Result — e.g. a
	// periodic --drain-only run wires no cursor round).
	RoundAbsent RoundOutcome = ""
	// RoundRan means the round ran and ended cleanly: its queue drained
	// or had nothing to do.
	RoundRan RoundOutcome = "ran"
	// RoundError means the round failed with an actual error: a pull
	// failure, an upload or retry failure (retry exhaustion, budget
	// decline, network), a credential read/verification failure, a hard
	// license/server-state error, or a rejected receipt. An
	// authorization preflight that itself failed — including the
	// persistent preflight accounting — is an error, never a verdict.
	RoundError RoundOutcome = "error"
	// RoundFenceStop means an authorization-boundary drift stopped the
	// round mid-flight: a moved fence or consent revision, a source
	// state change or reassignment under an upload, or a retry preflight
	// that refused to realign. Work may already have been uploaded under
	// the old boundary.
	RoundFenceStop RoundOutcome = "fence_stop"
	// RoundPaused means the device or the server-side source is paused,
	// so the round could not upload; queued batches stay pending.
	RoundPaused RoundOutcome = "paused"
	// RoundBounded means the per-run batch bound stopped the drain with
	// batches still queued — a normal bounded stop, not a failure.
	RoundBounded RoundOutcome = "bounded"
	// RoundNoPermit means no local cursor permit exists.
	RoundNoPermit RoundOutcome = "no_permit"
	// RoundAuthWithheld means a permit exists but the current
	// authorization withholds collection before any work ran: a paused
	// or non-collectable permit, cursor outside the effective grant
	// scope, the source reassigned away from this device, or a revoked
	// device. Observed after work already ran this round it is an
	// authorization drift instead (collection's merge escalates it),
	// never a steady-state verdict.
	RoundAuthWithheld RoundOutcome = "auth_withheld"
)

// Result reports one sync round.
type Result struct {
	// Ran is true when a sync attempt actually executed (permit present,
	// gates passed).
	Ran bool
	// Skipped carries the reason no attempt ran.
	Skipped string
	// Status is the resulting permit status.
	Status cursorsource.Status
	// Outcome classifies how the round ended (see RoundOutcome). It is
	// assigned on every exit path of Sync and DrainPendingLocked so
	// callers judge completeness from structure, never from the
	// Skipped/Note text.
	Outcome RoundOutcome
	// FirstSyncCompleted is true when a pending_first_sync permit finished
	// its first complete pull this round.
	FirstSyncCompleted bool

	PulledEvents      int
	NewRecords        int
	ReplacedRecords   int
	SkippedUnchanged  int
	SkippedNoStableID int
	// ReemittedRecords counts unchanged events re-emitted by a forced
	// resync round (Options.ForceResync): their content matched the local
	// cache, but the round re-delivered them at a fresh revision so the
	// server's view of the account source is fully rebuilt. Reported
	// separately from NewRecords/ReplacedRecords/SkippedUnchanged. It is
	// the ONLY reporting surface for a forced round: a fully successful
	// forced round sets no Note, so consumers that key success on an
	// empty Note (the periodic layer's synced / leaderboard status
	// receipt) are not suppressed.
	ReemittedRecords int

	ExportedBatches int
	SyncedBatches   int
	SyncedRecords   int
	// PendingRemaining counts outbox batches still pending after the run.
	PendingRemaining int
	// PendingCounted reports whether PendingRemaining is a real
	// measurement of the durable account queue (a successful count).
	// Rounds that never read the queue — no local permit, an
	// authorization withheld before any preflight, a failed preflight —
	// leave it false, so a zero count never implies an empty queue.
	PendingCounted bool
	// Note carries non-fatal diagnostics.
	Note string
}

// EnableResult reports what one enable run did.
type EnableResult struct {
	// Confirmed is true when a first-time (or re-) confirmation was
	// obtained this run.
	Confirmed bool
	// ServerEnabled is true when the server enable call ran this run.
	ServerEnabled bool
	// Source is the authoritative server source metadata.
	Source protocol.Source
	// Sync is the first sync round run right after enabling (Ran=false
	// when the permit was already active and healthy).
	Sync Result
	// License is the resulting permit.
	License cursorsource.License
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now().UTC()
	}
	return time.Now().UTC()
}

func (o Options) out() io.Writer {
	if o.Out != nil {
		return o.Out
	}
	return io.Discard
}

func (o Options) maxBatches() int {
	if o.MaxBatches > 0 {
		return o.MaxBatches
	}
	return DefaultMaxBatches
}

// verifiedCredential reads the desktop credential and validates it through
// Verify, returning the canonical account id and the live session token.
// An expired login maps to the login_expired permit state by the caller.
func verifiedCredential(ctx context.Context, opt Options) (cred auth.Credential, accountID, sessionToken string, err error) {
	cred, err = opt.Auth.Fetch(ctx)
	if err != nil {
		return cred, "", "", err
	}
	if !cred.HasToken() {
		return cred, "", "", errors.New("the cursor desktop credential carries no access token")
	}
	result, err := opt.Verify(ctx, cred.AccessToken)
	if err != nil {
		return cred, "", "", err
	}
	if strings.TrimSpace(result.AccountID) == "" || strings.TrimSpace(result.SessionToken) == "" {
		return cred, "", "", errors.New("credential verification returned no account identity")
	}
	return cred, result.AccountID, result.SessionToken, nil
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

// DrainPending uploads already-persisted cursor outbox batches without reading
// desktop credentials or pulling upstream Cursor usage. It is the account-source
// counterpart of collection.DrainPending: safe for backlog draining, while still
// using the fresh server self view and the source fence/state checks before any
// upload. A moved fence leaves local state unchanged and requires a later full
// Sync to fence stale batches and re-pull under the new fence.
//
// Single-writer safety: unlike Sync and Enable — whose callers (the CLI
// cursor commands, collection.Run's cursor phase, connect's locked setup)
// already hold the collector runlock around the whole run, so those
// functions never take it — DrainPending is a standalone entry point and
// acquires the non-blocking runlock (internal/local/runlock) itself for
// the entire round. A concurrent holder therefore fails fast with
// runlock.ErrBusy before any local-state or network work: no deadlock, no
// interleaved writes to the license, outbox or cache. Callers that already
// hold the runlock must NOT call DrainPending — the lock is taken per open
// file description, so even a nested acquire from the same process fails
// with ErrBusy; they use DrainPendingLocked, which runs the identical
// round under the caller's own lock (connect's backlog pass does).
func DrainPending(ctx context.Context, opt Options, gate Gate) (Result, error) {
	stateDir := strings.TrimSpace(opt.StateDir)
	if stateDir == "" {
		return Result{}, errors.New("collector state directory is required")
	}
	lock, err := runlock.Acquire(stateDir)
	if err != nil {
		return Result{}, err
	}
	defer lock.Close()
	return DrainPendingLocked(ctx, opt, gate, lock)
}

// DrainPendingLocked is DrainPending's already-held-lock path: the full
// drain-only round WITHOUT acquiring the collector runlock. The caller
// must hold the state lock for opt.StateDir across the whole call and
// hand it in; the handle is verified first (runlock.Lock.Validate:
// non-nil, not closed, bound to this state directory's lock file), so a
// nil, released or foreign lock fails closed before any local-state or
// network work — busy content alone (another process holding the
// directory) can never read as "the caller holds the lock". The caller
// must not close the lock before this call returns. Connect's backlog
// pass runs the cursor drain this way — under the one lock it owns for
// the whole pass, never one taken here — so an in-lock caller can
// neither deadlock nor starve itself with ErrBusy. Single-writer
// serialization of the license, outbox and cache writes below relies
// entirely on that caller-held lock.
func DrainPendingLocked(ctx context.Context, opt Options, gate Gate, lock *runlock.Lock) (Result, error) {
	stateDir := strings.TrimSpace(opt.StateDir)
	if stateDir == "" {
		return Result{}, errors.New("collector state directory is required")
	}
	if err := lock.Validate(stateDir); err != nil {
		return Result{}, fmt.Errorf("cursor drain requires the caller's state lock: %w", err)
	}
	res := Result{}
	store := cursorsource.New(opt.StateDir)
	license, ok, err := store.Load()
	if err != nil {
		res.Outcome = RoundError
		return res, err
	}
	if !ok {
		res.Skipped = "no local cursor permit (run toktrail connect or toktrail cursor enable)"
		res.Outcome = RoundNoPermit
		return res, nil
	}
	res.Status = license.Status
	if !license.Collectable() {
		res.Skipped = skipReasonForStatus(license.Status)
		res.Outcome = RoundAuthWithheld
		return res, nil
	}
	if !gate.cursorAllowed() {
		res.Skipped = "cursor is not allowed by the effective server grant scope for this device"
		res.Outcome = RoundAuthWithheld
		return res, nil
	}
	self, st, err := fetchSelf(ctx, opt)
	if err != nil {
		// The preflight itself failed (network, or persisting the
		// preflight accounting): an actual error, never an
		// authorization verdict.
		res.Outcome = RoundError
		return res, err
	}
	if self.Paused || !self.UploadAuthorized || self.Revoked {
		res.Skipped = fmt.Sprintf("device is not authorized to upload (paused=%t revoked=%t)", self.Paused, self.Revoked)
		// Paused is a state (temporary, work stays queued); revoked or
		// an unauthorized device is an authorization verdict. Either
		// way the backlog the verdict keeps queued is recounted — an
		// unrunnable round with batches pending must never read as an
		// empty queue (the periodic §6.5 judgment keys on it).
		if self.Paused {
			res.Outcome = RoundPaused
		} else {
			res.Outcome = RoundAuthWithheld
		}
		if err := countPendingFailClosed(&res, opt.StateDir); err != nil {
			return res, err
		}
		return res, nil
	}
	effectiveGate := Gate{AllowedTools: gate.AllowedTools}
	if len(effectiveGate.AllowedTools) == 0 {
		effectiveGate.AllowedTools = self.AllowedTools
	}
	if !effectiveGate.cursorAllowed() || !(Gate{AllowedTools: self.AllowedTools}).cursorAllowed() {
		res.Skipped = "cursor is not allowed by the effective server grant scope for this device"
		res.Outcome = RoundAuthWithheld
		return res, nil
	}
	src, found := findSource(self.AccountSources, license.SourceInstanceID)
	if !found {
		res.Skipped = "the server no longer designates this device as the executor of the cursor source (reassign it on the website, then re-run toktrail cursor enable)"
		res.Outcome = RoundAuthWithheld
		return res, nil
	}
	if skip := sourceStateSkip(src.State); skip != "" {
		res.Skipped = skip
		res.Outcome = sourceStateOutcome(src.State)
		// A paused (or otherwise non-collecting) source keeps its
		// backlog queued: recount it so the skip never reads as an
		// empty queue.
		if err := countPendingFailClosed(&res, opt.StateDir); err != nil {
			return res, err
		}
		return res, nil
	}
	if src.NextRevision > license.NextRevision {
		license.NextRevision = src.NextRevision
	}
	if license.NextRevision < 1 || license.NextRevision > maxNextRevision {
		res.Outcome = RoundError
		return res, fmt.Errorf("cursor source nextRevision %d is outside the safe range 1..%d", license.NextRevision, maxNextRevision)
	}
	if src.FenceVersion < license.FenceVersion {
		res.Outcome = RoundError
		return res, fmt.Errorf("server fence version %d moved backwards below the recorded %d", src.FenceVersion, license.FenceVersion)
	}
	license.ConsentRevision = self.ConsentRevision
	ledger := cursoroutbox.New(opt.StateDir)
	if _, _, err := ledger.Recover(); err != nil {
		res.Outcome = RoundError
		return res, err
	}
	if src.FenceVersion != license.FenceVersion {
		pending, pErr := ledger.CountPending()
		if pErr != nil {
			res.Outcome = RoundError
			return res, pErr
		}
		res.PendingRemaining = pending
		res.PendingCounted = true
		res.Skipped = "cursor source fence changed; a full sync is required to recover pending history"
		res.Outcome = RoundFenceStop
		return res, nil
	}
	res.Ran = true
	stopped, err := drain(ctx, opt, gate, st, &license, &res, self)
	if err != nil {
		// The failed batch stays pending; keep the count honest so a
		// failed queue never reads as an empty one.
		if pending, pErr := ledger.CountPending(); pErr == nil {
			res.PendingRemaining = pending
			res.PendingCounted = true
		}
		if sErr := store.Save(license); sErr != nil {
			res.Outcome = RoundError
			return res, sErr
		}
		return res, err
	}
	pending, err := ledger.CountPending()
	if err != nil {
		res.Outcome = RoundError
		return res, err
	}
	res.PendingRemaining = pending
	res.PendingCounted = true
	if sErr := store.Save(license); sErr != nil {
		res.Outcome = RoundError
		return res, sErr
	}
	if stopped {
		res.Skipped = "cursor upload stopped because the server authorization or source state changed; a full sync is required"
	}
	if res.Outcome == RoundAbsent {
		res.Outcome = RoundRan
	}
	return res, nil
}

// Sync performs one cursor source round: refresh the server view, drain
// pending batches first, then pull the window, persist new batches, and
// drain again. Pull success means durably persisted locally; upload
// progress is tracked separately by the outbox.
func Sync(ctx context.Context, opt Options, gate Gate) (Result, error) {
	res := Result{}
	store := cursorsource.New(opt.StateDir)
	license, ok, err := store.Load()
	if err != nil {
		res.Outcome = RoundError
		return res, err
	}
	if !ok {
		res.Skipped = "no local cursor permit (run toktrail connect or toktrail cursor enable)"
		res.Outcome = RoundNoPermit
		return res, nil
	}
	res.Status = license.Status
	if !license.Collectable() {
		res.Skipped = skipReasonForStatus(license.Status)
		res.Outcome = RoundAuthWithheld
		return res, nil
	}
	if !gate.cursorAllowed() {
		res.Skipped = "cursor is not allowed by the effective server grant scope for this device"
		res.Outcome = RoundAuthWithheld
		return res, nil
	}

	// Fresh server view: consent, account source state, fence and
	// nextRevision. This is also the upload preflight.
	self, st, err := fetchSelf(ctx, opt)
	if err != nil {
		// The preflight itself failed (network, or persisting the
		// preflight accounting): an actual error, never an
		// authorization verdict.
		res.Outcome = RoundError
		return res, err
	}
	if self.Paused || !self.UploadAuthorized || self.Revoked {
		res.Skipped = fmt.Sprintf("device is not authorized to upload (paused=%t revoked=%t)", self.Paused, self.Revoked)
		// Paused is a state (temporary, work stays queued); revoked or
		// an unauthorized device is an authorization verdict. Either
		// way the backlog the verdict keeps queued is recounted — an
		// unrunnable round with batches pending must never read as an
		// empty queue (the periodic §6.5 judgment keys on it).
		if self.Paused {
			res.Outcome = RoundPaused
		} else {
			res.Outcome = RoundAuthWithheld
		}
		if err := countPendingFailClosed(&res, opt.StateDir); err != nil {
			return res, err
		}
		return res, nil
	}
	// Effective scope, applied BEFORE any credential read or pull: the
	// direct CLI passes an unrestricted Gate and relies on this fresh
	// self view; the periodic run passes the grant sync's overlay of the
	// same server. Merge conservatively: a non-empty tool list (either
	// side) must include Cursor, the later history bound wins, and the
	// pull end never exceeds the server's upload window.
	effectiveGate := Gate{AllowedTools: gate.AllowedTools}
	if len(effectiveGate.AllowedTools) == 0 {
		effectiveGate.AllowedTools = self.AllowedTools
	}
	if !effectiveGate.cursorAllowed() || !(Gate{AllowedTools: self.AllowedTools}).cursorAllowed() {
		res.Skipped = "cursor is not allowed by the effective server grant scope for this device"
		res.Outcome = RoundAuthWithheld
		return res, nil
	}
	effectiveGate.HistoryFrom = laterTime(gate.HistoryFrom, self.HistoryFrom)
	src, found := findSource(self.AccountSources, license.SourceInstanceID)
	if !found {
		res.Skipped = "the server no longer designates this device as the executor of the cursor source (reassign it on the website, then re-run toktrail cursor enable)"
		res.Outcome = RoundAuthWithheld
		return res, nil
	}
	if skip := sourceStateSkip(src.State); skip != "" {
		res.Skipped = skip
		res.Outcome = sourceStateOutcome(src.State)
		// A paused (or otherwise non-collecting) source keeps its
		// backlog queued: recount it so the skip never reads as an
		// empty queue.
		if err := countPendingFailClosed(&res, opt.StateDir); err != nil {
			return res, err
		}
		return res, nil
	}
	// nextRevision refresh: a new writer uses max(localNext, serverNext)
	// so a recreated source or a lost license never restarts at 1.
	if src.NextRevision > license.NextRevision {
		license.NextRevision = src.NextRevision
	}
	if license.NextRevision < 1 || license.NextRevision > maxNextRevision {
		res.Outcome = RoundError
		return res, fmt.Errorf("cursor source nextRevision %d is outside the safe range 1..%d", license.NextRevision, maxNextRevision)
	}
	if src.FenceVersion < license.FenceVersion {
		res.Outcome = RoundError
		return res, fmt.Errorf("server fence version %d moved backwards below the recorded %d", src.FenceVersion, license.FenceVersion)
	}
	fenceMoved := src.FenceVersion != license.FenceVersion
	license.FenceVersion = src.FenceVersion
	license.ConsentRevision = self.ConsentRevision

	res.Ran = true

	// Drain pending batches FIRST (they carry their persisted revisions;
	// retries never change them). A moved fence fences stale batches out
	// instead of re-sending them.
	ledger := cursoroutbox.New(opt.StateDir)
	if _, _, err := ledger.Recover(); err != nil {
		res.Outcome = RoundError
		return res, err
	}
	if fenceMoved {
		if fenced, ferr := ledger.MarkFenced(license.FenceVersion); ferr != nil {
			res.Outcome = RoundError
			return res, ferr
		} else if fenced > 0 {
			res.Note = appendNote(res.Note, fmt.Sprintf("%d pending batch(es) fenced out after the source fence moved", fenced))
		}
		// The fenced batches were never ACKed, yet the local event ledger
		// still marks their events as produced and the pull watermark as
		// covered — leaving either in place would silently lose every
		// event outside the overlap window. Reset both to the authorized
		// recovery window: this round re-produces everything from the
		// effective history start with fresh revisions, and the server
		// replaces by (subject, eventKey).
		if _, dErr := usage.DeleteCacheFile(opt.StateDir); dErr != nil {
			res.Outcome = RoundError
			return res, dErr
		}
		license.PullWatermark = nil
		license.PullCutoff, license.PullUnlimited = nil, false
		license.LastFullPullAt = nil
		res.Note = appendNote(res.Note, "source fence moved: local event ledger and pull watermark reset for recovery")
	}
	stopped, err := drain(ctx, opt, gate, st, &license, &res, self)
	if err != nil {
		// The failed batch stays pending; keep the count honest so a
		// failed queue never reads as an empty one.
		if pending, pErr := ledger.CountPending(); pErr == nil {
			res.PendingRemaining = pending
			res.PendingCounted = true
		}
		if sErr := store.Save(license); sErr != nil {
			res.Outcome = RoundError
			return res, sErr
		}
		return res, err
	}
	if stopped {
		// The server moved (fence, consent or source state) between the
		// preflight and the upload: end the round WITHOUT pulling or
		// advancing anything — never continue under a stale authorization
		// and never report the round as fully successful. drain() has
		// already recorded the structured stop outcome.
		if countErr := countPendingFailClosed(&res, opt.StateDir); countErr != nil {
			return res, countErr
		}
		if sErr := store.Save(license); sErr != nil {
			res.Outcome = RoundError
			return res, sErr
		}
		return res, nil
	}

	// Read the desktop credential, validate it live, and verify the
	// account still matches the confirmed one. A different account pauses
	// collection — the collector never switches accounts automatically.
	_, accountID, sessionToken, err := verifiedCredential(ctx, opt)
	if err != nil {
		// A mid-round credential failure (even one that pauses the
		// permit afterwards, like an expired login) is an actual
		// failure of this round, never an authorization verdict.
		res.Outcome = RoundError
		if errors.Is(err, api.ErrSessionExpired) {
			return res, classifyAuthError(store, &license, err)
		}
		return res, fmt.Errorf("cursor credential verification failed: %w", err)
	}
	match := identity.MatchAccount(accountID)
	if license.AccountMatchID != "" && match != license.AccountMatchID {
		license.Status = cursorsource.StatusPausedAccountSwitch
		if sErr := store.Save(license); sErr != nil {
			res.Outcome = RoundError
			return res, sErr
		}
		res.Status = license.Status
		res.Skipped = "the desktop login switched to a different Cursor account; collection paused (re-confirm with toktrail cursor enable)"
		// The paused permit keeps its backlog queued: recount it so the
		// skip never reads as an empty queue.
		if err := countPendingFailClosed(&res, opt.StateDir); err != nil {
			return res, err
		}
		// Work vs verdict: an account mismatch discovered before any
		// upload of this round is a pre-work authorization verdict;
		// the same mismatch AFTER this round already uploaded batches
		// (the drain-first sent data under the recorded account) is a
		// mid-round drift — Ran alone never decides this, only actual
		// synced work does.
		if res.SyncedBatches > 0 {
			res.Outcome = RoundFenceStop
		} else {
			res.Outcome = RoundAuthWithheld
		}
		return res, nil
	}

	// History widening: the pull watermark alone would hide newly
	// authorized older history — when the server moves the history start
	// from 7 to 30 days (or lifts it entirely), the watermark stays
	// recent and the extra history would never be fetched. Compare the
	// fresh effective cutoff against the one the last complete pull used;
	// on a widening, reset the watermark so this round re-fetches from
	// the new authorized start. The event cache stays: acknowledged
	// identities dedupe unchanged events, so only genuinely new older
	// history uploads.
	if historyWidened(&license, effectiveGate.HistoryFrom) {
		license.PullWatermark = nil
		license.PullCutoff, license.PullUnlimited = nil, false
		res.Note = appendNote(res.Note, "history authorization widened: pull watermark reset to re-fetch the newly authorized window")
	}
	// Daily full reconciliation: the regular PullOverlap misses upstream
	// backfill and corrections older than the overlap. The first round of
	// each UTC day (and every round after a watermark reset) pulls the
	// whole authorized window instead; LastFullPullAt advances only after
	// a complete, durably persisted pull. The pull still runs inside the
	// authorized window and the API client's hard budgets — no unlimited
	// beyond-window backfill is promised. A forced resync round
	// (Options.ForceResync) takes the same full window unconditionally,
	// so a reinstalled deployment re-covers everything currently
	// authorized even when the watermark says otherwise.
	fullPull := license.PullWatermark == nil || dueFullPull(opt.now(), license.LastFullPullAt) || opt.ForceResync
	// Pull window: overlap before the watermark (skipped for a full
	// pull), bounded by the effective (merged, fresh) history start; To
	// is frozen for the whole round and never exceeds the server's upload
	// window.
	from := time.Time{}
	if !fullPull && license.PullWatermark != nil {
		from = license.PullWatermark.Add(-PullOverlap)
	}
	if effectiveGate.HistoryFrom != nil && (from.IsZero() || effectiveGate.HistoryFrom.After(from)) {
		from = *effectiveGate.HistoryFrom
	}
	to := opt.now()
	if self.UploadUntil != nil && self.UploadUntil.Before(to) {
		to = *self.UploadUntil
	}
	events, err := opt.Pull(ctx, sessionToken, from, to)
	if err != nil {
		res.Outcome = RoundError
		if errors.Is(err, api.ErrSessionExpired) {
			return res, classifyAuthError(store, &license, err)
		}
		// Pull failure keeps the watermark, the cache and every pending
		// batch; it is never reported as zero usage.
		return res, fmt.Errorf("cursor usage pull failed (watermark not advanced): %w", err)
	}
	res.PulledEvents = len(events)
	// Clamp to the authorized window actually queried: the upstream may
	// answer rows outside the requested range, and rows at or beyond the
	// round end — notably past the server's UploadUntil cap — must never
	// be normalized, cached or uploaded. Future events come back through
	// the next round's overlap; rows before the window start were either
	// already covered by the watermark or arrive through the daily full
	// reconciliation.
	events = clampEvents(events, from, to)

	cache, err := usage.LoadCache(opt.StateDir)
	if err != nil {
		res.Outcome = RoundError
		return res, err
	}
	roundRevision := license.NextRevision
	// Normalize reads the cache read-only: staged entries are applied
	// only after the resulting batch is durable, so a failed round never
	// pollutes the live cache. A forced resync round additionally
	// re-emits unchanged events at the fresh revision instead of
	// skipping them (reinstall recovery); the cache itself is never
	// cleared. A fully successful forced round deliberately sets NO Note:
	// the count travels in Result.ReemittedRecords alone, so success
	// receipts keyed on an empty Note (the periodic layer's synced /
	// leaderboard status report) keep flowing.
	records, staged, stats, err := usage.NormalizeWithOptions(events, subjectNamespace(st), accountID, roundRevision, cache, usage.NormalizeOptions{
		ForceReemitUnchanged: opt.ForceResync,
	})
	if err != nil {
		res.Outcome = RoundError
		return res, fmt.Errorf("cursor usage normalization failed (watermark not advanced): %w", err)
	}
	res.NewRecords, res.ReplacedRecords = stats.NewRecords, stats.ReplacedRecords
	res.SkippedUnchanged, res.SkippedNoStableID = stats.SkippedUnchanged, stats.SkippedNoStableID
	res.ReemittedRecords = stats.ReemittedRecords

	if len(records) > 0 {
		for start := 0; start < len(records); start += protocol.MaxBatchRecords {
			end := start + protocol.MaxBatchRecords
			if end > len(records) {
				end = len(records)
			}
			batchID, bErr := newCursorBatchID(opt.now())
			if bErr != nil {
				res.Outcome = RoundError
				return res, bErr
			}
			batch := protocol.Batch{
				BatchID:          batchID,
				SourceInstanceID: license.SourceInstanceID,
				Records:          records[start:end],
			}
			encoded, encErr := protocol.EncodeBatch(batch)
			if encErr != nil {
				res.Outcome = RoundError
				return res, fmt.Errorf("encode cursor batch %s: %w", batchID, encErr)
			}
			if _, addErr := ledger.AddBatch(batch, license.FenceVersion, encoded); addErr != nil {
				res.Outcome = RoundError
				return res, fmt.Errorf("persist cursor batch %s: %w", batchID, addErr)
			}
			res.ExportedBatches++
		}
	}

	// The batch is durable: apply and commit the staged cache, advance the
	// round revision and the pull watermark. Upload failures after this
	// point never change revisions — the outbox retries the immutable
	// bytes.
	cache.Apply(staged)
	maxProduced := roundRevision
	for _, r := range records {
		if r.Revision > maxProduced {
			maxProduced = r.Revision
		}
	}
	if len(records) > 0 {
		license.NextRevision = maxProduced + 1
	}
	watermark := to
	license.PullWatermark = &watermark
	// Record the effective history cutoff this complete pull used (three
	// states: none, finite, unlimited) so a later widening is detectable,
	// and stamp the daily full-reconciliation clock when this round
	// covered the whole authorized window. A failed round never reaches
	// this point, so neither stamp advances on failure.
	if effectiveGate.HistoryFrom != nil {
		cutoff := *effectiveGate.HistoryFrom
		license.PullCutoff, license.PullUnlimited = &cutoff, false
	} else {
		license.PullCutoff, license.PullUnlimited = nil, true
	}
	if fullPull {
		fullAt := opt.now()
		license.LastFullPullAt = &fullAt
	}
	if license.Status == cursorsource.StatusPendingFirstSync {
		license.Status = cursorsource.StatusActive
		res.FirstSyncCompleted = true
		res.Status = license.Status
	}
	if err := cache.Commit(); err != nil {
		res.Outcome = RoundError
		return res, err
	}
	if err := store.Save(license); err != nil {
		res.Outcome = RoundError
		return res, err
	}

	// Drain what this round produced (bounded). A stop here (scope, fence
	// or source state moved mid-round) ends the run with the batches
	// safely pending; the pull itself already happened under the fresh
	// preflight, so only the drain outcome is affected. drain() records
	// the structured stop outcome itself.
	stopped, err = drain(ctx, opt, gate, st, &license, &res, self)
	if err != nil {
		// The failed batch stays pending; keep the count honest so a
		// failed queue never reads as an empty one.
		if pending, pErr := ledger.CountPending(); pErr == nil {
			res.PendingRemaining = pending
			res.PendingCounted = true
		}
		if sErr := store.Save(license); sErr != nil {
			res.Outcome = RoundError
			return res, sErr
		}
		return res, err
	}
	pending, err := ledger.CountPending()
	if err != nil {
		res.Outcome = RoundError
		return res, err
	}
	res.PendingRemaining = pending
	res.PendingCounted = true
	// A stop of the post-pull drain is recorded structurally by drain()
	// itself (RoundFenceStop / RoundPaused); the flag is consumed there.
	_ = stopped
	if res.Outcome == RoundAbsent {
		res.Outcome = RoundRan
	}
	return res, nil
}

// drain uploads pending batches up to the bound. The bound is the ROUND
// total: Sync calls drain twice (before and after the pull), and the
// budget counts batches already uploaded this round (res.SyncedBatches),
// so both calls together never exceed opt.maxBatches(). A receipt with
// rejected records is not a full acknowledgment: the batch stays pending
// and the error surfaces. Fence/consent/source-state changes STOP the
// drain without dropping anything; the returned flag tells the caller to
// end the round rather than continue under a stale authorization. A
// decline of the optional shared run budget (opt.Budget) is its own stop:
// the declined batch was never POSTed, acknowledged or dropped — it stays
// pending exactly as before, and the error (wrapping the syncbudget
// sentinel) tells the caller this run may not upload more while the next
// run resumes the backlog. With opt.Retry set, each batch upload runs
// under that policy (see uploadBatch); retries never consume the round's
// batch bound — only a fully acknowledged batch counts.
func drain(ctx context.Context, opt Options, gate Gate, st statedir.DeviceState, license *cursorsource.License, res *Result, self synccmd.SelfStatus) (bool, error) {
	ledger := cursoroutbox.New(opt.StateDir)
	report := newBatchReporter(opt)
	for res.SyncedBatches < opt.maxBatches() {
		entry, ok, err := ledger.NextPending()
		if err != nil {
			res.Outcome = RoundError
			return false, err
		}
		if !ok {
			return false, nil
		}
		batch, err := ledger.LoadBatchBytes(entry)
		if err != nil {
			res.Outcome = RoundError
			return false, err
		}
		encoded, err := protocol.EncodeBatch(batch)
		if err != nil {
			res.Outcome = RoundError
			return false, err
		}
		receipt, err := uploadBatch(ctx, opt, gate, st, license, self, ledger, entry, encoded)
		if err != nil {
			switch {
			case errors.Is(err, sourcebatch.ErrSourcePaused):
				// The server-side source paused under an upload: a pause
				// (queued work stays pending), not a boundary drift.
				res.Note = appendNote(res.Note, fmt.Sprintf("upload of batch %s stopped: %v", entry.BatchID, err))
				res.Outcome = RoundPaused
				report.emitOutcome(BatchResultPaused, time.Time{}, len(encoded), cursoroutbox.Receipt{}, false)
				return true, nil
			case errors.Is(err, sourcebatch.ErrFenceStale),
				errors.Is(err, sourcebatch.ErrSourceDeleted),
				errors.Is(err, sourcebatch.ErrStaleRevision),
				errors.Is(err, sourcebatch.ErrConsentStale),
				errors.Is(err, sourcebatch.ErrDeviceUnauthorized),
				errors.Is(err, errUploadBoundaryChanged):
				// An authorization-boundary drift mid-flight — work may
				// already have been uploaded under the old boundary, so
				// this must never read as a clean round.
				res.Note = appendNote(res.Note, fmt.Sprintf("upload of batch %s stopped: %v", entry.BatchID, err))
				res.Outcome = RoundFenceStop
				report.emitOutcome(BatchResultStopped, time.Time{}, len(encoded), cursoroutbox.Receipt{}, false)
				return true, nil
			case errors.Is(err, syncbudget.ErrTotalExhausted),
				errors.Is(err, syncbudget.ErrQueueExhausted),
				errors.Is(err, syncbudget.ErrDeadlineExceeded):
				// The run's shared upload budget declined the attempt
				// before any POST: the batch was not acknowledged and
				// not dropped — it stays pending, and the next run (with
				// a fresh budget) resumes from it. Report the backlog
				// the bounded run leaves behind so the result still
				// tells the truth; the wrapped sentinel distinguishes
				// this stop from an ordinary upload failure.
				if pending, pErr := ledger.CountPending(); pErr == nil {
					res.PendingRemaining = pending
					res.PendingCounted = true
				}
				res.Outcome = RoundError
				report.emitOutcome(BatchResultFailed, time.Time{}, len(encoded), cursoroutbox.Receipt{}, false)
				return false, fmt.Errorf("upload cursor batch %s: %w", entry.BatchID, err)
			}
			res.Outcome = RoundError
			report.emitOutcome(BatchResultFailed, time.Time{}, len(encoded), cursoroutbox.Receipt{}, false)
			return false, fmt.Errorf("upload cursor batch %s: %w", entry.BatchID, err)
		}
		if receipt.RejectedRecords > 0 {
			// A partial receipt is never a full acknowledgment: surface
			// the sanitized per-record rejections (index plus the stable
			// reason code, never server free text) and keep the batch
			// pending for the next round. It is a complete protocol
			// answer, so the retry policy never repeats it either.
			detail := describeRecordErrors(receipt.RecordErrors)
			if detail != "" {
				detail = ": " + detail
			}
			res.Outcome = RoundError
			report.emitOutcome(BatchResultRejected, time.Time{}, len(encoded), receipt, true)
			return false, fmt.Errorf("cursor batch %s had %d record(s) rejected by the server (batch stays pending)%s",
				entry.BatchID, receipt.RejectedRecords, detail)
		}
		ackStarted := report.now()
		if err := ledger.MarkSynced(receipt); err != nil {
			res.Outcome = RoundError
			// The receipt itself was valid and its counts are known; the
			// durable local acknowledgment is what failed.
			report.emitOutcome(BatchResultFailed, time.Time{}, len(encoded), receipt, true)
			return false, err
		}
		report.emitOutcome(BatchResultAcknowledged, ackStarted, len(encoded), receipt, true)
		res.SyncedBatches++
		res.SyncedRecords += receipt.AcceptedRecords
		syncedAt := receipt.ReceivedAt
		if syncedAt.IsZero() {
			syncedAt = opt.now()
		}
		license.LastSyncAt = &syncedAt
	}
	// The loop ended at the round's batch bound with work still queued: a
	// normal bounded stop. Callers that continue the queue (the fair
	// rotation's later steps) overwrite this with their own outcome; the
	// run-level bound stop is re-asserted by collection's rotation. An
	// unreadable queue fails closed — never default the round to "ran"
	// over a count it could not take.
	if res.Outcome == RoundAbsent {
		pending, pErr := ledger.CountPending()
		if pErr != nil {
			res.Outcome = RoundError
			return false, pErr
		}
		if pending > 0 {
			res.Outcome = RoundBounded
		}
	}
	return false, nil
}

// uploadBatch sends one immutable outbox batch to the server, running the
// optional retry policy (opt.Retry) around the real POSTs.
//
// A nil policy keeps the historical single attempt exactly: one
// MarkAttempt, one sourcebatch.PostBatch with no retry classification, no
// preflight — byte-for-byte the pre-retry behavior.
//
// With a policy, every attempt is a full re-send of the SAME encoded bytes
// under the SAME authorization boundary (device credentials, source fence
// and consent revision the round prefetched). The send callback re-reads
// the device self view before every retry and verifies the boundary did
// not move (verifyUploadBoundary), persists its own MarkAttempt
// immediately before the POST, and lets PostBatch reserve the shared run
// budget for each real POST on its own (a decline is final and stops the
// loop without waiting). sourcebatch classifies transient failures as
// retryable; every other failure — business codes, authorizations,
// receipt validation — returns final and ends the loop immediately.
//
// Acknowledgment stays with the caller: the receipt of the ONE successful
// attempt is returned after the policy reports success, and drain marks
// the batch synced exactly once. A partial (rejected) receipt is a valid
// protocol answer, returned as success here and surfaced as an error by
// the caller — it never retries, because re-sending cannot change which
// records the server rejects.
//
// Progress (opt.Progress) is wired through unchanged control flow only:
// each real POST attempt emits one http event (via the upload client's
// sanitized per-call facts — a pre-POST refusal like a declined budget
// emits none), every retried attempt is preceded by one wait event
// (the observed inter-attempt spacing) and one preflight event (the
// boundary re-verification), and the terminal outcome event is drain's
// to emit. None of it feeds back into any decision.
func uploadBatch(ctx context.Context, opt Options, gate Gate, st statedir.DeviceState, license *cursorsource.License, self synccmd.SelfStatus, ledger cursoroutbox.Store, entry cursoroutbox.Entry, encoded []byte) (cursoroutbox.Receipt, error) {
	report := newBatchReporter(opt)
	postOpt := sourcebatch.Options{
		ServerURL:         resolveServerURL(opt.ServerURL, st),
		HTTPClient:        opt.HTTPClient,
		DeviceID:          st.DeviceID,
		DeviceSecret:      st.DeviceSecret,
		SourceInstanceID:  license.SourceInstanceID,
		Budget:            opt.Budget,
		ClassifyRetryable: opt.Retry != nil,
	}
	// facts stashes the sanitized per-call facts of the most recent
	// PostBatch call (the low-layer truth: whether the request was
	// actually handed to the transport, and the strictly-validated
	// receipt's counts). Unwired without a progress callback.
	var facts sourcebatch.PostProgress
	if report.active() {
		postOpt.Progress = func(p sourcebatch.PostProgress) { facts = p }
	}
	if opt.Retry == nil {
		if err := ledger.MarkAttempt(entry.BatchID, opt.now()); err != nil {
			return cursoroutbox.Receipt{}, err
		}
		started := report.now()
		receipt, err := sourcebatch.PostBatch(ctx, postOpt, encoded, license.FenceVersion, self.ConsentRevision)
		report.emitHTTP(1, started, facts)
		return receipt, err
	}
	var receipt cursoroutbox.Receipt
	// lastDone is the observation-clock instant the previous attempt's
	// callback completed; the next attempt's wait event measures its
	// spacing from it. Maintained only while progress is wired.
	var lastDone time.Time
	err := opt.Retry.Do(ctx, func(ctx context.Context, attempt int) error {
		if report.active() {
			if attempt > 1 {
				report.emit(BatchProgress{
					Phase:             BatchPhaseWait,
					Result:            BatchResultOK,
					Attempt:           attempt,
					InterAttemptDelay: report.since(lastDone),
				})
			}
			defer func() { lastDone = report.now() }()
		}
		if attempt > 1 {
			// Retry preflight: prove the authorization boundary is
			// exactly the one this round's POSTs run under, re-reading
			// the live device self view. Anything that moved — or a view
			// that cannot be re-fetched — is a final stop, never a
			// bypass and never a retry under a different authorization.
			started := report.now()
			bErr := verifyUploadBoundary(ctx, opt, gate, license, self)
			result := BatchResultOK
			if bErr != nil {
				result = batchPreflightResult(bErr)
			}
			report.emit(BatchProgress{
				Phase:    BatchPhasePreflight,
				Result:   result,
				Attempt:  attempt,
				Duration: report.since(started),
			})
			if bErr != nil {
				return bErr
			}
		}
		// Durable attempt accounting precedes every real POST, retries
		// included.
		if err := ledger.MarkAttempt(entry.BatchID, opt.now()); err != nil {
			return err
		}
		started := report.now()
		r, pErr := sourcebatch.PostBatch(ctx, postOpt, encoded, license.FenceVersion, self.ConsentRevision)
		report.emitHTTP(attempt, started, facts)
		if pErr != nil {
			return pErr
		}
		receipt = r
		return nil
	})
	if err != nil {
		return cursoroutbox.Receipt{}, err
	}
	return receipt, nil
}

// verifyUploadBoundary re-reads the live device self view and proves the
// upload authorization boundary is exactly the one this round's batch
// POSTs run under: the device must still be an authorized, unpaused,
// unrevoked uploader; the consent revision the POSTs carry must still be
// current; the source instance must still be designated for this device,
// in a collecting state, under the same fence; and the cursor tool must
// still be inside the effective scope (the caller's gate merged with the
// fresh view exactly like the round start — the merge never widens).
//
// Any drift returns a final error wrapping the matching sourcebatch
// sentinel where one exists (device unauthorized, consent, source
// deleted, source paused, fence) or errUploadBoundaryChanged (scope
// narrowing, self view unavailable). The caller stops the round
// conservatively; it never adopts the moved values, never re-derives the
// boundary and never retries under a different authorization.
func verifyUploadBoundary(ctx context.Context, opt Options, gate Gate, license *cursorsource.License, round synccmd.SelfStatus) error {
	fresh, _, err := fetchSelf(ctx, opt)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			// A cancelled run propagates its cancellation unchanged:
			// wrapping it in errUploadBoundaryChanged would dress the
			// cancellation up as an authorization drift (a clean drift
			// stop with a nil error) and hide the real reason the round
			// ended.
			return ctxErr
		}
		return fmt.Errorf("%w: re-fetching the device self view failed: %w", errUploadBoundaryChanged, err)
	}
	if fresh.Paused || !fresh.UploadAuthorized || fresh.Revoked {
		return fmt.Errorf("%w (retry preflight: device paused=%t revoked=%t uploadAuthorized=%t)",
			sourcebatch.ErrDeviceUnauthorized, fresh.Paused, fresh.Revoked, fresh.UploadAuthorized)
	}
	if fresh.ConsentRevision != round.ConsentRevision {
		return fmt.Errorf("%w (retry preflight: consent revision moved from %d to %d)",
			sourcebatch.ErrConsentStale, round.ConsentRevision, fresh.ConsentRevision)
	}
	src, found := findSource(fresh.AccountSources, license.SourceInstanceID)
	if !found {
		// The recorded source id is untrusted historical text — a
		// permit persisted before the reflection boundary may carry a
		// credential a malicious server once mirrored — and is never
		// echoed into diagnostics.
		return fmt.Errorf("%w (retry preflight: the source is no longer designated for this device)",
			sourcebatch.ErrSourceDeleted)
	}
	if skip := sourceStateSkip(src.State); skip != "" {
		return fmt.Errorf("%w (retry preflight: %s)", sourcebatch.ErrSourcePaused, skip)
	}
	if src.FenceVersion != license.FenceVersion {
		return fmt.Errorf("%w (retry preflight: server fence moved from %d to %d)",
			sourcebatch.ErrFenceStale, license.FenceVersion, src.FenceVersion)
	}
	if !gate.cursorAllowed() || !(Gate{AllowedTools: fresh.AllowedTools}).cursorAllowed() {
		return fmt.Errorf("%w (retry preflight: cursor is no longer allowed by the effective server grant scope for this device)",
			errUploadBoundaryChanged)
	}
	oldFrom := laterTime(gate.HistoryFrom, round.HistoryFrom)
	newFrom := laterTime(gate.HistoryFrom, fresh.HistoryFrom)
	if newFrom != nil && (oldFrom == nil || newFrom.After(*oldFrom)) {
		return fmt.Errorf("%w (retry preflight: history scope narrowed)", errUploadBoundaryChanged)
	}
	if fresh.UploadUntil != nil && (round.UploadUntil == nil || fresh.UploadUntil.Before(*round.UploadUntil)) {
		return fmt.Errorf("%w (retry preflight: upload window narrowed)", errUploadBoundaryChanged)
	}
	return nil
}

// describeRecordErrors renders a receipt's sanitized record rejections —
// the record index plus the stable reason code only (the sourcebatch
// client already whitelists the codes and drops all server free text).
// An empty list renders as an empty string.
func describeRecordErrors(errs []cursoroutbox.RecordError) string {
	if len(errs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(errs))
	for _, re := range errs {
		if re.Code == "" {
			parts = append(parts, fmt.Sprintf("record %d rejected", re.Index))
			continue
		}
		parts = append(parts, fmt.Sprintf("record %d: %s", re.Index, re.Code))
	}
	return strings.Join(parts, "; ")
}

// ---------------------------------------------------------------------------
// Enable
// ---------------------------------------------------------------------------

// Enable performs the local confirmation and the server enable call, then
// runs the first sync. It never takes over an existing executor: a 409
// surfaces as ErrExecutorConflict with a clear message (reassignment is a
// website action).
//
// Order of trust: the FIRST-TIME confirmation strictly precedes any
// credential reading. An existing permit already covers reading, so
// re-enables verify first and only re-confirm when the account actually
// changed. Idempotence: an already-collectable permit for the same
// account with its source still listed and healthy on the self view is
// returned without a new confirmation.
func Enable(ctx context.Context, opt Options, confirm ConfirmFunc) (EnableResult, error) {
	out := opt.out()
	res := EnableResult{}
	store := cursorsource.New(opt.StateDir)
	statedirStore := statedir.New(opt.StateDir)
	st, err := statedirStore.Load()
	if err != nil {
		return res, err
	}
	if st.DeviceID == "" || st.DeviceSecret == "" {
		return res, errors.New("device is not bound; run toktrail connect first")
	}
	if opt.Auth == nil || opt.Verify == nil || opt.Pull == nil {
		return res, errors.New("cursor auth, verification or usage pull is not wired in this build")
	}

	self, _, err := fetchSelf(ctx, opt)
	if err != nil {
		return res, err
	}
	if self.Paused || !self.UploadAuthorized || self.Revoked {
		return res, fmt.Errorf("device is not authorized (paused=%t revoked=%t)", self.Paused, self.Revoked)
	}

	license, hasLicense, err := store.Load()
	if err != nil {
		return res, err
	}

	// First time: the local confirmation strictly precedes reading the
	// credential — an unattended run can never complete it by itself.
	if !hasLicense {
		if confirm == nil {
			confirm = DefaultConfirm
		}
		confirmed, cerr := confirm(EnableNotice, out)
		if cerr != nil {
			return res, fmt.Errorf("cursor enable needs an interactive local confirmation (run `toktrail cursor enable` in a terminal): %w", cerr)
		}
		if !confirmed {
			return res, errors.New("cursor enable declined by the user")
		}
		res.Confirmed = true
		// Server capability gate BEFORE the credential read: an old
		// server without account-source support can never store cursor
		// records, so the desktop login is not read (nor live-verified)
		// against it. A self view already listing account sources is
		// compatibility evidence and skips the extra round trip.
		if err := requireAccountSources(ctx, opt, self, st); err != nil {
			return res, fmt.Errorf("cursor enable needs a server with account-source support: %w", err)
		}
		_, accountID, _, err := verifiedCredential(ctx, opt)
		if err != nil {
			return res, fmt.Errorf("cursor credential verification failed: %w", err)
		}
		return enableServerAndSync(ctx, opt, self, st, store, cursorsource.License{}, false, identity.MatchAccount(accountID), res)
	}

	// Existing permit: reading is already covered. Verify the credential
	// to learn the current account before deciding what to do. The same
	// capability gate applies first: an old server cannot store cursor
	// records, so the login is not read against it needlessly.
	if err := requireAccountSources(ctx, opt, self, st); err != nil {
		return res, fmt.Errorf("cursor enable needs a server with account-source support: %w", err)
	}
	_, accountID, _, err := verifiedCredential(ctx, opt)
	if err != nil {
		if errors.Is(err, auth.ErrNoLogin) || errors.Is(err, api.ErrSessionExpired) {
			// The desktop login is gone: surface it, but the permit keeps
			// its state — the user re-confirms after logging back in.
			return res, fmt.Errorf("the Cursor desktop login is not currently usable; log into Cursor and re-run toktrail cursor enable: %w", err)
		}
		return res, fmt.Errorf("cursor credential verification failed: %w", err)
	}
	match := identity.MatchAccount(accountID)
	sameAccount := license.AccountMatchID == match

	// Already enabled for this account with the source still designated
	// and healthy: idempotent no-op.
	if license.Collectable() && sameAccount {
		if src, found := findSource(self.AccountSources, license.SourceInstanceID); found && sourceStateSkip(src.State) == "" {
			res.License = license
			res.Source = src
			res.Sync.Skipped = "permit already active"
			return res, nil
		}
	}

	// Re-confirmation is required only when the account actually changed
	// (switch pause). The same account reactivates without a new prompt.
	if !sameAccount {
		fmt.Fprintln(out, "检测到桌面登录切换到了另一个 Cursor 账号。")
		if confirm == nil {
			confirm = DefaultConfirm
		}
		confirmed, cerr := confirm(EnableNotice, out)
		if cerr != nil {
			return res, fmt.Errorf("cursor enable needs an interactive local confirmation (run `toktrail cursor enable` in a terminal): %w", cerr)
		}
		if !confirmed {
			return res, errors.New("cursor enable declined by the user")
		}
		res.Confirmed = true
	}
	return enableServerAndSync(ctx, opt, self, st, store, license, hasLicense, match, res)
}

// enableServerAndSync performs the server enable call, writes the permit
// and runs the first sync.
//
// State continuity: an existing permit keeps its pull watermark, recorded
// history cutoff, revision memory and event ledger ONLY when the server
// kept the same source instance, the account is unchanged and the source
// fence did not move. Otherwise the local state lies about what the
// server holds — a recreated source (deleteData + re-enable) starts empty
// server-side yet the cache would skip-unchanged its history; a different
// account derives different event keys; a moved fence invalidates the
// recorded revisions — and stale pending batches of the old source can
// never upload under the new identity and would block its drain forever.
// In every one of those cases the stale pending batches are terminally
// fenced, the event ledger and the pull-window memory are reset, and the
// first sync re-pulls from the authorized start with fresh revisions;
// the server replaces by (subject, eventKey), so nothing double-counts.
// A fresh permit (no local license) runs the same gate so leftover cache
// or outbox state from a logged-out permit cannot leak into the new one.
func enableServerAndSync(ctx context.Context, opt Options, self synccmd.SelfStatus, st statedir.DeviceState, store cursorsource.Store, license cursorsource.License, hasLicense bool, match string, res EnableResult) (EnableResult, error) {
	src, err := accountsource.Enable(ctx, accountsource.Options{
		ServerURL:       resolveServerURL(opt.ServerURL, st),
		HTTPClient:      opt.HTTPClient,
		DeviceID:        st.DeviceID,
		DeviceSecret:    st.DeviceSecret,
		ConsentRevision: self.ConsentRevision,
	}, cursorsource.SourceType)
	if err != nil {
		if errors.Is(err, accountsource.ErrExecutorConflict) {
			return res, fmt.Errorf("another device already collects this cursor account source; reassign the executor on the website first (%w)", err)
		}
		return res, err
	}
	res.ServerEnabled = true
	res.Source = src
	if src.NextRevision < 1 || src.NextRevision > maxNextRevision {
		return res, fmt.Errorf("server returned nextRevision %d outside the safe range 1..%d", src.NextRevision, maxNextRevision)
	}

	now := opt.now()
	if !hasLicense {
		license = cursorsource.License{
			SourceType:  cursorsource.SourceType,
			ConfirmedAt: now,
		}
	}
	// Continuity gate (see the function comment). The comparison runs on
	// the OLD license values, before they are overwritten below.
	if license.SourceInstanceID != src.SourceInstanceID ||
		license.AccountMatchID != match ||
		license.FenceVersion != src.FenceVersion {
		if fenced, ferr := cursoroutbox.New(opt.StateDir).MarkFencedForSource(src.SourceInstanceID, src.FenceVersion); ferr != nil {
			return res, ferr
		} else if fenced > 0 {
			fmt.Fprintf(opt.out(), "%d pending cursor batch(es) cannot upload under the changed source identity and were fenced out\n", fenced)
		}
		if _, dErr := usage.DeleteCacheFile(opt.StateDir); dErr != nil {
			return res, dErr
		}
		license.PullWatermark = nil
		license.PullCutoff, license.PullUnlimited = nil, false
		license.LastFullPullAt = nil
	}
	license.SchemaVersion = 1
	license.SourceInstanceID = src.SourceInstanceID
	license.SourceType = cursorsource.SourceType
	license.AccountMatchID = match
	license.Status = cursorsource.StatusPendingFirstSync
	license.ConfirmedAt = now
	license.ConsentRevision = self.ConsentRevision
	license.FenceVersion = src.FenceVersion
	// A new writer uses max(localNext, serverNext): a recreated source or
	// a lost license never restarts revisions at 1 (all-stale replays).
	if src.NextRevision > license.NextRevision {
		license.NextRevision = src.NextRevision
	}
	if license.NextRevision < 1 {
		license.NextRevision = 1
	}
	if err := store.Save(license); err != nil {
		return res, err
	}
	res.License = license

	// First sync round right away; failure leaves the permit at
	// pending_first_sync (the next periodic run retries).
	gate := Gate{AllowedTools: self.AllowedTools, HistoryFrom: self.HistoryFrom, Paused: self.Paused}
	syncRes, syncErr := Sync(ctx, opt, gate)
	res.Sync = syncRes
	if syncErr != nil {
		return res, fmt.Errorf("cursor enabled but the first sync failed (the permit stays pending; the next run retries): %w", syncErr)
	}
	if l, _, lErr := store.Load(); lErr == nil {
		res.License = l
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// Status / Logout
// ---------------------------------------------------------------------------

// StatusResult is the local view for `toktrail cursor status`.
type StatusResult struct {
	HasLicense bool
	License    cursorsource.License
	// Source is the server's view of this device's cursor source (zero
	// when the server does not list one for this device).
	Source    protocol.Source
	HasSource bool
	// ServerReached is false when the self view could not be fetched.
	ServerReached  bool
	ServerError    error
	PendingBatches int
}

// Status collects the local permit, the server source view and the
// outbox backlog. It never reads the Cursor credential.
func Status(ctx context.Context, opt Options) (StatusResult, error) {
	res := StatusResult{}
	store := cursorsource.New(opt.StateDir)
	license, ok, err := store.Load()
	if err != nil {
		return res, err
	}
	res.HasLicense, res.License = ok, license
	st, err := statedir.New(opt.StateDir).Load()
	if err != nil {
		return res, err
	}
	if st.DeviceID != "" {
		self, _, err := fetchSelf(ctx, opt)
		if err != nil {
			res.ServerError = err
		} else {
			res.ServerReached = true
			if ok {
				if src, found := findSource(self.AccountSources, license.SourceInstanceID); found {
					res.Source, res.HasSource = src, true
				}
			}
		}
	}
	res.PendingBatches, err = cursoroutbox.New(opt.StateDir).CountPending()
	if err != nil {
		return res, err
	}
	return res, nil
}

// Logout revokes the local permit. It never deletes already-uploaded data
// (the server-side deletion flow governs that). With purge it also
// removes the local usage cache, the cursor outbox and its batch files.
func Logout(opt Options, purge bool) (removedLicense, purgedCache bool, err error) {
	store := cursorsource.New(opt.StateDir)
	removedLicense, err = store.Delete()
	if err != nil {
		return false, false, err
	}
	if !purge {
		return removedLicense, false, nil
	}
	if err := cursoroutbox.Purge(opt.StateDir); err != nil {
		return removedLicense, false, err
	}
	purgedCache, err = usage.DeleteCacheFile(opt.StateDir)
	if err != nil {
		return removedLicense, false, err
	}
	return removedLicense, purgedCache, nil
}

// DefaultConfirm prints the notice and reads a y/N answer from stdin. A
// closed or non-interactive stdin fails with a clear message so an
// unattended run can never complete the first-time confirmation by
// itself. The answer read is strictly bounded (a confirmation is a few
// bytes; anything longer is refused without echoing it) and only an
// explicit yes/y confirms.
func DefaultConfirm(notice string, out io.Writer) (bool, error) {
	fmt.Fprintln(out, notice)
	fmt.Fprint(out, "确认在本机启用 Cursor 用量采集？[y/N] ")
	line, err := readBoundedLine(os.Stdin, 64)
	if err != nil {
		return false, fmt.Errorf("no interactive input available: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

// maxStdinTokenBytes bounds a manually supplied token: real Cursor tokens
// are far smaller; anything beyond this is refused without being echoed.
const maxStdinTokenBytes = 64 << 10

// readBoundedLine reads one line from r, at most max bytes (plus the
// newline). An over-long line is an error; the content read is never
// included in the error.
func readBoundedLine(r io.Reader, max int) (string, error) {
	br := bufio.NewReader(io.LimitReader(r, int64(max)+1))
	line, err := br.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	if len(line) > max {
		return "", fmt.Errorf("input exceeds %d bytes and was refused", max)
	}
	return line, nil
}

// stdinTokenProvider supplies a manually entered access token for one
// process only (`toktrail cursor sync --token-stdin`). The token is read
// from input with a hard length bound (never printed, never persisted,
// never written into the license, never echoed in errors); the local
// permit and server grant must already exist — this provider never
// enables anything by itself. The account identity is derived exclusively
// by the injected Verify function (api.VerifySession), never from
// unverified local hints. Interactive terminals are refused at the CLI
// layer: a token typed into a TTY would echo in cleartext.
type stdinTokenProvider struct{ r io.Reader }

// NewStdinTokenProvider returns an auth.Provider reading one access token
// (a single bounded line) from r. Callers must pass a non-interactive
// source (a pipe or file), not a terminal.
func NewStdinTokenProvider(r io.Reader) auth.Provider {
	return stdinTokenProvider{r: r}
}

func (p stdinTokenProvider) Fetch(ctx context.Context) (auth.Credential, error) {
	if err := ctx.Err(); err != nil {
		return auth.Credential{}, err
	}
	line, err := readBoundedLine(p.r, maxStdinTokenBytes)
	if err != nil {
		return auth.Credential{}, fmt.Errorf("no usable token on stdin: %w", err)
	}
	token := strings.TrimSpace(line)
	if token == "" {
		return auth.Credential{}, errors.New("the token read from stdin is empty")
	}
	return auth.Credential{AccessToken: token, Source: "manual-stdin"}, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func skipReasonForStatus(s cursorsource.Status) string {
	switch s {
	case cursorsource.StatusPausedAccountSwitch:
		return "permit paused: the desktop login switched to a different Cursor account; re-confirm with toktrail cursor enable"
	case cursorsource.StatusLoginExpired:
		return "permit paused: the Cursor desktop login expired; log into Cursor and re-confirm with toktrail cursor enable"
	default:
		return fmt.Sprintf("permit status %q does not collect", s)
	}
}

// sourceStateSkip maps server source states onto skip reasons; empty
// means the state collects. The accepted collecting states are "active"
// and "pending"; "paused" keeps batches queued. An unrecognized state
// renders as the fixed word "unknown" — the raw value is untrusted
// server text (it could mirror a credential) and is never echoed into
// the Skipped diagnostics that connect and the CLI print.
func sourceStateSkip(state string) string {
	switch strings.TrimSpace(state) {
	case "active", "pending", "":
		return ""
	case "paused":
		return "the cursor source is paused server-side"
	default:
		return "the cursor source is in an unknown server state"
	}
}

// sourceStateOutcome classifies a non-collecting server source state
// structurally, mirroring sourceStateSkip's switch: only the known
// "paused" state is a pause; any other non-collecting state is an
// authorization verdict (the state string itself travels in Skipped).
func sourceStateOutcome(state string) RoundOutcome {
	switch strings.TrimSpace(state) {
	case "paused":
		return RoundPaused
	default:
		return RoundAuthWithheld
	}
}

// countPendingFailClosed recounts the durable cursor queue onto a skip
// exit, failing closed when the ledger cannot be read: a round that
// skips while batches may still be queued (a paused device or source
// keeps its backlog) must never report an empty queue it could not
// count — the unreadable queue itself is an error, never a clean skip.
func countPendingFailClosed(res *Result, stateDir string) error {
	pending, err := cursoroutbox.New(stateDir).CountPending()
	if err != nil {
		res.Outcome = RoundError
		return err
	}
	res.PendingRemaining = pending
	res.PendingCounted = true
	return nil
}

// classifyAuthError maps credential failures onto the permit status: an
// expired/rejected login marks the permit login_expired; an environment
// problem (permissions while unattended) surfaces as an actionable error
// without degrading the permit.
//
// Desktop-state readability is NOT uniform: the state database is always
// opened read-only and WAL content is immutable, but a login that exists
// only in the WAL becomes readable only after Cursor itself closes and
// checkpoints it. Already-checkpointed state reads fine at any time, so
// the messages below never claim every login state is readable.
func classifyAuthError(store cursorsource.Store, license *cursorsource.License, err error) error {
	if errors.Is(err, api.ErrSessionExpired) {
		license.Status = cursorsource.StatusLoginExpired
		if sErr := store.Save(*license); sErr != nil {
			return sErr
		}
		return fmt.Errorf("the Cursor login was rejected or expired; the permit is paused (log into Cursor, then toktrail cursor enable): %w", err)
	}
	if errors.Is(err, auth.ErrNoLogin) {
		return fmt.Errorf("no Cursor desktop login is available: %w", err)
	}
	if errors.Is(err, auth.ErrPermission) {
		return fmt.Errorf("the Cursor desktop state cannot be read with the current permissions (typical for an unattended scheduled run); re-confirm interactively or fix the local access: %w", err)
	}
	if errors.Is(err, auth.ErrUnsupportedSchema) || errors.Is(err, auth.ErrUnavailable) {
		return fmt.Errorf("the Cursor desktop state exists but cannot be read right now (a fresh login may live only in the SQLite WAL until Cursor is closed and checkpoints it; already-checkpointed state reads fine): %w", err)
	}
	return fmt.Errorf("reading or verifying the Cursor credential failed: %w", err)
}

// fetchSelf re-reads the live device self view (GET /v1/devices/self)
// for every cursor round phase: the round-start preflight of Sync,
// DrainPendingLocked and Enable, the Status view, and the retry preflight
// of verifyUploadBoundary. Because these GETs are not batch-bound (no
// cursoroutbox MarkAttempt covers them), each one is preceded by the
// durable authorization-attempt accounting of the device outbox ledger
// (outbox.Store.RecordPreflightAttempt — the same preflight-attempts.json
// the device sync paths, the grant sync and the tool-status report use).
// An already-canceled run is checked BEFORE that write (ctx.Err is
// returned as-is, so errors.Is keeps identifying the cancellation) — a
// dead context never persists accounting. The accounting write itself
// must succeed BEFORE the GET, and a failure returns with zero HTTP
// traffic of any kind — no self GET, no ingest POST, nothing
// acknowledged or dropped, the source fence/consent and the local permit
// untouched (fail closed exactly like the MarkAttempt-before-POST rule).
// The accounting stores only a monotonic count and timestamps (opt.Now
// injectable for tests); a crash between the write and the GET can only
// over-count attempts, never under-count them or duplicate server
// traffic. Cancellation and GET errors keep their existing semantics and
// privacy shape: the surfaced accounting error carries only the ledger
// path and the write failure — never the Cursor credential, the account
// identity or any upstream response.
func fetchSelf(ctx context.Context, opt Options) (synccmd.SelfStatus, statedir.DeviceState, error) {
	store := statedir.New(opt.StateDir)
	st, err := store.Load()
	if err != nil {
		return synccmd.SelfStatus{}, st, err
	}
	// A canceled run must not even persist accounting state: check the
	// context before the durable write and surface the cancellation
	// unwrapped (errors.Is keeps matching context.Canceled /
	// DeadlineExceeded).
	if err := ctx.Err(); err != nil {
		return synccmd.SelfStatus{}, st, err
	}
	if _, err := outbox.New(opt.StateDir).RecordPreflightAttempt(opt.now()); err != nil {
		return synccmd.SelfStatus{}, st, fmt.Errorf("cannot persist the device self preflight accounting; no HTTP request was made: %w", err)
	}
	self, err := synccmd.FetchDeviceSelf(ctx, store, synccmd.Options{
		StateDir:   opt.StateDir,
		ServerURL:  opt.ServerURL,
		HTTPClient: opt.HTTPClient,
	})
	return self, st, err
}

func findSource(sources []protocol.Source, instanceID string) (protocol.Source, bool) {
	for _, s := range sources {
		if s.SourceInstanceID == instanceID && s.SourceType == cursorsource.SourceType {
			return s, true
		}
	}
	return protocol.Source{}, false
}

func resolveServerURL(optURL string, st statedir.DeviceState) string {
	if u := strings.TrimSpace(optURL); u != "" {
		return strings.TrimRight(u, "/")
	}
	if u := strings.TrimSpace(st.ServerURL); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://127.0.0.1:3211"
}

// subjectNamespace derives the event-key subject namespace from the bound
// device state: the TokTrail application id plus the external subject id,
// canonical and length-framed (identity.SubjectNamespace). The same
// subject is stable across devices and source instances, while different
// TokTrail applications never derive identical event keys for one
// external subject id. An unbound state yields "" and fails closed in
// Normalize.
func subjectNamespace(st statedir.DeviceState) string {
	return identity.SubjectNamespace(strings.TrimSpace(st.ApplicationID), strings.TrimSpace(st.ExternalSubjectID))
}

// laterTime returns the later of two optional timestamps (nil-safe); the
// later bound is the more restrictive history cutoff.
func laterTime(a, b *time.Time) *time.Time {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if b.After(*a) {
		return b
	}
	return a
}

// historyWidened reports whether the fresh effective history cutoff
// authorizes history older than the last complete pull covered. A nil
// cutoff means unrestricted, so a finite record becoming nil is a
// widening. Nothing recorded (fresh or legacy permit) never resets: an
// unknown past window is not evidence of widening, and resetting without
// evidence would re-pull everything on every upgrade. The watermark
// being nil already means the next pull starts at the authorized start,
// so there is nothing to widen then.
func historyWidened(license *cursorsource.License, fresh *time.Time) bool {
	if license.PullWatermark == nil {
		return false
	}
	if license.PullUnlimited {
		return false
	}
	if license.PullCutoff == nil {
		return false
	}
	if fresh == nil {
		return true
	}
	return fresh.Before(*license.PullCutoff)
}

// dueFullPull reports whether a full-window reconciliation pull is due:
// the first round of each UTC day (nothing recorded yet counts as due).
func dueFullPull(now time.Time, last *time.Time) bool {
	if last == nil {
		return true
	}
	a, b := now.UTC(), last.UTC()
	return a.Year() != b.Year() || a.YearDay() != b.YearDay()
}

// requireAccountSources verifies the server speaks the account-sources
// protocol before the collector reads the Cursor desktop credential: an
// old server cannot store cursor records, so reading (and live-verifying)
// the login against it would be pointless exposure. A self view that
// already lists account sources is itself compatibility evidence and
// skips the extra round trip, so the check does not repeat on every run.
func requireAccountSources(ctx context.Context, opt Options, self synccmd.SelfStatus, st statedir.DeviceState) error {
	if len(self.AccountSources) > 0 {
		return nil
	}
	return accountsource.RequireCapability(ctx, accountsource.Options{
		ServerURL:    resolveServerURL(opt.ServerURL, st),
		HTTPClient:   opt.HTTPClient,
		DeviceID:     st.DeviceID,
		DeviceSecret: st.DeviceSecret,
	})
}

// clampEvents restricts upstream rows to the authorized window actually
// queried [from, to). A divergent or hostile upstream may return rows
// outside the range it was asked for: rows at or after `to` (notably past
// the server's UploadUntil cap) must never be cached or uploaded — the
// next round's overlap picks them up once they are genuinely inside the
// window — and rows before `from` were either already covered by the
// watermark or arrive through the daily full reconciliation. A zero
// `from` (full pull from the authorized start) imposes no lower bound.
func clampEvents(events []api.UsageEvent, from, to time.Time) []api.UsageEvent {
	var out []api.UsageEvent
	for _, e := range events {
		if !from.IsZero() && e.TimestampMS < from.UnixMilli() {
			continue
		}
		if e.TimestampMS >= to.UnixMilli() {
			continue
		}
		out = append(out, e)
	}
	return out
}

func appendNote(note, add string) string {
	if note == "" {
		return add
	}
	return note + "; " + add
}

func newCursorBatchID(now time.Time) (string, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generate cursor batch id: %w", err)
	}
	return fmt.Sprintf("cursor-%s-%s", now.UTC().Format("20060102T150405Z"), hex.EncodeToString(buf[:])), nil
}
