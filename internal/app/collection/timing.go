package collection

import "time"

// ProgressEvent describes a coarse-grained collection stage transition,
// a count update, a per-batch send observation, a queue snapshot, or a
// periodic heartbeat. It is intentionally low-cardinality: events carry
// no batch, device, subject or record identifiers, no credentials, no
// URLs, no file paths, no record keys and no raw error text — only
// closed enums, monotonic durations behind Measured/Known bits, planned
// payload sizes and receipt counts behind ReceiptObserved.
type ProgressEvent struct {
	// Kind is "stage_start", "stage_end", "count", "batch", "queue", or
	// "heartbeat".
	Kind string
	// Stage names the coarse phase: prepare, grant_sync, cursor_sync,
	// source_scan, drain, tool_status, complete, history, backlog and so
	// on.
	Stage string
	// Source names the source-scoped stage; Input is retained for
	// compatibility but is not populated by collection progress events.
	Source string
	Input  string
	// StartedAt and EndedAt use wall-clock UTC for durable logs. Duration is
	// measured with Go's monotonic clock by subtracting the paired instants.
	StartedAt time.Time
	EndedAt   time.Time
	Duration  time.Duration
	// Err is a sanitized error summary for failed stages.
	Err string
	// Counts carry optional phase totals without adding stage-specific fields
	// to the top-level event schema.
	ExportedBatches  int
	ExportedRecords  int
	SyncedBatches    int
	SyncedRecords    int
	PendingRemaining int

	// ---- batch observations (Kind == ProgressBatch) ----
	//
	// Two sealed shapes share these fields, mirroring the producing
	// agents' real semantics verbatim rather than folding them into one
	// invented vocabulary:
	//
	//   - device (internal/syncclient.AttemptEvent): exactly one event
	//     per send attempt. Phase stays empty; AttemptStage names where
	//     the attempt ended ("prepare"|"upload"|"ack"); Result is
	//     "acked"|"retryable_failure"|"final_failure"; the whole-attempt
	//     phase durations below are gated by their Measured bits.
	//   - account (internal/app/cursorsync.BatchProgress): one event per
	//     phase. Phase is "preflight"|"wait"|"http"|"outcome" — the
	//     terminal outcome fires exactly once per uploaded batch; Result
	//     is the phase's sealed outcome ("ok"|"failed"|"stopped"|
	//     "paused"|"acknowledged"|"rejected"); Duration (gated by
	//     DurationKnown) is that phase's length. A wait phase is NEVER
	//     reported as an http duration, and InterAttempt carries the
	//     observed spacing only on wait events.
	//   - history (resync.ProgressEvent adapted in connect): one
	//     terminal event per parent batch; Phase stays empty.
	Queue string // device | cursor | history
	// Attempt is the 1-based attempt ordinal within the batch's upload.
	// Account terminal outcome events carry 0 (they belong to the batch
	// as a whole).
	Attempt int
	// Phase is the account source's sealed phase (see above); empty on
	// whole-attempt and terminal-only shapes.
	Phase string
	// AttemptStage is the device attempt's ended stage ("prepare"|
	// "upload"|"ack"); empty on the other shapes.
	AttemptStage string
	// Result is the producing agent's sealed outcome vocabulary for the
	// attempt or phase (see the shapes above).
	Result string
	// Whole-attempt phase durations (device shape). Each is valid only
	// when its Measured bit is set: a cleared bit means the phase was
	// never reached, never a genuine zero. Prepare includes SelfCheck;
	// SelfCheck times the authorization preflight call as a whole and
	// makes no claim that an HTTP request reached the wire; InterAttempt
	// is the observed spacing from the previous attempt's conclusion and
	// is deliberately not labeled a backoff.
	Prepare, SelfCheck, HTTP, ACK, InterAttempt                                         time.Duration
	PrepareMeasured, SelfCheckMeasured, HTTPMeasured, ACKMeasured, InterAttemptMeasured bool
	// Duration is the phase's length on account events (valid only when
	// DurationKnown), the stage's length on stage_end events and the
	// stage's elapsed time on heartbeat events.
	DurationKnown bool
	// PayloadBytes is the PLANNED size of the serialized request payload
	// in play — never a claim of bytes actually transmitted. Valid only
	// when PayloadBytesKnown.
	PayloadBytes      int64
	PayloadBytesKnown bool
	// Receipt fields are valid only when ReceiptObserved: an unseen,
	// undecodable or unvalidated receipt is never reported as zero
	// accepts or a false replay. AcceptedRecords is the receipt's
	// per-batch decision count and nothing more — with BatchReplay false
	// it must NOT be read as records the server newly added (a record
	// may already have been accepted under another batch), and with
	// BatchReplay true the counts belong to the stored receipt.
	AcceptedRecords int
	RejectedRecords int
	ReceiptObserved bool
	BatchReplay     bool
	// FirstBatchConfirmation reports whether THIS LOCAL BATCH completed
	// its pending→synced transition for the first time, strictly from
	// local persistent evidence (the entry was selected as pending and a
	// valid receipt durably confirmed it). It makes no record-level
	// claim, does not require BatchReplay=false (a lost-response resend
	// that returns a replay receipt can still be the local first
	// confirmation), and is "unknown" whenever the evidence is absent.
	FirstBatchConfirmation string // yes | no | unknown
	// Origin is the batch's locally-known provenance; OriginUnknown when
	// it cannot be established.
	Origin string

	// ---- queue snapshots and heartbeats ----
	// (Kind == ProgressQueue, and the aggregate carried by
	// Kind == ProgressHeartbeat.)
	PendingBatches int
	PendingRecords int
	// Counted reports whether the pending snapshot is a real ledger
	// read: an unread queue is never reported as an observed empty one.
	Counted bool
	// RecordsCounted reports whether the record total is known: an
	// older ledger without per-entry record counts decodes them as
	// zero, so PendingRecords is valid only under this gate.
	RecordsCounted bool
	// PendingBytes is valid only when BytesCounted: every pending batch
	// file was stat'd successfully. A failed stat is unknown, never zero.
	PendingBytes int64
	BytesCounted bool
	// OldestPendingAge is valid only when AgeCounted: at least one
	// pending entry carried a usable persisted CreatedAt. Ages use the
	// persisted wall clock; negative skew clamps to zero.
	OldestPendingAge time.Duration
	AgeCounted       bool
	// Heartbeat-only: the in-flight send attempt and the drain rate.
	// AttemptInFlight is valid only when AttemptInFlightKnown is set:
	// a queue whose flow has no accurate Begin/End attempt hooks (the
	// first-enable round, the history phase) reports UNKNOWN — the
	// field is omitted, never defaulted to false.
	AttemptInFlightKnown bool
	AttemptInFlight      bool
	AttemptElapsed       time.Duration
	// ProcessingRateRecPerSec is the processing/drain rate — accepted
	// records per second over the drain, re-deliveries included. It is
	// deliberately NOT a "new data" rate: record-level first
	// confirmations and server-side novelty are both unknown without a
	// protocol change. Valid only when RateKnown is set: a drain that
	// never started, or whose observation window has no positive
	// elapsed time, computes no rate at all — never a fabricated zero.
	ProcessingRateRecPerSec float64
	RateKnown               bool
	// FirstBatchConfirmedBatches counts only "yes" first batch
	// confirmations — batch granularity, never records.
	FirstBatchConfirmedBatches int
	Samples                    int
	// Eta is the estimated time to drain the observed pending queues,
	// valid only when EtaKnown.
	Eta      time.Duration
	EtaKnown bool
}

const (
	ProgressStageStart = "stage_start"
	ProgressStageEnd   = "stage_end"
	ProgressCount      = "count"
	ProgressBatch      = "batch"
	ProgressQueue      = "queue"
	ProgressHeartbeat  = "heartbeat"
)

// Queue labels for batch and queue events.
const (
	ProgressQueueDevice  = "device"
	ProgressQueueCursor  = "cursor"
	ProgressQueueHistory = "history"
)

// FirstBatchConfirmation values.
const (
	FirstBatchConfirmationYes     = "yes"
	FirstBatchConfirmationNo      = "no"
	FirstBatchConfirmationUnknown = "unknown"
)

// Origin values. OriginReorgChild also covers quarantine-recovery
// re-pends: the outbox marks both with OriginConsentRevision and does
// not distinguish them further.
const (
	OriginFreshExport        = "fresh_export"
	OriginPendingBacklog     = "pending_backlog"
	OriginHistoryRetransmit  = "history_retransmit"
	OriginReorgChild         = "reorg_child"
	OriginQuarantineRecovery = "quarantine_recovery"
	OriginCursorReemit       = "cursor_reemit"
	OriginUnknown            = "unknown"
)

func emitProgress(progress func(ProgressEvent), event ProgressEvent) {
	if progress == nil {
		return
	}
	progress(event)
}

func startProgress(progress func(ProgressEvent), stage, source, input string) (time.Time, time.Time) {
	startedMono := time.Now()
	startedWall := startedMono.UTC()
	emitProgress(progress, ProgressEvent{
		Kind:      ProgressStageStart,
		Stage:     stage,
		Source:    source,
		StartedAt: startedWall,
	})
	return startedMono, startedWall
}

func endProgress(progress func(ProgressEvent), stage, source, input string, startedMono, startedWall time.Time, err error, counts ProgressEvent) {
	ended := time.Now()
	event := counts
	event.Kind = ProgressStageEnd
	event.Stage = stage
	event.Source = source
	event.Input = ""
	event.StartedAt = startedWall
	event.EndedAt = ended.UTC()
	event.Duration = ended.Sub(startedMono)
	if err != nil {
		event.Err = "stage failed"
	}
	emitProgress(progress, event)
}
