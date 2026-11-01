package connect

import (
	"time"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/app/resync"
)

// Connect's progress wiring: phase markers for its own orchestration
// stages and the history adapter into the unified stream. Everything
// dispatches through the serialized fn built in Sync, so no invocation
// ever runs concurrently with a round's emitter or another phase.

// emitProgressStageStart emits one stage_start marker; it returns the
// monotonic start (zero when progress is nil, which also disables the
// paired end marker).
func emitProgressStageStart(progress func(collection.ProgressEvent), stage string) time.Time {
	if progress == nil {
		return time.Time{}
	}
	started := time.Now()
	progress(collection.ProgressEvent{
		Kind:      collection.ProgressStageStart,
		Stage:     stage,
		StartedAt: started.UTC(),
	})
	return started
}

// emitProgressStageEnd emits the paired stage_end marker.
func emitProgressStageEnd(progress func(collection.ProgressEvent), stage string, started time.Time) {
	if progress == nil || started.IsZero() {
		return
	}
	ended := time.Now()
	progress(collection.ProgressEvent{
		Kind:      collection.ProgressStageEnd,
		Stage:     stage,
		StartedAt: started.UTC(),
		EndedAt:   ended.UTC(),
		Duration:  ended.Sub(started),
	})
}

// historyBatchEvent adapts one history retransmission batch outcome
// into the unified stream. Result carries resync's sealed outcome
// vocabulary verbatim (done | blocked | failed). The receipt fields
// stay conservatively UNKNOWN: resync's done outcome AGGREGATES the
// parent batch's stored receipts — every child upload, including
// receipts recorded by earlier rounds of a resumed job, with Replay as
// the OR across them, and a resumed batch can complete with zero
// uploads this round. Those aggregates are neither one batch's receipt
// nor this round's processing, so they are never presented as either;
// the phase totals remain visible through the §6.5 result summary.
// FirstBatchConfirmation is "no" with local evidence: resync executes
// over the already-synced archive, so the parent batch was synced
// before this run — no record-level claim is made.
func historyBatchEvent(ev resync.ProgressEvent) collection.ProgressEvent {
	return collection.ProgressEvent{
		Kind:                   collection.ProgressBatch,
		Queue:                  collection.ProgressQueueHistory,
		Result:                 ev.Outcome,
		Origin:                 collection.OriginHistoryRetransmit,
		FirstBatchConfirmation: collection.FirstBatchConfirmationNo,
	}
}
