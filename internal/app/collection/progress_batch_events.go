package collection

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/local/cursoroutbox"
	"toktrail-collector/internal/local/outbox"
	synccmd "toktrail-collector/internal/syncclient"
)

// This file adapts the producing agents' sealed per-batch event types
// into the unified ProgressEvent stream and reads the honest queue
// snapshots. The adapters add exactly two facts the producers cannot
// know — the queue label and the local first-batch-confirmation
// evidence — and copy everything else verbatim behind its Observed/
// Known gates. They never fold one producer's vocabulary into another's
// (an account wait phase is never reported as an http duration, and an
// unknown receipt is never reported as zero counts).

// deviceAttemptEvents adapts internal/syncclient's per-attempt events
// for one device outbox drain step into the unified stream.
// parentReorgShaped reports whether the pending entry the step selected
// carries OriginConsentRevision (a scope-reorganization child or a
// quarantine-recovery re-pend). syncclient may replace the
// actually-sent batch with a split child of the selected entry BEFORE
// the POST (an oversize reorganization or the first attempt's
// consent-scope gate), so the origin is derived conservatively from
// metadata the step already holds — never from a fresh ledger read per
// event (that would be O(N²) disk traffic on large backlogs) and never
// as a guess. A nil emitter returns nil (the producer side then stays
// unwired).
func deviceAttemptEvents(emitter *ProgressEmitter, parentReorgShaped bool) func(synccmd.AttemptEvent) {
	if emitter == nil {
		return nil
	}
	return func(ev synccmd.AttemptEvent) {
		unified := deviceAttemptEvent(ev, parentReorgShaped)
		emitter.Dispatch(unified)
		if ev.Result == synccmd.ResultAcked {
			// The attempted batch was pending-selected by this drain
			// step (or born pending by this run's split), so the
			// receipt's durable ACK is that batch's first local
			// confirmation — exactly one per acked attempt.
			emitter.AddBatchOutcome(ev.Accepted, 1)
		}
	}
}

// deviceAttemptEvent maps one device AttemptEvent. Every duration and
// the payload size are copied only behind their Observed bits; the
// receipt fields only behind ReceiptKnown.
func deviceAttemptEvent(ev synccmd.AttemptEvent, parentReorgShaped bool) ProgressEvent {
	e := ProgressEvent{
		Kind:            ProgressBatch,
		Queue:           ProgressQueueDevice,
		Attempt:         ev.Attempt,
		AttemptStage:    ev.Stage.String(),
		Result:          ev.Result.String(),
		AcceptedRecords: ev.Accepted,
		RejectedRecords: ev.Rejected,
		ReceiptObserved: ev.ReceiptKnown,
		BatchReplay:     ev.BatchReplay,
		Origin:          deviceSentBatchOrigin(parentReorgShaped),
	}
	if ev.Result == synccmd.ResultAcked {
		// The attempted batch was pending when this drain selected it
		// (or was born pending by this run's split): the receipt's
		// durable ACK is its first local confirmation, regardless of
		// BatchReplay — a lost-response resend can return a replay
		// receipt for a batch no local ACK ever covered.
		e.FirstBatchConfirmation = FirstBatchConfirmationYes
	} else {
		// This attempt completed no local transition.
		e.FirstBatchConfirmation = FirstBatchConfirmationNo
	}
	if ev.Observed.Has(synccmd.ObservedPrepare) {
		e.Prepare = ev.PrepareDuration
		e.PrepareMeasured = true
	}
	if ev.Observed.Has(synccmd.ObservedSelfCheck) {
		e.SelfCheck = ev.SelfCheckDuration
		e.SelfCheckMeasured = true
	}
	if ev.Observed.Has(synccmd.ObservedHTTP) {
		e.HTTP = ev.HTTPDuration
		e.HTTPMeasured = true
	}
	if ev.Observed.Has(synccmd.ObservedACK) {
		e.ACK = ev.ACKDuration
		e.ACKMeasured = true
	}
	if ev.Observed.Has(synccmd.ObservedInterAttempt) {
		e.InterAttempt = ev.InterAttemptDelay
		e.InterAttemptMeasured = true
	}
	if ev.Observed.Has(synccmd.ObservedPayloadBytes) {
		e.PayloadBytes = ev.PayloadBytes
		e.PayloadBytesKnown = true
	}
	return e
}

// deviceSentBatchOrigin derives the actually-sent batch's origin
// conservatively, from metadata the drain step already holds and with
// NO extra ledger read: a per-attempt full-table Load would be O(N²)
// disk traffic and parsing on large backlogs, against this project's
// performance goal. Only the provable label survives:
//
//   - a selected entry carrying OriginConsentRevision is
//     reorg/recovery-shaped, and so is every split child of it (the
//     oversize and consent-scope reorganization journals stamp their
//     children with the revision), so reorg_child holds whichever
//     batch was actually sent;
//   - a plain selected entry may have been replaced by a split child
//     before the POST — the consent-scope gate's decision depends on
//     the live server scope at send time and cannot be ruled out in
//     advance — so everything else is unknown rather than guessed.
//     (If finer-grained device origins are wanted, the producing side
//     would have to expose a sealed origin flag on its event; the
//     collector side must not re-read the ledger per event.)
func deviceSentBatchOrigin(parentReorgShaped bool) string {
	if parentReorgShaped {
		return OriginReorgChild
	}
	return OriginUnknown
}

// CursorProgressEvents adapts the account source's per-phase
// BatchProgress events into the unified stream and folds the drain
// counters. origin labels the round's locally-known provenance:
// OriginFreshExport for a normal pull round (unchanged events are
// skipped, so its batches carry new events), OriginCursorReemit for a
// forced full-range round, OriginPendingBacklog is NOT used here — a
// drain-only round cannot correlate events to entries positionally, so
// callers pass OriginUnknown for it. A nil emitter returns nil.
func CursorProgressEvents(emitter *ProgressEmitter, origin string) func(cursorsync.BatchProgress) {
	if emitter == nil {
		return nil
	}
	return func(ev cursorsync.BatchProgress) {
		emitter.Dispatch(cursorBatchEvent(ev, origin))
		if ev.Phase == cursorsync.BatchPhaseOutcome && ev.Result == cursorsync.BatchResultAcknowledged {
			// cursorsync marks a pending entry synced only on the
			// acknowledged terminal, so the local pending→synced
			// evidence holds — one first batch confirmation.
			emitter.AddBatchOutcome(ev.AcceptedRecords, 1)
		}
	}
}

// cursorBatchEvent maps one account BatchProgress. Duration is known
// only where the producer actually times a phase (http, preflight and
// the acknowledged terminal's durable write); a wait event carries the
// observed InterAttemptDelay instead — never folded into an http
// duration. PayloadBytes is carried only when the event has one in
// play (cursor batches always hold at least one record, so a zero size
// means the event does not carry one).
func cursorBatchEvent(ev cursorsync.BatchProgress, origin string) ProgressEvent {
	e := ProgressEvent{
		Kind:            ProgressBatch,
		Queue:           ProgressQueueCursor,
		Attempt:         ev.Attempt,
		Phase:           string(ev.Phase),
		Result:          string(ev.Result),
		AcceptedRecords: ev.AcceptedRecords,
		RejectedRecords: ev.RejectedRecords,
		ReceiptObserved: ev.ReceiptKnown,
		BatchReplay:     ev.Replay,
		Origin:          origin,
	}
	switch {
	case ev.Phase == cursorsync.BatchPhaseOutcome && ev.Result == cursorsync.BatchResultAcknowledged:
		// The acknowledged terminal marks a pending entry synced: this
		// local batch's first confirmation.
		e.FirstBatchConfirmation = FirstBatchConfirmationYes
		e.Duration = ev.Duration
		e.DurationKnown = true
	case ev.Phase == cursorsync.BatchPhaseHTTP, ev.Phase == cursorsync.BatchPhasePreflight:
		e.FirstBatchConfirmation = FirstBatchConfirmationNo
		e.Duration = ev.Duration
		e.DurationKnown = true
	default:
		// Wait events and non-acknowledged terminals time no phase of
		// their own.
		e.FirstBatchConfirmation = FirstBatchConfirmationNo
	}
	if ev.Phase == cursorsync.BatchPhaseWait {
		e.InterAttempt = ev.InterAttemptDelay
		e.InterAttemptMeasured = true
	}
	if ev.PayloadBytes > 0 {
		e.PayloadBytes = int64(ev.PayloadBytes)
		e.PayloadBytesKnown = true
	}
	return e
}

// cursorRoundOrigin labels the account round's batch-event provenance
// conservatively. A pull round is MIXED by construction — its internal
// drain first processes whatever backlog exists and only then pulls
// (and a forced round re-emits on top of that), so no round-level
// fresh/re-emit label is provable: unknown. The one provable case is a
// drain-only round whose every pending entry predates the run (nothing
// was created during it, so everything it can drain is backlog); any
// pending entry created during the run — or an unreadable ledger —
// keeps it unknown.
func cursorRoundOrigin(stateDir string, drainOnly bool, runStarted time.Time) string {
	if !drainOnly || runStarted.IsZero() {
		return OriginUnknown
	}
	entries, err := cursoroutbox.New(stateDir).Load()
	if err != nil {
		return OriginUnknown
	}
	for _, entry := range entries {
		if entry.Status != cursoroutbox.StatusPending {
			continue
		}
		if entry.CreatedAt.IsZero() || !entry.CreatedAt.Before(runStarted) {
			return OriginUnknown
		}
	}
	return OriginPendingBacklog
}

// Test hooks counting the progress layer's bounded IO. They are nil in
// production (zero cost beyond a nil check) and swapped only by
// in-package tests to pin the IO budget: bounded ledger reads per round
// and O(1) guarded stats per drained batch — never a full-queue rescan
// per batch.
var (
	progressQueueReadHook func(queue string)
	progressFileStatHook  func()
)

func notifyProgressQueueRead(queue string) {
	if progressQueueReadHook != nil {
		progressQueueReadHook(queue)
	}
}

func notifyProgressFileStat() {
	if progressFileStatHook != nil {
		progressFileStatHook()
	}
}

// pendingEntryView is the ledger-independent view of one pending entry
// the snapshot summarizer consumes.
type pendingEntryView struct {
	records   int
	createdAt time.Time
	file      string
}

// addCheckedInt adds two ints with overflow detection: an old or
// corrupt ledger can carry extreme RecordCount values, and a wrapped
// sum would fabricate a pending total.
func addCheckedInt(a, b int) (int, bool) {
	sum := a + b
	if (b > 0 && sum < a) || (b < 0 && sum > a) {
		return 0, false
	}
	return sum, true
}

// addCheckedInt64 is addCheckedInt's int64 twin (pending byte sums).
func addCheckedInt64(a, b int64) (int64, bool) {
	sum := a + b
	if (b > 0 && sum < a) || (b < 0 && sum > a) {
		return 0, false
	}
	return sum, true
}

// pendingSummaryResult carries a snapshot plus the persisted CreatedAt
// behind its OldestPendingAge, so incremental per-batch updates can
// decide whether the oldest survived a drain step.
type pendingSummaryResult struct {
	snapshot        QueueSnapshot
	oldestCreatedAt time.Time
}

// summarizePendingEntries folds pending entries into one honest
// snapshot: every field is gated (a failed or refused stat and a missing
// CreatedAt are unknown, never an observed zero), and ages use the
// persisted wall-clock CreatedAt with negative skew clamped to zero. An
// empty pending set is a real observation (zero batches, zero bytes, no
// oldest age). Every file stat is path-guarded: only regular files
// inside stateDir are ever touched — an entry pointing elsewhere (a
// corrupt ledger) counts as unknown bytes, never as an unauthorized
// filesystem probe.
func summarizePendingEntries(pending []pendingEntryView, stateDir string, now time.Time) pendingSummaryResult {
	s := QueueSnapshot{Counted: true, RecordsCounted: true, BytesCounted: true}
	statFailed := false
	missingCreatedAt := false
	missingRecords := false
	oldestSet := false
	var oldest time.Duration
	var oldestCreatedAt time.Time
	for _, p := range pending {
		s.PendingBatches++
		if sum, ok := addCheckedInt(s.PendingRecords, p.records); p.records > 0 && ok {
			s.PendingRecords = sum
		} else {
			// An omitempty int that an older ledger never wrote, a
			// non-positive count, or a sum that would overflow: the
			// record total is unknown — never presented as a zero or
			// wrapped total. The batch count stays known.
			missingRecords = true
		}
		if p.createdAt.IsZero() {
			// A pending entry without a usable timestamp: the true
			// oldest is unknowable — never claim the known-entry
			// maximum as the queue's oldest age.
			missingCreatedAt = true
		} else {
			age := now.Sub(p.createdAt)
			if age < 0 {
				age = 0
			}
			if !oldestSet || age > oldest {
				oldest = age
				oldestSet = true
				oldestCreatedAt = p.createdAt
			}
		}
		if size, ok := statPendingFile(stateDir, p.file); ok {
			if sum, ok2 := addCheckedInt64(s.PendingBytes, size); ok2 {
				s.PendingBytes = sum
			} else {
				statFailed = true
			}
		} else {
			statFailed = true
		}
	}
	if statFailed {
		s.PendingBytes = 0
		s.BytesCounted = false
	}
	if missingRecords {
		s.PendingRecords = 0
		s.RecordsCounted = false
	}
	if oldestSet && !missingCreatedAt {
		s.OldestPendingAge = oldest
		s.AgeCounted = true
	}
	return pendingSummaryResult{snapshot: s, oldestCreatedAt: oldestCreatedAt}
}

// statPendingFile stats one pending batch file through a Root confined
// to the state directory. The outbox is local state the collector
// itself wrote, yet a corrupt or hostile ledger must never turn
// telemetry into a probe of arbitrary external paths:
//
//   - os.OpenRoot(stateDir) confines the WHOLE path walk: an
//     intermediate-directory symlink that would escape the root, and
//     any .. traversal, are rejected by the Root itself — closing the
//     gap a leaf-only Lstat plus a lexical prefix check leaves open;
//   - the leaf must be a regular file: root.Lstat does not follow the
//     leaf, so a leaf symlink is refused outright;
//   - TOCTOU: containment is enforced during the path resolution
//     itself (the Root holds the directory fd; there is no separate
//     check-then-stat gap for containment), and the returned size is
//     only ever used as telemetry — nothing later acts on it, so a
//     post-stat mutation cannot turn into an unauthorized access.
//
// A path that cannot be proven safe counts as unknown bytes.
func statPendingFile(stateDir, file string) (int64, bool) {
	if stateDir == "" || file == "" {
		return 0, false
	}
	rootDir, err := filepath.Abs(stateDir)
	if err != nil {
		return 0, false
	}
	absFile, err := filepath.Abs(file)
	if err != nil {
		return 0, false
	}
	rel, err := filepath.Rel(rootDir, absFile)
	if err != nil || rel == "." || rel == ".." ||
		filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return 0, false
	}
	notifyProgressFileStat()
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return 0, false
	}
	defer root.Close()
	info, err := root.Lstat(rel)
	if err != nil || !info.Mode().IsRegular() {
		return 0, false
	}
	return info.Size(), true
}

// devicePendingSummary reads the device outbox once and summarizes its
// pending entries. A read failure returns a zero snapshot (Counted
// false) together with the error — the caller decides whether to
// propagate it; the event itself never fakes a queue.
func devicePendingSummary(stateDir string, now time.Time) (pendingSummaryResult, error) {
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		return pendingSummaryResult{}, err
	}
	pending := make([]pendingEntryView, 0, len(out.Batches))
	for _, b := range out.Batches {
		if b.Status != outbox.StatusPending {
			continue
		}
		pending = append(pending, pendingEntryView{records: b.RecordCount, createdAt: b.CreatedAt, file: b.File})
	}
	return summarizePendingEntries(pending, stateDir, now), nil
}

// cursorPendingSummary is devicePendingSummary's account-queue twin.
func cursorPendingSummary(stateDir string, now time.Time) (pendingSummaryResult, error) {
	entries, err := cursoroutbox.New(stateDir).Load()
	if err != nil {
		return pendingSummaryResult{}, err
	}
	pending := make([]pendingEntryView, 0, len(entries))
	for _, entry := range entries {
		if entry.Status != cursoroutbox.StatusPending {
			continue
		}
		pending = append(pending, pendingEntryView{records: entry.RecordCount, createdAt: entry.CreatedAt, file: entry.File})
	}
	return summarizePendingEntries(pending, stateDir, now), nil
}

// emitQueueSnapshot dispatches one queue event. A nil emitter no-ops;
// an unread queue arrives as Counted=false, never as zeros.
func emitQueueSnapshot(emitter *ProgressEmitter, stage, queue string, snap QueueSnapshot) {
	if emitter == nil {
		return
	}
	emitter.Dispatch(ProgressEvent{
		Kind:             ProgressQueue,
		Stage:            stage,
		Queue:            queue,
		PendingBatches:   snap.PendingBatches,
		PendingRecords:   snap.PendingRecords,
		Counted:          snap.Counted,
		RecordsCounted:   snap.RecordsCounted,
		PendingBytes:     snap.PendingBytes,
		BytesCounted:     snap.BytesCounted,
		OldestPendingAge: snap.OldestPendingAge,
		AgeCounted:       snap.AgeCounted,
	})
}

// publishDeviceQueue reads, publishes and emits one bounded device
// queue snapshot (the drain's start/end points). A nil emitter returns
// before ANY read: with progress disabled the run performs zero extra
// file or ledger IO. The snapshot's clock is the emitter's observation
// clock, never the business Options.Now. A read failure publishes an
// honest unknown snapshot; the drain's own fail-closed counts stay with
// countPending.
func publishDeviceQueue(emitter *ProgressEmitter, stateDir, stage string) {
	if emitter == nil {
		return
	}
	notifyProgressQueueRead(ProgressQueueDevice)
	res, err := devicePendingSummary(stateDir, emitter.obsNow())
	snap := res.snapshot
	if err != nil {
		snap = QueueSnapshot{}
	}
	emitter.SetDeviceQueue(snap)
	emitter.setDeviceOldestCreatedAt(res.oldestCreatedAt)
	emitQueueSnapshot(emitter, stage, ProgressQueueDevice, snap)
}

// publishCursorQueue is publishDeviceQueue's account-queue twin.
func publishCursorQueue(emitter *ProgressEmitter, stateDir, stage string) {
	if emitter == nil {
		return
	}
	notifyProgressQueueRead(ProgressQueueCursor)
	res, err := cursorPendingSummary(stateDir, emitter.obsNow())
	snap := res.snapshot
	if err != nil {
		snap = QueueSnapshot{}
	}
	emitter.SetCursorQueue(snap)
	emitter.setCursorOldestCreatedAt(res.oldestCreatedAt)
	emitQueueSnapshot(emitter, stage, ProgressQueueCursor, snap)
}

// ApplyDeviceDrain folds one completed device drain step into the held
// device-queue snapshot INCREMENTALLY — no ledger re-read and no
// whole-queue stat (a per-batch full re-sample would be O(N²) IO on
// large backlogs). The decrement is provable only when the selected
// entry itself was acked (receiptBatchID matches) and nothing was
// re-pended (recovered == 0); a split child, a quarantine recovery or
// any inconsistency marks the snapshot unknown until the next bounded
// re-sample (the drain's end snapshot) — never a silent guess. The one
// bounded stat is the drained entry's own file, path-guarded like every
// other pending-file stat.
func (e *ProgressEmitter) ApplyDeviceDrain(stateDir string, entry outbox.BatchEntry, receiptBatchID string, recovered int) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return
	}
	defer func() {
		// The per-batch queue update rides the folded state — no read,
		// no stat, just the increment (or the honest unknown).
		e.fn(ProgressEvent{
			Kind:             ProgressQueue,
			Stage:            "drain",
			Queue:            ProgressQueueDevice,
			PendingBatches:   e.state.DeviceQueue.PendingBatches,
			PendingRecords:   e.state.DeviceQueue.PendingRecords,
			Counted:          e.state.DeviceQueue.Counted,
			RecordsCounted:   e.state.DeviceQueue.RecordsCounted,
			PendingBytes:     e.state.DeviceQueue.PendingBytes,
			BytesCounted:     e.state.DeviceQueue.BytesCounted,
			OldestPendingAge: e.state.DeviceQueue.OldestPendingAge,
			AgeCounted:       e.state.DeviceQueue.AgeCounted,
		})
	}()
	q := e.state.DeviceQueue
	if receiptBatchID != entry.BatchID || recovered > 0 || !q.Counted {
		e.state.DeviceQueue = QueueSnapshot{}
		return
	}
	q.PendingBatches--
	if q.RecordsCounted && entry.RecordCount > 0 {
		q.PendingRecords -= entry.RecordCount
	} else {
		// The drained entry's record count is not provable (an older
		// ledger shape): the remaining total is unknown, never guessed.
		q.RecordsCounted = false
		q.PendingRecords = 0
	}
	if q.BytesCounted {
		if size, ok := statPendingFile(stateDir, entry.File); ok {
			q.PendingBytes -= size
		} else {
			q.BytesCounted = false
			q.PendingBytes = 0
		}
	}
	if q.AgeCounted {
		if entry.CreatedAt.IsZero() || e.state.DeviceOldestCreatedAt.IsZero() ||
			!entry.CreatedAt.After(e.state.DeviceOldestCreatedAt) {
			// The drained entry was at least as old as the recorded
			// oldest (or the ages cannot be compared): the new oldest
			// is unknown until the next bounded re-sample.
			q.AgeCounted = false
			q.OldestPendingAge = 0
			e.state.DeviceOldestCreatedAt = time.Time{}
		}
	}
	if q.PendingBatches < 0 || q.PendingRecords < 0 || q.PendingBytes < 0 {
		e.state.DeviceQueue = QueueSnapshot{}
		return
	}
	e.state.DeviceQueue = q
}

// ApplyCursorDrain folds one completed account drain step into the held
// cursor-queue snapshot incrementally. Which files drained is not held
// per step, so bytes and the oldest age become unknown until the next
// bounded re-sample; the counts decrement provably (every synced batch
// was a pending entry).
func (e *ProgressEmitter) ApplyCursorDrain(syncedBatches, syncedRecords int) {
	if e == nil || syncedBatches <= 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return
	}
	defer func() {
		e.fn(ProgressEvent{
			Kind:             ProgressQueue,
			Stage:            "drain",
			Queue:            ProgressQueueCursor,
			PendingBatches:   e.state.CursorQueue.PendingBatches,
			PendingRecords:   e.state.CursorQueue.PendingRecords,
			Counted:          e.state.CursorQueue.Counted,
			RecordsCounted:   e.state.CursorQueue.RecordsCounted,
			PendingBytes:     e.state.CursorQueue.PendingBytes,
			BytesCounted:     e.state.CursorQueue.BytesCounted,
			OldestPendingAge: e.state.CursorQueue.OldestPendingAge,
			AgeCounted:       e.state.CursorQueue.AgeCounted,
		})
	}()
	q := e.state.CursorQueue
	if !q.Counted {
		return
	}
	q.PendingBatches -= syncedBatches
	if q.RecordsCounted && syncedRecords > 0 {
		// An acknowledged cursor batch is fully accepted, so its receipt
		// count IS its full record total; anything less provable keeps
		// the records unknown.
		q.PendingRecords -= syncedRecords
	} else {
		q.RecordsCounted = false
		q.PendingRecords = 0
	}
	q.BytesCounted = false
	q.PendingBytes = 0
	q.AgeCounted = false
	q.OldestPendingAge = 0
	e.state.CursorOldestCreatedAt = time.Time{}
	if q.PendingBatches < 0 || q.PendingRecords < 0 {
		e.state.CursorQueue = QueueSnapshot{}
		return
	}
	e.state.CursorQueue = q
}

// InvalidateDeviceQueue marks the held device-queue snapshot unknown
// after a step whose effect on the pending queue the drain cannot prove
// (a quarantine recovery re-pended records, or a scope reorganization
// settled a batch without a receipt); the next bounded re-sample
// restores it.
func (e *ProgressEmitter) InvalidateDeviceQueue() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return
	}
	e.state.DeviceQueue = QueueSnapshot{}
	e.state.DeviceOldestCreatedAt = time.Time{}
}

func (e *ProgressEmitter) setDeviceOldestCreatedAt(t time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.state.DeviceOldestCreatedAt = t
}

func (e *ProgressEmitter) setCursorOldestCreatedAt(t time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.state.CursorOldestCreatedAt = t
}
