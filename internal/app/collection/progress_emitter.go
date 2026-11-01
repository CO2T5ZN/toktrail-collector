package collection

import (
	"context"
	"math"
	"sync"
	"time"
)

// DefaultProgressHeartbeat is the nominal interval between heartbeat
// events during long steps (plan §10: roughly every five seconds).
const DefaultProgressHeartbeat = 5 * time.Second

// QueueSnapshot is one honest reading of a pending queue. Every field
// is valid only when its gate is set: an unread ledger (Counted false),
// a failed file stat (BytesCounted false) or a missing CreatedAt
// (AgeCounted false) must never be reported as an observed zero.
type QueueSnapshot struct {
	PendingBatches int
	PendingRecords int
	// Counted reports whether the ledger read succeeded and the BATCH
	// count is known.
	Counted bool
	// RecordsCounted reports whether every pending entry carried a
	// provable record count. The outbox's RecordCount is an omitempty
	// int: an older ledger missing the field decodes as zero, so a
	// successful Load never implies the record total is known. Any
	// pending entry with a non-positive count leaves the records
	// unknown — the batch count stays known.
	RecordsCounted bool
	PendingBytes   int64
	BytesCounted   bool
	// OldestPendingAge uses the entries' persisted wall-clock CreatedAt;
	// negative clock skew clamps to zero.
	OldestPendingAge time.Duration
	AgeCounted       bool
}

// HeartbeatState is the in-memory snapshot the run goroutine publishes
// for the heartbeat. The ticker goroutine only ever reads a copy of it
// under the emitter's mutex — it never touches the state directory, the
// WAL, the runlock or the network (the flock does not serialize
// goroutines of one process, so every ledger read stays on the run
// goroutine).
type HeartbeatState struct {
	Stage          string
	StageStarted   time.Time
	Queue          string
	AttemptStarted time.Time
	DrainStarted   time.Time
	// AcceptedRecords accumulates the drain's accepted records — the
	// processing volume, re-deliveries included; never a "new data"
	// count.
	AcceptedRecords int
	// FirstBatchConfirmedBatches counts "yes" first batch confirmations
	// (batch granularity only).
	FirstBatchConfirmedBatches int
	// Samples counts completed batch outcomes observed during the drain.
	Samples int
	// CursorInScope reports whether the run also drains the account
	// queue; the heartbeat's aggregate pending count is only Counted
	// when every queue in scope was.
	// AttemptTracked reports whether this emitter's flow carries
	// accurate Begin/End attempt hooks: only then may a heartbeat state
	// an in-flight attempt at all (true or false); otherwise the status
	// is unknown and must be omitted, never defaulted to false.
	AttemptTracked bool
	CursorInScope  bool
	DeviceQueue    QueueSnapshot
	CursorQueue    QueueSnapshot
	// DeviceOldestCreatedAt / CursorOldestCreatedAt back the snapshots'
	// OldestPendingAge gates: a per-batch incremental update can keep
	// the age only while the drained entry was provably newer than the
	// recorded oldest.
	DeviceOldestCreatedAt time.Time
	CursorOldestCreatedAt time.Time
}

// ProgressEmitter serializes every progress callback invocation of one
// run and owns its heartbeat ticker goroutine.
//
// Contract: the callback is never invoked concurrently with itself, but
// MAY be invoked from the heartbeat goroutine. Callers that dispatch
// events from several places into one output share one serialization
// point either through an emitter or through SerialProgress.
//
// Lifecycle: construct with NewProgressEmitter (nil fn returns a nil
// emitter — a nil *ProgressEmitter is a valid no-op receiver for every
// method, with zero goroutines and zero output) and stop it exactly
// once per construction site with defer Stop(). Stop is idempotent and
// joins the goroutine; after Stop returns no further event is
// dispatched. The goroutine also exits on ctx cancellation, so a
// cancelled run unwinds through its existing context checks and the
// deferred Stop joins promptly.
//
// The heartbeat goroutine performs no I/O of any kind: it copies the
// mutex-guarded HeartbeatState, builds one event and dispatches it
// under the same mutex.
type ProgressEmitter struct {
	fn func(ProgressEvent)
	// now is the OBSERVATION clock — deliberately separate from the
	// business Options.Now (which drives authorization and deadline
	// behavior and must never gain or lose calls when progress is
	// enabled). Production uses time.Now; tests inject.
	now        func() time.Time
	mu         sync.Mutex
	state      HeartbeatState
	stopped    bool
	ticks      <-chan time.Time
	stopTicker func()
	stopCh     chan struct{}
	doneCh     chan struct{}
}

// NewProgressEmitter returns an emitter that dispatches every event
// through fn — serialized — and emits one heartbeat roughly every
// interval. fn == nil returns nil; every <= 0 falls back to
// DefaultProgressHeartbeat.
func NewProgressEmitter(ctx context.Context, fn func(ProgressEvent), every time.Duration) *ProgressEmitter {
	if fn == nil {
		return nil
	}
	if every <= 0 {
		every = DefaultProgressHeartbeat
	}
	ticker := time.NewTicker(every)
	e := newProgressEmitter(ctx, fn, ticker.C, time.Now)
	e.stopTicker = ticker.Stop
	return e
}

// newProgressEmitterWithTicks is the test constructor: the tick source
// and the observation clock are injected, so tests drive heartbeats and
// ages deterministically without sleeping. A closed tick channel ends
// the goroutine.
func newProgressEmitterWithTicks(ctx context.Context, fn func(ProgressEvent), ticks <-chan time.Time, now func() time.Time) *ProgressEmitter {
	return newProgressEmitter(ctx, fn, ticks, now)
}

func newProgressEmitter(ctx context.Context, fn func(ProgressEvent), ticks <-chan time.Time, now func() time.Time) *ProgressEmitter {
	if now == nil {
		now = time.Now
	}
	e := &ProgressEmitter{
		fn:     fn,
		now:    now,
		ticks:  ticks,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	go e.run(ctx)
	return e
}

// obsNow reads the observation clock (never the business Options.Now).
func (e *ProgressEmitter) obsNow() time.Time {
	if e == nil || e.now == nil {
		return time.Now()
	}
	return e.now()
}

func (e *ProgressEmitter) run(ctx context.Context) {
	defer close(e.doneCh)
	defer func() {
		if e.stopTicker != nil {
			e.stopTicker()
		}
	}()
	for {
		select {
		case <-e.stopCh:
			return
		case <-ctx.Done():
			return
		case _, ok := <-e.ticks:
			if !ok {
				return
			}
			e.emitHeartbeat()
		}
	}
}

// Dispatch serializes one event through the callback. Events dispatched
// after Stop (or on a nil emitter) are dropped.
func (e *ProgressEmitter) Dispatch(ev ProgressEvent) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return
	}
	e.fn(ev)
}

// Stop idempotently stops the heartbeat goroutine and joins it. Safe on
// a nil emitter and safe to call more than once; every caller returns
// only after the goroutine has exited.
func (e *ProgressEmitter) Stop() {
	if e == nil {
		return
	}
	e.mu.Lock()
	already := e.stopped
	e.stopped = true
	e.mu.Unlock()
	if !already {
		close(e.stopCh)
	}
	<-e.doneCh
}

// PublishState replaces the heartbeat snapshot wholesale.
func (e *ProgressEmitter) PublishState(s HeartbeatState) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return
	}
	e.state = s
}

// EnterStage records a stage transition for the heartbeat.
func (e *ProgressEmitter) EnterStage(stage string) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return
	}
	e.state.Stage = stage
	e.state.StageStarted = e.now()
}

// BeginAttempt records that a send attempt of queue started; the
// heartbeat reports it as in flight.
func (e *ProgressEmitter) BeginAttempt(queue string) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return
	}
	e.state.Queue = queue
	e.state.AttemptStarted = e.now()
	e.state.AttemptTracked = true
}

// EndAttempt clears the in-flight attempt marker.
func (e *ProgressEmitter) EndAttempt() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return
	}
	e.state.AttemptStarted = time.Time{}
	e.state.Queue = ""
}

// BeginDrain records the drain's start (the rate denominator); it only
// takes effect once per emitter.
func (e *ProgressEmitter) BeginDrain() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped || !e.state.DrainStarted.IsZero() {
		return
	}
	e.state.DrainStarted = e.now()
}

// AddBatchOutcome folds one completed batch outcome into the drain
// counters. acceptedRecords is the receipt's accepted count (the
// processing volume); firstBatchConfirmations counts "yes" first batch
// confirmations observed in it (batch granularity).
func (e *ProgressEmitter) AddBatchOutcome(acceptedRecords, firstBatchConfirmations int) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return
	}
	e.state.AcceptedRecords += acceptedRecords
	e.state.Samples++
	e.state.FirstBatchConfirmedBatches += firstBatchConfirmations
}

// SetDeviceQueue publishes the device queue snapshot.
func (e *ProgressEmitter) SetDeviceQueue(s QueueSnapshot) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return
	}
	e.state.DeviceQueue = s
}

// SetCursorQueue publishes the account queue snapshot.
func (e *ProgressEmitter) SetCursorQueue(s QueueSnapshot) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return
	}
	e.state.CursorQueue = s
}

// SetCursorInScope marks whether the run also drains the account queue.
func (e *ProgressEmitter) SetCursorInScope(v bool) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return
	}
	e.state.CursorInScope = v
}

// EmitHeartbeatNow dispatches one heartbeat built from the current
// snapshot — used for the run's final status line. Dropped after Stop.
func (e *ProgressEmitter) EmitHeartbeatNow() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return
	}
	e.fn(heartbeatEvent(e.state, e.now()))
}

func (e *ProgressEmitter) emitHeartbeat() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return
	}
	e.fn(heartbeatEvent(e.state, e.now()))
}

// heartbeatEvent builds one heartbeat from the published state. The
// aggregate pending count is only Counted when every queue in scope
// was; the rate and ETA appear only once a completed-batch sample
// exists, and the ETA only when the aggregate pending is both observed
// and non-zero.
func heartbeatEvent(state HeartbeatState, now time.Time) ProgressEvent {
	ev := ProgressEvent{
		Kind:                       ProgressHeartbeat,
		Stage:                      state.Stage,
		Queue:                      state.Queue,
		FirstBatchConfirmedBatches: state.FirstBatchConfirmedBatches,
		Samples:                    state.Samples,
	}
	if !state.StageStarted.IsZero() {
		ev.Duration = now.Sub(state.StageStarted)
	}
	if state.AttemptTracked {
		// The flow's Begin/End hooks are accurate: state the in-flight
		// status (true mid-attempt, false between them).
		ev.AttemptInFlightKnown = true
		if !state.AttemptStarted.IsZero() {
			ev.AttemptInFlight = true
			ev.AttemptElapsed = now.Sub(state.AttemptStarted)
		}
	}
	dev, cur := state.DeviceQueue, state.CursorQueue
	agg := dev
	if state.CursorInScope {
		agg = QueueSnapshot{Counted: dev.Counted && cur.Counted}
		if agg.Counted {
			// Checked adds throughout: an old or corrupt ledger can
			// carry extreme counts, and a wrapped sum would fabricate a
			// pending total. An overflow degrades exactly its own gate
			// to unknown.
			if sum, ok := addCheckedInt(dev.PendingBatches, cur.PendingBatches); ok {
				agg.PendingBatches = sum
			} else {
				agg.Counted = false
			}
			agg.RecordsCounted = dev.RecordsCounted && cur.RecordsCounted
			if agg.RecordsCounted {
				if sum, ok := addCheckedInt(dev.PendingRecords, cur.PendingRecords); ok {
					agg.PendingRecords = sum
				} else {
					agg.RecordsCounted = false
				}
			}
			agg.BytesCounted = dev.BytesCounted && cur.BytesCounted
			if agg.BytesCounted {
				if sum, ok := addCheckedInt64(dev.PendingBytes, cur.PendingBytes); ok {
					agg.PendingBytes = sum
				} else {
					agg.BytesCounted = false
				}
			}
			// The oldest age is aggregable only when every NON-EMPTY
			// queue in scope knows its own oldest: an empty queue has
			// no age to contribute and must not block, but a non-empty
			// queue with an unknown age would let the other queue's
			// age masquerade as the aggregate oldest.
			if (dev.PendingBatches > 0 && !dev.AgeCounted) || (cur.PendingBatches > 0 && !cur.AgeCounted) {
				agg.AgeCounted = false
			} else {
				agg.AgeCounted = dev.AgeCounted || cur.AgeCounted
				if agg.AgeCounted {
					agg.OldestPendingAge = dev.OldestPendingAge
					if !dev.AgeCounted || (cur.AgeCounted && cur.OldestPendingAge > agg.OldestPendingAge) {
						agg.OldestPendingAge = cur.OldestPendingAge
					}
				}
			}
		}
	}
	ev.PendingBatches = agg.PendingBatches
	ev.PendingRecords = agg.PendingRecords
	ev.Counted = agg.Counted
	ev.RecordsCounted = agg.RecordsCounted
	ev.PendingBytes = agg.PendingBytes
	ev.BytesCounted = agg.BytesCounted
	ev.OldestPendingAge = agg.OldestPendingAge
	ev.AgeCounted = agg.AgeCounted
	if !state.DrainStarted.IsZero() && state.Samples > 0 {
		if elapsed := now.Sub(state.DrainStarted); elapsed > 0 {
			ev.ProcessingRateRecPerSec = float64(state.AcceptedRecords) / elapsed.Seconds()
			ev.RateKnown = true
			if agg.Counted && agg.RecordsCounted && agg.PendingRecords > 0 && ev.ProcessingRateRecPerSec > 0 {
				if nanos, ok := etaNanos(agg.PendingRecords, ev.ProcessingRateRecPerSec); ok {
					ev.Eta = time.Duration(nanos)
					ev.EtaKnown = true
				}
			}
		}
	}
	return ev
}

// etaNanos computes the drain ETA in nanoseconds with explicit
// finiteness and range checks: a huge pending total over a tiny rate
// must degrade to unknown, never wrap into a negative duration.
//
// The upper bound is deliberately `>= float64(math.MaxInt64)`: the
// constant rounds UP to exactly 2^63 in float64, so a `>` comparison
// would let a nanos value of exactly 2^63 through — and converting
// 2^63 to int64 overflows (implementation-defined, typically a
// negative duration). Rejecting the rounded boundary keeps every
// accepted value strictly convertible; the largest float64 below 2^63
// still converts to a valid, positive duration.
func etaNanos(pendingRecords int, rateRecPerSec float64) (int64, bool) {
	nanos := (float64(pendingRecords) / rateRecPerSec) * float64(time.Second)
	if math.IsNaN(nanos) || math.IsInf(nanos, 0) || nanos < 0 || nanos >= float64(math.MaxInt64) {
		return 0, false
	}
	return int64(nanos), true
}

// WithProgressEmitter returns opt with e attached as the run's emitter.
// A caller that owns a longer orchestration (connect's backlog passes)
// constructs one emitter, attaches it to every collection round of the
// pass, and keeps the single deferred Stop itself: the rounds then
// reuse it instead of constructing their own, so no two tickers ever
// overlap. A nil emitter detaches (the rounds construct their own from
// Options.Progress again).
func (o Options) WithProgressEmitter(e *ProgressEmitter) Options {
	o.emitter = e
	return o
}

// SerialProgress wraps fn so invocations never run concurrently. It is
// the shared serialization point for callers that dispatch progress
// events from several places (phase adapters, collection rounds) into
// one output; unlike an emitter it starts no goroutine and emits no
// heartbeat of its own. nil returns nil.
func SerialProgress(fn func(ProgressEvent)) func(ProgressEvent) {
	if fn == nil {
		return nil
	}
	var mu sync.Mutex
	return func(ev ProgressEvent) {
		mu.Lock()
		defer mu.Unlock()
		fn(ev)
	}
}
