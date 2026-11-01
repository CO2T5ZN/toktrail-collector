package collection

// Unit tests for the progress emitter: serialization, heartbeat gating,
// stop/join semantics and the incremental queue folds. Everything is
// synthetic — injected tick channels and observation clocks, no real
// sleeping, no state directories (except where a fold stat is exercised
// with a tempdir), no network.

import (
	"context"
	"math"
	"runtime"
	"sync"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
)

func goroutineCount(t *testing.T) int {
	t.Helper()
	runtime.GC()
	deadline := time.Now().Add(2 * time.Second)
	for {
		n := runtime.NumGoroutine()
		if time.Now().After(deadline) {
			return n
		}
		_ = n
		return n
	}
}

// A nil callback must construct nothing at all: no goroutine, and every
// method is a no-op on the nil receiver.
func TestProgressEmitterNilFnStartsNoGoroutine(t *testing.T) {
	before := goroutineCount(t)
	if e := NewProgressEmitter(context.Background(), nil, DefaultProgressHeartbeat); e != nil {
		t.Fatalf("nil fn must return a nil emitter, got %v", e)
	}
	var nilEmitter *ProgressEmitter
	nilEmitter.Dispatch(ProgressEvent{Kind: ProgressHeartbeat})
	nilEmitter.PublishState(HeartbeatState{})
	nilEmitter.EnterStage("drain")
	nilEmitter.BeginAttempt(ProgressQueueDevice)
	nilEmitter.EndAttempt()
	nilEmitter.BeginDrain()
	nilEmitter.AddBatchOutcome(1, 1)
	nilEmitter.SetDeviceQueue(QueueSnapshot{})
	nilEmitter.SetCursorQueue(QueueSnapshot{})
	nilEmitter.SetCursorInScope(true)
	nilEmitter.EmitHeartbeatNow()
	nilEmitter.ApplyDeviceDrain(t.TempDir(), outbox.BatchEntry{}, "", 0)
	nilEmitter.ApplyCursorDrain(1, 1)
	nilEmitter.InvalidateDeviceQueue()
	nilEmitter.Stop()
	if after := goroutineCount(t); after > before {
		t.Fatalf("nil emitter must not start goroutines: before=%d after=%d", before, after)
	}
}

// Heartbeats fire only on injected ticks, carry the published state, and
// compute the processing rate / ETA only once a sample exists.
func TestProgressEmitterHeartbeatOnInjectedTick(t *testing.T) {
	events := make(chan ProgressEvent, 8)
	ticks := make(chan time.Time)
	obsNow := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	e := newProgressEmitterWithTicks(context.Background(), func(ev ProgressEvent) {
		events <- ev
	}, ticks, func() time.Time { return obsNow })
	defer e.Stop()

	e.EnterStage("drain")
	e.BeginDrain()
	e.SetDeviceQueue(QueueSnapshot{PendingBatches: 10, PendingRecords: 500, Counted: true, RecordsCounted: true})
	e.AddBatchOutcome(100, 1)

	// No heartbeat before a tick.
	select {
	case ev := <-events:
		t.Fatalf("no event may fire before a tick, got %+v", ev)
	default:
	}
	// Move the observation clock forward 10s and tick: the rate is
	// 100 records / 10s and the ETA covers the 400 remaining.
	obsNow = obsNow.Add(10 * time.Second)
	ticks <- obsNow
	ev := <-events
	if ev.Kind != ProgressHeartbeat || ev.Stage != "drain" {
		t.Fatalf("expected a drain heartbeat, got %+v", ev)
	}
	if ev.Samples != 1 || ev.FirstBatchConfirmedBatches != 1 {
		t.Fatalf("heartbeat counters must carry the folded outcome: %+v", ev)
	}
	if ev.PendingBatches != 10 || ev.PendingRecords != 500 || !ev.Counted {
		t.Fatalf("heartbeat must aggregate the device queue: %+v", ev)
	}
	if ev.ProcessingRateRecPerSec <= 0 {
		t.Fatalf("a sampled drain must carry a processing rate: %+v", ev)
	}
	if !ev.EtaKnown || ev.Eta <= 0 {
		t.Fatalf("a counted, non-empty pending queue must carry an ETA: %+v", ev)
	}
	if ev.AttemptInFlight {
		t.Fatalf("no attempt is in flight: %+v", ev)
	}
}

// Without a completed-batch sample there is no rate and no ETA — never a
// fabricated zero-derived estimate.
func TestProgressEmitterHeartbeatRequiresSamples(t *testing.T) {
	events := make(chan ProgressEvent, 8)
	ticks := make(chan time.Time)
	e := newProgressEmitterWithTicks(context.Background(), func(ev ProgressEvent) {
		events <- ev
	}, ticks, time.Now)
	defer e.Stop()

	e.EnterStage("drain")
	e.BeginDrain()
	e.SetDeviceQueue(QueueSnapshot{PendingBatches: 5, PendingRecords: 50, Counted: true, RecordsCounted: true})
	ticks <- time.Now()
	ev := <-events
	if ev.Samples != 0 {
		t.Fatalf("no outcome was folded: %+v", ev)
	}
	if ev.ProcessingRateRecPerSec != 0 || ev.EtaKnown {
		t.Fatalf("without samples there must be no rate and no ETA: %+v", ev)
	}
}

// The aggregate pending count is only Counted when every queue in scope
// was counted; a cursor queue in scope that was never sampled keeps the
// aggregate unknown — never a partial sum presented as the whole.
func TestProgressEmitterAggregateRequiresAllInScopeQueues(t *testing.T) {
	events := make(chan ProgressEvent, 8)
	ticks := make(chan time.Time)
	e := newProgressEmitterWithTicks(context.Background(), func(ev ProgressEvent) {
		events <- ev
	}, ticks, time.Now)
	defer e.Stop()

	e.SetDeviceQueue(QueueSnapshot{PendingBatches: 2, PendingRecords: 20, Counted: true, RecordsCounted: true})
	e.SetCursorInScope(true)
	// The cursor queue was never sampled.
	e.AddBatchOutcome(10, 1)
	ticks <- time.Now()
	ev := <-events
	if ev.Counted {
		t.Fatalf("an unsampled in-scope cursor queue must keep the aggregate unknown: %+v", ev)
	}
	if ev.EtaKnown {
		t.Fatalf("an unknown aggregate must not carry an ETA: %+v", ev)
	}
}

// Stop is idempotent, joins the goroutine, and no event fires after it.
func TestProgressEmitterStopIdempotentAndDropsLateEvents(t *testing.T) {
	var mu sync.Mutex
	var count int
	ticks := make(chan time.Time)
	e := newProgressEmitterWithTicks(context.Background(), func(ev ProgressEvent) {
		mu.Lock()
		count++
		mu.Unlock()
	}, ticks, time.Now)

	e.Stop()
	e.Stop()
	// A late tick after Stop must not dispatch (non-blocking: the
	// goroutine no longer drains the channel, by design).
	select {
	case ticks <- time.Now():
	default:
	}
	e.Dispatch(ProgressEvent{Kind: ProgressHeartbeat})
	e.EmitHeartbeatNow()
	mu.Lock()
	defer mu.Unlock()
	if count != 0 {
		t.Fatalf("no event may be dispatched after Stop, got %d", count)
	}
}

// A cancelled context ends the ticker goroutine; Stop still joins.
func TestProgressEmitterStopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time)
	e := newProgressEmitterWithTicks(ctx, func(ProgressEvent) {}, ticks, time.Now)
	cancel()
	// Stop joins regardless of how the goroutine exited.
	e.Stop()
	select {
	case <-ticks:
		t.Fatalf("the tick source must be abandoned")
	default:
	}
}

// Dispatch and the heartbeat never run the callback concurrently. Run
// under -race: any unsynchronized callback use races here.
func TestProgressEmitterConcurrentDispatchIsSerialized(t *testing.T) {
	var mu sync.Mutex
	seen := 0
	ticks := make(chan time.Time)
	e := newProgressEmitterWithTicks(context.Background(), func(ev ProgressEvent) {
		mu.Lock()
		seen++
		mu.Unlock()
	}, ticks, time.Now)
	defer e.Stop()

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				e.Dispatch(ProgressEvent{Kind: ProgressBatch, Queue: ProgressQueueDevice})
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 20; j++ {
			ticks <- time.Now()
		}
	}()
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if seen == 0 {
		t.Fatalf("the dispatches must have reached the callback")
	}
}

// SerialProgress never runs fn concurrently and nil returns nil.
func TestSerialProgress(t *testing.T) {
	if SerialProgress(nil) != nil {
		t.Fatalf("nil must pass through")
	}
	var mu sync.Mutex
	count := 0
	fn := SerialProgress(func(ProgressEvent) {
		mu.Lock()
		count++
		mu.Unlock()
	})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				fn(ProgressEvent{Kind: ProgressCount})
			}
		}()
	}
	wg.Wait()
	if count != 200 {
		t.Fatalf("every invocation must run exactly once, got %d", count)
	}
}

// The aggregate oldest age requires every NON-EMPTY queue in scope to
// know its own oldest: an empty queue never blocks (it has no age to
// contribute), but a non-empty queue with an unknown age must not let
// the other queue's age masquerade as the aggregate.
func TestProgressEmitterAggregateOldestAgeRequiresAllNonEmptyKnown(t *testing.T) {
	events := make(chan ProgressEvent, 8)
	ticks := make(chan time.Time)
	e := newProgressEmitterWithTicks(context.Background(), func(ev ProgressEvent) { events <- ev }, ticks, time.Now)
	defer e.Stop()

	// Device non-empty with an unknown age; cursor known: the aggregate
	// age stays unknown.
	e.SetDeviceQueue(QueueSnapshot{PendingBatches: 2, PendingRecords: 20, Counted: true, RecordsCounted: true})
	e.SetCursorQueue(QueueSnapshot{PendingBatches: 1, PendingRecords: 5, Counted: true, RecordsCounted: true, OldestPendingAge: time.Hour, AgeCounted: true})
	e.SetCursorInScope(true)
	e.AddBatchOutcome(1, 0)
	ticks <- time.Now()
	ev := <-events
	if ev.AgeCounted || ev.OldestPendingAge != 0 {
		t.Fatalf("a non-empty queue with an unknown age must block the aggregate: %+v", ev)
	}

	// The device queue empty (its unknown age is vacuous): the cursor's
	// known age becomes the aggregate.
	e.SetDeviceQueue(QueueSnapshot{PendingBatches: 0, PendingRecords: 0, Counted: true, RecordsCounted: true})
	ticks <- time.Now()
	ev = <-events
	if !ev.AgeCounted || ev.OldestPendingAge != time.Hour {
		t.Fatalf("an empty queue must not block the aggregate age: %+v", ev)
	}

	// Both non-empty and known: the maximum wins.
	e.SetDeviceQueue(QueueSnapshot{PendingBatches: 3, PendingRecords: 30, Counted: true, RecordsCounted: true, OldestPendingAge: 2 * time.Hour, AgeCounted: true})
	ticks <- time.Now()
	ev = <-events
	if !ev.AgeCounted || ev.OldestPendingAge != 2*time.Hour {
		t.Fatalf("both known ages aggregate to the maximum: %+v", ev)
	}
}

// The incremental device fold: a provable step decrements the held
// snapshot; a split child or a recovery marks it unknown — never a
// guessed number.
func TestProgressEmitterApplyDeviceDrain(t *testing.T) {
	stateDir := t.TempDir()
	events := make(chan ProgressEvent, 8)
	ticks := make(chan time.Time)
	e := newProgressEmitterWithTicks(context.Background(), func(ev ProgressEvent) { events <- ev }, ticks, time.Now)
	defer e.Stop()

	entry := outbox.BatchEntry{BatchID: "b1", RecordCount: 10, File: stateDir + "/batches/b1.json"}
	e.SetDeviceQueue(QueueSnapshot{PendingBatches: 2, PendingRecords: 20, Counted: true, RecordsCounted: true})

	// A split child was sent: the receipt names a different batch.
	e.ApplyDeviceDrain(stateDir, entry, "child-of-b1", 0)
	ev := <-events
	if ev.Counted {
		t.Fatalf("a split child must mark the queue unknown: %+v", ev)
	}

	// Re-sample and drain the entry itself: a provable decrement.
	e.SetDeviceQueue(QueueSnapshot{PendingBatches: 2, PendingRecords: 20, Counted: true, RecordsCounted: true})
	e.ApplyDeviceDrain(stateDir, entry, "b1", 0)
	ev = <-events
	if !ev.Counted || ev.PendingBatches != 1 || ev.PendingRecords != 10 {
		t.Fatalf("a matching receipt must decrement provably: %+v", ev)
	}

	// A recovery re-pended records: unknown again.
	e.SetDeviceQueue(QueueSnapshot{PendingBatches: 1, PendingRecords: 10, Counted: true, RecordsCounted: true})
	e.ApplyDeviceDrain(stateDir, entry, "b1", 3)
	ev = <-events
	if ev.Counted {
		t.Fatalf("a recovery must mark the queue unknown: %+v", ev)
	}

	// An uncounted queue stays unknown (no fabrication).
	e.SetDeviceQueue(QueueSnapshot{})
	e.ApplyDeviceDrain(stateDir, entry, "b1", 0)
	ev = <-events
	if ev.Counted {
		t.Fatalf("an uncounted queue must stay unknown: %+v", ev)
	}
}

// The incremental cursor fold decrements the counts and unknowns the
// bytes and oldest age (which drained files is not held per step).
func TestProgressEmitterApplyCursorDrain(t *testing.T) {
	events := make(chan ProgressEvent, 8)
	ticks := make(chan time.Time)
	e := newProgressEmitterWithTicks(context.Background(), func(ev ProgressEvent) { events <- ev }, ticks, time.Now)
	defer e.Stop()

	e.SetCursorQueue(QueueSnapshot{PendingBatches: 3, PendingRecords: 30, Counted: true, RecordsCounted: true, PendingBytes: 300, BytesCounted: true, OldestPendingAge: time.Hour, AgeCounted: true})
	e.ApplyCursorDrain(1, 10)
	ev := <-events
	if !ev.Counted || ev.PendingBatches != 2 || ev.PendingRecords != 20 {
		t.Fatalf("the counts must decrement: %+v", ev)
	}
	if ev.BytesCounted || ev.AgeCounted {
		t.Fatalf("bytes and age must become unknown until the next bounded re-sample: %+v", ev)
	}

	// An uncounted queue stays untouched.
	e.SetCursorQueue(QueueSnapshot{})
	e.ApplyCursorDrain(1, 10)
	ev = <-events
	if ev.Counted {
		t.Fatalf("an uncounted cursor queue must stay unknown: %+v", ev)
	}
}

// The checked adds refuse to wrap: an old or corrupt ledger's extreme
// counts must degrade to unknown, never a fabricated total.
func TestAddCheckedHelpersRefuseOverflow(t *testing.T) {
	if sum, ok := addCheckedInt(10, 5); !ok || sum != 15 {
		t.Fatalf("normal int adds must pass: %d %v", sum, ok)
	}
	if _, ok := addCheckedInt(math.MaxInt, 1); ok {
		t.Fatalf("int overflow must be refused")
	}
	if sum, ok := addCheckedInt64(100, 23); !ok || sum != 123 {
		t.Fatalf("normal int64 adds must pass: %d %v", sum, ok)
	}
	if _, ok := addCheckedInt64(math.MaxInt64, 1); ok {
		t.Fatalf("int64 overflow must be refused")
	}
}

// A huge pending total over a tiny rate must degrade the ETA to
// unknown — never wrap into a negative duration.
func TestProgressEmitterEtaOverflowStaysUnknown(t *testing.T) {
	events := make(chan ProgressEvent, 8)
	ticks := make(chan time.Time)
	obsNow := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	e := newProgressEmitterWithTicks(context.Background(), func(ev ProgressEvent) { events <- ev }, ticks, func() time.Time { return obsNow })
	defer e.Stop()

	e.EnterStage("drain")
	e.BeginDrain()
	e.SetDeviceQueue(QueueSnapshot{PendingBatches: 1, PendingRecords: math.MaxInt, Counted: true, RecordsCounted: true})
	// One accepted record over one millisecond: rate = 1000/s; the ETA
	// for MaxInt records at that rate is ~9.2e15 seconds — far past
	// MaxInt64 nanoseconds.
	e.AddBatchOutcome(1, 1)
	obsNow = obsNow.Add(time.Millisecond)
	ticks <- obsNow
	ev := <-events
	if !ev.RateKnown || ev.ProcessingRateRecPerSec <= 0 {
		t.Fatalf("the rate itself is computed and known: %+v", ev)
	}
	if ev.EtaKnown || ev.Eta != 0 {
		t.Fatalf("an overflowing ETA must stay unknown, never a wrapped duration: %+v", ev)
	}
}

// The in-flight attempt status is stated only where the flow's
// Begin/End hooks are accurate: an untracked emitter (the first-enable
// round, the history phase) reports UNKNOWN — never a defaulted false.
func TestProgressEmitterUntrackedAttemptIsUnknown(t *testing.T) {
	events := make(chan ProgressEvent, 8)
	ticks := make(chan time.Time)
	e := newProgressEmitterWithTicks(context.Background(), func(ev ProgressEvent) { events <- ev }, ticks, time.Now)
	defer e.Stop()

	// No BeginAttempt was ever called: the heartbeat must not claim an
	// attempt status at all.
	e.EnterStage("cursor_sync")
	ticks <- time.Now()
	ev := <-events
	if ev.AttemptInFlightKnown {
		t.Fatalf("an untracked flow must not state an in-flight status: %+v", ev)
	}
	if ev.AttemptInFlight {
		t.Fatalf("an untracked flow must never default to a claimed status: %+v", ev)
	}

	// Once the hooks run, the status is known — true mid-attempt.
	e.BeginAttempt(ProgressQueueDevice)
	ticks <- time.Now()
	ev = <-events
	if !ev.AttemptInFlightKnown || !ev.AttemptInFlight {
		t.Fatalf("a tracked in-flight attempt must be stated: %+v", ev)
	}

	// And false between attempts — still known, still accurate.
	e.EndAttempt()
	ticks <- time.Now()
	ev = <-events
	if !ev.AttemptInFlightKnown || ev.AttemptInFlight {
		t.Fatalf("between attempts the tracked status is a known false: %+v", ev)
	}
}

// The ETA boundary: a nanos value of EXACTLY 2^63 (reachable, e.g.,
// from a MaxInt pending total at a 1e9 records/s rate) must be
// rejected — the float64 rounding of math.MaxInt64 is 2^63, so a
// strict `>` comparison would pass it and the int64 conversion would
// overflow. Values strictly below the boundary convert validly.
func TestEtaNanosRejectsExactFloatBoundary(t *testing.T) {
	// Exactly 2^63: rejected.
	if nanos, ok := etaNanos(math.MaxInt, 1e9); ok {
		t.Fatalf("a nanos value of exactly 2^63 must be rejected, got %d", nanos)
	}
	// A second exact-2^63 construction (2^62 records at 0.5e9/s).
	if nanos, ok := etaNanos(1<<62, 0.5*1e9); ok {
		t.Fatalf("the second exact-2^63 construction must be rejected, got %d", nanos)
	}
	// Just below the boundary: valid and positive (the largest float64
	// below 2^63 converts to a legitimate duration).
	nanos, ok := etaNanos(1<<62, 1e9)
	if !ok || nanos <= 0 {
		t.Fatalf("a strictly-below-boundary ETA must convert validly: %d %v", nanos, ok)
	}
	// Ordinary values pass through unchanged.
	if nanos, ok := etaNanos(1500, 10); !ok || time.Duration(nanos) != 150*time.Second {
		t.Fatalf("an ordinary ETA must pass (1500 records at 10/s = 150s): %d %v", nanos, ok)
	}
}

// Aggregate overflow degrades exactly its own gate: batches, records
// and bytes each refuse to wrap across the two queues.
func TestProgressEmitterAggregateOverflowDegradesOwnGate(t *testing.T) {
	events := make(chan ProgressEvent, 8)
	ticks := make(chan time.Time)
	e := newProgressEmitterWithTicks(context.Background(), func(ev ProgressEvent) { events <- ev }, ticks, time.Now)
	defer e.Stop()

	e.SetDeviceQueue(QueueSnapshot{PendingBatches: math.MaxInt, PendingRecords: math.MaxInt, Counted: true, RecordsCounted: true, PendingBytes: math.MaxInt64, BytesCounted: true})
	e.SetCursorQueue(QueueSnapshot{PendingBatches: math.MaxInt, PendingRecords: math.MaxInt, Counted: true, RecordsCounted: true, PendingBytes: math.MaxInt64, BytesCounted: true})
	e.SetCursorInScope(true)
	e.AddBatchOutcome(1, 1)
	ticks <- time.Now()
	ev := <-events
	if ev.Counted {
		t.Fatalf("a batch-count overflow must degrade the aggregate count: %+v", ev)
	}
	if ev.RecordsCounted || ev.PendingRecords != 0 {
		t.Fatalf("a record overflow must degrade the records gate: %+v", ev)
	}
	if ev.BytesCounted || ev.PendingBytes != 0 {
		t.Fatalf("a byte overflow must degrade the bytes gate: %+v", ev)
	}
}

// InvalidateDeviceQueue marks the held snapshot unknown immediately —
// the staleness guard for failure paths that may have mutated the
// ledger under it.
func TestProgressEmitterInvalidateDeviceQueue(t *testing.T) {
	events := make(chan ProgressEvent, 8)
	ticks := make(chan time.Time)
	e := newProgressEmitterWithTicks(context.Background(), func(ev ProgressEvent) { events <- ev }, ticks, time.Now)
	defer e.Stop()

	e.SetDeviceQueue(QueueSnapshot{PendingBatches: 3, PendingRecords: 30, Counted: true, RecordsCounted: true})
	e.InvalidateDeviceQueue()
	ticks <- time.Now()
	ev := <-events
	if ev.Counted || ev.RecordsCounted || ev.PendingBatches != 0 {
		t.Fatalf("an invalidated snapshot must read as unknown: %+v", ev)
	}
}
