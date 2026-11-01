package syncclient

import (
	"strconv"
	"strings"
	"time"

	"toktrail-collector/internal/syncretry"
)

// AttemptStage is the closed set of phases one send attempt of a batch
// passes through inside Run. The value identifies where the attempt
// ENDED: a failure reports the stage it was in when it stopped, a
// successful attempt always reports StageAck. Consumers must match on
// the constants, never on the numeric value, and must not infer more
// than the stage boundary semantics documented on each field of
// AttemptEvent.
type AttemptStage uint8

const (
	// StagePrepare covers everything the attempt does before the ingest
	// POST is issued: the privacy re-check on retries, the durable outbox
	// attempt accounting (MarkAttempt), the durable authorization-attempt
	// accounting (the state-dir ledger or the caller's PreflightAccounting
	// hook), the authorization preflight call (preflightSelf), the paused
	// check, the first attempt's consent-scope gate (including a split and
	// quarantine recovery) or a retry's pure scope re-check, the payload
	// marshal that freezes the wire bytes, request construction, and the
	// upload-budget reservation. "Preflight" is deliberately NOT this
	// stage's name: the word is reserved for the authorization self check
	// alone (see AttemptEvent.SelfCheckDuration).
	StagePrepare AttemptStage = iota + 1
	// StageUpload covers the ingest POST round trip: issuing the request,
	// receiving the response, and fully reading and decoding the response
	// body, plus validating the returned receipt against the submitted
	// batch (reconcileReceipt). A receipt that fails validation ends the
	// attempt here.
	StageUpload
	// StageAck covers the local durable ACK commit (commitSyncACK) that
	// runs only after a receipt fully validated: state save, outbox
	// mark-synced, and cursor/per-message confirmations.
	StageAck
)

// String renders the stage for logs; the identifiers are stable.
func (s AttemptStage) String() string {
	switch s {
	case StagePrepare:
		return "prepare"
	case StageUpload:
		return "upload"
	case StageAck:
		return "ack"
	default:
		return "unknown_stage:" + strconv.Itoa(int(s))
	}
}

// AttemptResult is the closed set of outcomes of one send attempt.
type AttemptResult uint8

const (
	// ResultAcked: the server receipt was decoded, fully validated
	// against the submitted batch (ReceiptKnown), and the local durable
	// ACK committed. The receipt's per-record decisions are reported in
	// AttemptEvent.Accepted / Rejected.
	ResultAcked AttemptResult = iota + 1
	// ResultRetryableFailure: the attempt failed with an error carrying a
	// syncretry retry marking. This says ONLY that the failure was marked
	// retryable — the policy may still stop without another attempt
	// (retry budget exhausted, the next start would pass the run deadline,
	// or the wait itself was canceled). Whether a retry actually happens
	// is observable solely from the arrival of an event with the next
	// attempt number.
	ResultRetryableFailure
	// ResultFinalFailure: the attempt failed without a retry marking, so
	// no retry follows (this is also every failure when Options.Retry is
	// nil). Includes stops that are steady states rather than errors in
	// the retry sense (paused device, budget decline, authorization
	// preflight stops, receipt-validation failures, ACK commit failure).
	ResultFinalFailure
)

// String renders the result for logs; the identifiers are stable.
func (r AttemptResult) String() string {
	switch r {
	case ResultAcked:
		return "acked"
	case ResultRetryableFailure:
		return "retryable_failure"
	case ResultFinalFailure:
		return "final_failure"
	default:
		return "unknown_result:" + strconv.Itoa(int(r))
	}
}

// AttemptObserved is a closed bitmask stating which AttemptEvent fields
// carry a real measurement for this attempt. The discipline is strict:
// a field whose bit is clear holds a meaningless zero value and MUST NOT
// be read as a genuine zero duration or zero size — it means the phase
// was never reached or the value never became known. Receipt-derived
// fields (Accepted, Rejected, BatchReplay) use AttemptEvent.ReceiptKnown
// instead of a bit here.
type AttemptObserved uint16

const (
	// ObservedPrepare is set on every event: every attempt begins in the
	// prepare stage. PrepareDuration is therefore always a real monotonic
	// measurement — of the completed preparation when the ingest POST was
	// issued, or of the elapsed time until the attempt stopped inside
	// prepare when it failed there (a partial preparation, not a
	// completed one).
	ObservedPrepare AttemptObserved = 1 << iota
	// ObservedSelfCheck: the attempt invoked the authorization preflight
	// check (preflightSelf) and SelfCheckDuration timed that whole call.
	// The bit does NOT claim an HTTP request reached the wire: the call
	// includes endpoint URL parsing and request construction, which can
	// fail before any network I/O happens. Clear when the attempt stopped
	// before the call (privacy re-check, outbox accounting, or
	// preflight-accounting failures).
	ObservedSelfCheck
	// ObservedHTTP: the attempt handed the ingest request to the HTTP
	// client (entered client.Do) and HTTPDuration timed from that handoff
	// through the full response body decode. Entering client.Do is not a
	// guarantee that bytes reached the network — a transport failure
	// inside the call still sets this bit. Clear when the attempt never
	// reached client.Do.
	ObservedHTTP
	// ObservedACK: the attempt invoked the local durable ACK commit and
	// ACKDuration timed it.
	ObservedACK
	// ObservedInterAttempt: the attempt had an observed predecessor, so
	// InterAttemptDelay is a real measurement. Set exactly when Attempt
	// is greater than one; the first attempt has no predecessor.
	ObservedInterAttempt
	// ObservedPayloadBytes: the run had frozen the serialized request
	// body by the time this attempt concluded (the first attempt's
	// marshal succeeded, including cases where a later pre-POST step such
	// as the budget reservation declined). PayloadBytes then holds that
	// frozen body's size.
	ObservedPayloadBytes
)

// Has reports whether every bit in bits is set on o.
func (o AttemptObserved) Has(bits AttemptObserved) bool { return o&bits == bits }

// String renders the set of observed bits for logs, pipe-separated in
// declaration order.
func (o AttemptObserved) String() string {
	if o == 0 {
		return "none"
	}
	var parts []string
	for _, bit := range []struct {
		bit  AttemptObserved
		name string
	}{
		{ObservedPrepare, "prepare"},
		{ObservedSelfCheck, "self_check"},
		{ObservedHTTP, "http"},
		{ObservedACK, "ack"},
		{ObservedInterAttempt, "inter_attempt"},
		{ObservedPayloadBytes, "payload_bytes"},
	} {
		if o.Has(bit.bit) {
			parts = append(parts, bit.name)
		}
	}
	return strings.Join(parts, "|")
}

// AttemptEvent is the sanitized progress record for ONE send attempt of
// ONE batch inside Run, delivered through Options.Progress. Run sends a
// single batch per call, so the attempt numbering is per Run (per
// batch); callers looping over batches attach their own correlation.
//
// Privacy contract — the event is deliberately deaf to identifiers and
// diagnostics: it carries no file paths, no URLs, no batch, device, or
// record identifiers, no secrets, no consent revision, no HTTP status
// codes, no server free text, and no error text of any kind. Everything
// a consumer can learn from an event is listed below: closed enums,
// monotonic durations behind Observed bits, a planned payload size, and
// receipt decision counts behind ReceiptKnown.
//
// Field validity: a duration or PayloadBytes is meaningful only when its
// Observed bit is set; Accepted, Rejected, and BatchReplay are
// meaningful only when ReceiptKnown is true. Cleared bits mean "not
// reached / not known", never a true zero.
type AttemptEvent struct {
	// Attempt is the 1-based attempt ordinal within this Run. It is a
	// pure ordinal, not an identifier of anything.
	Attempt int `json:"attempt"`
	// Stage is the phase the attempt ended in.
	Stage AttemptStage `json:"stage"`
	// Result is the attempt's outcome.
	Result AttemptResult `json:"result"`
	// Observed states which duration and size fields below carry a real
	// measurement.
	Observed AttemptObserved `json:"observed"`
	// InterAttemptDelay is valid iff ObservedInterAttempt is set: the
	// monotonic time from the previous attempt's conclusion (its send
	// wrapper returning, AFTER that attempt's event was already
	// delivered to the Progress callback) to this attempt's start (its
	// wrapper being invoked). It therefore covers the retry policy's
	// wait — computed backoff and/or the server's Retry-After floor —
	// plus the policy's own classification overhead, and deliberately
	// EXCLUDES time spent in the Progress callback itself, so a slow
	// consumer cannot widen the measured gap. It is NOT guaranteed to
	// equal the pure backoff value and is deliberately not named
	// "backoff". When the policy stops after a retry-marked failure
	// (budget exhausted, deadline, canceled wait), no further event
	// exists to report a wait that never completed.
	InterAttemptDelay time.Duration `json:"interAttemptDelay"`
	// PrepareDuration is valid iff ObservedPrepare (always set): monotonic
	// time from the attempt's start to the ingest request being handed to
	// the HTTP client, or — when the attempt stopped inside prepare — to
	// that stopping point. It includes SelfCheckDuration within it, plus
	// the durable accounting writes, gates, marshal, and budget
	// reservation described on StagePrepare.
	PrepareDuration time.Duration `json:"prepareDuration"`
	// SelfCheckDuration is valid iff ObservedSelfCheck: the monotonic
	// duration of this attempt's authorization preflight call
	// (preflightSelf) as a whole — endpoint URL parsing, request
	// construction, the GET /v1/devices/self round trip when it happens,
	// response decoding, and the local scope adjustment. It is a strict
	// subset of PrepareDuration and makes no claim that an HTTP request
	// actually reached the wire. The extra self check an outbox
	// scope-error reorganization performs after a rejected POST is NOT
	// part of this or any other reported duration.
	SelfCheckDuration time.Duration `json:"selfCheckDuration"`
	// HTTPDuration is valid iff ObservedHTTP: monotonic time from handing
	// the ingest request to the HTTP client (entering client.Do) to the
	// round trip concluding — the client.Do call returning a transport
	// error, or the response body having been fully read and decoded
	// (body included). Entering client.Do is not a guarantee that bytes
	// reached the network. Receipt validation after the decode is not
	// timed separately.
	HTTPDuration time.Duration `json:"httpDuration"`
	// ACKDuration is valid iff ObservedACK: the monotonic duration of the
	// local durable ACK commit (commitSyncACK).
	ACKDuration time.Duration `json:"ackDuration"`
	// PayloadBytes is valid iff ObservedPayloadBytes: the size in bytes of
	// the serialized, frozen request body this run prepared to send. It
	// is a PLANNED size (len of the immutable payload), not a count of
	// bytes actually transmitted: a failure mid-flight may have
	// transmitted fewer bytes or none at all, and the event can never
	// verify what left the device. It must never be reported as "bytes
	// sent".
	PayloadBytes int64 `json:"payloadBytes"`
	// ReceiptKnown reports whether a server receipt was decoded AND fully
	// validated against the submitted batch (reconcileReceipt). Only then
	// do Accepted, Rejected, and BatchReplay describe the server's
	// receipt; a missing receipt, a mismatched batch ID, an inconsistent
	// receipt, or a lost response body all leave this false with those
	// fields meaningless.
	ReceiptKnown bool `json:"receiptKnown"`
	// Accepted is valid iff ReceiptKnown: the receipt's count of accepted
	// records for this batch. It is the receipt's per-batch decision
	// number and nothing more — with BatchReplay false it must NOT be
	// read as records the server newly added or confirmed for the first
	// time (a record may already have been accepted under another batch),
	// and with BatchReplay true it belongs to the stored receipt, not to
	// any particular POST.
	Accepted int `json:"accepted"`
	// Rejected is valid iff ReceiptKnown: the receipt's count of rejected
	// records for this batch, with the same per-batch-decision caveat as
	// Accepted.
	Rejected int `json:"rejected"`
	// BatchReplay is valid iff ReceiptKnown: it mirrors ONLY the
	// receipt's whole-batch replay flag. True means the server returned
	// its stored whole-batch receipt for a batch ID it had already
	// processed; the counts are that stored receipt's. The bit carries no
	// other semantics: it says nothing about per-record duplication, and
	// it does not exclude that the local ACK performed in this attempt is
	// this device's FIRST local ACK for the batch (for example after a
	// previous response was lost: the server had persisted the batch
	// while no local ACK ever ran). False means the receipt reports this
	// POST's processing — still without licensing any "first
	// confirmation" reading of Accepted.
	BatchReplay bool `json:"batchReplay"`
}

// attemptNow is the clock source for the attempt instrumentation — a
// package variable so tests can verify the nil-Progress contract: with
// no callback wired, Run must never read it. Production always uses
// time.Now, whose monotonic reading makes every measured duration
// monotonic.
var attemptNow = time.Now

// attemptProgress is the per-attempt instrumentation behind
// AttemptEvent. It only ever reads the monotonic clock and records
// stage boundaries; it changes no send behavior, and its finish method
// assembles the sanitized event. Zero times double as "not reached"
// sentinels, which is safe because every recorded value comes from
// attemptNow and is therefore never the zero Time.
//
// Nil-safety IS the nil-Progress contract: when Options.Progress is nil,
// Run hands a nil *attemptProgress down and every method below becomes a
// nil-receiver no-op that neither reads the clock nor allocates — the
// unobserved run performs no instrumentation work at all. Only finish
// requires a non-nil receiver; Run invokes it exactly when a callback
// exists, which is exactly when a tracker was created.
type attemptProgress struct {
	attempt int
	start   time.Time
	prevEnd time.Time
	// interAttempt is true when a previous attempt's conclusion was
	// observed (attempt > 1).
	interAttempt bool

	selfStart time.Time
	selfDone  time.Time
	postStart time.Time
	postDone  time.Time
	ackStart  time.Time
	ackDone   time.Time

	stage AttemptStage

	payloadBytes  int
	payloadFrozen bool
	receiptKnown  bool
	accepted      int
	rejected      int
	batchReplay   bool
}

// startAttemptProgress begins tracking one attempt. prevEnd is the
// previous attempt's conclusion time (zero for the first attempt).
// Called only when a Progress callback exists.
func startAttemptProgress(attemptNo int, prevEnd time.Time) *attemptProgress {
	tr := &attemptProgress{
		attempt:      attemptNo,
		start:        attemptNow(),
		prevEnd:      prevEnd,
		stage:        StagePrepare,
		interAttempt: attemptNo > 1 && !prevEnd.IsZero(),
	}
	return tr
}

// noteFrozenPayload records the size of the frozen request body. Called
// when the first attempt's marshal succeeds, and pre-seeded on retries
// from the run-level frozen payload. No-op on a nil tracker.
func (tr *attemptProgress) noteFrozenPayload(size int) {
	if tr == nil {
		return
	}
	tr.payloadBytes = size
	tr.payloadFrozen = true
}

// markSelfStart records that the authorization preflight check
// (preflightSelf) is being invoked. No-op on a nil tracker.
func (tr *attemptProgress) markSelfStart() {
	if tr == nil {
		return
	}
	tr.selfStart = attemptNow()
}

// markSelfDone records the preflight check's conclusion, success or
// failure — including failures inside URL parsing or request
// construction that never reach the network. No-op on a nil tracker.
func (tr *attemptProgress) markSelfDone() {
	if tr == nil {
		return
	}
	tr.selfDone = attemptNow()
}

// markPostIssued records that the ingest POST is being issued; the
// attempt is now in the upload stage. No-op on a nil tracker.
func (tr *attemptProgress) markPostIssued() {
	if tr == nil {
		return
	}
	tr.postStart = attemptNow()
	tr.stage = StageUpload
}

// markPostDone records the POST round trip's conclusion: a transport
// error from Do, or the response body having been fully decoded. No-op
// on a nil tracker.
func (tr *attemptProgress) markPostDone() {
	if tr == nil {
		return
	}
	tr.postDone = attemptNow()
}

// setReceipt records a receipt that decoded and fully validated. No-op
// on a nil tracker.
func (tr *attemptProgress) setReceipt(receipt BatchReceipt) {
	if tr == nil {
		return
	}
	tr.receiptKnown = true
	tr.accepted = receipt.AcceptedRecords
	tr.rejected = receipt.RejectedRecords
	tr.batchReplay = receipt.Replay
}

// markAckStart records that the local durable ACK commit is starting.
// No-op on a nil tracker.
func (tr *attemptProgress) markAckStart() {
	if tr == nil {
		return
	}
	tr.ackStart = attemptNow()
	tr.stage = StageAck
}

// markAckDone records the ACK commit's conclusion, success or failure.
// No-op on a nil tracker.
func (tr *attemptProgress) markAckDone() {
	if tr == nil {
		return
	}
	tr.ackDone = attemptNow()
}

// finish assembles the sanitized event for an attempt that returned
// err (nil only on the fully acknowledged success path). It reads the
// monotonic clock once more for the attempt's conclusion. Requires a
// non-nil tracker; Run calls it only under a wired Progress callback.
func (tr *attemptProgress) finish(err error) AttemptEvent {
	end := attemptNow()
	ev := AttemptEvent{
		Attempt:  tr.attempt,
		Stage:    tr.stage,
		Result:   attemptResultFor(err),
		Observed: ObservedPrepare, // every attempt begins in prepare
	}
	prepareEnd := tr.postStart
	if prepareEnd.IsZero() {
		prepareEnd = end
	}
	ev.PrepareDuration = prepareEnd.Sub(tr.start)
	if !tr.selfStart.IsZero() {
		selfEnd := tr.selfDone
		if selfEnd.IsZero() {
			selfEnd = end
		}
		ev.SelfCheckDuration = selfEnd.Sub(tr.selfStart)
		ev.Observed |= ObservedSelfCheck
	}
	if !tr.postStart.IsZero() {
		postEnd := tr.postDone
		if postEnd.IsZero() {
			postEnd = end
		}
		ev.HTTPDuration = postEnd.Sub(tr.postStart)
		ev.Observed |= ObservedHTTP
	}
	if !tr.ackStart.IsZero() {
		ackEnd := tr.ackDone
		if ackEnd.IsZero() {
			ackEnd = end
		}
		ev.ACKDuration = ackEnd.Sub(tr.ackStart)
		ev.Observed |= ObservedACK
	}
	if tr.interAttempt {
		ev.InterAttemptDelay = tr.start.Sub(tr.prevEnd)
		ev.Observed |= ObservedInterAttempt
	}
	if tr.payloadFrozen {
		ev.PayloadBytes = int64(tr.payloadBytes)
		ev.Observed |= ObservedPayloadBytes
	}
	ev.ReceiptKnown = tr.receiptKnown
	ev.Accepted = tr.accepted
	ev.Rejected = tr.rejected
	ev.BatchReplay = tr.batchReplay
	return ev
}

// attemptResultFor classifies an attempt's returned error without
// copying any of its content: nil means the attempt reached the fully
// acknowledged success path (runSendAttempt returns a nil error nowhere
// else), a retry marking makes the failure retryable from the attempt's
// point of view, and everything else is final.
func attemptResultFor(err error) AttemptResult {
	if err == nil {
		return ResultAcked
	}
	if syncretry.IsRetryable(err) {
		return ResultRetryableFailure
	}
	return ResultFinalFailure
}
