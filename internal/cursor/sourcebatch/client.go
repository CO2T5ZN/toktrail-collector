// Package sourcebatch uploads account-level cursor source batches to the
// TokTrail server ingest endpoint. It is deliberately separate from the
// device-batch syncclient: cursor records never travel to
// /v1/ingest/batches, and every request carries the source fence
// (X-Source-Fence) alongside the device authorization and the live
// consent revision.
//
// Security properties:
//
//   - the HTTP client never follows redirects (a cloned client with a
//     refusing CheckRedirect), so the device Authorization header can
//     never leak to another host;
//   - receipts are strictly validated (batch id match, the server's
//     accepted/rejected/partial_error status enum — which the server
//     derives from the record counts, so a status that disagrees with
//     the counts is invalid — non-negative counts covering every record,
//     non-zero receivedAt, in-range record error indexes) before they
//     are treated as an acknowledgment — a rejected or partial_error
//     receipt carries its indexed record errors and is NEVER a full
//     acknowledgment;
//   - error messages never echo server-provided message text (untrusted
//     data); only HTTP statuses and business codes from the fixed known
//     set travel, and an unrecognized code renders as the fixed word
//     "unknown" so no untrusted string — a reflected credential or
//     response content — can ride into logs or stderr.
//
// Retry classification (opt-in, Options.ClassifyRetryable): transient
// send failures are marked retryable through internal/syncretry so a
// caller-owned retry policy can distinguish them from final ones —
// network-shaped transport failures observed while the caller's context
// is still live, HTTP 429/500/502/503/504 answers whose business code is
// absent or known transient (internal_error, service_unavailable,
// rate_limited, too_many_requests — the same allowlist the device-batch
// send path uses), carrying the server's Retry-After hint, and 2xx
// answers whose receipt was lost or truncated in transit. Any other
// business code is final authority over the HTTP status — known codes
// map to their sentinels and unknown codes are conservatively final, so
// a 503/429 carrying scope_changed (or any unmapped code) never retries.
// Format-invalid receipts never retry either. With the flag unset (the
// default) every error is returned exactly as before; the retry loop,
// the payload identity across attempts and the upload budget stay with
// the caller.
//
// The optional progress hook (Options.Progress) mirrors this privacy
// posture: one closed PostProgress report per POST call — no URLs,
// paths, credentials, identifiers or error text — carrying the receipt
// counts only after they passed strict validation, and never claiming
// wire transmission (payload size is planned/attempted volume).
package sourcebatch

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/local/cursoroutbox"
	"toktrail-collector/internal/syncbudget"
	"toktrail-collector/internal/syncretry"
)

// Sentinel errors for actionable sync behavior (server wire codes:
// source_fence_changed, scope_changed, source_paused, source_deleted —
// plus the defensive aliases consent_revision_stale and stale_revision).
var (
	// ErrFenceStale: the server moved the source fence; the caller must
	// stop sending and re-fetch the self view (old pending batches are
	// fenced out, never re-sent).
	ErrFenceStale = errors.New("cursor source fence changed")
	// ErrConsentStale: the consent revision advanced; re-fetch and retry.
	ErrConsentStale = errors.New("consent revision is stale")
	// ErrSourcePaused: the server paused the account source; batches stay
	// pending and the next run re-checks the source state.
	ErrSourcePaused = errors.New("cursor source is paused server-side")
	// ErrSourceDeleted: the server deleted the account source; the next
	// self refresh will no longer list it.
	ErrSourceDeleted = errors.New("cursor source was deleted server-side")
	// ErrStaleRevision: the batch carries event revisions at or below the
	// facts the server already stores (obsolete replay). The batch is not
	// re-sent as-is; recovery is a nextRevision refresh followed by new
	// rounds.
	ErrStaleRevision = errors.New("cursor batch revisions are stale")
	// ErrDeviceUnauthorized: the device credentials were rejected.
	ErrDeviceUnauthorized = errors.New("device authorization rejected")
	// ErrInvalidReceipt: the server answered 2xx with a receipt that does
	// not strictly validate; never treated as success.
	ErrInvalidReceipt = errors.New("invalid source-batch receipt")
)

// errRedirectRefused is the cloned client's no-redirect policy error. A
// redirect answer is a deliberate local security refusal (the device
// Authorization header must never travel to another host), not a network
// failure, so it is excluded from retry classification.
var errRedirectRefused = errors.New("redirects are not allowed")

// transportError renders a fixed, human-safe message for a transport
// failure while keeping the original cause reachable through Unwrap, so
// every errors.Is / errors.As contract of the wrapped error survives:
// retry markers and their Retry-After hints, context cancellation and
// deadlines, net.Error shapes and the redirect refusal all keep
// matching exactly as on the unredacted error. Go's formatting never
// renders an error's chain — fmt's %v/%+v, the log package and
// %w-wrapping print only Error() — so the cause's raw text (which
// embeds the full request URL — including the source id in the GET
// query — and anything a hostile server placed into a refused
// redirect's Location header, such as the device secret from the
// Authorization bearer value) never reaches a human message.
type transportError struct {
	msg   string
	cause error
}

func (e *transportError) Error() string {
	return e.msg + ": " + transportCauseText(e.cause)
}

// Unwrap keeps the original cause reachable so errors.Is/As keep their
// full matching semantics; see the type comment for why that is safe.
func (e *transportError) Unwrap() error { return e.cause }

// wrapTransportError builds the sanitized wrapper. A nil err stays nil.
func wrapTransportError(msg string, err error) error {
	if err == nil {
		return nil
	}
	return &transportError{msg: msg, cause: err}
}

// transportCauseText renders a transport failure's identity as fixed,
// safe wording. A hostile endpoint cannot influence any of these strings
// (they key off sentinel identities, not error text); everything else
// collapses to the generic withheld-cause wording.
func transportCauseText(err error) string {
	switch {
	case errors.Is(err, errRedirectRefused):
		return "redirect refused (credentials never follow redirects)"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "connection closed by the server before a response"
	default:
		return "transport failure (network-level error text withheld; the cause remains matchable with errors.Is/errors.As)"
	}
}

const maxResponseBytes = 1 << 20

// budgetQueue is the syncbudget queue key every cursor source-batch
// ingest POST reserves under, so one run-wide budget can cap cursor
// upload attempts as a queue of its own next to the others (device, ...).
const budgetQueue = "cursor"

// RecordError is one server-rejected record with its index in the batch.
// The reason code is a stable server code; the server's free-text detail
// and recordKey fields are deliberately not modeled, so untrusted text
// never enters the collector.
type RecordError struct {
	Index int    `json:"index"`
	Code  string `json:"code,omitempty"`
}

// Receipt mirrors the device-batch ingest receipt shape
// (internal/syncclient.BatchReceipt) so the server can reuse the format,
// extended with indexed record errors for partial acknowledgments. The
// status is exactly the server's accepted / rejected / partial_error enum
// (the server derives it from the counts); a re-sent duplicate keeps its
// original status and sets Replay.
type Receipt struct {
	BatchID         string        `json:"batchId"`
	Status          string        `json:"status"`
	AcceptedRecords int           `json:"acceptedRecords"`
	RejectedRecords int           `json:"rejectedRecords"`
	Replay          bool          `json:"replay"`
	ReceivedAt      time.Time     `json:"receivedAt"`
	RecordErrors    []RecordError `json:"recordErrors,omitempty"`
}

// PostProgress reports the sanitized facts of ONE PostBatch call for the
// optional Options.Progress hook. It is deliberately closed: no URLs,
// paths, credentials, identifiers, HTTP statuses or raw error text —
// only what verifiably happened and, when a strictly-validated receipt
// arrived, its counts. Fields that cannot be determined stay at their
// zero values and are never faked (see ReceiptKnown's counterpart
// ValidReceipt below).
type PostProgress struct {
	// Attempted is true when the request was handed to the HTTP
	// transport — every local validation AND the optional budget
	// reservation passed. It is a statement about the call, never about
	// the wire: how many bytes actually left the machine is
	// unobservable, so PayloadBytes stays planned/attempted volume. A
	// budget decline or a local validation refusal leaves it false: the
	// POST never happened.
	Attempted bool
	// ValidReceipt is true when the server's answer decoded into a
	// receipt that passed the strict validation (batch id match, status
	// enum, count coverage, in-range indexes, receivedAt). Only then do
	// AcceptedRecords/RejectedRecords/Replay carry trustworthy values.
	// Every other outcome — transport failure, a non-2xx answer, an
	// invalid receipt — leaves them at zero: unknown, never a claim
	// that the server accepted or rejected zero records.
	ValidReceipt bool
	// PayloadBytes is the size in bytes of the immutable encoded batch
	// handed to the call (len(encoded)). Planned/attempted volume only:
	// the collector cannot observe actual transmission, so this is
	// never a claim of bytes sent or delivered.
	PayloadBytes int
	// AcceptedRecords/RejectedRecords mirror the strictly-validated
	// receipt (trusted only when ValidReceipt is true). RejectedRecords
	// above zero is still a valid receipt: the counts are known, the
	// caller decides what they mean for the batch.
	AcceptedRecords int
	RejectedRecords int
	// Replay is the receipt's batch-level replay flag: the server
	// answered a re-send of a batch id it had already stored durably.
	// It says nothing about local acknowledgment counting — a replay
	// receipt may well be the FIRST local acknowledgment of that batch
	// (a lost receipt proven by re-send).
	Replay bool
}

// Options configures one request set.
type Options struct {
	ServerURL  string
	HTTPClient *http.Client
	// DeviceID/DeviceSecret are the existing bound-device credentials;
	// account sources ride the device authentication.
	DeviceID, DeviceSecret string
	SourceInstanceID       string
	// Budget is optional. When set, one attempt is reserved under the
	// "cursor" queue immediately before the real ingest POST — after
	// every local validation has already refused what it could, so
	// nothing is spent on a batch that never reaches the wire. A decline
	// prevents the POST entirely (nothing was acknowledged or dropped;
	// the batch stays pending for a later run) and a reserved attempt is
	// never refunded — a POST that fails spends it. Nil keeps the
	// unconditional upload behavior.
	Budget *syncbudget.Budget
	// ClassifyRetryable, when set, marks transient send failures as
	// retryable through internal/syncretry (Retryable /
	// RetryAfterHeader) so a caller-owned retry policy can act on them:
	// network-shaped transport failures while the caller's context is
	// still live, HTTP 429/500/502/503/504 answers whose business code is
	// absent or known transient (carrying the server's Retry-After
	// hint), and 2xx answers whose receipt was lost or truncated in
	// transit. Business codes are final authority over the HTTP status —
	// known terminal codes map to their sentinels, unknown codes are
	// conservatively final — and format-invalid receipts never retry.
	// The default (false) returns every error exactly as before, so
	// single-attempt callers never see a retry marker.
	ClassifyRetryable bool
	// Progress, when set, receives exactly ONE sanitized PostProgress
	// report per PostBatch call, after the call fully resolved (success
	// or failure). The report is observational only — closed facts, no
	// URLs, paths, credentials, identifiers or raw error text — and
	// nothing in the upload's control flow reads it. GetBatch never
	// reports. Nil keeps the historical behavior byte for byte.
	Progress func(PostProgress)
}

type response struct {
	Batch *struct {
		BatchID         string        `json:"batchId"`
		Status          string        `json:"status"`
		AcceptedRecords int           `json:"acceptedRecords"`
		RejectedRecords int           `json:"rejectedRecords"`
		Replay          bool          `json:"replay"`
		ReceivedAt      time.Time     `json:"receivedAt"`
		RecordErrors    []RecordError `json:"recordErrors,omitempty"`
	} `json:"batch,omitempty"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// expectedReceiptStatus mirrors the server's usage.ReceiptStatus
// derivation: no rejections → accepted, every record rejected →
// rejected, some of each → partial_error. A receipt whose status
// disagrees with what its counts imply is invalid.
func expectedReceiptStatus(accepted, rejected int) string {
	switch {
	case rejected == 0:
		return "accepted"
	case accepted == 0:
		return "rejected"
	default:
		return "partial_error"
	}
}

// retryableIngestStatus reports whether a failed ingest response's HTTP
// status makes the send eligible for a policy retry. The list is the same
// explicit, deliberately narrow allowlist the device-batch send path uses
// (internal/syncclient): 429 (throttling, with the Retry-After header
// honored as a floor) and 500/502/503/504 (internal error and the
// gateway/proxy trio, all conventionally transient). Everything else is
// final: 401/403 authorization failures, 409 conflicts, other 4xx
// validation rejections, and even 5xx statuses that are not
// conventionally transient (501 Not Implemented, 505 version mismatches,
// …) — retrying those cannot help and only spends budget.
func retryableIngestStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

// retryableIngestCode reports whether a failed ingest response's business
// code keeps it eligible for a policy retry. Business codes are final
// authority over the HTTP status, so this fails closed on unknown codes
// even when the status looks retryable: only the empty code (the server
// stated no code) and the known transient codes — the same allowlist the
// device-batch send path uses, matching what the server actually writes
// (a real 500 carries code=internal_error) — may retry. Known terminal
// codes never reach this check; they map to their sentinels first.
func retryableIngestCode(code string) bool {
	switch strings.TrimSpace(code) {
	case "", "internal_error", "service_unavailable", "rate_limited", "too_many_requests":
		return true
	default:
		return false
	}
}

// displayCode renders a server-stated business code for an error
// message. Only the codes this collector itself recognizes — the mapped
// terminal codes and the known transient allowlist, exactly the sets the
// classification switches above use — keep their fixed name; every other
// non-empty code is untrusted server-controlled text (it could reflect a
// credential or response content) and collapses to the fixed word
// "unknown". The empty code (the server stated none) stays empty. The
// classification logic itself keeps working on the raw code; only the
// rendered message is sanitized.
func displayCode(code string) string {
	switch strings.TrimSpace(code) {
	case "":
		return ""
	case "stale_revision", "source_fence_changed", "source_paused", "source_deleted",
		"scope_changed", "consent_revision_stale",
		"internal_error", "service_unavailable", "rate_limited", "too_many_requests":
		return strings.TrimSpace(code)
	default:
		return "unknown"
	}
}

// receiptLossRetryable reports whether a response whose body could not be
// read at all (the status line arrived, the receipt did not) counts as
// transient: a lost receipt on a 2xx answer — the success receipt case —
// or on a status that is itself retryable. Every other status keeps the
// raw read error, final like the status it arrived with.
func receiptLossRetryable(status int) bool {
	return status == http.StatusOK || status == http.StatusAccepted || retryableIngestStatus(status)
}

// truncatedJSON reports whether a JSON parse failure is the truncation
// signature — the document ended mid-stream ("unexpected end of JSON
// input", which is also what an empty body yields) — rather than a
// malformed or wrongly-shaped one. Truncation means the receipt was cut
// off in transit (retryable: the same batch id and bytes re-send
// idempotently); anything else is a format error (final).
func truncatedJSON(err error) bool {
	var se *json.SyntaxError
	return errors.As(err, &se) && se.Error() == "unexpected end of JSON input"
}

// transportRetryable reports whether a failure of the ingest POST itself
// — observed while the caller's context is still live, which the caller
// checks separately — looks like a transient network failure a retry
// policy may wait out: connection-level errors (*net.OpError: refused,
// reset, DNS), premature EOF, TLS record errors, and the http.Client
// timeout whose error chain carries context.DeadlineExceeded. Deliberately
// excluded: any context cancellation (never transient), the client's own
// no-redirect refusal (a local security policy, not the network) and
// request/scheme-construction errors (local misconfiguration). Unknown
// error shapes stay final — the conservative direction.
func transportRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, errRedirectRefused) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		// A client request timeout; the still-live caller context is
		// what distinguishes it from the caller's own expired deadline.
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var tlsErr tls.RecordHeaderError
	if errors.As(err, &tlsErr) {
		return true
	}
	return false
}

// markRetryable wraps err with the syncretry marker so an opted-in retry
// policy can distinguish it from a final failure. The marking is
// idempotent: an error that already carries a retry marker is returned
// unchanged, so the same failure is never double-wrapped.
func markRetryable(err error) error {
	if err == nil {
		return nil
	}
	if syncretry.IsRetryable(err) {
		return err
	}
	return syncretry.Retryable(err)
}

// markRetryableWithHeader is markRetryable for a failure that carries the
// raw value of the server's Retry-After header; an empty or absent
// header degrades to the plain marker.
func markRetryableWithHeader(err error, header string) error {
	if err == nil {
		return nil
	}
	if syncretry.IsRetryable(err) {
		return err
	}
	if h := strings.TrimSpace(header); h != "" {
		return syncretry.RetryAfterHeader(err, h)
	}
	return syncretry.Retryable(err)
}

// validateReceipt strictly checks a 2xx receipt against the uploaded
// batch: the batch id must match, the status must be one of the server's
// accepted/rejected/partial_error enum and consistent with the record
// counts, counts must be non-negative, and receivedAt must be present.
// For a POST (recordCount >= 0) the counts must cover every record and
// every record error index must fall inside the batch; a GET receipt
// (recordCount < 0 — the server replays the stored receipt without the
// batch) skips only those two coverage checks. Receipts with rejected
// records (rejected / partial_error) validate and carry their indexed
// record errors: they are NEVER a full acknowledgment, and the caller
// must keep the batch pending (cursoroutbox.MarkSynced refuses them).
//
// Error privacy: the mismatching batch id and any non-enum status are
// untrusted server text and are never echoed into the error — a
// malicious response could plant a credential or response content
// there, and those values must not travel into logs or stderr. The
// three enum statuses and numeric counts are the collector's own parsed
// values and stay.
func validateReceipt(r *Receipt, batchID string, recordCount int) error {
	if r.BatchID != batchID {
		return fmt.Errorf("%w: receipt names a different batch than the uploaded one", ErrInvalidReceipt)
	}
	if r.AcceptedRecords < 0 || r.RejectedRecords < 0 {
		return fmt.Errorf("%w: negative record counts", ErrInvalidReceipt)
	}
	switch r.Status {
	case "accepted", "rejected", "partial_error":
		if want := expectedReceiptStatus(r.AcceptedRecords, r.RejectedRecords); r.Status != want {
			return fmt.Errorf("%w: receipt status %q disagrees with accepted %d / rejected %d records", ErrInvalidReceipt, r.Status, r.AcceptedRecords, r.RejectedRecords)
		}
	default:
		return fmt.Errorf("%w: receipt carries an unknown status", ErrInvalidReceipt)
	}
	if recordCount >= 0 {
		if r.AcceptedRecords+r.RejectedRecords != recordCount {
			return fmt.Errorf("%w: accepted %d + rejected %d != %d records", ErrInvalidReceipt, r.AcceptedRecords, r.RejectedRecords, recordCount)
		}
		for _, re := range r.RecordErrors {
			if re.Index < 0 || re.Index >= recordCount {
				return fmt.Errorf("%w: record error index %d out of range", ErrInvalidReceipt, re.Index)
			}
		}
	} else {
		// GET: the record count is unknown, so only the index sign is
		// checkable; coverage cannot be re-verified.
		for _, re := range r.RecordErrors {
			if re.Index < 0 {
				return fmt.Errorf("%w: record error index %d out of range", ErrInvalidReceipt, re.Index)
			}
		}
	}
	if r.ReceivedAt.IsZero() {
		return fmt.Errorf("%w: missing receivedAt", ErrInvalidReceipt)
	}
	return nil
}

// PostBatch uploads one validated batch. fenceVersion is the current
// source fence from the live self view; consentRevision is the live
// device consent revision. The body is the exact immutable outbox bytes
// (already protocol-encoded), re-validated here before transmission.
//
// When opt.Progress is set, exactly one sanitized PostProgress report
// fires for this call after it fully resolved — success or failure
// (see PostProgress). The hook is observational only and never changes
// the upload's behavior; a nil hook keeps the historical path byte for
// byte.
func PostBatch(ctx context.Context, opt Options, encoded []byte, fenceVersion, consentRevision int64) (cursoroutbox.Receipt, error) {
	receipt, err, progress := postBatch(ctx, opt, encoded, fenceVersion, consentRevision)
	if opt.Progress != nil {
		opt.Progress(progress)
	}
	return receipt, err
}

// postBatch is PostBatch's core: the full validated upload of one
// immutable batch, returning the regular receipt/error pair plus the
// sanitized per-call facts for the optional progress hook. The facts
// are accumulated along the existing control flow — every return path
// carries them unchanged — and nothing reads them back.
func postBatch(ctx context.Context, opt Options, encoded []byte, fenceVersion, consentRevision int64) (cursoroutbox.Receipt, error, PostProgress) {
	progress := PostProgress{PayloadBytes: len(encoded)}
	batch, err := protocol.DecodeBatch(encoded)
	if err != nil {
		return cursoroutbox.Receipt{}, fmt.Errorf("refusing to upload unvalidated cursor batch: %w", err), progress
	}
	if batch.SourceInstanceID != opt.SourceInstanceID {
		// The two source ids are historical, potentially untrusted text
		// (a permit or its persisted batches from before the reflection
		// boundary may carry a credential a malicious server once
		// mirrored); they are never echoed. The batch id is locally
		// generated and stays for correlation.
		return cursoroutbox.Receipt{}, fmt.Errorf("cursor batch %s belongs to a different source than the configured one", batch.BatchID), progress
	}
	endpoint, err := joinURL(opt.ServerURL, "/v1/ingest/source-batches")
	if err != nil {
		return cursoroutbox.Receipt{}, err, progress
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return cursoroutbox.Receipt{}, wrapTransportError("source-batch upload request could not be built", err), progress
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+opt.DeviceID+"."+opt.DeviceSecret)
	req.Header.Set("X-Source-Fence", strconv.FormatInt(fenceVersion, 10))
	req.Header.Set("X-Consent-Revision", strconv.FormatInt(consentRevision, 10))
	// Shared run budget: reserve one attempt immediately before the real
	// ingest POST (the GET receipt path never reserves). A decline ends
	// the upload with no network activity at all — the caller keeps the
	// batch pending and a later run resumes it; a granted attempt is
	// spent for good, even when the POST itself then fails. A nil Budget
	// keeps the unconditional upload behavior.
	if opt.Budget != nil {
		if err := opt.Budget.Reserve(ctx, budgetQueue); err != nil {
			return cursoroutbox.Receipt{}, err, progress
		}
	}
	// The request is handed to the HTTP transport below: this is the one
	// wire-level fact the progress hook can state (Attempted). How many
	// bytes actually left the machine stays unobservable — PayloadBytes
	// remains planned/attempted volume, never a claim of transmission.
	progress.Attempted = true
	resp, err := client(opt).Do(req)
	if err != nil {
		// A transport failure is transient only when the caller's
		// context is still live (a canceled or deadline-expired parent
		// context is final — no retry may start) and the failure is
		// genuinely network-shaped: never the client's own redirect
		// refusal, never a request-construction error. A client request
		// timeout with a live parent context IS retryable. The
		// classification runs on the ORIGINAL error (unchanged); the
		// returned error is wrapped with a fixed human message that
		// never renders the transport text — which embeds the request
		// URL and anything a hostile server placed into a refused
		// redirect's Location — while Unwrap keeps the chain (markers,
		// cancellation, net.Error) fully matchable.
		if opt.ClassifyRetryable && ctx.Err() == nil && transportRetryable(err) {
			return cursoroutbox.Receipt{}, markRetryable(wrapTransportError("source-batch upload request failed on the transport", err)), progress
		}
		return cursoroutbox.Receipt{}, wrapTransportError("source-batch upload request failed on the transport", err), progress
	}
	defer resp.Body.Close()
	receipt, err := decodeReceipt(ctx, resp, batch.BatchID, len(batch.Records), opt.ClassifyRetryable)
	if err != nil {
		return cursoroutbox.Receipt{}, err, progress
	}
	stored := toStoreReceipt(receipt)
	// The receipt passed strict validation: its counts are the only
	// trustworthy server-side tallies the hook can report.
	progress.ValidReceipt = true
	progress.AcceptedRecords = stored.AcceptedRecords
	progress.RejectedRecords = stored.RejectedRecords
	progress.Replay = stored.Replay
	return stored, nil, progress
}

// GetBatch fetches the server-side receipt of one previously uploaded
// batch, carrying the current consent revision and source fence like the
// POST. It reports whether the server knows the batch. Transport
// failures are wrapped with fixed human messages: the GET URL carries
// the source id in its query (potentially a credential mirrored into an
// old permit) and a refused redirect's Location is server-controlled
// text, so neither may ever reach a human message; Unwrap keeps the
// original cause matchable.
func GetBatch(ctx context.Context, opt Options, batchID string, fenceVersion, consentRevision int64) (cursoroutbox.Receipt, bool, error) {
	endpoint, err := joinURL(opt.ServerURL, "/v1/ingest/source-batches/"+url.PathEscape(batchID))
	if err != nil {
		return cursoroutbox.Receipt{}, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return cursoroutbox.Receipt{}, false, wrapTransportError("source-batch receipt fetch request could not be built", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+opt.DeviceID+"."+opt.DeviceSecret)
	req.Header.Set("X-Source-Fence", strconv.FormatInt(fenceVersion, 10))
	req.Header.Set("X-Consent-Revision", strconv.FormatInt(consentRevision, 10))
	q := req.URL.Query()
	q.Set("sourceInstanceId", opt.SourceInstanceID)
	req.URL.RawQuery = q.Encode()
	resp, err := client(opt).Do(req)
	if err != nil {
		return cursoroutbox.Receipt{}, false, wrapTransportError("source-batch receipt fetch request failed on the transport", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return cursoroutbox.Receipt{}, false, nil
	}
	// A GET receipt is validated against the batch identity only: the
	// server replays the stored receipt (with its real counts and record
	// errors) but not the batch, so count coverage and the record error
	// index upper bound cannot be re-checked. The GET path never
	// classifies retries — it is not a send.
	receipt, err := decodeReceipt(ctx, resp, batchID, -1, false)
	if err != nil {
		return cursoroutbox.Receipt{}, false, err
	}
	return toStoreReceipt(receipt), true, nil
}

// sanitizeRecordErrors keeps the index and the stable reason code of
// each server-rejected record, but only for codes on the server's known
// safe list (stale_revision, record_conflict and the invalid_* family);
// every other code collapses to the generic record_rejected so untrusted
// server text can never ride into store receipts or diagnostics. The
// server's free-text message is never parsed at all.
func sanitizeRecordErrors(errs []RecordError) []cursoroutbox.RecordError {
	if len(errs) == 0 {
		return nil
	}
	out := make([]cursoroutbox.RecordError, 0, len(errs))
	for _, re := range errs {
		code := "record_rejected"
		switch re.Code {
		case "stale_revision", "record_conflict", "invalid_event_key", "invalid_revision", "invalid_kind", "invalid_time", "invalid_tool", "invalid_adapter_version", "invalid_source_type", "invalid_model", "invalid_decimal":
			code = re.Code
		}
		out = append(out, cursoroutbox.RecordError{Index: re.Index, Code: code})
	}
	return out
}

func toStoreReceipt(r Receipt) cursoroutbox.Receipt {
	return cursoroutbox.Receipt{
		BatchID:         r.BatchID,
		Status:          r.Status,
		AcceptedRecords: r.AcceptedRecords,
		RejectedRecords: r.RejectedRecords,
		Replay:          r.Replay,
		ReceivedAt:      r.ReceivedAt,
		RecordErrors:    sanitizeRecordErrors(r.RecordErrors),
	}
}

// decodeReceipt reads and classifies one ingest response. classifyRetryable
// (PostBatch's Options.ClassifyRetryable; the GET path always passes false)
// marks transient failures with the syncretry marker so the caller's retry
// policy can act on them:
//
//   - a body that cannot be read at all on a 2xx answer (the success
//     receipt was lost) or on a retryable status — transient, because
//     re-sending the same batch id and bytes is idempotent server-side;
//   - a 2xx body that is the JSON truncation signature (the receipt was
//     cut off mid-stream) — transient for the same reason;
//   - a non-2xx retryable status (429/500/502/503/504) whose business
//     code is absent or known transient, carrying the server's
//     Retry-After hint.
//
// Everything else stays final exactly as without classification: known
// terminal business codes map to their sentinels and win over any status,
// unknown business codes are conservatively final, other statuses are
// final, and a receipt that parses but fails strict validation (or is
// malformed rather than truncated, or oversized) is a format error.
func decodeReceipt(ctx context.Context, resp *http.Response, batchID string, recordCount int, classifyRetryable bool) (Receipt, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		// The status line arrived but the receipt did not. On a 2xx
		// answer that is a lost success receipt; on a retryable status
		// the loss changes nothing about the status's transience. Only
		// a still-live caller context may retry it. The classification
		// runs on the ORIGINAL error (unchanged); the returned error is
		// wrapped with a fixed human message (the read error's raw text
		// may embed transport details) while Unwrap keeps the chain
		// matchable.
		if classifyRetryable && ctx.Err() == nil && receiptLossRetryable(resp.StatusCode) {
			return Receipt{}, markRetryable(wrapTransportError("source-batch response could not be read", err))
		}
		return Receipt{}, wrapTransportError("source-batch response could not be read", err)
	}
	if len(body) > maxResponseBytes {
		return Receipt{}, errors.New("source-batch response exceeds 1 MB limit")
	}
	var r response
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted {
		if err := json.Unmarshal(body, &r); err != nil {
			if classifyRetryable && truncatedJSON(err) {
				// A 2xx answer whose receipt was cut off in transit: the
				// upload may well be stored, but only a re-send with the
				// same id and bytes can prove it (the server answers a
				// duplicate with a replay receipt). A malformed rather
				// than truncated body is a format error and stays final.
				return Receipt{}, markRetryable(fmt.Errorf("%w: HTTP %d receipt was truncated in transit", ErrInvalidReceipt, resp.StatusCode))
			}
			return Receipt{}, fmt.Errorf("%w: HTTP %d carries no receipt", ErrInvalidReceipt, resp.StatusCode)
		}
		if r.Batch == nil {
			return Receipt{}, fmt.Errorf("%w: HTTP %d carries no receipt", ErrInvalidReceipt, resp.StatusCode)
		}
		receipt := Receipt{
			BatchID:         r.Batch.BatchID,
			Status:          r.Batch.Status,
			AcceptedRecords: r.Batch.AcceptedRecords,
			RejectedRecords: r.Batch.RejectedRecords,
			Replay:          r.Batch.Replay,
			ReceivedAt:      r.Batch.ReceivedAt,
			RecordErrors:    r.Batch.RecordErrors,
		}
		if err := validateReceipt(&receipt, batchID, recordCount); err != nil {
			return Receipt{}, err
		}
		return receipt, nil
	}
	if uerr := json.Unmarshal(body, &r); uerr != nil {
		// The body is not protocol JSON at all (a proxy page, a truncated
		// error body): no business code was stated, so a retryable status
		// keeps its transience.
		failure := fmt.Errorf("source-batch request failed: HTTP %d", resp.StatusCode)
		if classifyRetryable && retryableIngestStatus(resp.StatusCode) {
			return Receipt{}, markRetryableWithHeader(failure, resp.Header.Get("Retry-After"))
		}
		return Receipt{}, failure
	}
	code := ""
	if r.Error != nil {
		code = r.Error.Code
	}
	switch {
	case code == "stale_revision":
		return Receipt{}, ErrStaleRevision
	case code == "source_fence_changed":
		return Receipt{}, ErrFenceStale
	case code == "source_paused":
		return Receipt{}, ErrSourcePaused
	case code == "source_deleted":
		return Receipt{}, ErrSourceDeleted
	case code == "scope_changed":
		// The server's actual wire code for a stale consent revision
		// (it carries the authoritative currentConsentRevision).
		return Receipt{}, ErrConsentStale
	case code == "consent_revision_stale":
		// Defensive alias kept for forward compatibility.
		return Receipt{}, ErrConsentStale
	case resp.StatusCode == http.StatusUnauthorized:
		return Receipt{}, fmt.Errorf("%w (HTTP %d)", ErrDeviceUnauthorized, resp.StatusCode)
	case resp.StatusCode == http.StatusForbidden:
		return Receipt{}, fmt.Errorf("%w (HTTP %d)", ErrDeviceUnauthorized, resp.StatusCode)
	}
	// The server's free-text message is untrusted echo data and is
	// deliberately not included in the error; the business code is
	// rendered through displayCode so an unrecognized code — equally
	// untrusted server text — collapses to the fixed word "unknown"
	// instead of being reflected.
	failure := fmt.Errorf("source-batch request failed: HTTP %d code=%q", resp.StatusCode, displayCode(code))
	if classifyRetryable && retryableIngestStatus(resp.StatusCode) && retryableIngestCode(code) {
		// Business codes are final authority over the HTTP status: every
		// mapped terminal code already returned above, and an unknown
		// non-empty code is conservatively final. Only an absent or known
		// transient code on a retryable status is transient; the raw
		// Retry-After header rides along so the policy honors the
		// server's floor.
		return Receipt{}, markRetryableWithHeader(failure, resp.Header.Get("Retry-After"))
	}
	return Receipt{}, failure
}

// client clones the configured client into one that never follows
// redirects, so the Authorization header cannot leak to another host.
func client(opt Options) *http.Client {
	base := &http.Client{}
	if opt.HTTPClient != nil {
		*base = *opt.HTTPClient
	}
	if base.Timeout <= 0 || base.Timeout > 60*time.Second {
		base.Timeout = 15 * time.Second
	}
	base.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errRedirectRefused
	}
	return base
}

func joinURL(base, path string) (string, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		return "", errors.New("server URL is required")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path, nil
}
