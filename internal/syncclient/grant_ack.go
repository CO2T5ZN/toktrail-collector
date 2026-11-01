package syncclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"toktrail-collector/internal/local/statedir"
)

// Grant-ack protocol (server-confirmed):
//
//	POST /v1/devices/grant-ack   (device bearer credentials)
//	  {"consentRevision": N, "collectorVersion": "vX.Y.Z[-pre]"?,
//	   "applyState"?: "applied"|"pending",
//	   "supportedTools"?: ["Codex", ...],
//	   "pendingReasons"?: [{"tool": "Codex", "code": "missing_input"}, ...]}
//	  -> {"grantAck": {"consentRevision": N, "currentConsentRevision": M,
//	                   "collectorVersion"?: string, "ackedAt": time}}
//
// The ack is the device's "actually applied" receipt for a consent
// revision. Callers must only send it after the revision's grant scope has
// been fully applied locally, and must treat an echo mismatch as a failed
// ack. currentConsentRevision greater than the acked revision means the
// server has moved on; the caller should re-fetch and re-apply instead of
// reading under the stale revision.

// Closed pending-reason codes for the optional grant-ack
// pendingReasons field. The vocabulary is fixed by the coordination
// contract; senders must use exactly these codes and nothing else.
const (
	// PendingReasonUnsupportedTool marks an allowed tool this collector
	// version does not know (no compiled-in adapter).
	PendingReasonUnsupportedTool = "unsupported_tool"
	// PendingReasonMissingInput marks an allowed tool whose built-in
	// default input directory is absent (and no custom grant covers it).
	PendingReasonMissingInput = "missing_input"
	// PendingReasonDisabled marks an allowed tool whose default-directory
	// grant the user manually disabled.
	PendingReasonDisabled = "disabled"
)

// GrantAckPendingReason is one entry of the optional pendingReasons ack
// field: the allowed tool name plus a closed reason code. It deliberately
// carries no free text and never a local path.
type GrantAckPendingReason struct {
	Tool string `json:"tool"`
	Code string `json:"code"`
}

// GrantAckRequest is the grant-ack POST body. ApplyState reports whether
// the revision is fully applied ("applied", the default when omitted) or
// applied with restrictions ("pending": an allowed tool is unknown, its
// default directory is missing, or its grant is manually disabled). The
// server uses it to keep the device UI honest about the CURRENT state
// instead of an earlier full ack. CollectorVersion is optional and only
// included when it is a strict SemVer string (the build-injected "dev" or
// unknown values are omitted, never faked).
//
// SupportedTools is the optional capability report: the collector's
// currently registered tool names (canonical registry names only, never
// local paths). PendingReasons is the structured detail behind
// applyState, with three deliberately distinct wire states:
//
//   - nil (the zero value): the field is OMITTED — the restriction
//     reasons are unknown/not reportable (at least one restricted tool
//     has no closed reason code), and the server must not read the
//     payload as a complete reason receipt;
//   - non-nil with no entries: the explicit empty array [], a COMPLETE
//     report stating that nothing is restricted;
//   - non-nil with entries: the complete per-tool closed-code list.
//
// Use CompletePendingReasons to build the non-nil (complete) form. When
// either capability field is present the request carries the capability
// report. When neither is set the payload is byte-identical to the
// legacy shape. The body never contains local paths or any other
// sensitive information: tool names match a closed alphabet (see
// ackToolNameRegex) and reason codes come from a fixed vocabulary.
type GrantAckRequest struct {
	ConsentRevision  int64                    `json:"consentRevision"`
	ApplyState       string                   `json:"applyState,omitempty"`
	CollectorVersion string                   `json:"collectorVersion,omitempty"`
	SupportedTools   []string                 `json:"supportedTools,omitempty"`
	PendingReasons   *[]GrantAckPendingReason `json:"pendingReasons,omitempty"`
}

// CompletePendingReasons builds the COMPLETE pending-reasons form of the
// capability report: the given entries travel verbatim (an empty list
// serializes as the explicit "no reasons" array []). A nil
// GrantAckRequest.PendingReasons — the zero value — omits the field
// entirely, which the server reads as "reasons unknown".
func CompletePendingReasons(entries ...GrantAckPendingReason) *[]GrantAckPendingReason {
	out := make([]GrantAckPendingReason, len(entries))
	copy(out, entries)
	return &out
}

// carriesCapabilities reports whether the request includes the capability
// report (the optional supportedTools/pendingReasons fields an older
// server may reject). A capability-bearing request always has a
// non-empty supportedTools list.
func (r GrantAckRequest) carriesCapabilities() bool {
	return len(r.SupportedTools) > 0 || r.PendingReasons != nil
}

// MarshalJSON keeps the wire shapes unambiguous:
//
//	legacy:     {"consentRevision", "applyState"?, "collectorVersion"?}
//	unknown:    legacy + "supportedTools": [...] (reasons not reportable)
//	complete:   legacy + "supportedTools": [...] and "pendingReasons":
//	            [{"tool","code"}, ...] or [] (explicitly "no reasons")
//
// A complete report never omits pendingReasons (missing means "unknown"
// to the server), an unknown-reasons report never emits it, and a legacy
// request never emits either field, so the fallback payload is
// byte-identical to the pre-capability protocol.
func (r GrantAckRequest) MarshalJSON() ([]byte, error) {
	if !r.carriesCapabilities() {
		return json.Marshal(struct {
			ConsentRevision  int64  `json:"consentRevision"`
			ApplyState       string `json:"applyState,omitempty"`
			CollectorVersion string `json:"collectorVersion,omitempty"`
		}{r.ConsentRevision, r.ApplyState, r.CollectorVersion})
	}
	supported := r.SupportedTools
	if supported == nil {
		supported = []string{}
	}
	if r.PendingReasons == nil {
		// Unknown reasons: the supported-tools report still travels,
		// but pendingReasons must stay absent so the server never
		// mistakes the payload for a complete reason receipt.
		return json.Marshal(struct {
			ConsentRevision  int64    `json:"consentRevision"`
			ApplyState       string   `json:"applyState,omitempty"`
			CollectorVersion string   `json:"collectorVersion,omitempty"`
			SupportedTools   []string `json:"supportedTools"`
		}{r.ConsentRevision, r.ApplyState, r.CollectorVersion, supported})
	}
	return json.Marshal(struct {
		ConsentRevision  int64                   `json:"consentRevision"`
		ApplyState       string                  `json:"applyState,omitempty"`
		CollectorVersion string                  `json:"collectorVersion,omitempty"`
		SupportedTools   []string                `json:"supportedTools"`
		PendingReasons   []GrantAckPendingReason `json:"pendingReasons"`
	}{r.ConsentRevision, r.ApplyState, r.CollectorVersion, supported, *r.PendingReasons})
}

// GrantAck is the server's receipt for one acknowledged revision.
type GrantAck struct {
	ConsentRevision        int64 `json:"consentRevision"`
	CurrentConsentRevision int64 `json:"currentConsentRevision"`
	// AckedState is the server's echo of the acknowledged state under the
	// receipt field name "ackedState" (the REQUEST field is applyState).
	// An absent field is backward-compatible with "applied" only; a
	// pending request never counts as confirmed by an absent echo.
	AckedState       string    `json:"ackedState,omitempty"`
	CollectorVersion string    `json:"collectorVersion,omitempty"`
	AckedAt          time.Time `json:"ackedAt"`
}

type grantAckResponse struct {
	GrantAck *GrantAck `json:"grantAck,omitempty"`
	Error    *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Ack error sentinels. ErrAckRevisionAdvanced means the server moved past
// the acked revision (409 scope_changed or a future-revision echo): the
// applied view may be stale and callers must re-fetch instead of reading
// under it. ErrAckEchoMismatch means the server confirmed an unexpected
// revision or state: the ack bookkeeping is unclear and callers should
// conservatively stop. ErrAckUnknownFields means the server rejected the
// request payload (HTTP 400/422) while it carried the optional
// supportedTools/pendingReasons capability fields — the signature of an
// older server that refuses unknown JSON fields; the caller may retry
// once with the legacy payload shape, and must never record the
// capability fields as reported on that fallback. Transport-level
// failures carry neither sentinel — the freshly fetched view remains this
// run's authorization and only the receipt is missing.
var (
	ErrAckRevisionAdvanced = errors.New("grant_ack_revision_advanced")
	ErrAckEchoMismatch     = errors.New("grant_ack_echo_mismatch")
	ErrAckUnknownFields    = errors.New("grant_ack_unknown_fields")
)

// maxCollectorVersionLen bounds the optional collector version echo.
const maxCollectorVersionLen = 64

// Capability-field bounds mirror the grant-view limit
// (managedconsent.MaxAllowedTools) so a view that passed validation can
// always be acked with its capabilities. Tool-name length is enforced by
// ackToolNameRegex (max 64 characters).
const maxAckCapabilityEntries = 64

// strictSemVerRegex matches exactly vX.Y.Z with an optional SemVer
// prerelease; "dev", empty, and other non-release identifiers are rejected
// so the ack never claims a release version the build cannot prove.
var strictSemVerRegex = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

// ValidCollectorVersion reports whether v is a strict SemVer release string
// suitable for the optional ack field.
func ValidCollectorVersion(v string) bool {
	v = strings.TrimSpace(v)
	return v != "" && len(v) <= maxCollectorVersionLen && strictSemVerRegex.MatchString(v)
}

// ackToolNameRegex is the closed tool-name alphabet shared with the
// release and server contracts: one leading alphanumeric character, then
// up to 63 alphanumeric, space, dot, underscore, plus, or hyphen
// characters. Path separators, colons, and quotes are impossible by
// construction, so no local path can ever travel in a tool or reason
// field.
var ackToolNameRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,63}$`)

// validateAckCapabilities checks the optional capability fields before
// any network traffic: a capability-bearing request must name a
// non-empty supportedTools list, every tool name (in both fields) must
// match the closed tool-name alphabet exactly once, and every
// pendingReasons entry must carry a code from the closed vocabulary
// (unsupported_tool/missing_input/disabled). Anything else fails the
// request locally so a malformed or path-bearing capability report is
// never sent.
func validateAckCapabilities(req GrantAckRequest) error {
	if !req.carriesCapabilities() {
		return nil
	}
	if len(req.SupportedTools) == 0 {
		return errors.New("grant ack capability report requires a non-empty supportedTools list")
	}
	if len(req.SupportedTools) > maxAckCapabilityEntries {
		return fmt.Errorf("grant ack supportedTools lists %d tools, exceeds limit %d", len(req.SupportedTools), maxAckCapabilityEntries)
	}
	seenTools := make(map[string]bool, len(req.SupportedTools))
	for i, tool := range req.SupportedTools {
		if !ackToolNameRegex.MatchString(tool) {
			return fmt.Errorf("grant ack supportedTools entry %d (%q) must match the tool-name alphabet ^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,63}$", i, tool)
		}
		if seenTools[tool] {
			return fmt.Errorf("grant ack supportedTools lists tool %q more than once", tool)
		}
		seenTools[tool] = true
	}
	if req.PendingReasons != nil {
		pending := *req.PendingReasons
		if len(pending) > maxAckCapabilityEntries {
			return fmt.Errorf("grant ack pendingReasons lists %d entries, exceeds limit %d", len(pending), maxAckCapabilityEntries)
		}
		seenPending := make(map[string]bool, len(pending))
		for i, pr := range pending {
			if !ackToolNameRegex.MatchString(pr.Tool) {
				return fmt.Errorf("grant ack pendingReasons entry %d tool (%q) must match the tool-name alphabet ^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,63}$", i, pr.Tool)
			}
			if seenPending[pr.Tool] {
				return fmt.Errorf("grant ack pendingReasons lists tool %q more than once", pr.Tool)
			}
			seenPending[pr.Tool] = true
			switch pr.Code {
			case PendingReasonUnsupportedTool, PendingReasonMissingInput, PendingReasonDisabled:
			default:
				return fmt.Errorf("grant ack pendingReasons entry %d has code %q outside the closed set (unsupported_tool, missing_input, disabled)", i, pr.Code)
			}
		}
	}
	return nil
}

// ReportGrantAck acknowledges that the device applied the given consent
// revision. The server must echo the same revision in grantAck.consentRevision;
// anything else is a failed ack (an old revision's ack must never stand in
// for a newer one). A nil GrantAck result with a nil error never happens:
// either the ack is confirmed or an error explains why it was not.
func ReportGrantAck(ctx context.Context, store statedir.Store, opt Options, req GrantAckRequest) (GrantAck, error) {
	if req.ConsentRevision <= 0 {
		return GrantAck{}, fmt.Errorf("grant ack requires a positive consentRevision, got %d", req.ConsentRevision)
	}
	switch req.ApplyState {
	case "", "applied", "pending":
	default:
		return GrantAck{}, fmt.Errorf("grant ack applyState must be \"applied\" or \"pending\", got %q", req.ApplyState)
	}
	if req.CollectorVersion != "" && !ValidCollectorVersion(req.CollectorVersion) {
		return GrantAck{}, errors.New("grant ack collectorVersion must be a strict semver release string or omitted")
	}
	if err := validateAckCapabilities(req); err != nil {
		return GrantAck{}, err
	}
	st, err := store.Load()
	if err != nil {
		return GrantAck{}, err
	}
	if st.DeviceID == "" || st.DeviceSecret == "" {
		return GrantAck{}, errors.New("device is not bound; run toktrail bind first")
	}
	serverURL := strings.TrimSpace(opt.ServerURL)
	if serverURL == "" {
		serverURL = st.ServerURL
	}
	if serverURL == "" {
		return GrantAck{}, errors.New("server URL is required")
	}
	client := noRedirectClient(opt.HTTPClient)
	endpoint, err := joinURL(serverURL, "/v1/devices/grant-ack")
	if err != nil {
		return GrantAck{}, err
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return GrantAck{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return GrantAck{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+st.DeviceID+"."+st.DeviceSecret)
	resp, err := client.Do(httpReq)
	if err != nil {
		// Raw transport text never reaches a human message; the cause
		// stays matchable through Unwrap.
		return GrantAck{}, wrapTransportError("grant ack failed", err)
	}
	defer resp.Body.Close()
	var body grantAckResponse
	if err := json.NewDecoder(capResponseBody(resp.Body)).Decode(&body); err != nil {
		if errors.Is(err, errResponseBodyTooLarge) {
			return GrantAck{}, fmt.Errorf("grant ack failed: status %d: response body exceeded the %d MiB safety limit", resp.StatusCode, maxResponseBodyBytes>>20)
		}
		return GrantAck{}, fmt.Errorf("grant ack failed: status %d: %w", resp.StatusCode, safeDecodeErrorOf(err))
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			return GrantAck{}, fmt.Errorf("grant ack endpoint not available (HTTP %d); the ack will be retried on the next run", resp.StatusCode)
		}
		code := ""
		if body.Error != nil {
			code = body.Error.Code
		}
		if resp.StatusCode == http.StatusConflict && code == "scope_changed" {
			return GrantAck{}, fmt.Errorf("%w: the server's consent revision moved past %d before the ack; the applied view may be stale", ErrAckRevisionAdvanced, req.ConsentRevision)
		}
		// Unknown-field rejection: an older server may validate the ack
		// body against a closed schema and refuse the optional
		// capability fields. Only validation-class statuses (400/422)
		// on a payload that actually carried those fields map to the
		// sentinel — authentication failures (401/403), scope changes
		// (409), and a missing endpoint (404/405) keep their own
		// classification and never take this path. The sentinel licenses
		// exactly one explicit legacy-shape retry by the caller; a
		// payload without the capability fields never produces it. The
		// server's code/message text is never echoed into the sentinel's
		// description.
		if (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnprocessableEntity) && req.carriesCapabilities() {
			return GrantAck{}, fmt.Errorf("%w: HTTP %d while the payload carried the optional supportedTools/pendingReasons fields; an older server may reject unknown fields, retrying once with the legacy payload is safe", ErrAckUnknownFields, resp.StatusCode)
		}
		return GrantAck{}, classifyIngestError(resp.StatusCode, code)
	}
	if body.GrantAck == nil {
		return GrantAck{}, errors.New("grant ack response missing grantAck")
	}
	if body.GrantAck.ConsentRevision > req.ConsentRevision {
		return GrantAck{}, fmt.Errorf("%w: the server confirmed revision %d while %d was acked; the applied view may be stale", ErrAckRevisionAdvanced, body.GrantAck.ConsentRevision, req.ConsentRevision)
	}
	if body.GrantAck.ConsentRevision != req.ConsentRevision {
		return GrantAck{}, fmt.Errorf("%w: acked %d but server confirmed %d; the ack is not recorded and the revision state is unclear", ErrAckEchoMismatch, req.ConsentRevision, body.GrantAck.ConsentRevision)
	}
	requested := req.ApplyState
	if requested == "" {
		requested = "applied"
	}
	echoed := body.GrantAck.AckedState
	if echoed == "" {
		echoed = "applied"
	}
	if echoed != requested {
		// The echoed state is untrusted server text and is never echoed
		// back into the message.
		return GrantAck{}, fmt.Errorf("%w: requested state %q but the server confirmed a different state; the ack is not recorded and the state is unclear", ErrAckEchoMismatch, requested)
	}
	return *body.GrantAck, nil
}
