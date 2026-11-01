package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Session carries the WorkosCursorSessionToken cookie value used to
// authenticate against Cursor's personal-account dashboard API.
//
// The cookie value format, verified in tokscale's
// session_token_from_access_token, is "{user_id}%3A%3A{access_token}"
// ("%3A%3A" is URL-encoded "::"); a literal "::" separator is tolerated.
// The user id embedded before the separator is a real high-entropy account
// identity ("user_…", also present in the access token JWT "sub" claim as
// e.g. "auth0|user_…"); it is stable across token rotation. Account
// identity matching itself lives in internal/cursor/identity, not here.
//
// The token is a credential: it never serializes to JSON and renders
// redacted through String/GoString.
type Session struct {
	// Token is the raw WorkosCursorSessionToken cookie value.
	Token string `json:"-"`
}

// String renders the session with the token redacted.
func (s Session) String() string {
	if s.Token == "" {
		return "api.Session{}"
	}
	return "api.Session{Token:[REDACTED]}"
}

// GoString renders the session with the token redacted.
func (s Session) GoString() string {
	return s.String()
}

// UsageEvent is one row of the usageEventsDisplay array.
//
// Rows sharing a UsageEventID are successive snapshots of ONE billable
// event, reported with running token totals: summing them counts the event
// many times over. FetchUsageEvents returns every snapshot as-is; use
// CollapseSnapshots to resolve duplicates within one response, and replace
// (never max-merge) stored events across successful pulls so server-side
// downward corrections apply.
//
// Data-minimization contract (TokTrail v1): the raw row, cost fields
// (chargedCents / tokenUsage.totalCents), and every unknown field are
// intentionally NOT retained; ConversationID is retained only to derive the
// fallback identity for snapshot collapse. Token counts are strict: an
// absent count stays nil (unknown), and a negative, fractional, or
// out-of-int64 value fails parsing instead of being coerced.
type UsageEvent struct {
	// UsageEventID is the event's own stable id. Empty when the row carries
	// none (legacy rows written before Cursor added the id).
	UsageEventID string
	// ConversationID is the Cursor session UUID that produced the event.
	// Retained only to derive the collapse fallback identity; not uploaded.
	ConversationID string
	// TimestampMS is the event's Unix timestamp in milliseconds. Cursor
	// sends it as a string; numbers and RFC 3339 strings are accepted.
	TimestampMS int64
	// Model is the model id, trimmed, required.
	Model string
	// Token counts; nil means the row did not carry the count.
	InputTokens      *int64
	OutputTokens     *int64
	CacheReadTokens  *int64
	CacheWriteTokens *int64
}

// TokenTotal returns the sum of the token counts. ok is false when any
// component is unknown or the sum overflows int64; it never coerces an
// unknown component to zero.
func (e *UsageEvent) TokenTotal() (total int64, ok bool) {
	if e.InputTokens == nil || e.OutputTokens == nil || e.CacheReadTokens == nil || e.CacheWriteTokens == nil {
		return 0, false
	}
	total = *e.InputTokens + *e.OutputTokens + *e.CacheReadTokens + *e.CacheWriteTokens
	// Every component is a non-negative strict int64, so a wrapped or
	// smaller-than-component sum can only be overflow.
	if total < 0 || total < *e.InputTokens || total < *e.OutputTokens || total < *e.CacheReadTokens || total < *e.CacheWriteTokens {
		return 0, false
	}
	return total, true
}

// UsageEvents is the result of one completed usage-events walk.
type UsageEvents struct {
	// Events holds every snapshot of every event the walk collected, in
	// arrival order, NOT summed and NOT collapsed. Aggregate only after
	// collapsing snapshots per UsageEventID.
	Events []UsageEvent
	// TotalUsageEventsCount is the server-advertised total, captured from
	// the first page that reports it. HasTotalCount is false when the server
	// never reported one.
	TotalUsageEventsCount int64
	HasTotalCount         bool
	// PagesFetched is the number of pages the walk requested.
	PagesFetched int
	// BytesRead is the cumulative response-body size across every page,
	// counted against the client's byte ceiling.
	BytesRead int
	// StartDateMS and EndDateMS are the window the walk requested.
	StartDateMS int64
	EndDateMS   int64
}

// UsageSummary is the verified subset of the GET /api/usage-summary
// response. tokscale's validate_cursor_session treats the presence of
// billingCycleStart and billingCycleEnd strings as proof the session token
// is valid, and surfaces membershipType when present. The endpoint is a
// session-validity check; tokscale reads no user-identity fields from it,
// and no user endpoint is used anywhere in the reference implementation.
// Nothing beyond these fields is retained.
type UsageSummary struct {
	MembershipType    string
	BillingCycleStart string
	BillingCycleEnd   string
}

// ParseUsageEvent decodes one usageEventsDisplay row strictly.
//
// Both the object form and the positional (JSON array) form are accepted;
// the positional order conversationId, timestamp, model, chargedCents,
// tokenUsage is a contract in the reference parser. Cost fields exist on
// the wire but are not modeled in v1.
//
// Error, never coercion: a row that is not an object/array, a missing or
// empty model, a missing/invalid timestamp, a non-string id field, a
// non-object tokenUsage, or a token count that is negative, fractional, or
// outside int64 returns an error. The reference skips malformed rows
// leniently; TokTrail fails the fetch instead so corrupt data is never
// silently dropped or zeroed. An absent token count stays nil (unknown).
// Error messages carry fixed field names and categories only: they never
// echo the row, a field value, or a preview of either — response content
// is untrusted and must not travel into logs or stderr through errors.
func ParseUsageEvent(raw json.RawMessage) (UsageEvent, error) {
	var e UsageEvent
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return e, errors.New("cursor api: event row is empty")
	}

	if trimmed[0] == '{' {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
			return e, errors.New("cursor api: event row is not a JSON object")
		}
		conversation, err := strictString("conversationId", obj["conversationId"])
		if err != nil {
			return e, err
		}
		timestamp, err := strictTimestampMS(obj["timestamp"])
		if err != nil {
			return e, err
		}
		model, err := strictString("model", obj["model"])
		if err != nil {
			return e, err
		}
		if model == "" {
			return e, errors.New("cursor api: model is required")
		}
		usageEventID, err := strictString("usageEventId", obj["usageEventId"])
		if err != nil {
			return e, err
		}
		counts, err := strictTokenCounts(obj["tokenUsage"])
		if err != nil {
			return e, err
		}
		e.ConversationID = conversation
		e.TimestampMS = timestamp
		e.Model = model
		e.UsageEventID = usageEventID
		e.InputTokens, e.OutputTokens, e.CacheReadTokens, e.CacheWriteTokens = counts[0], counts[1], counts[2], counts[3]
		return e, nil
	}

	if trimmed[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			return e, errors.New("cursor api: event row is not a JSON array")
		}
		if len(arr) < 3 {
			return e, errors.New("cursor api: positional event row needs conversationId, timestamp, and model")
		}
		conversation, err := strictString("conversationId", arr[0])
		if err != nil {
			return e, err
		}
		timestamp, err := strictTimestampMS(arr[1])
		if err != nil {
			return e, err
		}
		model, err := strictString("model", arr[2])
		if err != nil {
			return e, err
		}
		if model == "" {
			return e, errors.New("cursor api: model is required")
		}
		// arr[3] is chargedCents: present on the wire, not modeled in v1.
		var counts [4]*int64
		if len(arr) > 4 {
			counts, err = strictTokenCounts(arr[4])
			if err != nil {
				return e, err
			}
		}
		e.ConversationID = conversation
		e.TimestampMS = timestamp
		e.Model = model
		e.InputTokens, e.OutputTokens, e.CacheReadTokens, e.CacheWriteTokens = counts[0], counts[1], counts[2], counts[3]
		return e, nil
	}

	return e, errors.New("cursor api: event row must be a JSON object or array")
}

// strictTokenCounts reads the four modeled token counts from a tokenUsage
// value. Absent or null yields nil counts; invalid values error. Cost
// fields inside tokenUsage are ignored (not modeled in v1).
func strictTokenCounts(raw json.RawMessage) ([4]*int64, error) {
	var counts [4]*int64
	if len(raw) == 0 || string(raw) == "null" {
		return counts, nil
	}
	var tu map[string]json.RawMessage
	if err := json.Unmarshal(raw, &tu); err != nil || tu == nil {
		return counts, errors.New("cursor api: tokenUsage must be an object")
	}
	fields := []struct {
		name string
		raw  json.RawMessage
		dst  **int64
	}{
		{"tokenUsage.inputTokens", tu["inputTokens"], &counts[0]},
		{"tokenUsage.outputTokens", tu["outputTokens"], &counts[1]},
		{"tokenUsage.cacheReadTokens", tu["cacheReadTokens"], &counts[2]},
		{"tokenUsage.cacheWriteTokens", tu["cacheWriteTokens"], &counts[3]},
	}
	for _, f := range fields {
		v, err := strictTokenCount(f.name, f.raw)
		if err != nil {
			return counts, err
		}
		*f.dst = v
	}
	return counts, nil
}

// strictTokenCount decodes one token count: absent/null → nil; an integer
// number or integer string → its value; anything else (wrong type,
// fraction, negative, overflow) → an error.
//
// Error privacy: the message carries only the fixed field name and the
// problem category. The raw JSON fragment and the offending string value
// are never echoed — a malicious or compromised response can plant the
// session token or conversation text in any field, and those values must
// not travel into logs or stderr through the error. No preview and no
// truncation either: a truncated secret is still a secret.
func strictTokenCount(field string, raw json.RawMessage) (*int64, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var n int64
	switch raw[0] {
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("cursor api: %s must be a string or integer", field)
		}
		v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("cursor api: %s must be an integer", field)
		}
		n = v
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		var num json.Number
		if err := json.Unmarshal(raw, &num); err != nil {
			return nil, fmt.Errorf("cursor api: %s must be a string or integer", field)
		}
		v, err := strconv.ParseInt(num.String(), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("cursor api: %s must be an integer within int64", field)
		}
		n = v
	default:
		return nil, fmt.Errorf("cursor api: %s must be a string or integer", field)
	}
	if n < 0 {
		return nil, fmt.Errorf("cursor api: %s must not be negative", field)
	}
	return &n, nil
}

// strictTimestampMS decodes the required event timestamp: Unix
// milliseconds as an integer string or number, or an RFC 3339 string.
// Missing, non-positive, fractional, or overflowing values error.
//
// Error privacy: same contract as strictTokenCount — fixed field name
// and category only, never the raw fragment or the offending string
// (which is untrusted response text).
func strictTimestampMS(raw json.RawMessage) (int64, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, errors.New("cursor api: timestamp is required")
	}
	var n int64
	switch raw[0] {
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return 0, errors.New("cursor api: timestamp must be a string or integer")
		}
		s = strings.TrimSpace(s)
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			t, terr := time.Parse(time.RFC3339, s)
			if terr != nil {
				return 0, errors.New("cursor api: timestamp must be Unix milliseconds or RFC 3339")
			}
			v = t.UnixMilli()
		}
		n = v
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		var num json.Number
		if err := json.Unmarshal(raw, &num); err != nil {
			return 0, errors.New("cursor api: timestamp must be an integer")
		}
		v, err := strconv.ParseInt(num.String(), 10, 64)
		if err != nil {
			return 0, errors.New("cursor api: timestamp must be an integer within int64")
		}
		n = v
	default:
		return 0, errors.New("cursor api: timestamp must be a string or integer")
	}
	if n <= 0 {
		return 0, errors.New("cursor api: timestamp must be positive")
	}
	return n, nil
}

// strictString decodes a string field: absent or null yields "", a present
// non-string is an error. The result is trimmed. The error carries only
// the fixed field name and category — never the raw fragment, which is
// untrusted response text.
func strictString(field string, raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("cursor api: %s must be a string", field)
	}
	return strings.TrimSpace(s), nil
}
