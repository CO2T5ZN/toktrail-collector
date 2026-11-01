// Package accountsource talks to the TokTrail server account-source
// control endpoint: the old-server capability gate (RequireCapability —
// CLI enable must detect unsupported servers itself, not rely on website
// gating) and the device-authenticated enable call that creates the
// cursor source instance and CAS-binds this device as its executor (the
// server only binds when the executor slot is empty — it never takes
// over an existing executor, and neither does the collector).
package accountsource

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"toktrail-collector/internal/cursor/protocol"
)

// ErrExecutorConflict: another device already collects this account source.
// Resolution is a website-side reassignment; the collector never claims a
// taken executor slot.
var ErrExecutorConflict = errors.New("another device is the executor of this cursor account source")

// ErrMirroredCredential: the enable response carried the device
// credential inside a source field. A hostile or compromised server can
// reflect the Authorization bearer value into any string it returns;
// persisting or rendering such a field would leak the long-lived device
// secret through the permit file and every later status output. The
// source is refused wholesale, nothing is persisted, and the fixed
// message never echoes the field or the credential.
var ErrMirroredCredential = errors.New("account-source enable response mirrors the device credential in a source field; the source was refused and nothing was persisted")

// errRedirectRefused is the cloned client's no-redirect policy error. A
// redirect answer is a deliberate local security refusal (the device
// Authorization header must never travel to another host), not a
// network failure.
var errRedirectRefused = errors.New("redirects are not allowed")

const maxResponseBytes = 1 << 20

// Options configures the enable request.
type Options struct {
	ServerURL  string
	HTTPClient *http.Client
	// DeviceID/DeviceSecret are the existing bound-device credentials.
	DeviceID, DeviceSecret string
	// ConsentRevision is the live device consent revision echoed as
	// X-Consent-Revision.
	ConsentRevision int64
}

type enableResponse struct {
	Source *protocol.Source `json:"source,omitempty"`
	// Error.Message is parsed for shape compatibility only: it is
	// untrusted server free text and is never echoed into errors.
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Enable asks the server to create (or CAS-bind, executor slot empty) the
// account source of sourceType for the authenticated device. The response
// carries the authoritative source metadata: sourceInstanceId, state,
// fenceVersion and nextRevision (subject+sourceType MAX alive revision +
// 1, continued across source recreation, reset to 1 only by deleteData).
func Enable(ctx context.Context, opt Options, sourceType string) (protocol.Source, error) {
	endpoint, err := joinURL(opt.ServerURL, "/v1/account-sources/enable")
	if err != nil {
		return protocol.Source{}, err
	}
	payload, err := json.Marshal(struct {
		SourceType string `json:"sourceType"`
	}{SourceType: sourceType})
	if err != nil {
		return protocol.Source{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return protocol.Source{}, wrapTransportError("account-source enable request could not be built", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+opt.DeviceID+"."+opt.DeviceSecret)
	req.Header.Set("X-Consent-Revision", strconv.FormatInt(opt.ConsentRevision, 10))
	resp, err := client(opt).Do(req)
	if err != nil {
		return protocol.Source{}, wrapTransportError("account-source enable request failed on the transport", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return protocol.Source{}, wrapTransportError("account-source enable response could not be read", err)
	}
	if len(body) > maxResponseBytes {
		return protocol.Source{}, errors.New("account-source response exceeds 1 MB limit")
	}
	var r enableResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return protocol.Source{}, fmt.Errorf("invalid account-source response HTTP %d", resp.StatusCode)
	}
	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated:
		if r.Source == nil || strings.TrimSpace(r.Source.SourceInstanceID) == "" {
			return protocol.Source{}, fmt.Errorf("account-source response HTTP %d carries no source", resp.StatusCode)
		}
		// Trust boundary: the response rides the device credential this
		// request presented, and every source string the caller persists
		// or renders must be proven free of it before it is accepted.
		if err := refuseMirroredCredential(*r.Source, opt.DeviceSecret); err != nil {
			return protocol.Source{}, err
		}
		return *r.Source, nil
	case resp.StatusCode == http.StatusConflict:
		return protocol.Source{}, ErrExecutorConflict
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return protocol.Source{}, fmt.Errorf("account-source enable rejected: HTTP %d code=%q", resp.StatusCode, displayCode(errorCode(r)))
	}
	// The server's free-text message is untrusted echo data and is
	// deliberately not included in the error; the business code renders
	// through displayCode so an unrecognized code — equally untrusted
	// server text — collapses to the fixed word "unknown".
	return protocol.Source{}, fmt.Errorf("account-source enable failed: HTTP %d code=%q", resp.StatusCode, displayCode(errorCode(r)))
}

// refuseMirroredCredential rejects a returned Source whose string fields
// contain the current device secret — the exact value this request's
// Authorization header carried, matched case-insensitively because the
// secret is hex-shaped and a reflection may vary its case. A label or
// character-class check would not do: the secret itself is a perfectly
// valid label, so only matching the actual credential catches it. Every
// string field of the wire struct is checked (the numeric fields cannot
// carry text); a refusal keeps the whole source out of the caller, so
// nothing mirrored is ever persisted or rendered.
func refuseMirroredCredential(src protocol.Source, deviceSecret string) error {
	if deviceSecret == "" {
		return nil
	}
	needle := strings.ToLower(deviceSecret)
	for _, field := range []string{src.SourceInstanceID, src.SourceType, src.State} {
		if strings.Contains(strings.ToLower(field), needle) {
			return ErrMirroredCredential
		}
	}
	return nil
}

// errorCode extracts the server-stated business code ("" when the
// envelope carries none).
func errorCode(r enableResponse) string {
	if r.Error == nil {
		return ""
	}
	return r.Error.Code
}

// displayCode renders a server-stated business code for an error
// message. Only the fixed codes this repository's protocol handling and
// test doubles use for the account-source control endpoints keep their
// name; every other non-empty code is untrusted server-controlled text
// (it could reflect a credential or response content) and collapses to
// the fixed word "unknown". The empty code (the server stated none)
// stays empty. No logic keys on the code here — only the rendered
// message is sanitized.
func displayCode(code string) string {
	switch strings.TrimSpace(code) {
	case "":
		return ""
	case "not_found", "unauthorized", "device_revoked",
		"internal_error", "service_unavailable", "store_unavailable":
		return strings.TrimSpace(code)
	default:
		return "unknown"
	}
}

// CapabilityAccountSources is the server capability feature gating the
// account-level source protocol (enable + source-batch ingest).
const CapabilityAccountSources = "account-sources"

// maxCapabilityBytes bounds the capabilities document: it is a small
// feature list, never a data payload.
const maxCapabilityBytes = 64 << 10

// RequireCapability verifies the server speaks the account-sources
// protocol BEFORE the collector reads the Cursor desktop credential: GET
// /v1/capabilities must answer 200 with a features list containing
// "account-sources". Old servers answer 404 or omit the feature and can
// never store cursor records, so callers stop instead of pointlessly
// reading (and live-verifying) the desktop login against them. The probe
// is fail-closed on every unverifiable outcome (non-200, malformed or
// oversized document, transport error, timeout), never follows redirects
// (the Authorization header cannot leak to another host), and attaches no
// Cursor credential — only the device credentials, when present.
func RequireCapability(ctx context.Context, opt Options) error {
	endpoint, err := joinURL(opt.ServerURL, "/v1/capabilities")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return wrapTransportError("account-source capabilities request could not be built", err)
	}
	req.Header.Set("Accept", "application/json")
	if opt.DeviceID != "" && opt.DeviceSecret != "" {
		req.Header.Set("Authorization", "Bearer "+opt.DeviceID+"."+opt.DeviceSecret)
	}
	resp, err := client(opt).Do(req)
	if err != nil {
		return wrapTransportError("account-source capabilities request failed on the transport", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCapabilityBytes+1))
	if err != nil {
		return wrapTransportError("account-source capabilities response could not be read", err)
	}
	if len(body) > maxCapabilityBytes {
		return errors.New("account-source capabilities response exceeds size limit")
	}
	var caps struct {
		Features []string `json:"features"`
		Error    *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}
	if err := json.Unmarshal(body, &caps); err != nil {
		return fmt.Errorf("invalid account-source capabilities response HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		code := ""
		if caps.Error != nil {
			code = caps.Error.Code
		}
		return fmt.Errorf("account-source capabilities check failed: HTTP %d code=%q", resp.StatusCode, displayCode(code))
	}
	for _, f := range caps.Features {
		if strings.TrimSpace(f) == CapabilityAccountSources {
			return nil
		}
	}
	return fmt.Errorf("server does not support %s (feature missing from /v1/capabilities)", CapabilityAccountSources)
}

// client clones the configured client into one that never follows
// redirects and always carries a bounded timeout, so the device
// Authorization header cannot leak to another host and a hung server
// cannot stall an enable or capability probe.
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

// transportError renders a fixed, human-safe message for a transport
// failure while keeping the original cause reachable through Unwrap, so
// every errors.Is / errors.As contract of the wrapped error survives:
// context cancellation and deadlines, net.Error shapes and the redirect
// refusal all keep matching exactly as on the unredacted error. Go's
// formatting never renders an error's chain — fmt's %v/%+v, the log
// package and %w-wrapping print only Error() — so the cause's raw text
// (which embeds the full request URL and therefore anything a hostile
// server placed into a refused redirect's Location header, such as the
// device secret from the Authorization bearer value) never reaches a
// human message.
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
