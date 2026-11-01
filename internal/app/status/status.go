package status

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"toktrail-collector/internal/local/statedir"
)

type Options struct {
	ServerURL  string
	HTTPClient *http.Client
}

type Result struct {
	State statedir.DeviceState
}

type selfDevice struct {
	DeviceID          string    `json:"deviceId"`
	ApplicationID     string    `json:"applicationId"`
	ExternalSubjectID string    `json:"externalSubjectId"`
	DeviceName        string    `json:"deviceName"`
	Platform          string    `json:"platform"`
	ConsentRevision   int64     `json:"consentRevision"`
	UploadAuthorized  bool      `json:"uploadAuthorized"`
	PublicAuthorized  bool      `json:"publicAuthorized"`
	Revoked           bool      `json:"revoked"`
	CheckedAt         time.Time `json:"checkedAt"`
}

type selfResponse struct {
	Device selfDevice `json:"device"`
	Error  *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Run refreshes the bound device's authorization snapshot via
// GET /v1/devices/self and persists it. It is a QUERY over the bound
// device: the response may only update authorization facts about the
// SAME device (same device ID, same application/subject identity), and
// a temporary --server override selects where the query is sent without
// ever rebinding the device to that server.
//
// Security boundary (fail closed, zero state change on any anomaly):
//
//   - Redirects are refused on a shallow CLONE of the caller's client,
//     so the credential-bearing GET can never be aimed at a second URL
//     by a 3xx answer, and the caller's client object is never modified.
//   - The response body is read through a bounded reader; oversized
//     bodies are identified without recording any content.
//   - Every surfaced error text is fixed wording derived from error
//     identity or the numeric HTTP status — never server free text
//     (codes, messages, JSON fragments) and never credential material.
//     The sanitized wrappers keep their causes reachable through
//     Unwrap, so errors.Is/errors.As still match context cancellation,
//     deadlines, EOF, and the redirect refusal.
//   - A 200 response must name exactly the bound device ID, must not
//     reflect the device secret into any string that would be
//     persisted, and must not contradict an already-bound application
//     or subject identity (empty local fields may be backfilled).
//     Any violation — like every other failure — returns before
//     store.Save, leaving the persisted state byte-for-byte unchanged.
//
// Legitimate responses, including a revoked=true snapshot, keep the
// historical update behavior; the device secret itself is never written
// from response data.
func Run(ctx context.Context, store statedir.Store, opt Options) (Result, error) {
	st, err := store.Load()
	if err != nil {
		return Result{}, err
	}
	if st.DeviceID == "" || st.DeviceSecret == "" {
		return Result{}, errors.New("device is not bound; run toktrail bind first")
	}
	serverURL := strings.TrimSpace(opt.ServerURL)
	if serverURL == "" {
		serverURL = st.ServerURL
	}
	if serverURL == "" {
		serverURL = "http://127.0.0.1:3211"
	}
	endpoint, err := joinURL(serverURL, "/v1/devices/self")
	if err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Authorization", "Bearer "+st.DeviceID+"."+st.DeviceSecret)
	resp, err := noRedirectClient(opt.HTTPClient).Do(req)
	if err != nil {
		// The raw transport error (endpoint, runtime detail) never
		// reaches a human message; the cause stays matchable through
		// Unwrap.
		return Result{}, wrapTransportError("status request failed", err)
	}
	defer resp.Body.Close()
	var body selfResponse
	if err := json.NewDecoder(capResponseBody(resp.Body)).Decode(&body); err != nil {
		if errors.Is(err, errResponseBodyTooLarge) {
			return Result{}, fmt.Errorf("%w: the status response needed more than the %d MiB cap to complete its first JSON value (HTTP %d)", errResponseBodyTooLarge, maxResponseBodyBytes>>20, resp.StatusCode)
		}
		return Result{}, fmt.Errorf("status failed: response body was not decodable (HTTP %d): %w", resp.StatusCode, safeDecodeErrorOf(err))
	}
	if resp.StatusCode != http.StatusOK {
		code := ""
		if body.Error != nil {
			code = body.Error.Code
		}
		// The server's code is untrusted free text used only for a
		// closed-set lookup; the message is never read for display.
		// Unknown codes collapse to fixed "(server error code: other)"
		// wording and are never echoed.
		switch code {
		case "device_revoked":
			return Result{}, fmt.Errorf("status failed: the server revoked this device (HTTP %d)", resp.StatusCode)
		case "subject_deleted":
			return Result{}, fmt.Errorf("status failed: the server deleted the subject (HTTP %d)", resp.StatusCode)
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return Result{}, fmt.Errorf("status failed: the server rejected the device credentials (HTTP %d)", resp.StatusCode)
		}
		if code != "" {
			return Result{}, fmt.Errorf("status failed: status %d (server error code: other)", resp.StatusCode)
		}
		return Result{}, fmt.Errorf("status failed: status %d", resp.StatusCode)
	}
	dev := body.Device
	if dev.DeviceID == "" {
		return Result{}, errors.New("status response missing deviceId")
	}
	// The snapshot must describe THIS device. The server's device
	// identifier is untrusted free text and is never echoed, so a
	// hostile response cannot learn whether it guessed close.
	if dev.DeviceID != st.DeviceID {
		return Result{}, errors.New("status response describes a different device than the bound one; refusing to apply it")
	}
	// Credential-reflection guard, before anything is applied or
	// persisted: a hostile server that echoes the device secret it just
	// received in the Authorization header back into any downstream
	// string field fails closed here, with fixed wording that never
	// names the reflected value. The secret is hex, so an attacker
	// cannot case-fold its way past the case-insensitive check.
	if responseReflectsSecret([]string{dev.DeviceID, dev.ApplicationID, dev.ExternalSubjectID, dev.DeviceName, dev.Platform}, st.DeviceSecret) {
		return Result{}, errors.New("status failed: response contained reflected credential material")
	}
	// Identity stability: an already-bound application or subject
	// identity never changes through a status query — a same-device-ID
	// response describing a different subject must not rebind the state
	// directory onto that subject. Empty local fields (older state
	// files) are compatibly backfilled instead.
	if old, got := strings.TrimSpace(st.ApplicationID), strings.TrimSpace(dev.ApplicationID); old != "" && got != old {
		return Result{}, errors.New("status response application identity does not match the bound device; refusing to rebind")
	}
	if old, got := strings.TrimSpace(st.ExternalSubjectID), strings.TrimSpace(dev.ExternalSubjectID); old != "" && got != old {
		return Result{}, errors.New("status response subject identity does not match the bound device; refusing to rebind")
	}
	// Everything validated; apply onto the in-memory copy. Identity
	// fields are only ever backfilled (never overwritten), and the
	// bound server URL is preserved: a --server override targets the
	// query, not the binding, so the next upload cannot be silently
	// aimed at a different server.
	if strings.TrimSpace(st.ApplicationID) == "" {
		st.ApplicationID = dev.ApplicationID
	}
	if strings.TrimSpace(st.ExternalSubjectID) == "" {
		st.ExternalSubjectID = dev.ExternalSubjectID
	}
	if strings.TrimSpace(st.ServerURL) == "" {
		st.ServerURL = strings.TrimRight(serverURL, "/")
	}
	// st.DeviceID is deliberately not reassigned: equality with the
	// response was proven above, so the bound ID is what persists.
	st.DeviceName = dev.DeviceName
	st.Platform = dev.Platform
	st.ConsentRevision = dev.ConsentRevision
	st.UploadAuthorized = dev.UploadAuthorized
	st.PublicAuthorized = dev.PublicAuthorized
	st.Revoked = dev.Revoked
	st.LastCheckedAt = dev.CheckedAt
	if err := store.Save(st); err != nil {
		return Result{}, err
	}
	return Result{State: st}, nil
}

func joinURL(base string, path string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", errors.New("invalid server URL")
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	return u.String(), nil
}

// errStatusRedirect is the fixed refusal every 3xx answer on the device
// self endpoint produces. A redirect would carry the device credential
// to an arbitrary second URL, so the cloned client rejects them all and
// this sentinel lets callers (and tests) match the outcome with
// errors.Is.
var errStatusRedirect = errors.New("status: redirects are not allowed on device endpoints")

// noRedirectClient returns a shallow copy of client that never follows
// redirects. The caller's client is not modified; its Timeout,
// Transport, and Jar are preserved exactly, and a nil client becomes
// the package default (the historical 10-second timeout) with redirects
// refused. A 3xx answer surfaces as an error from Do with the redirect
// response body closed, so no credential-bearing second request is ever
// made and exactly one request leaves the device.
func noRedirectClient(client *http.Client) *http.Client {
	cloned := http.Client{}
	if client != nil {
		cloned = *client
	} else {
		cloned.Timeout = 10 * time.Second
	}
	cloned.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errStatusRedirect
	}
	return &cloned
}

// maxResponseBodyBytes caps the device self response body this package
// decodes. It matches the syncclient device-self cap exactly: both
// query paths speak to the same endpoint, and the self snapshot is
// expected to grow (account sources, authorization fields), so a
// legitimate response must never hit one package's cap and not the
// other's. A legitimate snapshot today is a few hundred bytes, leaving
// orders of magnitude of headroom while bounding what a hostile or
// broken server can make the collector read. A body that
// needs MORE than the cap to complete its first JSON value is hostile
// or broken: the capped reader reads at most cap+1 bytes, identifies
// the excess explicitly (errResponseBodyTooLarge) without recording any
// content, and the run fails closed with zero state change.
//
// Boundary behavior, stated exactly: a JSON value that completes within
// the cap decodes normally — trailing bytes after a complete value are
// never read, exactly as an unrestricted json.Decoder behaves; a value
// that ends precisely at the cap succeeds without the probe; a body
// that ends cleanly at the cap mid-value surfaces as a plain truncated
// body (unexpected EOF), not as an over-cap excess.
const maxResponseBodyBytes int64 = 8 << 20

// errResponseBodyTooLarge marks a response body whose first JSON value
// required more than maxResponseBodyBytes. The capped reader discards
// the one probe byte it reads beyond the cap; no oversized content is
// ever buffered, logged, or embedded in an error.
var errResponseBodyTooLarge = errors.New("response body exceeds the safety limit")

// cappedResponseBody allows at most maxResponseBodyBytes to flow to the
// decoder. When the decoder is still hungry at the cap, exactly one
// further byte is read and discarded to distinguish "the body continues
// past the cap" (errResponseBodyTooLarge) from "the body ended at the
// cap" (clean io.EOF); both outcomes latch so repeated reads are stable.
type cappedResponseBody struct {
	r         io.Reader
	remaining int64
	eof       bool
	over      bool
}

// capResponseBody bounds a response body for decoding.
func capResponseBody(r io.Reader) io.Reader {
	return &cappedResponseBody{r: r, remaining: maxResponseBodyBytes}
}

func (c *cappedResponseBody) Read(p []byte) (int, error) {
	if c.over {
		return 0, errResponseBodyTooLarge
	}
	if c.eof {
		return 0, io.EOF
	}
	if c.remaining <= 0 {
		// The decoder needs more than the cap allows. Probe a single
		// byte — content discarded — so over-cap is an explicit,
		// identified outcome rather than a silent truncation.
		var probe [1]byte
		if _, err := io.ReadFull(c.r, probe[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				c.eof = true
				return 0, io.EOF
			}
			return 0, err
		}
		c.over = true
		return 0, errResponseBodyTooLarge
	}
	if int64(len(p)) > c.remaining {
		p = p[:int(c.remaining)]
	}
	n, err := c.r.Read(p)
	c.remaining -= int64(n)
	if errors.Is(err, io.EOF) {
		c.eof = true
	}
	return n, err
}

// sanitizedTransportError replaces a raw transport error (typically a
// *url.Error, whose text names the endpoint and whatever an intermediary
// or the runtime chose to include — up to and including reflected
// credential material) with a fixed, human-safe description, while
// keeping the cause reachable through Unwrap for errors.Is and
// errors.As — context cancellation, deadlines, io.EOF from a dropped
// connection, and the redirect refusal all keep matching. The scope
// string is a stable human prefix; the cause text is derived only from
// the error's identity, never from its message.
type sanitizedTransportError struct {
	scope string
	err   error
}

// wrapTransportError builds the sanitized wrapper. A nil err stays nil.
func wrapTransportError(scope string, err error) error {
	if err == nil {
		return nil
	}
	return &sanitizedTransportError{scope: scope, err: err}
}

func (e *sanitizedTransportError) Error() string {
	return e.scope + ": " + transportCauseText(e.err)
}

func (e *sanitizedTransportError) Unwrap() error { return e.err }

// transportCauseText renders a transport failure's identity as fixed,
// safe wording. A hostile endpoint cannot influence any of these strings
// (they key off sentinel identities, not error text); everything else
// collapses to the generic withheld-cause wording.
func transportCauseText(err error) string {
	switch {
	case errors.Is(err, errStatusRedirect):
		return "redirect refused (credentials never follow redirects)"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	case errors.Is(err, io.EOF):
		return "connection closed by the server before a response"
	default:
		return "transport failure (network-level error text withheld; the cause remains matchable with errors.Is/errors.As)"
	}
}

// safeDecodeError hides a response-body decode error's own text behind a
// fixed description derived only from the error's identity. Go's JSON
// syntax errors quote a character of the offending body — untrusted
// server content — so the raw text must never reach a human message;
// the identity-derived wording below is what dropped-connection
// semantics needs, and Unwrap keeps the original cause for
// programmatic matching.
type safeDecodeError struct {
	err error
}

func safeDecodeErrorOf(err error) error {
	if err == nil {
		return nil
	}
	return &safeDecodeError{err: err}
}

func (e *safeDecodeError) Error() string {
	switch {
	case errors.Is(e.err, io.EOF):
		return "EOF"
	case errors.Is(e.err, io.ErrUnexpectedEOF):
		return "unexpected EOF"
	case errors.Is(e.err, errResponseBodyTooLarge):
		return fmt.Sprintf("response body exceeded the %d MiB safety limit", maxResponseBodyBytes>>20)
	case errors.Is(e.err, context.Canceled):
		return "body read canceled"
	case errors.Is(e.err, context.DeadlineExceeded):
		return "body read timed out"
	default:
		return "malformed response body"
	}
}

func (e *safeDecodeError) Unwrap() error { return e.err }

// responseReflectsSecret reports whether any string field of a decoded
// 200 response that status would persist contains the device secret
// (case-insensitively; the secret is hex, so an attacker cannot
// case-fold its way past the check). A hostile server that echoes the
// credential it just received in the Authorization header back into any
// of these fields must never see it travel on into persisted state,
// the returned Result, or human output.
func responseReflectsSecret(fields []string, secret string) bool {
	if secret == "" {
		return false
	}
	needle := strings.ToLower(secret)
	for _, f := range fields {
		if f != "" && strings.Contains(strings.ToLower(f), needle) {
			return true
		}
	}
	return false
}
