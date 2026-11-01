package connect

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"toktrail-collector/internal/bind"
)

// parseAndValidateConnectURL parses rawURL, extracts and validates the 64-hex ticket
// from the fragment, strips the fragment, and validates transport security.
//
// Failures report fixed categories only: url.Parse errors quote the raw URL
// verbatim, and even with the ticket fragment already cut a pasted URL can
// carry userinfo, passwords, or other secrets in its scheme or body, so the
// raw URL and scheme are never echoed back. The validation logic itself is
// unchanged.
func parseAndValidateConnectURL(rawURL string) (string, string, error) {
	baseURLStr, ticket, hasFragment := strings.Cut(rawURL, "#")
	if !hasFragment || strings.TrimSpace(ticket) == "" {
		return "", "", errors.New("missing connect ticket in URL fragment")
	}
	ticket = strings.TrimSpace(ticket)
	if len(ticket) != 64 {
		return "", "", errors.New("invalid connect ticket: must be 64-character hex")
	}
	if _, err := hex.DecodeString(ticket); err != nil {
		return "", "", errors.New("invalid connect ticket: must be 64-character hex")
	}

	u, err := url.Parse(baseURLStr)
	if err != nil {
		return "", "", errors.New("invalid connect URL")
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", errors.New("invalid connect URL scheme; only https (or http for loopback) allowed")
	}

	if u.User != nil {
		return "", "", errors.New("connect URL must not contain userinfo")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return "", "", errors.New("connect URL must not contain query parameters")
	}

	hostname := u.Hostname()
	if hostname == "" {
		return "", "", errors.New("missing host in connect URL")
	}

	if scheme == "http" && !isLoopbackHost(hostname) {
		return "", "", errors.New("insecure HTTP connect URL is only permitted for loopback hosts (localhost, 127.0.0.1, ::1); HTTPS is required")
	}

	u.Fragment = ""
	return u.String(), ticket, nil
}

// isLoopbackHost checks if host is localhost or an IPv4/IPv6 loopback address.
func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// validateServerURL validates the serverUrl provided in connect response.
//
// The serverUrl is untrusted server data: a hostile connect server can
// reflect the bearer ticket (or any other attacker-chosen string) into it.
// Failures therefore report fixed categories only — never the raw URL, its
// userinfo or scheme, and never the url.Parse error text (which quotes the
// raw value verbatim). No caller matches these errors via errors.Is/As, so
// no chain is preserved on the sanitized paths.
func validateServerURL(serverURL string) error {
	u, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil {
		return errors.New("server URL is not parseable")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return errors.New("server URL scheme must be https (http only permitted for loopback)")
	}
	if u.User != nil {
		return errors.New("server URL must not contain userinfo")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return errors.New("server URL must not contain query parameters or fragment")
	}
	hostname := u.Hostname()
	if hostname == "" {
		return errors.New("missing host in server URL")
	}
	if scheme == "http" && !isLoopbackHost(hostname) {
		return errors.New("serverUrl must use HTTPS (HTTP only permitted for loopback)")
	}
	return nil
}

// fetchConnectConfig performs an HTTP GET to the stripped connect URL with Authorization: Bearer <ticket>,
// enforces redirect rejection, body size limits, and strictly validates the returned Config schema.
func fetchConnectConfig(ctx context.Context, client *http.Client, endpoint, ticket string, now time.Time) (Config, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		// Never surface the underlying text: it can quote the raw endpoint.
		return Config{}, &safeError{msg: "invalid connect request", cause: err}
	}
	req.Header.Set("Authorization", "Bearer "+ticket)
	req.Header.Set("Accept", "application/json")

	safeClient := newSafeHTTPClient(client)

	resp, err := safeClient.Do(req)
	if err != nil {
		// net/http puts the raw server-controlled Location header into the
		// *url.Error it returns for a refused redirect (and quotes it
		// verbatim when a malformed Location fails to parse before the
		// CheckRedirect hook runs), so no underlying text is ever echoed —
		// ticket redaction would not help, since hex tickets are
		// case-insensitive and a hostile server can send any case variant.
		// The redirect refusal keeps its fixed user hint via the sentinel;
		// every Do failure keeps its cause wrapped for errors.Is (context
		// cancellation, redirect classification).
		if errors.Is(err, errConnectRedirect) {
			return Config{}, &safeError{msg: "connect failed: redirects are not allowed", cause: err}
		}
		return Config{}, &safeError{msg: "connect request failed", cause: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Config{}, fmt.Errorf("connect failed: server returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		// The read error's text comes from the transport/proxy layer and is
		// not enumerable (it may embed credentials, proxy URLs, or reflected
		// request data), so only a fixed message is surfaced; the cause
		// stays wrapped for errors.Is/errors.As.
		return Config{}, &safeError{msg: "failed to read connect response body", cause: err}
	}
	if len(body) > 1<<20 {
		return Config{}, errors.New("connect response exceeds 1 MB limit")
	}

	var cfg Config
	if err := json.Unmarshal(body, &cfg); err != nil {
		// json error text can quote body content, which is untrusted and
		// may carry reflected credentials; report a fixed category.
		return Config{}, errors.New("invalid connect response JSON")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		return Config{}, errors.New("invalid connect response JSON: expected an object")
	}
	if reflectedTicket(cfg, ticket) {
		// Fail closed before the config can be printed or persisted: the
		// connect server knows the bearer ticket and can reflect it into
		// any config field, and those fields are surfaced to the user and
		// stored in state by the caller.
		return Config{}, errReflectedTicket
	}
	if cfg.SchemaVersion != 1 {
		return Config{}, fmt.Errorf("unsupported connect schemaVersion: %d (expected 1)", cfg.SchemaVersion)
	}
	if _, present := fields["days"]; !present {
		return Config{}, errors.New("missing days in connect response")
	}
	if err := validateServerURL(cfg.ServerURL); err != nil {
		return Config{}, fmt.Errorf("invalid serverUrl in connect response: %w", err)
	}
	cfg.ApplicationID = strings.TrimSpace(cfg.ApplicationID)
	if cfg.ApplicationID == "" {
		return Config{}, errors.New("missing applicationId in connect response")
	}
	cfg.SubjectID = strings.TrimSpace(cfg.SubjectID)
	if cfg.SubjectID == "" {
		return Config{}, errors.New("missing subjectId in connect response")
	}
	if cfg.Days != nil && *cfg.Days != 7 && *cfg.Days != 30 && *cfg.Days != 90 {
		return Config{}, fmt.Errorf("invalid days %d in connect response (must be 7, 30, 90, or null)", *cfg.Days)
	}

	exp, err := time.Parse(time.RFC3339, cfg.ExpiresAt)
	if err != nil {
		exp, err = time.Parse(time.RFC3339Nano, cfg.ExpiresAt)
	}
	if err != nil {
		// expiresAt is untrusted server data and time's parse error quotes
		// the raw value verbatim; a hostile connect server can reflect the
		// bearer ticket into it. Only a fixed category is reported.
		return Config{}, errors.New("invalid expiresAt in connect response")
	}
	if !exp.After(now) {
		// exp is re-rendered from the parsed time, so it cannot carry the
		// raw server string (a reflected ticket fails parsing above).
		return Config{}, fmt.Errorf("connect authorization expired at %s", exp.UTC().Format(time.RFC3339))
	}

	if len(cfg.Tools) == 0 {
		return Config{}, errors.New("no tools specified in connect response")
	}

	return cfg, nil
}

// safeError is a failure whose message is a fixed literal while the wrapped
// cause remains reachable through errors.Is/errors.As.
type safeError struct {
	msg   string
	cause error
}

func (e *safeError) Error() string { return e.msg }

// Unwrap keeps errors.Is/errors.As semantics for the wrapped cause.
func (e *safeError) Unwrap() error { return e.cause }

// errReflectedTicket fail-closes a connect config whose server-controlled
// string fields echo the bearer ticket. connect prints and persists those
// fields, so a hostile server reflecting the ticket must never get them that
// far.
var errReflectedTicket = errors.New("connect response rejected: reflected credential material")

// reflectedTicket reports whether any server-controlled string field of the
// decoded config contains the bearer ticket. Hex tickets are
// case-insensitive, so the comparison ignores case. It runs on the decoded
// values, so JSON unicode escapes ("\u0061...") cannot smuggle a reflection
// past it.
func reflectedTicket(cfg Config, ticket string) bool {
	if ticket == "" {
		return false
	}
	needle := strings.ToLower(ticket)
	contains := func(haystack string) bool {
		return strings.Contains(strings.ToLower(haystack), needle)
	}
	if contains(cfg.ServerURL) || contains(cfg.ApplicationID) || contains(cfg.SubjectID) || contains(cfg.ExpiresAt) {
		return true
	}
	for _, tool := range cfg.Tools {
		if contains(tool) {
			return true
		}
	}
	return false
}

// errConnectRedirect is the fixed sentinel newSafeHTTPClient's redirect
// refusal returns. net/http wraps it (alongside the raw server-controlled
// Location URL) into the *url.Error Do returns; classification uses
// errors.Is on this sentinel, never the error text.
var errConnectRedirect = errors.New("redirects are not allowed")

func newSafeHTTPClient(client *http.Client) *http.Client {
	cloned := http.Client{}
	if client != nil {
		cloned = *client
	}
	if cloned.Timeout <= 0 || cloned.Timeout > 15*time.Second {
		cloned.Timeout = 15 * time.Second
	}
	cloned.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errConnectRedirect
	}
	return &cloned
}

// unvettedErrorMessage is the fixed message sanitizeError reports for any
// error whose text carries no fixed-literal guarantee.
const unvettedErrorMessage = "error details withheld (unvetted error text)"

// sanitizeError wraps err so that no credential or other unvetted text can
// leak into a human-facing message, while the wrapped cause stays reachable
// for the sentinel-based stop-reason classification (ClassifyRunError reads
// errors.Is only, never message text, so exit classification is unchanged).
//
// The previous implementation redacted just the exact ticket substring and
// flattened the chain with errors.New, which leaked unknown credentials and
// case-variant tickets (hex is case-insensitive) and destroyed errors.Is.
// Now only messages from types with a fixed-literal guarantee pass through:
// *bind.Error composes its message from fixed literals, numeric statuses and
// fixed categories, and *safeError is sanitized by construction. Anything
// else — including *url.Error, whose URL field net/http fills with the raw
// server-controlled Location header — gets the fixed generic message.
func sanitizeError(err error, ticket string) error {
	if err == nil {
		return nil
	}
	msg := unvettedErrorMessage
	var bindErr *bind.Error
	var safeErr *safeError
	switch {
	case errors.As(err, &bindErr):
		msg = bindErr.Error()
	case errors.As(err, &safeErr):
		msg = safeErr.Error()
	}
	// Defensive guard: a whitelisted message must never carry the ticket in
	// any case variant. If a future regression breaks the fixed-literal
	// guarantee, fall back to the generic message.
	if ticket != "" && msg != unvettedErrorMessage &&
		strings.Contains(strings.ToLower(msg), strings.ToLower(ticket)) {
		msg = unvettedErrorMessage
	}
	return &safeError{msg: msg, cause: err}
}
