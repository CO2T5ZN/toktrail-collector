// Package api implements the HTTP protocol for Cursor's personal-account
// usage dashboard API.
//
// Every wire fact below is verified against the official tokscale source at
// fixed commit 39ecb83ab045a300c6f502f9c9319acf5c80e764 (2026-10-27):
//
//   - crates/tokscale-cli/src/cursor.rs — endpoints, headers, auth cookie,
//     pagination walk, bounds, session validation
//   - crates/tokscale-core/src/sessions/cursor.rs — usageEventsDisplay row
//     schema and event-snapshot collapse
//     (https://github.com/junhoyeo/tokscale/tree/39ecb83ab045a300c6f502f9c9319acf5c80e764)
//
// Protocol summary:
//
//	POST https://cursor.com/api/dashboard/get-filtered-usage-events
//	     Cookie: WorkosCursorSessionToken=<token>
//	     Content-Type: application/json, Origin: https://cursor.com (CSRF check)
//	     User-Agent: Chrome, Referer: https://www.cursor.com/settings
//	     body {"startDate":"<ms>","endDate":"<ms>","page":<int>,"pageSize":<int>}
//	     → {"totalUsageEventsCount":<int>,"usageEventsDisplay":[<event>,…]}
//
//	GET  https://cursor.com/api/usage-summary   (session validity check)
//	     → must contain billingCycleStart/billingCycleEnd strings; optional
//	       membershipType. The reference reads no user-identity fields from
//	       it and uses no user endpoint anywhere.
//
// The dashboard lists events newest-first and re-reports recent events on
// later syncs with running token totals, which is how delayed billing
// corrections (including downward ones) arrive: rows sharing a
// usageEventId are snapshots of one event, never independent events.
// FetchUsageEvents returns raw snapshots without summing; CollapseSnapshots
// resolves duplicates within one response, and the sync layer replaces
// stored events wholesale on each successful pull.
//
// TokTrail deviations from the reference, deliberate: parsing is strict
// (unknown stays nil; negative/fractional/overflow errors instead of
// lenient coercion), raw rows/cost/conversation ids beyond the derived key
// are not retained, redirects are rejected outright, bounds are hard caps,
// and a whole-walk budget defaults to two minutes.
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Verified protocol constants (tokscale crates/tokscale-cli/src/cursor.rs).
const (
	// DefaultBaseURL is the only non-loopback origin this client will talk to.
	DefaultBaseURL = "https://cursor.com"
	// AllowedHost is the hardcoded production host allowlist entry.
	AllowedHost = "cursor.com"
	// UsageEventsPath is the paginated usage-events JSON endpoint (POST).
	UsageEventsPath = "/api/dashboard/get-filtered-usage-events"
	// UsageSummaryPath is the session-validation summary endpoint (GET).
	UsageSummaryPath = "/api/usage-summary"

	// DefaultPageSize mirrors CURSOR_JSON_PAGE_SIZE.
	DefaultPageSize = 500
	// MaxPageSize is the hard cap on the requested page size.
	MaxPageSize = 1000

	// DefaultMaxPages mirrors CURSOR_MAX_JSON_PAGES and is also its hard
	// cap: the walk never exceeds this many pages, however the server
	// clamps its page size. A clamped server that cannot reach its
	// advertised total within the cap fails with a partial-history error.
	DefaultMaxPages  = 500
	DefaultMaxEvents = 250000

	// DefaultMaxBodyBytes mirrors CURSOR_MAX_JSON_BYTES and is also its hard
	// cap: the cumulative ceiling on response bytes across every page of
	// one walk.
	DefaultMaxBodyBytes = 64 << 20

	// DefaultTimeout mirrors CURSOR_HTTP_TIMEOUT, the per-request default.
	DefaultTimeout = 15 * time.Second
	// MaxTimeout is the hard cap on the per-request timeout.
	MaxTimeout = 2 * time.Minute
	// DefaultWalkBudget bounds a whole FetchUsageEvents walk when the
	// caller's context carries no deadline (the reference's explicit-sync
	// default, CURSOR_EXPLICIT_SYNC_TIMEOUT).
	DefaultWalkBudget = 2 * time.Minute

	// clockSkewMS mirrors CURSOR_USAGE_CLOCK_SKEW_MS: the tolerance applied
	// to event timestamps when filtering pages against the sync window.
	clockSkewMS = 5 * 60 * 1000

	cookieName     = "WorkosCursorSessionToken"
	originHeader   = "https://cursor.com"
	refererHeader  = "https://www.cursor.com/settings"
	agentHeader    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	acceptLanguage = "en-US,en;q=0.9"
)

// ErrSessionExpired reports HTTP 401/403 from Cursor: the session token is
// expired or invalid and the user must re-authenticate.
var ErrSessionExpired = errors.New("cursor session expired or invalid")

// Options configures a Client. The zero value is usable and selects every
// default. Every bound is a hard cap: callers may tighten, never loosen.
type Options struct {
	// HTTPClient overrides the underlying transport for tests. The client
	// is cloned; its CheckRedirect and Timeout are replaced.
	HTTPClient *http.Client
	// BaseURL defaults to https://cursor.com. Any other value must be an
	// http(s) loopback URL for tests; non-loopback hosts are rejected so the
	// credential can never be pointed at another origin.
	BaseURL string
	// PageSize defaults to DefaultPageSize, capped at MaxPageSize.
	PageSize int
	// MaxPages defaults to DefaultMaxPages and is a hard ceiling on one
	// walk's page count.
	MaxPages int
	// MaxEvents caps all parsed rows, including repeated snapshots.
	MaxEvents int
	// MaxBodyBytes is the cumulative response-body ceiling across all pages
	// of one walk; it defaults to DefaultMaxBodyBytes and never exceeds it.
	MaxBodyBytes int
	// Timeout is the per-request timeout; it defaults to DefaultTimeout and
	// never exceeds MaxTimeout.
	Timeout time.Duration
	// Now overrides the clock for tests.
	Now func() time.Time
}

// Client fetches usage data from Cursor's personal dashboard API. It is
// safe for concurrent use.
type Client struct {
	httpClient   *http.Client
	baseURL      *url.URL
	pageSize     int
	maxPages     int
	maxEvents    int
	maxBodyBytes int
	now          func() time.Time
}

// New builds a Client, enforcing the hardcoded production host allowlist.
// The only permitted non-loopback base is https://cursor.com with no user
// info, query, fragment, or port. Error messages never echo the URL, which
// could carry a credential.
func New(opts Options) (*Client, error) {
	base := DefaultBaseURL
	if opts.BaseURL != "" {
		base = opts.BaseURL
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, errors.New("cursor api: invalid base URL")
	}
	if err := validateBaseURL(u); err != nil {
		return nil, err
	}

	c := &Client{
		baseURL:      u,
		pageSize:     clampInt(opts.PageSize, DefaultPageSize, MaxPageSize),
		maxPages:     clampInt(opts.MaxPages, DefaultMaxPages, DefaultMaxPages),
		maxEvents:    clampInt(opts.MaxEvents, DefaultMaxEvents, DefaultMaxEvents),
		maxBodyBytes: clampInt(opts.MaxBodyBytes, DefaultMaxBodyBytes, DefaultMaxBodyBytes),
		now:          opts.Now,
	}
	if c.now == nil {
		c.now = time.Now
	}

	httpClient := http.Client{}
	if opts.HTTPClient != nil {
		httpClient = *opts.HTTPClient
	}
	httpClient.Timeout = clampDuration(opts.Timeout, DefaultTimeout, MaxTimeout)
	// Redirects are rejected outright: the Cookie header must never be
	// replayed against a Location the client did not choose, and Cursor's
	// endpoints answer directly.
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errRedirectRefused
	}
	c.httpClient = &httpClient
	return c, nil
}

// validateBaseURL enforces the allowlist: https + cursor.com without user
// info, query, fragment, or port for production; plain http only on
// loopback for tests, where a port is required.
func validateBaseURL(u *url.URL) error {
	if u.Path != "" && u.Path != "/" {
		return errors.New("cursor api: base URL must not contain a path")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawFragment != "" {
		return errors.New("cursor api: base URL must not contain user info, a query, or a fragment")
	}
	host := u.Hostname()
	if !isLoopbackHost(host) {
		if u.Scheme != "https" {
			return errors.New("cursor api: base URL must use https")
		}
		if host != AllowedHost {
			return errors.New("cursor api: base URL host is not allowed")
		}
		if u.Port() != "" {
			return errors.New("cursor api: base URL must use the default port")
		}
		return nil
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("cursor api: base URL scheme must be http or https")
	}
	return nil
}

// FetchOptions bounds one usage-events walk.
type FetchOptions struct {
	// StartDateMS, when non-nil, requests events at or after that Unix
	// millisecond epoch and stops the walk once a page crosses below it
	// (older events are excluded from the result). The reference re-fetches
	// one hour before the newest stored timestamp this way so delayed
	// billing corrections arrive without re-downloading history. nil fetches
	// from 0 (cold cache / full history).
	StartDateMS *int64
	// EndDateMS bounds the window end; 0 means now.
	EndDateMS int64
}

// FetchUsageEvents walks every page of get-filtered-usage-events until the
// advertised totalUsageEventsCount is collected, an explicit end-of-pages
// signal arrives (hasNext:false), an empty page ends the stream, or the
// StartDateMS window is crossed. It returns the raw snapshots in arrival
// order; it never sums or collapses rows sharing a usageEventId, and it
// merges nothing into local history — persisting and replacing stored
// events is the sync layer's job.
//
// A malformed 200 (missing usageEventsDisplay), an invalid event row, an
// empty page before the advertised total, an exhausted page ceiling, or a
// cumulative byte ceiling overrun is an error rather than a silently
// partial result. When the caller's context has no deadline, the whole walk
// is bounded by DefaultWalkBudget.
//
// Error privacy, double-gated: the strict row parser's errors carry only
// fixed field names and categories (never the row or a field value), and
// every error leaving this walk is additionally passed through
// sanitizeToken against the session token — the second layer behind the
// request-level sanitization. The boundary keeps errors.Is/As contracts
// intact: a token-free error passes through untouched with its full chain
// (ErrSessionExpired, cancellation, url.Error …), and a token-bearing
// message is redacted by a wrapper that keeps the cause reachable through
// Unwrap, so sentinel and net.Error matching survive the redaction too.
func (c *Client) FetchUsageEvents(ctx context.Context, sess Session, opts FetchOptions) (result *UsageEvents, err error) {
	// Second sanitization layer (see the function comment): applied on
	// every error exit, after the request-level one. Clean errors are
	// returned untouched, so no Is/As contract is lost unnecessarily.
	defer func() {
		if err != nil {
			err = sanitizeToken(err, sess.Token)
		}
	}()
	if strings.TrimSpace(sess.Token) == "" {
		return nil, errors.New("cursor api: session token is empty")
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		walkCtx, cancel := context.WithTimeout(ctx, DefaultWalkBudget)
		defer cancel()
		ctx = walkCtx
	}

	endMS := opts.EndDateMS
	if endMS == 0 {
		endMS = c.now().UnixMilli()
	}
	startMS := int64(0)
	if opts.StartDateMS != nil && *opts.StartDateMS > 0 {
		startMS = *opts.StartDateMS
	}
	// Plausibility ceiling for filtering, mirroring the reference's clock
	// skew allowance: an accepted future row cannot move the window.
	maxTimestamp := endMS + clockSkewMS

	result = &UsageEvents{StartDateMS: startMS, EndDateMS: endMS}
	completed := false
	seenPages := make(map[[32]byte]bool)
	rowsRead := 0

	for page := 1; page <= c.maxPages; page++ {
		body := map[string]any{
			"startDate": strconv.FormatInt(startMS, 10),
			"endDate":   strconv.FormatInt(endMS, 10),
			"page":      page,
			"pageSize":  c.pageSize,
		}
		// The byte ceiling is cumulative across pages: each page may read
		// only what earlier pages left of the budget, so a paginated
		// response cannot sidestep the cap by spreading a huge payload.
		text, err := c.request(ctx, UsageEventsPath, http.MethodPost, sess, body, true, c.maxBodyBytes-result.BytesRead)
		if err != nil {
			return nil, err
		}
		result.PagesFetched = page
		result.BytesRead += len(text)

		var pageValue struct {
			TotalUsageEventsCount *int64             `json:"totalUsageEventsCount"`
			UsageEventsDisplay    *[]json.RawMessage `json:"usageEventsDisplay"`
			HasNext               *bool              `json:"hasNext"`
		}
		if err := json.Unmarshal(text, &pageValue); err != nil {
			return nil, fmt.Errorf("cursor api: invalid usage events JSON on page %d", page)
		}
		if pageValue.UsageEventsDisplay == nil {
			// A 200 without the array is a WAF challenge or an API change,
			// never an empty result, so a good cache is never overwritten
			// with nothing.
			return nil, fmt.Errorf("cursor api: page %d is missing the usageEventsDisplay array", page)
		}
		if pageValue.TotalUsageEventsCount != nil && (*pageValue.TotalUsageEventsCount < 0 || *pageValue.TotalUsageEventsCount > int64(c.maxEvents)) {
			return nil, errors.New("cursor api: invalid or excessive usage-event total; narrow the history window")
		}
		if page == 1 && pageValue.TotalUsageEventsCount != nil {
			result.TotalUsageEventsCount = *pageValue.TotalUsageEventsCount
			result.HasTotalCount = true
		}

		rows := *pageValue.UsageEventsDisplay
		if len(rows) > c.maxEvents-rowsRead {
			return nil, errors.New("cursor api: usage-event count exceeds the fetch limit; refusing a partial history")
		}
		rowsRead += len(rows)
		pageEvents := make([]UsageEvent, 0, len(rows))
		pageHasID := false
		crossed := false
		for _, row := range rows {
			event, err := ParseUsageEvent(row)
			if err != nil {
				return nil, fmt.Errorf("cursor api: page %d holds an invalid event row: %w", page, err)
			}
			pageEvents = append(pageEvents, event)
			pageHasID = pageHasID || event.UsageEventID != ""
		}
		if pageHasID {
			canonical, _ := json.Marshal(pageEvents)
			fingerprint := sha256.Sum256(canonical)
			if seenPages[fingerprint] {
				return nil, errors.New("cursor api: repeated usage-event page; refusing a partial history")
			}
			seenPages[fingerprint] = true
		}
		for _, event := range pageEvents {
			if startMS > 0 && event.TimestampMS <= maxTimestamp && event.TimestampMS < startMS {
				crossed = true
				continue
			}
			result.Events = append(result.Events, event)
		}
		if crossed {
			completed = true
			break
		}

		// Termination, most reliable signal first:
		//  1. the advertised totalUsageEventsCount is collected;
		//  2. an explicit hasNext:false page-level signal, when the server
		//     sends one;
		//  3. an empty page (no total, no hasNext).
		// A short page alone is NOT a reliable end: a server that clamps the
		// requested page size returns short pages that are actually full,
		// and stopping there would silently truncate history. Without any
		// reliable signal the walk continues to the page cap and fails
		// loudly rather than returning a partial result.
		if result.HasTotalCount {
			if int64(len(result.Events)) >= result.TotalUsageEventsCount {
				completed = true
				break
			}
			if len(rows) == 0 {
				return nil, fmt.Errorf(
					"cursor api: empty page %d before the advertised total of %d events; refusing a partial history",
					page, result.TotalUsageEventsCount)
			}
		} else if pageValue.HasNext != nil {
			if !*pageValue.HasNext {
				completed = true
				break
			}
			if len(rows) == 0 {
				return nil, fmt.Errorf("cursor api: page %d is empty while the server claims hasNext", page)
			}
		} else if len(rows) == 0 {
			completed = true
			break
		}
	}
	if !completed {
		return nil, fmt.Errorf(
			"cursor api: usage events exceeded the %d-page fetch limit (%d events collected); refusing a partial history",
			c.maxPages, len(result.Events))
	}
	return result, nil
}

// FetchUsageSummary performs the GET /api/usage-summary session-validity
// check: the session is valid when the response is a 200 carrying
// billingCycleStart and billingCycleEnd strings. The endpoint carries no
// user-identity fields in the reference implementation — account identity
// is derived from the credential itself; see VerifySession.
func (c *Client) FetchUsageSummary(ctx context.Context, sess Session) (*UsageSummary, error) {
	if strings.TrimSpace(sess.Token) == "" {
		return nil, errors.New("cursor api: session token is empty")
	}
	text, err := c.request(ctx, UsageSummaryPath, http.MethodGet, sess, nil, false, c.maxBodyBytes)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(text, &fields); err != nil || fields == nil {
		return nil, errors.New("cursor api: invalid usage summary response: expected a JSON object")
	}
	// Non-string fields count as missing, mirroring the reference's
	// as_str() checks.
	summary := &UsageSummary{}
	summary.BillingCycleStart, _ = strictString("billingCycleStart", fields["billingCycleStart"])
	summary.BillingCycleEnd, _ = strictString("billingCycleEnd", fields["billingCycleEnd"])
	summary.MembershipType, _ = strictString("membershipType", fields["membershipType"])
	if summary.BillingCycleStart == "" || summary.BillingCycleEnd == "" {
		return nil, errors.New("cursor api: invalid usage summary response: missing billing cycle window")
	}
	return summary, nil
}

// request performs one call, enforcing status, size, and redirect
// policy. jsonHeaders selects the dashboard CSRF headers (Content-Type +
// Origin). maxBytes bounds this call's response body; callers advancing
// a paginated walk pass what remains of their cumulative budget.
//
// Error privacy: every request-construction, transport and body-read
// failure is wrapped by wrapTransportError — a fixed human message with
// the cause kept reachable through Unwrap. The raw transport text
// embeds the full request URL and therefore anything a hostile server
// placed into a refused redirect's Location header (the session token,
// a case variant, or any other secret), which sanitizeToken's
// exact-token replacement could not catch; the fixed wording never
// renders any of it, while errors.Is/As (cancellation, deadlines,
// net.Error, the redirect refusal, ErrSessionExpired on the status
// paths) keep matching exactly.
func (c *Client) request(ctx context.Context, path, method string, sess Session, body any, jsonHeaders bool, maxBytes int) ([]byte, error) {
	scope := "cursor api: " + endpointScope(path)
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, errors.New("cursor api: failed to encode request body")
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL.JoinPath(path).String(), reader)
	if err != nil {
		return nil, wrapTransportError(scope+" request could not be built", err)
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", acceptLanguage)
	req.Header.Set("Referer", refererHeader)
	req.Header.Set("User-Agent", agentHeader)
	req.Header.Set("Cookie", cookieName+"="+sess.Token)
	if jsonHeaders {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", originHeader)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, wrapTransportError(scope+" request failed on the transport", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ErrSessionExpired
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("cursor api: %s returned status %d", endpointScope(path), resp.StatusCode)
	}

	remaining := maxBytes
	if remaining < 0 {
		remaining = 0
	}
	text, err := readBodyCapped(resp, remaining)
	if err != nil {
		// The byte-cap refusal is locally constructed fixed text; only
		// the read failure is a transport error needing the
		// cause-preserving wrapper.
		if errors.Is(err, errResponseBodyCap) {
			return nil, err
		}
		return nil, wrapTransportError(scope+" response could not be read", err)
	}
	return text, nil
}

// errResponseBodyCap is the sentinel behind the cumulative body-cap
// refusals, so request can tell a local policy error from a transport
// failure.
var errResponseBodyCap = errors.New("cursor api: response body exceeds the byte limit")

// readBodyCapped reads at most limit bytes, refusing an oversized
// Content-Length before reading and the actual stream while reading. A
// read failure is returned raw — the caller wraps it, keeping its cause
// (cancellation, connection loss) matchable through Unwrap.
func readBodyCapped(resp *http.Response, limit int) ([]byte, error) {
	if resp.ContentLength > int64(limit) {
		return nil, fmt.Errorf("%w (%d bytes)", errResponseBodyCap, limit)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("%w (%d bytes)", errResponseBodyCap, limit)
	}
	return data, nil
}

// errRedirectRefused is the cloned client's no-redirect policy error. A
// redirect answer is a deliberate local security refusal (the session
// cookie must never travel to another origin), not a network failure.
var errRedirectRefused = errors.New("cursor api: redirects are not allowed")

// endpointScope renders a request path as a fixed internal label — the
// only form in which a path may appear in a message. An unknown path
// (impossible from this package's own callers) is not displayed at all.
func endpointScope(path string) string {
	switch path {
	case UsageEventsPath:
		return "usage events"
	case UsageSummaryPath:
		return "usage summary"
	default:
		return "request"
	}
}

// transportError renders a fixed, human-safe message for a transport
// failure while keeping the original cause reachable through Unwrap, so
// every errors.Is / errors.As contract of the wrapped error survives:
// context cancellation and deadlines, net.Error shapes, the redirect
// refusal and any retry marker all keep matching exactly as on the
// unredacted error. Go's formatting never renders an error's chain —
// fmt's %v/%+v, the log package and %w-wrapping print only Error() —
// so the cause's raw text (which embeds the request URL and anything a
// hostile server put into a refused redirect's Location) never reaches
// a human message.
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

// redactedError renders a sanitized message while keeping the original
// cause reachable through Unwrap, so every errors.Is / errors.As
// contract of the wrapped error survives redaction: authorization
// sentinels (ErrSessionExpired), cancellation, retry markers and
// net.Error shapes all keep matching exactly as on the unredacted
// error.
//
// Logging safety: Go's formatting never renders an error's chain —
// fmt's %v/%+v, the log package and %w-wrapping all print only
// Error(), which is the redacted text. The secret-bearing cause is
// reachable only by explicitly unwrapping or errors.As traversal, which
// no logging or classification path performs. The alternative —
// dropping the cause — would silently strip authorization and retry
// classification from a failure, a correctness loss the redaction must
// never cause.
type redactedError struct {
	msg   string
	cause error
}

func (e *redactedError) Error() string { return e.msg }

// Unwrap keeps the original cause reachable so errors.Is/As keep their
// full matching semantics; see the type comment for why that is safe.
func (e *redactedError) Unwrap() error { return e.cause }

// sanitizeToken keeps the session token out of the rendered error
// message. Errors whose message carries no token are returned untouched,
// so their full chain (url.Error, context sentinels, …) stays reachable.
// A secret-bearing error is wrapped by a redactedError: the rendered
// message is redacted (every occurrence of the token replaced), while
// the original cause stays reachable through Unwrap so no errors.Is /
// errors.As contract — authorization sentinels, cancellation, retry
// markers, net.Error — is lost to the redaction. A wrapped chain's
// Error() renders every nested message, so a token anywhere in the
// chain surfaces in the top-level rendering and is caught here.
func sanitizeToken(err error, token string) error {
	if err == nil || token == "" {
		return err
	}
	msg := err.Error()
	if !strings.Contains(msg, token) {
		return err
	}
	return &redactedError{
		msg:   strings.ReplaceAll(msg, token, "[REDACTED]"),
		cause: err,
	}
}

// isLoopbackHost reports whether the host is a loopback address, the only
// hosts permitted to use plain http for tests.
func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
}

func clampInt(v, def, hardMax int) int {
	if v <= 0 {
		return def
	}
	if v > hardMax {
		return hardMax
	}
	return v
}

func clampDuration(v, def, hardMax time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	if v > hardMax {
		return hardMax
	}
	return v
}
