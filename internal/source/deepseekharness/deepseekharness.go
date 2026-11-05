// Package deepseekharness reads DeepSeek Harness (DSH) native session logs
// and emits per-attempt token usage delta records.
//
// Storage layout (verified against the DSH implementation; see the reference
// NOTES.md in ../Ref/TokenRank/collector/internal/adapter/deepseekharness):
//
//	<root>/<project>/<encoded-session-id>/session.vN.jsonl[.zstd]
//
// where the input root is the DSH sessions directory (~/.dsh/sessions).
// Files are newline-delimited JSON: line 1 is the session header
// {type:"session",version,id,createdAt,isSeeded,...}; every later line is one
// durable event {type,seq,time,data,...} with a dense seq starting at 0 and
// time as epoch milliseconds.
//
// Turn-lifecycle semantics (aligned with DSH's token-meter
// deriveTurnTokenUsage — the whole turn is accounted or nothing):
//
//   - Only COMPLETE, VALID turns produce records. A turn is complete when
//     its turn/end event has been consumed (a torn final line or a session
//     killed mid-turn leaves the turn unaccounted; the stateless full rescan
//     picks it up once the turn closes). A turn is valid when every
//     step-scoped event observes the DSH state machine:
//     step/start opens an attempt; assistant/message settles it and
//     assistant/attempt closes it failed (each requires the attempt open);
//     llm/retry arms a retry only after a finalized attempt and
//     llm/retry-started reopens it while its step is still open (a retry
//     never starts after step/end); step/end requires a finalized attempt
//     and legally closes a step whose armed retry never started (the DSH
//     state machine's settled-by-retry → idle transition, so a failed
//     attempt's usage stays attributed); turn/end requires every step
//     finalized and ended. Any violation
//     (duplicate settlement, settlement without step/start, events outside
//     the turn boundaries, ...) invalidates the WHOLE turn — partial turns
//     are never exported, mirroring token-meter returning undefined.
//   - Each attempt-closing event (assistant/message, assistant/attempt)
//     emits ONE kind=delta record when it carries a valid usage sample;
//     each retry attempt counts at most once. llm/retry carries no usage
//     sample of its own (its attempt was already finalized by the
//     preceding assistant event), so counting it would double count.
//   - A usage sample is data.usage for assistant/message (explicit null
//     falls back to the stream, matching JS ??) or the last 'usage' entry
//     of the event's compact stream (both the direct {type:"usage"} entry
//     shape and the wrapped {type:"chunk",chunk:{type:"usage"}} shape are
//     accepted; the last one is authoritative). Samples are validated the
//     way DSH's normalizeUsage does: inputTokens and outputTokens must be
//     present non-negative JS safe integers; cacheReadTokens,
//     cacheWriteTokens, reasoningTokens and totalTokens are optional but
//     must be valid when present; reasoningTokens must not exceed
//     outputTokens; totalTokens must not contradict the known buckets.
//     Invalid samples produce no record at all — never partial counts.
//   - inputTokens is uncached input; outputTokens INCLUDES reasoning tokens
//     (reasoningTokens is a subset and is never uploaded separately).
//     Omitted DSH cache buckets are derived from totalTokens (residual 0
//     proves them zero; a positive residual attributes to the single
//     omitted bucket) before the nothing-reportable check, so cache-only
//     residuals are never lost. Unattributable buckets upload as null.
//   - Seeded sessions (forks/resumes) physically contain an inherited event
//     prefix copied from their source session, ending at a
//     session/end-seed {data:{inherited:true}} marker. The lifecycle runs
//     over the whole file, but only events after the LAST marker emit
//     records, so the prefix is counted only in the session that owns it.
//     A seeded header without a marker is not attributable safely: the
//     file emits nothing and reports an issue (fail closed).
//   - Only the highest canonical generation (largest vN; "session.jsonl"
//     is generation 0; names with leading zeros or other suffixes are not
//     canonical) per session directory is scanned. When the same
//     generation exists both raw and .zstd, the raw file wins.
//   - The model is the value the event itself recorded, kept VERBATIM:
//     only assistant/message attributes (from message.source.model), and
//     a route alias such as main/coder or an explicit model id survives
//     unchanged — TokTrail maintains no allowlist, never rewrites a valid
//     value, and never drops a recorded model because its provider is
//     missing (no backend speculation). Not reliably attributable and
//     reported as "unknown": assistant/attempt (recorded history shows
//     attempt events carry no message source), a missing message or
//     source, and an absent or JSON-null model. A model that is PRESENT
//     but fails the shared adapter.ValidateModel wire check (the explicit
//     empty string, whitespace-only, control characters, over 128 bytes,
//     non-string JSON) is never silently mapped: the whole turn fails
//     closed and the value is reported as an issue. Raw lines are
//     validated as UTF-8 BEFORE JSON decoding — Go's decoder silently
//     replaces invalid bytes with U+FFFD, which would rewrite the
//     recorded model — and invalid lines are rejected as malformed.
//   - The recordKey is "deepseek-harness:" + ShortHash(sessionID + "|" +
//     seq) and the groupKey is "dsh-session:" + ShortHash(sessionID):
//     stable across rescans and generation rotation, scoped per session,
//     and never leaking the raw session id. Because this pipeline is
//     stateless (no incremental marks), every Load re-emits the full
//     history; replays are made idempotent by FilterForExport, which drops
//     records already present in the outbox/quarantine history (history.go).
package deepseekharness

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/klauspost/compress/zstd"

	"toktrail-collector/internal/local/scanledger"
	"toktrail-collector/internal/source/adapter"
)

const (
	// dshTool must match the canonical tool name in registry.SupportedTools.
	dshTool = "DeepSeek Harness"
	// adapterVersion identifies the record layout produced by this adapter.
	adapterVersion = "deepseek-harness-v1"
	// recordKeyDomain prefixes every stable record key.
	recordKeyDomain = "deepseek-harness"
	// groupKeyDomain prefixes every per-session group key.
	groupKeyDomain = "dsh-session"
	// maxSafeInteger mirrors JS Number.isSafeInteger (2^53-1); larger or
	// fractional counts are unsafe and invalidate the sample.
	maxSafeInteger = int64(1)<<53 - 1
	// maxIssues caps the LineIssue list; every anomaly still increments
	// Quarantined so counts stay complete.
	maxIssues = 50
)

// Adapter returns the DeepSeek Harness source adapter.
func Adapter() adapter.Adapter {
	return adapter.Adapter{
		Source:      adapter.DeepSeekHarnessSource,
		Description: "DeepSeek Harness session JSONL (per-attempt deltas)",
		Load: func(opt adapter.Options) (adapter.LoadResult, error) {
			return loadRecordsResuming(opt)
		},
		FilterForExport: func(opt adapter.Options, records []adapter.Record) ([]adapter.Record, error) {
			ctx := opt.ContextOrBackground()
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if strings.TrimSpace(opt.StateDir) == "" {
				return records, nil
			}
			return filterKnownDSHRecordsContext(ctx, opt.StateDir, records)
		},
	}
}

// LoadRecords scans a DSH sessions root and returns every per-attempt usage
// record found in the highest canonical generation of each session log
// (plain or zstd). It is stateless: repeated calls return the same records
// with the same stable keys; export-time deduplication happens in
// FilterForExport. opt.Limit is intentionally not applied here — the
// pipeline applies its own preview limits, and a partial scan would have no
// mark to resume from. It keeps the historical uncancellable signature for
// direct callers; the adapter's Load passes its cancellation scope through
// loadRecordsContext.
func LoadRecords(root string) (adapter.LoadResult, error) {
	return loadRecordsContext(context.Background(), root)
}

// loadRecordsContext scans with cancellation support: the context is checked
// during file discovery, once per session file, and once per event line. On
// cancellation it returns ctx.Err() (matchable with errors.Is(err,
// context.Canceled) or errors.Is(err, context.DeadlineExceeded)) and no
// partial result — records, issues, and quarantine counts accumulated so far
// are discarded, so a scan cut short never exports half of a session.
func loadRecordsContext(ctx context.Context, root string) (adapter.LoadResult, error) {
	return loadRecordsWithPrior(ctx, root, nil)
}

// loadRecordsResuming is the production loader: unchanged session files are
// skipped instead of being re-decoded on every scheduled run.
//
// A skip is content-proven (whole-file SHA-256 over the chosen generation
// file, see internal/local/scanledger); a rewritten or appended session is
// parsed exactly as before, and the downstream known-set keeps the authority
// for counting each record once. The returned ScanStates let the caller
// advance the ledger only after this scan's records are committed.
func loadRecordsResuming(opt adapter.Options) (adapter.LoadResult, error) {
	var prior map[string]scanledger.FileState
	if strings.TrimSpace(opt.StateDir) != "" {
		if loaded, _, err := scanledger.New(opt.StateDir).Load(adapter.DeepSeekHarnessSource); err == nil {
			prior = loaded
		}
	}
	return loadRecordsWithPrior(opt.ContextOrBackground(), opt.Input, prior)
}

// loadRecordsWithPrior is the shared scan. A nil prior parses every file (the
// historical behavior); a non-nil map skips files whose content digest
// matches it.
func loadRecordsWithPrior(ctx context.Context, root string, prior map[string]scanledger.FileState) (adapter.LoadResult, error) {
	res := adapter.LoadResult{}
	clean := strings.TrimSpace(root)
	if clean == "" {
		return res, errors.New("missing input path")
	}
	files, err := collectSessionFiles(ctx, clean)
	if err != nil {
		return res, err
	}
	states := make(map[string]scanledger.FileState, len(files))
	seen := map[string]bool{}
	for _, path := range files {
		if err := ctx.Err(); err != nil {
			return adapter.LoadResult{}, err
		}
		current, unchanged, derr := scanledger.Inspect(path, prior)
		if derr == nil && unchanged {
			// Already exported, and provably unchanged: no records.
			states[path] = current
			continue
		}
		records, issues, quarantined, err := loadSessionFile(ctx, path)
		if err != nil {
			return adapter.LoadResult{}, err
		}
		if derr == nil {
			states[path] = current
		}
		res.Quarantined += quarantined
		res.Issues = appendIssues(res.Issues, issues)
		for _, rec := range records {
			key := adapter.StringField(rec, "recordKey")
			if seen[key] {
				// The same session id + seq was already emitted from another
				// file (a pathological layout): never count it twice.
				res.Quarantined++
				res.Issues = appendIssues(res.Issues, []adapter.LineIssue{{File: path, Line: 0, Reason: "duplicate record key " + key + " skipped"}})
				continue
			}
			seen[key] = true
			res.Records = append(res.Records, rec)
		}
	}
	sort.Slice(res.Records, func(i, j int) bool {
		a := adapter.StringField(res.Records[i], "occurredAt")
		b := adapter.StringField(res.Records[j], "occurredAt")
		if a == b {
			return adapter.StringField(res.Records[i], "recordKey") < adapter.StringField(res.Records[j], "recordKey")
		}
		return a < b
	})
	res.ScanStates = states
	return res, nil
}

// appendIssues appends capped issues to the list.
func appendIssues(dst, src []adapter.LineIssue) []adapter.LineIssue {
	for _, issue := range src {
		if len(dst) >= maxIssues {
			return dst
		}
		dst = append(dst, issue)
	}
	return dst
}

// --- file discovery ---------------------------------------------------------

// collectSessionFiles walks the sessions root and returns the newest
// canonical session file per session directory, sorted by path. A missing
// root is a normal not-installed state and yields no files, no error. The
// context is checked before the root is resolved and once per walked
// directory entry, mirroring jsonl.FilesContext's coarse boundaries.
func collectSessionFiles(ctx context.Context, root string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := os.Stat(root); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	best := map[string]string{}
	var dirs []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if cancelErr := ctx.Err(); cancelErr != nil {
			return cancelErr
		}
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		gen, compressed, ok := parseSessionFileName(d.Name())
		if !ok {
			return nil
		}
		dir := filepath.Dir(path)
		if _, seen := best[dir]; !seen {
			dirs = append(dirs, dir)
			best[dir] = path
			return nil
		}
		if betterSessionFile(path, gen, compressed, best[dir]) {
			best[dir] = path
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	files := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		files = append(files, best[dir])
	}
	sort.Strings(files)
	return files, nil
}

// parseSessionFileName classifies one DSH session log file name:
// session.jsonl (generation 0), session.vN.jsonl (generation N >= 1, no
// leading zeros), each optionally .zstd-compressed. Anything else —
// session.lock, .tmp suffixes, wrong case, leading-zero generations — is
// not canonical and never contributes records.
func parseSessionFileName(name string) (gen int64, compressed bool, ok bool) {
	compressed = strings.HasSuffix(name, ".zstd")
	base := strings.TrimSuffix(name, ".zstd")
	if base == "session.jsonl" {
		return 0, compressed, true
	}
	if !strings.HasPrefix(base, "session.v") || !strings.HasSuffix(base, ".jsonl") {
		return 0, false, false
	}
	mid := strings.TrimSuffix(strings.TrimPrefix(base, "session.v"), ".jsonl")
	// Canonical generations are plain decimal digits with a nonzero leading
	// digit (DSH CANONICAL_LOG_FILENAME): v04, v+4, v4x are rejected.
	if mid == "" || mid[0] < '1' || mid[0] > '9' {
		return 0, false, false
	}
	for _, r := range mid {
		if r < '0' || r > '9' {
			return 0, false, false
		}
	}
	n, err := strconv.ParseInt(mid, 10, 64)
	if err != nil || n < 1 {
		return 0, false, false
	}
	return n, compressed, true
}

// betterSessionFile reports whether candidate (with its parsed generation
// and compression) supersedes incumbent: higher generation wins, and within
// the same generation the raw (uncompressed) file wins (the writer flushes
// raw before compressing).
func betterSessionFile(candidate string, candGen int64, candCompressed bool, incumbent string) bool {
	incGen, incCompressed, _ := parseSessionFileName(filepath.Base(incumbent))
	if candGen != incGen {
		return candGen > incGen
	}
	return incCompressed && !candCompressed
}

// --- line streaming ----------------------------------------------------------

// lineStream reads newline-delimited records from a raw or .zstd session
// file (concatenated zstd frames are decoded transparently). A trailing
// line without '\n' is treated as incomplete (mid-append) and is not
// consumed until the writer completes it.
type lineStream struct {
	f  *os.File
	zr *zstd.Decoder
	br *bufio.Reader
}

func openLines(path string) (*lineStream, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	ls := &lineStream{f: f, br: bufio.NewReaderSize(f, 1<<16)}
	if strings.HasSuffix(path, ".zstd") {
		zr, err := zstd.NewReader(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		ls.zr = zr
		ls.br = bufio.NewReaderSize(zr.IOReadCloser(), 1<<16)
	}
	return ls, nil
}

// next returns the next complete line (without its newline). ok is false at
// EOF or when the remaining bytes form an incomplete final line.
func (ls *lineStream) next() (string, bool, error) {
	line, err := ls.br.ReadBytes('\n')
	if err == io.EOF {
		// A final line without '\n' is mid-append; wait for the next scan.
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return strings.TrimRight(string(line), "\r\n"), true, nil
}

func (ls *lineStream) close() {
	if ls.zr != nil {
		ls.zr.Close()
	}
	ls.f.Close()
}

// --- per-file scan ------------------------------------------------------------

// sessionHeader is the first line of every session log.
type sessionHeader struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	IsSeeded bool   `json:"isSeeded"`
}

func parseHeader(line string) *sessionHeader {
	var h sessionHeader
	if err := json.Unmarshal([]byte(line), &h); err != nil || h.Type != "session" || h.ID == "" {
		return nil
	}
	return &h
}

// event is one durable session event row. seq is dense (header line 1 is
// followed by seq 0 at line 2) and time is epoch milliseconds.
type event struct {
	Type string          `json:"type"`
	Seq  int64           `json:"seq"`
	Time int64           `json:"time"`
	Data json.RawMessage `json:"data"`
}

type assistantData struct {
	Turn    *json.Number      `json:"turn"`
	Step    *json.Number      `json:"step"`
	Message *assistantMessage `json:"message"`
	Stream  []streamEntry     `json:"stream"`
	Usage   json.RawMessage   `json:"usage"`
}

type assistantMessage struct {
	ID     string     `json:"id"`
	Source *msgSource `json:"source"`
}

// msgSource is the message.source object of an assistant/message event.
// Model stays raw JSON so a non-string value can be inspected and reported
// without failing the whole event decode. Recorded sources also carry
// other keys (provider, replayState, ...); provider in particular does NOT
// gate model attribution — when an event records a model, that model is
// the event's recorded value regardless of its provider, and speculating
// about the backend from a missing provider is out of scope.
type msgSource struct {
	Model json.RawMessage `json:"model"`
}

// streamEntry is one entry of an event's compact stream. DSH writes usage
// entries directly ({type:"usage",usage:{...}}); the reference TokenRank
// research also documented a chunk-wrapped shape
// ({type:"chunk",chunk:{type:"usage",usage:{...}}}). Both are accepted.
type streamEntry struct {
	Type  string          `json:"type"`
	Chunk json.RawMessage `json:"chunk"`
	Usage json.RawMessage `json:"usage"`
}

type usageChunk struct {
	Type  string          `json:"type"`
	Usage json.RawMessage `json:"usage"`
}

// turn/step coordinates shared by the lifecycle events.
type turnStepData struct {
	Turn *json.Number `json:"turn"`
	Step *json.Number `json:"step"`
}

// stepLifecycle is the DSH attempt state for one (turn, step):
// "" = not started, "open" = attempt in flight, "finishClosed" = closed by
// assistant/attempt, "settled" = settled by assistant/message.
type stepLifecycle struct {
	state      string
	ended      bool
	retryArmed bool
}

// turnLifecycle tracks one turn's completeness and validity.
type turnLifecycle struct {
	started bool
	ended   bool
	invalid bool
	steps   map[int64]*stepLifecycle
}

// loadSessionFile scans one canonical session file and returns its records.
// The whole file is read even when errors appear mid-stream: malformed lines
// become issues, and a mid-file read error keeps the records parsed so far
// (the scan is stateless and retries on the next run). Cancellation is
// neither: a ctx.Err() from the per-line check aborts the whole scan with
// the bare context error so the caller discards everything.
func loadSessionFile(ctx context.Context, path string) ([]adapter.Record, []adapter.LineIssue, int, error) {
	var issues []adapter.LineIssue
	quarantined := 0
	addIssue := func(line int, reason string) {
		quarantined++
		if len(issues) < maxIssues {
			issues = append(issues, adapter.LineIssue{File: path, Line: line, Reason: reason})
		}
	}

	ls, err := openLines(path)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("dsh: open %s: %w", path, err)
	}
	defer ls.close()

	headerLine, ok, err := ls.next()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("dsh: read %s: %w", path, err)
	}
	if !ok {
		addIssue(1, "empty session file")
		return nil, issues, quarantined, nil
	}
	if !utf8.ValidString(headerLine) {
		// Go's JSON decoder silently replaces invalid UTF-8 bytes with
		// U+FFFD; rejecting the raw line first keeps recorded ids (and any
		// model value) from being rewritten under us.
		addIssue(1, "session header is not valid UTF-8")
		return nil, issues, quarantined, nil
	}
	hdr := parseHeader(headerLine)
	if hdr == nil {
		addIssue(1, "first line is not a session header")
		return nil, issues, quarantined, nil
	}

	// The lifecycle state machine runs over the WHOLE file (including an
	// inherited seeded prefix) so settlement bookkeeping stays aligned with
	// DSH's own derivation; records are buffered and only emitted for
	// complete, valid turns, then filtered by the seed cut.
	turns := map[int64]*turnLifecycle{}
	turn := func(n int64) *turnLifecycle {
		t := turns[n]
		if t == nil {
			t = &turnLifecycle{steps: map[int64]*stepLifecycle{}}
			turns[n] = t
		}
		return t
	}
	invalidate := func(t *turnLifecycle, line int, reason string) {
		if t.invalid {
			return
		}
		t.invalid = true
		addIssue(line, "turn invalidated: "+reason)
	}
	step := func(t *turnLifecycle, s int64) *stepLifecycle {
		st := t.steps[s]
		if st == nil {
			st = &stepLifecycle{}
			t.steps[s] = st
		}
		return st
	}

	type pendingRecord struct {
		line   int
		turn   int64
		record adapter.Record
		// diag is the value-free reason carried when the record's model is
		// unattributable ("unknown"); it becomes a local LineIssue only if
		// the record is actually emitted.
		diag string
	}
	var pending []pendingRecord
	cut := -1 // 1-based file line through which everything is inherited
	lineNo := 1

	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, 0, err
		}
		line, ok, err := ls.next()
		if err != nil {
			// Keep what parsed so far; the next run retries the file.
			addIssue(lineNo+1, "read error: "+err.Error())
			break
		}
		if !ok {
			break
		}
		lineNo++
		if !utf8.ValidString(line) {
			// Same pre-decode guard as the header: an invalid-UTF-8 line
			// must be rejected as malformed, never decoded with silent
			// U+FFFD rewrites. The affected turn then fails closed through
			// the lifecycle (its settlement never happened).
			addIssue(lineNo, "malformed JSON event line (invalid UTF-8)")
			continue
		}
		var ev event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			addIssue(lineNo, "malformed JSON event line")
			continue
		}
		if hdr.IsSeeded && ev.Type == "session/end-seed" {
			var marker struct {
				Inherited bool `json:"inherited"`
			}
			if len(ev.Data) > 0 && json.Unmarshal(ev.Data, &marker) == nil && marker.Inherited {
				// The LAST inherited marker wins (fork chains re-seed).
				cut = lineNo
			}
			continue
		}

		switch ev.Type {
		case "turn/start", "turn/end":
			var data turnStepData
			decoded := len(ev.Data) > 0 && json.Unmarshal(ev.Data, &data) == nil
			n, okTurn := numberInt(data.Turn)
			if !decoded || !okTurn {
				addIssue(lineNo, ev.Type+" without turn")
				continue
			}
			t := turn(n)
			if ev.Type == "turn/start" {
				if t.started || t.ended {
					invalidate(t, lineNo, "duplicate or out-of-order turn/start")
				} else {
					t.started = true
				}
				continue
			}
			if !t.started || t.ended {
				invalidate(t, lineNo, "turn/end without a started turn")
				continue
			}
			for _, st := range t.steps {
				if st.state == "open" {
					invalidate(t, lineNo, "turn/end with an open attempt")
					break
				}
				if !st.ended {
					invalidate(t, lineNo, "turn/end with an unfinished step")
					break
				}
			}
			if !t.invalid {
				t.ended = true
			}
		case "step/start", "step/end", "llm/retry", "llm/retry-started", "assistant/message", "assistant/attempt":
			var data turnStepData
			decoded := len(ev.Data) > 0 && json.Unmarshal(ev.Data, &data) == nil
			n, okTurn := numberInt(data.Turn)
			s, okStep := numberInt(data.Step)
			if !decoded || !okTurn {
				addIssue(lineNo, ev.Type+" without turn")
				continue
			}
			t := turn(n)
			if !okStep {
				invalidate(t, lineNo, ev.Type+" without step")
				continue
			}
			if t.invalid {
				continue
			}
			if !t.started || t.ended {
				invalidate(t, lineNo, ev.Type+" outside turn boundaries")
				continue
			}
			st := step(t, s)
			switch ev.Type {
			case "step/start":
				if st.state != "" || st.ended {
					invalidate(t, lineNo, "step/start on an existing step")
				} else {
					st.state = "open"
				}
			case "assistant/message", "assistant/attempt":
				if st.state != "open" {
					// A settlement requires an open attempt: a duplicate
					// settlement (state.kind !== 'open' in DSH) invalidates
					// the whole turn rather than double counting.
					invalidate(t, lineNo, ev.Type+" without an open attempt")
					continue
				}
				if ev.Type == "assistant/attempt" {
					st.state = "finishClosed"
				} else {
					st.state = "settled"
				}
				var ad assistantData
				if len(ev.Data) > 0 {
					if err := json.Unmarshal(ev.Data, &ad); err != nil {
						addIssue(lineNo, "malformed "+ev.Type+" data")
						continue
					}
				}
				rec, reason, diag := parseSettlement(ev, ad, hdr.ID)
				if rec == nil {
					if reason != "" {
						invalidate(t, lineNo, reason)
					}
					continue
				}
				pending = append(pending, pendingRecord{line: lineNo, turn: n, record: rec, diag: diag})
			case "llm/retry":
				if st.state != "finishClosed" || st.retryArmed {
					invalidate(t, lineNo, "llm/retry without a finalized attempt")
				} else {
					st.retryArmed = true
				}
			case "llm/retry-started":
				if st.ended || !st.retryArmed || (st.state != "finishClosed" && st.state != "settled") {
					invalidate(t, lineNo, "llm/retry-started without an armed retry")
				} else {
					st.state = "open"
					st.retryArmed = false
				}
			case "step/end":
				// A step may end with an armed retry that never started:
				// DSH's state machine ends such steps legally
				// (settled-by-retry → idle), so the failed attempt's usage
				// stays attributed.
				if (st.state != "finishClosed" && st.state != "settled") || st.ended {
					invalidate(t, lineNo, "step/end without a finalized attempt")
				} else {
					st.ended = true
				}
			}
		default:
			// user/message and other event types carry no attempt
			// lifecycle meaning here.
		}
	}

	if hdr.IsSeeded && cut < 0 {
		// A seeded header without a marker cannot be attributed safely:
		// emit nothing for the file (fail closed, never double-count).
		addIssue(1, "seeded session has no end-seed marker")
		return nil, issues, quarantined, nil
	}

	records := make([]adapter.Record, 0, len(pending))
	for _, p := range pending {
		t := turns[p.turn]
		if t == nil || t.invalid || !t.started || !t.ended {
			// Incomplete (torn tail / live turn) or invalid turn: the whole
			// turn is unaccounted, exactly like token-meter's undefined.
			continue
		}
		if cut > 0 && p.line <= cut {
			// Inherited prefix: already counted in the owning session's log.
			continue
		}
		if p.diag != "" {
			// Local, value-free diagnostic for an emitted record whose
			// model is unattributable: the usage still exports (nothing is
			// quarantined), but the reason stays visible to the operator.
			if len(issues) < maxIssues {
				issues = append(issues, adapter.LineIssue{File: path, Line: p.line, Reason: p.diag})
			}
		}
		records = append(records, p.record)
	}
	return records, issues, quarantined, nil
}

// numberInt converts a JSON number coordinate (turn/step) to int64.
func numberInt(n *json.Number) (int64, bool) {
	if n == nil {
		return 0, false
	}
	v, err := n.Int64()
	if err != nil {
		return 0, false
	}
	return v, true
}

// parseSettlement builds one delta record for an attempt-closing event that
// carries a valid usage sample, or returns nil with an optional issue
// reason. Only assistant/message and assistant/attempt reach this function;
// llm/retry closes attempts whose sample was already finalized by a prior
// assistant event, so counting its stream would double count. The model is
// attributed by recordedModel (the event's own recorded value, verbatim):
// an illegal recorded model returns a reason and fails the whole turn
// closed; an unattributable model yields "unknown" plus a value-free diag
// that becomes a local LineIssue when the record is emitted.
func parseSettlement(ev event, data assistantData, sessionID string) (adapter.Record, string, string) {
	attribution := recordedModel(ev.Type, data.Message)
	if attribution.fatal != "" {
		return nil, attribution.fatal, ""
	}
	model := attribution.model
	var sample json.RawMessage
	if ev.Type == "assistant/message" {
		// Direct data.usage wins; explicit null falls back to the stream
		// (JS ?? semantics, turn-usage.js L104-108).
		sample = data.Usage
		if isJSONNull(sample) {
			sample = nil
		}
	}
	if sample == nil {
		sample = lastUsageChunk(data.Stream)
	}
	if sample == nil {
		return nil, "missing usage sample", ""
	}
	counts, ok, reason := evaluateSample(sample)
	if !ok {
		return nil, reason, ""
	}
	if allMissingOrZero(counts.input, counts.cacheRead, counts.cacheWrite, counts.output) {
		// Nothing reportable after derivation; no zero record is emitted.
		return nil, "", ""
	}
	// reasoningTokens is a subset of outputTokens; neither it nor
	// totalTokens is uploaded (totalTokens was consumed above to prove the
	// omitted cache buckets).
	localID := sessionID + "|" + strconv.FormatInt(ev.Seq, 10)
	return adapter.Record{
		"recordKey":      recordKeyDomain + ":" + adapter.ShortHash(localID),
		"groupKey":       groupKeyDomain + ":" + adapter.ShortHash(sessionID),
		"resetKey":       nil,
		"kind":           "delta",
		"occurredAt":     time.UnixMilli(ev.Time).UTC().Format(time.RFC3339),
		"tool":           dshTool,
		"model":          model,
		"input":          optCount(counts.input),
		"cacheRead":      optCount(counts.cacheRead),
		"cacheWrite":     optCount(counts.cacheWrite),
		"output":         optCount(counts.output),
		"adapterVersion": adapterVersion,
		"sourceType":     adapter.DeepSeekHarnessSource,
	}, "", attribution.diag
}

// jsonString decodes a raw JSON value that must be a string. ok is false
// for any non-string value (number, boolean, object, array); a JSON null
// or an absent key yields ("", false) as well.
func jsonString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// modelAttribution is the outcome of attributing one settlement's model.
type modelAttribution struct {
	// model is the attributed value; "unknown" when unattributable.
	model string
	// fatal is non-empty when the recorded model is present but illegal:
	// the caller fails the whole turn closed and reports it.
	fatal string
	// diag is a value-free reason carried when model == "unknown"; it
	// becomes a local LineIssue if the record is emitted.
	diag string
}

// recordedModel attributes the model of one attempt-closing event from the
// value the event itself recorded, keeping it verbatim.
//
//   - assistant/attempt never attributes: deriveTurnTokenUsage closes
//     attempts without a route, and recorded history shows attempt events
//     carry no message source at all.
//   - assistant/message attributes from message.source.model only: a
//     missing or JSON-null model is not reliably attributable ("unknown";
//     the usage still counts). The recorded provider never gates the
//     attribution — when the event records a model, that model IS the
//     event's recorded value, and a missing provider must not drop it.
//   - A non-empty model string is kept VERBATIM — route aliases (main,
//     coder, ...) and explicit model ids alike; there is no allowlist and
//     no rewriting.
//   - A model that is present but fails the shared wire validation
//     (adapter.ValidateModel: the explicit empty string, whitespace-only,
//     control characters, over 128 bytes, non-string JSON) must not be
//     silently rewritten to "unknown": a fatal reason is returned so the
//     caller fails the whole turn closed and reports the value.
func recordedModel(evType string, message *assistantMessage) modelAttribution {
	if evType != "assistant/message" {
		return modelAttribution{model: "unknown", diag: evType + " event carries no message source; model reported unknown"}
	}
	if message == nil || message.Source == nil {
		return modelAttribution{model: "unknown", diag: "assistant/message event has no message source; model reported unknown"}
	}
	if len(message.Source.Model) == 0 || isJSONNull(message.Source.Model) {
		return modelAttribution{model: "unknown", diag: "assistant/message event has no recorded model; model reported unknown"}
	}
	model, isString := jsonString(message.Source.Model)
	if !isString {
		return modelAttribution{model: "unknown", fatal: "recorded model is not a JSON string"}
	}
	if err := adapter.ValidateModel(model); err != nil {
		return modelAttribution{model: "unknown", fatal: "invalid recorded model: " + err.Error()}
	}
	return modelAttribution{model: model}
}

// lastUsageChunk returns the usage payload of the last usage entry in the
// event's compact stream. The accumulator pushes exactly one final usage
// entry per attempt; the last one is authoritative.
func lastUsageChunk(stream []streamEntry) json.RawMessage {
	var last json.RawMessage
	for _, entry := range stream {
		switch entry.Type {
		case "usage":
			if len(entry.Usage) > 0 && !isJSONNull(entry.Usage) {
				last = entry.Usage
			}
		case "chunk":
			if len(entry.Chunk) == 0 {
				continue
			}
			var chunk usageChunk
			if json.Unmarshal(entry.Chunk, &chunk) == nil && chunk.Type == "usage" && len(chunk.Usage) > 0 {
				last = chunk.Usage
			}
		}
	}
	return last
}

// isJSONNull reports whether a raw JSON value is an explicit null.
func isJSONNull(raw json.RawMessage) bool {
	return len(raw) == 4 && string(raw) == "null"
}

// --- usage validation (DSH normalizeUsage alignment) --------------------------

// sampleCounts is the validated, derived uploadable bucket set of one usage
// sample. Nil pointers are unknown and upload as null.
type sampleCounts struct {
	input, cacheRead, cacheWrite, output *int64
}

// evaluateSample validates one usage sample the way DSH's normalizeUsage
// does and derives omitted cache buckets from totalTokens. It returns
// ok=false with a reason when the sample is invalid: inputTokens and
// outputTokens must be present non-negative JS safe integers;
// cacheReadTokens/cacheWriteTokens/reasoningTokens/totalTokens are optional
// but must be valid when present; reasoningTokens must not exceed
// outputTokens (it is a subset); totalTokens must not contradict the known
// buckets. Invalid samples are rejected whole — partial counts are never
// uploaded.
//
// Omitted-cache derivation (DSH persistence property): mapUsage omits a
// cache key exactly when the provider reported zero, and totalTokens is the
// exact bucket sum input+output+cacheRead+cacheWrite. With omitted buckets
// counted as zero, residual = total − input − output − known buckets:
// residual 0 proves every omitted bucket zero; a safe positive residual
// attributes to the single omitted bucket; a residual with both buckets
// omitted cannot be attributed and stays unknown (null). This shortcut is
// valid only for DSH durable samples and must not be generalized to other
// tools or to explicitly invalid values. Derivation runs BEFORE the
// nothing-reportable check so cache-only residuals are never lost.
func evaluateSample(sample json.RawMessage) (sampleCounts, bool, string) {
	counts, err := usageCounts(sample)
	if err != nil {
		return sampleCounts{}, false, "malformed usage sample"
	}
	input := safeCount(counts, "inputTokens")
	if input == nil {
		return sampleCounts{}, false, "invalid inputTokens"
	}
	output := safeCount(counts, "outputTokens")
	if output == nil {
		return sampleCounts{}, false, "invalid outputTokens"
	}
	cacheRead := safeCount(counts, "cacheReadTokens")
	if keyPresent(counts, "cacheReadTokens") && cacheRead == nil {
		return sampleCounts{}, false, "invalid cacheReadTokens"
	}
	cacheWrite := safeCount(counts, "cacheWriteTokens")
	if keyPresent(counts, "cacheWriteTokens") && cacheWrite == nil {
		return sampleCounts{}, false, "invalid cacheWriteTokens"
	}
	if keyPresent(counts, "reasoningTokens") {
		reasoning := safeCount(counts, "reasoningTokens")
		if reasoning == nil {
			return sampleCounts{}, false, "invalid reasoningTokens"
		}
		if *reasoning > *output {
			return sampleCounts{}, false, "reasoningTokens exceeds outputTokens"
		}
	}
	if keyPresent(counts, "totalTokens") {
		total := safeCount(counts, "totalTokens")
		if total == nil {
			return sampleCounts{}, false, "invalid totalTokens"
		}
		read, write := int64(0), int64(0)
		if cacheRead != nil {
			read = *cacheRead
		}
		if cacheWrite != nil {
			write = *cacheWrite
		}
		residual := *total - *input - *output - read - write
		switch {
		case residual < 0:
			return sampleCounts{}, false, "totalTokens below known buckets"
		case residual == 0:
			// Conforming sample: omitted buckets are proven zero.
			if cacheRead == nil {
				z := int64(0)
				cacheRead = &z
			}
			if cacheWrite == nil {
				z := int64(0)
				cacheWrite = &z
			}
		default:
			if cacheRead != nil && cacheWrite != nil {
				return sampleCounts{}, false, "totalTokens exceeds known buckets"
			}
			if cacheRead == nil && cacheWrite == nil {
				// Both buckets omitted: the residual cannot be attributed
				// between them; both stay unknown (null), not zero.
			} else if cacheWrite == nil {
				cw := residual
				cacheWrite = &cw
			} else {
				cr := residual
				cacheRead = &cr
			}
		}
	}
	return sampleCounts{input: input, cacheRead: cacheRead, cacheWrite: cacheWrite, output: output}, true, ""
}

// usageCounts decodes a usage object into raw JSON values, preserving the
// distinction between a missing key, a JSON string, and a numeric literal
// (DSH isCount requires typeof number — quoted numbers are invalid).
func usageCounts(sample json.RawMessage) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(sample, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// safeCount mirrors DSH isCount: a non-negative safe integer (JS
// Number.isSafeInteger) written as a JSON number literal. JSON strings,
// booleans, null and objects are not numbers and yield nil; fractional or
// exponent forms fail integer parsing and yield nil.
func safeCount(m map[string]json.RawMessage, key string) *int64 {
	raw, ok := m[key]
	if !ok || len(raw) == 0 {
		return nil
	}
	if raw[0] != '-' && (raw[0] < '0' || raw[0] > '9') {
		// A quoted number ("100"), true, null or an object: not a number.
		return nil
	}
	n, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || n < 0 || n > maxSafeInteger {
		return nil
	}
	return &n
}

// keyPresent distinguishes a key the persistence layer omitted (which, for
// DSH cache buckets, encodes zero) from a key present with an invalid value
// (which must stay unknown and must not be derived).
func keyPresent(m map[string]json.RawMessage, key string) bool {
	_, ok := m[key]
	return ok
}

// allMissingOrZero reports whether every count is absent or zero, in which
// case the attempt has nothing reportable and is skipped. It must run only
// AFTER omitted-cache derivation.
func allMissingOrZero(counts ...*int64) bool {
	for _, c := range counts {
		if c != nil && *c != 0 {
			return false
		}
	}
	return true
}

// optCount renders one count for a record; nil stays nil (unknown).
func optCount(p *int64) any {
	if p == nil {
		return nil
	}
	return strconv.FormatInt(*p, 10)
}
