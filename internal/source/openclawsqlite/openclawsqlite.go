package openclawsqlite

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/source/adapter"
)

const (
	openClawTool           = "OpenClaw"
	openClawAdapterVersion = "openclaw-sqlite-v1"
)

type openClawUsage struct {
	Input      uint64
	CacheRead  uint64
	CacheWrite uint64
	Output     uint64
}

type openClawObservation struct {
	DBPath    string
	RowID     int64
	SessionID string
	Timestamp time.Time
	Model     string
	Usage     openClawUsage
}

// LoadRecords reads OpenClaw 2026.9+ per-agent SQLite transcript stores from
// an explicitly granted root. It scans for openclaw-agent.sqlite files and
// reads transcript_events.event_json rows. Prompt/response content in other
// event fields is ignored; only usage/model/time/session identity fields are
// copied into TokTrail records. Rows stored only in compressed event_zstd form
// are not decoded in this first version. It keeps the historical context-free
// signature for direct callers; the adapter's Load threads the caller's
// cancellation scope through adapter.Options.ContextOrBackground into
// loadRecordsContext.
func LoadRecords(input string) (adapter.LoadResult, error) {
	return loadRecordsContext(context.Background(), input)
}

// loadRecordsContext scans with cancellation support: the context is checked
// before the scan starts, once per database file and once per assembled
// record, and readDB derives its per-database deadline from it. On
// cancellation it returns ctx.Err() (matching errors.Is(context.Canceled) or
// errors.Is(context.DeadlineExceeded)) and an empty result, so a scan cut
// short by its deadline never commits partial records.
func loadRecordsContext(ctx context.Context, input string) (adapter.LoadResult, error) {
	var result adapter.LoadResult
	if err := ctx.Err(); err != nil {
		return result, err
	}
	files, err := sqliteFiles(input)
	if err != nil {
		return result, err
	}
	records := map[string]adapter.Record{}
	conflicts := map[string]bool{}
	issue := func(file string, reason string) {
		result.Quarantined++
		if len(result.Issues) < 50 {
			result.Issues = append(result.Issues, adapter.LineIssue{File: "file:" + adapter.ShortHash(file), Line: 0, Reason: reason})
		}
	}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return adapter.LoadResult{}, err
		}
		obs, skippedCompressed, err := readDB(ctx, file)
		if err != nil {
			return adapter.LoadResult{}, err
		}
		if skippedCompressed > 0 {
			issue(file, fmt.Sprintf("%d compressed transcript_events rows skipped", skippedCompressed))
		}
		for _, ob := range obs {
			if err := ctx.Err(); err != nil {
				return adapter.LoadResult{}, err
			}
			rec := openClawRecord(ob)
			key := adapter.StringField(rec, "recordKey")
			if conflicts[key] {
				continue
			}
			if old, exists := records[key]; exists {
				if !sameRecord(old, rec) {
					delete(records, key)
					conflicts[key] = true
					issue(file, "conflicting usage for same OpenClaw transcript event")
				}
				continue
			}
			records[key] = rec
		}
	}
	for _, record := range records {
		result.Records = append(result.Records, record)
	}
	sort.Slice(result.Records, func(i, j int) bool {
		a, b := result.Records[i], result.Records[j]
		if adapter.StringField(a, "occurredAt") == adapter.StringField(b, "occurredAt") {
			return adapter.StringField(a, "recordKey") < adapter.StringField(b, "recordKey")
		}
		return adapter.StringField(a, "occurredAt") < adapter.StringField(b, "occurredAt")
	})
	return result, nil
}

func sqliteFiles(input string) ([]string, error) {
	clean := strings.TrimSpace(input)
	info, err := os.Stat(clean)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		if strings.EqualFold(filepath.Base(clean), "openclaw-agent.sqlite") || strings.EqualFold(filepath.Ext(clean), ".sqlite") {
			return []string{clean}, nil
		}
		return nil, fmt.Errorf("OpenClaw input file %q must be openclaw-agent.sqlite or .sqlite", clean)
	}
	var files []string
	if err := filepath.WalkDir(clean, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Base(path), "openclaw-agent.sqlite") {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

// readDB scans one OpenClaw transcript database. It derives the historical
// 30-second per-database deadline from ctx, so a caller-supplied
// cancellation or a shorter parent deadline propagates into every query and
// row below; a plain context.Background() keeps the exact pre-context
// behavior. Each row is also checked for cancellation before it is parsed.
func readDB(ctx context.Context, path string) ([]openClawObservation, int, error) {
	db, err := sql.Open("sqlite", sqliteReadOnlyDSN(path))
	if err != nil {
		return nil, 0, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if ok, err := hasTable(ctx, db, "transcript_events"); err != nil {
		return nil, 0, contextErr(ctx, err)
	} else if !ok {
		return nil, 0, fmt.Errorf("OpenClaw DB missing transcript_events table")
	}
	skipped := 0
	if hasZstd, err := hasColumn(ctx, db, "transcript_events", "event_zstd"); err == nil && hasZstd {
		_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM transcript_events WHERE event_json IS NULL AND event_zstd IS NOT NULL`).Scan(&skipped)
	}
	if scanQueryHook != nil {
		scanQueryHook(ctx)
	}
	rows, err := db.QueryContext(ctx, `SELECT rowid, COALESCE(session_id, ''), COALESCE(created_at, 0), event_json FROM transcript_events WHERE event_json IS NOT NULL ORDER BY rowid ASC`)
	if err != nil {
		return nil, skipped, contextErr(ctx, fmt.Errorf("query OpenClaw transcript_events: %w", err))
	}
	defer rows.Close()
	var out []openClawObservation
	for rows.Next() {
		if scanRowHook != nil {
			scanRowHook(ctx)
		}
		if err := ctx.Err(); err != nil {
			return nil, skipped, err
		}
		var rowID int64
		var sessionID string
		var createdRaw any
		var eventRaw any
		if err := rows.Scan(&rowID, &sessionID, &createdRaw, &eventRaw); err != nil {
			return nil, skipped, err
		}
		text := valueString(eventRaw)
		if strings.TrimSpace(text) == "" {
			continue
		}
		ob, ok, err := parseEvent(path, rowID, sessionID, createdRaw, text)
		if err != nil {
			return nil, skipped, err
		}
		if ok {
			out = append(out, ob)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, skipped, contextErr(ctx, err)
	}
	return out, skipped, nil
}

// contextErr reports the context's own error whenever it is done, so callers
// can always match cancellation with errors.Is regardless of how the driver
// wrapped the failure; otherwise it passes the original error through.
func contextErr(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}

// Test-only scan hooks; both stay nil in production and are never set
// outside this package's tests. They exist so cancellation tests can fire
// the caller's scope at a chosen checkpoint (after the schema probe but
// before the main query, or at a specific row) instead of racing a real
// timer across an oversized fixture. scanQueryHook runs immediately before
// the main transcript query; scanRowHook runs once per row iteration,
// before the per-row context check, and receives the per-database scan
// scope the query runs under. Neither hook can alter control flow beyond
// the cancellation the context itself reports.
var (
	scanQueryHook func(ctx context.Context)
	scanRowHook   func(ctx context.Context)
)

func parseEvent(path string, rowID int64, sessionID string, createdRaw any, text string) (openClawObservation, bool, error) {
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	var event map[string]any
	if err := decoder.Decode(&event); err != nil {
		return openClawObservation{}, false, fmt.Errorf("OpenClaw transcript row %d invalid JSON: %w", rowID, err)
	}
	usage := firstObject(event["usage"], object(event["message"])["usage"], object(event["payload"])["usage"])
	if len(usage) == 0 {
		return openClawObservation{}, false, nil
	}
	counts, reason := parseUsage(usage)
	if reason != "" {
		return openClawObservation{}, false, fmt.Errorf("OpenClaw transcript row %d %s", rowID, reason)
	}
	if counts.Input == 0 && counts.CacheRead == 0 && counts.CacheWrite == 0 && counts.Output == 0 {
		return openClawObservation{}, false, nil
	}
	model, missing, ok := modelFromEvent(event)
	if !ok {
		return openClawObservation{}, false, fmt.Errorf("OpenClaw transcript row %d invalid model", rowID)
	}
	if missing {
		model = "unknown"
	}
	timestamp, ok := timestampFromEvent(event)
	if !ok {
		timestamp, ok = parseOpenClawTime(createdRaw)
	}
	if !ok {
		return openClawObservation{}, false, fmt.Errorf("OpenClaw transcript row %d missing timestamp", rowID)
	}
	if sessionID == "" {
		sessionID = firstString(event["sessionId"], event["session_id"])
	}
	return openClawObservation{DBPath: path, RowID: rowID, SessionID: sessionID, Timestamp: timestamp, Model: model, Usage: counts}, true, nil
}

func parseUsage(usage map[string]any) (openClawUsage, string) {
	input, ok := firstUint(usage, "input_tokens", "inputTokens", "prompt_tokens", "promptTokens", "input")
	if !ok {
		return openClawUsage{}, "invalid input token counter"
	}
	output, ok := firstUint(usage, "output_tokens", "outputTokens", "completion_tokens", "completionTokens", "output")
	if !ok {
		return openClawUsage{}, "invalid output token counter"
	}
	cacheRead, ok := firstUint(usage, "cache_read_tokens", "cacheReadTokens", "cached_input_tokens", "cachedInputTokens", "cacheRead")
	if !ok {
		return openClawUsage{}, "invalid cache read token counter"
	}
	cacheWrite, ok := firstUint(usage, "cache_write_tokens", "cacheWriteTokens", "cache_creation_input_tokens", "cacheCreationInputTokens", "cacheWrite")
	if !ok {
		return openClawUsage{}, "invalid cache write token counter"
	}
	return openClawUsage{Input: input, CacheRead: cacheRead, CacheWrite: cacheWrite, Output: output}, ""
}

func firstUint(m map[string]any, names ...string) (uint64, bool) {
	for _, name := range names {
		value, exists := m[name]
		if !exists || value == nil {
			continue
		}
		return uintAny(value)
	}
	return 0, true
}

func modelFromEvent(event map[string]any) (string, bool, bool) {
	msg := object(event["message"])
	payload := object(event["payload"])
	for _, value := range []any{event["responseModel"], event["model"], event["modelId"], event["model_id"], msg["responseModel"], msg["model"], msg["modelId"], payload["responseModel"], payload["model"], payload["modelId"]} {
		if value == nil {
			continue
		}
		if err := adapter.ValidateModel(value); err != nil {
			return "", false, false
		}
		return value.(string), false, true
	}
	return "", true, true
}

func timestampFromEvent(event map[string]any) (time.Time, bool) {
	msg := object(event["message"])
	payload := object(event["payload"])
	for _, value := range []any{event["timestamp"], event["time"], event["createdAt"], event["created_at"], msg["timestamp"], payload["timestamp"]} {
		if value == nil {
			continue
		}
		return parseOpenClawTime(value)
	}
	return time.Time{}, false
}

func parseOpenClawTime(value any) (time.Time, bool) {
	if s := adapter.StringAny(value); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t, true
		}
		if n, ok := adapter.ParseUint(s); ok {
			return unixOpenClawTime(n), true
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil && f >= 0 {
			return unixOpenClawFloatSeconds(f), true
		}
		return time.Time{}, false
	}
	if n, ok := uintAny(value); ok {
		return unixOpenClawTime(n), true
	}
	if num, ok := value.(json.Number); ok {
		if f, err := strconv.ParseFloat(num.String(), 64); err == nil && f >= 0 {
			return unixOpenClawFloatSeconds(f), true
		}
	}
	return time.Time{}, false
}

func unixOpenClawTime(n uint64) time.Time {
	if n > 100000000000 {
		return time.Unix(0, int64(n)*int64(time.Millisecond)).UTC()
	}
	return time.Unix(int64(n), 0).UTC()
}

func unixOpenClawFloatSeconds(seconds float64) time.Time {
	sec := int64(seconds)
	nsec := int64((seconds - float64(sec)) * 1e9)
	return time.Unix(sec, nsec).UTC()
}

func uintAny(value any) (uint64, bool) {
	switch v := value.(type) {
	case int64:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case int:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case []byte:
		return adapter.ParseUint(strings.TrimSpace(string(v)))
	case string:
		return adapter.ParseUint(strings.TrimSpace(v))
	default:
		return adapter.UintAny(value)
	}
}

func openClawRecord(obs openClawObservation) adapter.Record {
	identity := fmt.Sprintf("%s\x00%d", obs.DBPath, obs.RowID)
	return adapter.Record{
		"recordKey":      adapter.OpenClawSQLiteSource + ":" + adapter.ShortHash(identity),
		"groupKey":       "openclaw-event:" + adapter.ShortHash(identity),
		"resetKey":       nil,
		"kind":           "delta",
		"occurredAt":     obs.Timestamp.UTC().Format(time.RFC3339),
		"tool":           openClawTool,
		"model":          obs.Model,
		"input":          strconv.FormatUint(obs.Usage.Input, 10),
		"cacheRead":      strconv.FormatUint(obs.Usage.CacheRead, 10),
		"cacheWrite":     strconv.FormatUint(obs.Usage.CacheWrite, 10),
		"output":         strconv.FormatUint(obs.Usage.Output, 10),
		"adapterVersion": openClawAdapterVersion,
		"sourceType":     adapter.OpenClawSQLiteSource,
	}
}

func hasTable(ctx context.Context, db *sql.DB, name string) (bool, error) {
	row := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name)
	var count int
	if err := row.Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func hasColumn(ctx context.Context, db *sql.DB, table, column string) (bool, error) {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid any
		var name string
		var typ, notnull, dflt, pk any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if strings.EqualFold(name, column) {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	return false, nil
}

func sqliteReadOnlyDSN(path string) string {
	var b strings.Builder
	b.WriteString("file:")
	for i := 0; i < len(path); i++ {
		c := path[i]
		switch {
		case runtime.GOOS == "windows" && c == '\\':
			b.WriteByte('/')
		case c == '%' || c == '?' || c == '#' || c == ' ':
			fmt.Fprintf(&b, "%%%02X", c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteString("?mode=ro&immutable=1")
	return b.String()
}

func Adapter() adapter.Adapter {
	return adapter.Adapter{
		Source:      adapter.OpenClawSQLiteSource,
		Description: "OpenClaw transcript_events SQLite",
		Load: func(opt adapter.Options) (adapter.LoadResult, error) {
			return loadRecordsContext(opt.ContextOrBackground(), opt.Input)
		},
		FilterForExport: func(opt adapter.Options, records []adapter.Record) ([]adapter.Record, error) {
			ctx := opt.ContextOrBackground()
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if strings.TrimSpace(opt.StateDir) == "" {
				return records, nil
			}
			return filterKnownRecordsContext(ctx, opt.StateDir, records)
		},
	}
}

// filterKnownRecordsContext checks immutable outbox and quarantine records,
// so repeated full rescans cannot re-export known OpenClaw records. The
// context is consulted at coarse boundaries (entry, per outbox batch, per
// stored record, before the quarantine load, per quarantine entry, per
// fresh record); on cancellation it returns ctx.Err() (matchable with
// errors.Is(err, context.Canceled) or errors.Is(err, context.DeadlineExceeded))
// and no partial result — the fresh slice accumulated so far is discarded, so
// a filter cut short never exports a prefix of the scan. A nil
// Options.Context reaches here as context.Background() via
// ContextOrBackground and keeps the exact pre-cancellation behavior.
func filterKnownRecordsContext(ctx context.Context, stateDir string, records []adapter.Record) ([]adapter.Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	known := make(map[string][]byte)
	remember := func(raw []byte) error {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var record adapter.Record
		if err := decoder.Decode(&record); err != nil {
			return err
		}
		key := adapter.StringField(record, "recordKey")
		if key == "" {
			return fmt.Errorf("stored OpenClaw record has no key")
		}
		canonical, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if old, exists := known[key]; exists && !bytes.Equal(old, canonical) {
			return fmt.Errorf("stored OpenClaw record %s has conflicting content", key)
		}
		known[key] = canonical
		return nil
	}
	ledger, err := outbox.New(stateDir).Load()
	if err != nil {
		return nil, err
	}
	for _, entry := range ledger.Batches {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.Source != adapter.OpenClawSQLiteSource {
			continue
		}
		switch entry.Status {
		case outbox.StatusPending, outbox.StatusSynced, outbox.StatusReorganized:
		default:
			return nil, fmt.Errorf("unknown OpenClaw outbox status %q", entry.Status)
		}
		raw, err := os.ReadFile(entry.File)
		if err != nil {
			return nil, fmt.Errorf("read OpenClaw history batch %s: %w", entry.BatchID, err)
		}
		var batch struct {
			BatchID string            `json:"batchId"`
			Records []json.RawMessage `json:"records"`
		}
		if err := json.Unmarshal(raw, &batch); err != nil {
			return nil, err
		}
		if batch.BatchID != entry.BatchID {
			return nil, fmt.Errorf("OpenClaw history batch identity mismatch")
		}
		for _, record := range batch.Records {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if err := remember(record); err != nil {
				return nil, err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entries, err := quarantine.New(stateDir).Load()
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.Source == adapter.OpenClawSQLiteSource {
			if err := remember(entry.Record); err != nil {
				return nil, err
			}
		}
	}
	fresh := make([]adapter.Record, 0, len(records))
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key := adapter.StringField(record, "recordKey")
		canonical, err := json.Marshal(record)
		if err != nil {
			return nil, err
		}
		if previous, exists := known[key]; exists {
			if !bytes.Equal(previous, canonical) {
				return nil, fmt.Errorf("OpenClaw record %s changed after export; refusing to overwrite immutable history", key)
			}
			continue
		}
		fresh = append(fresh, record)
	}
	return fresh, nil
}

func object(value any) map[string]any {
	m, _ := value.(map[string]any)
	return m
}

func firstObject(values ...any) map[string]any {
	for _, v := range values {
		if m := object(v); len(m) > 0 {
			return m
		}
	}
	return nil
}

func firstString(values ...any) string {
	for _, v := range values {
		if s := adapter.StringAny(v); s != "" {
			return s
		}
	}
	return ""
}

func valueString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return ""
	}
}

func sameRecord(a, b adapter.Record) bool {
	ca, errA := json.Marshal(a)
	cb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ca, cb)
}
