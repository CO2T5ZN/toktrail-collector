package hermessqlite

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
	hermesTool           = "Hermes Agent"
	hermesAdapterVersion = "hermes-sqlite-v1"
)

type hermesUsage struct {
	Input      uint64
	CacheRead  uint64
	CacheWrite uint64
	Output     uint64
}

type hermesObservation struct {
	ID        string
	Model     string
	StartedAt time.Time
	Usage     hermesUsage
	File      string
}

// LoadRecords reads Hermes Agent local usage from an explicitly granted
// Hermes home directory or state.db file. It prefers the per-model
// session_model_usage table and falls back to the sessions summary table for
// older schemas. It does not query messages, FTS content, memories, gateway
// routes, credentials, or prompt/response bodies. It keeps the historical
// context-free signature for direct callers; the adapter's Load threads the
// caller's cancellation scope through adapter.Options.ContextOrBackground
// into loadRecordsContext.
func LoadRecords(input string) (adapter.LoadResult, error) {
	return loadRecordsContext(context.Background(), input)
}

// loadRecordsContext scans with cancellation support: the context is checked
// before the scan starts and once per assembled record, and readDB derives
// its per-database deadline from it. On cancellation it returns ctx.Err()
// (matching errors.Is(context.Canceled) or errors.Is(context.DeadlineExceeded))
// and an empty result, so a scan cut short by its deadline never commits
// partial records.
func loadRecordsContext(ctx context.Context, input string) (adapter.LoadResult, error) {
	var result adapter.LoadResult
	if err := ctx.Err(); err != nil {
		return result, err
	}
	path, err := stateDBPath(input)
	if err != nil {
		return result, err
	}
	obs, err := readDB(ctx, path)
	if err != nil {
		return adapter.LoadResult{}, err
	}
	records := make(map[string]adapter.Record)
	conflicts := map[string]bool{}
	issue := func(reason string) {
		result.Quarantined++
		if len(result.Issues) < 50 {
			result.Issues = append(result.Issues, adapter.LineIssue{File: "file:" + adapter.ShortHash(path), Line: 0, Reason: reason})
		}
	}
	for _, ob := range obs {
		if err := ctx.Err(); err != nil {
			return adapter.LoadResult{}, err
		}
		rec := hermesRecord(ob)
		key := adapter.StringField(rec, "recordKey")
		if conflicts[key] {
			continue
		}
		if old, exists := records[key]; exists {
			if !sameRecord(old, rec) {
				delete(records, key)
				conflicts[key] = true
				issue("conflicting usage for same Hermes row")
			}
			continue
		}
		records[key] = rec
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

func stateDBPath(input string) (string, error) {
	clean := strings.TrimSpace(input)
	info, err := os.Stat(clean)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return filepath.Join(clean, "state.db"), nil
	}
	if strings.EqualFold(filepath.Base(clean), "state.db") || strings.EqualFold(filepath.Ext(clean), ".db") {
		return clean, nil
	}
	return "", fmt.Errorf("Hermes input file %q must be state.db or a .db SQLite database", clean)
}

// readDB scans one Hermes state database. It derives the historical 30-second
// per-database deadline from ctx, so a caller-supplied cancellation or a
// shorter parent deadline propagates into every query and row below; a plain
// context.Background() keeps the exact pre-context behavior.
func readDB(ctx context.Context, path string) ([]hermesObservation, error) {
	db, err := sql.Open("sqlite", sqliteReadOnlyDSN(path))
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	hasPerModel, err := hasTable(ctx, db, "session_model_usage")
	if err != nil {
		return nil, contextErr(ctx, err)
	}
	if hasPerModel {
		return readSessionModelUsage(ctx, db, path)
	}
	hasSessions, err := hasTable(ctx, db, "sessions")
	if err != nil {
		return nil, contextErr(ctx, err)
	}
	if hasSessions {
		return readSessions(ctx, db, path)
	}
	return nil, fmt.Errorf("Hermes state DB has neither session_model_usage nor sessions table")
}

func readSessionModelUsage(ctx context.Context, db *sql.DB, path string) ([]hermesObservation, error) {
	query := `SELECT COALESCE(smu.session_id, ''), COALESCE(smu.model, ''), COALESCE(s.started_at, 0), COALESCE(smu.input_tokens, 0), COALESCE(smu.output_tokens, 0), COALESCE(smu.cache_read_tokens, 0), COALESCE(smu.cache_write_tokens, 0) FROM session_model_usage smu LEFT JOIN sessions s ON s.id = smu.session_id ORDER BY COALESCE(s.started_at, 0), smu.session_id, smu.model`
	if scanQueryHook != nil {
		scanQueryHook(ctx)
	}
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, contextErr(ctx, fmt.Errorf("query Hermes session_model_usage: %w", err))
	}
	defer rows.Close()
	var out []hermesObservation
	for rows.Next() {
		if scanRowHook != nil {
			scanRowHook(ctx)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ob, ok, err := scanHermesRow(rows, path, "session_model_usage")
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, ob)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, contextErr(ctx, err)
	}
	return out, nil
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
// the main table query; scanRowHook runs once per row iteration, before the
// per-row context check, and receives the per-database scan scope the query
// runs under. Neither hook can alter control flow beyond the cancellation
// the context itself reports.
var (
	scanQueryHook func(ctx context.Context)
	scanRowHook   func(ctx context.Context)
)

func readSessions(ctx context.Context, db *sql.DB, path string) ([]hermesObservation, error) {
	query := `SELECT COALESCE(id, ''), COALESCE(model, ''), COALESCE(started_at, 0), COALESCE(input_tokens, 0), COALESCE(output_tokens, 0), COALESCE(cache_read_tokens, 0), COALESCE(cache_write_tokens, 0) FROM sessions ORDER BY started_at ASC, id ASC`
	if scanQueryHook != nil {
		scanQueryHook(ctx)
	}
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, contextErr(ctx, fmt.Errorf("query Hermes sessions: %w", err))
	}
	defer rows.Close()
	var out []hermesObservation
	for rows.Next() {
		if scanRowHook != nil {
			scanRowHook(ctx)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ob, ok, err := scanHermesRow(rows, path, "sessions")
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, ob)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, contextErr(ctx, err)
	}
	return out, nil
}

func scanHermesRow(rows *sql.Rows, path, table string) (hermesObservation, bool, error) {
	var id, model string
	var startedRaw any
	var inputRaw, outputRaw, cacheReadRaw, cacheWriteRaw any
	if err := rows.Scan(&id, &model, &startedRaw, &inputRaw, &outputRaw, &cacheReadRaw, &cacheWriteRaw); err != nil {
		return hermesObservation{}, false, err
	}
	startedAt, ok := parseHermesTime(startedRaw)
	if !ok {
		return hermesObservation{}, false, fmt.Errorf("Hermes %s row %q has invalid started_at", table, id)
	}
	input, ok := uintAny(inputRaw)
	if !ok {
		return hermesObservation{}, false, fmt.Errorf("Hermes %s row %q has invalid input_tokens", table, id)
	}
	output, ok := uintAny(outputRaw)
	if !ok {
		return hermesObservation{}, false, fmt.Errorf("Hermes %s row %q has invalid output_tokens", table, id)
	}
	cacheRead, ok := uintAny(cacheReadRaw)
	if !ok {
		return hermesObservation{}, false, fmt.Errorf("Hermes %s row %q has invalid cache_read_tokens", table, id)
	}
	cacheWrite, ok := uintAny(cacheWriteRaw)
	if !ok {
		return hermesObservation{}, false, fmt.Errorf("Hermes %s row %q has invalid cache_write_tokens", table, id)
	}
	if input == 0 && output == 0 && cacheRead == 0 && cacheWrite == 0 {
		return hermesObservation{}, false, nil
	}
	model = strings.TrimSpace(model)
	if model == "" {
		model = "unknown"
	} else if err := adapter.ValidateModel(model); err != nil {
		return hermesObservation{}, false, fmt.Errorf("Hermes %s row %q has invalid model", table, id)
	}
	if strings.TrimSpace(id) == "" {
		id = fmt.Sprintf("%s:%s:%s", table, path, startedAt.Format(time.RFC3339Nano))
	}
	return hermesObservation{
		ID:        table + ":" + id,
		Model:     model,
		StartedAt: startedAt,
		Usage: hermesUsage{
			Input:      input,
			CacheRead:  cacheRead,
			CacheWrite: cacheWrite,
			Output:     output,
		},
		File: path,
	}, true, nil
}

func hasTable(ctx context.Context, db *sql.DB, name string) (bool, error) {
	row := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name)
	var count int
	if err := row.Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func parseHermesTime(value any) (time.Time, bool) {
	switch v := value.(type) {
	case int64:
		return unixHermesTime(uint64(v)), v >= 0
	case int:
		return unixHermesTime(uint64(v)), v >= 0
	case float64:
		if v < 0 {
			return time.Time{}, false
		}
		return unixHermesFloatSeconds(v), true
	case []byte:
		return parseHermesTimeString(string(v))
	case string:
		return parseHermesTimeString(v)
	case nil:
		return time.Time{}, false
	default:
		return time.Time{}, false
	}
}

func parseHermesTimeString(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	if n, ok := adapter.ParseUint(s); ok {
		return unixHermesTime(n), true
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && f >= 0 {
		return unixHermesFloatSeconds(f), true
	}
	return time.Time{}, false
}

func unixHermesTime(n uint64) time.Time {
	if n > 100000000000 {
		return time.Unix(0, int64(n)*int64(time.Millisecond)).UTC()
	}
	return time.Unix(int64(n), 0).UTC()
}

func unixHermesFloatSeconds(seconds float64) time.Time {
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

func hermesRecord(obs hermesObservation) adapter.Record {
	identity := obs.File + "\x00" + obs.ID + "\x00" + obs.Model
	include, _ := adapter.AddUint64Checked(obs.Usage.Input, obs.Usage.CacheRead)
	include, _ = adapter.AddUint64Checked(include, obs.Usage.CacheWrite)
	include, _ = adapter.AddUint64Checked(include, obs.Usage.Output)
	exclude, _ := adapter.AddUint64Checked(obs.Usage.Input, obs.Usage.Output)
	return adapter.Record{
		"recordKey":      fmt.Sprintf("%s:%s:%020d:%020d", adapter.HermesSQLiteSource, adapter.ShortHash(identity), include, exclude),
		"groupKey":       "hermes-usage:" + adapter.ShortHash(identity),
		"resetKey":       "hermes-sqlite-v1",
		"kind":           "cumulative",
		"occurredAt":     obs.StartedAt.UTC().Format(time.RFC3339),
		"tool":           hermesTool,
		"model":          obs.Model,
		"input":          strconv.FormatUint(obs.Usage.Input, 10),
		"cacheRead":      strconv.FormatUint(obs.Usage.CacheRead, 10),
		"cacheWrite":     strconv.FormatUint(obs.Usage.CacheWrite, 10),
		"output":         strconv.FormatUint(obs.Usage.Output, 10),
		"adapterVersion": hermesAdapterVersion,
		"sourceType":     adapter.HermesSQLiteSource,
	}
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
		Source:      adapter.HermesSQLiteSource,
		Description: "Hermes Agent state.db SQLite",
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
// so repeated full rescans cannot re-export known Hermes records. The
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
			return fmt.Errorf("stored Hermes record has no key")
		}
		canonical, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if old, exists := known[key]; exists && !bytes.Equal(old, canonical) {
			return fmt.Errorf("stored Hermes record %s has conflicting content", key)
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
		if entry.Source != adapter.HermesSQLiteSource {
			continue
		}
		switch entry.Status {
		case outbox.StatusPending, outbox.StatusSynced, outbox.StatusReorganized:
		default:
			return nil, fmt.Errorf("unknown Hermes outbox status %q", entry.Status)
		}
		raw, err := os.ReadFile(entry.File)
		if err != nil {
			return nil, fmt.Errorf("read Hermes history batch %s: %w", entry.BatchID, err)
		}
		var batch struct {
			BatchID string            `json:"batchId"`
			Records []json.RawMessage `json:"records"`
		}
		if err := json.Unmarshal(raw, &batch); err != nil {
			return nil, err
		}
		if batch.BatchID != entry.BatchID {
			return nil, fmt.Errorf("Hermes history batch identity mismatch")
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
		if entry.Source == adapter.HermesSQLiteSource {
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
				return nil, fmt.Errorf("Hermes record %s changed after export; refusing to overwrite immutable history", key)
			}
			continue
		}
		fresh = append(fresh, record)
	}
	return fresh, nil
}

func sameRecord(a, b adapter.Record) bool {
	ca, errA := json.Marshal(a)
	cb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ca, cb)
}
