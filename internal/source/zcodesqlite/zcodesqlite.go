package zcodesqlite

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
	zcodeTool           = "ZCode"
	zcodeAdapterVersion = "zcode-sqlite-v1"
)

type zcodeUsage struct {
	Input      uint64
	CacheRead  uint64
	CacheWrite uint64
	Output     uint64
}

type zcodeObservation struct {
	ID        string
	Model     string
	StartedAt time.Time
	Usage     zcodeUsage
	File      string
}

// LoadRecords reads ZCode local usage SQLite databases from an explicitly
// granted path. The verified source is the model_usage table under
// ~/.zcode/cli/db/db.sqlite; when a directory is granted, every *.sqlite file
// in that directory is read so future sharded stores do not require a new
// grant. Only aggregate token columns are read; prompts, responses, session
// content, auth state and account data are not queried. It keeps the
// historical context-free signature for direct callers; the adapter's Load
// threads the caller's cancellation scope through
// adapter.Options.ContextOrBackground into loadRecordsContext.
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
	records := make(map[string]adapter.Record)
	conflicts := make(map[string]bool)
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
		obs, err := readDB(ctx, file)
		if err != nil {
			return adapter.LoadResult{}, err
		}
		for _, ob := range obs {
			if err := ctx.Err(); err != nil {
				return adapter.LoadResult{}, err
			}
			rec := zcodeRecord(ob)
			key := adapter.StringField(rec, "recordKey")
			if conflicts[key] {
				continue
			}
			if old, exists := records[key]; exists {
				if !sameRecord(old, rec) {
					delete(records, key)
					conflicts[key] = true
					issue(file, "conflicting usage for same ZCode model_usage row")
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
		if strings.EqualFold(filepath.Ext(clean), ".sqlite") || strings.EqualFold(filepath.Base(clean), "db.sqlite") {
			return []string{clean}, nil
		}
		return nil, fmt.Errorf("ZCode input file %q must be a .sqlite database", clean)
	}
	entries, err := os.ReadDir(clean)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.EqualFold(filepath.Ext(name), ".sqlite") {
			files = append(files, filepath.Join(clean, name))
		}
	}
	sort.Strings(files)
	return files, nil
}

// readDB scans one ZCode SQLite database. It derives the historical
// 30-second per-database deadline from ctx, so a caller-supplied
// cancellation or a shorter parent deadline propagates into every query and
// row below; a plain context.Background() keeps the exact pre-context
// behavior. Each row is also checked for cancellation before it is parsed.
func readDB(ctx context.Context, path string) ([]zcodeObservation, error) {
	db, err := sql.Open("sqlite", sqliteReadOnlyDSN(path))
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	hasStatus, err := modelUsageHasColumn(ctx, db, "status")
	if err != nil {
		return nil, contextErr(ctx, err)
	}
	query := `SELECT COALESCE(CAST(id AS TEXT), ''), COALESCE(model_id, ''), COALESCE(started_at, 0), COALESCE(input_tokens, 0), COALESCE(output_tokens, 0), COALESCE(cache_creation_input_tokens, 0), COALESCE(cache_read_input_tokens, 0) FROM model_usage`
	if hasStatus {
		query += ` WHERE status = 'completed'`
	}
	query += ` ORDER BY started_at ASC, id ASC`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, contextErr(ctx, fmt.Errorf("query ZCode model_usage: %w", err))
	}
	defer rows.Close()
	var out []zcodeObservation
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var id, model string
		var startedRaw any
		var inputRaw, outputRaw, cacheWriteRaw, cacheReadRaw any
		if err := rows.Scan(&id, &model, &startedRaw, &inputRaw, &outputRaw, &cacheWriteRaw, &cacheReadRaw); err != nil {
			return nil, err
		}
		startedAt, ok := parseZcodeTime(startedRaw)
		if !ok {
			return nil, fmt.Errorf("ZCode model_usage row %q has invalid started_at", id)
		}
		inputTokens, ok := uintAny(inputRaw)
		if !ok {
			return nil, fmt.Errorf("ZCode model_usage row %q has invalid input_tokens", id)
		}
		output, ok := uintAny(outputRaw)
		if !ok {
			return nil, fmt.Errorf("ZCode model_usage row %q has invalid output_tokens", id)
		}
		cacheWrite, ok := uintAny(cacheWriteRaw)
		if !ok {
			return nil, fmt.Errorf("ZCode model_usage row %q has invalid cache_creation_input_tokens", id)
		}
		cacheRead, ok := uintAny(cacheReadRaw)
		if !ok {
			return nil, fmt.Errorf("ZCode model_usage row %q has invalid cache_read_input_tokens", id)
		}
		cacheTotal, ok := adapter.AddUint64Checked(cacheRead, cacheWrite)
		if !ok {
			return nil, fmt.Errorf("ZCode model_usage row %q has cache tokens exceeding uint64", id)
		}
		netInput := uint64(0)
		switch {
		case inputTokens == 0:
			// Official ZCode normalization falls back to cache read/write as the
			// input side when input_tokens is absent/zero.
		case cacheTotal > inputTokens:
			return nil, fmt.Errorf("ZCode model_usage row %q has cache tokens exceeding input_tokens", id)
		default:
			netInput = inputTokens - cacheTotal
		}
		model = strings.TrimSpace(model)
		if model == "" {
			model = "unknown"
		} else if err := adapter.ValidateModel(model); err != nil {
			return nil, fmt.Errorf("ZCode model_usage row %q has invalid model", id)
		}
		if strings.TrimSpace(id) == "" {
			id = fmt.Sprintf("%s:%s", path, startedAt.Format(time.RFC3339Nano))
		}
		out = append(out, zcodeObservation{
			ID:        id,
			Model:     model,
			StartedAt: startedAt,
			Usage: zcodeUsage{
				Input:      netInput,
				CacheRead:  cacheRead,
				CacheWrite: cacheWrite,
				Output:     output,
			},
			File: path,
		})
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

func modelUsageHasColumn(ctx context.Context, db *sql.DB, column string) (bool, error) {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(model_usage)`)
	if err != nil {
		return false, fmt.Errorf("inspect ZCode model_usage schema: %w", err)
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

func parseZcodeTime(value any) (time.Time, bool) {
	switch v := value.(type) {
	case int64:
		return unixZcodeTime(uint64(v)), v >= 0
	case int:
		return unixZcodeTime(uint64(v)), v >= 0
	case float64:
		if v < 0 {
			return time.Time{}, false
		}
		return unixZcodeFloatSeconds(v), true
	case []byte:
		return parseZcodeTimeString(string(v))
	case string:
		return parseZcodeTimeString(v)
	case nil:
		return time.Time{}, false
	default:
		return time.Time{}, false
	}
}

func parseZcodeTimeString(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	if n, ok := adapter.ParseUint(s); ok {
		return unixZcodeTime(n), true
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && f >= 0 {
		return unixZcodeFloatSeconds(f), true
	}
	return time.Time{}, false
}

func unixZcodeTime(n uint64) time.Time {
	if n > 100000000000 {
		return time.Unix(0, int64(n)*int64(time.Millisecond)).UTC()
	}
	return time.Unix(int64(n), 0).UTC()
}

func unixZcodeFloatSeconds(seconds float64) time.Time {
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

func zcodeRecord(obs zcodeObservation) adapter.Record {
	identity := obs.File + "\x00" + obs.ID
	return adapter.Record{
		"recordKey":      adapter.ZCodeSQLiteSource + ":" + adapter.ShortHash(identity),
		"groupKey":       "zcode-model-usage:" + adapter.ShortHash(identity),
		"resetKey":       nil,
		"kind":           "delta",
		"occurredAt":     obs.StartedAt.UTC().Format(time.RFC3339),
		"tool":           zcodeTool,
		"model":          obs.Model,
		"input":          strconv.FormatUint(obs.Usage.Input, 10),
		"cacheRead":      strconv.FormatUint(obs.Usage.CacheRead, 10),
		"cacheWrite":     strconv.FormatUint(obs.Usage.CacheWrite, 10),
		"output":         strconv.FormatUint(obs.Usage.Output, 10),
		"adapterVersion": zcodeAdapterVersion,
		"sourceType":     adapter.ZCodeSQLiteSource,
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
	// immutable keeps the collector from creating SQLite sidecar files in a
	// live ZCode directory. Fresh WAL-only commits may be invisible until ZCode
	// checkpoints, which is acceptable for the next scheduled read.
	b.WriteString("?mode=ro&immutable=1")
	return b.String()
}

func Adapter() adapter.Adapter {
	return adapter.Adapter{
		Source:      adapter.ZCodeSQLiteSource,
		Description: "ZCode model_usage SQLite",
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
// so repeated full rescans cannot re-export known ZCode records. The context
// is consulted at coarse boundaries (entry, per outbox batch, per stored
// record, before the quarantine load, per quarantine entry, per fresh
// record); on cancellation it returns ctx.Err() (matchable with
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
			return fmt.Errorf("stored ZCode record has no key")
		}
		canonical, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if old, exists := known[key]; exists && !bytes.Equal(old, canonical) {
			return fmt.Errorf("stored ZCode record %s has conflicting content", key)
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
		if entry.Source != adapter.ZCodeSQLiteSource {
			continue
		}
		switch entry.Status {
		case outbox.StatusPending, outbox.StatusSynced, outbox.StatusReorganized:
		default:
			return nil, fmt.Errorf("unknown ZCode outbox status %q", entry.Status)
		}
		raw, err := os.ReadFile(entry.File)
		if err != nil {
			return nil, fmt.Errorf("read ZCode history batch %s: %w", entry.BatchID, err)
		}
		var batch struct {
			BatchID string            `json:"batchId"`
			Records []json.RawMessage `json:"records"`
		}
		if err := json.Unmarshal(raw, &batch); err != nil {
			return nil, err
		}
		if batch.BatchID != entry.BatchID {
			return nil, fmt.Errorf("ZCode history batch identity mismatch")
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
		if entry.Source == adapter.ZCodeSQLiteSource {
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
				return nil, fmt.Errorf("ZCode record %s changed after export; refusing to overwrite immutable history", key)
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
