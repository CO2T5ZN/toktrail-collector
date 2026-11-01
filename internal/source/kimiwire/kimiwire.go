package kimiwire

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/jsonl"
)

const (
	KimiCLIAdapterVersion  = "kimi-cli-jsonl-v1"
	KimiCodeAdapterVersion = "kimi-code-jsonl-v1"
)

type SourceConfig struct {
	Source         string
	Tool           string
	AdapterVersion string
}

var (
	KimiCLIConfig = SourceConfig{
		Source:         adapter.KimiCLIJSONLSource,
		Tool:           "Kimi CLI",
		AdapterVersion: KimiCLIAdapterVersion,
	}
	KimiCodeConfig = SourceConfig{
		Source:         adapter.KimiCodeJSONLSource,
		Tool:           "Kimi Code",
		AdapterVersion: KimiCodeAdapterVersion,
	}
)

type kimiUsage struct {
	InputOther         uint64
	InputCacheRead     uint64
	InputCacheCreation uint64
	Output             uint64
}

type kimiObservation struct {
	Timestamp    time.Time
	Identity     string
	SessionID    string
	Model        string
	Usage        kimiUsage
	MissingModel bool
}

type kimiFileContext struct {
	lastModel    *string
	lastIdentity string
}

// LoadRecords reads Kimi wire JSONL under an explicitly granted sessions root.
// Kimi CLI writes StatusUpdate events with token_usage snake_case counters;
// Kimi Code writes usage.record events with camelCase counters. Both are
// per-turn self-reported counts in wire.jsonl. Kimi Code session-scoped
// cumulative usage records are ignored to avoid double counting. It keeps the
// historical uncancellable signature for direct callers; the adapter's Load
// passes its cancellation scope through loadRecordsContext.
func LoadRecords(root string, cfg SourceConfig) (adapter.LoadResult, error) {
	return loadRecordsContext(context.Background(), root, cfg)
}

// loadRecordsContext scans with cancellation support: the context is checked
// during file discovery, once per file, and once per line. On cancellation it
// returns ctx.Err() (matchable with errors.Is(err, context.Canceled) or
// errors.Is(err, context.DeadlineExceeded)) and no partial result — records,
// issues, and quarantine counts accumulated so far are discarded, so a scan
// cut short never exports half of the Kimi usage.
func loadRecordsContext(ctx context.Context, root string, cfg SourceConfig) (adapter.LoadResult, error) {
	var result adapter.LoadResult
	files, err := wireFilesContext(ctx, root)
	if err != nil {
		return result, err
	}
	records := make(map[string]adapter.Record)
	locations := make(map[string]adapter.LineIssue)
	missingModel := make(map[string]bool)
	conflicts := make(map[string]bool)
	issue := func(file string, line int, reason string) {
		result.Quarantined++
		if len(result.Issues) < 50 {
			result.Issues = append(result.Issues, adapter.LineIssue{File: "file:" + adapter.ShortHash(file), Line: line, Reason: reason})
		}
	}
	remember := func(obs kimiObservation, file string, line int) {
		rec := kimiRecord(obs, cfg)
		key := adapter.StringField(rec, "recordKey")
		if obs.MissingModel {
			missingModel[key] = true
			if _, exists := locations[key]; !exists {
				locations[key] = adapter.LineIssue{File: "file:" + adapter.ShortHash(file), Line: line, Reason: "model not recorded; model reported unknown"}
			}
		}
		if conflicts[key] {
			return
		}
		if old, exists := records[key]; exists {
			if !sameRecord(old, rec) {
				delete(records, key)
				conflicts[key] = true
				issue(file, line, "conflicting usage for same Kimi turn")
			}
			return
		}
		records[key] = rec
	}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return adapter.LoadResult{}, err
		}
		if info, err := os.Lstat(file); err != nil {
			return adapter.LoadResult{}, err
		} else if !info.Mode().IsRegular() {
			issue(file, 0, "non-regular file skipped")
			continue
		}
		fallbackSession := sessionFromPath(file)
		fileCtx := &kimiFileContext{}
		if err := jsonl.WalkLinesContext(ctx, file, func(line jsonl.Line) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			row, err := jsonl.DecodeObject(line.Text)
			if err != nil {
				issue(line.File, line.Number, "invalid JSON")
				return nil
			}
			obs, ok, reason := parseKimiLine(row, fallbackSession, line.File, line.Number, fileCtx)
			if reason != "" {
				issue(line.File, line.Number, reason)
				return nil
			}
			if ok {
				remember(obs, line.File, line.Number)
			}
			return nil
		}); err != nil {
			return adapter.LoadResult{}, err
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
	for _, record := range result.Records {
		key := adapter.StringField(record, "recordKey")
		if missingModel[key] && len(result.Issues) < 50 {
			result.Issues = append(result.Issues, locations[key])
		}
	}
	return result, nil
}

// wireFilesContext discovers the wire.jsonl files under an explicitly granted
// root with cancellation support: the context is checked before the root is
// resolved and once per walked directory entry, mirroring
// jsonl.FilesContext's coarse boundaries.
func wireFilesContext(ctx context.Context, root string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	clean := strings.TrimSpace(root)
	info, err := os.Stat(clean)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		if strings.EqualFold(filepath.Base(clean), "wire.jsonl") || strings.EqualFold(filepath.Ext(clean), ".jsonl") {
			return []string{clean}, nil
		}
		return nil, fmt.Errorf("Kimi input file %q must be wire.jsonl or .jsonl", clean)
	}
	var files []string
	if err := filepath.WalkDir(clean, func(path string, d os.DirEntry, err error) error {
		if cancelErr := ctx.Err(); cancelErr != nil {
			return cancelErr
		}
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Base(path), "wire.jsonl") {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func parseKimiLine(row map[string]any, fallbackSession, file string, line int, ctx *kimiFileContext) (kimiObservation, bool, string) {
	message := object(row["message"])
	payload := object(message["payload"])
	event := firstString(message["type"], row["event"], row["type"], row["name"])
	if event == "llm.request" {
		return kimiObservation{}, false, noteKimiCodeRequest(row, ctx)
	}
	var usage kimiUsage
	var reason string
	var model string
	missingModel := false
	var identity string
	switch event {
	case "StatusUpdate":
		usageRaw := object(payload["token_usage"])
		if len(usageRaw) == 0 {
			usageRaw = object(row["token_usage"])
		}
		if len(usageRaw) == 0 {
			return kimiObservation{}, false, ""
		}
		usage, reason = parseSnakeUsage(usageRaw)
		if reason != "" {
			return kimiObservation{}, false, reason
		}
		// Legacy kimi-cli StatusUpdate does not carry a model identifier. Do not
		// invent the displayed product default; preserve the uncertainty.
		model = "unknown"
		missingModel = true
		identity = firstString(payload["message_id"], payload["messageId"], row["message_id"], row["messageId"], row["id"], row["uuid"])
	case "usage.record":
		// Kimi Code evidence is currently split: some readers treat session scope
		// as cumulative while others report it as incremental. Until fixture-backed
		// TokTrail validation resolves that, count only turn-scoped records to
		// avoid overcounting session totals.
		if scope := firstString(row["usageScope"], row["usage_scope"], row["scope"]); scope != "" && scope != "turn" {
			return kimiObservation{}, false, ""
		}
		usageRaw := object(row["usage"])
		if len(usageRaw) == 0 {
			usageRaw = row
		}
		usage, reason = parseCamelUsage(usageRaw)
		if reason != "" {
			return kimiObservation{}, false, reason
		}
		if ctx != nil && ctx.lastModel != nil {
			model = *ctx.lastModel
		} else {
			model = "unknown"
			missingModel = true
		}
		identity = firstString(row["messageId"], row["message_id"], row["requestId"], row["request_id"], row["id"], row["uuid"])
		if identity == "" && ctx != nil {
			identity = ctx.lastIdentity
		}
	default:
		return kimiObservation{}, false, ""
	}
	if usage.InputOther == 0 && usage.InputCacheRead == 0 && usage.InputCacheCreation == 0 && usage.Output == 0 {
		return kimiObservation{}, false, ""
	}
	timestamp, reason := parseKimiTimestamp(row)
	if reason != "" {
		return kimiObservation{}, false, reason
	}
	sessionID := firstString(row["sessionId"], row["session_id"], fallbackSession)
	if identity == "" {
		identity = fmt.Sprintf("%s:%d", adapter.ShortHash(file), line)
	}
	return kimiObservation{Timestamp: timestamp, Identity: identity, SessionID: sessionID, Model: model, Usage: usage, MissingModel: missingModel}, true, ""
}

func noteKimiCodeRequest(row map[string]any, ctx *kimiFileContext) string {
	if ctx == nil {
		return ""
	}
	model, _, ok := kimiModelFromValues(row["model"], row["modelId"], row["modelID"], row["model_id"])
	if !ok {
		return "invalid llm.request model"
	}
	if model != "" {
		ctx.lastModel = &model
	}
	if id := firstString(row["requestId"], row["request_id"], row["messageId"], row["message_id"], row["id"], row["uuid"]); id != "" {
		ctx.lastIdentity = id
	}
	return ""
}

func parseSnakeUsage(m map[string]any) (kimiUsage, string) {
	return parseUsage(m, usageKeys{input: "input_other", cacheRead: "input_cache_read", cacheCreation: "input_cache_creation", output: "output"})
}

func parseCamelUsage(m map[string]any) (kimiUsage, string) {
	return parseUsage(m, usageKeys{input: "inputOther", cacheRead: "inputCacheRead", cacheCreation: "inputCacheCreation", output: "output"})
}

type usageKeys struct {
	input, cacheRead, cacheCreation, output string
}

func parseUsage(m map[string]any, keys usageKeys) (kimiUsage, string) {
	input, ok := uintField(m, keys.input, false)
	if !ok {
		return kimiUsage{}, "invalid " + keys.input
	}
	cacheRead, ok := uintField(m, keys.cacheRead, false)
	if !ok {
		return kimiUsage{}, "invalid " + keys.cacheRead
	}
	cacheCreation, ok := uintField(m, keys.cacheCreation, false)
	if !ok {
		return kimiUsage{}, "invalid " + keys.cacheCreation
	}
	output, ok := uintField(m, keys.output, false)
	if !ok {
		return kimiUsage{}, "invalid " + keys.output
	}
	return kimiUsage{InputOther: input, InputCacheRead: cacheRead, InputCacheCreation: cacheCreation, Output: output}, ""
}

func uintField(m map[string]any, key string, required bool) (uint64, bool) {
	v, exists := m[key]
	if !exists || v == nil {
		return 0, !required
	}
	n, ok := adapter.UintAny(v)
	return n, ok
}

func parseKimiTimestamp(row map[string]any) (time.Time, string) {
	for _, key := range []string{"timestamp", "time"} {
		value, exists := row[key]
		if !exists || value == nil {
			continue
		}
		if t, ok := parseKimiTimeValue(value); ok {
			return t, ""
		}
		return time.Time{}, "invalid timestamp"
	}
	return time.Time{}, "missing timestamp"
}

func parseKimiTimeValue(value any) (time.Time, bool) {
	if s := adapter.StringAny(value); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t, true
		}
		if n, ok := adapter.ParseUint(s); ok {
			return unixKimiTime(n), true
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil && f >= 0 {
			return unixKimiFloatSeconds(f), true
		}
		return time.Time{}, false
	}
	if n, ok := adapter.UintAny(value); ok {
		return unixKimiTime(n), true
	}
	if num, ok := value.(json.Number); ok {
		if f, err := strconv.ParseFloat(num.String(), 64); err == nil && f >= 0 {
			return unixKimiFloatSeconds(f), true
		}
	}
	return time.Time{}, false
}

func unixKimiTime(n uint64) time.Time {
	// Kimi CLI StatusUpdate logs have been observed with seconds, while Kimi
	// Code usage.record logs use milliseconds. Treat large Unix values as ms.
	if n > 100000000000 {
		return time.Unix(0, int64(n)*int64(time.Millisecond)).UTC()
	}
	return time.Unix(int64(n), 0).UTC()
}

func unixKimiFloatSeconds(seconds float64) time.Time {
	sec := int64(seconds)
	nsec := int64((seconds - float64(sec)) * 1e9)
	return time.Unix(sec, nsec).UTC()
}

func kimiModelFromValues(values ...any) (string, bool, bool) {
	for _, value := range values {
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

func kimiRecord(obs kimiObservation, cfg SourceConfig) adapter.Record {
	return adapter.Record{
		"recordKey":      cfg.Source + ":" + adapter.ShortHash(obs.Identity),
		"groupKey":       cfg.Source + "-turn:" + adapter.ShortHash(obs.Identity),
		"resetKey":       nil,
		"kind":           "delta",
		"occurredAt":     obs.Timestamp.UTC().Format(time.RFC3339),
		"tool":           cfg.Tool,
		"model":          obs.Model,
		"input":          strconv.FormatUint(obs.Usage.InputOther, 10),
		"cacheRead":      strconv.FormatUint(obs.Usage.InputCacheRead, 10),
		"cacheWrite":     strconv.FormatUint(obs.Usage.InputCacheCreation, 10),
		"output":         strconv.FormatUint(obs.Usage.Output, 10),
		"adapterVersion": cfg.AdapterVersion,
		"sourceType":     cfg.Source,
	}
}

func Adapter(cfg SourceConfig) adapter.Adapter {
	return adapter.Adapter{
		Source:      cfg.Source,
		Description: cfg.Tool + " wire JSONL",
		Load: func(opt adapter.Options) (adapter.LoadResult, error) {
			return loadRecordsContext(opt.ContextOrBackground(), opt.Input, cfg)
		},
		FilterForExport: func(opt adapter.Options, records []adapter.Record) ([]adapter.Record, error) {
			ctx := opt.ContextOrBackground()
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if strings.TrimSpace(opt.StateDir) == "" {
				return records, nil
			}
			return filterKnownRecordsContext(ctx, opt.StateDir, cfg.Source, cfg.Tool, records)
		},
	}
}

func KimiCLIAdapter() adapter.Adapter  { return Adapter(KimiCLIConfig) }
func KimiCodeAdapter() adapter.Adapter { return Adapter(KimiCodeConfig) }

// filterKnownRecordsContext checks immutable outbox and quarantine records,
// so repeated full rescans cannot re-export known records. The context is
// consulted at coarse boundaries (entry, per outbox batch, per stored
// record, before the quarantine load, per quarantine entry, per fresh
// record); on cancellation it returns ctx.Err() (matchable with
// errors.Is(err, context.Canceled) or errors.Is(err, context.DeadlineExceeded))
// and no partial result — the fresh slice accumulated so far is discarded, so
// a filter cut short never exports a prefix of the scan. A nil
// Options.Context reaches here as context.Background() via
// ContextOrBackground and keeps the exact pre-cancellation behavior.
func filterKnownRecordsContext(ctx context.Context, stateDir, source, tool string, records []adapter.Record) ([]adapter.Record, error) {
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
			return fmt.Errorf("stored %s record has no key", tool)
		}
		canonical, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if old, exists := known[key]; exists && !bytes.Equal(old, canonical) {
			return fmt.Errorf("stored %s record %s has conflicting content", tool, key)
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
		if entry.Source != source {
			continue
		}
		switch entry.Status {
		case outbox.StatusPending, outbox.StatusSynced, outbox.StatusReorganized:
		default:
			return nil, fmt.Errorf("unknown %s outbox status %q", tool, entry.Status)
		}
		raw, err := os.ReadFile(entry.File)
		if err != nil {
			return nil, fmt.Errorf("read %s history batch %s: %w", tool, entry.BatchID, err)
		}
		var batch struct {
			BatchID string            `json:"batchId"`
			Records []json.RawMessage `json:"records"`
		}
		if err := json.Unmarshal(raw, &batch); err != nil {
			return nil, err
		}
		if batch.BatchID != entry.BatchID {
			return nil, fmt.Errorf("%s history batch identity mismatch", tool)
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
		if entry.Source == source {
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
				return nil, fmt.Errorf("%s record %s changed after export; refusing to overwrite immutable history", tool, key)
			}
			continue
		}
		fresh = append(fresh, record)
	}
	return fresh, nil
}

func sessionFromPath(path string) string {
	dir := filepath.Dir(path)
	parent := filepath.Base(filepath.Dir(dir))
	base := filepath.Base(dir)
	if strings.EqualFold(parent, "agents") {
		return filepath.Base(filepath.Dir(filepath.Dir(dir)))
	}
	if parent == "." || parent == string(filepath.Separator) || parent == "" {
		return base
	}
	return parent + "/" + base
}

func sameRecord(a, b adapter.Record) bool {
	ca, errA := json.Marshal(a)
	cb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ca, cb)
}

func object(value any) map[string]any {
	m, _ := value.(map[string]any)
	return m
}

func firstString(values ...any) string {
	for _, v := range values {
		if s := adapter.StringAny(v); s != "" {
			return s
		}
	}
	return ""
}
