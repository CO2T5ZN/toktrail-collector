package piwire

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
	PiAdapterVersion  = "pi-jsonl-v1"
	OMPAdapterVersion = "omp-jsonl-v1"
)

// SourceConfig keeps the per-source identity shared by the Pi and Oh My Pi
// adapters. Both products write the same JSONL session format (Oh My Pi is a
// fork of pi-mono), but they live in different directories and are granted
// separately, so each gets its own source id and tool name.
type SourceConfig struct {
	Source         string
	Tool           string
	AdapterVersion string
}

var (
	PiConfig = SourceConfig{
		Source:         adapter.PiJSONLSource,
		Tool:           "Pi",
		AdapterVersion: PiAdapterVersion,
	}
	OMPConfig = SourceConfig{
		Source:         adapter.OMPJSONLSource,
		Tool:           "Oh My Pi",
		AdapterVersion: OMPAdapterVersion,
	}
)

// piUsage records the four disjoint Pi usage buckets. Pi follows the OpenAI
// convention: input + output + cacheRead + cacheWrite = totalTokens, so input
// is the net (uncached) input and the counters are uploaded verbatim without
// any subtraction. reasoning/reasoningTokens is an informational subset of
// output and is not separately represented in the TokTrail record schema.
type piUsage struct {
	Input      uint64
	CacheRead  uint64
	CacheWrite uint64
	Output     uint64
}

type piObservation struct {
	Timestamp    time.Time
	Identity     string
	SessionID    string
	Model        string
	Usage        piUsage
	MissingModel bool
}

// piFileContext tracks per-file parse state: the session id declared by the
// header line and the most recent model_change model used as a fallback for
// usage entries that do not carry their own model.
type piFileContext struct {
	sessionID string
	lastModel *string
}

// LoadRecords reads Pi / Oh My Pi session JSONL under an explicitly granted
// sessions root. Each session file is an append-only tree: the first line is
// a session header and every later entry carries type/id/parentId/timestamp.
// Usage is per-request (assistant message usage plus standalone usage and
// model_usage entries for calls outside the conversation flow), so records are
// deltas keyed by the entry id. The PI_CODING_AGENT_DIR and
// PI_CODING_AGENT_SESSION_DIR environment variables are deliberately NOT
// honored: both products read the same variable names, so honoring them from
// two sources could scan one directory twice and double count every entry.
func LoadRecords(root string, cfg SourceConfig) (adapter.LoadResult, error) {
	return loadRecordsContext(context.Background(), root, cfg)
}

func loadRecordsContext(ctx context.Context, root string, cfg SourceConfig) (adapter.LoadResult, error) {
	var result adapter.LoadResult
	if err := ctx.Err(); err != nil {
		return result, err
	}
	files, err := jsonl.FilesContext(ctx, root, jsonl.Options{SkipHiddenFiles: true})
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
	remember := func(obs piObservation, file string, line int) {
		rec := piRecord(obs, cfg)
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
				issue(file, line, "conflicting usage for same Pi entry")
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
		fileCtx := &piFileContext{sessionID: fallbackSession}
		if err := jsonl.WalkLinesContext(ctx, file, func(line jsonl.Line) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			row, err := jsonl.DecodeObject(line.Text)
			if err != nil {
				// Oh My Pi files can carry a fixed-width title slot before the
				// header; keep the quarantine visible rather than guessing how
				// to skip it byte-wise.
				issue(line.File, line.Number, "invalid JSON")
				return nil
			}
			obs, ok, reason := parsePiLine(row, fileCtx, line.File, line.Number)
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

// parsePiLine converts one session entry into an observation. The header line
// updates the tracked session id and model_change entries update the fallback
// model; any entry carrying a usage object (assistant messages, standalone
// usage entries, Oh My Pi model_usage records, compaction usage) becomes a
// delta record. Entry types without usage — including unknown future types —
// are skipped silently per the Pi session-format guidance.
func parsePiLine(row map[string]any, fileCtx *piFileContext, file string, line int) (piObservation, bool, string) {
	entryType := firstString(row["type"])
	if entryType == "session" {
		if id := firstString(row["id"]); id != "" && fileCtx != nil {
			fileCtx.sessionID = id
		}
		return piObservation{}, false, ""
	}
	if entryType == "model_change" {
		if fileCtx != nil {
			if model := firstString(row["modelId"], row["model_id"], row["model"]); model != "" {
				fileCtx.lastModel = &model
			}
		}
		return piObservation{}, false, ""
	}
	message := object(row["message"])
	usageRaw := object(row["usage"])
	if len(usageRaw) == 0 {
		usageRaw = object(message["usage"])
	}
	if len(usageRaw) == 0 {
		return piObservation{}, false, ""
	}
	usage, reason := parsePiUsage(usageRaw)
	if reason != "" {
		return piObservation{}, false, reason
	}
	if usage.Input == 0 && usage.CacheRead == 0 && usage.CacheWrite == 0 && usage.Output == 0 {
		return piObservation{}, false, ""
	}
	model, missing, ok := piModel(row, message, fileCtx)
	if !ok {
		return piObservation{}, false, "invalid model"
	}
	timestamp, ok := piTimestamp(row, message)
	if !ok {
		return piObservation{}, false, "missing timestamp"
	}
	identity := firstString(row["id"], row["entryId"], row["entry_id"])
	if identity == "" {
		identity = fmt.Sprintf("%s:%d", adapter.ShortHash(file), line)
	}
	sessionID := fallbackSessionOf(fileCtx)
	return piObservation{Timestamp: timestamp, Identity: identity, SessionID: sessionID, Model: model, Usage: usage, MissingModel: missing}, true, ""
}

// parsePiUsage reads the four camelCase buckets. The counters are disjoint
// per the OpenAI convention Pi normalizes to, so they are preserved verbatim.
func parsePiUsage(m map[string]any) (piUsage, string) {
	input, ok := uintField(m, "input")
	if !ok {
		return piUsage{}, "invalid input counter"
	}
	output, ok := uintField(m, "output")
	if !ok {
		return piUsage{}, "invalid output counter"
	}
	cacheRead, ok := uintField(m, "cacheRead")
	if !ok {
		return piUsage{}, "invalid cacheRead counter"
	}
	cacheWrite, ok := uintField(m, "cacheWrite")
	if !ok {
		return piUsage{}, "invalid cacheWrite counter"
	}
	return piUsage{Input: input, CacheRead: cacheRead, CacheWrite: cacheWrite, Output: output}, ""
}

func piModel(row, message map[string]any, fileCtx *piFileContext) (string, bool, bool) {
	for _, value := range []any{message["model"], message["modelId"], row["model"], row["modelId"]} {
		if value == nil {
			continue
		}
		if err := adapter.ValidateModel(value); err != nil {
			return "", false, false
		}
		return value.(string), false, true
	}
	if fileCtx != nil && fileCtx.lastModel != nil {
		return *fileCtx.lastModel, false, true
	}
	return "unknown", true, true
}

// piTimestamp prefers the entry-level ISO 8601 timestamp and falls back to the
// message-level Unix millisecond timestamp.
func piTimestamp(row, message map[string]any) (time.Time, bool) {
	if s := firstString(row["timestamp"], row["time"]); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t, true
		}
		return time.Time{}, false
	}
	if message["timestamp"] != nil {
		if n, ok := uintAny(message["timestamp"]); ok {
			return time.Unix(0, int64(n)*int64(time.Millisecond)).UTC(), true
		}
	}
	return time.Time{}, false
}

func piRecord(obs piObservation, cfg SourceConfig) adapter.Record {
	identity := obs.SessionID + "\x00" + obs.Identity
	return adapter.Record{
		"recordKey":      cfg.Source + ":" + adapter.ShortHash(identity),
		"groupKey":       cfg.Source + "-entry:" + adapter.ShortHash(identity),
		"resetKey":       nil,
		"kind":           "delta",
		"occurredAt":     obs.Timestamp.UTC().Format(time.RFC3339),
		"tool":           cfg.Tool,
		"model":          obs.Model,
		"input":          strconv.FormatUint(obs.Usage.Input, 10),
		"cacheRead":      strconv.FormatUint(obs.Usage.CacheRead, 10),
		"cacheWrite":     strconv.FormatUint(obs.Usage.CacheWrite, 10),
		"output":         strconv.FormatUint(obs.Usage.Output, 10),
		"adapterVersion": cfg.AdapterVersion,
		"sourceType":     cfg.Source,
	}
}

func Adapter(cfg SourceConfig) adapter.Adapter {
	return adapter.Adapter{
		Source:      cfg.Source,
		Description: cfg.Tool + " session JSONL",
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

func PiAdapter() adapter.Adapter  { return Adapter(PiConfig) }
func OMPAdapter() adapter.Adapter { return Adapter(OMPConfig) }

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

// sessionFromPath recovers a fallback session id from a Pi session filename
// of the form <timestamp>_<session-id>.jsonl.
func sessionFromPath(path string) string {
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if idx := strings.LastIndex(base, "_"); idx >= 0 && idx+1 < len(base) {
		return base[idx+1:]
	}
	return base
}

func fallbackSessionOf(fileCtx *piFileContext) string {
	if fileCtx != nil && fileCtx.sessionID != "" {
		return fileCtx.sessionID
	}
	return ""
}

func uintField(m map[string]any, key string) (uint64, bool) {
	value, exists := m[key]
	if !exists || value == nil {
		return 0, true
	}
	return uintAny(value)
}

func uintAny(value any) (uint64, bool) {
	switch v := value.(type) {
	case json.Number:
		return adapter.ParseUint(v.String())
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
	case float64:
		if v < 0 || v != float64(uint64(v)) {
			return 0, false
		}
		return uint64(v), true
	case string:
		return adapter.ParseUint(strings.TrimSpace(v))
	default:
		return adapter.UintAny(value)
	}
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

func sameRecord(a, b adapter.Record) bool {
	ca, errA := json.Marshal(a)
	cb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ca, cb)
}
