package qwenjsonl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/jsonl"
)

const (
	qwenTool           = "Qwen Code"
	qwenAdapterVersion = "qwen-jsonl-v1"
)

type qwenUsage struct {
	Input     uint64
	CacheRead uint64
	Output    uint64
}

type qwenObservation struct {
	Timestamp    time.Time
	SessionID    string
	Identity     string
	Model        string
	Usage        qwenUsage
	MissingModel bool
}

// LoadRecords reads Qwen Code / Qwen CLI chat JSONL files from an explicitly
// granted path. For current Qwen Code releases, token usage is recorded in
// system/ui_telemetry records whose systemPayload.uiEvent event.name is
// qwen-code.api_response. Assistant usageMetadata records are used only as a
// per-file fallback for older layouts that do not contain api_response
// telemetry; reading both would double count the main model call. It keeps the
// historical uncancellable signature for direct callers; the adapter's Load
// passes its cancellation scope through loadRecordsContext.
func LoadRecords(root string) (adapter.LoadResult, error) {
	return loadRecordsContext(context.Background(), root)
}

// loadRecordsContext scans with cancellation support: the context is checked
// during file discovery, once per file, and once per line. On cancellation it
// returns ctx.Err() (matchable with errors.Is(err, context.Canceled) or
// errors.Is(err, context.DeadlineExceeded)) and no partial result — records,
// issues, and quarantine counts accumulated so far are discarded, so a scan
// cut short never exports half of the Qwen usage.
func loadRecordsContext(ctx context.Context, root string) (adapter.LoadResult, error) {
	var result adapter.LoadResult
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
	remember := func(obs qwenObservation, file string, line int, source string) {
		rec := qwenRecord(obs)
		key := adapter.StringField(rec, "recordKey")
		if obs.MissingModel {
			missingModel[key] = true
			if _, exists := locations[key]; !exists {
				locations[key] = adapter.LineIssue{File: "file:" + adapter.ShortHash(file), Line: line, Reason: source + " model not recorded; model reported unknown"}
			}
		}
		if conflicts[key] {
			return
		}
		if old, exists := records[key]; exists {
			if !sameRecord(old, rec) {
				delete(records, key)
				conflicts[key] = true
				issue(file, line, "conflicting usage for same Qwen API response")
			}
			return
		}
		records[key] = rec
	}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return adapter.LoadResult{}, err
		}
		if !strings.EqualFold(filepath.Ext(file), ".jsonl") {
			issue(file, 0, "non-JSONL input skipped")
			continue
		}
		if info, err := os.Lstat(file); err != nil {
			return adapter.LoadResult{}, err
		} else if !info.Mode().IsRegular() {
			issue(file, 0, "non-regular file skipped")
			continue
		}
		fallbackSession := strings.TrimSuffix(filepath.Base(file), filepath.Ext(file))
		var apiResponses []struct {
			obs  qwenObservation
			line int
		}
		var assistantResponses []struct {
			obs  qwenObservation
			line int
		}
		if err := jsonl.WalkLinesContext(ctx, file, func(line jsonl.Line) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			row, err := jsonl.DecodeObject(line.Text)
			if err != nil {
				issue(line.File, line.Number, "invalid JSON")
				return nil
			}
			if obs, ok, reason := parseQwenAPIResponse(row, fallbackSession, line.File, line.Number); reason != "" {
				issue(line.File, line.Number, reason)
			} else if ok {
				apiResponses = append(apiResponses, struct {
					obs  qwenObservation
					line int
				}{obs: obs, line: line.Number})
				return nil
			}
			if obs, ok, reason := parseQwenAssistantUsage(row, fallbackSession, line.File, line.Number); reason != "" {
				issue(line.File, line.Number, reason)
			} else if ok {
				assistantResponses = append(assistantResponses, struct {
					obs  qwenObservation
					line int
				}{obs: obs, line: line.Number})
			}
			return nil
		}); err != nil {
			return adapter.LoadResult{}, err
		}
		if len(apiResponses) > 0 {
			for _, entry := range apiResponses {
				remember(entry.obs, file, entry.line, "api response")
			}
			continue
		}
		for _, entry := range assistantResponses {
			remember(entry.obs, file, entry.line, "assistant usage")
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

func parseQwenAPIResponse(row map[string]any, fallbackSession, file string, line int) (qwenObservation, bool, string) {
	if text(row["type"]) != "system" || text(row["subtype"]) != "ui_telemetry" {
		return qwenObservation{}, false, ""
	}
	systemPayload := object(row["systemPayload"])
	uiEvent := object(systemPayload["uiEvent"])
	if eventName(uiEvent) != "qwen-code.api_response" {
		return qwenObservation{}, false, ""
	}
	timestamp, reason := parseTimestamp(firstString(uiEvent["event.timestamp"], row["timestamp"]))
	if reason != "" {
		return qwenObservation{}, false, reason
	}
	model, missing, modelOK := qwenModel(uiEvent["model"])
	if !modelOK {
		return qwenObservation{}, false, "invalid api response model"
	}
	usage, reason := parseQwenSnakeUsage(uiEvent)
	if reason != "" {
		return qwenObservation{}, false, reason
	}
	sessionID := firstString(row["sessionId"], uiEvent["session_id"], fallbackSession)
	identity := firstString(uiEvent["response_id"], row["uuid"])
	if identity == "" {
		identity = fmt.Sprintf("%s:%d", adapter.ShortHash(file), line)
	}
	return qwenObservation{Timestamp: timestamp, SessionID: sessionID, Identity: identity, Model: model, Usage: usage, MissingModel: missing}, true, ""
}

func parseQwenAssistantUsage(row map[string]any, fallbackSession, file string, line int) (qwenObservation, bool, string) {
	if text(row["type"]) != "assistant" {
		return qwenObservation{}, false, ""
	}
	usageRaw := object(row["usageMetadata"])
	if len(usageRaw) == 0 {
		return qwenObservation{}, false, ""
	}
	timestamp, reason := parseTimestamp(text(row["timestamp"]))
	if reason != "" {
		return qwenObservation{}, false, reason
	}
	exec := object(row["executionContext"])
	model, missing, modelOK := qwenModel(firstPresent(row["model"], exec["modelId"]))
	if !modelOK {
		return qwenObservation{}, false, "invalid assistant model"
	}
	usage, reason := parseQwenCamelUsage(usageRaw)
	if reason != "" {
		return qwenObservation{}, false, reason
	}
	sessionID := firstString(row["sessionId"], fallbackSession)
	identity := firstString(row["uuid"])
	if identity == "" {
		identity = fmt.Sprintf("%s:%d", adapter.ShortHash(file), line)
	}
	return qwenObservation{Timestamp: timestamp, SessionID: sessionID, Identity: identity, Model: model, Usage: usage, MissingModel: missing}, true, ""
}

func parseQwenSnakeUsage(m map[string]any) (qwenUsage, string) {
	return parseQwenUsage(m, qwenUsageFields{
		input: "input_token_count", output: "output_token_count", cacheRead: "cached_content_token_count", thoughts: "thoughts_token_count", total: "total_token_count",
	})
}

func parseQwenCamelUsage(m map[string]any) (qwenUsage, string) {
	return parseQwenUsage(m, qwenUsageFields{
		input: "promptTokenCount", output: "candidatesTokenCount", cacheRead: "cachedContentTokenCount", thoughts: "thoughtsTokenCount", total: "totalTokenCount",
	})
}

type qwenUsageFields struct {
	input, output, cacheRead, thoughts, total string
}

func parseQwenUsage(m map[string]any, fields qwenUsageFields) (qwenUsage, string) {
	input, ok := uintField(m, fields.input, true)
	if !ok {
		return qwenUsage{}, "Qwen usage missing or invalid " + fields.input
	}
	output, ok := uintField(m, fields.output, true)
	if !ok {
		return qwenUsage{}, "Qwen usage missing or invalid " + fields.output
	}
	cacheRead, ok := uintField(m, fields.cacheRead, false)
	if !ok {
		return qwenUsage{}, "Qwen usage invalid " + fields.cacheRead
	}
	thoughts, ok := uintField(m, fields.thoughts, false)
	if !ok {
		return qwenUsage{}, "Qwen usage invalid " + fields.thoughts
	}
	if cacheRead > input {
		return qwenUsage{}, "Qwen usage cached tokens exceed input tokens"
	}
	if total, ok := uintField(m, fields.total, false); !ok {
		return qwenUsage{}, "Qwen usage invalid " + fields.total
	} else if total != 0 {
		inputPlusOutput, sumOK := adapter.AddUint64Checked(input, output)
		if !sumOK {
			return qwenUsage{}, "Qwen usage input + output exceeds uint64"
		}
		switch {
		case total == inputPlusOutput:
			// OpenAI-compatible Qwen Code logs include reasoning tokens in output.
		case thoughts > 0:
			withThoughts, ok := adapter.AddUint64Checked(inputPlusOutput, thoughts)
			if !ok {
				return qwenUsage{}, "Qwen usage input + output + thoughts exceeds uint64"
			}
			if total != withThoughts {
				return qwenUsage{}, "Qwen usage total token count does not match known counters"
			}
			output += thoughts
		default:
			return qwenUsage{}, "Qwen usage total token count does not match known counters"
		}
	} else if thoughts > 0 {
		return qwenUsage{}, "Qwen usage has thoughts tokens but no total token count to disambiguate output"
	}
	return qwenUsage{Input: input - cacheRead, CacheRead: cacheRead, Output: output}, ""
}

func uintField(m map[string]any, key string, required bool) (uint64, bool) {
	v, exists := m[key]
	if !exists || v == nil {
		return 0, !required
	}
	n, ok := adapter.UintAny(v)
	return n, ok
}

func parseTimestamp(raw string) (time.Time, string) {
	if raw == "" {
		return time.Time{}, "missing timestamp"
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, "invalid timestamp"
	}
	return t, ""
}

func qwenModel(value any) (model string, missing bool, ok bool) {
	if value == nil {
		return "unknown", true, true
	}
	if err := adapter.ValidateModel(value); err != nil {
		return "", false, false
	}
	return value.(string), false, true
}

func qwenRecord(obs qwenObservation) adapter.Record {
	return adapter.Record{
		"recordKey":      "qwen-jsonl:" + adapter.ShortHash(obs.Identity),
		"groupKey":       "qwen-response:" + adapter.ShortHash(obs.Identity),
		"resetKey":       nil,
		"kind":           "delta",
		"occurredAt":     obs.Timestamp.UTC().Format(time.RFC3339),
		"tool":           qwenTool,
		"model":          obs.Model,
		"input":          fmt.Sprintf("%d", obs.Usage.Input),
		"cacheRead":      fmt.Sprintf("%d", obs.Usage.CacheRead),
		"cacheWrite":     "0",
		"output":         fmt.Sprintf("%d", obs.Usage.Output),
		"adapterVersion": qwenAdapterVersion,
		"sourceType":     adapter.QwenJSONLSource,
	}
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

func text(value any) string { return adapter.StringAny(value) }

func firstString(values ...any) string {
	for _, v := range values {
		if s := text(v); s != "" {
			return s
		}
	}
	return ""
}

func firstPresent(values ...any) any {
	for _, v := range values {
		if v != nil {
			return v
		}
	}
	return nil
}

func eventName(uiEvent map[string]any) string {
	return firstString(uiEvent["event.name"], uiEvent["eventName"], uiEvent["name"])
}

// Adapter exposes the Qwen source to the collector pipeline.
func Adapter() adapter.Adapter {
	return adapter.Adapter{
		Source:      adapter.QwenJSONLSource,
		Description: "Qwen Code / Qwen CLI api_response JSONL",
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
// so repeated full rescans cannot re-export known Qwen records. The context
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
			return fmt.Errorf("stored Qwen record has no key")
		}
		canonical, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if old, exists := known[key]; exists && !bytes.Equal(old, canonical) {
			return fmt.Errorf("stored Qwen record %s has conflicting content", key)
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
		if entry.Source != adapter.QwenJSONLSource {
			continue
		}
		switch entry.Status {
		case outbox.StatusPending, outbox.StatusSynced, outbox.StatusReorganized:
		default:
			return nil, fmt.Errorf("unknown Qwen outbox status %q", entry.Status)
		}
		raw, err := os.ReadFile(entry.File)
		if err != nil {
			return nil, fmt.Errorf("read Qwen history batch %s: %w", entry.BatchID, err)
		}
		var batch struct {
			BatchID string            `json:"batchId"`
			Records []json.RawMessage `json:"records"`
		}
		if err := json.Unmarshal(raw, &batch); err != nil {
			return nil, err
		}
		if batch.BatchID != entry.BatchID {
			return nil, fmt.Errorf("Qwen history batch identity mismatch")
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
		if entry.Source == adapter.QwenJSONLSource {
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
				return nil, fmt.Errorf("Qwen record %s changed after export; refusing to overwrite immutable history", key)
			}
			continue
		}
		fresh = append(fresh, record)
	}
	return fresh, nil
}
