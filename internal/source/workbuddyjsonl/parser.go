package workbuddyjsonl

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/jsonl"
)

// LoadRecords reads only JSONL files under the explicitly granted path.
// It never opens WorkBuddy databases, traces, configuration or credentials.
// It keeps the historical uncancellable signature for direct callers; the
// adapter's Load passes its cancellation scope through loadRecordsContext.
func LoadRecords(root string) (adapter.LoadResult, error) {
	return loadRecordsContext(context.Background(), root)
}

// loadRecordsContext scans with cancellation support: the context is checked
// during file discovery, once per file, and once per line. On cancellation it
// returns ctx.Err() (matchable with errors.Is(err, context.Canceled) or
// errors.Is(err, context.DeadlineExceeded)) and no partial result — records,
// issues, and quarantine counts accumulated so far are discarded, so a scan
// cut short never exports half of a WorkBuddy session. The per-line check
// mirrors jsonl.WalkLinesContext's coarse boundary; the custom reader is kept
// because WorkBuddy tails need the torn-final-line semantics it implements.
func loadRecordsContext(ctx context.Context, root string) (adapter.LoadResult, error) {
	var result adapter.LoadResult
	files, err := jsonl.FilesContext(ctx, root, jsonl.Options{SkipHiddenFiles: true})
	if err != nil {
		return result, err
	}
	records := make(map[string]adapter.Record)
	modelRecorded := make(map[string]bool)
	locations := make(map[string]adapter.LineIssue)
	conflicts := make(map[string]bool)
	issue := func(file string, line int, reason string) {
		result.Quarantined++
		if len(result.Issues) < 50 {
			result.Issues = append(result.Issues, adapter.LineIssue{File: "file:" + adapter.ShortHash(file), Line: line, Reason: reason})
		}
	}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return adapter.LoadResult{}, err
		}
		if !strings.EqualFold(filepath.Ext(file), ".jsonl") {
			issue(file, 0, "non-JSONL input skipped")
			continue
		}
		info, err := os.Lstat(file)
		if err != nil {
			return adapter.LoadResult{}, err
		}
		if !info.Mode().IsRegular() {
			issue(file, 0, "non-regular file skipped")
			continue
		}
		f, err := os.Open(file)
		if err != nil {
			return adapter.LoadResult{}, err
		}
		reader := bufio.NewReader(f)
		lineNo := 0
		for {
			if err := ctx.Err(); err != nil {
				f.Close()
				return adapter.LoadResult{}, err
			}
			line, tooLong, terminated, readErr := readCompleteLine(reader)
			if errors.Is(readErr, io.EOF) && line == "" && !tooLong {
				break
			}
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				f.Close()
				return adapter.LoadResult{}, readErr
			}
			lineNo++
			if tooLong {
				issue(file, lineNo, "JSONL line exceeds size limit")
				if errors.Is(readErr, io.EOF) {
					break
				}
				continue
			}
			if strings.TrimSpace(line) == "" {
				if errors.Is(readErr, io.EOF) {
					break
				}
				continue
			}
			row, err := jsonl.DecodeObject(line)
			if err != nil {
				if !terminated && errors.Is(readErr, io.EOF) {
					break // likely a concurrently written torn tail
				}
				issue(file, lineNo, "invalid JSON")
				if errors.Is(readErr, io.EOF) {
					break
				}
				continue
			}
			rec, reason := parseRecord(row, strings.TrimSuffix(filepath.Base(file), filepath.Ext(file)))
			if reason != "" {
				issue(file, lineNo, reason)
			}
			if rec != nil {
				key := adapter.StringField(rec, "recordKey")
				provider := object(row["providerData"])
				value, exists := provider["requestModelId"]
				newModelRecorded := exists && value != nil
				oldModelRecorded := modelRecorded[key]
				modelRecorded[key] = oldModelRecorded || newModelRecorded
				if _, exists := locations[key]; !exists {
					locations[key] = adapter.LineIssue{File: "file:" + adapter.ShortHash(file), Line: lineNo, Reason: "request model not recorded; model reported unknown"}
				}
				if !conflicts[key] {
					if old, ok := records[key]; ok {
						mergedModel, modelOK := mergeRecordedModels(old["model"], rec["model"], oldModelRecorded, newModelRecorded)
						switch {
						case !sameUsage(old, rec):
							delete(records, key)
							conflicts[key] = true
							issue(file, lineNo, "conflicting usage for same request")
						case !modelOK:
							// The same request carries two different
							// recorded model identifiers; neither may be
							// silently preferred, so the record is isolated.
							delete(records, key)
							conflicts[key] = true
							issue(file, lineNo, "conflicting model for same request")
						default:
							if adapter.StringField(rec, "occurredAt") < adapter.StringField(old, "occurredAt") {
								rec["model"] = mergedModel
								records[key] = rec
							} else {
								old["model"] = mergedModel
							}
						}
					} else {
						records[key] = rec
					}
				}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
		}
		if err := f.Close(); err != nil {
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
		if !modelRecorded[key] && len(result.Issues) < 50 {
			result.Issues = append(result.Issues, locations[key])
		}
	}
	return result, nil
}

// readCompleteLine bounds retained memory. An EOF with buffered bytes is
// returned as an unterminated line; the caller only accepts it if it is valid
// JSON, and otherwise treats it as a concurrently written torn tail.
func readCompleteLine(r *bufio.Reader) (line string, tooLong bool, terminated bool, err error) {
	var buf []byte
	for {
		fragment, readErr := r.ReadSlice('\n')
		if !tooLong && len(buf)+len(fragment) <= jsonl.MaxLineBytes {
			buf = append(buf, fragment...)
		} else if len(fragment) > 0 {
			tooLong = true
			buf = nil
		}
		if errors.Is(readErr, bufio.ErrBufferFull) {
			continue
		}
		if readErr != nil {
			return string(buf), tooLong, false, readErr
		}
		return string(buf), tooLong, true, nil
	}
}

func object(value any) map[string]any {
	m, _ := value.(map[string]any)
	return m
}

// mergeRecordedModels merges the model identifiers of two records for the
// same request (same recordKey). Equal identifiers and the pair
// recorded/missing are compatible — WorkBuddy may repeat a request's usage
// on lines that do not repeat its model — and the recorded identifier wins.
// Two different recorded identifiers conflict: the caller isolates the
// record instead of silently preferring one side. Values are compared and
// returned verbatim; nothing is trimmed or rewritten here.
func mergeRecordedModels(oldValue, newValue any, oldRecorded, newRecorded bool) (any, bool) {
	oldModel, oldOK := oldValue.(string)
	newModel, newOK := newValue.(string)
	if !oldOK || !newOK {
		return nil, false
	}
	switch {
	case !oldRecorded:
		return newValue, true
	case !newRecorded || oldModel == newModel:
		return oldValue, true
	default:
		return nil, false
	}
}

// requestModelIdentifier extracts the model identifier WorkBuddy recorded
// for one request. providerData.requestModelId is the only model field
// verified in the WorkBuddy session JSONL fixtures and documentation: it
// names the model the client requested for the call. No response-side
// model field is verified, so none is read, and the identifier is never
// resolved to a backend model identity. A missing or null field records no
// model and reports "unknown". Any present value that fails the shared
// model validation — an explicit empty or whitespace-only string, a
// non-string, over 128 bytes, or control characters — quarantines the
// record instead of silently collapsing to "unknown". Valid identifiers
// are kept verbatim: no trimming, no rewriting.
func requestModelIdentifier(provider map[string]any) (string, bool) {
	value, exists := provider["requestModelId"]
	if !exists || value == nil {
		return "unknown", true
	}
	if err := adapter.ValidateModel(value); err != nil {
		return "", false
	}
	return value.(string), true
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

// countAliases rejects malformed or contradictory duplicate fields.
func countAliases(m map[string]any, names ...string) (*uint64, error) {
	var found *uint64
	for _, name := range names {
		value, exists := m[name]
		if !exists {
			continue
		}
		if _, ok := value.(json.Number); !ok {
			return nil, fmt.Errorf("invalid %s", name)
		}
		n, ok := adapter.UintAny(value)
		if !ok {
			return nil, fmt.Errorf("invalid %s", name)
		}
		if found != nil && *found != n {
			return nil, errors.New("conflicting usage fields")
		}
		copy := n
		found = &copy
	}
	return found, nil
}

func parseRecord(row map[string]any, fallbackSession string) (adapter.Record, string) {
	typ := text(row["type"])
	message := object(row["message"])
	role := firstString(row["role"], message["role"])
	status := strings.ToLower(firstString(row["status"], message["status"], row["state"], message["state"]))
	if typ == "message" {
		if role != "assistant" && role != "assistant_message" {
			return nil, ""
		}
		if status != "completed" && status != "complete" && status != "success" {
			return nil, ""
		}
	} else if typ != "function_call" {
		return nil, ""
	} else if status != "" && status != "completed" && status != "complete" && status != "success" {
		return nil, ""
	}
	provider := object(row["providerData"])
	raw := object(provider["rawUsage"])
	if raw == nil {
		// Alternate usage schemas have different input/cache semantics.
		return nil, ""
	}
	id := firstString(provider["messageId"], provider["traceId"], row["uuid"], row["id"])
	session := firstString(row["sessionId"], row["session_id"], fallbackSession)
	if id == "" || session == "" {
		return nil, "missing stable request identity"
	}
	occurred, ok := parseTime(row)
	if !ok {
		return nil, "missing or invalid request timestamp"
	}
	prompt, err := countAliases(raw, "prompt_tokens", "input_tokens", "inputTokens")
	if err != nil {
		return nil, "invalid prompt tokens"
	}
	output, err := countAliases(raw, "completion_tokens", "output_tokens", "outputTokens")
	if err != nil {
		return nil, "invalid completion tokens"
	}
	if prompt == nil || output == nil {
		return nil, "missing prompt or completion tokens"
	}
	read, err := countAliases(raw, "prompt_cache_hit_tokens", "cache_read_input_tokens", "cacheReadInputTokens", "cacheTokens", "cached_tokens")
	if err != nil {
		return nil, "invalid cache read tokens"
	}
	details := object(raw["prompt_tokens_details"])
	if details != nil {
		detailRead, e := countAliases(details, "cached_tokens")
		if e != nil {
			return nil, "invalid cache read details"
		}
		if detailRead != nil {
			if read != nil && *read != *detailRead {
				return nil, "conflicting cache read tokens"
			}
			read = detailRead
		}
	}
	write, err := countAliases(raw, "cache_creation_input_tokens", "cacheCreationInputTokens", "cachedWriteTokens", "prompt_cache_write_tokens")
	if err != nil {
		return nil, "invalid cache write tokens"
	}
	miss, err := countAliases(raw, "prompt_cache_miss_tokens", "cachedMissTokens", "cacheMissTokens")
	if err != nil {
		return nil, "invalid cache miss tokens"
	}
	var input *uint64
	if miss != nil {
		input = miss
		if read != nil && write != nil && (*read > *prompt || *write > *prompt-*read || *miss != *prompt-*read-*write) {
			return nil, "inconsistent prompt token components"
		}
	} else {
		readValue, writeValue := uint64(0), uint64(0)
		if read != nil {
			readValue = *read
		}
		if write != nil {
			writeValue = *write
		}
		if readValue > *prompt || writeValue > *prompt-readValue {
			return nil, "cache exceeds prompt tokens"
		}
		n := *prompt - readValue - writeValue
		input = &n
		if read == nil {
			zero := uint64(0)
			read = &zero
		}
		if write == nil {
			zero := uint64(0)
			write = &zero
		}
	}
	total, err := countAliases(raw, "total_tokens")
	if err != nil {
		return nil, "invalid total tokens"
	}
	if total != nil && (*prompt > ^uint64(0)-*output || *total != *prompt+*output) {
		return nil, "inconsistent total tokens"
	}
	outDetails := object(raw["completion_tokens_details"])
	if outDetails != nil {
		reasoning, e := countAliases(outDetails, "reasoning_tokens", "reasoningTokens")
		if e != nil || (reasoning != nil && *reasoning > *output) {
			return nil, "invalid reasoning tokens"
		}
	}
	if *prompt == 0 && *output == 0 {
		return nil, ""
	}
	model, validModel := requestModelIdentifier(provider)
	if !validModel {
		return nil, "invalid request model identifier"
	}
	return adapter.Record{
		"recordKey": "workbuddy-jsonl:" + adapter.ShortHash(session+"\x00"+id),
		"groupKey":  nil, "resetKey": nil, "kind": "delta",
		"occurredAt": occurred.UTC().Format(time.RFC3339Nano),
		"tool":       "WorkBuddy", "model": model, "input": optionalCount(input),
		"cacheRead": optionalCount(read), "cacheWrite": optionalCount(write), "output": optionalCount(output),
		"adapterVersion": "workbuddy-jsonl-v1", "sourceType": adapter.WorkBuddyJSONLSource,
	}, ""
}

func optionalCount(n *uint64) any {
	if n == nil {
		return nil
	}
	return strconv.FormatUint(*n, 10)
}

func sameUsage(a, b adapter.Record) bool {
	for _, key := range []string{"input", "output", "cacheRead", "cacheWrite"} {
		if a[key] != b[key] {
			return false
		}
	}
	return true
}

func parseTime(row map[string]any) (time.Time, bool) {
	for _, key := range []string{"completedAt", "completed_at", "timestamp", "createdAt", "created_at"} {
		switch v := row[key].(type) {
		case string:
			if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
				return t, true
			}
		case json.Number:
			n, err := v.Int64()
			if err == nil && n > 0 {
				if n < 10000000000 {
					return time.Unix(n, 0), true
				}
				return time.UnixMilli(n), true
			}
		}
	}
	return time.Time{}, false
}
