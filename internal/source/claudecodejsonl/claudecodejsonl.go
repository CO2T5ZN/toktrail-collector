package claudecodejsonl

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/jsonl"
)

const (
	claudeCodeAdapterVersion = "claude-code-jsonl-v1"
	claudeCodeTool           = "Claude Code"
	// claudeUnknownModel is the reported model when no snapshot of a
	// message records a usable identifier, or when snapshots contradict
	// each other. Missing is mapped explicitly; it is never guessed.
	claudeUnknownModel = "unknown"
	// claudeMissingModelReason is the local, value-free diagnostic for a
	// message whose snapshots never record a model identifier: the record
	// still exports with the explicit "unknown" mapping, so the gap is
	// surfaced without embedding any value and without quarantining the
	// usage. A literal recorded "unknown" identifier is data, not a gap,
	// and never triggers this diagnostic.
	claudeMissingModelReason = "model missing from every snapshot of this message; reporting unknown"
)

// maxReportedLineIssues caps how many quarantined lines are kept for
// reporting; the total count is tracked separately.
const maxReportedLineIssues = 50

type claudeCodeUsage struct {
	Input      *uint64
	CacheRead  *uint64
	CacheWrite *uint64
	Output     *uint64
}

func (u claudeCodeUsage) equal(v claudeCodeUsage) bool {
	return usagePointerEqual(u.Input, v.Input) &&
		usagePointerEqual(u.CacheRead, v.CacheRead) &&
		usagePointerEqual(u.CacheWrite, v.CacheWrite) &&
		usagePointerEqual(u.Output, v.Output)
}

func usagePointerEqual(a, b *uint64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func (u claudeCodeUsage) components() [4]*uint64 {
	return [4]*uint64{u.Input, u.CacheRead, u.CacheWrite, u.Output}
}

func messageUsageComponents(s progress.MessageUsageState) [4]*uint64 {
	return [4]*uint64{s.Input, s.CacheRead, s.CacheWrite, s.Output}
}

// claudeUsageComponentNames are the API field names used in diagnostics.
var claudeUsageComponentNames = [4]string{"input_tokens", "cache_read_input_tokens", "cache_creation_input_tokens", "output_tokens"}

// claudeModelSnapshot is the model identifier recorded by one assistant
// snapshot. present is false when the snapshot carries no model at all
// (absent key or JSON null); value is the identifier verbatim otherwise —
// never trimmed, rewritten, or guessed.
type claudeModelSnapshot struct {
	present bool
	value   string
}

// claudeModelSnapshotFrom extracts the model identifier recorded by an
// assistant message object, verbatim. The model may be a plain string or an
// object with an id field. An absent key or JSON null is not an error: the
// snapshot simply carries no model. Any other shape that yields no valid
// identifier (empty or whitespace-only string, number, object without a
// usable id, control characters, over-long values) fails the shared
// validation so the line is quarantined instead of silently degrading the
// record to "unknown".
func claudeModelSnapshotFrom(message map[string]any) (claudeModelSnapshot, error) {
	raw, ok := message["model"]
	if !ok || raw == nil {
		return claudeModelSnapshot{}, nil
	}
	candidate := raw
	if object, isObject := raw.(map[string]any); isObject {
		id, hasID := object["id"]
		if !hasID || id == nil {
			candidate = ""
		} else {
			candidate = id
		}
	}
	if err := adapter.ValidateModel(candidate); err != nil {
		return claudeModelSnapshot{}, err
	}
	value, _ := candidate.(string)
	return claudeModelSnapshot{present: true, value: value}, nil
}

// claudeCodeObservation is one assistant message.usage observation. The same
// message.id can appear as several observations: streaming snapshots of one
// response grow toward the final usage, and the same session content can be
// duplicated or renamed across the scanned input. Model carries the verified
// identifier this snapshot records, if any.
type claudeCodeObservation struct {
	MessageID string
	Timestamp time.Time
	Usage     claudeCodeUsage
	Model     claudeModelSnapshot
	File      string
	Line      int
}

// claudeCodeMessage is the deduplicated view of one assistant message keyed
// by API message.id. Usage is the latest distinct observed value, selected
// by observation timestamp (newest wins; equal-timestamp ties keep the
// within-file line order). The timestamp and source location come from the
// first observation of that latest distinct value (representative), which
// keeps exports deterministic regardless of file order or duplicates. The
// model is resolved independently of the representative: it is the single
// recorded identifier carried by every snapshot of the message — verbatim,
// or "unknown" when no snapshot records one or snapshots contradict each
// other.
type claudeCodeMessage struct {
	ID        string
	Model     string
	Timestamp time.Time
	Usage     claudeCodeUsage
	File      string
	Line      int

	// modelObserved holds the one valid identifier recorded so far (""
	// while none has been seen); modelConflict marks that snapshots
	// recorded contradicting identifiers. Model is derived from both once
	// the scan completes (resolveClaudeModel), never mid-scan.
	modelObserved string
	modelConflict bool
}

// resolveClaudeModel finalizes the per-message model after the scan: the
// single recorded identifier verbatim, or "unknown" when every snapshot
// omitted the model or snapshots conflicted. It never picks between
// contradicting identifiers. A message whose snapshots all omit the model
// additionally emits one local, value-free diagnostic at the usage
// representative: the record still exports with "unknown" and nothing is
// quarantined, while a literal recorded "unknown" identifier is kept as
// data and never misreported as missing.
func (m *claudeCodeMessage) resolveClaudeModel(quarantine *claudeCodeQuarantine) {
	switch {
	case m.modelConflict:
		m.Model = claudeUnknownModel
	case m.modelObserved == "":
		quarantine.report(m.File, m.Line, claudeMissingModelReason)
		m.Model = claudeUnknownModel
	default:
		m.Model = m.modelObserved
	}
}

type claudeLineOutcome int

const (
	// claudeLineIgnore: the line carries no usage to attribute (non-assistant
	// line, assistant line without message or usage). Not an error.
	claudeLineIgnore claudeLineOutcome = iota
	// claudeLineObserve: a valid usage observation.
	claudeLineObserve
	// claudeLineQuarantine: the line looks like usage but is invalid, or a
	// usage-bearing assistant line lacks stable message identity.
	claudeLineQuarantine
)

type claudeCodeQuarantine struct {
	issues []adapter.LineIssue
	total  int
}

func (q *claudeCodeQuarantine) add(file string, line int, reason string) {
	q.total++
	q.report(file, line, reason)
}

// report records a diagnostic without quarantining the line: the line's
// usage stays valid and counted (for example a model conflict between two
// valid snapshots of one message), but the problem is surfaced instead of
// being silently resolved.
func (q *claudeCodeQuarantine) report(file string, line int, reason string) {
	if len(q.issues) < maxReportedLineIssues {
		q.issues = append(q.issues, adapter.LineIssue{File: file, Line: line, Reason: reason})
	}
}

// loadClaudeCodeMessages scans Claude Code session JSONL and returns the
// per-message (message.id keyed) latest usage snapshots together with each
// message's recorded model identifier, sorted by message id for
// deterministic output. Only assistant message.usage counters are read;
// every other field stays local. Invalid lines are quarantined and reported
// instead of aborting the scan, and a message whose snapshots never record
// a model gets one local diagnostic while still exporting "unknown". The
// context is checked during discovery, per file, and per line; cancellation
// returns ctx.Err() with no partial messages, so an interrupted scan never
// reaches record building or pending-state updates.
func loadClaudeCodeMessages(ctx context.Context, path string) ([]claudeCodeMessage, []adapter.LineIssue, int, error) {
	paths, err := jsonl.FilesContext(ctx, path, jsonl.Options{SkipHiddenFiles: true})
	if err != nil {
		return nil, nil, 0, err
	}
	quarantine := &claudeCodeQuarantine{}
	final := map[string]*claudeCodeMessage{}
	for _, file := range paths {
		if err := ctx.Err(); err != nil {
			return nil, nil, 0, err
		}
		if err := loadClaudeCodeJSONLFile(ctx, file, final, quarantine); err != nil {
			return nil, nil, 0, err
		}
	}
	messages := make([]claudeCodeMessage, 0, len(final))
	for _, message := range final {
		message.resolveClaudeModel(quarantine)
		messages = append(messages, *message)
	}
	sort.Slice(messages, func(i, j int) bool { return messages[i].ID < messages[j].ID })
	return messages, quarantine.issues, quarantine.total, nil
}

// applyClaudeObservation merges one observation into the per-message state.
// The latest distinct usage value wins by observation timestamp, not by scan
// order: an observation older than the current snapshot is stale and ignored,
// a newer-or-equal observation replaces the usage and re-selects the
// representative, and an equal usage value keeps the earlier representative.
// Equal-timestamp ties stay resolved by within-file line order, so two
// same-instant observations with different usage remain file-order dependent.
// The model is merged separately by mergeClaudeModelSnapshot: it is resolved
// across every snapshot of the message, independently of which snapshot is
// the usage representative.
func applyClaudeObservation(final map[string]*claudeCodeMessage, obs claudeCodeObservation, quarantine *claudeCodeQuarantine) {
	current, ok := final[obs.MessageID]
	if !ok {
		current = &claudeCodeMessage{
			ID:        obs.MessageID,
			Timestamp: obs.Timestamp,
			Usage:     obs.Usage,
			File:      obs.File,
			Line:      obs.Line,
		}
		final[obs.MessageID] = current
	} else if !current.Usage.equal(obs.Usage) && !obs.Timestamp.Before(current.Timestamp) {
		current.Usage = obs.Usage
		current.Timestamp = obs.Timestamp
		current.File = obs.File
		current.Line = obs.Line
	}
	mergeClaudeModelSnapshot(current, obs, quarantine)
}

// mergeClaudeModelSnapshot folds one snapshot's verified model identifier
// into the per-message model state. Snapshots that carry no model keep the
// identifier already recorded by other snapshots of the same message (a
// streaming snapshot may omit the field); they never erase or invent one.
// Two different identifiers on the same message id are a conflict: refusing
// to guess, the conflict is reported and the message's model becomes
// "unknown" while its usage keeps the existing dedup semantics.
func mergeClaudeModelSnapshot(current *claudeCodeMessage, obs claudeCodeObservation, quarantine *claudeCodeQuarantine) {
	if !obs.Model.present {
		return
	}
	switch {
	case current.modelConflict:
		// Already reported; later snapshots add nothing.
	case current.modelObserved == "":
		current.modelObserved = obs.Model.value
	case current.modelObserved != obs.Model.value:
		current.modelConflict = true
		quarantine.report(obs.File, obs.Line, fmt.Sprintf("model conflict on one message id: earlier snapshots record %q, this snapshot records %q; reporting unknown instead of guessing", current.modelObserved, obs.Model.value))
	}
}

// loadClaudeCodeJSONLFile folds one session file into the per-message state.
// Cancellation is NOT a quarantine case: a ctx.Err() from the per-line check
// aborts the whole scan instead of being counted as a bad line, and the
// caller discards everything.
func loadClaudeCodeJSONLFile(ctx context.Context, path string, final map[string]*claudeCodeMessage, quarantine *claudeCodeQuarantine) error {
	return jsonl.WalkLinesContext(ctx, path, func(line jsonl.Line) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		obs, outcome, reason := parseClaudeCodeLine(line.Text, line.File, line.Number)
		switch outcome {
		case claudeLineQuarantine:
			quarantine.add(line.File, line.Number, reason)
		case claudeLineObserve:
			applyClaudeObservation(final, obs, quarantine)
		}
		return nil
	})
}

func parseClaudeCodeLine(line string, path string, lineNo int) (claudeCodeObservation, claudeLineOutcome, string) {
	var obs claudeCodeObservation
	raw, err := jsonl.DecodeObject(line)
	if err != nil {
		return obs, claudeLineQuarantine, "invalid JSON: " + err.Error()
	}
	if adapter.StringAny(raw["type"]) != "assistant" {
		return obs, claudeLineIgnore, ""
	}
	message, ok := raw["message"].(map[string]any)
	if !ok {
		return obs, claudeLineIgnore, ""
	}
	usageValue, present := message["usage"]
	if !present || usageValue == nil {
		return obs, claudeLineIgnore, ""
	}
	usage, ok := usageValue.(map[string]any)
	if !ok {
		return obs, claudeLineQuarantine, "message.usage must be an object"
	}
	obs.MessageID = adapter.StringAny(message["id"])
	if obs.MessageID == "" {
		// The per-line uuid is NOT a message identity: without message.id the
		// streaming snapshots of one response cannot be grouped, so skip the
		// line conservatively rather than risk double counting.
		return obs, claudeLineQuarantine, "assistant usage line missing message.id"
	}
	timestampStr := adapter.StringAny(raw["timestamp"])
	if timestampStr == "" {
		return obs, claudeLineQuarantine, "missing timestamp"
	}
	timestamp, err := time.Parse(time.RFC3339, timestampStr)
	if err != nil {
		return obs, claudeLineQuarantine, "invalid timestamp: " + err.Error()
	}
	usageCounts, reason := parseClaudeCodeUsage(usage)
	if reason != "" {
		return obs, claudeLineQuarantine, reason
	}
	if usageCounts.Input == nil && usageCounts.CacheRead == nil && usageCounts.CacheWrite == nil && usageCounts.Output == nil {
		// A usage object without any known counter carries no usage
		// information; unknown is not zero, so there is nothing to record.
		return obs, claudeLineIgnore, ""
	}
	model, modelErr := claudeModelSnapshotFrom(message)
	if modelErr != nil {
		// A recorded but malformed model invalidates the whole line: the
		// usage is not attributed and the line is quarantined, instead of
		// silently degrading the record's model to "unknown".
		return obs, claudeLineQuarantine, "invalid model: " + modelErr.Error()
	}
	obs.Timestamp = timestamp
	obs.Usage = usageCounts
	obs.Model = model
	obs.File = path
	obs.Line = lineNo
	return obs, claudeLineObserve, ""
}

// parseClaudeCodeUsage reads the four Anthropic usage counters. Absent or
// null counters stay unknown (nil), never zero. Present counters must be
// exact non-negative decimal integers within uint64; fractions, exponents,
// signs, and overflow are rejected.
func parseClaudeCodeUsage(usage map[string]any) (claudeCodeUsage, string) {
	var u claudeCodeUsage
	fields := []struct {
		key   string
		field **uint64
	}{
		{"input_tokens", &u.Input},
		{"cache_read_input_tokens", &u.CacheRead},
		{"cache_creation_input_tokens", &u.CacheWrite},
		{"output_tokens", &u.Output},
	}
	for _, f := range fields {
		v, present := usage[f.key]
		if !present || v == nil {
			continue
		}
		n, ok := adapter.UintAny(v)
		if !ok {
			return claudeCodeUsage{}, fmt.Sprintf("usage %s must be a non-negative integer within uint64 range", f.key)
		}
		value := n
		*f.field = &value
	}
	return u, ""
}

// loadClaudeMessageProgress loads the per-message baselines for
// claude-code-jsonl and enforces the progress-integrity rule: after prior
// claude-code-jsonl exports from this state directory, a missing or empty
// progress state is a hard error, because re-baselining from zero would
// double count usage on the server. The very first initialization on a
// fresh state directory succeeds normally.
func loadClaudeMessageProgress(stateDir string) (map[string]progress.MessageProgress, error) {
	store := progress.New(stateDir)
	progress, _, err := store.MessageProgressFor(adapter.ClaudeCodeJSONLSource)
	if err != nil {
		return nil, fmt.Errorf("claude-code-jsonl message progress state unusable at %s: %w", store.MessageProgressPath(), err)
	}
	if len(progress) > 0 {
		return progress, nil
	}
	used, err := store.HasSource(adapter.ClaudeCodeJSONLSource)
	if err != nil {
		return nil, fmt.Errorf("claude-code-jsonl cannot check prior export state: %w", err)
	}
	if used {
		return nil, fmt.Errorf("claude-code-jsonl message progress state is missing at %s after prior exports from this state directory; refusing to re-baseline from zero because that would double count already-uploaded usage. Restore the state directory (message-progress.json) from a backup, or start fresh with a new state directory and a newly bound device", store.MessageProgressPath())
	}
	return progress, nil
}

// claudeStateString renders a counted-state snapshot for record identity:
// decimal per known component, "-" per unknown component.
func claudeStateString(vals [4]*uint64) string {
	parts := make([]string, 4)
	for i, v := range vals {
		if v == nil {
			parts[i] = "-"
		} else {
			parts[i] = strconv.FormatUint(*v, 10)
		}
	}
	return strings.Join(parts, ",")
}

// claudeIntervalKey derives the record key for one interval. The key hashes
// only stable identity (message id, from-state, to-state): re-uploading the
// same interval replays identically server-side, while a grown message
// produces a different key carrying only the incremental delta.
func claudeIntervalKey(messageID string, fromState, toState string) string {
	return "claude-code-jsonl:" + adapter.ShortHash(messageID+"\x00"+fromState+"\x00"+toState)
}

// claudeIntervalDelta computes the per-component interval between the
// confirmed baseline and the current snapshot:
//   - fresh message (no baseline): delta = current value, to = current value
//     (explicit zero stays "0", unknown stays null);
//   - both known and current >= baseline: delta = current - baseline;
//   - current < baseline: the whole message is skipped as a diagnostic
//     (regression), baseline untouched;
//   - baseline known, current unknown: component not counted, to keeps the
//     already-counted baseline value (diagnostic);
//   - baseline unknown, current known: the first known value establishes a
//     NEW baseline without being counted (no backfill), so the delta stays
//     nil and to adopts the known value only after the server ACKs the
//     baseline-only interval (rebased = true).
//
// Unknown is never treated as zero.
func claudeIntervalDelta(base *progress.MessageUsageState, cur claudeCodeUsage) (deltas [4]*uint64, to progress.MessageUsageState, diagnostics []string, rebased, regression bool) {
	curVals := cur.components()
	if base == nil {
		to = progress.MessageUsageState{Input: curVals[0], CacheRead: curVals[1], CacheWrite: curVals[2], Output: curVals[3]}
		return curVals, to, nil, false, false
	}
	baseVals := [4]*uint64{base.Input, base.CacheRead, base.CacheWrite, base.Output}
	var toVals [4]*uint64
	for i := 0; i < 4; i++ {
		b, c := baseVals[i], curVals[i]
		name := claudeUsageComponentNames[i]
		switch {
		case b == nil && c == nil:
			toVals[i] = nil
		case b == nil && c != nil:
			diagnostics = append(diagnostics, fmt.Sprintf("%s changed from unknown to known; first known value %d establishes a new baseline and is not counted", name, *c))
			toVals[i] = c
			rebased = true
		case b != nil && c == nil:
			diagnostics = append(diagnostics, fmt.Sprintf("%s changed from known to unknown; counted value unchanged", name))
			toVals[i] = b
		case *c < *b:
			diagnostics = append(diagnostics, fmt.Sprintf("%s decreased from %d to %d; message interval skipped", name, *b, *c))
			regression = true
			toVals[i] = b
		default:
			delta := *c - *b
			deltas[i] = &delta
			toVals[i] = c
		}
	}
	to = progress.MessageUsageState{Input: toVals[0], CacheRead: toVals[1], CacheWrite: toVals[2], Output: toVals[3]}
	return deltas, to, diagnostics, rebased, regression
}

func anyDeltaPositive(deltas [4]*uint64) bool {
	for _, d := range deltas {
		if d != nil && *d > 0 {
			return true
		}
	}
	return false
}

// buildClaudeCodeRecords turns per-message snapshots into interval delta
// records plus pending-state updates. Messages with an unACKed pending
// interval are frozen and skipped. Messages whose last interval the server
// rejected are not re-sent with the same key; growth still exports the
// incremental delta from the unchanged baseline under a new key.
func buildClaudeCodeRecords(messages []claudeCodeMessage, progressByMessage map[string]progress.MessageProgress) ([]adapter.Record, []progress.MessagePendingUpdate, []adapter.LineIssue) {
	var records []adapter.Record
	var updates []progress.MessagePendingUpdate
	var issues []adapter.LineIssue
	addIssue := func(message claudeCodeMessage, reason string) {
		if len(issues) < maxReportedLineIssues {
			issues = append(issues, adapter.LineIssue{File: message.File, Line: message.Line, Reason: reason})
		}
	}
	for _, message := range messages {
		entry := progressByMessage[message.ID]
		if entry.Pending != nil {
			// Frozen until the pending batch is ACKed or rejected.
			continue
		}
		if entry.QuarantinedKey != "" {
			// The last interval fell outside the live consent scope and is
			// held in the recoverable quarantine store. Skipping here breaks
			// the re-export loop: the interval is neither re-emitted nor
			// re-baselined until scope recovery re-pends it and the server
			// ACKs it.
			addIssue(message, fmt.Sprintf("interval %s is quarantined outside the consent scope (%s); waiting for scope recovery before it is re-sent", entry.QuarantinedKey, entry.QuarantinedReason))
			continue
		}
		base := entry.Confirmed
		deltas, to, diagnostics, rebased, regression := claudeIntervalDelta(base, message.Usage)
		for _, diag := range diagnostics {
			addIssue(message, diag)
		}
		if regression {
			continue
		}
		fromState := "0,0,0,0"
		if base != nil {
			fromState = claudeStateString([4]*uint64{base.Input, base.CacheRead, base.CacheWrite, base.Output})
		}
		key := claudeIntervalKey(message.ID, fromState, claudeStateString(messageUsageComponents(to)))
		if entry.RejectedKey != "" && entry.RejectedKey == key {
			addIssue(message, fmt.Sprintf("interval %s was rejected by the server (%s); not resent automatically", key, entry.RejectedCode))
			continue
		}
		// A rebased component (unknown → first known) emits a baseline-only
		// interval: every count is null, nothing is counted, and the new
		// baseline only advances when the server ACKs the batch.
		emit := base == nil || anyDeltaPositive(deltas) || rebased
		if !emit {
			// No growth since the baseline: nothing to upload or re-baseline.
			continue
		}
		records = append(records, claudeCodeRecord(message, key, deltas))
		updates = append(updates, progress.MessagePendingUpdate{
			MessageID: message.ID,
			RecordKey: key,
			To:        &to,
		})
	}
	sort.Slice(records, func(i, j int) bool {
		a := adapter.StringField(records[i], "occurredAt")
		b := adapter.StringField(records[j], "occurredAt")
		if a == b {
			return adapter.StringField(records[i], "recordKey") < adapter.StringField(records[j], "recordKey")
		}
		return a < b
	})
	return records, updates, issues
}

// Load is the stateful loader behind Scan, Preview, and PrepareExport. With
// a state directory it loads the confirmed per-message baselines (enforcing
// the progress-integrity rule) and emits incremental intervals; without one
// it emits the full current usage per message. Each record carries the model
// identifier recorded in the history for that message, preserved verbatim;
// missing models report "unknown" (with a local, value-free diagnostic) and
// conflicting or malformed models are
// reported, never guessed.
func Load(opt adapter.Options) (adapter.LoadResult, error) {
	if strings.TrimSpace(opt.StateDir) == "" && strings.TrimSpace(opt.Output) != "" {
		return adapter.LoadResult{}, fmt.Errorf("claude-code-jsonl export requires a state directory (Set --state-dir / TOKTRAIL_HOME) so usage baselines are not double counted")
	}
	messages, issues, quarantined, err := loadClaudeCodeMessages(opt.ContextOrBackground(), opt.Input)
	if err != nil {
		return adapter.LoadResult{}, err
	}
	progress := map[string]progress.MessageProgress{}
	if strings.TrimSpace(opt.StateDir) != "" {
		progress, err = loadClaudeMessageProgress(opt.StateDir)
		if err != nil {
			return adapter.LoadResult{}, err
		}
	}
	records, updates, intervalIssues := buildClaudeCodeRecords(messages, progress)
	issues = append(issues, intervalIssues...)
	return adapter.LoadResult{Records: records, Issues: issues, Quarantined: quarantined, MessageUpdates: updates}, nil
}

// claudeCodeRecord builds the interval delta record for one message. The
// recordKey and groupKey derive only from the API message id (never session
// ids, file names, or paths), so copying or renaming log files cannot change
// the uploaded identity.
func claudeCodeRecord(message claudeCodeMessage, key string, deltas [4]*uint64) adapter.Record {
	return adapter.Record{
		"recordKey":      key,
		"groupKey":       "claude-code-message:" + adapter.ShortHash(message.ID),
		"resetKey":       nil,
		"kind":           "delta",
		"occurredAt":     message.Timestamp.UTC().Format(time.RFC3339),
		"tool":           claudeCodeTool,
		"model":          message.Model,
		"input":          decimalOrNil(deltas[0]),
		"cacheRead":      decimalOrNil(deltas[1]),
		"cacheWrite":     decimalOrNil(deltas[2]),
		"output":         decimalOrNil(deltas[3]),
		"adapterVersion": claudeCodeAdapterVersion,
		"sourceType":     adapter.ClaudeCodeJSONLSource,
	}
}

func decimalOrNil(v *uint64) any {
	if v == nil {
		return nil
	}
	return fmt.Sprintf("%d", *v)
}

func Adapter() adapter.Adapter {
	return adapter.Adapter{Source: adapter.ClaudeCodeJSONLSource, Description: "Claude Code session JSONL", Load: LoadResuming, ValidateCommit: func(stateDir string) error {
		if strings.TrimSpace(stateDir) == "" {
			return nil
		}
		_, err := loadClaudeMessageProgress(stateDir)
		return err
	}}
}
