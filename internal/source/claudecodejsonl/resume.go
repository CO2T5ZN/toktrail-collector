package claudecodejsonl

// Resumable scanning for claude-code-jsonl.
//
// The Claude Code source merges streaming snapshots of the same API message
// across every session file: the newest distinct usage wins, model
// identifiers are compared across all snapshots, and contradicting ones are
// reported instead of guessed. That cross-file merge is order sensitive, so
// this cache does NOT store a folded per-message state — it stores each
// file's observed usage lines in order and replays them on a cache hit. The
// merge then sees exactly the observation sequence a full rescan would
// produce, which keeps the semantics identical by construction.
//
// Validity is content-based and commit-ordered: a cached file entry is used
// only when the file's current SHA-256 matches the digest recorded for it AND
// that digest is present in the committed scan ledger (internal/local/
// scanledger), which the collection advances only after a source's records
// are safely enqueued. A cache written before a failed export therefore
// cannot cause records to be skipped.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/local/scanledger"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/jsonl"
)

const claudeCacheVersion = 1

// cachedObservation is one usage-bearing line of one session file.
type cachedObservation struct {
	MessageID    string    `json:"id"`
	Timestamp    time.Time `json:"ts"`
	Input        *uint64   `json:"in,omitempty"`
	CacheRead    *uint64   `json:"cr,omitempty"`
	CacheWrite   *uint64   `json:"cw,omitempty"`
	Output       *uint64   `json:"out,omitempty"`
	ModelPresent bool      `json:"mp,omitempty"`
	ModelValue   string    `json:"mv,omitempty"`
	Line         int       `json:"ln"`
}

func (o cachedObservation) toObservation(path string) claudeCodeObservation {
	return claudeCodeObservation{
		MessageID: o.MessageID,
		Timestamp: o.Timestamp,
		Usage: claudeCodeUsage{
			Input:      o.Input,
			CacheRead:  o.CacheRead,
			CacheWrite: o.CacheWrite,
			Output:     o.Output,
		},
		Model: claudeModelSnapshot{present: o.ModelPresent, value: o.ModelValue},
		File:  path,
		Line:  o.Line,
	}
}

func observationToCache(obs claudeCodeObservation) cachedObservation {
	return cachedObservation{
		MessageID:    obs.MessageID,
		Timestamp:    obs.Timestamp,
		Input:        obs.Usage.Input,
		CacheRead:    obs.Usage.CacheRead,
		CacheWrite:   obs.Usage.CacheWrite,
		Output:       obs.Usage.Output,
		ModelPresent: obs.Model.present,
		ModelValue:   obs.Model.value,
		Line:         obs.Line,
	}
}

// fileScan is one file's scan output: its usage observations in line order,
// the diagnostics it produced, and how many lines it quarantined.
type fileScan struct {
	observations []claudeCodeObservation
	issues       []adapter.LineIssue
	quarantined  int
}

// scanClaudeCodeFile walks one session file and collects its observations
// without folding them anywhere, so the caller can either fold them (the
// historical path) or cache them (the resumable path).
func scanClaudeCodeFile(ctx context.Context, path string) (fileScan, error) {
	var scan fileScan
	err := jsonl.WalkLinesContext(ctx, path, func(line jsonl.Line) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		obs, outcome, reason := parseClaudeCodeLine(line.Text, line.File, line.Number)
		switch outcome {
		case claudeLineQuarantine:
			scan.quarantined++
			if len(scan.issues) < maxReportedLineIssues {
				scan.issues = append(scan.issues, adapter.LineIssue{File: line.File, Line: line.Number, Reason: reason})
			}
		case claudeLineObserve:
			scan.observations = append(scan.observations, obs)
		}
		return nil
	})
	if err != nil {
		return fileScan{}, err
	}
	return scan, nil
}

// cacheEntry is one file's cached scan output.
type cacheEntry struct {
	Digest       string              `json:"digest"`
	Observations []cachedObservation `json:"observations,omitempty"`
	Issues       []adapter.LineIssue `json:"issues,omitempty"`
	Quarantined  int                 `json:"quarantined,omitempty"`
}

type cacheDocument struct {
	Version int                   `json:"version"`
	Files   map[string]cacheEntry `json:"files"`
}

// cachePath names the cache for one input root, so two configured roots never
// share a file.
func cachePath(stateDir, input string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(input)))
	return filepath.Join(stateDir, "claude-observations-"+hex.EncodeToString(sum[:8])+".json")
}

func loadCache(stateDir, input string) map[string]cacheEntry {
	raw, err := os.ReadFile(cachePath(stateDir, input))
	if err != nil {
		return map[string]cacheEntry{}
	}
	var doc cacheDocument
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Version != claudeCacheVersion {
		return map[string]cacheEntry{}
	}
	if doc.Files == nil {
		return map[string]cacheEntry{}
	}
	return doc.Files
}

// saveCache writes the cache atomically. A failure is non-fatal for the
// caller: the next scan simply re-parses.
func saveCache(stateDir, input string, files map[string]cacheEntry) error {
	path := cachePath(stateDir, input)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	doc := cacheDocument{Version: claudeCacheVersion, Files: files}
	payload, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// loadClaudeCodeMessagesResuming is the resumable scan: unchanged files whose
// observations were already committed are replayed from the cache instead of
// being re-read and JSON-decoded, while every changed file is parsed exactly
// as before. It returns the merged per-message view, the merged diagnostics,
// the quarantine total and the file states the caller may persist after its
// export commits.
func loadClaudeCodeMessagesResuming(ctx context.Context, path, stateDir string) ([]claudeCodeMessage, []adapter.LineIssue, int, map[string]scanledger.FileState, error) {
	paths, err := jsonl.FilesContext(ctx, path, jsonl.Options{SkipHiddenFiles: true})
	if err != nil {
		return nil, nil, 0, nil, err
	}
	var committed map[string]scanledger.FileState
	if strings.TrimSpace(stateDir) != "" {
		if states, _, lerr := scanledger.New(stateDir).Load(adapter.ClaudeCodeJSONLSource); lerr == nil {
			committed = states
		}
	}
	cached := map[string]cacheEntry{}
	if strings.TrimSpace(stateDir) != "" {
		cached = loadCache(stateDir, path)
	}
	nextCache := make(map[string]cacheEntry, len(paths))
	states := make(map[string]scanledger.FileState, len(paths))
	final := map[string]*claudeCodeMessage{}
	quarantine := &claudeCodeQuarantine{}
	for _, file := range paths {
		if err := ctx.Err(); err != nil {
			return nil, nil, 0, nil, err
		}
		current, unchanged, derr := scanledger.Inspect(file, committed)
		if derr == nil {
			states[file] = current
		}
		if derr == nil && unchanged {
			if entry, ok := cached[file]; ok && entry.Digest == current.Digest {
				// Committed and provably unchanged: replay its
				// observations in the original order.
				for _, obs := range entry.Observations {
					applyClaudeObservation(final, obs.toObservation(file), quarantine)
				}
				quarantine.issues = appendCappedIssues(quarantine.issues, entry.Issues)
				quarantine.total += entry.Quarantined
				nextCache[file] = entry
				continue
			}
			// Committed but no cache (lost or never written): parse below.
		}
		scan, serr := scanClaudeCodeFile(ctx, file)
		if serr != nil {
			return nil, nil, 0, nil, serr
		}
		for _, obs := range scan.observations {
			applyClaudeObservation(final, obs, quarantine)
		}
		quarantine.issues = appendCappedIssues(quarantine.issues, scan.issues)
		quarantine.total += scan.quarantined
		if derr == nil {
			cachedObs := make([]cachedObservation, 0, len(scan.observations))
			for _, obs := range scan.observations {
				cachedObs = append(cachedObs, observationToCache(obs))
			}
			nextCache[file] = cacheEntry{Digest: current.Digest, Observations: cachedObs, Issues: scan.issues, Quarantined: scan.quarantined}
		}
	}
	if strings.TrimSpace(stateDir) != "" {
		// Cache writes are an accelerator only: a failure never fails the scan.
		_ = saveCache(stateDir, path, nextCache)
	}
	messages := make([]claudeCodeMessage, 0, len(final))
	for _, message := range final {
		message.resolveClaudeModel(quarantine)
		messages = append(messages, *message)
	}
	sort.Slice(messages, func(i, j int) bool { return messages[i].ID < messages[j].ID })
	return messages, quarantine.issues, quarantine.total, states, nil
}

// appendCappedIssues appends diagnostics up to the reporting cap.
func appendCappedIssues(dst, src []adapter.LineIssue) []adapter.LineIssue {
	for _, issue := range src {
		if len(dst) >= maxReportedLineIssues {
			return dst
		}
		dst = append(dst, issue)
	}
	return dst
}

// LoadResuming is the adapter entry point: the historical Load when no state
// directory is configured, the resumable scan otherwise.
func LoadResuming(opt adapter.Options) (adapter.LoadResult, error) {
	if strings.TrimSpace(opt.StateDir) == "" && strings.TrimSpace(opt.Output) != "" {
		return adapter.LoadResult{}, fmt.Errorf("claude-code-jsonl export requires a state directory (Set --state-dir / TOKTRAIL_HOME) so usage baselines are not double counted")
	}
	var (
		messages    []claudeCodeMessage
		issues      []adapter.LineIssue
		quarantined int
		states      map[string]scanledger.FileState
		err         error
	)
	if strings.TrimSpace(opt.StateDir) == "" {
		messages, issues, quarantined, err = loadClaudeCodeMessages(opt.ContextOrBackground(), opt.Input)
	} else {
		messages, issues, quarantined, states, err = loadClaudeCodeMessagesResuming(opt.ContextOrBackground(), opt.Input, opt.StateDir)
	}
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
	return adapter.LoadResult{Records: records, Issues: issues, Quarantined: quarantined, MessageUpdates: updates, ScanStates: states}, nil
}
