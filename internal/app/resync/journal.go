package resync

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// journalFileName is the single resync job journal. It is resync-owned
// state: nothing else in the collector reads or writes it, and resync never
// mutates the outbox, per-message progress, cursors, quarantine store, or
// batch files. The journal is what makes an interrupted run resumable and a
// repeated upload idempotent locally.
const journalFileName = "resync-journal.json"

const journalSchema = 2

// legacyJournalSchema is the journal format written before the job-level
// scope baseline existed (schema 1): its batches carry per-attempt
// scopeRevision stamps, but the job itself records no scope snapshot.
// loadJob still accepts that format and upgrades the in-memory form; the
// next save persists the current schema. A legacy incomplete journal
// derives its baseline from the per-batch stamps (see jobDecisionRevision)
// and is re-planned whenever those decisions cannot be attributed to the
// live consent revision.
const legacyJournalSchema = 1

// Batch outcomes within one job. "planned" means selected for
// retransmission but not yet attempted; "done" means every derived upload
// was ACKed by the server; "blocked" means a deterministic refusal (local
// grant withdrawn, or every record outside the live consent scope); "failed"
// means the last attempt errored (transient; retried on resume).
const (
	outcomePlanned = "planned"
	outcomeDone    = "done"
	outcomeBlocked = "blocked"
	outcomeFailed  = "failed"
)

// skippedRecord is one record of a planned parent batch that was NOT
// retransmitted because it falls outside the live consent scope. The record
// stays in the original immutable batch file; nothing is quarantined or
// deleted, and a later explicit pass under a wider scope re-evaluates it.
type skippedRecord struct {
	RecordKey string `json:"recordKey"`
	Reason    string `json:"reason"`
}

// jobUpload is one concrete upload executed for a parent batch: either the
// original immutable batch file verbatim (fully in scope and within the
// server size limits) or a deterministic child batch derived from it (scope
// filtering or chunking). Deterministic batch identities make a re-run after
// a crash produce the same upload, which the server answers with a replay
// receipt instead of counting the records twice. Replace marks uploads
// whose records carry acknowledged override content: they are sent with
// BatchRequest.replaceExisting=true so the server's same-key copy is
// replaced instead of rejected as record_conflict.
type jobUpload struct {
	BatchID         string    `json:"batchId"`
	File            string    `json:"file"`
	Records         int       `json:"records"`
	ReceiptStatus   string    `json:"receiptStatus,omitempty"`
	AcceptedRecords int       `json:"acceptedRecords"`
	RejectedRecords int       `json:"rejectedRecords"`
	Replay          bool      `json:"replay"`
	Replace         bool      `json:"replace,omitempty"`
	SyncedAt        time.Time `json:"syncedAt,omitempty"`
}

// jobBatch mirrors one already-synced outbox entry inside the job plan.
// PayloadSHA256 freezes the file content the job was planned against, so a
// resume detects tampering before anything is retransmitted.
type jobBatch struct {
	BatchID       string     `json:"batchId"`
	File          string     `json:"file"`
	Source        string     `json:"source,omitempty"`
	Input         string     `json:"input,omitempty"`
	Records       int        `json:"records"`
	PayloadSHA256 string     `json:"payloadSha256"`
	CreatedAt     time.Time  `json:"createdAt"`
	Outcome       string     `json:"outcome"`
	Attempts      int        `json:"attempts"`
	LastAttemptAt *time.Time `json:"lastAttemptAt,omitempty"`
	// ScopeRevision is the consent revision the last evaluation (upload
	// decision, skipped records, child batch identities) was made under.
	ScopeRevision int64           `json:"scopeRevision,omitempty"`
	Skipped       []skippedRecord `json:"skipped,omitempty"`
	Uploads       []jobUpload     `json:"uploads,omitempty"`
	BlockedReason string          `json:"blockedReason,omitempty"`
	Error         string          `json:"error,omitempty"`
}

// jobScope is the journal's durable record of the live consent scope the
// job's accumulated done/skip decisions were made under. An incomplete
// job whose recorded scope no longer matches the fresh live scope must
// not treat those decisions as completing the current authorization: the
// run re-plans instead, within the job's frozen snapshot universe when
// it has one and over the complete synced history otherwise (see
// reconcileJobScope). Journals written before this field existed
// (schema 1) carry no snapshot; their baseline is derived from the
// per-batch scope revision stamps.
type jobScope struct {
	Revision     int64      `json:"revision"`
	Fingerprint  string     `json:"fingerprint"`
	HistoryFrom  *time.Time `json:"historyFrom,omitempty"`
	UploadUntil  *time.Time `json:"uploadUntil,omitempty"`
	AllowedTools []string   `json:"allowedTools,omitempty"`
}

// jobExclusions records what the job deliberately did not include, so a
// resumed run (and its dry-run) can still report full coverage honestly.
type jobExclusions struct {
	Pending     int      `json:"pending,omitempty"`
	Reorganized int      `json:"reorganized,omitempty"`
	LocalGrant  []string `json:"localGrant,omitempty"`
	// AfterSnapshot counts synced batches excluded because they were
	// synced AFTER the restricting snapshot was captured — for connect's
	// snapshot-restricted automatic pass, the batches that very run's
	// own collection uploaded. Always zero for unrestricted jobs.
	AfterSnapshot int `json:"afterSnapshot,omitempty"`
}

// job is one resync pass: a frozen snapshot of the synced outbox leaves at
// job start, with per-batch outcomes durably updated as the run progresses.
// An incomplete job (CompletedAt nil) is resumed by the next explicit
// `toktrail resync --all`; a completed job is replaced by a fresh full pass,
// which stays safe because batch identities and record keys are stable and
// the server de-duplicates replays. Scope carries the consent scope the
// recorded decisions were made under; a resume that observes a different
// live scope re-plans rather than trusting stale done/skip state.
// OverrideUploads records the receipts of the override-ledger retransmission
// (acknowledged current-scan records no archived batch carries), so a
// resume skips them like batch uploads.
type job struct {
	Schema         int           `json:"schema"`
	JobID          string        `json:"jobId"`
	DeviceID       string        `json:"deviceId"`
	ServerURL      string        `json:"serverUrl"`
	CreatedAt      time.Time     `json:"createdAt"`
	CompletedAt    *time.Time    `json:"completedAt,omitempty"`
	Exclusions     jobExclusions `json:"exclusions,omitempty"`
	Scope          *jobScope     `json:"scope,omitempty"`
	Batches        []jobBatch    `json:"batches"`
	OverrideUpload []jobUpload   `json:"overrideUploads,omitempty"`
	// Snapshot is the frozen batch-id universe this job's plan — and
	// every re-plan of it — is restricted to: the outbox batches that
	// were already synced when the caller captured its snapshot, BEFORE
	// the local grants were applied, so entries the grants excluded at
	// plan time stay in the universe and rejoin a re-plan once a widened
	// authorization allows them again. The universe is preserved
	// verbatim across resume and re-plan: batches synced after the
	// capture (most commonly the same run's collection uploads) can
	// never join this job lineage.
	//
	// nil means the job is unrestricted — the explicit resync pass, and
	// legacy journals written before the field existed — so its plans
	// and re-plans cover the complete synced history, exactly as before.
	// A non-nil Snapshot with zero BatchIDs records a first install
	// (nothing was synced at capture time) and stays distinct from nil.
	Snapshot *SyncedBatchSnapshot `json:"snapshot,omitempty"`
}

func (j job) completed() bool { return j.CompletedAt != nil }

func journalPath(stateDir string) string {
	return filepath.Join(strings.TrimSpace(stateDir), journalFileName)
}

func newJobID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "resync-" + hex.EncodeToString(b[:]), nil
}

func validOutcome(outcome string) bool {
	switch outcome {
	case outcomePlanned, outcomeDone, outcomeBlocked, outcomeFailed:
		return true
	}
	return false
}

func validPayloadHash(hash string) bool {
	if len(hash) != 64 {
		return false
	}
	_, err := hex.DecodeString(hash)
	return err == nil
}

// loadJob reads the resync job journal. A missing journal is (false, nil);
// a corrupt or foreign-schema journal is a hard error: the resume state is
// unknown, so resync fails closed instead of guessing. Removing the file is
// the explicit user action to abandon an interrupted job.
func loadJob(stateDir string) (job, bool, error) {
	b, err := os.ReadFile(journalPath(stateDir))
	if errors.Is(err, os.ErrNotExist) {
		return job{}, false, nil
	}
	if err != nil {
		return job{}, false, err
	}
	var j job
	if err := json.Unmarshal(b, &j); err != nil {
		return job{}, false, fmt.Errorf("corrupt %s: %w; failing closed (remove the file only if you accept abandoning the resume state)", journalPath(stateDir), err)
	}
	if err := j.validate(); err != nil {
		return job{}, false, err
	}
	if j.Schema == legacyJournalSchema {
		// In-place upgrade: the on-disk file keeps its legacy schema until
		// the next save, which then persists the current schema together
		// with the scope baseline the run adopts (or with the re-planned
		// job that replaces this one).
		j.Schema = journalSchema
	}
	return j, true, nil
}

func (j job) validate() error {
	if j.Schema != journalSchema && j.Schema != legacyJournalSchema {
		return fmt.Errorf("corrupt resync journal: unsupported schema %d", j.Schema)
	}
	if j.Scope != nil {
		if j.Scope.Revision <= 0 {
			return fmt.Errorf("corrupt resync journal: scope baseline has no revision")
		}
		if strings.TrimSpace(j.Scope.Fingerprint) == "" {
			return fmt.Errorf("corrupt resync journal: scope baseline has no fingerprint")
		}
	}
	if j.JobID == "" || j.DeviceID == "" || j.ServerURL == "" {
		return fmt.Errorf("corrupt resync journal: missing job id, device id, or server url")
	}
	if j.CreatedAt.IsZero() {
		return fmt.Errorf("corrupt resync journal: missing createdAt")
	}
	seen := make(map[string]bool, len(j.Batches))
	for idx, b := range j.Batches {
		if b.BatchID == "" {
			return fmt.Errorf("corrupt resync journal: batch %d has no batchId", idx)
		}
		if seen[b.BatchID] {
			return fmt.Errorf("corrupt resync journal: duplicate batch %s", b.BatchID)
		}
		seen[b.BatchID] = true
		if b.File == "" || b.Records <= 0 {
			return fmt.Errorf("corrupt resync journal: batch %s has no file or record count", b.BatchID)
		}
		if !validPayloadHash(b.PayloadSHA256) {
			return fmt.Errorf("corrupt resync journal: batch %s has a malformed payload hash", b.BatchID)
		}
		if !validOutcome(b.Outcome) {
			return fmt.Errorf("corrupt resync journal: batch %s has unknown outcome %q", b.BatchID, b.Outcome)
		}
		if b.Outcome == outcomeDone && len(b.Uploads) == 0 {
			return fmt.Errorf("corrupt resync journal: done batch %s records no upload", b.BatchID)
		}
		for uidx, u := range b.Uploads {
			if u.BatchID == "" || u.File == "" || u.Records <= 0 {
				return fmt.Errorf("corrupt resync journal: batch %s upload %d is malformed", b.BatchID, uidx)
			}
		}
		for sidx, s := range b.Skipped {
			if s.RecordKey == "" || s.Reason == "" {
				return fmt.Errorf("corrupt resync journal: batch %s skipped record %d is malformed", b.BatchID, sidx)
			}
		}
	}
	seenOverride := make(map[string]bool, len(j.OverrideUpload))
	for uidx, u := range j.OverrideUpload {
		if u.BatchID == "" || u.File == "" || u.Records <= 0 {
			return fmt.Errorf("corrupt resync journal: override upload %d is malformed", uidx)
		}
		if seenOverride[u.BatchID] {
			return fmt.Errorf("corrupt resync journal: duplicate override upload %s", u.BatchID)
		}
		seenOverride[u.BatchID] = true
	}
	return nil
}

// saveJob persists the journal atomically (tmp + rename, 0600, private
// directory). It is called before the first upload and after every batch
// outcome, so a crash or Ctrl+C at any point leaves a replayable resume
// state. The schema is written as-is: a legacy journal loaded into memory
// was already upgraded, so an ordinary save persists the current schema.
func saveJob(stateDir string, j job) error {
	stateDir = strings.TrimSpace(stateDir)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	path := journalPath(stateDir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// jobDecisionRevision summarizes the live-scope decisions recorded in a
// journal with no job-level scope baseline (a legacy schema-1 journal, or
// a job that never reached its preflight). decided reports whether any
// batch carries a live-scope decision at all (attempted, done, blocked,
// failed, or withheld records); attributable reports whether every such
// decision stamps the same positive consent revision, so all of them can
// be attributed to exactly that revision. Decisions that cannot be
// attributed to a single revision (mixed stamps, or a decided batch with
// no stamp) can never be trusted as completing any live scope and force a
// re-plan.
func jobDecisionRevision(j job) (revision int64, decided, attributable bool) {
	attributable = true
	for _, b := range j.Batches {
		if b.Outcome == outcomePlanned && len(b.Skipped) == 0 && b.ScopeRevision <= 0 {
			continue
		}
		decided = true
		if b.ScopeRevision <= 0 {
			attributable = false
			continue
		}
		if revision == 0 {
			revision = b.ScopeRevision
		} else if revision != b.ScopeRevision {
			attributable = false
		}
	}
	if !decided {
		// Nothing was decided under any scope: no revision to attribute.
		return 0, false, true
	}
	return revision, decided, attributable
}
