package resync

// Cross-version journal compatibility tests (P6 rollback boundary).
//
// WHAT THESE TESTS ARE ABOUT
//
// The NEW collector (this working tree) writes resync journals that carry a
// frozen snapshot universe (job.Snapshot, schema 2, additive omitempty
// fields `snapshot` and `exclusions.afterSnapshot`). The OLD collector
// binary (repo HEAD, which predates the field) decodes the same file with
// encoding/json and NO DisallowUnknownFields, so the decode SUCCEEDS while
// the snapshot field is silently dropped. That is NOT a lossless load:
//
//   - while the old binary only RESUMES the job without re-planning, it
//     executes journal.Batches — which the new binary already restricted —
//     so nothing diverges yet;
//   - the moment the old binary RE-PLANS the job (an incomplete journal
//     whose recorded scope no longer matches the live consent scope), its
//     replanJob has no universe to preserve, so the replacement plan is
//     built over the COMPLETE synced history — including batches synced
//     after the snapshot capture, which the new binary would have kept
//     excluded. The replacement journal it writes back has no snapshot,
//     so the frozen boundary is permanently lost for that job lineage,
//     even after upgrading forward again.
//
// The divergence is therefore wider retransmission under the old binary.
// These tests EXECUTE that divergence offline, with no server, no network
// listener, and no subprocess, by driving the re-plan machinery directly.
//
// WHAT IS AND IS NOT VERIFIED HERE
//
// Verified (offline, this file):
//   1. A journal written by the new machinery decodes without error into a
//      struct that mirrors the OLD binary's job type field-for-field — the
//      fields the old binary reads are all present and well-typed — while
//      the snapshot is invisible to that shape by construction.
//   2. Re-planning that journal through the NEW machinery with the snapshot
//      intact stays within the frozen universe (3 of 6 batches).
//   3. Re-planning the same journal with the snapshot erased — exactly the
//      state the old binary's decode produces, since Unmarshal drops the
//      unknown field and every other field decodes identically — expands
//      to the complete synced history (6 of 6 batches), and the persisted
//      replacement journal has no snapshot (the freeze does not survive
//      the old binary's write-back).
//
// NOT verified here (do not claim otherwise):
//   - the old BINARY end-to-end (its own Unmarshal, its own replanJob):
//     item 3 relies on the equivalence argument that the worktree's
//     nil-restriction buildNewJob branch is byte-for-byte the HEAD
//     universe-selection loop (verified by diffing buildNewJob between HEAD
//     and this tree: the only changes are the restrict parameter, the
//     only-filter, the AfterSnapshot counter, and the Snapshot field — all
//     inert when restrict is nil), plus the field-level decode proof of
//     item 1. The binary-level confirmation belongs to the gated
//     cross-version harness (old collector binary against a fake self
//     endpoint) and is intentionally deferred.
//   - any server-side consequence of the wider retransmission: replay
//     idempotency across versions is the DESIGN INTENT (deterministic
//     batch identities), but no cross-version, real-server verification
//     has run, so nothing here may be read as a guarantee of "no duplicate
//     side effects". That question stays open until the gated harness
//     executes against a throwaway server.

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/statedir"
)

// crossOld* mirror the OLD binary's journal types, copied field-for-field
// from internal/app/resync/journal.go at repo HEAD (commit f92bf83) — the
// version the archived old binary is built from. Deliberately WITHOUT the
// snapshot and afterSnapshot fields the new working tree added: this is the
// shape the old binary actually decodes into. If the old shape ever needs
// updating (a different "old" baseline), copy the new HEAD again and cite
// the commit here.
type crossOldSkippedRecord struct {
	RecordKey string `json:"recordKey"`
	Reason    string `json:"reason"`
}

type crossOldJobUpload struct {
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

type crossOldJobBatch struct {
	BatchID       string                  `json:"batchId"`
	File          string                  `json:"file"`
	Source        string                  `json:"source,omitempty"`
	Input         string                  `json:"input,omitempty"`
	Records       int                     `json:"records"`
	PayloadSHA256 string                  `json:"payloadSha256"`
	CreatedAt     time.Time               `json:"createdAt"`
	Outcome       string                  `json:"outcome"`
	Attempts      int                     `json:"attempts"`
	LastAttemptAt *time.Time              `json:"lastAttemptAt,omitempty"`
	ScopeRevision int64                   `json:"scopeRevision,omitempty"`
	Skipped       []crossOldSkippedRecord `json:"skipped,omitempty"`
	Uploads       []crossOldJobUpload     `json:"uploads,omitempty"`
	BlockedReason string                  `json:"blockedReason,omitempty"`
	Error         string                  `json:"error,omitempty"`
}

type crossOldJobScope struct {
	Revision     int64      `json:"revision"`
	Fingerprint  string     `json:"fingerprint"`
	HistoryFrom  *time.Time `json:"historyFrom,omitempty"`
	UploadUntil  *time.Time `json:"uploadUntil,omitempty"`
	AllowedTools []string   `json:"allowedTools,omitempty"`
}

type crossOldJobExclusions struct {
	Pending     int      `json:"pending,omitempty"`
	Reorganized int      `json:"reorganized,omitempty"`
	LocalGrant  []string `json:"localGrant,omitempty"`
}

type crossOldJob struct {
	Schema         int                   `json:"schema"`
	JobID          string                `json:"jobId"`
	DeviceID       string                `json:"deviceId"`
	ServerURL      string                `json:"serverUrl"`
	CreatedAt      time.Time             `json:"createdAt"`
	CompletedAt    *time.Time            `json:"completedAt,omitempty"`
	Exclusions     crossOldJobExclusions `json:"exclusions,omitempty"`
	Scope          *crossOldJobScope     `json:"scope,omitempty"`
	Batches        []crossOldJobBatch    `json:"batches"`
	OverrideUpload []crossOldJobUpload   `json:"overrideUploads,omitempty"`
}

// crossJournalFixture builds a synthetic state directory whose journal is
// exactly what the NEW binary persists for an interrupted restricted pass:
// six synced batches, the first three frozen as the snapshot universe, the
// recorded scope baseline at revision 1 (the live scope will be at revision
// 2, which is the re-plan trigger). The URL is never dialed — the re-plan
// machinery is offline; only Run would use it.
func crossJournalFixture(t *testing.T) (dir string, st statedir.DeviceState) {
	t.Helper()
	const url = "http://cross-version.invalid"
	batches := make([][]json.RawMessage, 6)
	for i := range batches {
		batches[i] = []json.RawMessage{record("cross-"+string(rune('a'+i)), "2026-10-2"+string(rune('0'+i))+"T00:00:00Z")}
	}
	dir = fixture(t, url, batches...)
	loaded, err := statedir.New(dir).Load()
	if err != nil {
		t.Fatalf("load synthetic device state: %v", err)
	}
	st = loaded
	synced, err := outbox.New(dir).Load()
	if err != nil {
		t.Fatalf("load synthetic outbox: %v", err)
	}
	restricted, _, err := buildNewJob(dir, st, url, synced, func() time.Time { return time.Now().UTC() }, Plan{
		DeviceID:     st.DeviceID,
		ServerURL:    url,
		StateDir:     dir,
		JournalPath:  journalPath(dir),
		CoverageNote: coverageNote,
	}, NewSyncedBatchSnapshot([]string{"batch-00", "batch-01", "batch-02"}))
	if err != nil {
		t.Fatalf("build restricted job: %v", err)
	}
	if len(restricted.Batches) != 3 || restricted.Snapshot == nil || len(restricted.Snapshot.BatchIDs) != 3 {
		t.Fatalf("restricted fixture job is not universe-bound: %+v", restricted)
	}
	if restricted.Exclusions.AfterSnapshot != 3 {
		t.Fatalf("restricted fixture job must exclude the three after-capture batches: %+v", restricted.Exclusions)
	}
	// Decisions were made under revision 1; the live scope below is at
	// revision 2 — the consent drift that triggers a re-plan on resume.
	restricted.Scope = snapshotScope(liveScope{revision: 1, allowedTools: map[string]struct{}{"Codex": {}}})
	if err := saveJob(dir, restricted); err != nil {
		t.Fatalf("save restricted journal: %v", err)
	}
	return dir, st
}

// TestCrossVersionJournalDecodesIntoOldJobShape proves the format-level
// compatibility AND its hazard: the old shape decodes the new journal
// without error and with every field it reads intact, but it structurally
// cannot see the snapshot universe — the freeze is silently dropped, not
// preserved. (Control: the new shape decodes the same bytes with the
// universe.)
func TestCrossVersionJournalDecodesIntoOldJobShape(t *testing.T) {
	dir, _ := crossJournalFixture(t)
	raw, err := os.ReadFile(journalPath(dir))
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	var oldShape crossOldJob
	if err := json.Unmarshal(raw, &oldShape); err != nil {
		t.Fatalf("old job shape must decode a new-written journal: %v", err)
	}
	if oldShape.Schema != journalSchema || oldShape.JobID == "" || oldShape.DeviceID == "" || oldShape.ServerURL == "" {
		t.Fatalf("old shape lost identity fields: %+v", oldShape)
	}
	if len(oldShape.Batches) != 3 {
		t.Fatalf("old shape must see the restricted plan's three batches, got %d", len(oldShape.Batches))
	}
	if oldShape.Scope == nil || oldShape.Scope.Revision != 1 || oldShape.Scope.Fingerprint == "" {
		t.Fatalf("old shape must see the recorded scope baseline: %+v", oldShape.Scope)
	}
	for _, b := range oldShape.Batches {
		if b.Outcome != outcomePlanned || b.PayloadSHA256 == "" {
			t.Fatalf("old shape must see well-formed planned batches: %+v", b)
		}
	}
	// The hazard, stated as code: the old shape has no snapshot field, so
	// nothing above could have checked it. The new shape reads the same
	// bytes WITH the universe — the divergence carrier is real.
	var newShape job
	if err := json.Unmarshal(raw, &newShape); err != nil {
		t.Fatalf("new job shape must decode its own journal: %v", err)
	}
	if newShape.Snapshot == nil || len(newShape.Snapshot.BatchIDs) != 3 {
		t.Fatalf("control: new shape must see the frozen universe: %+v", newShape.Snapshot)
	}
	if newShape.Exclusions.AfterSnapshot != 3 {
		t.Fatalf("control: new shape must see the after-snapshot exclusions: %+v", newShape.Exclusions)
	}
}

// TestCrossVersionOldBinaryReplanExpandsToCompleteSyncedHistory executes
// the semantic divergence offline: the same snapshot-bearing journal,
// re-planned once with the universe intact (the new binary's behavior) and
// once with the universe erased (the state the old binary's decode
// produces, per TestCrossVersionJournalDecodesIntoOldJobShape plus the
// documented HEAD/worktree buildNewJob equivalence for nil restrictions).
// The old-binary-shaped re-plan covers all six synced batches — including
// the three synced after the snapshot capture — and its persisted
// replacement journal has no snapshot, so the freeze does not survive the
// old binary's write-back.
//
// This test says nothing about server-side consequences of the wider
// retransmission; replay idempotency across versions is unverified design
// intent until the gated cross-version harness runs it against a throwaway
// server.
func TestCrossVersionOldBinaryReplanExpandsToCompleteSyncedHistory(t *testing.T) {
	live := liveScope{revision: 2, allowedTools: map[string]struct{}{"Codex": {}}}

	// New binary: the re-plan stays inside the frozen universe.
	newDir, newSt := crossJournalFixture(t)
	jb, exists, err := loadJob(newDir)
	if err != nil || !exists {
		t.Fatalf("load new-binary journal: exists=%t err=%v", exists, err)
	}
	newSynced, err := outbox.New(newDir).Load()
	if err != nil {
		t.Fatalf("load new-binary outbox: %v", err)
	}
	gate, err := reconcileJobScope(newDir, newSt, jb.ServerURL, newSynced, &jb, live, func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatalf("new-binary re-plan: %v", err)
	}
	if !gate.replanned || len(gate.job.Batches) != 3 || gate.job.Snapshot == nil || len(gate.job.Snapshot.BatchIDs) != 3 {
		t.Fatalf("new-binary re-plan must stay universe-bound: %+v", gate.job)
	}
	persisted, exists, err := loadJob(newDir)
	if err != nil || !exists || len(persisted.Batches) != 3 || persisted.Snapshot == nil {
		t.Fatalf("new-binary replacement journal must keep the freeze: exists=%t err=%v job=%+v", exists, err, persisted)
	}

	// Old binary (simulated decode): the snapshot is dropped, the re-plan
	// expands to the complete synced history, and the write-back loses the
	// freeze permanently.
	oldDir, oldSt := crossJournalFixture(t)
	jb, exists, err = loadJob(oldDir)
	if err != nil || !exists {
		t.Fatalf("load old-binary journal: exists=%t err=%v", exists, err)
	}
	jb.Snapshot = nil // the old binary's Unmarshal drops the unknown field; every other field decodes identically
	oldSynced, err := outbox.New(oldDir).Load()
	if err != nil {
		t.Fatalf("load old-binary outbox: %v", err)
	}
	gate, err = reconcileJobScope(oldDir, oldSt, jb.ServerURL, oldSynced, &jb, live, func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatalf("old-binary re-plan: %v", err)
	}
	if !gate.replanned {
		t.Fatalf("old-binary re-plan must trigger on the same scope drift: %+v", gate)
	}
	if len(gate.job.Batches) != 6 {
		t.Fatalf("old-binary re-plan must expand to the complete synced history: want 6 batches, got %d", len(gate.job.Batches))
	}
	for _, id := range []string{"batch-03", "batch-04", "batch-05"} {
		found := false
		for _, b := range gate.job.Batches {
			if b.BatchID == id {
				found = true
			}
		}
		if !found {
			t.Fatalf("old-binary re-plan must include the after-capture batch %s", id)
		}
	}
	if gate.job.Snapshot != nil {
		t.Fatalf("old-binary re-plan must not freeze a universe: %+v", gate.job.Snapshot)
	}
	persisted, exists, err = loadJob(oldDir)
	if err != nil || !exists || len(persisted.Batches) != 6 || persisted.Snapshot != nil {
		t.Fatalf("old-binary replacement journal must lose the freeze permanently: exists=%t err=%v job=%+v", exists, err, persisted)
	}
}
