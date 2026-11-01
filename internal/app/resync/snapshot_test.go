package resync

// Snapshot-restriction tests: a NEW job may be limited to the synced
// batches a caller captured before its collection ran (connect does, so
// its automatic pass never immediately replays what the same run just
// uploaded). The invariants under test:
//   - a non-nil snapshot restricts exactly the NEW-job plan, and the
//     excluded batches are reported, never silently dropped;
//   - an empty snapshot (nothing synced yet: a first install) plans an
//     empty pass, and a nil snapshot (the explicit `toktrail resync
//     --all`) keeps the original full-archive semantics — the two are
//     distinct, in the options AND in the persisted journal;
//   - resuming an unfinished journal keeps its frozen plan, ignoring the
//     snapshot this resume arrived with;
//   - a consent-scope change re-plans WITHIN the job's frozen snapshot
//     universe: batches synced after the capture (this run's uploads)
//     never join the lineage, while entries the grants excluded at plan
//     time stay in the universe and rejoin once the authorization
//     widens. Jobs without a universe (nil, or legacy journals without
//     the field) re-plan over the complete synced history, as before;
//   - the grant-verdict error wording survives the restriction (connect
//     classifies those strings as authorization verdicts).

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/syncclient"
)

// universeHas reports whether the job's frozen snapshot universe lists
// the batch id.
func universeHas(jb job, batchID string) bool {
	if jb.Snapshot == nil {
		return false
	}
	for _, id := range jb.Snapshot.BatchIDs {
		if id == batchID {
			return true
		}
	}
	return false
}

func TestSnapshotRestrictsNewJobToCapturedBatches(t *testing.T) {
	remote, server := newRemote(t)
	dir := fixture(t, server.URL,
		[]json.RawMessage{record("snap-a", "2026-10-28T00:00:00Z")},
		[]json.RawMessage{record("snap-b", "2026-10-27T00:00:00Z")},
		[]json.RawMessage{record("snap-c", "2026-10-26T00:00:00Z")},
	)
	opt := options(dir)
	// batch-01 is deliberately absent from the snapshot (synced after it
	// was captured); a stale id no outbox lists must be ignored.
	opt.Snapshot = NewSyncedBatchSnapshot([]string{"batch-00", "batch-02", "batch-gone"})
	result, err := Run(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Completed || result.Uploads != 2 || remote.postCount() != 2 {
		t.Fatalf("the restricted pass must retransmit exactly the snapshotted batches: %+v", result)
	}
	if remote.seen["snap-b"] || !remote.seen["snap-a"] || !remote.seen["snap-c"] {
		t.Fatalf("only the snapshotted records may be retransmitted: %v", remote.seen)
	}
	if result.Plan.ExcludedAfterSnapshot != 1 || !result.Plan.SnapshotRestricted {
		t.Fatalf("the excluded batch must be reported, never hidden: %+v", result.Plan)
	}
	if !strings.Contains(result.Plan.CoverageNote, "restricted to the batches already synced") {
		t.Fatalf("the coverage note must state the restriction: %s", result.Plan.CoverageNote)
	}
	jb, exists, err := loadJob(dir)
	if err != nil || !exists || jb.Snapshot == nil || len(jb.Batches) != 2 {
		t.Fatalf("the journal must record the restricted plan: exists=%t err=%v job=%+v", exists, err, jb)
	}
	// The universe is frozen as captured — including the stale id, and
	// excluding nothing the caller listed — so a later re-plan keeps the
	// same boundary.
	if len(jb.Snapshot.BatchIDs) != 3 || !universeHas(jb, "batch-00") || !universeHas(jb, "batch-02") || !universeHas(jb, "batch-gone") {
		t.Fatalf("the journal must freeze the captured universe verbatim: %+v", jb.Snapshot)
	}
	for _, b := range jb.Batches {
		if b.BatchID == "batch-01" {
			t.Fatalf("the after-snapshot batch must not be planned: %+v", jb.Batches)
		}
	}
}

func TestEmptySnapshotPlansNothingAndNilSnapshotCoversAll(t *testing.T) {
	remote, server := newRemote(t)
	dir := fixture(t, server.URL,
		[]json.RawMessage{record("empty-a", "2026-10-28T00:00:00Z")},
		[]json.RawMessage{record("empty-b", "2026-10-27T00:00:00Z")},
	)
	opt := options(dir)
	opt.Snapshot = NewSyncedBatchSnapshot(nil) // first install: nothing synced yet
	result, err := Run(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Completed || result.Uploads != 0 || remote.callCount() != 0 {
		t.Fatalf("an empty snapshot must plan an empty, fully offline pass: %+v calls=%d", result, remote.callCount())
	}
	if result.Plan.ExcludedAfterSnapshot != 2 || !result.Plan.PendingFinalize {
		t.Fatalf("the synced batches must be reported as excluded by the empty snapshot: %+v", result.Plan)
	}
	jb, exists, err := loadJob(dir)
	if err != nil || !exists || len(jb.Batches) != 0 || jb.CompletedAt == nil {
		t.Fatalf("the empty restricted job must be completed and persisted: exists=%t err=%v job=%+v", exists, err, jb)
	}
	// The empty universe is a RESTRICTION, not an absent field: it must
	// round-trip as non-nil with zero ids, distinct from the nil that
	// means "unrestricted" (legacy journals have no field at all).
	if jb.Snapshot == nil || len(jb.Snapshot.BatchIDs) != 0 {
		t.Fatalf("the empty universe must persist as a non-nil snapshot with zero ids: %+v", jb.Snapshot)
	}

	// nil (the explicit `toktrail resync --all`) keeps the original
	// full-archive semantics, replacing even a completed empty job.
	full, err := Run(context.Background(), options(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !full.Completed || full.Uploads != 2 || full.Plan.Resumed || full.Plan.SnapshotRestricted {
		t.Fatalf("the nil-snapshot pass must cover the complete archive as a fresh full pass: %+v", full)
	}
	if !remote.seen["empty-a"] || !remote.seen["empty-b"] {
		t.Fatalf("the full pass must retransmit both batches: %v", remote.seen)
	}
}

func TestResumeKeepsFrozenPlanIgnoringSnapshot(t *testing.T) {
	remote, server := newRemote(t)
	dir := fixture(t, server.URL,
		[]json.RawMessage{record("res-a", "2026-10-28T00:00:00Z")},
		[]json.RawMessage{record("res-b", "2026-10-27T00:00:00Z")},
	)
	opt := options(dir)
	opt.MaxBatches = 1
	if _, err := Run(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	jb, exists, err := loadJob(dir)
	if err != nil || !exists || jb.CompletedAt != nil || len(jb.Batches) != 2 {
		t.Fatalf("incomplete full job: exists=%t err=%v job=%+v", exists, err, jb)
	}

	// The resume arrives with a snapshot that no longer lists the
	// remaining batch (batch-01: synced after that snapshot was
	// captured). The frozen journal plan is the authority — the resume
	// must finish it instead of re-planning to the snapshot.
	resume := options(dir)
	resume.Snapshot = NewSyncedBatchSnapshot([]string{"batch-00"})
	result, err := Run(context.Background(), resume)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Completed || !result.Plan.Resumed || result.Uploads != 1 {
		t.Fatalf("the resume must finish the frozen plan: %+v", result)
	}
	if !remote.seen["res-a"] || !remote.seen["res-b"] {
		t.Fatalf("both records must reach the server: %v", remote.seen)
	}
	if result.Plan.ExcludedAfterSnapshot != 0 || result.Plan.SnapshotRestricted {
		t.Fatalf("a resume must not re-derive snapshot restrictions: %+v", result.Plan)
	}
}

// TestRestrictedJournalResumeAfterInterruption covers the ordinary resume
// of a RESTRICTED journal: connect's snapshot-restricted pass is stopped
// mid-plan (a transient upload failure, or the per-run upload budget), and
// the next run — same authorization, carrying the NEW snapshot a later
// connect captured — must finish the journal's frozen plan as planned:
//   - the resume's own snapshot is ignored in both directions: the
//     remaining batch it no longer lists is still retransmitted, and the
//     after-snapshot batch it now lists stays excluded;
//   - the frozen plan's coverage is unchanged: same job id, same two
//     planned batches, same single after-snapshot exclusion;
//   - SnapshotRestricted, ExcludedAfterSnapshot, and the restricted
//     coverage note stay mutually consistent on the resumed report,
//     exactly as the journal recorded them.
func TestRestrictedJournalResumeAfterInterruption(t *testing.T) {
	for _, interrupt := range []string{"failure", "budget"} {
		t.Run(interrupt, func(t *testing.T) {
			remote, server := newRemote(t)
			dir := fixture(t, server.URL,
				[]json.RawMessage{record("rjr-a", "2026-10-28T00:00:00Z")},
				[]json.RawMessage{record("rjr-b", "2026-10-27T00:00:00Z")},
				[]json.RawMessage{record("rjr-c", "2026-10-26T00:00:00Z")},
			)
			opt := options(dir)
			// batch-02 models a batch synced after the snapshot was
			// captured: the restricted plan owes exactly batch-00 and
			// batch-01.
			opt.Snapshot = NewSyncedBatchSnapshot([]string{"batch-00", "batch-01"})
			if interrupt == "failure" {
				remote.failBatch = "batch-01"
			} else {
				opt.MaxBatches = 1
			}
			first, err := Run(context.Background(), opt)
			if interrupt == "failure" && err == nil {
				t.Fatal("expected the transient upload failure to stop the restricted pass")
			}
			if interrupt == "budget" && err != nil {
				t.Fatal(err)
			}
			if first.Completed || first.Uploads != 1 {
				t.Fatalf("the restricted pass must stop after exactly one upload, one batch still owed: %+v", first)
			}
			if interrupt == "budget" {
				if first.Remaining != 1 || !strings.Contains(first.Stopped, "upload budget reached") {
					t.Fatalf("the budget stop must report the remaining batch: %+v", first)
				}
			} else if first.Failed != 1 || first.Stopped != "upload failed" {
				t.Fatalf("the failure stop must report the failed batch: %+v", first)
			}
			if !first.Plan.SnapshotRestricted || first.Plan.ExcludedAfterSnapshot != 1 ||
				!strings.Contains(first.Plan.CoverageNote, "restricted to the batches already synced") {
				t.Fatalf("the interrupted restricted pass must report its restriction consistently: %+v", first.Plan)
			}
			interrupted, exists, err := loadJob(dir)
			if err != nil || !exists || interrupted.CompletedAt != nil || interrupted.Snapshot == nil ||
				len(interrupted.Snapshot.BatchIDs) != 2 ||
				interrupted.Exclusions.AfterSnapshot != 1 || len(interrupted.Batches) != 2 {
				t.Fatalf("the journal must freeze the incomplete restricted plan and its universe: exists=%t err=%v job=%+v", exists, err, interrupted)
			}

			// A later connect captured a NEW snapshot before this resume:
			// it no longer lists the remaining batch (batch-01) and now
			// lists the after-snapshot one (batch-02). The authorization
			// is unchanged, so the resume must ignore it entirely and
			// finish the frozen plan.
			remote.failBatch = ""
			resume := options(dir)
			resume.Snapshot = NewSyncedBatchSnapshot([]string{"batch-02"})
			result, err := Run(context.Background(), resume)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Completed || !result.Plan.Resumed || result.Uploads != 1 {
				t.Fatalf("the resume must finish the frozen restricted plan: %+v", result)
			}
			if !remote.seen["rjr-a"] || !remote.seen["rjr-b"] {
				t.Fatalf("both planned records must reach the server: %v", remote.seen)
			}
			if remote.seen["rjr-c"] {
				t.Fatalf("the after-snapshot batch must stay excluded even though the new snapshot lists it: %v", remote.seen)
			}
			if !result.Plan.SnapshotRestricted || result.Plan.ExcludedAfterSnapshot != 1 ||
				!strings.Contains(result.Plan.CoverageNote, "restricted to the batches already synced") {
				t.Fatalf("the resumed report must keep the journal's restricted reporting state: %+v", result.Plan)
			}
			if result.Plan.TotalInJob != 2 || result.Plan.DoneInJob != 1 || len(result.Plan.Batches) != 1 ||
				result.Plan.Batches[0].BatchID != "batch-01" {
				t.Fatalf("the resume's plan must be the frozen remainder, never a new snapshot plan: %+v", result.Plan)
			}
			finished, exists, err := loadJob(dir)
			if err != nil || !exists || finished.CompletedAt == nil || finished.Snapshot == nil ||
				len(finished.Snapshot.BatchIDs) != 2 ||
				finished.Exclusions.AfterSnapshot != 1 || len(finished.Batches) != 2 || finished.JobID != interrupted.JobID {
				t.Fatalf("the completed journal must keep the frozen restricted plan and universe: exists=%t err=%v job=%+v", exists, err, finished)
			}
			for _, b := range finished.Batches {
				if b.BatchID == "batch-02" {
					t.Fatalf("the after-snapshot batch must never join the frozen plan: %+v", finished.Batches)
				}
			}
		})
	}
}

// TestScopeReplanPreservesJobSnapshotBoundary verifies the re-plan rule
// for a snapshot-restricted job: when the consent scope moves, the
// re-plan stays WITHIN the job's frozen snapshot universe — batches
// synced after the capture (this run's uploads) never join the lineage,
// not even when the driving run's own snapshot would allow them — and
// the replacement job freezes the same universe, so the boundary
// survives later re-plans too. The next explicit full pass (nil
// snapshot) starts a NEW job and covers the rest.
func TestScopeReplanPreservesJobSnapshotBoundary(t *testing.T) {
	remote, server := newRemote(t)
	dir := fixture(t, server.URL,
		[]json.RawMessage{record("plan-a", "2026-10-28T00:00:00Z")},
		[]json.RawMessage{record("plan-b", "2026-10-27T00:00:00Z")},
		[]json.RawMessage{record("plan-c", "2026-10-26T00:00:00Z")},
	)
	// batch-02 models a batch synced after the snapshot was captured:
	// the job's universe is exactly {batch-00, batch-01}.
	opt := options(dir)
	opt.MaxBatches = 1
	opt.Snapshot = NewSyncedBatchSnapshot([]string{"batch-00", "batch-01"})
	first, err := Run(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if first.Completed || first.Uploads != 1 || first.Remaining != 1 {
		t.Fatalf("the restricted budgeted pass must stay incomplete: %+v", first)
	}

	// The authorization moves; the resume arrives with a snapshot that
	// now lists everything. The re-plan must stay within the job's
	// frozen universe — batch-02 stays excluded — and stop before any
	// upload, exactly as an unrestricted re-plan does.
	remote.set(2, nil)
	replan := options(dir)
	replan.Snapshot = NewSyncedBatchSnapshot([]string{"batch-00", "batch-01", "batch-02"})
	postsBefore := remote.postCount()
	second, err := Run(context.Background(), replan)
	if err == nil {
		t.Fatal("expected the scope-change stop")
	}
	if second.Completed || second.Stopped != "consent scope changed" || remote.postCount() != postsBefore {
		t.Fatalf("the re-plan must stop before any upload: %+v err=%v", second, err)
	}
	if second.Remaining != 2 || !second.Plan.SnapshotRestricted {
		t.Fatalf("the stop must report the boundary-bound re-planned remainder: %+v", second)
	}
	replanned, exists, err := loadJob(dir)
	if err != nil || !exists || replanned.CompletedAt != nil || len(replanned.Batches) != 2 {
		t.Fatalf("the re-planned job must stay within the frozen universe: exists=%t err=%v job=%+v", exists, err, replanned)
	}
	if replanned.Snapshot == nil || len(replanned.Snapshot.BatchIDs) != 2 ||
		!universeHas(replanned, "batch-00") || !universeHas(replanned, "batch-01") || universeHas(replanned, "batch-02") {
		t.Fatalf("the re-planned job must freeze the SAME universe for later re-plans: %+v", replanned.Snapshot)
	}
	for _, b := range replanned.Batches {
		if b.Outcome != outcomePlanned || b.BatchID == "batch-02" {
			t.Fatalf("the re-planned plan must be fresh and boundary-bound: %+v", b)
		}
	}

	// The next run executes the re-planned plan and finishes INSIDE the
	// boundary; batch-02's record never reaches the server through this
	// job lineage.
	third, err := Run(context.Background(), options(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !third.Completed || !remote.seen["plan-a"] || !remote.seen["plan-b"] {
		t.Fatalf("the re-planned pass must restore the universe's history: %+v", third)
	}
	if remote.seen["plan-c"] {
		t.Fatalf("the after-capture batch must stay outside the job lineage: %v", remote.seen)
	}

	// An explicit full pass (nil snapshot) starts a NEW job over the
	// complete synced history and covers the boundary-excluded batch.
	fourth, err := Run(context.Background(), options(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !fourth.Completed || fourth.Plan.SnapshotRestricted || !remote.seen["plan-c"] {
		t.Fatalf("the next explicit full pass must cover the after-capture batch: %+v", fourth)
	}
}

// TestScopeReplanRecoversGrantExcludedHistoryWithinBoundary verifies why
// the journal freezes the universe BEFORE grant filtering: a batch the
// local grants excluded at plan time stays IN the universe, so once the
// authorization widens (the grant is re-enabled) a scope-change re-plan
// recovers that old history — while still never admitting batches synced
// after the capture.
func TestScopeReplanRecoversGrantExcludedHistoryWithinBoundary(t *testing.T) {
	remote, server := newRemote(t)
	dir := fixture(t, server.URL,
		[]json.RawMessage{record("wid-a", "2026-10-28T00:00:00Z")},
		[]json.RawMessage{record("wid-b", "2026-10-27T00:00:00Z")},
	)
	// A third synced batch lives under a second input whose grant is
	// NOT enabled at plan time: it is inside the captured universe (the
	// snapshot predates grant filtering) but excluded from the plan by
	// the local grant verdict.
	otherInput := filepath.Join(dir, "synthetic", "other")
	if err := os.MkdirAll(otherInput, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "batch-02.json")
	writeJSON(t, file, syncclient.BatchRequest{BatchID: "batch-02", Records: []json.RawMessage{record("wid-c", "2026-10-26T00:00:00Z")}})
	ledger := outbox.New(dir)
	ob, err := ledger.Load()
	if err != nil {
		t.Fatal(err)
	}
	ob.Batches = append(ob.Batches, outbox.BatchEntry{
		BatchID:     "batch-02",
		File:        file,
		Source:      "codex-jsonl",
		Input:       otherInput,
		Status:      outbox.StatusSynced,
		RecordCount: 1,
		CreatedAt:   time.Now().UTC(),
	})
	if err := ledger.Save(ob); err != nil {
		t.Fatal(err)
	}

	opt := options(dir)
	opt.MaxBatches = 1
	opt.Snapshot = NewSyncedBatchSnapshot([]string{"batch-00", "batch-01", "batch-02"})
	first, err := Run(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if first.Completed || first.Uploads != 1 {
		t.Fatalf("the restricted budgeted pass must stay incomplete: %+v", first)
	}
	jb, exists, err := loadJob(dir)
	if err != nil || !exists || len(jb.Batches) != 2 || !universeHas(jb, "batch-02") {
		t.Fatalf("the grant-excluded batch must stay in the frozen universe though outside the plan: exists=%t err=%v job=%+v", exists, err, jb)
	}
	grantExcluded := false
	for _, id := range jb.Exclusions.LocalGrant {
		if id == "batch-02" {
			grantExcluded = true
		}
	}
	if !grantExcluded {
		t.Fatalf("the plan must report the grant exclusion: %+v", jb.Exclusions)
	}

	// The authorization widens: the second input's grant is re-enabled
	// and the consent scope moves. The re-plan must re-evaluate the
	// universe under the CURRENT grants, recovering batch-02.
	if _, err := grants.New(dir).Enable("codex-jsonl", otherInput); err != nil {
		t.Fatal(err)
	}
	remote.set(2, nil)
	second, err := Run(context.Background(), options(dir))
	if err == nil || second.Stopped != "consent scope changed" {
		t.Fatalf("expected the scope-change stop before any upload: %+v err=%v", second, err)
	}
	replanned, exists, err := loadJob(dir)
	if err != nil || !exists || len(replanned.Batches) != 3 {
		t.Fatalf("the re-plan must recover the grant-excluded history within the universe: exists=%t err=%v job=%+v", exists, err, replanned)
	}
	if len(replanned.Exclusions.LocalGrant) != 0 || replanned.Snapshot == nil || !universeHas(replanned, "batch-02") {
		t.Fatalf("the re-planned job must carry no grant exclusion and the same universe: %+v", replanned)
	}

	third, err := Run(context.Background(), options(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !third.Completed || !remote.seen["wid-c"] {
		t.Fatalf("the recovered history must be retransmitted: %+v seen=%v", third, remote.seen)
	}
}

func TestSnapshotKeepsGrantVerdictWording(t *testing.T) {
	remote, server := newRemote(t)
	dir := fixture(t, server.URL,
		[]json.RawMessage{record("gv-a", "2026-10-28T00:00:00Z")},
		[]json.RawMessage{record("gv-b", "2026-10-27T00:00:00Z")},
	)
	if _, found, err := grants.New(dir).Disable("codex-jsonl", fixtureInput(dir)); err != nil || !found {
		t.Fatalf("disable synthetic grant: found=%t err=%v", found, err)
	}
	opt := options(dir)
	opt.Snapshot = NewSyncedBatchSnapshot([]string{"batch-00"})
	if _, err := Run(context.Background(), opt); err == nil ||
		!strings.Contains(err.Error(), "none of the 1 synced batch(es) match a currently enabled local source grant (excluded: batch-00); enable the sources you want to recover with `toktrail sources enable --source <source> --input <absolute-path>` and re-run resync") {
		t.Fatalf("the grant verdict must keep its exact wording over the filtered candidates: %v", err)
	}
	if remote.postCount() != 0 {
		t.Fatal("nothing may be uploaded without an enabled grant")
	}

	// The missing-config verdict keeps its wording under a snapshot too.
	other := fixture(t, server.URL, []json.RawMessage{record("gv-c", "2026-10-28T00:00:00Z")})
	if err := os.Remove(filepath.Join(other, "grants.json")); err != nil {
		t.Fatal(err)
	}
	absent := options(other)
	absent.Snapshot = NewSyncedBatchSnapshot([]string{"batch-00"})
	if _, err := Run(context.Background(), absent); err == nil ||
		!strings.Contains(err.Error(), "no local source grants are configured (grants.json is absent): resync denies retransmission by default so residual archives cannot bypass local permission; enable the sources you want to recover with `toktrail sources enable --source <source> --input <absolute-path>` and re-run resync") {
		t.Fatalf("the missing-config verdict must keep its exact wording: %v", err)
	}
}
