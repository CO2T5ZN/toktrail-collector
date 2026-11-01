// Synthetic end-to-end tests for the cursorsync orchestration: Enable
// ordering and idempotence, and Sync collection rounds. Everything runs
// against fake collaborators and a local httptest TokTrail server (see
// fakes_test.go); no real Cursor state, credential or account is ever
// read.
package cursorsync_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/cursor/identity"
	"toktrail-collector/internal/cursor/usage"
	"toktrail-collector/internal/local/cursorsource"
)

// expectedEventKey mirrors the event-key derivation for the harness
// subject namespace and account.
func expectedEventKey(t *testing.T, account, eventID string) string {
	t.Helper()
	key, err := identity.EventKey(identity.SubjectNamespace(testApplication, testSubject), account, eventID)
	if err != nil {
		t.Fatalf("derive event key: %v", err)
	}
	return key
}

func loadLicense(t *testing.T, dir string) cursorsource.License {
	t.Helper()
	license, ok, err := cursorsource.New(dir).Load()
	if err != nil {
		t.Fatalf("load license: %v", err)
	}
	if !ok {
		t.Fatal("license missing")
	}
	return license
}

func loadCache(t *testing.T, dir string) *usage.EventCache {
	t.Helper()
	cache, err := usage.LoadCache(dir)
	if err != nil {
		t.Fatalf("load cache: %v", err)
	}
	return cache
}

// ---------------------------------------------------------------------------
// Enable: confirmation ordering and idempotence
// ---------------------------------------------------------------------------

// TestEnableConfirmPrecedesCredentialRead pins the order-of-trust
// invariant: on a first-time enable the local confirmation strictly
// precedes any read of the Cursor desktop credential, the server
// capability gate runs after the confirmation but still before the
// credential read, and a full enable completes the first sync.
func TestEnableConfirmPrecedesCredentialRead(t *testing.T) {
	h := newHarness(t)
	h.pull.setEvents(
		ev("evt-0001", baseTime.Add(-30*time.Minute), 100, 0, 0, 50),
		ev("evt-0002", baseTime.Add(-40*time.Minute), 7, 0, 0, 3),
	)
	var order []string
	confirm := &fakeConfirm{answer: true, order: &order}
	h.auth.order = &order

	res, err := cursorsync.Enable(context.Background(), h.options(), confirm.confirm)
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if len(order) == 0 || order[0] != "confirm" {
		t.Fatalf("the confirmation must precede every credential read, got order %v", order)
	}
	for _, step := range order[:1] {
		if step == "auth" {
			t.Fatalf("credential read before confirmation: %v", order)
		}
	}
	if confirm.notice() != cursorsync.EnableNotice {
		t.Fatalf("confirm received notice %q, want EnableNotice", confirm.notice())
	}
	if !res.Confirmed || !res.ServerEnabled {
		t.Fatalf("confirmed=%t serverEnabled=%t, want both true", res.Confirmed, res.ServerEnabled)
	}
	if !res.Sync.Ran || !res.Sync.FirstSyncCompleted {
		t.Fatalf("first sync did not complete: %+v", res.Sync)
	}
	if res.Sync.NewRecords != 2 || res.Sync.SyncedBatches != 1 || res.Sync.PendingRemaining != 0 {
		t.Fatalf("unexpected first sync result: %+v", res.Sync)
	}
	if res.License.Status != cursorsource.StatusActive {
		t.Fatalf("license status %q, want active", res.License.Status)
	}
	_, _, _, caps, _ := h.srv.stats()
	if caps < 1 {
		t.Fatal("the capability gate must run on a first enable against a server that lists no account sources yet")
	}
}

// TestEnableDeclinedNeverReadsCredential verifies a declined
// confirmation aborts before any credential read, any server enable call
// and any license write.
func TestEnableDeclinedNeverReadsCredential(t *testing.T) {
	h := newHarness(t)
	confirm := &fakeConfirm{answer: false}

	_, err := cursorsync.Enable(context.Background(), h.options(), confirm.confirm)
	if err == nil || !strings.Contains(err.Error(), "declined") {
		t.Fatalf("declined enable must fail, got %v", err)
	}
	if h.auth.fetchCount() != 0 {
		t.Fatalf("credential read %d time(s) after a declined confirmation", h.auth.fetchCount())
	}
	if h.verify.callCount() != 0 {
		t.Fatalf("credential verified %d time(s) after a declined confirmation", h.verify.callCount())
	}
	if _, enable, ingest, _, _ := h.srv.stats(); enable != 0 || ingest != 0 {
		t.Fatalf("server enable=%d ingest=%d after a declined confirmation, want 0/0", enable, ingest)
	}
	if _, ok, err := cursorsource.New(h.dir).Load(); err != nil || ok {
		t.Fatalf("license must not exist after a declined confirmation (ok=%t err=%v)", ok, err)
	}
}

// TestEnableIdempotentSameAccount covers reuse of an existing login: a
// second enable for the same account with the source still designated
// and healthy is a no-op — no new confirmation prompt, no new server
// enable call, and the local pull memory is preserved.
func TestEnableIdempotentSameAccount(t *testing.T) {
	h := newHarness(t)
	h.pull.setEvents(ev("evt-0001", baseTime.Add(-30*time.Minute), 100, 0, 0, 50))
	confirm := &fakeConfirm{answer: true}

	if _, err := cursorsync.Enable(context.Background(), h.options(), confirm.confirm); err != nil {
		t.Fatalf("first enable: %v", err)
	}
	first := loadLicense(t, h.dir)
	if first.PullWatermark == nil {
		t.Fatal("first enable must leave a pull watermark")
	}

	confirm.mu.Lock()
	confirm.calls = 0
	confirm.mu.Unlock()
	res, err := cursorsync.Enable(context.Background(), h.options(), confirm.confirm)
	if err != nil {
		t.Fatalf("idempotent enable: %v", err)
	}
	if res.Confirmed || res.ServerEnabled {
		t.Fatalf("re-enable for the same account must not re-confirm or re-enable the server: %+v", res)
	}
	if confirm.callCount() != 0 {
		t.Fatal("re-enable for the same account must not prompt again")
	}
	if _, enable, _, _, _ := h.srv.stats(); enable != 1 {
		t.Fatal("re-enable for the same account must not call the server enable endpoint again")
	}
	if res.Sync.Skipped != "permit already active" {
		t.Fatalf("re-enable skip reason %q, want %q", res.Sync.Skipped, "permit already active")
	}
	second := loadLicense(t, h.dir)
	if !second.PullWatermark.Equal(*first.PullWatermark) {
		t.Fatal("idempotent re-enable must preserve the pull watermark")
	}
}

// ---------------------------------------------------------------------------
// Sync collection rounds: first pull, repeat, same-id corrections
// ---------------------------------------------------------------------------

// TestSyncCollectionRounds walks the collection lifecycle with a frozen
// clock: the first pull completes the pending permit, a repeated pull
// skips unchanged events, an upward correction of the same usageEventId
// replaces the stored record, and — crucially — a DOWNWARD correction
// also replaces it (never max-merged), and both corrections reach the
// server.
func TestSyncCollectionRounds(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, cursorsource.License{
		SourceInstanceID: "src_inst_1",
		AccountMatchID:   identity.MatchAccount(accountA),
		Status:           cursorsource.StatusPendingFirstSync,
		ConfirmedAt:      baseTime,
		NextRevision:     1,
		FenceVersion:     1,
	})
	e1 := ev("evt-0001", baseTime.Add(-30*time.Minute), 100, 0, 0, 50)
	e2 := ev("evt-0002", baseTime.Add(-40*time.Minute), 7, 0, 0, 3)
	h.pull.setEvents(e1, e2)
	opt := h.options()
	gate := cursorsync.Gate{}

	// Round 1 — first collection.
	res1, err := cursorsync.Sync(context.Background(), opt, gate)
	if err != nil {
		t.Fatalf("round 1: %v", err)
	}
	if !res1.Ran || !res1.FirstSyncCompleted || res1.Status != cursorsource.StatusActive {
		t.Fatalf("round 1 must complete the first sync: ran=%t first=%t status=%q", res1.Ran, res1.FirstSyncCompleted, res1.Status)
	}
	if res1.NewRecords != 2 || res1.SkippedUnchanged != 0 {
		t.Fatalf("round 1 new=%d unchanged=%d, want 2/0", res1.NewRecords, res1.SkippedUnchanged)
	}
	if res1.SyncedBatches != 1 || res1.SyncedRecords != 2 || res1.PendingRemaining != 0 {
		t.Fatalf("round 1 upload: %+v", res1)
	}
	if res1.Outcome != cursorsync.RoundRan {
		t.Fatalf("round 1 outcome %q, want ran", res1.Outcome)
	}
	lic1 := loadLicense(t, h.dir)
	if lic1.Status != cursorsource.StatusActive || lic1.PullWatermark == nil || !lic1.PullWatermark.Equal(baseTime) {
		t.Fatalf("round 1 license: %+v", lic1)
	}
	if lic1.NextRevision != 2 {
		t.Fatalf("round 1 nextRevision %d, want 2", lic1.NextRevision)
	}
	if lic1.PullCutoff != nil || !lic1.PullUnlimited || lic1.LastFullPullAt == nil {
		t.Fatalf("round 1 must record an unrestricted full pull: cutoff=%v unlimited=%t full=%v", lic1.PullCutoff, lic1.PullUnlimited, lic1.LastFullPullAt)
	}
	_, _, _, caps, batches := h.srv.stats()
	if caps != 0 {
		t.Fatal("sync must not re-probe capabilities when the self view already lists the source")
	}
	if len(batches) != 1 || len(batches[0].Records) != 2 {
		t.Fatalf("round 1 server batches: %+v", batches)
	}
	for i, rec := range batches[0].Records {
		if rec.Revision != 1 {
			t.Fatalf("round 1 record %d revision %d, want 1", i, rec.Revision)
		}
	}
	wantKey1 := expectedEventKey(t, accountA, "evt-0001")
	wantKey2 := expectedEventKey(t, accountA, "evt-0002")
	if batches[0].Records[0].EventKey != wantKey1 || batches[0].Records[1].EventKey != wantKey2 {
		t.Fatal("round 1 records carry unexpected event keys")
	}

	// Round 2 — repeated pull, same events: unchanged, no new batch.
	res2, err := cursorsync.Sync(context.Background(), opt, gate)
	if err != nil {
		t.Fatalf("round 2: %v", err)
	}
	if res2.NewRecords != 0 || res2.SkippedUnchanged != 2 || res2.ExportedBatches != 0 {
		t.Fatalf("round 2 new=%d unchanged=%d exported=%d, want 0/2/0", res2.NewRecords, res2.SkippedUnchanged, res2.ExportedBatches)
	}
	calls := h.pull.callLog()
	if len(calls) != 2 || !calls[1].from.Equal(baseTime.Add(-cursorsync.PullOverlap)) {
		t.Fatalf("round 2 must use the overlap window, got %+v", calls)
	}

	// Round 3 — same usageEventId, upward correction.
	h.pull.setEvents(ev("evt-0001", baseTime.Add(-30*time.Minute), 200, 0, 0, 80), e2)
	res3, err := cursorsync.Sync(context.Background(), opt, gate)
	if err != nil {
		t.Fatalf("round 3: %v", err)
	}
	if res3.ReplacedRecords != 1 || res3.NewRecords != 0 || res3.SkippedUnchanged != 1 {
		t.Fatalf("round 3 replaced=%d new=%d unchanged=%d, want 1/0/1", res3.ReplacedRecords, res3.NewRecords, res3.SkippedUnchanged)
	}
	_, _, _, _, batches = h.srv.stats()
	last := batches[len(batches)-1]
	if len(last.Records) != 1 || last.Records[0].EventKey != wantKey1 || last.Records[0].Revision != 2 {
		t.Fatalf("round 3 upload: %+v", last.Records)
	}
	if last.Records[0].Input == nil || *last.Records[0].Input != "200" {
		t.Fatalf("round 3 upward correction must reach the server, got input %v", last.Records[0].Input)
	}
	if loadLicense(t, h.dir).NextRevision != 3 {
		t.Fatal("round 3 must advance nextRevision to 3")
	}

	// Round 4 — same usageEventId, DOWNWARD correction: replace, never
	// max-merge.
	h.pull.setEvents(ev("evt-0001", baseTime.Add(-30*time.Minute), 50, 0, 0, 20), e2)
	res4, err := cursorsync.Sync(context.Background(), opt, gate)
	if err != nil {
		t.Fatalf("round 4: %v", err)
	}
	if res4.ReplacedRecords != 1 {
		t.Fatalf("round 4 replaced=%d, want 1 (downward corrections must replace)", res4.ReplacedRecords)
	}
	_, _, _, _, batches = h.srv.stats()
	last = batches[len(batches)-1]
	if len(last.Records) != 1 || last.Records[0].Revision != 3 {
		t.Fatalf("round 4 upload: %+v", last.Records)
	}
	if last.Records[0].Input == nil || *last.Records[0].Input != "50" || last.Records[0].Output == nil || *last.Records[0].Output != "20" {
		t.Fatalf("round 4 downward correction must reach the server, got input=%v output=%v", last.Records[0].Input, last.Records[0].Output)
	}
	cache := loadCache(t, h.dir)
	if entry, ok := cache.Get(wantKey1); !ok || entry.Revision != 3 {
		t.Fatalf("cache must track the replaced revision, got %+v ok=%t", entry, ok)
	}
}

// ---------------------------------------------------------------------------
// Account switch
// ---------------------------------------------------------------------------

// TestSyncAccountSwitchPauses verifies a desktop login switched to a
// different Cursor account pauses collection without pulling, and the
// paused permit skips subsequent rounds before any credential read.
func TestSyncAccountSwitchPauses(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, cursorsource.License{
		SourceInstanceID: "src_inst_1",
		AccountMatchID:   identity.MatchAccount(accountA),
		Status:           cursorsource.StatusActive,
		ConfirmedAt:      baseTime,
		NextRevision:     1,
		FenceVersion:     1,
	})
	h.auth.setToken("tok-B")

	res, err := cursorsync.Sync(context.Background(), h.options(), cursorsync.Gate{})
	if err != nil {
		t.Fatalf("sync with switched account: %v", err)
	}
	if !res.Ran {
		t.Fatal("the switch-check round did run")
	}
	if res.Status != cursorsource.StatusPausedAccountSwitch {
		t.Fatalf("status %q, want paused_account_switch", res.Status)
	}
	if !strings.Contains(res.Skipped, "switched to a different Cursor account") {
		t.Fatalf("skip reason %q", res.Skipped)
	}
	if res.Outcome != cursorsync.RoundAuthWithheld {
		t.Fatalf("a mid-round account switch is an authorization verdict, outcome %q", res.Outcome)
	}
	if len(h.pull.callLog()) != 0 {
		t.Fatal("a switched account must never be pulled")
	}
	license := loadLicense(t, h.dir)
	if license.Status != cursorsource.StatusPausedAccountSwitch {
		t.Fatalf("persisted status %q, want paused_account_switch", license.Status)
	}

	// The paused permit skips before reading the credential again.
	fetches := h.auth.fetchCount()
	res2, err := cursorsync.Sync(context.Background(), h.options(), cursorsync.Gate{})
	if err != nil {
		t.Fatalf("sync under paused permit: %v", err)
	}
	if res2.Ran || !strings.Contains(res2.Skipped, "permit paused") {
		t.Fatalf("paused round: ran=%t skipped=%q", res2.Ran, res2.Skipped)
	}
	if res2.Outcome != cursorsync.RoundAuthWithheld {
		t.Fatalf("a paused permit is an authorization verdict, outcome %q", res2.Outcome)
	}
	if h.auth.fetchCount() != fetches {
		t.Fatal("a paused permit must not re-read the credential")
	}
}

// writeLicense persists a prepared permit.
func (h *harness) writeLicense(t *testing.T, license cursorsource.License) {
	t.Helper()
	if err := cursorsource.New(h.dir).Save(license); err != nil {
		t.Fatalf("write license: %v", err)
	}
}
