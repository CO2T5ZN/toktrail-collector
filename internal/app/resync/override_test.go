package resync

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/overrides"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/registry"
	"toktrail-collector/internal/syncclient"
)

// ---------------------------------------------------------------------------
// Override-mode fake remote: capabilities, self, and an ingest endpoint
// that records every posted body (including the replaceExisting flag) and
// replays the stored receipt when the same batch identity is re-posted.
// ---------------------------------------------------------------------------

type postedOverride struct {
	BatchID         string
	ReplaceExisting bool
	Records         []json.RawMessage
	Replay          bool
}

type overrideRemote struct {
	mu           sync.Mutex
	posts        int
	selfCalls    int
	requests     int // every HTTP request of any kind, capabilities included
	posted       []postedOverride
	receipts     map[string]syncclient.BatchReceipt
	rejectAll    bool // reject every record with record_conflict
	noCapability bool // capabilities without replace-existing
	revision     int64
}

func newOverrideRemote(t *testing.T) (*overrideRemote, *httptest.Server) {
	t.Helper()
	s := &overrideRemote{receipts: map[string]syncclient.BatchReceipt{}, revision: 1}
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.requests++
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/capabilities":
			features := []string{"batch-idempotency", "replace-existing"}
			if s.noCapability {
				features = []string{"batch-idempotency"}
			}
			json.NewEncoder(w).Encode(map[string]any{"service": "toktrail-server", "features": features})
			return
		case "/v1/devices/self":
			s.selfCalls++
			v := 1
			json.NewEncoder(w).Encode(map[string]any{"device": syncclient.SelfStatus{
				DeviceID: "device-resync", ConsentRevision: s.revision, UploadAuthorized: true,
				GrantProtocolVersion: &v, AllowedTools: []string{"Codex"},
			}})
			return
		case "/v1/ingest/batches":
			s.posts++
			var batch syncclient.BatchRequest
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				t.Errorf("decode ingest body: %v", err)
				w.WriteHeader(400)
				return
			}
			replay := false
			receipt, ok := s.receipts[batch.BatchID]
			if ok {
				replay = true
				receipt.Replay = true
			} else {
				receipt = syncclient.BatchReceipt{BatchID: batch.BatchID, Status: "accepted", AcceptedRecords: len(batch.Records), ReceivedAt: time.Now().UTC()}
				for idx := range batch.Records {
					if s.rejectAll {
						receipt.AcceptedRecords--
						receipt.RejectedRecords++
						receipt.Status = "partial"
						var probe map[string]any
						json.Unmarshal(batch.Records[idx], &probe)
						receipt.RecordErrors = append(receipt.RecordErrors, syncclient.RecordError{Index: idx, RecordKey: fmt.Sprint(probe["recordKey"]), Code: "record_conflict", Message: "synthetic conflict"})
					}
				}
				s.receipts[batch.BatchID] = receipt
			}
			s.posted = append(s.posted, postedOverride{BatchID: batch.BatchID, ReplaceExisting: batch.ReplaceExisting, Records: batch.Records, Replay: replay})
			json.NewEncoder(w).Encode(map[string]any{"batch": receipt})
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(h.Close)
	return s, h
}

func (f *overrideRemote) snapshot() []postedOverride {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]postedOverride(nil), f.posted...)
}

// requestCount reports every HTTP request the fake has served, the
// unauthenticated capabilities probe included, so a cancellation test can
// prove zero network traffic of any kind.
func (f *overrideRemote) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

// ---------------------------------------------------------------------------
// Codex session fixture: the archived baseline and the "current scan" come
// from real session files, so drift is a genuine same-key content change.
// ---------------------------------------------------------------------------

func writeCodexSession(t *testing.T, path string, secondCount [4]uint64) {
	t.Helper()
	lines := []string{
		`{"timestamp":"2026-10-20T01:00:00Z","type":"session_meta","payload":{"id":"SYNTHETIC_SESSION"}}`,
		`{"timestamp":"2026-10-20T01:01:00Z","type":"turn_context","payload":{"model":"gpt-5.4"}}`,
		`{"timestamp":"2026-10-20T01:03:00Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":100,"cached_input_tokens":20,"cache_write_input_tokens":5,"output_tokens":40}}}}`,
		fmt.Sprintf(`{"timestamp":"2026-10-20T01:04:00Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":%d,"cached_input_tokens":%d,"cache_write_input_tokens":%d,"output_tokens":%d}}}}`,
			secondCount[0], secondCount[1], secondCount[2], secondCount[3]),
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func scanCodex(t *testing.T, input string) []json.RawMessage {
	t.Helper()
	loaded, err := registry.LoadRecordsForSource(adapter.Options{Source: "codex-jsonl", Input: input})
	if err != nil {
		t.Fatal(err)
	}
	out := make([]json.RawMessage, 0, len(loaded.Records))
	for _, rec := range loaded.Records {
		raw, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, raw)
	}
	return out
}

func sessionPath(dir string) string {
	return filepath.Join(fixtureInput(dir), "rollout-synthetic.jsonl")
}

func autoConfirmOverride(func(OverridePlan) error) func(OverridePlan) error {
	return func(OverridePlan) error { return nil }
}

// overrideFixture builds a bound state directory with one synced archived
// batch holding exactly the records of the current session scan, so the
// baseline and the scan start in sync.
func overrideFixture(t *testing.T, url string, secondCount [4]uint64) (string, []json.RawMessage) {
	t.Helper()
	dir := t.TempDir()
	if err := statedir.New(dir).Save(statedir.DeviceState{DeviceID: "device-resync", DeviceSecret: strings.Repeat("a", 64), ApplicationID: "synthetic-app", ExternalSubjectID: "synthetic-user", ServerURL: url, UploadAuthorized: true, ConsentRevision: 1}); err != nil {
		t.Fatal(err)
	}
	input := fixtureInput(dir)
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := grants.New(dir).Enable("codex-jsonl", input); err != nil {
		t.Fatalf("create synthetic source grant: %v", err)
	}
	writeCodexSession(t, sessionPath(dir), secondCount)
	records := scanCodex(t, input)
	if len(records) == 0 {
		t.Fatal("session scan produced no records")
	}
	file := filepath.Join(dir, "batch-00.json")
	writeJSON(t, file, syncclient.BatchRequest{BatchID: "batch-00", Records: records})
	if err := outbox.New(dir).Save(outbox.Outbox{Batches: []outbox.BatchEntry{{
		BatchID: "batch-00", File: file, Source: "codex-jsonl", Input: input,
		Status: outbox.StatusSynced, RecordCount: len(records), CreatedAt: time.Now().UTC(),
	}}}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"message-progress.json", "adapter-cursors.json", "scope-quarantine.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("[]\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, records
}

func TestOverrideUploadsCurrentScanWithReplaceFlag(t *testing.T) {
	remote, server := newOverrideRemote(t)
	dir, archived := overrideFixture(t, server.URL, [4]uint64{160, 30, 8, 80})
	// The source drifts: same key (same file, same closing count line),
	// different token deltas.
	writeCodexSession(t, sessionPath(dir), [4]uint64{260, 60, 20, 180})
	current := scanCodex(t, fixtureInput(dir))
	if string(current[0]) == string(archived[0]) {
		t.Fatal("fixture did not drift")
	}

	res, err := RunOverride(context.Background(), OverrideOptions{
		StateDir: dir, ServerURL: server.URL, Confirm: autoConfirmOverride(nil),
	})
	if err != nil || !res.Completed {
		t.Fatalf("override pass: %v completed=%t", err, res.Completed)
	}
	posts := remote.snapshot()
	if len(posts) != 1 {
		t.Fatalf("expected exactly one upload, got %d", len(posts))
	}
	if !posts[0].ReplaceExisting {
		t.Fatal("override upload must set replaceExisting=true")
	}
	if len(posts[0].Records) != 1 || string(posts[0].Records[0]) != string(current[0]) {
		t.Fatalf("override must upload the CURRENT scanned record, got %s", posts[0].Records)
	}
	ledger, has, err := overrides.New(dir).Load()
	if err != nil || !has {
		t.Fatalf("ledger: %v %v", has, err)
	}
	key := recordKeyString(t, current[0])
	entry := ledger.Entries[key]
	if entry.Status != overrides.StatusConfirmed || string(entry.Record) != string(current[0]) || entry.AttemptID == "" {
		t.Fatalf("ledger entry not confirmed with the current content: %#v", entry)
	}
	// A second pass with no further drift uploads nothing and completes.
	res2, err := RunOverride(context.Background(), OverrideOptions{
		StateDir: dir, ServerURL: server.URL, Confirm: autoConfirmOverride(nil),
	})
	if err != nil || !res2.Completed || res2.Uploads != 0 {
		t.Fatalf("second pass must be a no-op: %v completed=%t uploads=%d", err, res2.Completed, res2.Uploads)
	}
	if len(remote.snapshot()) != 1 {
		t.Fatal("second pass must not upload")
	}
}

func TestOverrideAbortsBeforeAnyWrite(t *testing.T) {
	remote, server := newOverrideRemote(t)
	dir, _ := overrideFixture(t, server.URL, [4]uint64{160, 30, 8, 80})
	writeCodexSession(t, sessionPath(dir), [4]uint64{260, 60, 20, 180})
	_, err := RunOverride(context.Background(), OverrideOptions{
		StateDir: dir, ServerURL: server.URL,
		Confirm: func(OverridePlan) error { return fmt.Errorf("no") },
	})
	if err == nil {
		t.Fatal("confirmation refusal must abort")
	}
	if remote.posts != 0 {
		t.Fatal("aborted pass must not upload")
	}
	if _, err := os.Stat(overrides.New(dir).Path()); !os.IsNotExist(err) {
		t.Fatal("aborted pass must not write the override ledger")
	}
}

func TestOverrideCapabilityGate(t *testing.T) {
	remote, server := newOverrideRemote(t)
	remote.noCapability = true
	dir, _ := overrideFixture(t, server.URL, [4]uint64{160, 30, 8, 80})
	writeCodexSession(t, sessionPath(dir), [4]uint64{260, 60, 20, 180})
	_, err := RunOverride(context.Background(), OverrideOptions{
		StateDir: dir, ServerURL: server.URL, Confirm: autoConfirmOverride(nil),
	})
	if err == nil || !strings.Contains(err.Error(), "replace-existing") {
		t.Fatalf("missing capability must fail closed: %v", err)
	}
	if remote.posts != 0 {
		t.Fatal("no upload may happen without the capability")
	}
	if _, serr := os.Stat(overrides.New(dir).Path()); !os.IsNotExist(serr) {
		t.Fatal("capability gate must run before any ledger write")
	}
}

func TestOverrideRejectedStaysPendingAndBlocksPlainResync(t *testing.T) {
	remote, server := newOverrideRemote(t)
	dir, _ := overrideFixture(t, server.URL, [4]uint64{160, 30, 8, 80})
	writeCodexSession(t, sessionPath(dir), [4]uint64{260, 60, 20, 180})
	remote.rejectAll = true

	res, err := RunOverride(context.Background(), OverrideOptions{
		StateDir: dir, ServerURL: server.URL, Confirm: autoConfirmOverride(nil),
	})
	if err == nil {
		t.Fatal("a pass with server rejections must return an error")
	}
	if res.Completed {
		t.Fatal("a pass with server rejections must not be completed")
	}
	ledger, _, lerr := overrides.New(dir).Load()
	if lerr != nil {
		t.Fatal(lerr)
	}
	key := recordKeyString(t, scanCodex(t, fixtureInput(dir))[0])
	entry := ledger.Entries[key]
	if entry.Status != overrides.StatusPending || entry.PendingAttemptID == "" || len(entry.PendingRecord) == 0 {
		t.Fatalf("rejected record must keep its frozen attempt pending: %#v", entry)
	}
	// Plain resync is explicitly blocked while the override is pending.
	if _, rerr := Run(context.Background(), Options{
		StateDir: dir, ServerURL: server.URL, Confirm: func(Plan) error { return nil },
	}); rerr == nil || !strings.Contains(rerr.Error(), "override pass is incomplete") {
		t.Fatalf("plain resync must be blocked by a pending override: %v", rerr)
	}
	// A retry replays the same frozen identity; the rejection stands.
	remote.rejectAll = false
	res2, err2 := RunOverride(context.Background(), OverrideOptions{
		StateDir: dir, ServerURL: server.URL, Confirm: autoConfirmOverride(nil),
	})
	if err2 == nil {
		t.Fatal("the replayed rejection keeps the pass incomplete")
	}
	posts := remote.snapshot()
	if len(posts) != 2 || posts[0].BatchID != posts[1].BatchID {
		t.Fatalf("the frozen attempt must retry under the same identity: %+v", posts)
	}
	if !posts[1].Replay {
		t.Fatal("the retry of the same identity must be a server-side replay")
	}
	if res2.Completed {
		t.Fatal("replayed rejection must not complete the pass")
	}
}

func TestOverrideFrozenRetryConvergesAfterCrashBetweenACKAndConfirm(t *testing.T) {
	remote, server := newOverrideRemote(t)
	dir, _ := overrideFixture(t, server.URL, [4]uint64{160, 30, 8, 80})
	writeCodexSession(t, sessionPath(dir), [4]uint64{260, 60, 20, 180})
	current := scanCodex(t, fixtureInput(dir))

	// Pass 1 succeeds: the server acknowledged and cached the receipt.
	if _, err := RunOverride(context.Background(), OverrideOptions{
		StateDir: dir, ServerURL: server.URL, Confirm: autoConfirmOverride(nil),
	}); err != nil {
		t.Fatal(err)
	}
	// Simulate the crash window: the acknowledgment happened but the
	// local confirmation write did not — revert the entry to pending
	// with its frozen payload and attempt id.
	ledgerStore := overrides.New(dir)
	ledger, _, err := ledgerStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	key := recordKeyString(t, current[0])
	entry := ledger.Entries[key]
	at := time.Now().UTC()
	entry.Status = overrides.StatusPending
	entry.PendingRecord = entry.Record
	entry.PendingAttemptID = entry.AttemptID
	entry.PendingSince = &at
	entry.Record = nil
	entry.AttemptID = ""
	ledger.Entries[key] = entry
	if err := ledgerStore.Save(ledger); err != nil {
		t.Fatal(err)
	}
	postsBefore := len(remote.snapshot())

	// Pass 2 resolves the frozen attempt under the same identity: the
	// server replays the acknowledged receipt and the pass converges
	// without a second data change.
	res, err := RunOverride(context.Background(), OverrideOptions{
		StateDir: dir, ServerURL: server.URL, Confirm: autoConfirmOverride(nil),
	})
	if err != nil || !res.Completed {
		t.Fatalf("frozen retry must converge: %v completed=%t", err, res.Completed)
	}
	posts := remote.snapshot()
	if len(posts) != postsBefore+1 {
		t.Fatalf("the frozen attempt must be re-uploaded once, got %d posts (before %d)", len(posts), postsBefore)
	}
	if posts[len(posts)-1].BatchID != posts[postsBefore-1].BatchID {
		t.Fatal("the frozen retry must reuse the original batch identity")
	}
	ledger2, _, err := ledgerStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	if e := ledger2.Entries[key]; e.Status != overrides.StatusConfirmed || string(e.Record) != string(current[0]) {
		t.Fatalf("frozen attempt must be confirmed with its payload: %#v", e)
	}
}

func TestOverrideABAContentNeverReusesAnOldReceipt(t *testing.T) {
	remote, server := newOverrideRemote(t)
	dir, _ := overrideFixture(t, server.URL, [4]uint64{160, 30, 8, 80})
	// A: the original archived content (input delta 60).
	contentA := scanCodex(t, fixtureInput(dir))
	// B: first drift.
	writeCodexSession(t, sessionPath(dir), [4]uint64{260, 60, 20, 180})
	if _, err := RunOverride(context.Background(), OverrideOptions{
		StateDir: dir, ServerURL: server.URL, Confirm: autoConfirmOverride(nil),
	}); err != nil {
		t.Fatal(err)
	}
	// A again: the source reverts to the archived values. This is a NEW
	// drift against the confirmed B baseline, and its upload must NOT
	// reuse any earlier batch identity (there is no earlier A upload
	// here, but the identity must still be attempt-scoped).
	writeCodexSession(t, sessionPath(dir), [4]uint64{160, 30, 8, 80})
	res, err := RunOverride(context.Background(), OverrideOptions{
		StateDir: dir, ServerURL: server.URL, Confirm: autoConfirmOverride(nil),
	})
	if err != nil || !res.Completed {
		t.Fatalf("A→B→A override must complete: %v", err)
	}
	posts := remote.snapshot()
	if len(posts) != 2 {
		t.Fatalf("expected two uploads (B then A), got %d", len(posts))
	}
	if posts[0].BatchID == posts[1].BatchID {
		t.Fatal("distinct attempts must derive distinct batch identities")
	}
	if posts[1].Replay {
		t.Fatal("the reverted content must be freshly applied, never a replay of the earlier receipt")
	}
	ledger, _, err := overrides.New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	key := recordKeyString(t, contentA[0])
	if e := ledger.Entries[key]; e.Status != overrides.StatusConfirmed || string(e.Record) != string(contentA[0]) {
		t.Fatalf("the reverted content must be the confirmed baseline: %#v", e)
	}
}

func TestPlainResyncSubstitutesConfirmedOverrideAndRetransmitsLedgerOnly(t *testing.T) {
	remote, server := newOverrideRemote(t)
	dir, archived := overrideFixture(t, server.URL, [4]uint64{160, 30, 8, 80})
	// Drift and confirm the override for the archived key.
	writeCodexSession(t, sessionPath(dir), [4]uint64{260, 60, 20, 180})
	current := scanCodex(t, fixtureInput(dir))
	if _, err := RunOverride(context.Background(), OverrideOptions{
		StateDir: dir, ServerURL: server.URL, Confirm: autoConfirmOverride(nil),
	}); err != nil {
		t.Fatal(err)
	}
	// A ledger-only confirmed entry: a current-scan record no archived
	// batch carries (the override pass would have created it for a new
	// key; here it is seeded directly).
	ledgerStore := overrides.New(dir)
	ledger, _, err := ledgerStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	ledgerOnly := record("codex-jsonl:ledger-only", "2026-10-20T01:05:00Z")
	ledger.Entries["codex-jsonl:ledger-only"] = overrides.Entry{
		RecordKey: "codex-jsonl:ledger-only", Source: "codex-jsonl", Input: fixtureInput(dir),
		Record: ledgerOnly, AttemptID: "oa-seed", Status: overrides.StatusConfirmed,
		UpdatedAt: time.Now().UTC(),
	}
	if err := ledgerStore.Save(ledger); err != nil {
		t.Fatal(err)
	}

	res, err := Run(context.Background(), Options{
		StateDir: dir, ServerURL: server.URL, Confirm: func(Plan) error { return nil },
	})
	if err != nil {
		t.Fatalf("plain resync with confirmed overrides: %v", err)
	}
	if !res.Completed {
		t.Fatal("plain resync must complete")
	}
	posts := remote.snapshot()
	// Posts: 1 override pass + archived substitution child + ledger-only.
	if len(posts) != 3 {
		t.Fatalf("expected 3 posts (override, substituted child, ledger-only), got %d", len(posts))
	}
	substituted, ledgerOnlyPost := posts[1], posts[2]
	if !substituted.ReplaceExisting {
		t.Fatal("the substituted archived child must be sent with replaceExisting=true")
	}
	if len(substituted.Records) != 1 || string(substituted.Records[0]) != string(current[0]) {
		t.Fatalf("the archived record must be substituted with the override content, got %s", substituted.Records)
	}
	if substituted.BatchID == "batch-00" {
		t.Fatal("a substituted parent must never be retransmitted verbatim")
	}
	if !ledgerOnlyPost.ReplaceExisting || len(ledgerOnlyPost.Records) != 1 || string(ledgerOnlyPost.Records[0]) != string(ledgerOnly) {
		t.Fatalf("the ledger-only record must be retransmitted with replacement: %+v", ledgerOnlyPost)
	}
	// The superseded archived payload never leaves the device.
	for _, p := range posts {
		for _, r := range p.Records {
			if string(r) == string(archived[0]) {
				t.Fatal("the superseded archived payload must never be retransmitted")
			}
		}
	}
}

func recordKeyString(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	key, err := recordKeyOf(raw)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
