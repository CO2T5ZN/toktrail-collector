package resync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncclient"
)

type fakeRemote struct {
	mu                                    sync.Mutex
	calls                                 int
	selfCalls                             int
	posts                                 int
	posted                                [][]string
	seen                                  map[string]bool
	receipts                              map[string]syncclient.BatchReceipt
	paused, revoked, reject, wrongReceipt bool
	failBatch                             string
	scopeRejectBatch                      string
	// dropResponseBatch models a server that COMMITS an ingest (receipt
	// recorded, record keys counted) but loses the response on the wire:
	// the declared body is longer than the truncated bytes actually
	// written, so the client cannot decode the reply while the commit
	// stands. A retry of the same batch id then replays idempotently.
	dropResponseBatch string
	allowed           []string
	from              *time.Time
	revision          int64
	// Mid-run authorization drift: once more than widenAfterSelf self
	// GETs have been served, the served scope switches to
	// widenRevision/widenFrom (modeling a consent change between this
	// collector's preflight and a later read). Zero disables the switch.
	widenAfterSelf int
	widenRevision  int64
	widenFrom      *time.Time
}

// servedScope reports the consent scope the fake currently serves.
func (f *fakeRemote) servedScope() (revision int64, from *time.Time) {
	if f.widenAfterSelf > 0 && f.selfCalls > f.widenAfterSelf {
		return f.widenRevision, f.widenFrom
	}
	return f.revision, f.from
}

func newRemote(t *testing.T) (*fakeRemote, *httptest.Server) {
	t.Helper()
	s := &fakeRemote{seen: map[string]bool{}, receipts: map[string]syncclient.BatchReceipt{}, allowed: []string{"Codex"}, revision: 1}
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.calls++
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/devices/self" {
			s.selfCalls++
			revision, from := s.servedScope()
			v := 1
			json.NewEncoder(w).Encode(map[string]any{"device": syncclient.SelfStatus{DeviceID: "device-resync", ConsentRevision: revision, UploadAuthorized: !s.revoked, Revoked: s.revoked, Paused: s.paused, GrantProtocolVersion: &v, AllowedTools: s.allowed, HistoryFrom: from}})
			return
		}
		if r.URL.Path != "/v1/ingest/batches" {
			w.WriteHeader(404)
			return
		}
		effectiveRevision, _ := s.servedScope()
		if r.Header.Get("X-Consent-Revision") != strconv.FormatInt(effectiveRevision, 10) {
			t.Error("missing live consent revision")
		}
		s.posts++
		var batch syncclient.BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		keys := make([]string, 0, len(batch.Records))
		for _, raw := range batch.Records {
			var probe map[string]any
			if json.Unmarshal(raw, &probe) == nil {
				keys = append(keys, fmt.Sprint(probe["recordKey"]))
			}
		}
		s.posted = append(s.posted, keys)
		if batch.BatchID == s.failBatch {
			w.WriteHeader(503)
			fmt.Fprint(w, `{"error":{"code":"temporarily_unavailable","message":"synthetic failure"}}`)
			return
		}
		if batch.BatchID == s.scopeRejectBatch {
			w.WriteHeader(409)
			fmt.Fprint(w, `{"error":{"code":"scope_changed","message":"synthetic scope change"}}`)
			return
		}
		if batch.BatchID == s.dropResponseBatch {
			// Commit exactly as a normal accept would...
			if _, ok := s.receipts[batch.BatchID]; !ok {
				dropped := syncclient.BatchReceipt{BatchID: batch.BatchID, Status: "accepted", AcceptedRecords: len(batch.Records), ReceivedAt: time.Now().UTC()}
				for _, raw := range batch.Records {
					var rec map[string]any
					json.Unmarshal(raw, &rec)
					if key, ok := rec["recordKey"].(string); ok {
						s.seen[key] = true
					}
				}
				s.receipts[batch.BatchID] = dropped
			}
			// ...then lose the response: the declared Content-Length
			// exceeds the truncated bytes written, so the client's decode
			// fails after the headers arrived (never retried by the
			// transport) while the commit stands.
			w.Header().Set("Content-Length", "4096")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"batch":{"batchId":%q,"status":"acce`, batch.BatchID)
			return
		}
		receipt, ok := s.receipts[batch.BatchID]
		if ok {
			receipt.Replay = true
		} else {
			receipt = syncclient.BatchReceipt{BatchID: batch.BatchID, Status: "accepted", AcceptedRecords: len(batch.Records), ReceivedAt: time.Now().UTC()}
			for idx, raw := range batch.Records {
				var rec map[string]any
				json.Unmarshal(raw, &rec)
				key := rec["recordKey"].(string)
				if s.reject {
					receipt.AcceptedRecords--
					receipt.RejectedRecords++
					// The status word must agree with the counts: the
					// syncclient fails contradictory receipts closed.
					switch {
					case receipt.RejectedRecords == 0:
						receipt.Status = "accepted"
					case receipt.AcceptedRecords == 0:
						receipt.Status = "rejected"
					default:
						receipt.Status = "partial"
					}
					receipt.RecordErrors = append(receipt.RecordErrors, syncclient.RecordError{Index: idx, RecordKey: key, Code: "record_conflict", Message: "synthetic conflict"})
				} else {
					s.seen[key] = true
				}
			}
			s.receipts[batch.BatchID] = receipt
		}
		if s.wrongReceipt {
			receipt.BatchID = "another-batch"
		}
		json.NewEncoder(w).Encode(map[string]any{"batch": receipt})
	}))
	t.Cleanup(h.Close)
	return s, h
}

// set swaps the live consent revision and history cutoff the fake serves
// (and disables any armed mid-run switch, stabilizing the new scope).
func (f *fakeRemote) set(revision int64, from *time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revision = revision
	f.from = from
	f.widenAfterSelf = 0
}

// armWiden switches the served consent scope once more than afterSelf
// self GETs have been served.
func (f *fakeRemote) armWiden(afterSelf int, revision int64, from *time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.widenAfterSelf = afterSelf
	f.widenRevision = revision
	f.widenFrom = from
}

func (f *fakeRemote) postCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.posts
}

func (f *fakeRemote) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeRemote) resetPosted() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.posted = nil
}

func (f *fakeRemote) postedKeys() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]string(nil), f.posted...)
}

// seenHas reports whether the fake ever committed the record key.
func (f *fakeRemote) seenHas(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seen[key]
}

// receiptFor returns the committed receipt the fake holds for a batch.
func (f *fakeRemote) receiptFor(batchID string) (syncclient.BatchReceipt, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	receipt, ok := f.receipts[batchID]
	return receipt, ok
}
func record(key, occurred string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"recordKey": key, "kind": "delta", "tool": "Codex", "model": "gpt-5.4", "occurredAt": occurred, "input": "100", "output": "50", "cacheRead": "20", "cacheWrite": "5", "adapterVersion": "synthetic", "sourceType": "fixture"})
	return b
}
func fixtureInput(dir string) string {
	return filepath.Join(dir, "synthetic", "codex")
}

func fixture(t *testing.T, url string, batches ...[]json.RawMessage) string {
	t.Helper()
	dir := t.TempDir()
	if err := statedir.New(dir).Save(statedir.DeviceState{DeviceID: "device-resync", DeviceSecret: strings.Repeat("a", 64), ApplicationID: "synthetic-app", ExternalSubjectID: "synthetic-user", ServerURL: url, UploadAuthorized: true, ConsentRevision: 1}); err != nil {
		t.Fatal(err)
	}
	input := fixtureInput(dir)
	rel, err := filepath.Rel(dir, input)
	if err != nil || !filepath.IsAbs(input) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		t.Fatalf("synthetic input must be absolute and inside the test directory: %q", input)
	}
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := grants.New(dir).Enable("codex-jsonl", input); err != nil {
		t.Fatalf("create synthetic source grant: %v", err)
	}
	var entries []outbox.BatchEntry
	for idx, records := range batches {
		id := fmt.Sprintf("batch-%02d", idx)
		file := filepath.Join(dir, id+".json")
		writeJSON(t, file, syncclient.BatchRequest{BatchID: id, Records: records})
		entries = append(entries, outbox.BatchEntry{BatchID: id, File: file, Source: "codex-jsonl", Input: input, Status: outbox.StatusSynced, RecordCount: len(records), CreatedAt: time.Now().UTC()})
	}
	if err := outbox.New(dir).Save(outbox.Outbox{Batches: entries}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"message-progress.json", "adapter-cursors.json", "scope-quarantine.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("[]\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}
func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	m := map[string]string{}
	if err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		m[filepath.ToSlash(rel)] = string(b)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return m
}
func options(dir string) Options {
	return Options{StateDir: dir, Confirm: func(Plan) error { return nil }}
}
func assertOriginals(t *testing.T, dir string, before map[string]string) {
	t.Helper()
	for path, value := range before {
		if path == "device.json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != value {
			t.Fatalf("original file changed: %s", path)
		}
	}
}
func TestFixtureUsesNativeAbsoluteGrantPaths(t *testing.T) {
	dir := fixture(t, "http://127.0.0.1:1", []json.RawMessage{record("fixture-path", "2026-10-28T00:00:00Z")})
	enabled, err := grants.New(dir).Enabled()
	if err != nil || len(enabled) != 1 {
		t.Fatalf("load synthetic source grant: grants=%v err=%v", enabled, err)
	}
	input := enabled[0].Input
	rel, err := filepath.Rel(dir, input)
	if err != nil || !filepath.IsAbs(input) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		t.Fatalf("grant must use an absolute path inside its fixture: %q", input)
	}
	if info, err := os.Stat(input); err != nil || !info.IsDir() {
		t.Fatalf("grant must refer to an existing synthetic directory: %v", err)
	}
	ledger, err := outbox.New(dir).Load()
	if err != nil || len(ledger.Batches) != 1 {
		t.Fatalf("load synthetic archives: %v", err)
	}
	for _, entry := range ledger.Batches {
		if entry.Input != input || !filepath.IsAbs(entry.Input) {
			t.Fatalf("archive input must match its native source grant: %q vs %q", entry.Input, input)
		}
	}
}

func TestSnapshotUsesPortableRelativeKeys(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, filepath.Join(dir, "device.json"), map[string]string{"state": "before"})
	archiveDir := filepath.Join(dir, "archives")
	if err := os.MkdirAll(archiveDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(archiveDir, "batch.json"), map[string]string{"record": "original"})
	before := snapshot(t, dir)
	if len(before) != 2 || before["device.json"] == "" || before["archives/batch.json"] == "" {
		t.Fatalf("snapshot must use slash-separated relative keys: %v", before)
	}
	writeJSON(t, filepath.Join(dir, "device.json"), map[string]string{"state": "acknowledged"})
	assertOriginals(t, dir, before)
}

func TestDryRunIsOfflineAndReadOnly(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprint(empty), func(t *testing.T) {
			remote, server := newRemote(t)
			var batches [][]json.RawMessage
			if !empty {
				batches = append(batches, []json.RawMessage{record("a", "2026-10-28T00:00:00Z")})
			}
			dir := fixture(t, server.URL, batches...)
			before := snapshot(t, dir)
			opt := options(dir)
			opt.DryRun = true
			result, err := Run(context.Background(), opt)
			if err != nil {
				t.Fatal(err)
			}
			if !result.DryRun || remote.calls != 0 {
				t.Fatalf("dry-run made requests: %+v", result)
			}
			if !reflect.DeepEqual(before, snapshot(t, dir)) {
				t.Fatal("dry-run changed disk")
			}
		})
	}
}
func TestRestoreReplayAndPreserveOriginalProgress(t *testing.T) {
	remote, server := newRemote(t)
	dir := fixture(t, server.URL, []json.RawMessage{record("a", "2026-10-28T00:00:00Z")}, []json.RawMessage{record("b", "2026-10-27T00:00:00Z")})
	before := snapshot(t, dir)
	first, err := Run(context.Background(), options(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !first.Completed || first.AcceptedRecords != 2 || len(remote.seen) != 2 {
		t.Fatalf("restore: %+v", first)
	}
	assertOriginals(t, dir, before)
	again, err := Run(context.Background(), options(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !again.Completed || again.ReplayReceipts != 2 || len(remote.seen) != 2 || remote.posts != 4 {
		t.Fatalf("explicit second pass must replay without duplicates: %+v", again)
	}
	assertOriginals(t, dir, before)
}
func TestBudgetAndFailureResume(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			remote, server := newRemote(t)
			dir := fixture(t, server.URL, []json.RawMessage{record("a", "2026-10-28T00:00:00Z")}, []json.RawMessage{record("b", "2026-10-27T00:00:00Z")})
			opt := options(dir)
			if failure {
				remote.failBatch = "batch-01"
			} else {
				opt.MaxBatches = 1
			}
			first, err := Run(context.Background(), opt)
			if failure && err == nil {
				t.Fatal("expected transient failure")
			}
			if !failure && err != nil {
				t.Fatal(err)
			}
			if first.Completed {
				t.Fatal("premature completion")
			}
			remote.failBatch = ""
			resumed, err := Run(context.Background(), options(dir))
			if err != nil {
				t.Fatal(err)
			}
			if !resumed.Completed || !resumed.Plan.Resumed || resumed.Uploads != 1 || len(remote.seen) != 2 {
				t.Fatalf("resume: %+v", resumed)
			}
		})
	}
}
func TestScopeFiltersWithoutChangingArchives(t *testing.T) {
	remote, server := newRemote(t)
	cutoff := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	remote.from = &cutoff
	dir := fixture(t, server.URL, []json.RawMessage{record("old", "2025-01-01T00:00:00Z"), record("new", "2026-10-28T00:00:00Z")})
	before := snapshot(t, dir)
	result, err := Run(context.Background(), options(dir))
	if err != nil {
		t.Fatal(err)
	}
	if result.AcceptedRecords != 1 || result.SkippedOutOfScopeRecords != 1 || remote.seen["old"] || !remote.seen["new"] {
		t.Fatalf("scope: %+v", result)
	}
	assertOriginals(t, dir, before)
}
func TestAuthorizationStopsResync(t *testing.T) {
	for _, kind := range []string{"paused", "revoked", "local-disabled", "local-missing"} {
		t.Run(kind, func(t *testing.T) {
			remote, server := newRemote(t)
			dir := fixture(t, server.URL, []json.RawMessage{record("a", "2026-10-28T00:00:00Z")})
			switch kind {
			case "paused":
				remote.paused = true
			case "revoked":
				remote.revoked = true
			case "local-disabled":
				if _, found, err := grants.New(dir).Disable("codex-jsonl", fixtureInput(dir)); err != nil || !found {
					t.Fatalf("disable synthetic grant: found=%t err=%v", found, err)
				}
			case "local-missing":
				if err := os.Remove(filepath.Join(dir, "grants.json")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Run(context.Background(), options(dir)); err == nil {
				t.Fatal("expected authorization refusal")
			}
			if remote.posts != 0 {
				t.Fatal("uploaded without authorization")
			}
		})
	}
}
func TestResumeRejectsTamperingAndMissingArchive(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprint(missing), func(t *testing.T) {
			remote, server := newRemote(t)
			dir := fixture(t, server.URL, []json.RawMessage{record("a", "2026-10-28T00:00:00Z")}, []json.RawMessage{record("b", "2026-10-27T00:00:00Z")})
			opt := options(dir)
			opt.MaxBatches = 1
			if _, err := Run(context.Background(), opt); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(dir, "batch-01.json")
			if missing {
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(file, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			previous := remote.posts
			if _, err := Run(context.Background(), options(dir)); err == nil {
				t.Fatal("expected changed archive refusal")
			}
			if remote.posts != previous {
				t.Fatal("uploaded after archive divergence")
			}
		})
	}
}
func TestDryRunDoesNotFinalizeInterruptedJob(t *testing.T) {
	_, server := newRemote(t)
	dir := fixture(t, server.URL, []json.RawMessage{record("a", "2026-10-28T00:00:00Z")})
	if _, err := Run(context.Background(), options(dir)); err != nil {
		t.Fatal(err)
	}
	jb, _, err := loadJob(dir)
	if err != nil {
		t.Fatal(err)
	}
	jb.CompletedAt = nil
	if err := saveJob(dir, jb); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, dir)
	opt := options(dir)
	opt.DryRun = true
	result, err := Run(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Plan.PendingFinalize || !reflect.DeepEqual(before, snapshot(t, dir)) {
		t.Fatal("dry-run finalized a job")
	}
	opt.DryRun = false
	opt.Confirm = func(Plan) error { return errors.New("cancelled") }
	if _, err := Run(context.Background(), opt); err == nil {
		t.Fatal("expected cancelled finalize")
	}
	if !reflect.DeepEqual(before, snapshot(t, dir)) {
		t.Fatal("cancelled confirmation wrote state")
	}
}
func TestWrongBatchReceiptRemainsResumable(t *testing.T) {
	remote, server := newRemote(t)
	remote.wrongReceipt = true
	dir := fixture(t, server.URL, []json.RawMessage{record("a", "2026-10-28T00:00:00Z")})
	result, err := Run(context.Background(), options(dir))
	if err == nil || result.Completed || !strings.Contains(err.Error(), "does not match submitted batch") {
		t.Fatalf("wrong receipt accepted: %+v err=%v", result, err)
	}
	job, exists, err := loadJob(dir)
	if err != nil || !exists || job.CompletedAt != nil || job.Batches[0].Outcome == outcomeDone {
		t.Fatalf("wrong receipt marked completed: %+v err=%v", job, err)
	}
	remote.wrongReceipt = false
	result, err = Run(context.Background(), options(dir))
	if err != nil || !result.Completed || !result.Plan.Resumed {
		t.Fatalf("valid receipt could not resume: %+v err=%v", result, err)
	}
}

func TestRejectedReceiptIsNotReportedAsSuccessfulRestore(t *testing.T) {
	remote, server := newRemote(t)
	remote.reject = true
	dir := fixture(t, server.URL, []json.RawMessage{record("a", "2026-10-28T00:00:00Z")})
	result, err := Run(context.Background(), options(dir))
	if err == nil || result.RejectedRecords != 1 || result.AcceptedRecords != 0 || len(remote.seen) != 0 {
		t.Fatalf("rejection hidden: %+v err=%v", result, err)
	}
}

// ---------------------------------------------------------------------------
// Consent-scope changes on incomplete jobs
// ---------------------------------------------------------------------------

// rewriteJournalAsSchemaOne rewrites the on-disk journal in the legacy
// schema-1 form (no job-level scope baseline, per-batch revision stamps
// preserved), optionally editing the job first. It models journals written
// before the scope baseline existed.
func rewriteJournalAsSchemaOne(t *testing.T, dir string, edit func(*job)) {
	t.Helper()
	jb, exists, err := loadJob(dir)
	if err != nil || !exists {
		t.Fatalf("load journal: exists=%t err=%v", exists, err)
	}
	if edit != nil {
		edit(&jb)
	}
	jb.Schema = legacyJournalSchema
	jb.Scope = nil
	if err := saveJob(dir, jb); err != nil {
		t.Fatal(err)
	}
}

func TestResumeReplansWhenScopeWidens(t *testing.T) {
	remote, server := newRemote(t)
	cutoff := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	remote.from = &cutoff
	dir := fixture(t, server.URL,
		[]json.RawMessage{record("old", "2025-01-01T00:00:00Z"), record("new", "2026-10-28T00:00:00Z")},
		[]json.RawMessage{record("b", "2026-10-27T00:00:00Z")},
	)
	opt := options(dir)
	opt.MaxBatches = 1
	first, err := Run(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if first.Completed || first.SkippedOutOfScopeRecords != 1 || remote.seen["old"] || !remote.seen["new"] {
		t.Fatalf("first pass: %+v", first)
	}
	staleJob, exists, err := loadJob(dir)
	if err != nil || !exists || staleJob.CompletedAt != nil {
		t.Fatalf("incomplete job: exists=%t err=%v", exists, err)
	}

	// The authorization widens: no history cutoff, revision bumped.
	remote.set(2, nil)

	postsBefore := remote.postCount()
	second, err := Run(context.Background(), options(dir))
	if err == nil {
		t.Fatal("expected the scope-change stop")
	}
	if second.Completed || second.Stopped != "consent scope changed" || remote.postCount() != postsBefore {
		t.Fatalf("the scope-change run must stop before any upload: %+v err=%v", second, err)
	}
	if !strings.Contains(err.Error(), "NOT treated as completing the current scope") {
		t.Fatalf("the stop must explain the stale-decision rule: %v", err)
	}

	replanned, exists, err := loadJob(dir)
	if err != nil || !exists {
		t.Fatalf("re-planned journal: exists=%t err=%v", exists, err)
	}
	if replanned.CompletedAt != nil || replanned.JobID == staleJob.JobID || replanned.Scope == nil || replanned.Scope.Revision != 2 {
		t.Fatalf("the journal must carry a fresh incomplete plan pinned to revision 2: %+v", replanned)
	}
	for _, b := range replanned.Batches {
		if b.Outcome != outcomePlanned || len(b.Uploads) > 0 || len(b.Skipped) > 0 {
			t.Fatalf("stale decision carried into the re-planned job: %+v", b)
		}
	}

	third, err := Run(context.Background(), options(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !third.Completed || !third.Plan.Resumed || !remote.seen["old"] || !remote.seen["b"] {
		t.Fatalf("the re-planned pass must restore the widened history: %+v", third)
	}
}

func TestResumeReplansWhenScopeNarrows(t *testing.T) {
	remote, server := newRemote(t)
	dir := fixture(t, server.URL,
		[]json.RawMessage{record("a", "2026-10-28T00:00:00Z"), record("b2", "2026-10-27T00:00:00Z")},
		[]json.RawMessage{record("c", "2026-10-26T00:00:00Z")},
	)
	opt := options(dir)
	opt.MaxBatches = 1
	first, err := Run(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if first.Completed || !remote.seen["a"] || !remote.seen["b2"] {
		t.Fatalf("first pass: %+v", first)
	}

	// The authorization narrows: history now starts at 2026-10-28.
	cutoff := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	remote.set(2, &cutoff)

	postsBefore := remote.postCount()
	second, err := Run(context.Background(), options(dir))
	if err == nil || second.Completed || second.Stopped != "consent scope changed" || remote.postCount() != postsBefore {
		t.Fatalf("the scope-change run must stop before any upload: %+v err=%v", second, err)
	}

	remote.resetPosted()
	third, err := Run(context.Background(), options(dir))
	if err != nil {
		t.Fatal(err)
	}
	// Records withheld outside the narrowed scope are a normal exclusion,
	// never a failure: the pass still completes.
	if !third.Completed || third.SkippedOutOfScopeRecords != 2 || third.Blocked != 1 {
		t.Fatalf("narrowed pass: %+v", third)
	}
	posted := remote.postedKeys()
	if len(posted) != 1 || len(posted[0]) != 1 || posted[0][0] != "a" {
		t.Fatalf("only in-scope records may be retransmitted after narrowing: %v", posted)
	}
}

func TestFinalizeVerifiesLiveScopeBeforeCompleting(t *testing.T) {
	remote, server := newRemote(t)
	cutoff := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	remote.from = &cutoff
	dir := fixture(t, server.URL, []json.RawMessage{record("old", "2025-01-01T00:00:00Z"), record("new", "2026-10-28T00:00:00Z")})
	if _, err := Run(context.Background(), options(dir)); err != nil {
		t.Fatal(err)
	}
	jb, exists, err := loadJob(dir)
	if err != nil || !exists || jb.CompletedAt == nil {
		t.Fatalf("completed job: exists=%t err=%v", exists, err)
	}
	// Simulate the crash the lazy finalize path exists for: the last
	// upload landed, the completion write did not.
	jb.CompletedAt = nil
	if err := saveJob(dir, jb); err != nil {
		t.Fatal(err)
	}

	// The authorization widens before the job may be marked complete.
	remote.set(2, nil)
	postsBefore := remote.postCount()
	result, err := Run(context.Background(), options(dir))
	if err == nil || result.Completed || result.Stopped != "consent scope changed" || remote.postCount() != postsBefore {
		t.Fatalf("stale done must not complete under a changed scope: %+v err=%v", result, err)
	}

	final, err := Run(context.Background(), options(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !final.Completed || !remote.seen["old"] {
		t.Fatalf("the re-planned pass must restore the widened record: %+v", final)
	}
}

func TestFinalizeConvergesWhenScopeUnchanged(t *testing.T) {
	remote, server := newRemote(t)
	dir := fixture(t, server.URL, []json.RawMessage{record("a", "2026-10-28T00:00:00Z")})
	if _, err := Run(context.Background(), options(dir)); err != nil {
		t.Fatal(err)
	}
	jb, _, err := loadJob(dir)
	if err != nil {
		t.Fatal(err)
	}
	jb.CompletedAt = nil
	if err := saveJob(dir, jb); err != nil {
		t.Fatal(err)
	}
	postsBefore := remote.postCount()
	callsBefore := remote.callCount()
	result, err := Run(context.Background(), options(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Completed || !result.Plan.PendingFinalize {
		t.Fatalf("lazy finalize: %+v", result)
	}
	if remote.postCount() != postsBefore {
		t.Fatal("the lazy finalize must not re-upload anything")
	}
	if remote.callCount() == callsBefore {
		t.Fatal("the lazy finalize must re-verify the live scope before completing")
	}
	converged, _, err := loadJob(dir)
	if err != nil || converged.CompletedAt == nil {
		t.Fatalf("job not converged: %+v err=%v", converged, err)
	}
}

func TestLegacyJournalMigratesWithoutReplanWhenRevisionMatches(t *testing.T) {
	remote, server := newRemote(t)
	dir := fixture(t, server.URL,
		[]json.RawMessage{record("a", "2026-10-28T00:00:00Z")},
		[]json.RawMessage{record("b", "2026-10-27T00:00:00Z")},
	)
	opt := options(dir)
	opt.MaxBatches = 1
	if _, err := Run(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	rewriteJournalAsSchemaOne(t, dir, nil)

	postsBefore := remote.postCount()
	result, err := Run(context.Background(), options(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Completed || !result.Plan.Resumed {
		t.Fatalf("a legacy journal with a matching revision must resume: %+v", result)
	}
	if remote.postCount() != postsBefore+1 {
		t.Fatalf("migration must keep the resume fast path (only the remaining batch uploads): posts %d -> %d", postsBefore, remote.postCount())
	}
	upgraded, _, err := loadJob(dir)
	if err != nil {
		t.Fatal(err)
	}
	if upgraded.Schema != journalSchema || upgraded.Scope == nil || upgraded.Scope.Revision != 1 || upgraded.CompletedAt == nil {
		t.Fatalf("the journal must be upgraded with the adopted baseline: %+v", upgraded)
	}
}

func TestLegacyJournalReplansWhenRevisionDiffers(t *testing.T) {
	remote, server := newRemote(t)
	dir := fixture(t, server.URL,
		[]json.RawMessage{record("a", "2026-10-28T00:00:00Z")},
		[]json.RawMessage{record("b", "2026-10-27T00:00:00Z")},
	)
	opt := options(dir)
	opt.MaxBatches = 1
	if _, err := Run(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	rewriteJournalAsSchemaOne(t, dir, nil)
	remote.set(2, nil)

	postsBefore := remote.postCount()
	result, err := Run(context.Background(), options(dir))
	if err == nil || result.Completed || result.Stopped != "consent scope changed" || remote.postCount() != postsBefore {
		t.Fatalf("a legacy journal under a new revision must re-plan: %+v err=%v", result, err)
	}
	if !strings.Contains(err.Error(), "the job's scope content was not recorded") {
		t.Fatalf("the stop must describe the legacy baseline: %v", err)
	}
	final, err := Run(context.Background(), options(dir))
	if err != nil || !final.Completed {
		t.Fatalf("re-planned pass: %+v err=%v", final, err)
	}
	if remote.postCount() != postsBefore+2 {
		t.Fatalf("the re-planned pass re-sends the complete history: posts %d -> %d", postsBefore, remote.postCount())
	}
}

func TestLegacyJournalWithMixedRevisionsReplans(t *testing.T) {
	remote, server := newRemote(t)
	dir := fixture(t, server.URL,
		[]json.RawMessage{record("a", "2026-10-28T00:00:00Z")},
		[]json.RawMessage{record("b", "2026-10-27T00:00:00Z")},
	)
	opt := options(dir)
	opt.MaxBatches = 1
	if _, err := Run(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	rewriteJournalAsSchemaOne(t, dir, func(j *job) {
		// Simulate decisions recorded under two different consent
		// revisions (a job that ran across a scope change).
		j.Batches[1].ScopeRevision = 2
	})
	postsBefore := remote.postCount()
	result, err := Run(context.Background(), options(dir))
	if err == nil || result.Completed || result.Stopped != "consent scope changed" || remote.postCount() != postsBefore {
		t.Fatalf("unattributable decisions must re-plan even at an unchanged revision: %+v err=%v", result, err)
	}
	if !strings.Contains(err.Error(), "mixed or unrecorded") {
		t.Fatalf("the stop must describe the unattributable baseline: %v", err)
	}
}

func TestCompletedLegacyJournalIsReplacedByFreshPass(t *testing.T) {
	remote, server := newRemote(t)
	dir := fixture(t, server.URL, []json.RawMessage{record("a", "2026-10-28T00:00:00Z")})
	if _, err := Run(context.Background(), options(dir)); err != nil {
		t.Fatal(err)
	}
	completed, _, err := loadJob(dir)
	if err != nil {
		t.Fatal(err)
	}
	rewriteJournalAsSchemaOne(t, dir, nil)
	remote.set(2, nil)

	result, err := Run(context.Background(), options(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Completed || result.Plan.Resumed || result.Plan.JobID == completed.JobID {
		t.Fatalf("a completed job is always replaced by a fresh full pass: %+v", result)
	}
	if remote.postCount() != 2 {
		t.Fatalf("the fresh pass re-sends the history once more: posts=%d", remote.postCount())
	}
}

func TestMidRunScopeChangeReplansOnResume(t *testing.T) {
	remote, server := newRemote(t)
	dir := fixture(t, server.URL,
		[]json.RawMessage{record("a", "2026-10-28T00:00:00Z")},
		[]json.RawMessage{record("b", "2026-10-27T00:00:00Z")},
	)
	remote.scopeRejectBatch = "batch-01"
	first, err := Run(context.Background(), options(dir))
	if err == nil || first.Completed {
		t.Fatalf("expected the server scope rejection to stop the run: %+v", first)
	}
	if first.Blocked != 1 || first.Stopped != "server scope rejection" {
		t.Fatalf("scope rejection outcome: %+v", first)
	}
	// The change the server was rejecting under becomes visible.
	remote.scopeRejectBatch = ""
	remote.set(2, nil)

	postsBefore := remote.postCount()
	second, err := Run(context.Background(), options(dir))
	if err == nil || second.Stopped != "consent scope changed" || remote.postCount() != postsBefore {
		t.Fatalf("the resume must re-plan after a mid-run scope change: %+v err=%v", second, err)
	}
	third, err := Run(context.Background(), options(dir))
	if err != nil || !third.Completed {
		t.Fatalf("re-planned pass: %+v err=%v", third, err)
	}
}

func TestUndecidedJobAdoptsFreshScopeWithoutReplan(t *testing.T) {
	remote, server := newRemote(t)
	dir := fixture(t, server.URL,
		[]json.RawMessage{record("a", "2026-10-28T00:00:00Z")},
		[]json.RawMessage{record("b", "2026-10-27T00:00:00Z")},
	)
	if _, err := Run(context.Background(), options(dir)); err != nil {
		t.Fatal(err)
	}
	jb, _, err := loadJob(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Roll the journal back to the crash-after-plan state: the durable
	// plan was written, but no decision was ever recorded under any scope.
	jb.CompletedAt = nil
	jb.Scope = nil
	for idx := range jb.Batches {
		jb.Batches[idx].Outcome = outcomePlanned
		jb.Batches[idx].Uploads = nil
		jb.Batches[idx].Skipped = nil
		jb.Batches[idx].ScopeRevision = 0
		jb.Batches[idx].Attempts = 0
		jb.Batches[idx].LastAttemptAt = nil
	}
	if err := saveJob(dir, jb); err != nil {
		t.Fatal(err)
	}
	// The authorization moved on since the plan was frozen; with nothing
	// decided there is nothing stale, so the run adopts the fresh scope.
	remote.set(2, nil)

	result, err := Run(context.Background(), options(dir))
	if err != nil || !result.Completed || !result.Plan.Resumed {
		t.Fatalf("an undecided job must adopt the fresh scope instead of re-planning: %+v err=%v", result, err)
	}
	if !remote.seen["a"] || !remote.seen["b"] {
		t.Fatalf("both batches must be retransmitted: %+v", result)
	}
}

func TestDoneBatchUnderDifferentRevisionIsReEvaluated(t *testing.T) {
	remote, server := newRemote(t)
	dir := fixture(t, server.URL,
		[]json.RawMessage{record("a", "2026-10-28T00:00:00Z")},
		[]json.RawMessage{record("b", "2026-10-27T00:00:00Z")},
	)
	opt := options(dir)
	opt.MaxBatches = 1
	if _, err := Run(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	// Force the job-level gate to pass while the done batch's own revision
	// stamp still disagrees with the live revision: the per-batch dynamic
	// scope check must re-open the batch instead of skipping it as done.
	remote.set(2, nil)
	jb, _, err := loadJob(dir)
	if err != nil {
		t.Fatal(err)
	}
	jb.Scope = snapshotScope(liveScope{revision: 2, allowedTools: map[string]struct{}{"Codex": {}}})
	if err := saveJob(dir, jb); err != nil {
		t.Fatal(err)
	}

	remote.resetPosted()
	result, err := Run(context.Background(), options(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Completed || result.UploadedBatches != 2 {
		t.Fatalf("re-evaluated pass: %+v", result)
	}
	posted := remote.postedKeys()
	if len(posted) != 2 {
		t.Fatalf("the stale done batch must be retransmitted under the live revision: %v", posted)
	}
}

func TestMidRunWideningDriftStopsBeforeCompleting(t *testing.T) {
	remote, server := newRemote(t)
	cutoff := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	remote.from = &cutoff
	dir := fixture(t, server.URL, []json.RawMessage{record("old", "2025-01-01T00:00:00Z"), record("new", "2026-10-28T00:00:00Z")})
	// The server widens the consent scope right after this run's own
	// preflight: the first upload then succeeds under the NEWER scope
	// (no 409), while this run's keep/skip decisions were derived from
	// the old one. The pass must not complete on those stale decisions.
	remote.armWiden(1, 2, nil)

	result, err := Run(context.Background(), options(dir))
	if err == nil {
		t.Fatal("expected the mid-run scope drift to stop the pass")
	}
	if result.Completed || result.Stopped != "consent scope changed" {
		t.Fatalf("drift outcome: %+v", result)
	}
	if !strings.Contains(err.Error(), "consent revision 1 -> 2") {
		t.Fatalf("the stop must describe the drift: %v", err)
	}
	// The drifted upload itself stands (the server accepted it under the
	// live authorization), but the widened record stays withheld.
	if remote.postCount() != 1 || !remote.seen["new"] || remote.seen["old"] {
		t.Fatalf("the drifted upload must land while the widened record stays withheld: posts=%d seen=%v", remote.postCount(), remote.seen)
	}
	jb, exists, err := loadJob(dir)
	if err != nil || !exists || jb.CompletedAt != nil || jb.Scope == nil || jb.Scope.Revision != 1 {
		t.Fatalf("the job must stay incomplete under the planned baseline: %+v err=%v", jb, err)
	}

	remote.set(2, nil)
	second, err := Run(context.Background(), options(dir))
	if err == nil || second.Stopped != "consent scope changed" || remote.postCount() != 1 {
		t.Fatalf("the next run must re-plan under the live scope before uploading: %+v err=%v", second, err)
	}
	third, err := Run(context.Background(), options(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !third.Completed || !remote.seen["old"] {
		t.Fatalf("the re-planned pass must restore the widened record: %+v", third)
	}
}

func TestCompletionVerifiesFreshScopeAfterLastUpload(t *testing.T) {
	remote, server := newRemote(t)
	cutoff := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	remote.from = &cutoff
	dir := fixture(t, server.URL, []json.RawMessage{record("old", "2025-01-01T00:00:00Z"), record("new", "2026-10-28T00:00:00Z")})
	// The upload is authorized under the planning scope; the consent
	// scope widens only afterwards, before the completion write.
	remote.armWiden(2, 2, nil)

	result, err := Run(context.Background(), options(dir))
	if err == nil {
		t.Fatal("expected the completion gate to stop the pass")
	}
	if result.Completed || result.Stopped != "consent scope changed" {
		t.Fatalf("completion outcome: %+v", result)
	}
	if remote.postCount() != 1 || !remote.seen["new"] || remote.seen["old"] {
		t.Fatalf("the accepted upload must stand while the completion is withheld: posts=%d seen=%v", remote.postCount(), remote.seen)
	}
	jb, exists, err := loadJob(dir)
	if err != nil || !exists || jb.CompletedAt != nil {
		t.Fatalf("the job must not be marked complete on stale decisions: %+v err=%v", jb, err)
	}

	// The resume must refuse to finalize the all-done job under the
	// widened authorization: it re-plans instead.
	remote.set(2, nil)
	second, err := Run(context.Background(), options(dir))
	if err == nil || second.Stopped != "consent scope changed" || remote.postCount() != 1 {
		t.Fatalf("the resume must re-plan instead of finalizing: %+v err=%v", second, err)
	}
	third, err := Run(context.Background(), options(dir))
	if err != nil || !third.Completed || !remote.seen["old"] {
		t.Fatalf("the re-planned pass must restore the widened record: %+v err=%v", third, err)
	}
}
