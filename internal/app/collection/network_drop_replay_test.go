package collection

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/local/statedir"
)

// committedBatch is the fake server's durable record of one accepted upload.
// The connection drop loses only the response, never the commit.
type committedBatch struct {
	BatchID         string
	Status          string
	AcceptedRecords int
	RejectedRecords int
	ReceivedAt      string
	Body            []byte
}

// dropAfterCommitServer models the P2 high-risk fault on top of the existing
// fake ingest contract (the same endpoints and receipt shapes as
// fakeCollectorServer, plus the record-level dedupe semantics the connect
// tests already exercise server-side):
//
//   - GET /v1/devices/self answers the standard bound-device snapshot (old
//     protocol, consent revision 7, unrestricted scope).
//   - The FIRST POST /v1/ingest/batches carrying a batch id is read to the
//     last byte and durably committed — the record counter sees it exactly
//     once — and then the connection is hijacked and closed WITHOUT writing
//     any response byte. The collector observes a bare transport failure
//     after the server has already committed.
//   - A re-POST of a known batch id must be byte-identical; the server then
//     answers HTTP 202 with the stored receipt and replay=true and does NOT
//     count the records again — the real server's idempotent-receipt
//     contract for identical (batch id, bytes) re-sends.
//   - POST /v1/devices/tool-status records the statuses[] entries.
//
// The collector implements no in-run retry, so every drop surfaces as an
// error to that run; only a later run re-sends.
type dropAfterCommitServer struct {
	*httptest.Server
	t *testing.T

	self    atomic.Int64
	ingest  atomic.Int64
	tooling atomic.Int64

	mu               sync.Mutex
	committed        map[string]committedBatch
	committedRecords int
	dropped          int
	replayCount      int
	posts            [][]byte
	reports          []toolStatusReport
}

func newDropAfterCommitServer(t *testing.T) *dropAfterCommitServer {
	t.Helper()
	s := &dropAfterCommitServer{t: t, committed: map[string]committedBatch{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.Server.Close)
	return s
}

func (s *dropAfterCommitServer) selfRequests() int64       { return s.self.Load() }
func (s *dropAfterCommitServer) ingestRequests() int64     { return s.ingest.Load() }
func (s *dropAfterCommitServer) toolStatusRequests() int64 { return s.tooling.Load() }

// committedRecordCount reports how many records the server has durably
// counted. A correct replay never increases it.
func (s *dropAfterCommitServer) committedRecordCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.committedRecords
}

// droppedCommits reports how many committed uploads lost their response.
func (s *dropAfterCommitServer) droppedCommits() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

// replaysServed reports how many re-sends were answered from storage.
func (s *dropAfterCommitServer) replaysServed() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.replayCount
}

// ingestBodies returns every received ingest body in arrival order.
func (s *dropAfterCommitServer) ingestBodies() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, len(s.posts))
	copy(out, s.posts)
	return out
}

// toolStatusReports returns every recorded statuses[] entry in order.
func (s *dropAfterCommitServer) toolStatusReports() []toolStatusReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]toolStatusReport, len(s.reports))
	copy(out, s.reports)
	return out
}

func (s *dropAfterCommitServer) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self":
		s.self.Add(1)
		writeJSONForTest(w, http.StatusOK, map[string]any{"device": map[string]any{
			"deviceId":          "dev-1",
			"applicationId":     "app-1",
			"externalSubjectId": "sub-1",
			"deviceName":        "collector",
			"platform":          "darwin",
			"consentRevision":   7,
			"uploadAuthorized":  true,
			"publicAuthorized":  false,
			"revoked":           false,
			"checkedAt":         "2026-10-21T04:00:00Z",
		}})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/batches":
		s.ingest.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			s.t.Errorf("read ingest body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var batch struct {
			BatchID string           `json:"batchId"`
			Records []map[string]any `json:"records"`
		}
		if err := json.Unmarshal(body, &batch); err != nil {
			s.t.Errorf("invalid ingest body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.posts = append(s.posts, append([]byte(nil), body...))
		stored, seen := s.committed[batch.BatchID]
		if !seen {
			stored = committedBatch{
				BatchID:         batch.BatchID,
				Status:          "accepted",
				AcceptedRecords: len(batch.Records),
				RejectedRecords: 0,
				ReceivedAt:      "2026-10-21T04:01:00Z",
				Body:            append([]byte(nil), body...),
			}
			s.committed[batch.BatchID] = stored
			s.committedRecords += len(batch.Records)
			s.dropped++
			s.mu.Unlock()
			// The fault under test: the batch is durably committed and the
			// connection dies before any response byte is written. Hijack
			// and close so the client sees a bare transport failure.
			hj, ok := w.(http.Hijacker)
			if !ok {
				s.t.Errorf("server does not support hijacking")
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				s.t.Errorf("hijack connection: %v", err)
				return
			}
			_ = conn.Close()
			return
		}
		s.mu.Unlock()
		// Idempotent receipt: same batch id must arrive with the same bytes;
		// the stored receipt is replayed and the records are NOT counted again.
		if !bytes.Equal(stored.Body, body) {
			s.t.Errorf("re-send of batch %s must be byte-identical to the committed upload", batch.BatchID)
		}
		s.mu.Lock()
		s.replayCount++
		s.mu.Unlock()
		writeJSONForTest(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId":         stored.BatchID,
			"status":          stored.Status,
			"acceptedRecords": stored.AcceptedRecords,
			"rejectedRecords": stored.RejectedRecords,
			"replay":          true,
			"receivedAt":      stored.ReceivedAt,
		}})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/devices/tool-status":
		s.tooling.Add(1)
		var body struct {
			Statuses []toolStatusReport `json:"statuses"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			s.t.Errorf("invalid tool-status body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.reports = append(s.reports, body.Statuses...)
		s.mu.Unlock()
		writeJSONForTest(w, http.StatusAccepted, map[string]any{"accepted": true})
	default:
		s.t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

// TestNetworkDropAfterServerCommitReplayIsIdempotent covers the P2
// high-risk fault: the server durably commits the device's first batch and
// the connection then dies before any response byte reaches the collector.
//
// Expected end-to-end behavior through the REAL collection/syncclient
// wiring (no stubbed sync layer, no product retry):
//
//  1. Run 1 exports the observations locally, the drain's single upload is
//     committed server-side and then dropped. The run fails with a
//     transport error; the batch stays pending with durable attempt
//     accounting; the cursor watermark is advanced but NOT confirmed; the
//     per-message intervals stay frozen pending; no receipt, no ACK
//     journal, and exactly one ingest POST left the device (no in-run
//     retry).
//  2. Run 2 — from the state directory's point of view a fresh client
//     process — re-exports nothing (frozen messages) and re-sends the SAME
//     batch id with byte-identical content. The server answers from
//     storage (replay=true) without counting the records twice, the local
//     outbox/ACK/watermark state converges, and the batch file itself is
//     untouched.
//  3. Run 3 over the settled state uploads nothing: the server's record
//     counter never exceeded the two committed records.
//
// All state lives in t.TempDir and every endpoint is an httptest server;
// no real device state or user data is read.
func TestNetworkDropAfterServerCommitReplayIsIdempotent(t *testing.T) {
	stateDir := t.TempDir()
	server := newDropAfterCommitServer(t)
	bindDevice(t, stateDir, server.URL)

	sessions := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, sessions, "session-drop.jsonl",
		claudeLine(t, "2026-10-21T05:00:00Z", "s-drop", "msg_1", claudeUsage(15, 2, 0, 8)),
		claudeLine(t, "2026-10-21T05:01:00Z", "s-drop", "msg_2", claudeUsage(10, 0, 0, 5)))
	enableGrant(t, stateDir, "claude-code-jsonl", sessions)

	// ------------------------------------------------------------------
	// Run 1: server commits the first batch, then drops the connection.
	// ------------------------------------------------------------------
	res1, err1 := Run(t.Context(), Options{
		StateDir:  stateDir,
		ServerURL: server.URL,
		Now: func() time.Time {
			return time.Date(2026, 10, 21, 5, 2, 0, 0, time.UTC)
		},
	})
	if err1 == nil {
		t.Fatal("expected the run to fail when the server drops the connection after committing the batch")
	}
	if !errors.Is(err1, io.EOF) && !strings.Contains(err1.Error(), "EOF") {
		t.Fatalf("expected an EOF-style transport failure from the dropped connection, got %v", err1)
	}
	if res1.ExportedBatches != 1 || res1.ExportedRecords != 2 {
		t.Fatalf("expected the local export of one 2-record batch before the network failure, got %#v", res1)
	}
	if res1.SyncedBatches != 0 || res1.SyncedRecords != 0 {
		t.Fatalf("nothing may count as synced when no receipt arrived, got %#v", res1)
	}
	if res1.PendingRemaining != 1 || !strings.Contains(res1.DrainStopped, "upload of batch") {
		t.Fatalf("expected the drain to stop on the failed upload with one pending batch, got %#v", res1)
	}
	// No in-run retry: exactly one ingest POST left the device, and the
	// server committed (then dropped) exactly that one upload.
	if got := server.ingestRequests(); got != 1 {
		t.Fatalf("the dropped upload must not be retried within the same run, got %d ingest POSTs", got)
	}
	if got := server.droppedCommits(); got != 1 {
		t.Fatalf("expected exactly one commit-then-drop, got %d", got)
	}
	if got := server.committedRecordCount(); got != 2 {
		t.Fatalf("server must have committed the 2 records exactly once, got %d", got)
	}
	if got := server.selfRequests(); got != 2 {
		t.Fatalf("run 1 must only perform the grant-sync and drain preflights, got %d self requests", got)
	}
	if got := server.toolStatusRequests(); got != 0 {
		t.Fatalf("a run without any receipt must not report tool status, got %d tool-status POSTs", got)
	}

	// Local pending state: the batch stays pending with no receipt, but the
	// durable attempt accounting survived the dropped response.
	ledger := outbox.New(stateDir)
	ob, err := ledger.Load()
	if err != nil {
		t.Fatalf("load outbox: %v", err)
	}
	if len(ob.Batches) != 1 {
		t.Fatalf("expected exactly one batch in the outbox, got %d", len(ob.Batches))
	}
	pending := ob.Batches[0]
	if pending.Status != outbox.StatusPending {
		t.Fatalf("expected the batch to stay pending, got %s", pending.Status)
	}
	if pending.ReceiptStatus != "" || !pending.SyncedAt.IsZero() || pending.AcceptedRecords != 0 || pending.RejectedRecords != 0 {
		t.Fatalf("no receipt may be recorded without a response: %#v", pending)
	}
	if pending.LastAttemptAt.IsZero() {
		t.Fatalf("durable attempt accounting must survive the dropped response: %#v", pending)
	}
	batchID := pending.BatchID
	batchFile := pending.File
	batchFileBytes, err := os.ReadFile(batchFile)
	if err != nil {
		t.Fatalf("read batch file: %v", err)
	}

	// Watermark: the cursor advanced to the batch but is NOT confirmed.
	cursors := progress.New(stateDir)
	cur, err := cursors.Load()
	if err != nil {
		t.Fatalf("load progress: %v", err)
	}
	if len(cur.Cursors) != 1 || cur.Cursors[0].BatchID != batchID ||
		cur.Cursors[0].ConfirmedBatchID != "" || cur.Cursors[0].ConfirmedAt != nil {
		t.Fatalf("expected the cursor advanced but unconfirmed after the drop: %#v", cur.Cursors)
	}

	// Per-message intervals stay frozen pending under the dropped batch.
	msgs, _, err := cursors.MessageProgressFor("claude-code-jsonl")
	if err != nil {
		t.Fatalf("load message progress: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected two frozen messages, got %d: %#v", len(msgs), msgs)
	}
	for id, m := range msgs {
		if m.Pending == nil || m.Pending.BatchID != batchID || m.Confirmed != nil || m.RejectedKey != "" {
			t.Fatalf("message %s must stay frozen pending without confirmation: %#v", id, m)
		}
	}

	// Device state carries no receipt and no half-applied ACK journal.
	st, err := statedir.New(stateDir).Load()
	if err != nil {
		t.Fatalf("load device state: %v", err)
	}
	if st.LastSyncBatchID != "" || !st.LastSyncedAt.IsZero() {
		t.Fatalf("expected no sync receipt in device state, got %#v", st)
	}
	if _, statErr := os.Stat(filepath.Join(stateDir, "sync-ack-transaction.json")); !os.IsNotExist(statErr) {
		t.Fatalf("no ACK journal may exist before any receipt arrived, stat err=%v", statErr)
	}

	// ------------------------------------------------------------------
	// Run 2: the next run (a fresh client from the state's perspective)
	// re-sends the same batch id with byte-identical content and the
	// server replays its stored receipt without double counting.
	// ------------------------------------------------------------------
	res2, err2 := Run(t.Context(), Options{
		StateDir:  stateDir,
		ServerURL: server.URL,
		Now: func() time.Time {
			return time.Date(2026, 10, 21, 5, 5, 0, 0, time.UTC)
		},
	})
	if err2 != nil {
		t.Fatalf("expected the replay run to succeed, got %v", err2)
	}
	if res2.ExportedBatches != 0 {
		t.Fatalf("the unchanged input must not re-export while messages stay frozen, got %d exported batches", res2.ExportedBatches)
	}
	if res2.SyncedBatches != 1 || res2.SyncedRecords != 2 || res2.PendingRemaining != 0 || res2.DrainStopped != "" {
		t.Fatalf("expected the replayed batch to drain cleanly, got %#v", res2)
	}

	// Wire-level identity: exactly one more POST, same batch id, same bytes.
	bodies := server.ingestBodies()
	if len(bodies) != 2 {
		t.Fatalf("expected exactly two ingest uploads (drop + replay), got %d", len(bodies))
	}
	if !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatalf("the resend must be byte-identical to the dropped upload:\nfirst:  %s\nsecond: %s", bodies[0], bodies[1])
	}
	var posted struct {
		BatchID string `json:"batchId"`
	}
	if err := json.Unmarshal(bodies[1], &posted); err != nil {
		t.Fatalf("decode replayed upload: %v", err)
	}
	if posted.BatchID != batchID {
		t.Fatalf("the resend must reuse the same batch id %q, got %q", batchID, posted.BatchID)
	}
	if got := server.ingestRequests(); got != 2 {
		t.Fatalf("expected exactly two ingest POSTs total, got %d", got)
	}
	if got := server.replaysServed(); got != 1 {
		t.Fatalf("expected exactly one replayed receipt from storage, got %d", got)
	}
	// The server counted each record exactly once despite two uploads.
	if got := server.committedRecordCount(); got != 2 {
		t.Fatalf("the replay receipt must not double count: committed records = %d, want 2", got)
	}
	// The batch file itself is untouched by the resend.
	freshBytes, err := os.ReadFile(batchFile)
	if err != nil {
		t.Fatalf("re-read batch file: %v", err)
	}
	if !bytes.Equal(batchFileBytes, freshBytes) {
		t.Fatal("the batch file must stay byte-identical across the drop and the replay")
	}

	// Local state after the replay receipt: outbox settled with the receipt.
	ob2, err := ledger.Load()
	if err != nil {
		t.Fatalf("load outbox after replay: %v", err)
	}
	if len(ob2.Batches) != 1 {
		t.Fatalf("expected exactly one batch in the outbox, got %d", len(ob2.Batches))
	}
	synced := ob2.Batches[0]
	if synced.Status != outbox.StatusSynced || synced.ReceiptStatus != "accepted" ||
		synced.AcceptedRecords != 2 || synced.RejectedRecords != 0 || synced.SyncedAt.IsZero() {
		t.Fatalf("expected the replayed batch settled as synced/accepted 2-0, got %#v", synced)
	}

	// Watermark: the cursor is confirmed for the batch.
	cur2, err := cursors.Load()
	if err != nil {
		t.Fatalf("load progress after replay: %v", err)
	}
	if len(cur2.Cursors) != 1 {
		t.Fatalf("expected one cursor, got %#v", cur2.Cursors)
	}
	confirmed := cur2.Cursors[0]
	if confirmed.ConfirmedBatchID != batchID || confirmed.ConfirmedStatus != "accepted" ||
		confirmed.ConfirmedRecordCount != 2 || confirmed.ConfirmedAt == nil {
		t.Fatalf("expected the cursor confirmed for the replayed batch, got %#v", confirmed)
	}

	// Per-message baselines advanced to their pending to-states exactly once.
	msgs2, _, err := cursors.MessageProgressFor("claude-code-jsonl")
	if err != nil {
		t.Fatalf("load message progress after replay: %v", err)
	}
	if len(msgs2) != 2 {
		t.Fatalf("expected two messages, got %d: %#v", len(msgs2), msgs2)
	}
	for id, m := range msgs2 {
		if m.Pending != nil || m.Confirmed == nil || m.RejectedKey != "" {
			t.Fatalf("message %s must be confirmed and unfrozen after the replay receipt: %#v", id, m)
		}
	}
	if m := msgs2["msg_1"]; m.Confirmed == nil || m.Confirmed.Input == nil || *m.Confirmed.Input != 15 || m.Confirmed.Output == nil || *m.Confirmed.Output != 8 {
		t.Fatalf("msg_1 must adopt its pending to-state (input 15, output 8), got %#v", m.Confirmed)
	}
	if m := msgs2["msg_2"]; m.Confirmed == nil || m.Confirmed.Input == nil || *m.Confirmed.Input != 10 || m.Confirmed.Output == nil || *m.Confirmed.Output != 5 {
		t.Fatalf("msg_2 must adopt its pending to-state (input 10, output 5), got %#v", m.Confirmed)
	}

	// Device state carries the replayed receipt.
	st2, err := statedir.New(stateDir).Load()
	if err != nil {
		t.Fatalf("load device state after replay: %v", err)
	}
	if st2.LastSyncBatchID != batchID || st2.LastSyncStatus != "accepted" ||
		st2.LastSyncAcceptedRecords != 2 || st2.LastSyncRejectedRecords != 0 || st2.LastSyncedAt.IsZero() {
		t.Fatalf("expected the replayed receipt in device state, got %#v", st2)
	}
	// The ACK transaction was fully applied and removed.
	if _, statErr := os.Stat(filepath.Join(stateDir, "sync-ack-transaction.json")); !os.IsNotExist(statErr) {
		t.Fatalf("no ACK journal may remain after the replay receipt, stat err=%v", statErr)
	}

	// The replay run reports exactly one synced tool receipt.
	if got := server.toolStatusRequests(); got != 1 {
		t.Fatalf("expected exactly one tool-status POST in the replay run, got %d", got)
	}
	if reports := server.toolStatusReports(); len(reports) != 1 ||
		reports[0] != (toolStatusReport{Tool: "Claude Code", Status: "synced"}) {
		t.Fatalf("expected a single Claude Code synced receipt, got %#v", reports)
	}
	if got := server.selfRequests(); got != 5 { // run 1: 2; run 2: grant-sync + drain + receipt preflights
		t.Fatalf("unexpected self request count after the replay run, got %d", got)
	}

	// ------------------------------------------------------------------
	// Run 3: the settled state uploads nothing — no duplicate counting
	// loop, the outbox never re-sends a synced batch.
	// ------------------------------------------------------------------
	res3, err3 := Run(t.Context(), Options{
		StateDir:  stateDir,
		ServerURL: server.URL,
		Now: func() time.Time {
			return time.Date(2026, 10, 21, 5, 8, 0, 0, time.UTC)
		},
	})
	if err3 != nil {
		t.Fatalf("expected the settled run to succeed, got %v", err3)
	}
	if res3.SyncedBatches != 0 || res3.PendingRemaining != 0 || res3.ExportedBatches != 0 {
		t.Fatalf("expected a fully settled no-op run, got %#v", res3)
	}
	if got := server.ingestRequests(); got != 2 {
		t.Fatalf("a settled batch must never be re-uploaded, got %d ingest POSTs", got)
	}
	if got := server.committedRecordCount(); got != 2 {
		t.Fatalf("the server must still hold exactly the 2 committed records, got %d", got)
	}
	if got := server.replaysServed(); got != 1 {
		t.Fatalf("no additional replay may be served after the state settled, got %d", got)
	}
}
