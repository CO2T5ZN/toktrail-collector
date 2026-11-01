package syncclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/local/statedir"
)

func TestRunSyncReplaceExistingRequiresExplicitOption(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(fmt.Sprintf("replace=%t", replace), func(t *testing.T) {
			store := statedir.New(t.TempDir())
			if err := store.Save(statedir.DeviceState{DeviceID: "dev-1", DeviceSecret: strings.Repeat("b", 64)}); err != nil {
				t.Fatal(err)
			}
			file := writeBatchFile(t, map[string]any{
				"batchId": "replace-test", "replaceExisting": true,
				"records": []map[string]any{{"recordKey": "record-1", "kind": "delta", "occurredAt": "2026-10-20T10:00:00Z", "tool": "Codex", "model": "unknown", "input": "10", "cacheRead": "0", "cacheWrite": "0", "output": "5", "adapterVersion": "test", "sourceType": "codex-jsonl"}},
			})
			var posted atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if serveSelf(t, w, r, 7) {
					return
				}
				var body map[string]json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				var got bool
				if value, exists := body["replaceExisting"]; exists {
					if err := json.Unmarshal(value, &got); err != nil {
						t.Fatal(err)
					}
				}
				if got != replace {
					t.Errorf("replaceExisting = %t, want %t", got, replace)
				}
				posted.Store(true)
				writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{"batchId": "replace-test", "status": "accepted", "acceptedRecords": 1, "rejectedRecords": 0, "replay": false, "receivedAt": "2026-10-20T10:12:00Z"}})
			}))
			defer server.Close()
			if _, err := Run(t.Context(), store, Options{ServerURL: server.URL, BatchFile: file, ReplaceExisting: replace}); err != nil {
				t.Fatal(err)
			}
			if !posted.Load() {
				t.Fatal("batch was not uploaded")
			}
		})
	}
}

func TestRunSyncUploadsBatchAndPersistsReceipt(t *testing.T) {
	secret := strings.Repeat("b", 64)
	store := statedir.New(t.TempDir())
	if err := store.Save(statedir.DeviceState{ServerURL: "http://unused", DeviceID: "dev-1", DeviceSecret: secret}); err != nil {
		t.Fatal(err)
	}
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": "batch-1",
		"records": []map[string]any{{
			"recordKey":      "record-1",
			"groupKey":       nil,
			"resetKey":       nil,
			"kind":           "delta",
			"occurredAt":     "2026-10-20T10:00:00Z",
			"tool":           "claude-code",
			"model":          nil,
			"input":          "10",
			"cacheRead":      nil,
			"cacheWrite":     "0",
			"output":         "5",
			"adapterVersion": "test-adapter-1",
			"sourceType":     "fixture",
		}},
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelf(t, w, r, 7) {
			return
		}
		if r.URL.Path != "/v1/ingest/batches" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer dev-1."+secret {
			t.Fatalf("unexpected auth header %q", got)
		}
		if got := r.Header.Get("X-Consent-Revision"); got != "7" {
			t.Fatalf("unexpected X-Consent-Revision header %q", got)
		}
		var got BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.BatchID != "batch-1" || len(got.Records) != 1 {
			t.Fatalf("unexpected batch: %#v", got)
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId":         got.BatchID,
			"status":          "accepted",
			"acceptedRecords": 1,
			"rejectedRecords": 0,
			"replay":          false,
			"receivedAt":      "2026-10-20T10:12:00Z",
		}})
	}))
	defer server.Close()
	res, err := Run(t.Context(), store, Options{ServerURL: server.URL, BatchFile: batchFile})
	if err != nil {
		t.Fatal(err)
	}
	if res.Receipt.BatchID != "batch-1" || res.Receipt.Status != "accepted" || res.Status != http.StatusAccepted {
		t.Fatalf("unexpected result: %#v", res)
	}
	saved, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if saved.LastSyncBatchID != "batch-1" || saved.LastSyncStatus != "accepted" || saved.LastSyncAcceptedRecords != 1 || saved.LastSyncRejectedRecords != 0 || saved.LastSyncedAt.IsZero() {
		t.Fatalf("sync receipt was not persisted: %#v", saved)
	}
	stateBytes, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(stateBytes), `"lastSyncRejectedRecords": 0`) {
		t.Fatalf("expected explicit zero rejected record count in state JSON: %s", string(stateBytes))
	}
}

func TestRunSyncUsesPendingOutboxWhenBatchFileOmitted(t *testing.T) {
	secret := strings.Repeat("d", 64)
	stateDir := t.TempDir()
	store := statedir.New(stateDir)
	if err := store.Save(statedir.DeviceState{ServerURL: "http://unused", DeviceID: "dev-1", DeviceSecret: secret}); err != nil {
		t.Fatal(err)
	}
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": "batch-outbox-1",
		"records": []map[string]any{{
			"recordKey":      "record-1",
			"kind":           "delta",
			"occurredAt":     "2026-10-20T10:00:00Z",
			"tool":           "usage-json",
			"input":          "10",
			"cacheRead":      "0",
			"cacheWrite":     "0",
			"output":         "5",
			"adapterVersion": "test-adapter-1",
			"sourceType":     "fixture",
		}},
	})
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{BatchID: "batch-outbox-1", File: batchFile, Source: "usage-json", Input: batchFile, RecordCount: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := progress.New(stateDir).Advance(progress.AdvanceOptions{Source: "usage-json", Input: batchFile, BatchID: "batch-outbox-1", RecordCount: 1}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelf(t, w, r, 3) {
			return
		}
		var got BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.BatchID != "batch-outbox-1" || len(got.Records) != 1 {
			t.Fatalf("unexpected batch from outbox: %#v", got)
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId":         got.BatchID,
			"status":          "accepted",
			"acceptedRecords": 1,
			"rejectedRecords": 0,
			"replay":          false,
			"receivedAt":      "2026-10-20T10:12:00Z",
		}})
	}))
	defer server.Close()
	if _, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir}); err != nil {
		t.Fatal(err)
	}
	_, ok, err := outbox.New(stateDir).NextPending()
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected outbox batch to be marked synced")
	}
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Batches) != 1 || out.Batches[0].Status != outbox.StatusSynced || out.Batches[0].ReceiptStatus != "accepted" || out.Batches[0].AcceptedRecords != 1 {
		t.Fatalf("unexpected outbox after sync: %#v", out)
	}
	cursors, err := progress.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cursors.Cursors) != 1 || cursors.Cursors[0].ConfirmedBatchID != "batch-outbox-1" || cursors.Cursors[0].ConfirmedStatus != "accepted" || cursors.Cursors[0].ConfirmedAt == nil {
		t.Fatalf("expected cursor to be confirmed after ACK: %#v", cursors)
	}
}

func TestRunSyncACKJournalRecoversCursorConfirmFailure(t *testing.T) {
	secret := strings.Repeat("e", 64)
	stateDir := t.TempDir()
	store := statedir.New(stateDir)
	if err := store.Save(statedir.DeviceState{ServerURL: "http://unused", DeviceID: "dev-1", DeviceSecret: secret}); err != nil {
		t.Fatal(err)
	}
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": "batch-outbox-recover-1",
		"records": []map[string]any{{
			"recordKey":      "record-1",
			"kind":           "delta",
			"occurredAt":     "2026-10-20T10:00:00Z",
			"tool":           "usage-json",
			"input":          "10",
			"cacheRead":      "0",
			"cacheWrite":     "0",
			"output":         "5",
			"adapterVersion": "test-adapter-1",
			"sourceType":     "fixture",
		}},
	})
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{BatchID: "batch-outbox-recover-1", File: batchFile, Source: "usage-json", Input: batchFile, RecordCount: 1}); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(progress.New(stateDir).Path(), 0o700); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelf(t, w, r, 2) {
			return
		}
		var got BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId":         got.BatchID,
			"status":          "accepted",
			"acceptedRecords": 1,
			"rejectedRecords": 0,
			"replay":          false,
			"receivedAt":      "2026-10-20T10:12:00Z",
		}})
	}))
	defer server.Close()
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err == nil {
		t.Fatal("expected cursor confirm failure")
	}
	if _, statErr := os.Stat(syncACKJournalPath(stateDir)); statErr != nil {
		t.Fatalf("expected pending ACK journal: %v", statErr)
	}
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Batches) != 1 || out.Batches[0].Status != outbox.StatusSynced {
		t.Fatalf("expected outbox applied before cursor failure: %#v", out)
	}
	if err := os.Remove(progress.New(stateDir).Path()); err != nil {
		t.Fatal(err)
	}
	if err := recoverPendingSyncACK(store, stateDir); err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(syncACKJournalPath(stateDir)); !os.IsNotExist(statErr) {
		t.Fatalf("expected journal removed after recovery, stat err=%v", statErr)
	}
	cursors, err := progress.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cursors.Cursors) != 1 || cursors.Cursors[0].ConfirmedBatchID != "batch-outbox-recover-1" || cursors.Cursors[0].ConfirmedAt == nil {
		t.Fatalf("expected cursor recovered from ACK journal: %#v", cursors)
	}
}

func TestRunSyncMarkAttemptFailurePreventsSend(t *testing.T) {
	secret := strings.Repeat("f", 64)
	stateDir := t.TempDir()
	store := statedir.New(stateDir)
	if err := store.Save(statedir.DeviceState{ServerURL: "http://unused", DeviceID: "dev-1", DeviceSecret: secret}); err != nil {
		t.Fatal(err)
	}
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": "batch-outbox-attempt-1",
		"records": []map[string]any{{
			"recordKey":      "record-1",
			"kind":           "delta",
			"occurredAt":     "2026-10-20T10:00:00Z",
			"tool":           "usage-json",
			"input":          "10",
			"cacheRead":      "0",
			"cacheWrite":     "0",
			"output":         "5",
			"adapterVersion": "test-adapter-1",
			"sourceType":     "fixture",
		}},
	})
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{BatchID: "batch-outbox-attempt-1", File: batchFile, Source: "usage-json", Input: batchFile, RecordCount: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := progress.New(stateDir).Advance(progress.AdvanceOptions{Source: "usage-json", Input: batchFile, BatchID: "batch-outbox-attempt-1", RecordCount: 1}); err != nil {
		t.Fatal(err)
	}
	var gets, posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelf(t, w, r, 4) {
			gets.Add(1)
			return
		}
		posts.Add(1)
		var got BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId":         got.BatchID,
			"status":          "accepted",
			"acceptedRecords": 1,
			"rejectedRecords": 0,
			"replay":          false,
			"receivedAt":      "2026-10-20T10:12:00Z",
		}})
	}))
	defer server.Close()

	// Failure injection: occupy the outbox temp-file path so MarkAttempt cannot
	// persist durable retry accounting, while reads (NextPending, loadBatch)
	// still succeed. This isolates the attempt write failure.
	blocker := outbox.New(stateDir).Path() + ".tmp"
	if err := os.Mkdir(blocker, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err == nil {
		t.Fatal("expected sync to fail when outbox attempt cannot be persisted")
	}
	if !strings.Contains(err.Error(), "outbox.json.tmp") {
		t.Fatalf("expected failure from outbox attempt persistence, got: %v", err)
	}
	if got := posts.Load() + gets.Load(); got != 0 {
		t.Fatalf("expected no HTTP traffic when attempt accounting cannot be written, got %d request(s)", got)
	}
	out, loadErr := outbox.New(stateDir).Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(out.Batches) != 1 || out.Batches[0].Status != outbox.StatusPending {
		t.Fatalf("expected outbox batch to remain pending: %#v", out)
	}
	if !out.Batches[0].LastAttemptAt.IsZero() {
		t.Fatalf("expected no attempt timestamp recorded: %#v", out.Batches[0])
	}
	if _, statErr := os.Stat(syncACKJournalPath(stateDir)); !os.IsNotExist(statErr) {
		t.Fatalf("expected no ACK journal, stat err=%v", statErr)
	}
	saved, loadErr := store.Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if saved.LastSyncBatchID != "" || !saved.LastSyncedAt.IsZero() {
		t.Fatalf("expected device state untouched by failed attempt: %#v", saved)
	}

	// Recovery: once the attempt write succeeds again, the same pending batch
	// syncs exactly once — one self preflight GET and exactly one ingest POST
	// per run — and the ACK commit stays atomic.
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir}); err != nil {
		t.Fatal(err)
	}
	if got := posts.Load(); got != 1 {
		t.Fatalf("expected exactly one ingest POST after recovery, got %d", got)
	}
	if got := gets.Load(); got != 1 {
		t.Fatalf("expected exactly one self preflight GET after recovery, got %d", got)
	}
	out, loadErr = outbox.New(stateDir).Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(out.Batches) != 1 || out.Batches[0].Status != outbox.StatusSynced || out.Batches[0].ReceiptStatus != "accepted" || out.Batches[0].LastAttemptAt.IsZero() {
		t.Fatalf("expected outbox batch synced after recovery: %#v", out)
	}
	cursors, loadErr := progress.New(stateDir).Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(cursors.Cursors) != 1 || cursors.Cursors[0].ConfirmedBatchID != "batch-outbox-attempt-1" || cursors.Cursors[0].ConfirmedAt == nil {
		t.Fatalf("expected cursor confirmed after recovery: %#v", cursors)
	}
}

func TestRunSyncRequiresBoundDevice(t *testing.T) {
	batchFile := writeBatchFile(t, map[string]any{"batchId": "batch-1", "records": []map[string]any{{"recordKey": "r"}}})
	_, err := Run(t.Context(), statedir.New(t.TempDir()), Options{BatchFile: batchFile})
	if err == nil {
		t.Fatal("expected unbound error")
	}
}

func TestRunSyncRequiresBatchFile(t *testing.T) {
	store := statedir.New(t.TempDir())
	if err := store.Save(statedir.DeviceState{DeviceID: "dev-1", DeviceSecret: strings.Repeat("c", 64)}); err != nil {
		t.Fatal(err)
	}
	_, err := Run(t.Context(), store, Options{})
	if err == nil {
		t.Fatal("expected missing batch file error")
	}
}

// serveSelf handles the per-sync device self preflight (GET /v1/devices/self)
// and reports whether it answered the request. revision versions the snapshot
// that the collector must echo as X-Consent-Revision on the ingest POST.
func serveSelf(t *testing.T, w http.ResponseWriter, r *http.Request, revision int64) bool {
	t.Helper()
	if r.Method != http.MethodGet || r.URL.Path != "/v1/devices/self" {
		return false
	}
	if got := r.Header.Get("Authorization"); got == "" {
		t.Errorf("self preflight missing Authorization header")
	}
	writeJSON(w, http.StatusOK, map[string]any{"device": map[string]any{
		"deviceId":          "dev-1",
		"applicationId":     "app-1",
		"externalSubjectId": "sub-1",
		"deviceName":        "collector",
		"platform":          "darwin",
		"consentRevision":   revision,
		"uploadAuthorized":  true,
		"publicAuthorized":  false,
		"revoked":           false,
		"checkedAt":         "2026-10-21T04:00:00Z",
	}})
	return true
}

// setupBoundState returns a state directory with a bound device.
func setupBoundState(t *testing.T) (string, statedir.Store, string) {
	t.Helper()
	secret := strings.Repeat("a", 64)
	stateDir := t.TempDir()
	store := statedir.New(stateDir)
	if err := store.Save(statedir.DeviceState{ServerURL: "http://unused", DeviceID: "dev-1", DeviceSecret: secret}); err != nil {
		t.Fatal(err)
	}
	return stateDir, store, secret
}

func TestRunSyncPreflightStopsOnRevokedDevice(t *testing.T) {
	stateDir, store, secret := setupBoundState(t)
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": "batch-revoked-1",
		"records": []map[string]any{{
			"recordKey":      "record-1",
			"kind":           "delta",
			"occurredAt":     "2026-10-20T10:00:00Z",
			"tool":           "usage-json",
			"input":          "10",
			"cacheRead":      "0",
			"cacheWrite":     "0",
			"output":         "5",
			"adapterVersion": "test-adapter-1",
			"sourceType":     "fixture",
		}},
	})
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{BatchID: "batch-revoked-1", File: batchFile, Source: "usage-json", Input: batchFile, RecordCount: 1}); err != nil {
		t.Fatal(err)
	}
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			if got := r.Header.Get("Authorization"); got != "Bearer dev-1."+secret {
				t.Errorf("unexpected self auth header %q", got)
			}
			writeJSON(w, http.StatusOK, map[string]any{"device": map[string]any{
				"deviceId":         "dev-1",
				"consentRevision":  5,
				"uploadAuthorized": false,
				"revoked":          true,
			}})
			return
		}
		posts.Add(1)
		writeJSON(w, http.StatusAccepted, map[string]any{})
	}))
	defer server.Close()
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("expected ErrDeviceRevoked, got %v", err)
	}
	if !strings.Contains(err.Error(), "never re-binds") {
		t.Fatalf("expected no-auto-rebind diagnosis, got %v", err)
	}
	if got := posts.Load(); got != 0 {
		t.Fatalf("expected zero ingest POSTs for revoked device, got %d", got)
	}
	// MarkAttempt ran before any HTTP: the attempt stays durable even though
	// the preflight stopped the upload.
	out, loadErr := outbox.New(stateDir).Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(out.Batches) != 1 || out.Batches[0].Status != outbox.StatusPending || out.Batches[0].LastAttemptAt.IsZero() {
		t.Fatalf("expected outbox batch pending with attempt recorded before preflight: %#v", out)
	}
	saved, loadErr := store.Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if saved.LastSyncBatchID != "" || !saved.LastSyncedAt.IsZero() {
		t.Fatalf("expected device state untouched: %#v", saved)
	}
}

func TestRunSyncPreflightStopsOnSubjectDeleted(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": "batch-subject-deleted-1",
		"records": []map[string]any{{
			"recordKey":      "record-1",
			"kind":           "delta",
			"occurredAt":     "2026-10-20T10:00:00Z",
			"tool":           "usage-json",
			"input":          "10",
			"cacheRead":      "0",
			"cacheWrite":     "0",
			"output":         "5",
			"adapterVersion": "test-adapter-1",
			"sourceType":     "fixture",
		}},
	})
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{BatchID: "batch-subject-deleted-1", File: batchFile, Source: "usage-json", Input: batchFile, RecordCount: 1}); err != nil {
		t.Fatal(err)
	}
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]any{
				"code":    "subject_deleted",
				"message": "subject identity is deleted",
			}})
			return
		}
		posts.Add(1)
		writeJSON(w, http.StatusAccepted, map[string]any{})
	}))
	defer server.Close()
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if !errors.Is(err, ErrSubjectDeleted) {
		t.Fatalf("expected ErrSubjectDeleted, got %v", err)
	}
	if got := posts.Load(); got != 0 {
		t.Fatalf("expected zero ingest POSTs for deleted subject, got %d", got)
	}
}

func TestRunSyncScopeChangedReorganizesUnderLiveScopeAndRecoveryPostsOnce(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	const source = "usage-json"
	const batchID = "batch-scope-1"
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": batchID,
		"records": []map[string]any{{
			"recordKey":      "record-1",
			"kind":           "delta",
			"occurredAt":     "2026-10-20T10:00:00Z",
			"tool":           "usage-json",
			"input":          "10",
			"cacheRead":      "0",
			"cacheWrite":     "0",
			"output":         "5",
			"adapterVersion": "test-adapter-1",
			"sourceType":     "fixture",
		}},
	})
	oldBytes, err := os.ReadFile(batchFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{BatchID: batchID, File: batchFile, Source: source, Input: batchFile, RecordCount: 1}); err != nil {
		t.Fatal(err)
	}
	cursors := progress.New(stateDir)
	if _, err := cursors.Advance(progress.AdvanceOptions{Source: source, Input: batchFile, BatchID: batchID, RecordCount: 1}); err != nil {
		t.Fatal(err)
	}
	frozenTo := &progress.MessageUsageState{Input: u64ptr(10), CacheRead: u64ptr(0), CacheWrite: u64ptr(0), Output: u64ptr(5)}
	if err := cursors.ApplyMessagePending(source, batchID, []progress.MessagePendingUpdate{{MessageID: "msg-1", RecordKey: "record-1", To: frozenTo}}); err != nil {
		t.Fatal(err)
	}
	// The expected reorganized batch ID is fully deterministic: hash of the
	// old batch, the live revision, the scope content, and the kept keys.
	expectedNewID := reorgBatchID(batchID, 7, liveScope{revision: 7}, []string{"record-1"})

	var gets, posts atomic.Int32
	var revision atomic.Int64
	var accept atomic.Bool
	revision.Store(7)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			gets.Add(1)
			writeJSON(w, http.StatusOK, map[string]any{"device": map[string]any{
				"deviceId":         "dev-1",
				"consentRevision":  revision.Load(),
				"uploadAuthorized": true,
				"revoked":          false,
			}})
			return
		}
		posts.Add(1)
		if !accept.Load() {
			writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]any{
				"code":    "scope_changed",
				"message": "consent revision moved; the submitted batch predates the change",
			}})
			return
		}
		var got BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
			return
		}
		if got.BatchID != expectedNewID {
			t.Errorf("recovery POST must use the reorganized batch id %s, got %q", expectedNewID, got.BatchID)
		}
		if r.Header.Get("X-Consent-Revision") != "8" {
			t.Errorf("recovery POST must echo the fresh consent revision, got %q", r.Header.Get("X-Consent-Revision"))
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId":         got.BatchID,
			"status":          "accepted",
			"acceptedRecords": 1,
			"rejectedRecords": 0,
			"replay":          false,
			"receivedAt":      "2026-10-20T10:12:00Z",
		}})
	}))
	defer server.Close()

	_, err = Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if !errors.Is(err, ErrScopeChanged) {
		t.Fatalf("expected ErrScopeChanged, got %v", err)
	}
	// scope_changed still reorganizes when every record is legal under the
	// live scope: the next run must POST a fresh batch under the new
	// revision instead of blindly resubmitting the old one.
	if got := gets.Load(); got != 2 || posts.Load() != 1 {
		t.Fatalf("expected one self GET before the POST plus one re-fetch for the reorganization (2 GET / 1 POST), got %d GET / %d POST", gets.Load(), posts.Load())
	}
	// Outbox: the old batch is terminally reorganized, the kept records
	// form a new pending batch born under revision 7.
	out, loadErr := outbox.New(stateDir).Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(out.Batches) != 2 {
		t.Fatalf("expected old plus reorganized batch in outbox: %#v", out)
	}
	var oldEntry, newEntry *outbox.BatchEntry
	for i := range out.Batches {
		if out.Batches[i].BatchID == batchID {
			oldEntry = &out.Batches[i]
		}
		if out.Batches[i].BatchID == expectedNewID {
			newEntry = &out.Batches[i]
		}
	}
	if oldEntry == nil || newEntry == nil {
		t.Fatalf("expected batches %s and %s, got %#v", batchID, expectedNewID, out.Batches)
	}
	if oldEntry.Status != outbox.StatusReorganized || oldEntry.ReorganizedInto != expectedNewID || oldEntry.ReorganizedRevision != 7 {
		t.Fatalf("expected old batch terminal reorganization: %#v", oldEntry)
	}
	if newEntry.Status != outbox.StatusPending || newEntry.OriginConsentRevision != 7 || newEntry.File != batchFilePath(stateDir, expectedNewID) || newEntry.RecordCount != 1 {
		t.Fatalf("expected reorganized batch pending under revision 7: %#v", newEntry)
	}
	// Old batch content is immutable.
	if fresh, readErr := os.ReadFile(batchFile); readErr != nil || !bytes.Equal(oldBytes, fresh) {
		t.Fatalf("old batch file must stay byte-identical, err=%v", readErr)
	}
	newBytes, readErr := os.ReadFile(batchFilePath(stateDir, expectedNewID))
	if readErr != nil {
		t.Fatal(readErr)
	}
	var newBatch BatchRequest
	if json.Unmarshal(newBytes, &newBatch) != nil || newBatch.BatchID != expectedNewID || len(newBatch.Records) != 1 {
		t.Fatalf("expected reorganized batch file with the kept record: %s", newBytes)
	}
	// Nothing was quarantined (all records stayed in scope).
	qEntries, qErr := quarantine.New(stateDir).Load()
	if qErr != nil || len(qEntries) != 0 {
		t.Fatalf("expected empty quarantine store, err=%v entries=%#v", qErr, qEntries)
	}
	// Cursor pending pointer follows the new batch; nothing is confirmed.
	cursorLedger, loadErr := cursors.Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(cursorLedger.Cursors) != 1 || cursorLedger.Cursors[0].BatchID != expectedNewID || cursorLedger.Cursors[0].ConfirmedBatchID != "" {
		t.Fatalf("expected cursor pending on the reorganized batch, unconfirmed: %#v", cursorLedger)
	}
	msgs, _, msgErr := cursors.MessageProgressFor(source)
	if msgErr != nil {
		t.Fatal(msgErr)
	}
	if len(msgs) != 1 || msgs["msg-1"].Pending == nil || msgs["msg-1"].Pending.BatchID != expectedNewID || msgs["msg-1"].Pending.RecordKey != "record-1" || msgs["msg-1"].Confirmed != nil {
		t.Fatalf("expected message interval migrated to the reorganized batch: %#v", msgs)
	}
	if msgs["msg-1"].Pending.To == nil || *msgs["msg-1"].Pending.To.Input != 10 {
		t.Fatalf("expected message interval endpoint preserved: %#v", msgs["msg-1"].Pending)
	}
	saved, loadErr := store.Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if saved.LastSyncBatchID != "" {
		t.Fatalf("expected device state untouched after scope change: %#v", saved)
	}

	// Recovery: the next run performs exactly one more POST — the
	// reorganized batch under the fresh revision, never the old content.
	revision.Store(8)
	accept.Store(true)
	if _, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir}); err != nil {
		t.Fatal(err)
	}
	if got := gets.Load(); got != 3 || posts.Load() != 2 {
		t.Fatalf("expected one GET and one POST in the recovery run, got %d GET / %d POST total", gets.Load(), posts.Load())
	}
	out, loadErr = outbox.New(stateDir).Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(out.Batches) != 2 {
		t.Fatalf("expected outbox unchanged in size: %#v", out)
	}
	for i := range out.Batches {
		if out.Batches[i].BatchID == batchID && out.Batches[i].Status != outbox.StatusReorganized {
			t.Fatalf("old batch must stay terminal: %#v", out.Batches[i])
		}
		if out.Batches[i].BatchID == expectedNewID && (out.Batches[i].Status != outbox.StatusSynced || out.Batches[i].ReceiptStatus != "accepted") {
			t.Fatalf("expected reorganized batch synced: %#v", out.Batches[i])
		}
	}
	msgs, _, msgErr = cursors.MessageProgressFor(source)
	if msgErr != nil {
		t.Fatal(msgErr)
	}
	if len(msgs) != 1 || msgs["msg-1"].Pending != nil || msgs["msg-1"].Confirmed == nil || *msgs["msg-1"].Confirmed.Input != 10 {
		t.Fatalf("expected message confirmed after recovery: %#v", msgs)
	}
}

func TestRunSyncPartialAckAdvancesAcceptedMessagesOnly(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	const source = "claude-code-jsonl"
	const batchID = "batch-partial-1"
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": batchID,
		"records": []map[string]any{
			{
				"recordKey":      "rk-a",
				"kind":           "delta",
				"occurredAt":     "2026-10-20T10:00:00Z",
				"tool":           "claude-code",
				"input":          "13",
				"cacheRead":      "0",
				"cacheWrite":     "0",
				"output":         "4",
				"adapterVersion": "test-adapter-1",
				"sourceType":     "fixture",
			},
			{
				"recordKey":      "rk-b",
				"kind":           "delta",
				"occurredAt":     "2026-10-20T10:01:00Z",
				"tool":           "claude-code",
				"input":          "15",
				"cacheRead":      "0",
				"cacheWrite":     "0",
				"output":         "6",
				"adapterVersion": "test-adapter-1",
				"sourceType":     "fixture",
			},
		},
	})
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{BatchID: batchID, File: batchFile, Source: source, Input: batchFile, RecordCount: 2}); err != nil {
		t.Fatal(err)
	}
	cursors := progress.New(stateDir)
	if _, err := cursors.Advance(progress.AdvanceOptions{Source: source, Input: batchFile, BatchID: batchID, RecordCount: 2}); err != nil {
		t.Fatal(err)
	}
	// msg-b already has a confirmed baseline from an earlier batch, so the
	// rejected branch must keep that baseline instead of adopting the new one.
	oldBaseline := &progress.MessageUsageState{Input: u64ptr(10), CacheRead: u64ptr(0), CacheWrite: u64ptr(0), Output: u64ptr(2)}
	if err := cursors.ApplyMessagePending(source, "batch-pre-1", []progress.MessagePendingUpdate{{MessageID: "msg-b", RecordKey: "rk-b-pre", To: oldBaseline}}); err != nil {
		t.Fatal(err)
	}
	if _, err := cursors.ConfirmMessageBatch(progress.MessageBatchConfirm{BatchID: "batch-pre-1"}); err != nil {
		t.Fatal(err)
	}
	toA := &progress.MessageUsageState{Input: u64ptr(13), CacheRead: u64ptr(0), CacheWrite: u64ptr(0), Output: u64ptr(4)}
	toB := &progress.MessageUsageState{Input: u64ptr(15), CacheRead: u64ptr(0), CacheWrite: u64ptr(0), Output: u64ptr(6)}
	if err := cursors.ApplyMessagePending(source, batchID, []progress.MessagePendingUpdate{
		{MessageID: "msg-a", RecordKey: "rk-a", To: toA},
		{MessageID: "msg-b", RecordKey: "rk-b", To: toB},
	}); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelf(t, w, r, 6) {
			return
		}
		var got BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
			return
		}
		if got.BatchID != batchID || len(got.Records) != 2 {
			t.Errorf("unexpected batch: %#v", got)
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId":         got.BatchID,
			"status":          "partial",
			"acceptedRecords": 1,
			"rejectedRecords": 1,
			"replay":          false,
			"receivedAt":      "2026-10-20T10:12:00Z",
			"recordErrors": []map[string]any{{
				"index":     1,
				"recordKey": "rk-b",
				"code":      "record_conflict",
				"message":   "payload hash differs",
			}},
		}})
	}))
	defer server.Close()
	res, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if res.Receipt.AcceptedRecords != 1 || res.Receipt.RejectedRecords != 1 || len(res.Receipt.RecordErrors) != 1 || res.Receipt.RecordErrors[0].Index != 1 {
		t.Fatalf("unexpected partial receipt: %#v", res.Receipt)
	}
	msgs, _, msgErr := cursors.MessageProgressFor(source)
	if msgErr != nil {
		t.Fatal(msgErr)
	}
	// Accepted message advanced to its pending to-state.
	advanced, ok := msgs["msg-a"]
	if !ok || advanced.Pending != nil || advanced.RejectedKey != "" || advanced.Confirmed == nil || *advanced.Confirmed.Input != 13 {
		t.Fatalf("expected msg-a confirmed at to-state: %#v", advanced)
	}
	// Rejected message unfroze, kept its old baseline, and recorded the
	// rejected interval key so it is never auto-resent.
	rejected, ok := msgs["msg-b"]
	if !ok || rejected.Pending != nil || rejected.RejectedKey != "rk-b" || rejected.RejectedCode != "record_conflict" {
		t.Fatalf("expected msg-b rejected and unfrozen: %#v", rejected)
	}
	if rejected.Confirmed == nil || *rejected.Confirmed.Input != 10 {
		t.Fatalf("expected msg-b to keep its prior confirmed baseline, got %#v", rejected.Confirmed)
	}
	out, loadErr := outbox.New(stateDir).Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(out.Batches) != 1 || out.Batches[0].Status != outbox.StatusSynced || out.Batches[0].ReceiptStatus != "partial_error" || out.Batches[0].AcceptedRecords != 1 || out.Batches[0].RejectedRecords != 1 {
		t.Fatalf("unexpected outbox after partial ACK: %#v", out)
	}
	saved, loadErr := store.Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if saved.LastSyncBatchID != batchID || saved.LastSyncStatus != "partial_error" || saved.LastSyncAcceptedRecords != 1 || saved.LastSyncRejectedRecords != 1 {
		t.Fatalf("unexpected device state after partial ACK: %#v", saved)
	}
}

func TestRunSyncReceiptInconsistencyKeepsBatchPending(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	const source = "usage-json"
	const batchID = "batch-inconsistent-1"
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": batchID,
		"records": []map[string]any{{
			"recordKey":      "record-1",
			"kind":           "delta",
			"occurredAt":     "2026-10-20T10:00:00Z",
			"tool":           "usage-json",
			"input":          "10",
			"cacheRead":      "0",
			"cacheWrite":     "0",
			"output":         "5",
			"adapterVersion": "test-adapter-1",
			"sourceType":     "fixture",
		}},
	})
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{BatchID: batchID, File: batchFile, Source: source, Input: batchFile, RecordCount: 1}); err != nil {
		t.Fatal(err)
	}
	cursors := progress.New(stateDir)
	if _, err := cursors.Advance(progress.AdvanceOptions{Source: source, Input: batchFile, BatchID: batchID, RecordCount: 1}); err != nil {
		t.Fatal(err)
	}
	frozenTo := &progress.MessageUsageState{Input: u64ptr(10), CacheRead: u64ptr(0), CacheWrite: u64ptr(0), Output: u64ptr(5)}
	if err := cursors.ApplyMessagePending(source, batchID, []progress.MessagePendingUpdate{{MessageID: "msg-1", RecordKey: "record-1", To: frozenTo}}); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelf(t, w, r, 9) {
			return
		}
		// Inconsistent receipt: 2 accepted + 1 rejected != 1 submitted.
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId":         batchID,
			"status":          "partial",
			"acceptedRecords": 2,
			"rejectedRecords": 1,
			"replay":          false,
			"receivedAt":      "2026-10-20T10:12:00Z",
			"recordErrors": []map[string]any{{
				"index":     0,
				"recordKey": "record-1",
				"code":      "record_conflict",
				"message":   "payload hash differs",
			}},
		}})
	}))
	defer server.Close()
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err == nil || !strings.Contains(err.Error(), "receipt inconsistent") {
		t.Fatalf("expected receipt inconsistency error, got %v", err)
	}
	out, loadErr := outbox.New(stateDir).Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(out.Batches) != 1 || out.Batches[0].Status != outbox.StatusPending {
		t.Fatalf("expected outbox batch kept pending: %#v", out)
	}
	cursorLedger, loadErr := cursors.Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(cursorLedger.Cursors) != 1 || cursorLedger.Cursors[0].ConfirmedBatchID != "" {
		t.Fatalf("expected cursor unconfirmed: %#v", cursorLedger)
	}
	msgs, _, msgErr := cursors.MessageProgressFor(source)
	if msgErr != nil {
		t.Fatal(msgErr)
	}
	if len(msgs) != 1 || msgs["msg-1"].Pending == nil {
		t.Fatalf("expected message still frozen: %#v", msgs)
	}
	if _, statErr := os.Stat(syncACKJournalPath(stateDir)); !os.IsNotExist(statErr) {
		t.Fatalf("expected no ACK journal left behind, stat err=%v", statErr)
	}
	saved, loadErr := store.Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if saved.LastSyncBatchID != "" {
		t.Fatalf("expected device state untouched: %#v", saved)
	}
}

func u64ptr(v uint64) *uint64 { return &v }

func writeBatchFile(t *testing.T, body any) string {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "batch.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
