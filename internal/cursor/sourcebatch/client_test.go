package sourcebatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/local/cursoroutbox"
	"toktrail-collector/internal/syncbudget"
)

// Synthetic placeholders only: no real device, secret, source or server
// is ever read from the environment.
const (
	testDeviceID     = "dev-cursor-test-1"
	testDeviceSecret = "synthetic-device-secret-0123456789abcdef"
	testSource       = "src-inst-cursor-1"
	testBatchID      = "batch-cursor-0001"
	testFence        = int64(9)
	testConsent      = int64(7)
	// marker is untrusted server free text; it must never surface in any
	// collector error.
	marker = "UNTRUSTED-SERVER-FREETEXT-e1c7"
)

func testBatch(batchID string, records int) protocol.Batch {
	b := protocol.Batch{BatchID: batchID, SourceInstanceID: testSource}
	for i := 0; i < records; i++ {
		b.Records = append(b.Records, protocol.Event{
			EventKey:       fmt.Sprintf("%s%064x", protocol.EventKeyPrefix, i+1),
			Revision:       int64(i + 1),
			Kind:           "event",
			OccurredAt:     "2026-10-28T12:00:00Z",
			Tool:           protocol.Tool,
			Model:          nil,
			Input:          nil,
			CacheRead:      nil,
			CacheWrite:     nil,
			Output:         nil,
			AdapterVersion: "test-adapter-1",
			SourceType:     protocol.SourceType,
		})
	}
	return b
}

func mustEncode(t *testing.T, b protocol.Batch) []byte {
	t.Helper()
	enc, err := protocol.EncodeBatch(b)
	if err != nil {
		t.Fatalf("encode test batch: %v", err)
	}
	return enc
}

func testOptions(serverURL string) Options {
	return Options{
		ServerURL:        serverURL,
		DeviceID:         testDeviceID,
		DeviceSecret:     testDeviceSecret,
		SourceInstanceID: testSource,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// serverReceipt builds the server's {"batch": receipt} envelope with the
// real wire shape (status enum accepted/rejected/partial_error, indexed
// record errors).
func serverReceipt(batchID, status string, accepted, rejected int, receivedAt string, replay bool, recordErrors []map[string]any) map[string]any {
	batch := map[string]any{
		"batchId":         batchID,
		"status":          status,
		"acceptedRecords": accepted,
		"rejectedRecords": rejected,
		"replay":          replay,
		"receivedAt":      receivedAt,
	}
	if recordErrors != nil {
		batch["recordErrors"] = recordErrors
	}
	return map[string]any{"batch": batch}
}

func recordErr(index int, code string) map[string]any {
	return map[string]any{"index": index, "recordKey": "cursor-v1:" + strings.Repeat("a", 64), "code": code, "message": marker}
}

const testReceivedAt = "2026-10-28T12:00:05Z"

func TestPostBatchSendsDeviceAuthFenceConsentAndExactBytes(t *testing.T) {
	batch := testBatch(testBatchID, 2)
	encoded := mustEncode(t, batch)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method %s", r.Method)
		}
		if r.URL.Path != "/v1/ingest/source-batches" {
			t.Errorf("cursor batch posted to unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+testDeviceID+"."+testDeviceSecret {
			t.Errorf("unexpected Authorization header %q", got)
		}
		if got := r.Header.Get("X-Source-Fence"); got != "9" {
			t.Errorf("unexpected X-Source-Fence header %q", got)
		}
		if got := r.Header.Get("X-Consent-Revision"); got != "7" {
			t.Errorf("unexpected X-Consent-Revision header %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("unexpected Content-Type header %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		if !bytes.Equal(body, encoded) {
			t.Errorf("uploaded bytes differ from the immutable outbox bytes")
		}
		writeJSON(w, http.StatusAccepted, serverReceipt(testBatchID, "accepted", 2, 0, testReceivedAt, false, nil))
	}))
	defer server.Close()
	receipt, err := PostBatch(t.Context(), testOptions(server.URL), encoded, testFence, testConsent)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.BatchID != testBatchID || receipt.Status != "accepted" || receipt.AcceptedRecords != 2 || receipt.RejectedRecords != 0 || receipt.Replay {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
	wantAt, _ := time.Parse(time.RFC3339, testReceivedAt)
	if !receipt.ReceivedAt.Equal(wantAt) {
		t.Fatalf("unexpected receivedAt: %v", receipt.ReceivedAt)
	}
}

// The device ingest endpoint must never see cursor records: only the
// source-batches path is ever targeted, whatever the server URL shape.
func TestPostBatchTargetsOnlySourceBatchesPath(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 1))
	cases := []struct {
		name string
		url  string
		path string
	}{
		{"plain", "", "/v1/ingest/source-batches"},
		{"trailing slash", "/", "/v1/ingest/source-batches"},
		{"subpath base", "/api", "/api/v1/ingest/source-batches"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.path {
					t.Errorf("unexpected path %s", r.URL.Path)
				}
				writeJSON(w, http.StatusAccepted, serverReceipt(testBatchID, "accepted", 1, 0, testReceivedAt, false, nil))
			}))
			defer server.Close()
			if _, err := PostBatch(t.Context(), testOptions(server.URL+tc.url), encoded, testFence, testConsent); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPostBatchReplayReceiptKeepsStatusAndSetsReplay(t *testing.T) {
	// A re-sent duplicate answers HTTP 200 with the stored status and
	// replay=true — "duplicate" is not a status value.
	encoded := mustEncode(t, testBatch(testBatchID, 2))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, serverReceipt(testBatchID, "accepted", 2, 0, testReceivedAt, true, nil))
	}))
	defer server.Close()
	receipt, err := PostBatch(t.Context(), testOptions(server.URL), encoded, testFence, testConsent)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.Replay || receipt.Status != "accepted" || receipt.AcceptedRecords != 2 {
		t.Fatalf("unexpected replay receipt: %#v", receipt)
	}
}

func TestPostBatchRefusesForeignAndUnvalidatedBatches(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("server must not be contacted for a refused batch")
		writeJSON(w, http.StatusAccepted, serverReceipt(testBatchID, "accepted", 0, 0, testReceivedAt, false, nil))
	}))
	defer server.Close()
	opt := testOptions(server.URL)

	foreign := testBatch(testBatchID, 1)
	foreign.SourceInstanceID = "src-inst-someone-else"
	if _, err := PostBatch(t.Context(), opt, mustEncode(t, foreign), testFence, testConsent); err == nil {
		t.Fatal("expected a batch belonging to another source to be refused")
	}

	tampered := append(mustEncode(t, testBatch(testBatchID, 1)), []byte("{}")...)
	if _, err := PostBatch(t.Context(), opt, tampered, testFence, testConsent); err == nil {
		t.Fatal("expected unvalidated wire bytes to be refused")
	}
}

func TestPostBatchRedirectDoesNotLeakAuthorization(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 1))
	for _, tc := range []struct {
		name   string
		target func(t *testing.T, redirector *httptest.Server) string
	}{
		{"cross host", func(t *testing.T, redirector *httptest.Server) string {
			return redirector.URL + "/steal"
		}},
		{"same host", func(t *testing.T, redirector *httptest.Server) string {
			return redirector.URL + "/v1/ingest/source-batches-elsewhere"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hit atomic.Bool
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hit.Store(true)
				if r.Header.Get("Authorization") != "" {
					t.Error("redirect target received the Authorization header")
				}
			}))
			defer target.Close()
			var redirector *httptest.Server
			redirector = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, tc.target(t, redirector), http.StatusFound)
			}))
			defer redirector.Close()
			_, err := PostBatch(t.Context(), testOptions(redirector.URL), encoded, testFence, testConsent)
			if err == nil {
				t.Fatal("expected the redirect to be refused")
			}
			if hit.Load() {
				t.Fatal("the redirect was followed")
			}
			if strings.Contains(err.Error(), testDeviceSecret) {
				t.Fatalf("error leaks the device secret: %v", err)
			}
		})
	}
}

func TestGetBatchSendsDeviceAuthAndQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method %s", r.Method)
		}
		if r.URL.Path != "/v1/ingest/source-batches/"+testBatchID {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("sourceInstanceId"); got != testSource {
			t.Errorf("unexpected sourceInstanceId query %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+testDeviceID+"."+testDeviceSecret {
			t.Errorf("unexpected Authorization header %q", got)
		}
		if got := r.Header.Get("X-Source-Fence"); got != "9" {
			t.Errorf("unexpected X-Source-Fence header %q", got)
		}
		if got := r.Header.Get("X-Consent-Revision"); got != "7" {
			t.Errorf("unexpected X-Consent-Revision header %q", got)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("unexpected Accept header %q", got)
		}
		// The stored receipt replays with its real counts even though the
		// GET path cannot re-verify coverage.
		writeJSON(w, http.StatusOK, serverReceipt(testBatchID, "accepted", 2, 0, testReceivedAt, true, nil))
	}))
	defer server.Close()
	receipt, found, err := GetBatch(t.Context(), testOptions(server.URL), testBatchID, testFence, testConsent)
	if err != nil || !found {
		t.Fatalf("unexpected result: found=%v err=%v", found, err)
	}
	if receipt.BatchID != testBatchID || receipt.AcceptedRecords != 2 || !receipt.Replay {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
}

func TestGetBatchNotFoundIsNotAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "not_found", "message": marker}})
	}))
	defer server.Close()
	_, found, err := GetBatch(t.Context(), testOptions(server.URL), testBatchID, testFence, testConsent)
	if err != nil || found {
		t.Fatalf("unexpected result: found=%v err=%v", found, err)
	}
}

func TestGetBatchRedirectDoesNotLeakAuthorization(t *testing.T) {
	var hit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Store(true)
		if r.Header.Get("Authorization") != "" {
			t.Error("redirect target received the Authorization header")
		}
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/steal", http.StatusFound)
	}))
	defer server.Close()
	_, _, err := GetBatch(t.Context(), testOptions(server.URL), testBatchID, testFence, testConsent)
	if err == nil {
		t.Fatal("expected the redirect to be refused")
	}
	if hit.Load() {
		t.Fatal("the redirect was followed")
	}
	if strings.Contains(err.Error(), testDeviceSecret) {
		t.Fatalf("error leaks the device secret: %v", err)
	}
}

func TestPostBatchReceiptStrictness(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 2))
	cases := []struct {
		name    string
		status  int
		body    any
		wantErr error
	}{
		{"full accept", http.StatusAccepted, serverReceipt(testBatchID, "accepted", 2, 0, testReceivedAt, false, nil), nil},
		{"all rejected with record errors", http.StatusAccepted, serverReceipt(testBatchID, "rejected", 0, 2, testReceivedAt, false, []map[string]any{recordErr(0, "stale_revision"), recordErr(1, "record_conflict")}), nil},
		{"partial error with record errors", http.StatusAccepted, serverReceipt(testBatchID, "partial_error", 1, 1, testReceivedAt, false, []map[string]any{recordErr(1, "invalid_decimal")}), nil},
		{"wrong batch id", http.StatusAccepted, serverReceipt("batch-someone-else", "accepted", 2, 0, testReceivedAt, false, nil), ErrInvalidReceipt},
		{"legacy status duplicate", http.StatusAccepted, serverReceipt(testBatchID, "duplicate", 2, 0, testReceivedAt, false, nil), ErrInvalidReceipt},
		{"legacy status replay", http.StatusAccepted, serverReceipt(testBatchID, "replay", 2, 0, testReceivedAt, false, nil), ErrInvalidReceipt},
		{"unknown status", http.StatusAccepted, serverReceipt(testBatchID, "half-done", 2, 0, testReceivedAt, false, nil), ErrInvalidReceipt},
		{"status accepted with rejections", http.StatusAccepted, serverReceipt(testBatchID, "accepted", 1, 1, testReceivedAt, false, nil), ErrInvalidReceipt},
		{"status rejected with accepts", http.StatusAccepted, serverReceipt(testBatchID, "rejected", 1, 1, testReceivedAt, false, nil), ErrInvalidReceipt},
		{"status partial error without rejections", http.StatusAccepted, serverReceipt(testBatchID, "partial_error", 2, 0, testReceivedAt, false, nil), ErrInvalidReceipt},
		{"status rejected with zero records", http.StatusAccepted, serverReceipt(testBatchID, "rejected", 0, 0, testReceivedAt, false, nil), ErrInvalidReceipt},
		{"counts do not cover records", http.StatusAccepted, serverReceipt(testBatchID, "accepted", 1, 0, testReceivedAt, false, nil), ErrInvalidReceipt},
		{"counts exceed records", http.StatusAccepted, serverReceipt(testBatchID, "partial_error", 2, 1, testReceivedAt, false, nil), ErrInvalidReceipt},
		{"negative accepted", http.StatusAccepted, serverReceipt(testBatchID, "partial_error", -1, 3, testReceivedAt, false, nil), ErrInvalidReceipt},
		{"missing receivedAt", http.StatusAccepted, serverReceipt(testBatchID, "accepted", 2, 0, "", false, nil), ErrInvalidReceipt},
		{"record error index out of range", http.StatusAccepted, serverReceipt(testBatchID, "partial_error", 1, 1, testReceivedAt, false, []map[string]any{recordErr(99, "invalid_decimal")}), ErrInvalidReceipt},
		{"record error negative index", http.StatusAccepted, serverReceipt(testBatchID, "partial_error", 1, 1, testReceivedAt, false, []map[string]any{recordErr(-1, "invalid_decimal")}), ErrInvalidReceipt},
		{"record errors without rejections", http.StatusAccepted, serverReceipt(testBatchID, "accepted", 2, 0, testReceivedAt, false, []map[string]any{recordErr(0, "invalid_decimal")}), nil},
		{"no receipt object", http.StatusAccepted, map[string]any{"error": nil}, ErrInvalidReceipt},
		{"malformed json", http.StatusAccepted, json.RawMessage("{not json"), ErrInvalidReceipt},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, tc.status, tc.body)
			}))
			defer server.Close()
			receipt, err := PostBatch(t.Context(), testOptions(server.URL), encoded, testFence, testConsent)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("expected a valid receipt, got %v", err)
				}
				if receipt.BatchID != testBatchID {
					t.Fatalf("unexpected receipt: %#v", receipt)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected %v, got receipt %#v", tc.wantErr, receipt)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("error echoes untrusted server message: %v", err)
			}
			if strings.Contains(err.Error(), testDeviceSecret) {
				t.Fatalf("error leaks the device secret: %v", err)
			}
		})
	}
}

// A rejected or partial_error receipt is a VALID receipt (it parses with
// its indexed record errors so the concrete rejection codes survive),
// but it is never a full acknowledgment: the store must refuse to mark
// the batch synced and keep it pending.
func TestPostBatchPartialReceiptIsNeverAFullAcknowledgment(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   string
		accepted int
		rejected int
		errors   []map[string]any
	}{
		{"partial error", "partial_error", 1, 1, []map[string]any{recordErr(1, "stale_revision")}},
		{"all rejected", "rejected", 0, 2, []map[string]any{recordErr(0, "record_conflict"), recordErr(1, "invalid_decimal")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch := testBatch(testBatchID, 2)
			encoded := mustEncode(t, batch)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, http.StatusAccepted, serverReceipt(testBatchID, tc.status, tc.accepted, tc.rejected, testReceivedAt, false, tc.errors))
			}))
			defer server.Close()
			receipt, err := PostBatch(t.Context(), testOptions(server.URL), encoded, testFence, testConsent)
			if err != nil {
				t.Fatalf("a %s receipt must validate, not fail: %v", tc.status, err)
			}
			if receipt.RejectedRecords != tc.rejected || receipt.AcceptedRecords != tc.accepted {
				t.Fatalf("receipt lost its counts: %#v", receipt)
			}
			if receipt.Status != tc.status {
				t.Fatalf("receipt lost its status: %#v", receipt)
			}

			store := cursoroutbox.New(t.TempDir())
			if _, err := store.AddBatch(batch, testFence, encoded); err != nil {
				t.Fatal(err)
			}
			storeReceipt := cursoroutbox.Receipt{
				BatchID:         receipt.BatchID,
				Status:          receipt.Status,
				AcceptedRecords: receipt.AcceptedRecords,
				RejectedRecords: receipt.RejectedRecords,
				Replay:          receipt.Replay,
				ReceivedAt:      receipt.ReceivedAt,
			}
			if err := store.MarkSynced(storeReceipt); err == nil {
				t.Fatalf("a %s receipt must not mark the batch synced", tc.status)
			}
			entry, ok, err := store.NextPending()
			if err != nil || !ok {
				t.Fatalf("the batch must stay pending: ok=%v err=%v", ok, err)
			}
			if entry.BatchID != testBatchID || entry.Status != cursoroutbox.StatusPending {
				t.Fatalf("unexpected entry: %#v", entry)
			}

			// Contrast: a full receipt marks the batch synced.
			full := cursoroutbox.Receipt{
				BatchID:         receipt.BatchID,
				Status:          "accepted",
				AcceptedRecords: 2,
				RejectedRecords: 0,
				ReceivedAt:      receipt.ReceivedAt,
			}
			if err := store.MarkSynced(full); err != nil {
				t.Fatalf("a full receipt must mark the batch synced: %v", err)
			}
			if _, ok, _ := store.NextPending(); ok {
				t.Fatal("no batch may stay pending after a full acknowledgment")
			}
		})
	}
}

// The concrete rejection reasons of a partial receipt must survive into
// the store receipt — indexes intact, codes whitelisted, unknown codes
// collapsed to record_rejected, and never any server free text.
func TestPostBatchPartialReceiptPreservesSanitizedRecordErrorCodes(t *testing.T) {
	batch := testBatch(testBatchID, 3)
	encoded := mustEncode(t, batch)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusAccepted, serverReceipt(testBatchID, "partial_error", 1, 2, testReceivedAt, false, []map[string]any{
			{"index": 0, "recordKey": "cursor-v1:" + strings.Repeat("a", 64), "code": "invalid_decimal", "message": marker},
			{"index": 2, "recordKey": "cursor-v1:" + strings.Repeat("b", 64), "code": "stale_revision", "message": marker},
		}))
	}))
	defer server.Close()
	receipt, err := PostBatch(t.Context(), testOptions(server.URL), encoded, testFence, testConsent)
	if err != nil {
		t.Fatalf("a partial_error receipt must validate: %v", err)
	}
	want := []cursoroutbox.RecordError{
		{Index: 0, Code: "invalid_decimal"},
		{Index: 2, Code: "stale_revision"},
	}
	if !reflect.DeepEqual(receipt.RecordErrors, want) {
		t.Fatalf("record error codes were lost or altered: %#v", receipt.RecordErrors)
	}
	for _, re := range receipt.RecordErrors {
		if strings.Contains(re.Code, marker) {
			t.Fatalf("record error code carries untrusted server text: %#v", re)
		}
	}

	// Unknown codes collapse to the generic record_rejected.
	unknown := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusAccepted, serverReceipt(testBatchID, "rejected", 0, 3, testReceivedAt, false, []map[string]any{
			{"index": 0, "code": "some_new_server_code", "message": marker},
			{"index": 1, "code": "", "message": marker},
			{"index": 2, "code": "record_conflict", "message": marker},
		}))
	}))
	defer unknown.Close()
	receipt, err = PostBatch(t.Context(), testOptions(unknown.URL), encoded, testFence, testConsent)
	if err != nil {
		t.Fatalf("a rejected receipt must validate: %v", err)
	}
	want = []cursoroutbox.RecordError{
		{Index: 0, Code: "record_rejected"},
		{Index: 1, Code: "record_rejected"},
		{Index: 2, Code: "record_conflict"},
	}
	if !reflect.DeepEqual(receipt.RecordErrors, want) {
		t.Fatalf("unknown codes must collapse to record_rejected: %#v", receipt.RecordErrors)
	}

	// A fully accepted receipt carries no record errors at all.
	full := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusAccepted, serverReceipt(testBatchID, "accepted", 3, 0, testReceivedAt, false, nil))
	}))
	defer full.Close()
	receipt, err = PostBatch(t.Context(), testOptions(full.URL), encoded, testFence, testConsent)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.RecordErrors != nil {
		t.Fatalf("fully accepted receipt carries record errors: %#v", receipt.RecordErrors)
	}
}

// The GET receipt replay keeps the sanitized codes as well.
func TestGetBatchPartialReceiptPreservesSanitizedRecordErrorCodes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, serverReceipt(testBatchID, "partial_error", 1, 1, testReceivedAt, false, []map[string]any{
			{"index": 1, "code": "record_conflict", "message": marker},
		}))
	}))
	defer server.Close()
	receipt, found, err := GetBatch(t.Context(), testOptions(server.URL), testBatchID, testFence, testConsent)
	if err != nil || !found {
		t.Fatalf("unexpected result: found=%v err=%v", found, err)
	}
	want := []cursoroutbox.RecordError{{Index: 1, Code: "record_conflict"}}
	if !reflect.DeepEqual(receipt.RecordErrors, want) {
		t.Fatalf("record error codes were lost or altered: %#v", receipt.RecordErrors)
	}
}

func TestGetBatchReceiptStrictness(t *testing.T) {
	cases := []struct {
		name    string
		body    any
		wantErr error
	}{
		{"stored partial receipt with real counts", serverReceipt(testBatchID, "partial_error", 1, 1, testReceivedAt, false, []map[string]any{recordErr(1, "stale_revision")}), nil},
		{"stored rejected receipt", serverReceipt(testBatchID, "rejected", 0, 2, testReceivedAt, false, []map[string]any{recordErr(0, "record_conflict"), recordErr(1, "record_conflict")}), nil},
		{"record error index beyond a local batch is unverifiable", serverReceipt(testBatchID, "partial_error", 1, 1, testReceivedAt, false, []map[string]any{recordErr(7, "stale_revision")}), nil},
		{"wrong batch id", serverReceipt("batch-someone-else", "accepted", 2, 0, testReceivedAt, false, nil), ErrInvalidReceipt},
		{"status disagrees with counts", serverReceipt(testBatchID, "accepted", 1, 1, testReceivedAt, false, nil), ErrInvalidReceipt},
		{"unknown status", serverReceipt(testBatchID, "duplicate", 2, 0, testReceivedAt, false, nil), ErrInvalidReceipt},
		{"negative counts", serverReceipt(testBatchID, "partial_error", -1, 2, testReceivedAt, false, nil), ErrInvalidReceipt},
		{"missing receivedAt", serverReceipt(testBatchID, "accepted", 2, 0, "", false, nil), ErrInvalidReceipt},
		{"negative record error index", serverReceipt(testBatchID, "partial_error", 1, 1, testReceivedAt, false, []map[string]any{recordErr(-2, "stale_revision")}), ErrInvalidReceipt},
		{"no receipt object", map[string]any{"error": nil}, ErrInvalidReceipt},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, http.StatusOK, tc.body)
			}))
			defer server.Close()
			receipt, found, err := GetBatch(t.Context(), testOptions(server.URL), testBatchID, testFence, testConsent)
			if tc.wantErr == nil {
				if err != nil || !found {
					t.Fatalf("expected a valid receipt, got found=%v err=%v", found, err)
				}
				if receipt.RejectedRecords < 0 || receipt.BatchID != testBatchID {
					t.Fatalf("unexpected receipt: %#v", receipt)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected %v, got receipt %#v", tc.wantErr, receipt)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("error echoes untrusted server message: %v", err)
			}
		})
	}
}

// The mapped wire codes are the server's stable codes; the server's
// free-text message and the device secret must never surface.
func TestPostBatchErrorMappingNeverEchoesServerMessage(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 1))
	cases := []struct {
		name    string
		status  int
		code    string
		wantErr error
	}{
		{"fence stale", http.StatusConflict, "source_fence_changed", ErrFenceStale},
		{"consent stale via scope changed", http.StatusConflict, "scope_changed", ErrConsentStale},
		{"consent stale alias", http.StatusConflict, "consent_revision_stale", ErrConsentStale},
		{"source paused", http.StatusForbidden, "source_paused", ErrSourcePaused},
		{"source deleted", http.StatusGone, "source_deleted", ErrSourceDeleted},
		{"stale revision", http.StatusConflict, "stale_revision", ErrStaleRevision},
		{"device unauthorized", http.StatusUnauthorized, "unauthorized", ErrDeviceUnauthorized},
		{"device revoked", http.StatusForbidden, "device_revoked", ErrDeviceUnauthorized},
		{"executor mismatch is a plain error", http.StatusConflict, "source_executor_mismatch", nil},
		{"unknown server error", http.StatusInternalServerError, "internal_error", nil},
		{"non json body", http.StatusBadRequest, "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.code == "" && tc.name == "non json body" {
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte("not-json{" + marker))
					return
				}
				writeJSON(w, tc.status, map[string]any{"error": map[string]any{"code": tc.code, "message": marker}})
			}))
			defer server.Close()
			receipt, err := PostBatch(t.Context(), testOptions(server.URL), encoded, testFence, testConsent)
			if err == nil {
				t.Fatalf("expected an error, got receipt %#v", receipt)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}
			if tc.wantErr == nil && errors.Is(err, ErrInvalidReceipt) {
				t.Fatalf("transport-level failure misreported as an invalid receipt: %v", err)
			}
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("error echoes untrusted server message: %v", err)
			}
			if strings.Contains(err.Error(), testDeviceSecret) {
				t.Fatalf("error leaks the device secret: %v", err)
			}
		})
	}
}

func TestPostBatchRejectsOversizedResponse(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 1))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write(make([]byte, maxResponseBytes+1))
	}))
	defer server.Close()
	if _, err := PostBatch(t.Context(), testOptions(server.URL), encoded, testFence, testConsent); err == nil {
		t.Fatal("expected an oversized response to be rejected")
	}
}

func TestPostBatchHonorsBoundedClientTimeout(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 1))
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer server.Close()
	opt := testOptions(server.URL)
	opt.HTTPClient = &http.Client{Timeout: 80 * time.Millisecond}
	start := time.Now()
	_, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent)
	close(release)
	if err == nil {
		t.Fatal("expected the hung server to time out")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("timeout took %v", elapsed)
	}
	if strings.Contains(err.Error(), testDeviceSecret) {
		t.Fatalf("error leaks the device secret: %v", err)
	}
}

func TestClientClampsTimeoutAndRefusesRedirects(t *testing.T) {
	tr := &http.Transport{}
	c := client(Options{HTTPClient: &http.Client{Transport: tr}})
	if c.Transport == nil || c.Transport != *(&tr) {
		t.Fatal("cloned client lost the configured transport")
	}
	if c.Timeout <= 0 || c.Timeout > 60*time.Second {
		t.Fatalf("unexpected cloned timeout %v", c.Timeout)
	}
	if c.CheckRedirect == nil || c.CheckRedirect(nil, nil) == nil {
		t.Fatal("cloned client must refuse redirects")
	}
	defaults := client(Options{})
	if defaults.Timeout != 15*time.Second {
		t.Fatalf("unexpected default timeout %v", defaults.Timeout)
	}
	huge := client(Options{HTTPClient: &http.Client{Timeout: 5 * time.Minute}})
	if huge.Timeout != 15*time.Second {
		t.Fatalf("absurd timeout was not clamped: %v", huge.Timeout)
	}
}

func TestJoinURL(t *testing.T) {
	cases := []struct {
		base, path, want string
	}{
		{"http://x", "/p", "http://x/p"},
		{"http://x/", "/p", "http://x/p"},
		{" http://x ", "p", "http://x/p"},
	}
	for _, tc := range cases {
		if got, err := joinURL(tc.base, tc.path); err != nil || got != tc.want {
			t.Errorf("joinURL(%q, %q) = %q, %v; want %q", tc.base, tc.path, got, err, tc.want)
		}
	}
	if _, err := joinURL("  ", "/p"); err == nil {
		t.Error("expected an error for an empty server URL")
	}
}

// ---------------------------------------------------------------------------
// Shared run budget (syncbudget) wiring
// ---------------------------------------------------------------------------

// newBudgetServer accepts one source-batch ingest POST at a time and
// counts them; nothing else is served.
func newBudgetServer(t *testing.T, posts *atomic.Int64) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		writeJSON(w, http.StatusAccepted, serverReceipt(testBatchID, "accepted", 1, 0, testReceivedAt, false, nil))
	}))
	t.Cleanup(server.Close)
	return server
}

// A declined budget must prevent the ingest POST entirely and spend
// nothing; the decline is the budget's own sentinel, never a transport
// error. The reservation rides the "cursor" queue: a cap on another queue
// leaves cursor uploads untouched.
func TestPostBatchSharedBudgetDeclinePreventsPost(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 1))
	cases := []struct {
		name    string
		budget  *syncbudget.Budget
		wantErr error
	}{
		{"total exhausted", syncbudget.New(syncbudget.WithTotal(0)), syncbudget.ErrTotalExhausted},
		{"cursor queue exhausted", syncbudget.New(syncbudget.WithQueueCap("cursor", 0)), syncbudget.ErrQueueExhausted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var posts atomic.Int64
			server := newBudgetServer(t, &posts)
			opt := testOptions(server.URL)
			opt.Budget = tc.budget
			_, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}
			if posts.Load() != 0 {
				t.Fatalf("a declined budget must not POST, posts=%d", posts.Load())
			}
			if tc.budget.Used() != 0 || tc.budget.QueueUsed("cursor") != 0 {
				t.Fatalf("a declined reservation must spend nothing: used=%d cursor=%d", tc.budget.Used(), tc.budget.QueueUsed("cursor"))
			}
		})
	}
	t.Run("another queue's cap does not bind cursor", func(t *testing.T) {
		var posts atomic.Int64
		server := newBudgetServer(t, &posts)
		opt := testOptions(server.URL)
		opt.Budget = syncbudget.New(syncbudget.WithQueueCap("device", 0))
		if _, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent); err != nil {
			t.Fatalf("a device-queue cap must not decline a cursor upload: %v", err)
		}
		if posts.Load() != 1 {
			t.Fatalf("expected exactly one POST, posts=%d", posts.Load())
		}
	})
}

// One granted attempt uploads once and is spent for good; the next
// upload under the same budget declines without a POST. A nil Budget
// keeps the unconditional upload behavior.
func TestPostBatchSharedBudgetGrantsOnePostThenDeclines(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 1))
	var posts atomic.Int64
	server := newBudgetServer(t, &posts)
	opt := testOptions(server.URL)
	opt.Budget = syncbudget.New(syncbudget.WithTotal(1))

	if _, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent); err != nil {
		t.Fatalf("the granted attempt must upload: %v", err)
	}
	if posts.Load() != 1 || opt.Budget.Used() != 1 || opt.Budget.QueueUsed("cursor") != 1 {
		t.Fatalf("granted attempt accounting: posts=%d used=%d cursor=%d", posts.Load(), opt.Budget.Used(), opt.Budget.QueueUsed("cursor"))
	}

	_, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent)
	if !errors.Is(err, syncbudget.ErrTotalExhausted) {
		t.Fatalf("expected the spent budget to decline, got %v", err)
	}
	if posts.Load() != 1 {
		t.Fatalf("a declined retry must not POST, posts=%d", posts.Load())
	}

	// Nil Budget: the unconditional upload behavior is unchanged.
	opt.Budget = nil
	if _, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent); err != nil {
		t.Fatalf("a nil budget must keep uploading: %v", err)
	}
	if posts.Load() != 2 {
		t.Fatalf("expected the nil-budget upload, posts=%d", posts.Load())
	}
}

// The reservation happens immediately before the real POST, after every
// local validation: a batch refused locally never spends budget.
func TestPostBatchSharedBudgetNotSpentOnLocalRefusals(t *testing.T) {
	var posts atomic.Int64
	server := newBudgetServer(t, &posts)
	opt := testOptions(server.URL)
	opt.Budget = syncbudget.New(syncbudget.WithTotal(0))

	foreign := testBatch(testBatchID, 1)
	foreign.SourceInstanceID = "src-inst-someone-else"
	if _, err := PostBatch(t.Context(), opt, mustEncode(t, foreign), testFence, testConsent); err == nil {
		t.Fatal("expected a batch belonging to another source to be refused")
	} else if errors.Is(err, syncbudget.ErrTotalExhausted) {
		t.Fatalf("the local refusal must surface, not the budget decline: %v", err)
	}
	if posts.Load() != 0 || opt.Budget.Used() != 0 {
		t.Fatalf("a locally refused batch must not POST or spend budget: posts=%d used=%d", posts.Load(), opt.Budget.Used())
	}
}

// A POST that fails after the reservation is not refunded: the attempt
// stays spent and the next upload under the same budget declines without
// another POST.
func TestPostBatchSharedBudgetSpentWhenPostFails(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 1))
	var posts atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "unavailable", "message": marker}})
	}))
	defer server.Close()
	opt := testOptions(server.URL)
	opt.Budget = syncbudget.New(syncbudget.WithTotal(1))

	if _, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent); err == nil || errors.Is(err, syncbudget.ErrTotalExhausted) {
		t.Fatalf("the failed POST must surface as an upload failure, not a budget decline: %v", err)
	}
	if posts.Load() != 1 || opt.Budget.Used() != 1 {
		t.Fatalf("a failed POST must still spend its reserved attempt: posts=%d used=%d", posts.Load(), opt.Budget.Used())
	}

	_, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent)
	if !errors.Is(err, syncbudget.ErrTotalExhausted) {
		t.Fatalf("the spent attempt must not be refunded, got %v", err)
	}
	if posts.Load() != 1 {
		t.Fatalf("the declined retry must not POST again, posts=%d", posts.Load())
	}
}

// An ordinary transport failure — here a client timeout, whose Go error
// chain carries context.DeadlineExceeded — must never be mistaken for
// the budget's own ErrDeadlineExceeded decline: only a real budget
// deadline stop reads as one, so network timeouts keep surfacing as
// plain upload failures (they still spend their reserved attempt).
func TestPostBatchClientTimeoutIsNotABudgetDeadline(t *testing.T) {
	encoded := mustEncode(t, testBatch(testBatchID, 1))
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer server.Close()
	opt := testOptions(server.URL)
	opt.HTTPClient = &http.Client{Timeout: 80 * time.Millisecond}
	opt.Budget = syncbudget.New(syncbudget.WithTotal(1))

	_, err := PostBatch(t.Context(), opt, encoded, testFence, testConsent)
	close(release)
	if err == nil {
		t.Fatal("expected the hung server to time out")
	}
	if errors.Is(err, syncbudget.ErrDeadlineExceeded) || errors.Is(err, syncbudget.ErrTotalExhausted) || errors.Is(err, syncbudget.ErrQueueExhausted) {
		t.Fatalf("a client timeout must not be misread as a budget decline: %v", err)
	}
	if opt.Budget.Used() != 1 {
		t.Fatalf("the timed-out POST must still spend its reserved attempt, used=%d", opt.Budget.Used())
	}
}
