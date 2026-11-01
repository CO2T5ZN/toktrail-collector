package main

// CLI-level coverage for connect's shared POST budget: --max-total-batches
// must reach connect.Run's run-wide budget and cap every real ingest POST of
// the sync phase (here: the device outbox drain on a first install), leaving
// the rest honestly pending with an ErrSyncIncomplete result. Everything is
// synthetic: temp dirs, an httptest config server, an httptest TokTrail
// double, a hand-seeded outbox. No real tool state is read.
import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"toktrail-collector/internal/connect"
	"toktrail-collector/internal/local/outbox"
)

// seedCLIDeviceBatch writes one pending device batch attributed to the codex
// grant connect will enable for the synthetic home.
func seedCLIDeviceBatch(t *testing.T, stateDir, homeDir, batchID, key string, age time.Duration) {
	t.Helper()
	batchesDir := filepath.Join(stateDir, "batches")
	if err := os.MkdirAll(batchesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	record := map[string]any{
		"recordKey":      key,
		"kind":           "delta",
		"tool":           "Codex",
		"model":          "gpt-5.4",
		"occurredAt":     time.Now().UTC().Add(-age).Format(time.RFC3339),
		"input":          "100",
		"output":         "50",
		"cacheRead":      "20",
		"cacheWrite":     "5",
		"adapterVersion": "synthetic",
		"sourceType":     "fixture",
	}
	raw, err := json.Marshal(map[string]any{"batchId": batchID, "records": []map[string]any{record}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(batchesDir, batchID+".json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(homeDir, ".codex", "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	out.Batches = append(out.Batches, outbox.BatchEntry{
		BatchID:     batchID,
		File:        path,
		Source:      "codex-jsonl",
		Input:       input,
		Status:      outbox.StatusPending,
		RecordCount: 1,
		CreatedAt:   time.Now().UTC().Add(-age),
	})
	if err := outbox.New(stateDir).Save(out); err != nil {
		t.Fatal(err)
	}
}

// TestRunConnectCLIMaxTotalBatchesCapsPosts drives the real runConnect flag
// surface end to end: with --max-total-batches 2 over three pending batches,
// exactly two real ingest POSTs happen, one batch stays pending, and the CLI
// reports connect's honest incomplete result.
func TestRunConnectCLIMaxTotalBatchesCapsPosts(t *testing.T) {
	oldRunner := connectSchedulerRunner
	connectSchedulerRunner = mockSchedulerRunner{}
	defer func() { connectSchedulerRunner = oldRunner }()

	stateDir := t.TempDir()
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)

	var mu sync.Mutex
	ingests := 0
	toktrailServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/devices/bind":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device": map[string]any{
					"deviceId":          "dev-cli-budget-1",
					"applicationId":     "app-cli",
					"externalSubjectId": "sub-cli",
					"deviceName":        "dev-name",
					"platform":          "test-platform",
					"consentRevision":   1,
					"boundAt":           time.Now().UTC().Format(time.RFC3339),
				},
			})
		case "/v1/devices/self":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device": map[string]any{
					"deviceId":         "dev-cli-budget-1",
					"consentRevision":  1,
					"uploadAuthorized": true,
					"revoked":          false,
				},
			})
		case "/v1/ingest/batches":
			var batch struct {
				BatchID string           `json:"batchId"`
				Records []map[string]any `json:"records"`
			}
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				t.Errorf("invalid ingest body: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			ingests++
			mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]any{"batch": map[string]any{
				"batchId":         batch.BatchID,
				"status":          "accepted",
				"acceptedRecords": len(batch.Records),
				"rejectedRecords": 0,
				"replay":          false,
				"receivedAt":      time.Now().UTC().Format(time.RFC3339),
			}})
		case "/v1/devices/tool-status":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"accepted": true})
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
	defer toktrailServer.Close()

	connectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(connect.Config{
			SchemaVersion: 1,
			ServerURL:     toktrailServer.URL,
			ApplicationID: "app-cli",
			SubjectID:     "sub-cli",
			Tools:         []string{"Codex"},
			ExpiresAt:     time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339),
		})
	}))
	defer connectServer.Close()

	for i := 1; i <= 3; i++ {
		seedCLIDeviceBatch(t, stateDir, homeDir, fmt.Sprintf("cli-budget-%d", i), fmt.Sprintf("cli-budget-key-%d", i), time.Duration(i)*time.Hour)
	}

	connectURL := fmt.Sprintf("%s/api/collector/connect#%s", connectServer.URL, strings.Repeat("3", 64))
	err := runConnect([]string{"--state-dir", stateDir, "--max-total-batches", "2", connectURL})
	if err == nil || !errors.Is(err, connect.ErrSyncIncomplete) {
		t.Fatalf("a budget-capped connect must report the honest incomplete result, got %v", err)
	}
	mu.Lock()
	got := ingests
	mu.Unlock()
	if got != 2 {
		t.Fatalf("the CLI budget must cap the run's real POSTs at 2, got %d", got)
	}
	out, loadErr := outbox.New(stateDir).Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	pending := 0
	for _, b := range out.Batches {
		if b.Status == outbox.StatusPending {
			pending++
		}
	}
	if pending != 1 {
		t.Fatalf("the declined batch must stay pending, got %d", pending)
	}
}
