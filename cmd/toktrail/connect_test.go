package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/connect"
	"toktrail-collector/internal/local/grants"
)

func intPtr(n int) *int { return &n }

func TestRunConnectCLIValidation(t *testing.T) {
	t.Run("missing_args", func(t *testing.T) {
		err := runConnect([]string{})
		if err == nil || !strings.Contains(err.Error(), "usage: toktrail connect") {
			t.Fatalf("expected usage error, got %v", err)
		}
	})

	t.Run("too_many_args", func(t *testing.T) {
		err := runConnect([]string{"http://localhost:8080/connect#abc", "extra"})
		if err == nil || !strings.Contains(err.Error(), "usage: toktrail connect") {
			t.Fatalf("expected usage error, got %v", err)
		}
	})

	t.Run("invalid_flag", func(t *testing.T) {
		err := runConnect([]string{"--invalid-flag", "http://localhost:8080/connect#abc"})
		if err == nil {
			t.Fatalf("expected flag parsing error, got nil")
		}
	})

	t.Run("negative_max_total_batches", func(t *testing.T) {
		err := runConnect([]string{"--max-total-batches", "-1", "http://localhost:8080/connect#" + strings.Repeat("a", 64)})
		if err == nil || !strings.Contains(err.Error(), "--max-total-batches must be non-negative") {
			t.Fatalf("expected max-total-batches validation error, got %v", err)
		}
	})
}

func TestRunPeriodicRejectsInvalidBudgetFlags(t *testing.T) {
	err := runPeriodic([]string{"--sync-timeout", "0"})
	if err == nil || !strings.Contains(err.Error(), "--sync-timeout must be positive") {
		t.Fatalf("expected sync-timeout validation error, got %v", err)
	}
	err = runPeriodic([]string{"--max-total-batches", "-1"})
	if err == nil || !strings.Contains(err.Error(), "--max-total-batches must be non-negative") {
		t.Fatalf("expected max-total-batches validation error, got %v", err)
	}
	// --max-total-batches without --drain-only is now supported (the
	// shared device+cursor POST budget); a synthetic unbound state dir
	// proves the flag is accepted in full mode without touching real
	// state or performing any network access.
	if err := runPeriodic([]string{"--state-dir", t.TempDir(), "--max-total-batches", "10", "--sync-timeout", "30s"}); err != nil {
		t.Fatalf("--max-total-batches must be accepted without --drain-only, got %v", err)
	}
}

func TestWriteCollectionProgressJSON(t *testing.T) {
	var buf bytes.Buffer
	writeProgress := writeCollectionProgressJSON(&buf)
	writeProgress(collection.ProgressEvent{
		Kind:             collection.ProgressStageEnd,
		Stage:            "drain",
		StartedAt:        time.Date(2026, 10, 30, 1, 2, 3, 0, time.UTC),
		EndedAt:          time.Date(2026, 10, 30, 1, 2, 4, 0, time.UTC),
		Duration:         time.Second,
		SyncedBatches:    2,
		SyncedRecords:    1000,
		PendingRemaining: 3,
	})
	line := strings.TrimSpace(buf.String())
	var got map[string]any
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("invalid JSONL %q: %v", line, err)
	}
	if got["type"] != "collection_progress" || got["stage"] != "drain" || got["kind"] != collection.ProgressStageEnd {
		t.Fatalf("unexpected progress payload: %#v", got)
	}
	if got["durationMs"] != float64(1000) || got["syncedBatches"] != float64(2) || got["pendingRemaining"] != float64(3) {
		t.Fatalf("unexpected progress counts: %#v", got)
	}
}

func TestPrintHelpIncludesConnect(t *testing.T) {
	// Capture printHelp output through a concurrently drained pipe: the
	// help text (~7 KiB) exceeds the OS pipe buffer on some platforms,
	// so a write-first-read-later capture would deadlock.
	output, err := captureStdoutPiped(t, func() error {
		printHelp()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(output, "connect '<URL>'") {
		t.Fatalf("expected printHelp to document connect '<URL>', got:\n%s", output)
	}
	if !strings.Contains(output, "--drain-only") || !strings.Contains(output, "--sync-timeout") || !strings.Contains(output, "--max-total-batches") {
		t.Fatalf("expected printHelp to document periodic drain/timeout options, got:\n%s", output)
	}
}

type mockSchedulerRunner struct{}

func (mockSchedulerRunner) Run(name string, args ...string) error { return nil }

func TestRunConnectCLIIntegration(t *testing.T) {
	oldRunner := connectSchedulerRunner
	connectSchedulerRunner = mockSchedulerRunner{}
	defer func() { connectSchedulerRunner = oldRunner }()

	stateDir := t.TempDir()
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
	resolvedHome, err := os.UserHomeDir()
	if err != nil || filepath.Clean(resolvedHome) != filepath.Clean(homeDir) {
		t.Fatalf("CLI must use the synthetic home: got %q, err=%v", resolvedHome, err)
	}

	validTicket := strings.Repeat("7", 64)

	// Mock toktrail-server
	toktrailServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/devices/bind":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device": map[string]any{
					"deviceId":          "dev-cli-1",
					"applicationId":     "app-cli",
					"externalSubjectId": "sub-cli",
					"deviceName":        "dev-name",
					"platform":          "test-platform",
					"consentRevision":   1,
					"boundAt":           time.Now().UTC().Format(time.RFC3339),
				},
			})
		case "/v1/devices/self":
			// preflightSelf expects the device envelope under "device".
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device": map[string]any{
					"deviceId":         "dev-cli-1",
					"consentRevision":  1,
					"uploadAuthorized": true,
					"publicAuthorized": true,
					"revoked":          false,
				},
			})
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
	defer toktrailServer.Close()

	// Mock connect server
	connectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(connect.Config{
			SchemaVersion: 1,
			ServerURL:     toktrailServer.URL,
			ApplicationID: "app-cli",
			SubjectID:     "sub-cli",
			Tools:         []string{"Codex"},
			Days:          intPtr(7),
			ExpiresAt:     time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339),
		})
	}))
	defer connectServer.Close()

	// Create local tool dir
	codexDir := filepath.Join(homeDir, ".codex", "sessions")
	if err := os.MkdirAll(codexDir, 0o700); err != nil {
		t.Fatal(err)
	}

	connectURL := fmt.Sprintf("%s/api/collector/connect#%s", connectServer.URL, validTicket)
	err = runConnect([]string{"--state-dir", stateDir, connectURL})
	if err != nil {
		t.Fatalf("runConnect failed: %v", err)
	}
	enabled, err := grants.New(stateDir).Enabled()
	if err != nil {
		t.Fatal(err)
	}
	if len(enabled) != 1 || enabled[0].Source != "codex-jsonl" || filepath.Clean(enabled[0].Input) != filepath.Clean(codexDir) {
		t.Fatalf("CLI must discover only the synthetic Codex directory: %+v", enabled)
	}
}
