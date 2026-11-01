package main

// Security regression for the sync command's human output: a malicious
// (or compromised) server can answer a fully valid ingest with a 202
// receipt whose status string echoes the collector's own credential.
// The syncclient collapses untrusted receipt statuses and record-error
// codes to closed sets at the receiving point, so the actual CLI output
// must show the fixed "unknown" wording and must never carry the echoed
// secret. Everything here is synthetic: a temporary state directory,
// an httptest server, and a scripted hostile success receipt.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toktrail-collector/internal/local/statedir"
)

func TestSyncOutputNeverEchoesHostileReceiptStatus(t *testing.T) {
	const secret = "TOPSECRET-credential-echo-0123456789abcdef"
	const batchID = "batch-cli-safety-1"

	stateDir := t.TempDir()
	store := statedir.New(stateDir)
	if err := store.Save(statedir.DeviceState{
		ServerURL: "http://unused", DeviceID: "dev-1", DeviceSecret: strings.Repeat("c", 64),
	}); err != nil {
		t.Fatal(err)
	}
	batchFile := filepath.Join(t.TempDir(), "batch.json")
	batch := map[string]any{
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
	}
	b, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(batchFile, b, 0o600); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self":
			writeJSONForCmd(w, http.StatusOK, map[string]any{"device": map[string]any{
				"deviceId": "dev-1", "consentRevision": 7,
				"uploadAuthorized": true, "revoked": false,
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/batches":
			var got map[string]any
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Errorf("invalid ingest body: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			// A fully reconcilable success receipt whose status echoes
			// the device credential back at the collector.
			writeJSONForCmd(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
				"batchId":         batchID,
				"status":          secret,
				"acceptedRecords": 1,
				"rejectedRecords": 0,
				"replay":          false,
				"receivedAt":      "2026-10-20T10:12:00Z",
			}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Capture the actual CLI output of the sync command.
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	runErr := runSync([]string{"--server", server.URL, "--state-dir", stateDir, "--file", batchFile})
	_ = w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	output := buf.String()

	if runErr != nil {
		t.Fatalf("the hostile-but-valid receipt must still succeed, got %v", runErr)
	}
	if !strings.Contains(output, "synced batch") || !strings.Contains(output, "status=accepted") {
		t.Fatalf("output must show the counts-derived status, got: %s", output)
	}
	if strings.Contains(output, secret) {
		t.Fatalf("CLI output leaked the echoed credential: %s", output)
	}
	// Defense in depth: the persisted state carries the closed-set value
	// too, so later reads of the state cannot surface the hostile string.
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.LastSyncStatus != "accepted" {
		t.Fatalf("persisted status = %q, want the derived accepted", st.LastSyncStatus)
	}
}

func writeJSONForCmd(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
