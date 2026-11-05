package collection

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/app/diagnostic"
	"toktrail-collector/internal/local/knowncache"
	"toktrail-collector/internal/local/scanledger"
	"toktrail-collector/internal/source/adapter"
)

// A state directory written by an older collector (pending batches without
// record windows, no scan ledger, no known-record cache) must keep working
// after the upgrade: the backlog still drains, the next scan exports, and the
// new accelerators appear only as a side effect.
func TestLegacyStateUpgradesAndRecordsScanState(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)

	// Legacy backlog: a pending batch with no record window at all.
	seedPendingBatch(t, stateDir, "legacy-batch", time.Time{}, time.Time{})
	// Legacy grants: a codex source the new code will scan.
	sessions := filepath.Join(t.TempDir(), "codex")
	writeMonotonicCodexSession(t, sessions, "a.jsonl", 4)
	enableGrant(t, stateDir, "codex-jsonl", sessions)

	// Doctor before any run: no incremental state yet, and that is not a
	// failure.
	before, err := diagnostic.Doctor(diagnostic.DoctorOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("doctor failed on a legacy state directory: %v", err)
	}
	found := false
	for _, check := range before.Checks {
		if check.Name == "scan-cache" {
			found = true
			if !strings.Contains(check.Detail, "no incremental scan state yet") {
				t.Fatalf("unexpected pre-run scan-cache detail: %q", check.Detail)
			}
		}
	}
	if !found {
		t.Fatalf("doctor must report the scan-cache check, got %+v", before.Checks)
	}

	// The upgraded collector runs: legacy backlog drains, new records export.
	res, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("run on a legacy state directory failed: %v", err)
	}
	if res.ExportedRecords != 3 {
		t.Fatalf("exported %d records, want 3", res.ExportedRecords)
	}
	pending, synced := pendingIDs(t, stateDir)
	if len(pending) != 0 || len(synced) != 2 {
		t.Fatalf("legacy backlog must drain alongside the new export, pending=%v synced=%v", pending, synced)
	}

	// The accelerators now exist and doctor reports them.
	states, existed, err := scanledger.New(stateDir).Load(adapter.CodexJSONLSource)
	if err != nil || !existed || len(states) != 1 {
		t.Fatalf("scan ledger = (%d states, existed=%v, err=%v), want one file", len(states), existed, err)
	}
	if _, err := os.Stat(knowncache.New(stateDir).Path(adapter.CodexJSONLSource)); err != nil {
		t.Fatalf("known-record cache missing after the upgrade run: %v", err)
	}
	after, err := diagnostic.Doctor(diagnostic.DoctorOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("doctor failed after the upgrade run: %v", err)
	}
	for _, check := range after.Checks {
		if check.Name == "scan-cache" && !strings.Contains(check.Detail, "covering 1 file") {
			t.Fatalf("post-run scan-cache detail = %q, want it to cover one file", check.Detail)
		}
	}

	// A second run finds nothing new: the upgrade did not change the
	// steady-state behaviour.
	quiet, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("second run failed: %v", err)
	}
	if quiet.ExportedRecords != 0 {
		t.Fatalf("second run exported %d records, want 0", quiet.ExportedRecords)
	}
}
