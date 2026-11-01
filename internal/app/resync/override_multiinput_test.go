package resync

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/overrides"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/registry"
)

// dshSession writes one minimal countable DSH turn into a session file so
// the deepseek-harness loader produces exactly one delta record keyed by
// the SESSION id (not the path): the same session id under two granted
// inputs produces the same recordKey, which is the cross-input overlap the
// override planner must handle.
func dshSession(t *testing.T, root, sessionID, usage string) string {
	t.Helper()
	dir := filepath.Join(root, "--demo--", "session-"+sessionID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	seq := 0
	next := func() (int, int64) {
		seq++
		return seq, int64(1698000000000) + int64(seq)*1000
	}
	s, m := next()
	lines := []string{fmt.Sprintf(`{"type":"session","version":4,"id":%q,"createdAt":%d,"isSeeded":false,"delegationDepth":0,"cwd":"/work/demo"}`, sessionID, m-1000)}
	_ = s
	turn := 1
	s2, m2 := next()
	lines = append(lines, fmt.Sprintf(`{"type":"turn/start","seq":%d,"time":%d,"data":{"turn":%d}}`, s2, m2, turn))
	s3, m3 := next()
	lines = append(lines, fmt.Sprintf(`{"type":"user/message","seq":%d,"time":%d,"data":{"turn":%d,"message":{"role":"user","content":"synthetic"}}}`, s3, m3, turn))
	s4, m4 := next()
	lines = append(lines, fmt.Sprintf(`{"type":"step/start","seq":%d,"time":%d,"data":{"turn":%d,"step":0}}`, s4, m4, turn))
	s5, m5 := next()
	lines = append(lines, fmt.Sprintf(`{"type":"assistant/message","seq":%d,"time":%d,"data":{"turn":%d,"step":0,"usage":%s,"message":{"source":{"kind":"model","provider":"deepseek","model":"deepseek-chat"}}}}`, s5, m5, turn, usage))
	s6, m6 := next()
	lines = append(lines, fmt.Sprintf(`{"type":"step/end","seq":%d,"time":%d,"data":{"turn":%d,"step":0}}`, s6, m6, turn))
	s7, m7 := next()
	lines = append(lines, fmt.Sprintf(`{"type":"turn/end","seq":%d,"time":%d,"data":{"turn":%d}}`, s7, m7, turn))
	path := filepath.Join(dir, "session.v1.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func scanDSH(t *testing.T, input string) int {
	t.Helper()
	loaded, err := registry.LoadRecordsForSource(adapter.Options{Source: "deepseek-harness", Input: input})
	if err != nil {
		t.Fatal(err)
	}
	return len(loaded.Records)
}

// TestOverrideMultiInputPendingAccounting verifies that pending attempts
// are accounted per (source, input): a source with several granted inputs
// never mixes one input's attempts into another's plan, and a pending
// attempt whose grant is missing is reported as withheld rather than
// silently attributed.
func TestOverrideMultiInputPendingAccounting(t *testing.T) {
	dir := t.TempDir()
	if err := statedir.New(dir).Save(statedir.DeviceState{DeviceID: "device-resync", DeviceSecret: strings.Repeat("a", 64), ServerURL: "http://srv"}); err != nil {
		t.Fatal(err)
	}
	inputA := filepath.Join(dir, "dsh", "a")
	inputB := filepath.Join(dir, "dsh", "b")
	for _, d := range []string{inputA, inputB} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := grants.New(dir).Enable("deepseek-harness", inputA); err != nil {
		t.Fatal(err)
	}
	if _, err := grants.New(dir).Enable("deepseek-harness", inputB); err != nil {
		t.Fatal(err)
	}
	dshSession(t, inputA, "SESSION-A", `{"inputTokens":100,"outputTokens":20}`)
	dshSession(t, inputB, "SESSION-B", `{"inputTokens":50,"outputTokens":10}`)
	if n := scanDSH(t, inputA); n != 1 {
		t.Fatalf("input A must scan one record, got %d", n)
	}
	if n := scanDSH(t, inputB); n != 1 {
		t.Fatalf("input B must scan one record, got %d", n)
	}
	// A pending attempt belonging to input B only.
	at := time.Now().UTC()
	ledger := overrides.Ledger{
		Schema: overrides.Schema, DeviceID: "device-resync", ServerURL: "http://srv",
		Entries: map[string]overrides.Entry{
			"deepseek-harness:pending-b": {
				RecordKey: "deepseek-harness:pending-b", Source: "deepseek-harness", Input: inputB,
				PendingRecord:    record("deepseek-harness:pending-b", "2026-10-20T01:05:00Z"),
				PendingAttemptID: "oa-b", Status: overrides.StatusPending, PendingSince: &at, UpdatedAt: at,
			},
			"deepseek-harness:pending-gone": {
				RecordKey: "deepseek-harness:pending-gone", Source: "deepseek-harness", Input: filepath.Join(dir, "dsh", "gone"),
				PendingRecord:    record("deepseek-harness:pending-gone", "2026-10-20T01:06:00Z"),
				PendingAttemptID: "oa-g", Status: overrides.StatusPending, PendingSince: &at, UpdatedAt: at,
			},
		},
	}
	if err := overrides.New(dir).Save(ledger); err != nil {
		t.Fatal(err)
	}
	st, err := statedir.New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	plan, delta, err := planOverride(dir, st, "http://srv", ledger)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Sources) != 2 {
		t.Fatalf("expected one plan entry per granted input, got %d", len(plan.Sources))
	}
	for _, sp := range plan.Sources {
		if sp.Input == inputB && sp.FrozenAttempts != 1 {
			t.Fatalf("input B must carry its own pending attempt, got %d", sp.FrozenAttempts)
		}
		if sp.Input == inputA && sp.FrozenAttempts != 0 {
			t.Fatalf("input A must not carry input B's pending attempt, got %d", sp.FrozenAttempts)
		}
	}
	if plan.WithheldNoGrant != 1 {
		t.Fatalf("the pending attempt with no enabled grant must be reported withheld, got %d", plan.WithheldNoGrant)
	}
	if len(delta) != 2 {
		t.Fatalf("both scanned records are new (no stored baseline) and must join the delta, got %d", len(delta))
	}
}

// TestOverrideCrossInputSameKeyFailsClosed verifies that two granted inputs
// producing the SAME recordKey (the DSH session-id key scope) with
// DIFFERENT content block the whole pass instead of silently choosing one.
func TestOverrideCrossInputSameKeyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := statedir.New(dir).Save(statedir.DeviceState{DeviceID: "device-resync", DeviceSecret: strings.Repeat("a", 64), ServerURL: "http://srv"}); err != nil {
		t.Fatal(err)
	}
	inputA := filepath.Join(dir, "dsh", "a")
	inputB := filepath.Join(dir, "dsh", "b")
	for _, d := range []string{inputA, inputB} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := grants.New(dir).Enable("deepseek-harness", inputA); err != nil {
		t.Fatal(err)
	}
	if _, err := grants.New(dir).Enable("deepseek-harness", inputB); err != nil {
		t.Fatal(err)
	}
	// Same session id under both inputs: identical record keys. Different
	// usage samples: conflicting content.
	dshSession(t, inputA, "SESSION-OVERLAP", `{"inputTokens":100,"outputTokens":20}`)
	dshSession(t, inputB, "SESSION-OVERLAP", `{"inputTokens":200,"outputTokens":40}`)
	st, err := statedir.New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = planOverride(dir, st, "http://srv", overrides.Ledger{})
	if err == nil || !strings.Contains(err.Error(), "conflicting content under two granted inputs") {
		t.Fatalf("a cross-input same-key conflict must fail closed: %v", err)
	}
}
