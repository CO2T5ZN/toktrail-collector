package diagnostic

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/scheduler"
)

const testSecret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func fakeStatusServer(t *testing.T, requests *atomic.Int64) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"device": map[string]any{
				"deviceId": "dev-1", "applicationId": "app-1", "externalSubjectId": "sub-1",
				"deviceName": "collector", "platform": "darwin", "consentRevision": 7,
				"uploadAuthorized": true, "publicAuthorized": false, "revoked": false,
				"checkedAt": "2026-10-21T04:00:00Z",
			}})
			return
		}
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	return server
}

func bindDevice(t *testing.T, stateDir, serverURL string) {
	t.Helper()
	if err := statedir.New(stateDir).Save(statedir.DeviceState{
		ServerURL:    serverURL,
		DeviceID:     "dev-1",
		DeviceSecret: testSecret,
	}); err != nil {
		t.Fatal(err)
	}
}

func writeSession(t *testing.T, dir, name string, lines ...string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func claudeLine(timestamp, session, msgID string, input, output int) string {
	line := map[string]any{
		"type":      "assistant",
		"timestamp": timestamp,
		"sessionId": session,
		"message": map[string]any{"id": msgID, "usage": map[string]any{
			"input_tokens": input, "cache_read_input_tokens": 0,
			"cache_creation_input_tokens": 0, "output_tokens": output,
		}},
	}
	b, err := json.Marshal(line)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func seedPendingBatch(t *testing.T, stateDir, batchID string) {
	t.Helper()
	batchesDir := filepath.Join(stateDir, "batches")
	if err := os.MkdirAll(batchesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(batchesDir, batchID+".json")
	payload := map[string]any{"batchId": batchID, "records": []map[string]any{{
		"recordKey": batchID + "-record-1", "kind": "delta",
		"occurredAt": "2026-10-21T04:00:00Z", "tool": "usage-json",
		"input": "10", "cacheRead": "0", "cacheWrite": "0", "output": "5",
		"adapterVersion": "diagnostic-test-1", "sourceType": "fixture",
	}}}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{
		BatchID: batchID, File: path, Source: "usage-json", Input: path, RecordCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
}

func enableGrant(t *testing.T, stateDir, source, input string) {
	t.Helper()
	if _, err := grants.New(stateDir).Enable(source, input); err != nil {
		t.Fatal(err)
	}
}

func findCheck(t *testing.T, report DoctorReport, name string) Check {
	t.Helper()
	for _, c := range report.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("check %q not found in %#v", name, report.Checks)
	return Check{}
}

// ---------------------------------------------------------------------------
// privacy
// ---------------------------------------------------------------------------

// Privacy is strictly local: a bound device pointing at a live test server,
// an enabled grant, and pending batches must not produce a single HTTP
// request.
func TestPrivacyIsLocalOnly(t *testing.T) {
	stateDir := t.TempDir()
	var requests atomic.Int64
	server := fakeStatusServer(t, &requests)
	bindDevice(t, stateDir, server.URL)

	sessions := filepath.Join(t.TempDir(), "sessions")
	writeSession(t, sessions, "session-a.jsonl",
		claudeLine("2026-10-21T04:00:00Z", "s1", "msg_1", 10, 5),
		claudeLine("2026-10-21T04:01:00Z", "s1", "msg_2", 7, 4))
	enableGrant(t, stateDir, "claude-code-jsonl", sessions)
	seedPendingBatch(t, stateDir, "batch-privacy-1")

	reports, err := Privacy(PrivacyOptions{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 {
		t.Fatalf("expected one report, got %d", len(reports))
	}
	r := reports[0]
	if r.Source != "claude-code-jsonl" || r.Input != sessions {
		t.Fatalf("unexpected report target: %#v", r)
	}
	if r.RecordCount != 2 || r.ValidRecords != 2 || r.UploadSafeRecords != 2 {
		t.Fatalf("unexpected scan summary: %#v", r)
	}
	if r.OutboxPending != 1 || r.OutboxPendingRecords != 1 {
		t.Fatalf("pending outbox must be reported: %#v", r)
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("privacy must not touch the network, got %d requests", n)
	}
}

// An explicit source+input narrows the report without any persisted grant.
func TestPrivacyExplicitSourceInput(t *testing.T) {
	stateDir := t.TempDir()
	sessions := filepath.Join(t.TempDir(), "sessions")
	writeSession(t, sessions, "session-a.jsonl",
		claudeLine("2026-10-21T04:00:00Z", "s1", "msg_1", 10, 5))

	reports, err := Privacy(PrivacyOptions{StateDir: stateDir, Source: "claude-code-jsonl", Input: sessions})
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 || reports[0].RecordCount != 1 {
		t.Fatalf("unexpected reports: %#v", reports)
	}

	// Half a grant must be rejected.
	if _, err := Privacy(PrivacyOptions{StateDir: stateDir, Source: "claude-code-jsonl"}); err == nil {
		t.Fatal("expected an error for source without input")
	}
	if _, err := Privacy(PrivacyOptions{StateDir: stateDir, Input: sessions}); err == nil {
		t.Fatal("expected an error for input without source")
	}
	// Unknown sources stay rejected.
	if _, err := Privacy(PrivacyOptions{StateDir: stateDir, Source: "bogus", Input: sessions}); err == nil {
		t.Fatal("expected an error for an unknown source")
	}
}

// No enabled grants means an empty report, not an error, and no network.
func TestPrivacyNoGrantsIsEmpty(t *testing.T) {
	stateDir := t.TempDir()
	var requests atomic.Int64
	server := fakeStatusServer(t, &requests)
	bindDevice(t, stateDir, server.URL)

	reports, err := Privacy(PrivacyOptions{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if reports != nil {
		t.Fatalf("expected no reports without grants, got %#v", reports)
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("privacy must not touch the network, got %d requests", n)
	}
}

func TestPrivacyRequiresStateDir(t *testing.T) {
	if _, err := Privacy(PrivacyOptions{}); err == nil {
		t.Fatal("expected an error for a missing state dir")
	}
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

// Doctor with no --check-server is fully local and reports the unbound,
// grant-less state as warnings, not failures.
func TestDoctorLocalOnlyUnbound(t *testing.T) {
	stateDir := t.TempDir()
	var requests atomic.Int64
	server := fakeStatusServer(t, &requests)
	bindDevice(t, stateDir, server.URL)
	// Wipe the binding to exercise the unbound path.
	if err := statedir.New(stateDir).Save(statedir.DeviceState{ServerURL: server.URL}); err != nil {
		t.Fatal(err)
	}

	home := t.TempDir()
	report, err := Doctor(DoctorOptions{
		StateDir: stateDir,
		Binary:   filepath.Join(t.TempDir(), "toktrail"),
		HomeDir:  home,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Failed() {
		t.Fatalf("unbound state is a warning, not a failure: %#v", report.Checks)
	}
	if c := findCheck(t, report, "binding"); c.Status != CheckWarn {
		t.Fatalf("expected binding warning, got %#v", c)
	}
	if c := findCheck(t, report, "grants"); c.Status != CheckWarn {
		t.Fatalf("expected grants warning, got %#v", c)
	}
	if c := findCheck(t, report, "scheduler"); c.Status != CheckWarn {
		t.Fatalf("expected scheduler warning for no task, got %#v", c)
	}
	if c := findCheck(t, report, "server"); c.Status != CheckSkipped {
		t.Fatalf("expected server check to be skipped, got %#v", c)
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("local doctor must not touch the network, got %d requests", n)
	}
}

// --check-server is the only networked check and reports server consent.
func TestDoctorCheckServerUsesNetworkOnlyWhenAsked(t *testing.T) {
	stateDir := t.TempDir()
	var requests atomic.Int64
	server := fakeStatusServer(t, &requests)
	bindDevice(t, stateDir, server.URL)
	seedPendingBatch(t, stateDir, "batch-doctor-1")

	report, err := Doctor(DoctorOptions{StateDir: stateDir, CheckServer: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.Failed() {
		t.Fatalf("healthy bound device must not fail: %#v", report.Checks)
	}
	if c := findCheck(t, report, "server"); c.Status != CheckOK {
		t.Fatalf("expected server check ok, got %#v", c)
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("expected exactly one self request, got %d", n)
	}
	if c := findCheck(t, report, "outbox"); c.Status != CheckOK {
		t.Fatalf("expected outbox ok with pending batch, got %#v", c)
	}
}

// Doctor recognizes an installed task (rendered into a temp home with an
// injected runner; no real host scheduler is touched).
func TestDoctorDetectsInstalledTask(t *testing.T) {
	stateDir := t.TempDir()
	home := t.TempDir()
	binary := filepath.Join(t.TempDir(), "path with space", "toktrail")
	if err := os.MkdirAll(filepath.Dir(binary), 0o700); err != nil {
		t.Fatal(err)
	}
	// Install validates the scheduled binary path even in dry-run mode.
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	enableGrant(t, stateDir, "claude-code-jsonl", t.TempDir())

	plan, err := scheduler.Install(scheduler.InstallOptions{
		Config: scheduler.TaskConfig{
			Platform: runtime.GOOS,
			StateDir: stateDir,
			Binary:   binary,
			Interval: scheduler.DefaultInterval,
			HomeDir:  home,
		},
		DryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Files) == 0 {
		t.Fatal("expected install plan files")
	}
	docOpts := DoctorOptions{
		StateDir: stateDir,
		Binary:   binary,
		HomeDir:  home,
	}

	if runtime.GOOS == "windows" {
		docOpts.Runner = &mockTaskRunner{xmlOutput: plan.Files[0].Content}
	} else {
		for _, f := range plan.Files {
			if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.Path, []byte(f.Content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}

	report, err := Doctor(docOpts)
	if err != nil {
		t.Fatal(err)
	}
	if !report.TaskInstalled {
		t.Fatalf("expected the rendered task to be detected: %#v", report.Checks)
	}
	if len(report.TaskFiles) == 0 {
		t.Fatal("expected task files to be listed")
	}
	if c := findCheck(t, report, "scheduler"); c.Status != CheckOK {
		t.Fatalf("expected scheduler check ok, got %#v", c)
	}
}

// A granted input that disappeared is a failure, not a warning.
func TestDoctorFailsOnMissingGrantedInput(t *testing.T) {
	stateDir := t.TempDir()
	sessions := filepath.Join(t.TempDir(), "sessions")
	writeSession(t, sessions, "session-a.jsonl",
		claudeLine("2026-10-21T04:00:00Z", "s1", "msg_1", 10, 5))
	enableGrant(t, stateDir, "claude-code-jsonl", sessions)
	// The whole granted input directory disappears (not just one file).
	if err := os.RemoveAll(sessions); err != nil {
		t.Fatal(err)
	}

	report, err := Doctor(DoctorOptions{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Failed() {
		t.Fatalf("missing granted input must fail: %#v", report.Checks)
	}
}

// An unreadable state file fails the state check and stops early without
// returning an error.
func TestDoctorFailsOnUnreadableState(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.WriteFile(statedir.New(stateDir).Path(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Doctor(DoctorOptions{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Failed() {
		t.Fatalf("unreadable state must fail: %#v", report.Checks)
	}
	if c := findCheck(t, report, "state"); c.Status != CheckFail {
		t.Fatalf("expected state failure, got %#v", c)
	}
}

func TestDoctorRequiresStateDir(t *testing.T) {
	if _, err := Doctor(DoctorOptions{}); err == nil {
		t.Fatal("expected an error for a missing state dir")
	}
}

type mockTaskRunner struct {
	xmlOutput string
}

func (m *mockTaskRunner) Run(name string, args ...string) error {
	return nil
}

func (m *mockTaskRunner) RunOutput(name string, args ...string) ([]byte, error) {
	return []byte(m.xmlOutput), nil
}

// installScheduleForTest writes the real scheduler registration for one binary
// into a temp home, so the identity check has something true to compare against.
func installScheduleForTest(t *testing.T, stateDir, home, binary string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(binary), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	plan, err := scheduler.Install(scheduler.InstallOptions{
		Config: scheduler.TaskConfig{
			Platform: runtime.GOOS,
			StateDir: stateDir,
			Binary:   binary,
			Interval: scheduler.DefaultInterval,
			HomeDir:  home,
		},
		DryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("the windows task is registered by schtasks; covered by the scheduler package tests")
	}
	for _, f := range plan.Files {
		if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.Path, []byte(f.Content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// An upgrade replaces one path. If the schedule starts a different copy, doctor
// must say so instead of reporting a healthy install — that is the difference
// between "I upgraded" and "the scheduled runs use the new binary".
func TestDoctorBinaryIdentity(t *testing.T) {
	stateDir := t.TempDir()
	home := t.TempDir()
	scheduled := filepath.Join(t.TempDir(), "scheduled", "toktrail")
	installScheduleForTest(t, stateDir, home, scheduled)

	t.Run("mismatch_fails_with_both_paths", func(t *testing.T) {
		other := filepath.Join(t.TempDir(), "other", "toktrail")
		if err := os.MkdirAll(filepath.Dir(other), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(other, []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		report, err := Doctor(DoctorOptions{
			StateDir: stateDir, Binary: other, HomeDir: home, Version: "v0.6.0",
			LookPath: func(string) (string, error) { return "", os.ErrNotExist },
		})
		if err != nil {
			t.Fatal(err)
		}
		check := findCheck(t, report, "binary")
		if check.Status != CheckFail {
			t.Fatalf("status = %s, want fail: %s", check.Status, check.Detail)
		}
		if !strings.Contains(check.Detail, scheduled) || !strings.Contains(check.Detail, other) {
			t.Fatalf("the failure must name both paths, got %q", check.Detail)
		}
		if !strings.Contains(check.Detail, "would not affect scheduled runs") {
			t.Fatalf("the failure must state the consequence, got %q", check.Detail)
		}
	})

	t.Run("same_binary_is_ok", func(t *testing.T) {
		report, err := Doctor(DoctorOptions{
			StateDir: stateDir, Binary: scheduled, HomeDir: home, Version: "v0.6.0",
			LookPath: func(string) (string, error) { return scheduled, nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		check := findCheck(t, report, "binary")
		if check.Status != CheckOK {
			t.Fatalf("status = %s, want ok: %s", check.Status, check.Detail)
		}
		if !strings.Contains(check.Detail, "v0.6.0") {
			t.Fatalf("the ok line must name the version, got %q", check.Detail)
		}
	})

	t.Run("path_copy_differs_warns", func(t *testing.T) {
		pathCopy := filepath.Join(t.TempDir(), "path", "toktrail")
		if err := os.MkdirAll(filepath.Dir(pathCopy), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pathCopy, []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		report, err := Doctor(DoctorOptions{
			StateDir: t.TempDir(), Binary: pathCopy, HomeDir: t.TempDir(), Version: "v0.6.0",
			LookPath: func(string) (string, error) { return scheduled, nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		check := findCheck(t, report, "binary")
		if check.Status != CheckWarn {
			t.Fatalf("status = %s, want warn: %s", check.Status, check.Detail)
		}
	})

	t.Run("symlinked_copy_is_the_same_install", func(t *testing.T) {
		linkDir := t.TempDir()
		link := filepath.Join(linkDir, "toktrail")
		if err := os.Symlink(scheduled, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		report, err := Doctor(DoctorOptions{
			StateDir: stateDir, Binary: link, HomeDir: home, Version: "v0.6.0",
			LookPath: func(string) (string, error) { return link, nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		if check := findCheck(t, report, "binary"); check.Status != CheckOK {
			t.Fatalf("a symlink to the scheduled binary must not fail: %s", check.Detail)
		}
	})
}

// A scheduler query that fails must not read as "no task installed": that would
// report a healthy-looking install whose identity was never verified. It is a
// warning, exactly like the neighbouring scheduler check.
func TestDoctorBinaryIdentityWarnsWhenTheTaskCannotBeInspected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the POSIX registration is a plist file; Windows uses schtasks")
	}
	stateDir := t.TempDir()
	home := t.TempDir()
	binary := filepath.Join(t.TempDir(), "toktrail")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	plan, err := scheduler.RenderInstall(scheduler.TaskConfig{
		Platform: runtime.GOOS, StateDir: stateDir, Binary: binary,
		Interval: scheduler.DefaultInterval, HomeDir: home,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Files) == 0 {
		t.Skip("no registration file on this platform")
	}
	blocked := ""
	for _, f := range plan.Files {
		if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(f.Path, ".service") || strings.HasSuffix(f.Path, ".plist") {
			// RegisteredBinary reads the service/plist, not the systemd
			// timer. A directory forces a read error even when running as
			// root, which can bypass chmod-based permission restrictions.
			if err := os.Mkdir(f.Path, 0o700); err != nil {
				t.Fatal(err)
			}
			blocked = f.Path
			continue
		}
		if err := os.WriteFile(f.Path, []byte(f.Content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if blocked == "" {
		t.Fatal("no service or plist registration was rendered")
	}
	if _, err := os.ReadFile(blocked); err == nil {
		t.Fatal("the registration fixture must fail to read")
	}

	report, err := Doctor(DoctorOptions{
		StateDir: stateDir, Binary: binary, HomeDir: home, Version: "v0.6.0",
		LookPath: func(string) (string, error) { return binary, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if check := findCheck(t, report, "binary"); check.Status != CheckWarn {
		t.Fatalf("an unreadable registration must warn, got %s: %s", check.Status, check.Detail)
	}
}
