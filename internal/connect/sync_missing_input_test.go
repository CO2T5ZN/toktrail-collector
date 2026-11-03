package connect

// Regressions for the missing-input reclassification on the connect
// side: never-installed optional tools must not read as incompleteness
// (with or without the NoGrants shape), and the initial-round/backlog
// concern count must merge by UNIQUE tool so a tool restricted in both
// rounds counts once while a real restriction from either round is
// never dropped.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/app/collection"
)

// TestEvaluateIncompleteMergesConcernToolsAcrossRounds pins the
// duplicate-counting fix: a tool whose unclassifiable restriction
// appears in BOTH the initial round's and a backlog pass's pending map
// counts once, a tool restricted in only one round still counts, and a
// never-installed tool (missing_input) counts from neither round.
func TestEvaluateIncompleteMergesConcernToolsAcrossRounds(t *testing.T) {
	syncRes := &SyncResult{
		Collection: collection.Result{
			GrantSync: collection.GrantSync{
				Active: true,
				Pending: map[string]string{
					// Restricted in both rounds: must count ONCE.
					"Codex": "some future restriction format",
					// Never installed: must count from neither round.
					"Claude Code": "default directory not found: /missing/home/.claude/projects",
				},
			},
		},
		Backlog: BacklogSummary{
			Passes: 2,
			Result: collection.Result{
				GrantSync: collection.GrantSync{
					Active: true,
					Pending: map[string]string{
						"Codex": "some future restriction format",
						// Restricted only in the backlog round: must count.
						"Qwen Code": "another future restriction format",
						// Never installed in the backlog round too.
						"Claude Code": "default directory not found: /missing/home/.claude/projects",
					},
				},
			},
		},
	}
	reasons := evaluateIncomplete(syncRes, SyncOptions{StateDir: t.TempDir()})

	var concernReasons []string
	for _, reason := range reasons {
		if strings.Contains(reason, "authorized source(s) are not covered") {
			concernReasons = append(concernReasons, reason)
		}
	}
	if len(concernReasons) != 1 {
		t.Fatalf("exactly one merged concern reason must be reported, got %#v (all: %#v)", concernReasons, reasons)
	}
	if !strings.Contains(concernReasons[0], "2 authorized source(s)") {
		t.Fatalf("the count must merge by unique tool (Codex + Qwen Code = 2), got %q", concernReasons[0])
	}
	if strings.Contains(concernReasons[0], "default input is missing") {
		t.Fatalf("the concern reason must no longer describe missing inputs, got %q", concernReasons[0])
	}
}

// probeFailServers builds the minimal connect server pair for a
// default-directory probe test over the named tools: it counts the
// tool-status POSTs (a fabricated not_detected must never be sent for
// a probe that failed) and returns the connect URL.
func probeFailServers(t *testing.T, tools []string) (string, *int) {
	t.Helper()
	toolStatusPosts := 0
	toktrailServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/devices/bind":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"device": map[string]any{
				"deviceId": "dev-probe-1", "applicationId": "app-probe", "externalSubjectId": "sub-probe",
				"deviceName": "dev-name", "platform": "test", "consentRevision": 1,
				"boundAt": time.Now().UTC().Format(time.RFC3339),
			}})
		case "/v1/devices/tool-status":
			toolStatusPosts++
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{})
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
	t.Cleanup(toktrailServer.Close)

	connectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(Config{
			SchemaVersion: 1,
			ServerURL:     toktrailServer.URL,
			ApplicationID: "app-probe",
			SubjectID:     "sub-probe",
			Tools:         tools,
			Days:          intPtr(30),
			ExpiresAt:     time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		})
	}))
	t.Cleanup(connectServer.Close)
	connectURL := fmt.Sprintf("%s/api/collector/connect#%s", connectServer.URL, strings.Repeat("7", 64))
	return connectURL, &toolStatusPosts
}

// noGrantRecorded asserts the state directory holds no grant at all
// (or none containing want) — a failed probe must never leave a grant
// behind.
func noGrantRecorded(t *testing.T, stateDir, want string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(stateDir, "grants.json"))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), want) {
		t.Fatalf("no grant may be recorded over a failed probe, got %s", b)
	}
}

// TestConnectProbePermissionErrorFailsClosed pins the connect-side
// honest-error half: a default-directory probe failing with anything
// other than os.ErrNotExist — here an injected EACCES on the tool's
// parent directory — must fail the run with the probe error instead of
// reporting a fabricated not_detected status or silently skipping the
// tool. A truly absent directory keeps the normal not_detected skip.
//
// The permission error is injected through the per-instance
// Options.statDefaultDir hook rather than a chmod-000 directory:
// chmod does not make a directory unreadable to its owner on Windows
// and is bypassed entirely under root, so a real-filesystem fault
// would make this test pass or fail depending on the runner. The
// injected PathError carries the same shape os.Stat returns
// (errors.Is(err, os.ErrPermission)) and exercises the identical
// production classification. NOT covered here: an actual
// Windows ACL denial reaching the probe — the Go standard library
// cannot install deny ACLs, so that platform-specific wiring remains
// unverified.
func TestConnectProbePermissionErrorFailsClosed(t *testing.T) {
	connectURL, toolStatusPosts := probeFailServers(t, []string{"Qwen Code"})

	home := t.TempDir()
	// The qwen tool's root directory exists with its projects child, as
	// it would on a machine where the directory became unreadable.
	qwenRoot := filepath.Join(home, ".qwen")
	if err := os.MkdirAll(filepath.Join(qwenRoot, "projects"), 0o700); err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	_, err := Run(context.Background(), Options{
		URL:        connectURL,
		StateDir:   stateDir,
		HomeDir:    home,
		HTTPClient: http.DefaultClient,
		statDefaultDir: func(name string) (fs.FileInfo, error) {
			// Every probe of the qwen tree fails with EACCES — the
			// same error os.Stat returns for an unreadable parent —
			// never with ErrNotExist.
			return nil, &fs.PathError{Op: "stat", Path: name, Err: os.ErrPermission}
		},
	})
	if err == nil {
		t.Fatal("a permission-denied default-directory probe must fail connect")
	}
	if !strings.Contains(err.Error(), "probe default directory for tool") || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("the probe error must surface verbatim, got %v", err)
	}
	// No fabricated probe statuses were reported for the unreadable
	// tool, and no grants were recorded.
	if *toolStatusPosts != 0 {
		t.Fatalf("an unreadable probe must not report a fabricated not_detected status, got %d posts", *toolStatusPosts)
	}
	noGrantRecorded(t, stateDir, "qwen")
}

// TestConnectProbeNonDirectoryPathFailsClosed pins the connect-side
// shape rule: every registry default path is a directory, so a regular
// file at that path is a real local fault — connect fails with an
// explicit error instead of reporting a fabricated not_detected
// status. Custom user grants pointing at files never pass through the
// default-directory probe and are unaffected.
func TestConnectProbeNonDirectoryPathFailsClosed(t *testing.T) {
	connectURL, toolStatusPosts := probeFailServers(t, []string{"Qwen Code"})

	home := t.TempDir()
	// A regular file sits where the tool's default DIRECTORY belongs.
	qwenRoot := filepath.Join(home, ".qwen")
	if err := os.MkdirAll(qwenRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(qwenRoot, "projects"), []byte("not a directory\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	_, err := Run(context.Background(), Options{
		URL:        connectURL,
		StateDir:   stateDir,
		HomeDir:    home,
		HTTPClient: http.DefaultClient,
	})
	if err == nil {
		t.Fatal("a non-directory default path must fail connect")
	}
	if !strings.Contains(err.Error(), "probe default directory for tool") || !strings.Contains(err.Error(), "exists but is not a directory") {
		t.Fatalf("the non-directory probe error must surface explicitly, got %v", err)
	}
	if *toolStatusPosts != 0 {
		t.Fatalf("a non-directory path must not report a fabricated not_detected status, got %d posts", *toolStatusPosts)
	}
	noGrantRecorded(t, stateDir, "qwen")
}

// TestEvaluateIncompleteMissingInputAloneIsNotIncomplete pins the
// steady state of a device that installed none of its authorized
// optional tools: the pending map is full of missing_input
// restrictions, but no executable local work is owed — no
// incompleteness reason at all.
func TestEvaluateIncompleteMissingInputAloneIsNotIncomplete(t *testing.T) {
	syncRes := &SyncResult{
		Collection: collection.Result{
			GrantSync: collection.GrantSync{
				Active: true,
				Pending: map[string]string{
					"Codex":            "default directory not found: /missing/.codex/sessions",
					"Claude Code":      "default directory not found: /missing/.claude/projects",
					"Qwen Code":        "default directory not found: /missing/.qwen/projects",
					"DeepSeek Harness": "default directory not found: /missing/.dsh/sessions",
				},
			},
			PendingRemaining: 0,
		},
	}
	reasons := evaluateIncomplete(syncRes, SyncOptions{StateDir: t.TempDir()})
	if len(reasons) != 0 {
		t.Fatalf("never-installed optional tools must not be incompleteness, got %#v", reasons)
	}
}

// TestEvaluateIncompleteAllNeverInstalledNoGrantsSkipsClean pins the
// NoGrants boundary: connect's activated-tool list is EMPTY when no
// authorized tool was detected locally (the probe marked them all
// not_detected), so the "no enabled source grants despite authorized
// tools" reason must not fire — the all-never-installed state is a
// normal skip. The contrast case keeps the guard honest: a run whose
// setup DID activate local tools (structural evidence) yet collected
// under zero enabled grants still reports the reason.
func TestEvaluateIncompleteAllNeverInstalledNoGrantsSkipsClean(t *testing.T) {
	allMissing := &SyncResult{
		Collection: collection.Result{
			NoGrants: true,
			GrantSync: collection.GrantSync{
				Active: true,
				Pending: map[string]string{
					"Codex":       "default directory not found: /missing/.codex/sessions",
					"Claude Code": "default directory not found: /missing/.claude/projects",
				},
			},
		},
	}
	// connect.Run passes AuthorizedTools = the tools it ACTIVATED this
	// run; with every default directory absent that list is empty.
	reasons := evaluateIncomplete(allMissing, SyncOptions{StateDir: t.TempDir()})
	if len(reasons) != 0 {
		t.Fatalf("an all-never-installed run must skip clean, got %#v", reasons)
	}

	// The guard itself stays: tools were activated in setup (their
	// directories were detected) yet the collection round found no
	// enabled grants — a real anomaly that must surface.
	activated := &SyncResult{
		Collection: collection.Result{
			NoGrants: true,
			GrantSync: collection.GrantSync{
				Active: true,
			},
		},
	}
	reasons = evaluateIncomplete(activated, SyncOptions{
		StateDir:        t.TempDir(),
		AuthorizedTools: []string{"Codex"},
	})
	found := false
	for _, reason := range reasons {
		if strings.Contains(reason, "no enabled source grants despite authorized tools") {
			found = true
		}
	}
	if !found {
		t.Fatalf("activated tools with no enabled grants must stay an incompleteness, got %#v", reasons)
	}
}
