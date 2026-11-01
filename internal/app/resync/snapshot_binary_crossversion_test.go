package resync

// Binary-level cross-version journal re-planning divergence (P6 rollback
// boundary; the gated counterpart of snapshot_crossversion_compat_test.go).
//
// WHAT THIS TEST EXECUTES
//
// Two REAL collector binaries — the OLD one (repo HEAD, predating the
// snapshot universe) and the NEW one (this working tree) — each run
// `toktrail resync --all --yes` against their own independent copy of the
// SAME synthetic state: a schema-2 journal built by the REAL new
// machinery (six synced outbox batches, the first three frozen as the
// snapshot universe, the recorded scope baseline at revision 1) and the
// SAME live scope change (a fake /v1/devices/self answering revision 2 —
// the consent drift that triggers a re-plan on resume).
//
// The design stops a re-planning run BEFORE any ingest upload (each run
// performs its authorization self GETs and may POST control-plane
// tool-status reports), so the observable divergence is the re-planned
// RANGE persisted to the journal plus the run's report:
//
//	OLD binary: its decode drops the unknown snapshot field, so its
//	  re-plan covers the COMPLETE synced history (6 batches, including
//	  the three synced after the capture), and the journal it writes
//	  back has no snapshot — the freeze is permanently lost for that
//	  job lineage, even after upgrading forward again.
//	NEW binary: the re-plan stays inside the frozen universe (3
//	  batches, the after-capture batches stay excluded), and the
//	  written journal keeps the snapshot.
//
// HONESTY BOUNDARIES (do not overstate):
//   - This test asserts the traffic OBSERVED on its own fake listener:
//     per run at least one authenticated GET /v1/devices/self, plus
//     whatever control-plane POST /v1/devices/tool-status reports the
//     collector chooses to make (answered 404 — an old-server-compatible
//     non-answer that keeps the run on its re-plan-stop path). ZERO
//     ingest uploads: any /v1/ingest/batches request — or any request
//     outside the two control-plane shapes above — fails the test. This
//     is an observation of these runs on THIS listener, and it is NOT a
//     general "zero server-side side effects" claim: a FOLLOW-UP run
//     that executes the re-planned pass WOULD retransmit — six batches
//     under the old binary versus three under the new — and that
//     cross-version replay idempotency is unverified design intent, not
//     something proven here. The follow-up run is deliberately not
//     executed.
//   - The old binary is whatever TOKTRAIL_CROSS_OLD_COLLECTOR_BIN points
//     at; the test verifies shape, hashes it for the record, and asserts
//     its BEHAVIOR against the fake endpoint. It does not verify the
//     binary's provenance.
//
// ISOLATION:
//   - GATED: nothing runs unless TOKTRAIL_CROSS_ENABLE is exactly "1"
//     and both binaries are provided via TOKTRAIL_CROSS_OLD_COLLECTOR_BIN
//     / TOKTRAIL_CROSS_NEW_COLLECTOR_BIN. A plain `go test` skips.
//   - The inherited environment is rejected when it carries PG-prefixed
//     variables or DATABASE_URL/TEST_DATABASE_URL (key names only —
//     values are never read or logged): their presence means an
//     unexpected environment (the audited runner scrubs them).
//   - Children run with a from-scratch environment (PATH + a dedicated
//     scene HOME only) and explicit --state-dir / --server flags.
//   - No PostgreSQL, no real user state: the only server surface is an
//     in-process httptest listener held by THIS test process; all state
//     lives in throwaway scene directories.
//   - Subprocess discipline: exactly ONE cmd.Wait per child (a single
//     goroutine), signals only ever sent while Wait has not returned
//     (a reaped PID is never signaled, so PID reuse can never be hit),
//     and a timeout keeps the scene for inspection.
//
// SCENE RETENTION: the scene directory is removed only when the test
// passed, every child was PROVEN reaped, and the removal safety checks
// (mirroring the audited crossversion scene discipline) all hold: the
// directory must be exactly the one this scene created — same path, same
// inode (os.SameFile), canonical, a direct prefixed child of the
// physical temp root. Any failure keeps everything.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncclient"
)

// crossBinTimeout bounds one collector child; the run is one GET plus
// local file IO, so this is generous headroom.
const crossBinTimeout = 120 * time.Second

// crossBinReplanCountRe matches both generations' stop message:
//
//	OLD: "The complete synced history was re-planned as job <id> (N batch(es)) ..."
//	NEW: "The job was re-planned as <id> (N batch(es)) under the fresh scope ..."
var crossBinReplanCountRe = regexp.MustCompile(`re-planned as (?:job )?[^\s(]+ \((\d+) batch\(es\)\)`)

// crossBinRequireBinary resolves a gated binary path: non-empty env
// value, an existing executable regular file, sha256 logged for the
// acceptance record.
func crossBinRequireBinary(t *testing.T, envName string) string {
	t.Helper()
	path := strings.TrimSpace(os.Getenv(envName))
	if path == "" {
		t.Fatalf("%s is required when TOKTRAIL_CROSS_ENABLE=1", envName)
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		t.Fatalf("%s must point at an executable regular file: %s (%v)", envName, path, err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s for hashing: %v", path, err)
	}
	sum := sha256.Sum256(b)
	t.Logf("%s = %s (sha256=%s)", envName, path, hex.EncodeToString(sum[:]))
	return path
}

// crossBinGate is the single entry point of the gated test: skip unless
// explicitly enabled, reject a non-scrubbed environment, and resolve
// both binaries.
func crossBinGate(t *testing.T) (oldBin, newBin string) {
	t.Helper()
	if os.Getenv("TOKTRAIL_CROSS_ENABLE") != "1" {
		t.Skip(`TOKTRAIL_CROSS_ENABLE is not "1"; skipping the binary cross-version test`)
	}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "PG") || key == "DATABASE_URL" || key == "TEST_DATABASE_URL" {
			t.Fatalf("refusing cross-version run: the inherited environment defines %s (the audited runner scrubs it; clear it for standalone runs)", key)
		}
	}
	return crossBinRequireBinary(t, "TOKTRAIL_CROSS_OLD_COLLECTOR_BIN"),
		crossBinRequireBinary(t, "TOKTRAIL_CROSS_NEW_COLLECTOR_BIN")
}

// crossBinScene is the throwaway scene directory (mirrors the audited
// crossversion scene discipline: physical temp root, creation-captured
// path and inode, strict removal safety, keep on any failure). It also
// EXPLICITLY tracks every started child: close stops every child that
// was not proven reaped — in reverse start order — and a directory with
// an unproven child is NEVER cleaned.
type crossBinScene struct {
	t          *testing.T
	createdDir string
	createdAt  os.FileInfo
	dir        string
	root       string
	home       string
	children   []*crossBinChild
	keep       bool
	closed     bool
}

func newCrossBinScene(t *testing.T) *crossBinScene {
	t.Helper()
	rawRoot := os.TempDir()
	if rawRoot == "" {
		t.Fatal("create cross binary scene: the ambient temp root is empty")
	}
	root, err := filepath.EvalSymlinks(rawRoot)
	if err != nil {
		t.Fatalf("create cross binary scene: resolve the temp root %s: %v", rawRoot, err)
	}
	if !filepath.IsAbs(root) {
		t.Fatalf("create cross binary scene: the physical temp root %s is not absolute", root)
	}
	dir, err := os.MkdirTemp(root, "toktrail-crossbin-")
	if err != nil {
		t.Fatalf("create cross binary scene: %v", err)
	}
	if resolved, err := filepath.EvalSymlinks(dir); err != nil || resolved != dir {
		t.Fatalf("create cross binary scene: %s does not resolve to itself (%v)", dir, err)
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		t.Fatalf("create cross binary scene: %s is not a real directory (%v)", dir, err)
	}
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatalf("create cross binary scene home: %v", err)
	}
	s := &crossBinScene{t: t, createdDir: dir, createdAt: info, dir: dir, root: root, home: home}
	t.Cleanup(s.close)
	return s
}

func (s *crossBinScene) close() {
	if s.closed {
		return
	}
	s.closed = true
	// Stop every child that was not proven reaped — reverse start order
	// — with the unproven latch: any stop failure keeps the child
	// latched (never signaled again) and the scene retained.
	unproven := false
	for i := len(s.children) - 1; i >= 0; i-- {
		if _, err := s.children[i].stop(); err != nil {
			unproven = true
			s.keep = true
			s.t.Errorf("cross binary child %s could not be proven exited: %v", s.children[i].name, err)
		}
	}
	if s.keep || unproven || s.t.Failed() {
		s.t.Logf("cross binary scene kept for inspection: %s", s.dir)
		return
	}
	if removed, reason := s.removeIfSafe(); !removed {
		s.t.Errorf("cross binary scene %s kept for inspection: %s", s.dir, reason)
		return
	}
	s.t.Logf("cross binary scene cleaned up: %s", s.dir)
}

// removeIfSafe deletes the scene directory only when it is provably the
// directory this scene created (path equality, os.SameFile inode
// equality, canonical form, direct prefixed child of the captured
// physical root).
func (s *crossBinScene) removeIfSafe() (bool, string) {
	if s.dir != s.createdDir {
		return false, "dir no longer equals the directory captured at creation"
	}
	if s.createdAt == nil {
		return false, "the creation-captured file identity is missing"
	}
	info, err := os.Lstat(s.dir)
	if err != nil {
		return false, fmt.Sprintf("stat failed: %v", err)
	}
	if !info.IsDir() {
		return false, "not a real directory (symlink endpoints are rejected)"
	}
	if !os.SameFile(s.createdAt, info) {
		return false, "the directory entry was replaced in place (different inode than at creation)"
	}
	resolved, err := filepath.EvalSymlinks(s.dir)
	if err != nil {
		return false, fmt.Sprintf("resolve failed: %v", err)
	}
	if resolved != s.dir {
		return false, "resolved path does not equal the captured creation path"
	}
	rel, err := filepath.Rel(s.root, s.dir)
	if err != nil {
		return false, fmt.Sprintf("relative path failed: %v", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || strings.Contains(rel, string(filepath.Separator)) {
		return false, "not a direct child of the captured physical temp root"
	}
	if !strings.HasPrefix(rel, "toktrail-crossbin-") {
		return false, "lacks the dedicated toktrail-crossbin- prefix"
	}
	if err := os.RemoveAll(s.dir); err != nil {
		return false, fmt.Sprintf("remove failed: %v", err)
	}
	if _, err := os.Lstat(s.dir); !os.IsNotExist(err) {
		return false, "still exists after removal"
	}
	return true, ""
}

// crossBinChild is one collector subprocess under single-Wait
// supervision: exactly one goroutine calls cmd.Wait, and it is called
// exactly once; signals are only ever sent while Wait has not returned
// (the process is not yet reaped, so its PID cannot have been reused).
// An unproven child — one whose exit could not be confirmed — is
// LATCHED: stop never signals it again.
//
// The child deliberately does NOT get its own process group (no
// Setpgid): a runaway child is contained by this test's own stop
// protocol, and ACCEPTANCE RUNS MUST EXECUTE UNDER THE pg-supervise
// CONTROLLED SESSION so an unclean shutdown of the whole test process
// is contained by the session supervisor.
type crossBinChild struct {
	name     string
	cmd      *exec.Cmd
	waitCh   chan error
	reaped   bool
	unproven bool
	logPath  string
}

func (s *crossBinScene) startCrossBinChild(t *testing.T, name, bin, stateDir, serverURL string) *crossBinChild {
	t.Helper()
	logPath := filepath.Join(s.dir, name+".log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("open child log %s: %v", logPath, err)
	}
	cmd := exec.Command(bin, "resync", "--all", "--yes", "--state-dir", stateDir, "--server", serverURL)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	// From-scratch environment: PATH plus the dedicated scene HOME only;
	// the state directory and server are explicit flags.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + s.home}
	cmd.Dir = s.dir
	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatalf("start %s: %v", name, err)
	}
	child := &crossBinChild{name: name, cmd: cmd, waitCh: make(chan error, 1), logPath: logPath}
	// Registered IMMEDIATELY after a successful start: scene.close stops
	// every child that was not proven reaped, even if the test aborts
	// between start and the supervised wait.
	s.children = append(s.children, child)
	go func() {
		waitErr := cmd.Wait()
		logFile.Close()
		child.waitCh <- waitErr
	}()
	return child
}

// stop terminates a still-running child PID-reuse-safely. When the
// timeout and the single Wait arrive together, waitCh is drained
// NON-BLOCKING first, so a child that already exited is never signaled;
// if Signal still reports os.ErrProcessDone (the child was reaped
// between the drain and the signal), the single Wait goroutine's result
// is AWAITED to confirm the reaping — ErrProcessDone is never treated
// as reaped on its own. stop returns completed=true when the child
// exited on its own (the race case); completed=false when it had to be
// terminated. Any exit that cannot be proven LATCHES the child unproven
// (stop never signals it again) and returns an error; the caller keeps
// the scene.
func (c *crossBinChild) stop() (completed bool, err error) {
	if c.reaped {
		return true, nil
	}
	if c.unproven {
		// Latched: a previously failed stop protocol must never signal
		// this child again.
		return false, fmt.Errorf("%s was already latched unproven by a failed stop", c.name)
	}
	latch := func(err error) (bool, error) {
		c.unproven = true
		return false, err
	}
	// Non-blocking drain: the timeout may have lost the race against an
	// exit that already happened.
	select {
	case <-c.waitCh:
		c.reaped = true
		return true, nil
	default:
	}
	if err := c.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			// The single Wait reaped the process between the drain and
			// this signal: confirm through its result, never assume.
			select {
			case <-c.waitCh:
				c.reaped = true
				return true, nil
			case <-time.After(10 * time.Second):
				return latch(fmt.Errorf("%s exited but its exit could not be confirmed within the grace window", c.name))
			}
		}
		return latch(fmt.Errorf("signal %s: %w", c.name, err))
	}
	select {
	case <-c.waitCh:
		c.reaped = true
		return false, nil
	case <-time.After(10 * time.Second):
	}
	if err := c.cmd.Process.Kill(); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			select {
			case <-c.waitCh:
				c.reaped = true
				return false, nil
			case <-time.After(10 * time.Second):
				return latch(fmt.Errorf("%s exited but its exit could not be confirmed within the grace window", c.name))
			}
		}
		return latch(fmt.Errorf("kill %s: %w", c.name, err))
	}
	select {
	case <-c.waitCh:
		c.reaped = true
		return false, nil
	case <-time.After(10 * time.Second):
		return latch(fmt.Errorf("%s could not be proven exited after SIGKILL", c.name))
	}
}

// crossBinRun runs one collector to completion (or the timeout) and
// returns its log bytes. On timeout the child is stopped through the
// PID-reuse-safe protocol: a child that exited on its own in the
// timeout/Wait race window counts as completed; one that had to be
// terminated, or whose exit cannot be proven, fails the test keeping the
// scene.
func crossBinRun(t *testing.T, scene *crossBinScene, name, bin, stateDir, serverURL string) []byte {
	t.Helper()
	child := scene.startCrossBinChild(t, name, bin, stateDir, serverURL)
	select {
	case <-child.waitCh:
		child.reaped = true
	case <-time.After(crossBinTimeout):
		completed, err := child.stop()
		if err != nil {
			scene.keep = true
			t.Fatalf("%s could not be proven exited after %s: %v (scene kept)", name, crossBinTimeout, err)
		}
		if !completed {
			scene.keep = true
			t.Fatalf("%s timed out after %s and had to be terminated (log: %s; scene kept for inspection)", name, crossBinTimeout, child.logPath)
		}
		// The child exited on its own inside the timeout/Wait race
		// window: the run counts as completed and the log is read below.
	}
	logBytes, err := os.ReadFile(child.logPath)
	if err != nil {
		t.Fatalf("read %s log: %v", name, err)
	}
	return logBytes
}

// crossBinState builds one independent synthetic state directory whose
// journal is exactly what the NEW machinery persists for an interrupted
// restricted pass: six synced batches, the first three frozen as the
// snapshot universe, the recorded scope baseline at revision 1. Mirrors
// the fixture() shape but lives under the scene (so a failure keeps it)
// and carries the fake server URL. Built twice — once per binary — the
// two runs start from equivalent, completely independent states.
func crossBinState(t *testing.T, parent, url string) string {
	t.Helper()
	dir, err := os.MkdirTemp(parent, "state-")
	if err != nil {
		t.Fatalf("create cross binary state dir: %v", err)
	}
	st := statedir.DeviceState{
		DeviceID:          "device-resync",
		DeviceSecret:      strings.Repeat("a", 64),
		ApplicationID:     "synthetic-app",
		ExternalSubjectID: "synthetic-user",
		ServerURL:         url,
		UploadAuthorized:  true,
		ConsentRevision:   1,
	}
	if err := statedir.New(dir).Save(st); err != nil {
		t.Fatalf("save synthetic device state: %v", err)
	}
	input := filepath.Join(dir, "synthetic", "codex")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatalf("create synthetic input: %v", err)
	}
	if _, err := grants.New(dir).Enable("codex-jsonl", input); err != nil {
		t.Fatalf("create synthetic source grant: %v", err)
	}
	var entries []outbox.BatchEntry
	for i := 0; i < 6; i++ {
		id := fmt.Sprintf("batch-%02d", i)
		file := filepath.Join(dir, id+".json")
		writeJSON(t, file, syncclient.BatchRequest{BatchID: id, Records: []json.RawMessage{record("crossbin-"+string(rune('a'+i)), "2026-10-2"+string(rune('0'+i))+"T00:00:00Z")}})
		entries = append(entries, outbox.BatchEntry{BatchID: id, File: file, Source: "codex-jsonl", Input: input, Status: outbox.StatusSynced, RecordCount: 1, CreatedAt: time.Now().UTC()})
	}
	if err := outbox.New(dir).Save(outbox.Outbox{Batches: entries}); err != nil {
		t.Fatalf("save synthetic outbox: %v", err)
	}
	for _, name := range []string{"message-progress.json", "adapter-cursors.json", "scope-quarantine.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("[]\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	synced, err := outbox.New(dir).Load()
	if err != nil {
		t.Fatalf("load synthetic outbox: %v", err)
	}
	restricted, _, err := buildNewJob(dir, st, url, synced, func() time.Time { return time.Now().UTC() }, Plan{
		DeviceID:     st.DeviceID,
		ServerURL:    url,
		StateDir:     dir,
		JournalPath:  journalPath(dir),
		CoverageNote: coverageNote,
	}, NewSyncedBatchSnapshot([]string{"batch-00", "batch-01", "batch-02"}))
	if err != nil {
		t.Fatalf("build restricted fixture job: %v", err)
	}
	if len(restricted.Batches) != 3 || restricted.Snapshot == nil || len(restricted.Snapshot.BatchIDs) != 3 {
		t.Fatalf("restricted fixture job is not universe-bound: %+v", restricted)
	}
	if restricted.Exclusions.AfterSnapshot != 3 {
		t.Fatalf("restricted fixture job must exclude the three after-capture batches: %+v", restricted.Exclusions)
	}
	// Overwrite the plan's scope baseline deliberately: buildNewJob
	// stamps no live scope itself (the real writer records whatever
	// scope its planning run observed), and the journal must record that
	// its done/skip decisions were made under the OLD consent scope
	// (revision 1) — so the live revision 2 the fake reports is the
	// re-plan trigger on resume.
	restricted.Scope = snapshotScope(liveScope{revision: 1, allowedTools: map[string]struct{}{"Codex": {}}})
	if err := saveJob(dir, restricted); err != nil {
		t.Fatalf("save restricted journal: %v", err)
	}
	return dir
}

// crossBinFakeSelf is the in-process fake server. It answers the
// authenticated GET /v1/devices/self with the fixture device and consent
// revision 2 (the scope change) and records every request it sees.
// Everything else — including the collector's control-plane
// POST /v1/devices/tool-status reports — is answered 404: an
// old-server-compatible non-answer that keeps the run on its
// re-plan-stop path (the status report is not required for this
// experiment). The per-run traffic assertions decide what is allowed:
// self GETs and tool-status POSTs pass, an INGEST request of any kind
// fails the test.
type crossBinFakeSelf struct {
	server *httptest.Server
	mu     sync.Mutex
	seen   []string // "METHOD path authprefix" per request, in order
}

func newCrossBinFakeSelf(t *testing.T) *crossBinFakeSelf {
	t.Helper()
	f := &crossBinFakeSelf{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		prefix := "none"
		if head, _, ok := strings.Cut(auth, "."); ok {
			prefix = head // "Bearer device-resync"
		}
		f.mu.Lock()
		f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+prefix)
		f.mu.Unlock()
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device": map[string]any{
					"deviceId":         "device-resync",
					"consentRevision":  2,
					"uploadAuthorized": true,
					"revoked":          false,
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *crossBinFakeSelf) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.seen...)
}

// TestCrossVersionCollectorBinaryReplanDivergence executes the
// journal-divergence experiment with real binaries: both generations
// run against their own equivalent synthetic state and the same scope
// change; the old binary's re-plan must cover the complete synced
// history (6 batches) and lose the freeze in its write-back, the new
// binary's re-plan must stay inside the frozen universe (3 batches) and
// keep it. See the file header for the honesty boundaries.
func TestCrossVersionCollectorBinaryReplanDivergence(t *testing.T) {
	oldBin, newBin := crossBinGate(t)
	scene := newCrossBinScene(t)
	fake := newCrossBinFakeSelf(t)
	url := fake.server.URL

	// Two equivalent, completely independent states (built separately:
	// each is self-contained — grants, batch files, device state and
	// journal all live inside its own directory).
	oldDir := crossBinState(t, scene.dir, url)
	newDir := crossBinState(t, scene.dir, url)

	// OLD binary: the snapshot is dropped by its decode, the re-plan
	// expands to the complete synced history, the write-back loses the
	// freeze. The designed outcome is a NON-ZERO exit (the run stops
	// before any upload by design), so the assertions are on the log and
	// the persisted journal.
	// Per-run traffic attribution on the fake listener (the runs are
	// sequential, so a counter snapshot before each run splits the log).
	oldSeen := len(fake.requests())
	oldLog := crossBinRun(t, scene, "old-collector", oldBin, oldDir, url)
	crossBinCheckRunTraffic(t, "old", fake.requests()[oldSeen:])
	if !strings.Contains(string(oldLog), "consent scope changed") {
		t.Fatalf("the old run must stop on the consent scope change; log:\n%s", oldLog)
	}
	m := crossBinReplanCountRe.FindSubmatch(oldLog)
	if m == nil {
		t.Fatalf("the old run must report its re-planned batch count; log:\n%s", oldLog)
	}
	if got := string(m[1]); got != "6" {
		t.Fatalf("the old binary's re-plan must cover the complete synced history (6 batches), got %s; log:\n%s", got, oldLog)
	}
	oldJournal, exists, err := loadJob(oldDir)
	if err != nil || !exists {
		t.Fatalf("load the old run's written journal: exists=%t err=%v", exists, err)
	}
	if len(oldJournal.Batches) != 6 {
		t.Fatalf("the old run's persisted journal must re-plan all six synced batches, got %d", len(oldJournal.Batches))
	}
	for _, id := range []string{"batch-03", "batch-04", "batch-05"} {
		found := false
		for _, b := range oldJournal.Batches {
			if b.BatchID == id {
				found = true
			}
		}
		if !found {
			t.Fatalf("the old run's persisted journal must include the after-capture batch %s", id)
		}
	}
	if oldJournal.Snapshot != nil {
		t.Fatalf("the old run's persisted journal must have LOST the snapshot freeze: %+v", oldJournal.Snapshot)
	}
	// The re-plan was made and written back under the LIVE scope the fake
	// reported: the replacement journal's scope baseline must be revision
	// 2 (the fixture recorded 1), directly proving the real binary — not
	// the fixture writer — produced this journal.
	if oldJournal.Scope == nil || oldJournal.Scope.Revision != 2 {
		t.Fatalf("the old run's persisted journal must record the re-planned scope revision 2: %+v", oldJournal.Scope)
	}

	// NEW binary: the re-plan stays inside the frozen universe and the
	// write-back keeps the freeze. Also a designed non-zero exit.
	newSeen := len(fake.requests())
	newLog := crossBinRun(t, scene, "new-collector", newBin, newDir, url)
	crossBinCheckRunTraffic(t, "new", fake.requests()[newSeen:])
	if !strings.Contains(string(newLog), "consent scope changed") {
		t.Fatalf("the new run must stop on the consent scope change; log:\n%s", newLog)
	}
	m = crossBinReplanCountRe.FindSubmatch(newLog)
	if m == nil {
		t.Fatalf("the new run must report its re-planned batch count; log:\n%s", newLog)
	}
	if got := string(m[1]); got != "3" {
		t.Fatalf("the new binary's re-plan must stay inside the frozen universe (3 batches), got %s; log:\n%s", got, newLog)
	}
	newJournal, exists, err := loadJob(newDir)
	if err != nil || !exists {
		t.Fatalf("load the new run's written journal: exists=%t err=%v", exists, err)
	}
	if len(newJournal.Batches) != 3 {
		t.Fatalf("the new run's persisted journal must stay universe-bound (3 batches), got %d", len(newJournal.Batches))
	}
	for _, id := range []string{"batch-03", "batch-04", "batch-05"} {
		for _, b := range newJournal.Batches {
			if b.BatchID == id {
				t.Fatalf("the new run's persisted journal must keep the after-capture batch %s excluded", id)
			}
		}
	}
	if newJournal.Snapshot == nil || len(newJournal.Snapshot.BatchIDs) != 3 {
		t.Fatalf("the new run's persisted journal must keep the snapshot freeze: %+v", newJournal.Snapshot)
	}
	// Same proof for the new binary: the replacement journal was written
	// by the REAL new binary under the live scope (revision 2, where the
	// fixture recorded 1).
	if newJournal.Scope == nil || newJournal.Scope.Revision != 2 {
		t.Fatalf("the new run's persisted journal must record the re-planned scope revision 2: %+v", newJournal.Scope)
	}
}

// crossBinCheckRunTraffic verifies ONE run's observed fake-listener
// traffic: at least one authenticated GET /v1/devices/self with the
// fixture device credential; control-plane POST /v1/devices/tool-status
// reports are allowed (the fake answers them 404 — old-server
// compatible); ANYTHING else fails — above all any /v1/ingest/batches
// request, which would mean a binary retransmitted where the design
// stops before any ingest upload. This is an observation of this run on
// THIS listener, not a general zero-POST claim (see the file header).
func crossBinCheckRunTraffic(t *testing.T, label string, seen []string) {
	t.Helper()
	const selfGET = "GET /v1/devices/self Bearer device-resync"
	const toolStatusPOST = "POST /v1/devices/tool-status Bearer device-resync"
	selfGETs := 0
	var other []string
	for _, req := range seen {
		switch req {
		case selfGET:
			selfGETs++
		case toolStatusPOST:
			// allowed control-plane status report
		default:
			other = append(other, req)
		}
	}
	if selfGETs < 1 {
		t.Fatalf("the %s run must perform at least one authenticated self check; observed: %v", label, seen)
	}
	for _, req := range other {
		if strings.Contains(req, "/v1/ingest/batches") {
			t.Fatalf("the %s run must stop before any ingest upload, but an ingest request was observed: %q (all traffic: %v)", label, req, seen)
		}
	}
	if len(other) > 0 {
		t.Fatalf("the %s run made requests outside the allowed control-plane shapes: %v (all traffic: %v)", label, other, seen)
	}
	t.Logf("%s run traffic: %d self GET(s), %d tool-status POST(s), %d other", label,
		selfGETs, len(seen)-selfGETs-len(other), len(other))
}
