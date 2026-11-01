package connect

import (
	"io"
	"net/http"
	"time"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/scheduler"
	"toktrail-collector/internal/syncretry"
)

// Options controls a connect orchestration run.
type Options struct {
	URL             string           // Raw connect URL: http(s)://<host>/api/collector/connect#<64-hex ticket>
	StateDir        string           // Local TokTrail state directory
	DeviceName      string           // Optional device name
	Interval        time.Duration    // Scheduling interval (defaults to scheduler.DefaultInterval)
	HomeDir         string           // Optional home directory override (defaults to os.UserHomeDir)
	BinaryPath      string           // Optional binary executable path override (defaults to os.Executable)
	HTTPClient      *http.Client     // Optional HTTP client override for testing
	SchedulerRunner scheduler.Runner // Optional scheduler runner override for testing
	DryRun          bool             // Optional dry run for scheduler installation
	Now             func() time.Time // Injectable clock for deterministic tests
	Out             io.Writer        // Destination for progress output (defaults to io.Discard)
	// MaxTotalBatches optionally caps the total real ingest POST attempts
	// of connect's sync phase across ALL queues — the device outbox
	// drain, the account-source uploads and the history retransmission —
	// through the shared run budget Run builds from it (see
	// DefaultBudgetTotal and DefaultBudgetDeadline for the defaults used
	// when this is zero; negative values are rejected). The per-pass
	// drain bounds of the sending layers are preserved on top of it.
	MaxTotalBatches int
	// Cursor carries the cursorsync options for the account-level Cursor
	// source. When the connect authorization names Cursor and no local
	// permit exists yet, connect performs the first-time local
	// confirmation (the integrated enable). Nil skips the cursor branch
	// entirely (builds without the cursor wiring).
	Cursor *cursorsync.Options
	// CursorConfirm overrides the first-enable confirmation prompt
	// (tests). Nil uses cursorsync.DefaultConfirm.
	CursorConfirm cursorsync.ConfirmFunc
	// Retry optionally overrides the run's bounded retry policy for
	// transient ingest send failures. Nil (production) makes Run build
	// one: syncretry.New(WithJitter(FullJitter), WithRunDeadline(<the
	// ctx deadline, or a real-time 10-minute cap when the ctx carries
	// none>)), threaded unchanged into the device, account-source and
	// history queues and the first-enable round. Tests inject a
	// fake-clock policy here for deterministic retry behavior.
	Retry *syncretry.Policy
	// Progress receives the unified collection progress events for the
	// sync phases: the initial collection round and the backlog passes
	// (stage, queue-snapshot, per-batch and heartbeat events through
	// collection's emitter), plus connect's own phase markers and the
	// history retransmission's per-batch events. Nil keeps the behavior
	// identical (no events, no goroutines). Invocations are serialized
	// (never concurrent) but may originate from a heartbeat goroutine.
	Progress func(collection.ProgressEvent)
}

// BindStatus reports how far connect's binding phase got, so the §6.5
// summary never fabricates a binding outcome on an early failure: the
// run records the last phase it actually reached.
type BindStatus string

const (
	// BindNotAttempted: the run failed before any bind attempt (URL
	// parse, config fetch, lock acquisition).
	BindNotAttempted BindStatus = "not_attempted"
	// BindFailed: the bind attempt itself failed.
	BindFailed BindStatus = "failed"
	// BindBound: a new device was bound.
	BindBound BindStatus = "bound"
	// BindSkipped: the device was already bound for this receipt.
	BindSkipped BindStatus = "skipped_bind"
)

// Result summarizes a completed connect orchestration.
type Result struct {
	DeviceID         string            `json:"deviceId"`
	ServerURL        string            `json:"serverUrl"`
	ApplicationID    string            `json:"applicationId"`
	SubjectID        string            `json:"subjectId"`
	ConsentRevision  int64             `json:"consentRevision"`
	SkippedBind      bool              `json:"skippedBind"`
	AuthorizedTools  []string          `json:"authorizedTools"`
	InstalledService string            `json:"installedService"`
	PeriodicResult   collection.Result `json:"periodicResult"`
	// Sync reports the post-install sync orchestration (the initial
	// collection round, the history retransmission, and the backlog
	// drain). Sync.Incomplete lists every reason the current
	// authorization was not fully covered; a non-empty list always came
	// with a non-nil Run error.
	Sync SyncResult `json:"sync"`
	// BindStatus is the structured binding outcome (§6.5 summary). It
	// is set on every exit path — including the early-error partial
	// result — so a failed run never reports a fabricated binding
	// state.
	BindStatus BindStatus `json:"-"`
}

// Config is the server-provided configuration payload fetched from the connect endpoint.
type Config struct {
	SchemaVersion int      `json:"schemaVersion"`
	ServerURL     string   `json:"serverUrl"`
	ApplicationID string   `json:"applicationId"`
	SubjectID     string   `json:"subjectId"`
	Tools         []string `json:"tools"`
	Days          *int     `json:"days"`
	ExpiresAt     string   `json:"expiresAt"`
}
