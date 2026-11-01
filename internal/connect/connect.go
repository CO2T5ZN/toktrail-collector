package connect

import (
	"context"

	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"toktrail-collector/internal/app/collection"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/bind"
	"toktrail-collector/internal/local/cursorsource"
	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/scheduler"
	"toktrail-collector/internal/source/registry"
	"toktrail-collector/internal/syncbudget"
	"toktrail-collector/internal/syncclient"
	"toktrail-collector/internal/syncretry"
)

// displaySourceState maps a server-reported source state onto a fixed
// display vocabulary: the known collecting/paused states pass through,
// anything else displays as "unknown". Display-layer only — the state
// machine is untouched. (cmd/toktrail/cursor.go carries the same twin.)
func displaySourceState(state string) string {
	switch strings.TrimSpace(state) {
	case "active", "pending", "paused":
		return strings.TrimSpace(state)
	case "":
		return "unspecified"
	default:
		return "unknown"
	}
}

// sourceConfiguredLabel reports the source linkage for display WITHOUT
// echoing the identifier: a server-sourced or old-permit value may carry
// arbitrary text, so it is never printed verbatim.
func sourceConfiguredLabel(sourceInstanceID string) string {
	if strings.TrimSpace(sourceInstanceID) == "" {
		return "not configured"
	}
	return "configured"
}

// Run coordinates the full connect orchestration:
//  1. Fetching server configuration via one-time ticket over HTTPS / loopback HTTP.
//  2. Binding device credentials (or skipping if already bound for this ticket/url receipt).
//  3. Probing locally available sources based on server-specified tool list and local disk existence.
//  4. Configuring local source grants (disabling previously active grants not in the new set).
//  5. Installing the scheduled background service.
//  6. Reporting probe-only tool statuses to the server (unsupported tools, missing default
//     directories); activated tools are reported by the collection flow (synced / no_new_records).
//  7. The shared post-install sync orchestration (Sync): an initial collection run that
//     refreshes the server authorization, scans local sources and recovers quarantine state;
//     backlog drain passes over the pending device and account-source queues (fair rotation
//     between the two, drained to empty within the run's shared POST budget); then the
//     history retransmission of the outbox batches already synced BEFORE this run started
//     (frozen into a snapshot under the setup lock) under an exclusive state lock — the
//     batches this run's collection uploads are never immediately replayed. Every
//     incompleteness — a budget decline included — is reported honestly —
//     the run returns ErrSyncIncomplete (or the phase error) instead of presenting a
//     partial sync as success, while the scheduled incremental installed in step 5 keeps
//     running regardless.
//
// Before any bind, connect fails closed on authorization-identity mismatches: a state
// directory already bound to a different server/application/subject is never silently
// re-pointed (the outbox does not record per-subject ownership, so its history cannot be
// moved to a new account), and a rebind that would change the device identity over an
// existing synced history is refused (cross-device de-duplication is not promised, so
// retransmitting it would double count).
func Run(ctx context.Context, opt Options) (Result, error) {
	out := opt.Out
	if out == nil {
		out = io.Discard
	}

	nowFn := opt.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	now := nowFn().UTC()

	homeDir := opt.HomeDir
	if homeDir == "" {
		var err error
		homeDir, err = os.UserHomeDir()
		if err != nil {
			return Result{BindStatus: BindNotAttempted}, fmt.Errorf("user home directory: %w", err)
		}
	}

	stateDir := strings.TrimSpace(opt.StateDir)
	if stateDir == "" {
		return Result{BindStatus: BindNotAttempted}, errors.New("state directory is required")
	}
	if opt.MaxTotalBatches < 0 {
		return Result{BindStatus: BindNotAttempted}, errors.New("max total batches must be non-negative")
	}

	// The run-wide shared POST budget. Every real ingest POST of this
	// run — the device outbox drain, the account-source uploads (the
	// first-enable round included) and the history retransmission —
	// reserves one unit under it right before sending, so the three
	// queues share one total and one deadline.
	budget := buildSyncBudget(opt.MaxTotalBatches, nowFn)

	// The run's single bounded retry policy for transient send failures,
	// shared by every queue below (device, account source, history and
	// the first-enable round). See buildSyncRetry for the deadline rules.
	retry := opt.Retry
	if retry == nil {
		retry = buildSyncRetry(ctx)
	}

	binary := opt.BinaryPath
	if binary == "" {
		var err error
		binary, err = os.Executable()
		if err != nil {
			return Result{BindStatus: BindNotAttempted}, fmt.Errorf("executable path: %w", err)
		}
		binary, err = filepath.Abs(binary)
		if err != nil {
			return Result{BindStatus: BindNotAttempted}, fmt.Errorf("absolute executable path: %w", err)
		}
	}

	interval := opt.Interval
	if interval == 0 {
		interval = scheduler.DefaultInterval
	}
	opt.HTTPClient = newSafeHTTPClient(opt.HTTPClient)

	// 1. Parse connect URL and ticket
	strippedURL, ticket, err := parseAndValidateConnectURL(opt.URL)
	if err != nil {
		return Result{BindStatus: BindNotAttempted}, err
	}

	// 2. Fetch server configuration via ticket
	cfg, err := fetchConnectConfig(ctx, opt.HTTPClient, strippedURL, ticket, now)
	if err != nil {
		return Result{BindStatus: BindNotAttempted}, err
	}
	fmt.Fprintf(out, "connected to %s (applicationId=%s, subjectId=%s)\n", strippedURL, cfg.ApplicationID, cfg.SubjectID)

	// Compute deterministic receipt fingerprint (SHA-256 of ticket and canonical URL).
	fingerprint := computeReceiptFingerprint(ticket, strippedURL)

	// 3-6. Perform state-locked setup operations
	var (
		deviceID        string
		consentRev      int64
		skippedBind     bool
		authorizedTools []string
		accountTools    []string
		serviceIdentity string
		// bindStatus records how far the binding phase got (§6.5
		// summary): not attempted, failed, bound, or skipped for this
		// receipt. It is returned on every exit path — including the
		// early-error partial result — so a failed run never reports a
		// fabricated binding state.
		bindStatus BindStatus
		// cursorFreshlyEnabled records that this run's setup performed
		// the first-time account-source enable AND its first sync round
		// ran to completion (the enable succeeded). The initial
		// collection round then runs its cursor phase drain-only — the
		// enable already pulled the full authorized window once, so the
		// round must not pull the upstream a second time; it still
		// refreshes the authorization and drains the persisted queue.
		cursorFreshlyEnabled bool
		// cursorFirstSyncFailed carries the first-sync failure of a
		// first-time enable whose first sync attempt EXECUTED and failed
		// (the permit is written; this command's single upstream pull is
		// spent or was never reached). The initial collection round then
		// runs its cursor phase drain-only too — one upstream pull per
		// command, success OR failure — and the failure is reported as
		// an incompleteness, never as success; the next run retries the
		// source. A failure before any permit existed (a declined
		// confirmation, a capability or credential failure) leaves it
		// empty: no permit exists, so the initial round keeps its
		// historical clean skip.
		cursorFirstSyncFailed string
	)

	lock, err := runlock.Acquire(stateDir)
	if err != nil {
		return Result{BindStatus: BindNotAttempted}, err
	}

	lockedWork := func() error {
		store := statedir.New(stateDir)
		st, err := store.Load()
		if err != nil {
			return err
		}

		// Ownership fail-closed checks. The outbox does not record which
		// device or subject originally synced a batch, and the server
		// does not promise cross-device de-duplication, so a state
		// directory's synced history must never be silently re-pointed
		// at a different authorization or device identity. All checks
		// below run before any bind, and the ownership guard makes them
		// durable: a refused mismatch leaves the state unchanged, so
		// every later run fails the same way until the user moves to a
		// separate state directory (or knowingly abandons the record).
		//
		// The synced-id read here feeds ONLY the ownership guard. The
		// history retransmission's scope snapshot is captured later, by
		// the initial collection round itself (see the Sync call below):
		// §6.3 places it after the authorization refresh and before any
		// of this run's scans or uploads, inside the SAME continuous
		// lock this setup acquired — which is held straight through to
		// that round, so no scheduled task can sync batches between the
		// two points.
		priorDeviceID := st.DeviceID
		priorSyncedIDs, err := syncedBatchIDs(stateDir)
		if err != nil {
			return err
		}
		priorSynced := len(priorSyncedIDs)
		if priorDeviceID != "" {
			if strings.TrimRight(strings.TrimSpace(st.ServerURL), "/") != strings.TrimRight(cfg.ServerURL, "/") ||
				strings.TrimSpace(st.ApplicationID) != cfg.ApplicationID ||
				strings.TrimSpace(st.ExternalSubjectID) != cfg.SubjectID {
				return fmt.Errorf("this state directory is already bound to a different authorization (server=%s applicationId=%s subjectId=%s) than this connect link authorizes (server=%s applicationId=%s subjectId=%s); the local outbox does not record per-subject ownership, so existing history cannot be moved to a new account automatically — use a separate --state-dir for this connect link",
					strings.TrimSpace(st.ServerURL), strings.TrimSpace(st.ApplicationID), strings.TrimSpace(st.ExternalSubjectID),
					cfg.ServerURL, cfg.ApplicationID, cfg.SubjectID)
			}
			ownership, hasOwnership, err := loadOwnership(stateDir)
			if err != nil {
				return err
			}
			if hasOwnership && ownership.DeviceID != priorDeviceID {
				return fmt.Errorf("the synced history in this state directory belongs to device %s, but this collector is bound as %s; cross-device de-duplication is not guaranteed, so connect refuses to retransmit it (avoiding double counting) — use a separate --state-dir, or remove %s only if you accept abandoning the ownership record",
					ownership.DeviceID, priorDeviceID, ownershipPath(stateDir))
			}
			// Record ownership before any bind that could change the
			// device identity, so the guard above also covers retries
			// after such a rebind.
			if priorSynced > 0 && !hasOwnership {
				if err := saveOwnership(stateDir, priorDeviceID, nowFn().UTC()); err != nil {
					return err
				}
			}
		} else if priorSynced > 0 {
			// An unbound state directory that still holds synced history
			// cannot attribute it: binding a new device over it would
			// retransmit another device's archives under the new
			// identity (double counting). Fail closed.
			return fmt.Errorf("this state directory holds %d synced batch(es) but no bound device; the history's owning device cannot be attributed, so connect refuses to bind a new device over it — use a separate --state-dir for this connect link", priorSynced)
		}

		deviceName := opt.DeviceName
		if deviceName == "" {
			deviceName = "toktrail-collector"
		}
		platform := runtime.GOOS + "-" + runtime.GOARCH
		bindFp := bind.Fingerprint(cfg.ServerURL, ticket, cfg.ApplicationID, cfg.SubjectID, deviceName, platform)

		var cutoff *time.Time
		historyDays := 0
		if cfg.Days != nil {
			historyDays = *cfg.Days
			t := nowFn().UTC().AddDate(0, 0, -historyDays)
			cutoff = &t
		}

		if shouldSkipBind(st, fingerprint, bindFp, cfg) {
			skippedBind = true
			bindStatus = BindSkipped
			deviceID = st.DeviceID
			consentRev = st.ConsentRevision
			needSave := false
			isNewReceipt := st.ConnectReceiptHash != fingerprint
			if isNewReceipt {
				// A receipt this state has not seen is a new
				// authorization acceptance: pin its history window.
				st.ConnectReceiptHash = fingerprint
				st.PendingConnectReceiptHash = ""
				applyHistoryCutoff(&st, cutoff, historyDays)
				needSave = true
			} else if st.HistoryFrom == nil || st.HistoryFrom.IsZero() {
				// First pinning for a receipt whose window was never
				// recorded (for example a device bound outside
				// connect). A same-receipt retry never re-derives the
				// cutoff: a now-based window would drift forward on
				// every retry, progressively narrowing the window.
				applyHistoryCutoff(&st, cutoff, historyDays)
				needSave = true
			}
			if needSave {
				if err := store.Save(st); err != nil {
					return fmt.Errorf("save state: %w", err)
				}
			}
			fmt.Fprintf(out, "device %s already bound; skipping bind\n", deviceID)
		} else {
			skippedBind = false
			bindStatus = BindNotAttempted
			st.PendingConnectReceiptHash = fingerprint
			if err := store.Save(st); err != nil {
				return fmt.Errorf("save pending state: %w", err)
			}

			bindRes, err := bind.Run(ctx, store, bind.Options{
				ServerURL:         cfg.ServerURL,
				Ticket:            ticket,
				ApplicationID:     cfg.ApplicationID,
				ExternalSubjectID: cfg.SubjectID,
				DeviceName:        opt.DeviceName,
				HTTPClient:        opt.HTTPClient,
				Now:               nowFn,
			})
			if err != nil {
				bindStatus = BindFailed
				return fmt.Errorf("device bind failed: %w", sanitizeError(err, ticket))
			}
			// A rebind that changed the device identity must not
			// retransmit the previous device's history: the outbox does
			// not attribute batches to devices and cross-device
			// de-duplication is not promised, so the run fails closed
			// instead of risking double counting. The ownership guard
			// recorded above makes the refusal durable across retries.
			if priorSynced > 0 && bindRes.State.DeviceID != priorDeviceID {
				return fmt.Errorf("rebinding this connect link changed the device identity from %s to %s; the %d synced batch(es) in this state directory belong to %s and connect will not retransmit them under the new device (cross-device de-duplication is not guaranteed, so retransmitting would double count) — use a separate --state-dir for the new device",
					priorDeviceID, bindRes.State.DeviceID, priorSynced, priorDeviceID)
			}
			deviceID = bindRes.State.DeviceID
			consentRev = bindRes.State.ConsentRevision
			bindStatus = BindBound

			st, err = store.Load()
			if err != nil {
				return err
			}
			st.ConnectReceiptHash = fingerprint
			st.PendingConnectReceiptHash = ""
			applyHistoryCutoff(&st, cutoff, historyDays)
			if err := store.Save(st); err != nil {
				return fmt.Errorf("save bound state: %w", err)
			}
			fmt.Fprintf(out, "bound device %s (consentRevision=%d)\n", deviceID, consentRev)
		}

		// Tool probing. Tools that could not be activated are reported to
		// the server with probe-only statuses (unsupported /
		// not_detected); activated tools are reported by the collection
		// flow with synced / no_new_records and are intentionally absent
		// here. Duplicate entries in cfg.Tools are collapsed by tool name
		// so the report stays within the tool-status contract.
		var grantsToApply []grants.Grant
		var probeStatuses []syncclient.ToolStatus
		reportedProbe := map[string]bool{}
		for _, toolName := range cfg.Tools {
			spec, ok := registry.LookupTool(toolName)
			if !ok {
				fmt.Fprintf(out, "tool %q: unsupported tool; skipped\n", toolName)
				if !reportedProbe[toolName] {
					reportedProbe[toolName] = true
					probeStatuses = append(probeStatuses, syncclient.ToolStatus{
						Tool:   toolName,
						Status: "unsupported",
						Detail: "unsupported tool",
					})
				}
				continue
			}
			if spec.IsAccountNetwork() {
				// Account-network tools never map to a local directory
				// grant. The first-time local confirmation (integrated
				// enable) runs here, inside the state lock, because the
				// server-side enable and the license write are state
				// mutations; an existing permit defers to the initial
				// collection. A confirmation failure is a clear skip — it
				// never fails the whole connect run (the other tools keep
				// their setup) and never reports a fabricated tool status;
				// the sync phase reports the account source as incomplete
				// instead.
				accountTools = append(accountTools, spec.Tool)
				if opt.Cursor == nil {
					fmt.Fprintf(out, "tool %q: account source; this build has no cursor wiring, skipped\n", spec.Tool)
					continue
				}
				license, hasLicense, lErr := cursorsource.New(stateDir).Load()
				if lErr != nil {
					return lErr
				}
				if hasLicense && license.Collectable() {
					fmt.Fprintf(out, "tool %q: local permit already active; the initial collection continues it\n", spec.Tool)
					authorizedTools = append(authorizedTools, spec.Tool)
					continue
				}
				enableOpts := *opt.Cursor
				enableOpts.StateDir = stateDir
				enableOpts.ServerURL = cfg.ServerURL
				enableOpts.HTTPClient = opt.HTTPClient
				enableOpts.Out = out
				// The first-enable round's uploads share the run budget:
				// they are real account-source POSTs, and the sync phase
				// below must honestly see what they spent.
				enableOpts.Budget = budget
				// ...and the run's single retry policy: the first-enable
				// round is a real sending queue of this run, so its
				// transient failures retry under the same run deadline as
				// every other queue.
				if enableOpts.Retry == nil {
					enableOpts.Retry = retry
				}
				// The first-enable round is a real, potentially long
				// sending phase (an upstream pull plus real source-batch
				// POSTs), so it emits the unified progress stream like
				// every other queue: per-phase batch events and a
				// heartbeat. The emitter is scoped to the enable phase
				// alone and stopped before the sync phase starts — no
				// ticker ever overlaps the initial round's own emitter. A
				// nil Progress keeps the enable byte-for-byte on its
				// historical path (no emitter, no goroutine, no events).
				// The origin label stays conservatively unknown: the
				// round's internal drain runs before the first pull, so
				// its batches' provenance is mixed by the same rule every
				// pull round follows.
				var enableEmitter *collection.ProgressEmitter
				if opt.Progress != nil {
					enableEmitter = collection.NewProgressEmitter(ctx, opt.Progress, collection.DefaultProgressHeartbeat)
					enableEmitter.EnterStage("cursor_sync")
					enableOpts.Progress = collection.CursorProgressEvents(enableEmitter, collection.OriginUnknown)
				}
				// The emitter is stopped the moment Enable returns —
				// inside this closure — so the sync phase below (with the
				// initial round's own emitter) never overlaps a second
				// ticker, whatever the enable's outcome.
				enableRes, enableErr := func() (cursorsync.EnableResult, error) {
					defer enableEmitter.Stop()
					return cursorsync.Enable(ctx, enableOpts, opt.CursorConfirm)
				}()
				if enableErr != nil {
					fmt.Fprintf(out, "tool %q: %v\n", spec.Tool, enableErr)
					if enableRes.Sync.Ran {
						// The first sync attempt executed and failed: the
						// server-side enable already happened and the
						// permit is written, so this command's single
						// upstream pull is spent (or the round stopped
						// right before it). The initial collection round
						// must not pull a second time — it runs
						// drain-only — and the failure is reported as an
						// incompleteness. Pointing the user at
						// `toktrail cursor enable` would be misleading
						// (an existing healthy permit is an idempotent
						// no-op there): the honest guidance is the
						// continuation path.
						cursorFirstSyncFailed = enableErr.Error()
						if budgetDeclined(enableErr) {
							fmt.Fprintf(out, "tool %q: enabled; the first sync stopped at this run's shared sync budget — the pending batches continue on the next connect or the scheduled collection\n", spec.Tool)
						} else {
							fmt.Fprintf(out, "tool %q: enabled; the first sync did not complete — the permit and its queue keep their state and the next connect or the scheduled collection continues them\n", spec.Tool)
						}
					} else {
						// No permit exists (a declined confirmation, a
						// capability or credential failure before the
						// enable wrote anything): the interactive enable
						// remains the right pointer.
						fmt.Fprintf(out, "tool %q: not enabled; run `toktrail cursor enable` in a terminal to confirm locally\n", spec.Tool)
					}
					continue
				}
				fmt.Fprintf(out, "tool %q: enabled (source %s, state=%s)\n", spec.Tool,
					sourceConfiguredLabel(enableRes.Source.SourceInstanceID), displaySourceState(enableRes.Source.State))
				if enableRes.Sync.Ran {
					fmt.Fprintf(out, "tool %q: first sync pulled=%d new=%d replaced=%d uploaded=%d pending=%d\n",
						spec.Tool, enableRes.Sync.PulledEvents, enableRes.Sync.NewRecords, enableRes.Sync.ReplacedRecords, enableRes.Sync.SyncedRecords, enableRes.Sync.PendingRemaining)
					// The enable's first sync pulled the full authorized
					// window (a fresh permit has no watermark) and it is
					// the run's ONLY upstream pull: the initial
					// collection round runs its cursor phase drain-only
					// over it — no second pull, not even the
					// incremental overlap round.
					cursorFreshlyEnabled = true
				}
				authorizedTools = append(authorizedTools, spec.Tool)
				continue
			}
			targetDir := spec.ResolveDefaultInput(homeDir)
			stat, err := os.Stat(targetDir)
			if err != nil || !stat.IsDir() {
				fmt.Fprintf(out, "tool %q: directory %s not found; skipped\n", spec.Tool, targetDir)
				if !reportedProbe[spec.Tool] {
					reportedProbe[spec.Tool] = true
					probeStatuses = append(probeStatuses, syncclient.ToolStatus{
						Tool:   spec.Tool,
						Status: "not_detected",
						Detail: "default directory not found",
					})
				}
				continue
			}
			fmt.Fprintf(out, "tool %q: detected directory %s; authorized\n", spec.Tool, targetDir)
			authorizedTools = append(authorizedTools, spec.Tool)
			grantsToApply = append(grantsToApply, grants.Grant{
				Source: spec.Source,
				Input:  targetDir,
			})
		}

		grantStore := grants.New(stateDir)
		enabledGrants, err := grantStore.ApplyConnectGrants(grantsToApply)
		if err != nil {
			return fmt.Errorf("apply grants: %w", err)
		}
		if len(enabledGrants) == 0 && len(authorizedTools) == 0 {
			// Account-network tools (Cursor) never create local grants;
			// a run that enabled one is not "no sources active".
			fmt.Fprintf(out, "warning: no tool directories detected locally; no sources active\n")
		}

		// Scheduler installation
		plan, err := scheduler.Install(scheduler.InstallOptions{
			Config: scheduler.TaskConfig{
				Platform: runtime.GOOS,
				StateDir: stateDir,
				Binary:   binary,
				Interval: interval,
				HomeDir:  homeDir,
			},
			Runner: opt.SchedulerRunner,
			DryRun: opt.DryRun,
			Out:    out,
		})
		if err != nil {
			return fmt.Errorf("install service failed: %w", err)
		}
		serviceIdentity = plan.TaskName
		fmt.Fprintf(out, "installed service %s (interval=%s)\n", plan.TaskName, interval)

		// 6. Report probe-only tool statuses to the server. Older servers
		// that have not deployed the tool-status endpoint answer 404/405,
		// which ReportToolStatuses tolerates. Any other failure surfaces:
		// the connect run fails rather than silently dropping the report.
		if len(probeStatuses) > 0 {
			_, err := syncclient.ReportToolStatuses(ctx, store, syncclient.Options{
				StateDir:     stateDir,
				ServerURL:    cfg.ServerURL,
				HTTPClient:   opt.HTTPClient,
				ToolStatuses: probeStatuses,
			})
			if err != nil {
				return fmt.Errorf("report tool statuses failed: %w", sanitizeError(err, ticket))
			}
		}
		return nil
	}

	err = lockedWork()
	if err != nil {
		// A failed setup releases the lock and fails the run, exactly
		// as before. A successful setup does NOT release it here: the
		// lock is handed to Sync below for the continuous hold. The
		// returned result keeps everything the setup had already
		// established (binding state, applied tools, the installed
		// service) so the §6.5 summary reports what actually happened
		// instead of a fabricated not-attempted state.
		_ = lock.Close()
		return Result{
			DeviceID:         deviceID,
			ConsentRevision:  consentRev,
			SkippedBind:      skippedBind,
			AuthorizedTools:  authorizedTools,
			InstalledService: serviceIdentity,
			BindStatus:       bindStatus,
		}, err
	}

	// 7. Shared post-install sync orchestration: initial collection
	// (authorization refresh, scan, quarantine recovery, bounded drain),
	// backlog drain passes over the pending device and account-source
	// queues (fair rotation, drained to empty within the run budget),
	// then the history retransmission under an exclusive state lock —
	// restricted to the synced-batch snapshot the INITIAL collection
	// round captured in-lock after the authorization refresh, so this
	// run's own uploads are never immediately replayed. The shared
	// budget built above caps all three queues' real POSTs; a decline is
	// an honest incomplete, never a lost batch and never a failure.
	// Failures and incompleteness are reported honestly and never break
	// the scheduled incremental installed above.
	//
	// The setup lock is HANDED to Sync, not released here: the initial
	// collection round runs under it through collection.RunLocked, so the
	// setup and the initial collection are one continuous hold — no
	// window in which a scheduled collection task could interleave and
	// sync pending batches (possibly against a rejecting receipt) under
	// the old authorization, leaving this run to mistake the mutated
	// state for its own clean coverage. Sync releases the lock exactly
	// when that round ends (success, budget decline, pause, refresh
	// failure, cancellation — every path); the backlog and history
	// phases then acquire their own locks. A failed setup above keeps
	// the historical behavior: release and fail.
	syncRes, syncErr := Sync(ctx, SyncOptions{
		StateDir:              stateDir,
		ServerURL:             cfg.ServerURL,
		HTTPClient:            opt.HTTPClient,
		Now:                   nowFn,
		Out:                   out,
		HomeDir:               homeDir,
		Cursor:                opt.Cursor,
		CursorFreshlyEnabled:  cursorFreshlyEnabled,
		CursorFirstSyncFailed: cursorFirstSyncFailed,
		AuthorizedTools:       authorizedTools,
		AccountTools:          accountTools,
		Budget:                budget,
		Retry:                 retry,
		InitialLock:           lock,
		CaptureResyncSnapshot: true,
		Progress:              opt.Progress,
	})

	return Result{
		DeviceID:         deviceID,
		ServerURL:        cfg.ServerURL,
		ApplicationID:    cfg.ApplicationID,
		SubjectID:        cfg.SubjectID,
		ConsentRevision:  consentRev,
		SkippedBind:      skippedBind,
		AuthorizedTools:  authorizedTools,
		InstalledService: serviceIdentity,
		PeriodicResult:   syncRes.Collection,
		Sync:             syncRes,
		BindStatus:       bindStatus,
	}, syncErr
}

// applyHistoryCutoff pins the consented history window to THIS run's
// authorization. The current cutoff replaces whatever was pinned before:
// narrowing (for example 30→7 days) follows the user's current consent,
// and a nil cutoff means unlimited history. It is called only when a NEW
// authorization is accepted — a fresh bind, or a receipt this state has
// not seen — because re-deriving a now-based cutoff on a same-receipt
// retry would drift the window forward run by run, progressively
// narrowing it. Records already collected that fall before a narrowed
// cutoff are quarantined by the pipeline (before_history_from), never
// deleted.
func applyHistoryCutoff(st *statedir.DeviceState, cutoff *time.Time, days int) {
	st.HistoryFrom = cutoff
	st.HistoryDays = days
}

// buildSyncBudget constructs the run-wide shared POST budget for Run's
// sync phase. maxTotalBatches <= 0 selects the DefaultBudgetTotal; the
// deadline is DefaultBudgetDeadline measured from now. The budget's
// clock and its deadline are both derived from the SAME now function:
// the deadline is evaluated lazily against that clock, so a test's fixed
// clock can never accidentally expire the deadline (and a real clock
// fires it exactly 10 minutes after the run started). The caller has
// already rejected negative totals.
func buildSyncBudget(maxTotalBatches int, now func() time.Time) *syncbudget.Budget {
	total := maxTotalBatches
	if total <= 0 {
		total = DefaultBudgetTotal
	}
	return syncbudget.New(
		syncbudget.WithTotal(total),
		syncbudget.WithNow(now),
		syncbudget.WithDeadline(now().Add(DefaultBudgetDeadline)),
	)
}

// buildSyncRetry constructs the run's single bounded retry policy for
// transient ingest send failures: the default retry shape with full
// jitter (never deterministic) and an explicit run deadline. The run
// deadline is the caller's ctx deadline whenever one exists — the
// connect CLI always sets a 10-minute one — so the policy and every
// HTTP call of the run share the same bound. A ctx WITHOUT a deadline
// (library callers, tests) gets a conservative real-time cap of
// DefaultBudgetDeadline instead, so no retry wait can ever be unbounded.
//
// The cap deliberately reads the REAL clock, not the run's injectable
// Now: the policy ticks on syncretry's RealClock, and a Now pinned to a
// historical test instant would produce a deadline that is already
// expired the moment the policy compares against it. Callers needing a
// deterministic policy inject one through Options.Retry.
func buildSyncRetry(ctx context.Context) *syncretry.Policy {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(DefaultBudgetDeadline)
	}
	return syncretry.New(
		syncretry.WithJitter(syncretry.FullJitter),
		syncretry.WithRunDeadline(deadline),
	)
}
