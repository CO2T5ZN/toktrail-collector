package pipeline

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"toktrail-collector/internal/local/filtertxn"
	"toktrail-collector/internal/local/managedconsent"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/adapter"
)

// recoverPendingFilterTxn completes any history-filter transaction an
// earlier crash left half-applied — including when the current call has no
// cutoff or nothing to skip (e.g. the cutoff widened between runs and the
// interrupted transaction still has to complete). It must run BEFORE any
// adapter loads cutoff-governed state (Claude message baselines, the
// quarantine store): records computed against a half-applied transaction
// would either re-emit intervals the transaction already handles or trip
// the adapter's progress-integrity gates. Only mutating flows (export)
// recover; Scan and Preview stay read-only by contract (diagnostic.Privacy
// promises no state mutation), so a pending journal converges at the next
// export.
//
// Serialization: like exportcommit's journal, the filter journal is a
// single per-state-directory slot whose create→apply→remove cycle is not
// intra-process locked. Callers already serialize state-directory access
// with the runlock (collection and the CLI commands acquire it around every
// export); pipeline must not acquire the runlock itself because collection
// holds it across PrepareExport. Recovery and commit are idempotent, so a
// replay under the runlock is always safe.
func recoverPendingFilterTxn(stateDir string) error {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return nil
	}
	if _, err := filtertxn.Recover(stateDir); err != nil {
		return fmt.Errorf("recover pending history-filter transaction: %w", err)
	}
	return nil
}

// FilterHistoryCutoff drops records whose occurredAt timestamp is strictly before the
// configured HistoryFrom cutoff (either provided in opt or loaded from opt.StateDir).
//
// To prevent cumulative baseline re-exports or replaying tokens from zero:
//  1. For Claude Code messages whose intervals are skipped, their To state is recorded
//     directly into message progress as Confirmed baseline via EstablishConfirmedBaseline.
//  2. Skipped records are quarantined with quarantine.ReasonBeforeHistoryFrom so that
//     adapters (like codex-jsonl) and sync reconciliation recognize them as known/handled
//     and do not re-emit them in subsequent runs.
//
// Both writes are ONE crash-safe transaction (filtertxn): the full intent is journaled
// before any store is touched, the quarantine half is applied before the baseline half,
// and any interruption is replayed to completion by the next run. Writing the baseline
// first (the pre-transaction order) was a permanent-loss window: a crash before the
// quarantine write suppressed re-emission of the skipped intervals, so the quarantine
// entries could never be re-created and widening the history window later could not
// recover the records.
//
// PrepareExport recovers a pending transaction BEFORE the adapter loads records, so
// this function's own recovery is a no-op there; it is kept so direct callers of
// FilterHistoryCutoff converge too.
//
// Cancellation: the interruptible, pure-computation parts (record/update
// partitioning, quarantine entry building) consult opt.Context at coarse
// boundaries and return its error (matchable with errors.Is(err,
// context.Canceled) or errors.Is(err, context.DeadlineExceeded)) with nil
// records and updates, never a prefix of the partition. A nil
// opt.Context behaves as context.Background() and keeps the exact
// pre-cancellation behavior.
//
// Two deliberately non-interruptible phases remain:
//
//  1. recoverPendingFilterTxn and filtertxn.Commit take no context (their
//     journaled create→apply→remove cycle is the crash-recovery mechanism
//     and must run to completion once started; interrupting mid-apply would
//     leave the same half-applied state a crash does). Instead the context
//     is checked immediately before filtertxn.Commit, so a cancelled run
//     never STARTS a new journaled transaction, and at entry, so a
//     cancelled run skips recovery entirely (it converges on the next
//     non-cancelled call).
//  2. The single-file state loads (managed consent overlay, device state,
//     outbox/quarantine ledgers) have no context-taking API; the scope is
//     checked between them, but a load already in progress completes.
func FilterHistoryCutoff(opt adapter.Options, records []adapter.Record, updates []progress.MessagePendingUpdate) ([]adapter.Record, []progress.MessagePendingUpdate, error) {
	ctx := opt.ContextOrBackground()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := recoverPendingFilterTxn(opt.StateDir); err != nil {
		return nil, nil, err
	}

	stateDir := strings.TrimSpace(opt.StateDir)

	cutoff := opt.HistoryFrom
	if cutoff == nil && stateDir != "" {
		// Legacy fallback: without an applied server grant view, the
		// bind-time state cutoff governs when the caller passed none.
		// Under the grant protocol the server-confirmed effective cutoff is
		// authoritative — including an explicit nil (unlimited), which must
		// NOT fall back to the bind-time cutoff, or a server-side widening
		// to unlimited could never take effect.
		managed, seen, err := managedconsent.New(stateDir).Load()
		if err != nil {
			return nil, nil, fmt.Errorf("load managed consent overlay: %w", err)
		}
		if !seen {
			st, err := statedir.New(stateDir).Load()
			if err != nil {
				return nil, nil, fmt.Errorf("load history cutoff: %w", err)
			}
			if st.HistoryFrom != nil && !st.HistoryFrom.IsZero() {
				cutoff = st.HistoryFrom
			}
		} else if managed.HistoryFrom != nil {
			cutoff = managed.HistoryFrom
		}
	}
	if cutoff == nil || cutoff.IsZero() {
		return records, updates, nil
	}

	// The consent/state loads above are single uncancellable file reads;
	// observe a cancellation that arrived during them before any
	// partitioning work starts.
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	kept := make([]adapter.Record, 0, len(records))
	skipped := make([]adapter.Record, 0)
	skippedKeys := make(map[string]bool)

	for _, rec := range records {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		tsStr := adapter.StringField(rec, "occurredAt")
		ts, err := time.Parse(time.RFC3339Nano, tsStr)
		if err != nil {
			ts, err = time.Parse(time.RFC3339, tsStr)
		}
		if err == nil && ts.Before(*cutoff) {
			skipped = append(skipped, rec)
			if key := adapter.StringField(rec, "recordKey"); key != "" {
				skippedKeys[key] = true
			}
			continue
		}
		kept = append(kept, rec)
	}

	if len(skipped) == 0 {
		return records, updates, nil
	}

	// Partition message updates
	keptUpdates := make([]progress.MessagePendingUpdate, 0, len(updates))
	skippedUpdates := make([]progress.MessagePendingUpdate, 0)
	for _, u := range updates {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if skippedKeys[u.RecordKey] {
			skippedUpdates = append(skippedUpdates, u)
		} else {
			keptUpdates = append(keptUpdates, u)
		}
	}

	if stateDir == "" {
		// Without a state directory nothing can be persisted: skipped
		// records are only dropped from the batch.
		return kept, keptUpdates, nil
	}

	// The revision the history scope was applied under: recovery of
	// these entries requires a strictly newer revision, so the real
	// current revision must be recorded — a zero revision would let a
	// future unchanged revision wrongly recover records that are still
	// before the live cutoff. An unreadable device state therefore fails
	// closed instead of silently persisting revision 0.
	quarantineRevision := int64(0)
	if managed, seen, err := managedconsent.New(stateDir).Load(); err == nil && seen {
		quarantineRevision = managed.ConsentRevision
	} else if err != nil {
		return nil, nil, fmt.Errorf("load managed consent overlay: %w", err)
	} else if st, serr := statedir.New(stateDir).Load(); serr != nil {
		return nil, nil, fmt.Errorf("load quarantine consent revision: %w", serr)
	} else {
		quarantineRevision = st.ConsentRevision
	}

	// Quarantine skipped records with ReasonBeforeHistoryFrom and advance
	// the Claude baseline for their message intervals in one journaled
	// transaction, so a crash between the two writes is replayed to
	// completion instead of losing the recoverable quarantine entries.
	// The revision loads above are single uncancellable file reads; a
	// cancellation that arrived during them is observed before entry
	// building starts.
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	entries := make([]quarantine.Entry, 0, len(skipped))
	now := time.Now().UTC()
	for _, r := range skipped {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		key := adapter.StringField(r, "recordKey")
		if key == "" {
			continue
		}
		raw, err := json.Marshal(r)
		if err != nil {
			continue
		}
		entries = append(entries, quarantine.Entry{
			Source:          opt.Source,
			Input:           opt.Input,
			RecordKey:       key,
			Record:          raw,
			OriginBatchID:   opt.BatchID,
			Reason:          quarantine.ReasonBeforeHistoryFrom,
			QuarantinedAt:   now,
			ConsentRevision: quarantineRevision,
		})
	}
	if len(entries) == 0 && len(skippedUpdates) == 0 {
		return kept, keptUpdates, nil
	}
	journal := filtertxn.Journal{
		Schema:     filtertxn.SchemaVersion,
		Source:     opt.Source,
		Input:      opt.Input,
		Quarantine: entries,
		Baselines:  skippedUpdates,
		CreatedAt:  now,
	}
	// Last cancellation checkpoint: once filtertxn.Commit starts, the
	// journaled create→apply→remove transaction must run to completion
	// (crash-recovery invariant), so a cancelled run stops HERE — it never
	// starts a transaction it would have to abandon. The next non-cancelled
	// run recomputes the whole partition from the same records and cutoff,
	// so nothing is lost by not committing.
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := filtertxn.Commit(stateDir, journal); err != nil {
		return nil, nil, fmt.Errorf("commit history-filter transaction: %w", err)
	}

	return kept, keptUpdates, nil
}
