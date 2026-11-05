package codexjsonl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"toktrail-collector/internal/local/knowncache"
	"toktrail-collector/internal/local/overrides"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/source/adapter"
)

// Immutable Codex line keys remain known across pending, ACK and scope
// quarantine. Read the existing immutable files rather than introducing a
// second index whose crash recovery could diverge from the export WAL.
//
// The context is consulted at coarse boundaries (entry, per outbox batch,
// per stored record, before the quarantine load, per quarantine entry,
// before the override baseline application and once per ledger record
// inside it, per fresh record); on cancellation it returns ctx.Err()
// (matchable with errors.Is(err, context.Canceled) or errors.Is(err,
// context.DeadlineExceeded)) and no partial result — the fresh slice
// accumulated so far is discarded, so a filter cut short never exports a
// prefix of the scan. A nil Options.Context reaches here as
// context.Background() via ContextOrBackground and keeps the exact
// pre-cancellation behavior.
func filterKnownCodexRecordsContext(ctx context.Context, stateDir string, records []adapter.Record) ([]adapter.Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// The baseline (recordKey -> canonical bytes) is cached and validated
	// against the outbox ledger; only a cache that provably covers every
	// batch is trusted, and anything else falls back to reading the batch
	// files exactly as before (see internal/local/knowncache).
	known, err := knowncache.LoadBaseline(ctx, stateDir, "codex-jsonl", "Codex")
	if err != nil {
		return nil, err
	}
	// remember folds one more stored payload (a quarantine entry) into the
	// baseline, keeping the byte-level "conflicting content" refusal.
	remember := func(raw []byte) error {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var rec adapter.Record
		if err := dec.Decode(&rec); err != nil {
			return err
		}
		key, _ := rec["recordKey"].(string)
		if key == "" {
			return fmt.Errorf("stored Codex record has no key")
		}
		canonical, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if prev, ok := known[key]; ok && !bytes.Equal(prev, canonical) {
			return fmt.Errorf("stored Codex record %s has conflicting content", key)
		}
		known[key] = canonical
		return nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	quarantine, err := quarantine.New(stateDir).Load()
	if err != nil {
		return nil, err
	}
	for _, entry := range quarantine {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.Source != "codex-jsonl" {
			continue
		}
		if err := remember(entry.Record); err != nil {
			return nil, err
		}
	}
	// Override baseline: an explicitly confirmed override pass may have
	// declared the current scan authoritative for some keys. Confirmed
	// overrides supersede the stored payloads for baseline comparison
	// (the old files stay untouched on disk); a pending override blocks
	// the whole scan fail-closed until the pass finishes or is abandoned.
	// The scope flows into the ledger application: its single-file load
	// and binding check stay non-interruptible at their file boundaries,
	// but both per-record ledger scans honor the scope and mutate the
	// known map only in one shot after every record check passes, so a
	// cancelled pass never leaves a half-applied baseline.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := overrides.ApplyToBaselineContext(ctx, stateDir, "codex-jsonl", known); err != nil {
		return nil, err
	}
	fresh := make([]adapter.Record, 0, len(records))
	for _, rec := range records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key, _ := rec["recordKey"].(string)
		canonical, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		if prior, ok := known[key]; ok {
			if !bytes.Equal(prior, canonical) {
				return nil, fmt.Errorf("Codex record %s changed after export or after an override baseline; refusing to overwrite immutable history (re-run toktrail resync --all --replace-existing to adopt the current scan)", key)
			}
			continue
		}
		fresh = append(fresh, rec)
	}
	return fresh, nil
}
