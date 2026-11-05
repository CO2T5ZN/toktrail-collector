// Package knowncache persists the "known record" baseline a source history
// filter compares fresh scans against.
//
// Why it exists: the filters used to rebuild that baseline on every run by
// reading and re-canonicalising every historical batch file. With a few
// hundred batches that is the second half of why a periodic scan could not
// finish inside its window. The baseline is a pure function of the outbox
// batches, so it can be cached and appended to as new batches commit.
//
// The cache is an accelerator, never the authority. It is validated against
// the outbox ledger on load (same batch ids, same record counts); any
// mismatch, missing file, corrupt line or unreadable record means the
// caller rebuilds from the batch files exactly as before. Because a rebuilt
// baseline is byte-identical to what the cache would hold, a stale or
// dropped cache can only cost time, never correctness.
package knowncache

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/scanledger"
)

// cacheVersion is bumped whenever the on-disk shape changes; an unknown
// version is treated as "no cache" and rebuilt.
const cacheVersion = 1

// Store persists one source's known-record baseline inside the state dir.
type Store struct{ dir string }

func New(dir string) Store { return Store{dir: strings.TrimSpace(dir)} }

func (s Store) Path(source string) string {
	return filepath.Join(s.dir, "known-records-"+safeSourceName(source)+".jsonl")
}

type cacheLine struct {
	Kind    string          `json:"kind"`
	Version int             `json:"v,omitempty"`
	BatchID string          `json:"batchId,omitempty"`
	Count   int             `json:"count,omitempty"`
	Digest  string          `json:"digest,omitempty"`
	Key     string          `json:"key,omitempty"`
	Record  json.RawMessage `json:"rec,omitempty"`
}

// snapshot is the decoded cache: canonical record bytes per key, plus the
// batch ids and record counts it covers.
type snapshot struct {
	records map[string][]byte
	batches map[string]batchMeta
}

// batchMeta is the proof one cache entry offers for a stored batch: its
// record count and the SHA-256 of the batch file itself. Counts alone would
// let an out-of-band edit of a batch file go unnoticed; the digest makes the
// cache provably describe the bytes the outbox points at.
type batchMeta struct {
	count  int
	digest string
}

// LoadBaseline returns the known-record baseline (recordKey → canonical JSON)
// for one source, using the cache when it provably matches the outbox ledger
// and rebuilding from the batch files otherwise.
//
// label names the source in error messages exactly as the source's own filter
// did before the cache existed, so operator-facing text is unchanged.
func LoadBaseline(ctx context.Context, stateDir, source, label string) (map[string][]byte, error) {
	ledger, err := outbox.New(stateDir).Load()
	if err != nil {
		return nil, err
	}
	store := New(stateDir)
	snap, ok, snapErr := store.loadSnapshot(ctx, source)
	if snapErr != nil {
		// A cancelled scan must stop, not quietly fall back to a rebuild.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		// Any other cache problem (corrupt, foreign version, unparsable)
		// is not fatal: rebuild below.
		snap, ok = nil, false
	}
	if ok && coversLedger(ctx, snap, ledger, source) {
		return snap.records, nil
	}
	known, batches, err := rebuildFromBatches(ctx, ledger, source, label)
	if err != nil {
		return nil, err
	}
	// Persist the rebuild so the next run can skip the batch files. A write
	// failure never fails the scan: the baseline in hand is already correct.
	_ = store.rewrite(source, known, batches)
	return known, nil
}

// AppendCommittedBatch extends the cache with one just-committed batch. payload
// is the batch file's bytes (the same bytes the outbox entry points at).
//
// Failure is deliberately non-fatal for the caller: the next LoadBaseline sees
// a count mismatch against the outbox and rebuilds. The batch itself is
// already durably committed by the caller.
func AppendCommittedBatch(stateDir, source, batchID string, payload []byte) error {
	if len(payload) == 0 || strings.TrimSpace(batchID) == "" {
		return errors.New("knowncache: missing batch payload or id")
	}
	records, err := canonicalRecords(payload, "")
	if err != nil {
		return err
	}
	store := New(stateDir)
	path := store.Path(source)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// Refuse to append to a cache written by another version: the next load
	// would reject the version anyway, and a half-mixed file is worse than a
	// rebuild.
	if existing, err := os.Open(path); err == nil {
		first := bufio.NewReader(existing)
		line, _ := first.ReadString('\n')
		existing.Close()
		var head cacheLine
		if err := json.Unmarshal([]byte(line), &head); err != nil || head.Kind != "header" || head.Version != cacheVersion {
			_ = os.Remove(path)
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	w := bufio.NewWriter(file)
	if info, statErr := file.Stat(); statErr == nil && info.Size() == 0 {
		if err := writeLine(w, cacheLine{Kind: "header", Version: cacheVersion}); err != nil {
			return err
		}
	}
	if err := writeLine(w, cacheLine{Kind: "batch", BatchID: batchID, Count: len(records), Digest: digestBytes(payload)}); err != nil {
		return err
	}
	for _, record := range records {
		if err := writeLine(w, cacheLine{Kind: "record", Key: record.key, Record: record.canonical}); err != nil {
			return err
		}
	}
	return w.Flush()
}

type canonicalRecord struct {
	key       string
	canonical []byte
}

// canonicalRecords decodes one batch payload into canonical record bytes.
func canonicalRecords(payload []byte, label string) ([]canonicalRecord, error) {
	var batch struct {
		BatchID string            `json:"batchId"`
		Records []json.RawMessage `json:"records"`
	}
	if err := json.Unmarshal(payload, &batch); err != nil {
		return nil, err
	}
	out := make([]canonicalRecord, 0, len(batch.Records))
	for _, raw := range batch.Records {
		key, canonical, err := canonicalize(raw, label)
		if err != nil {
			return nil, err
		}
		out = append(out, canonicalRecord{key: key, canonical: canonical})
	}
	return out, nil
}

// canonicalize decodes one stored record and re-encodes it canonically, the
// same way the filters always did (numbers preserved as json.Number, so a
// counter above 2^53 is never rounded).
func canonicalize(raw []byte, label string) (string, []byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var rec map[string]any
	if err := dec.Decode(&rec); err != nil {
		return "", nil, err
	}
	key, _ := rec["recordKey"].(string)
	if key == "" {
		if label == "" {
			return "", nil, errors.New("stored record has no key")
		}
		return "", nil, fmt.Errorf("stored %s record has no key", label)
	}
	canonical, err := json.Marshal(rec)
	if err != nil {
		return "", nil, err
	}
	return key, canonical, nil
}

// rebuildFromBatches reproduces the historical baseline: every batch of this
// source, decoded and canonicalised, with identical conflict handling.
func rebuildFromBatches(ctx context.Context, ledger outbox.Outbox, source, label string) (map[string][]byte, map[string]batchMeta, error) {
	known := make(map[string][]byte)
	batches := make(map[string]batchMeta)
	for _, entry := range ledger.Batches {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if entry.Source != source {
			continue
		}
		switch entry.Status {
		case outbox.StatusPending, outbox.StatusSynced, outbox.StatusReorganized:
		default:
			return nil, nil, fmt.Errorf("unknown %s outbox status %q", label, entry.Status)
		}
		raw, err := os.ReadFile(entry.File)
		if err != nil {
			return nil, nil, fmt.Errorf("read %s history batch %s: %w", label, entry.BatchID, err)
		}
		var batch struct {
			BatchID string            `json:"batchId"`
			Records []json.RawMessage `json:"records"`
		}
		if err := json.Unmarshal(raw, &batch); err != nil {
			return nil, nil, err
		}
		if batch.BatchID != entry.BatchID {
			return nil, nil, fmt.Errorf("%s history batch identity mismatch", label)
		}
		batches[entry.BatchID] = batchMeta{count: len(batch.Records), digest: digestBytes(raw)}
		for _, rec := range batch.Records {
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
			key, canonical, err := canonicalize(rec, label)
			if err != nil {
				return nil, nil, err
			}
			if prev, ok := known[key]; ok && !bytes.Equal(prev, canonical) {
				return nil, nil, fmt.Errorf("stored %s record %s has conflicting content", label, key)
			}
			known[key] = canonical
		}
	}
	return known, batches, nil
}

// loadSnapshot decodes the cache. ok is false on a missing file or an
// unparsable/foreign-version one; the caller then rebuilds.
func (s Store) loadSnapshot(ctx context.Context, source string) (*snapshot, bool, error) {
	file, err := os.Open(s.Path(source))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	snap := &snapshot{records: make(map[string][]byte), batches: make(map[string]batchMeta)}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 8<<20)
	sawHeader := false
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var entry cacheLine
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, false, err
		}
		switch entry.Kind {
		case "header":
			if entry.Version != cacheVersion {
				return nil, false, errors.New("knowncache: unknown version")
			}
			sawHeader = true
		case "batch":
			if entry.BatchID == "" {
				return nil, false, errors.New("knowncache: batch line without id")
			}
			snap.batches[entry.BatchID] = batchMeta{count: entry.Count, digest: entry.Digest}
		case "record":
			if entry.Key == "" || len(entry.Record) == 0 {
				return nil, false, errors.New("knowncache: record line incomplete")
			}
			// The stored bytes ARE the canonical encoding (written from the
			// same canonicaliser the baseline is built with), so they are
			// used as-is: re-decoding every cached record would reproduce
			// exactly the cost this cache exists to remove. The batch-file
			// digests prove the cache still describes the outbox bytes.
			snap.records[entry.Key] = entry.Record
		default:
			return nil, false, errors.New("knowncache: unknown line kind")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, false, err
	}
	if !sawHeader {
		return nil, false, errors.New("knowncache: missing header")
	}
	return snap, true, nil
}

// rewrite replaces the cache with a full baseline.
func (s Store) rewrite(source string, records map[string][]byte, batches map[string]batchMeta) error {
	path := s.Path(source)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(file)
	if err := writeLine(w, cacheLine{Kind: "header", Version: cacheVersion}); err != nil {
		file.Close()
		return err
	}
	for batchID, meta := range batches {
		if err := writeLine(w, cacheLine{Kind: "batch", BatchID: batchID, Count: meta.count, Digest: meta.digest}); err != nil {
			file.Close()
			return err
		}
	}
	for key, canonical := range records {
		if err := writeLine(w, cacheLine{Kind: "record", Key: key, Record: canonical}); err != nil {
			file.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// coversLedger reports whether the cache describes exactly the batches the
// outbox currently holds for this source: same ids, same record counts.
func coversLedger(ctx context.Context, snap *snapshot, ledger outbox.Outbox, source string) bool {
	want := 0
	for _, entry := range ledger.Batches {
		if entry.Source != source {
			continue
		}
		meta, ok := snap.batches[entry.BatchID]
		if !ok {
			return false
		}
		// The cached digest must still describe the file the outbox
		// points at; an out-of-band edit invalidates the cache instead of
		// hiding behind a matching record count. Hashing a batch file is
		// cheap next to decoding and canonicalising its records.
		current, err := scanledger.Digest(entry.File)
		if err != nil || meta.digest == "" || current.Digest != meta.digest {
			return false
		}
		want++
	}
	if ctx.Err() != nil {
		return false
	}
	return want == len(snap.batches)
}

func digestBytes(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func writeLine(w *bufio.Writer, line cacheLine) error {
	payload, err := json.Marshal(line)
	if err != nil {
		return err
	}
	if _, err := w.Write(payload); err != nil {
		return err
	}
	return w.WriteByte('\n')
}

func safeSourceName(source string) string {
	replacer := strings.NewReplacer("/", "-", "\\", "-", "..", "-", " ", "-")
	return replacer.Replace(strings.TrimSpace(source))
}
