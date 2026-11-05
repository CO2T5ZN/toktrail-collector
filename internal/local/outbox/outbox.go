package outbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const outboxFileName = "outbox.json"

const (
	StatusPending = "pending"
	StatusSynced  = "synced"
	// StatusReorganized marks a batch whose records were redistributed by a
	// consent-scope reorganization: in-scope records moved to a new pending
	// batch (ReorganizedInto), out-of-scope records moved to the recoverable
	// quarantine store. A reorganized batch is terminal: it is never
	// re-selected, re-sent, or modified — its file stays immutable.
	StatusReorganized = "reorganized"
)

type Store struct{ dir string }

type Outbox struct {
	Batches []BatchEntry `json:"batches"`
}

type BatchEntry struct {
	BatchID         string    `json:"batchId"`
	File            string    `json:"file"`
	Source          string    `json:"source,omitempty"`
	Input           string    `json:"input,omitempty"`
	RecordCount     int       `json:"recordCount,omitempty"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"createdAt"`
	LastAttemptAt   time.Time `json:"lastAttemptAt,omitempty"`
	SyncedAt        time.Time `json:"syncedAt,omitempty"`
	ReceiptStatus   string    `json:"receiptStatus,omitempty"`
	AcceptedRecords int       `json:"acceptedRecords"`
	RejectedRecords int       `json:"rejectedRecords"`
	// ReorganizedInto names the follow-up batch created by a scope
	// reorganization (empty when every record was quarantined).
	ReorganizedInto     string    `json:"reorganizedInto,omitempty"`
	ReorganizedRevision int64     `json:"reorganizedRevision,omitempty"`
	ReorganizedAt       time.Time `json:"reorganizedAt,omitempty"`
	// OriginConsentRevision records the consent revision a reorg/recovery
	// batch was born under. A scope error against a batch whose origin
	// revision already equals the live revision means the scope content
	// changed without a revision bump (a server anomaly): the collector
	// fails closed instead of reorganizing in a loop at one revision.
	OriginConsentRevision int64 `json:"originConsentRevision,omitempty"`
	// OldestRecordAt/NewestRecordAt bound the contained records' occurredAt
	// times. They let the drain give recent data priority; older entries
	// written before this field existed simply have no window and keep the
	// historical oldest-first order.
	OldestRecordAt time.Time `json:"oldestRecordAt,omitempty"`
	NewestRecordAt time.Time `json:"newestRecordAt,omitempty"`
}

type AddBatchOptions struct {
	BatchID     string
	File        string
	Source      string
	Input       string
	RecordCount int
	// OriginConsentRevision is set for batches created by a scope
	// reorganization or quarantine recovery; zero for fresh exports.
	OriginConsentRevision int64
	// OldestRecordAt/NewestRecordAt are the exported records' occurredAt
	// bounds (zero when unknown).
	OldestRecordAt time.Time
	NewestRecordAt time.Time
}

type Receipt struct {
	BatchID         string
	Status          string
	AcceptedRecords int
	RejectedRecords int
	ReceivedAt      time.Time
}

func New(dir string) Store { return Store{dir: strings.TrimSpace(dir)} }

func (s Store) Path() string { return filepath.Join(s.dir, outboxFileName) }

func (s Store) Load() (Outbox, error) {
	b, err := os.ReadFile(s.Path())
	if errors.Is(err, os.ErrNotExist) {
		return Outbox{}, nil
	}
	if err != nil {
		return Outbox{}, err
	}
	var out Outbox
	if err := json.Unmarshal(b, &out); err != nil {
		return Outbox{}, err
	}
	return out, nil
}

func (s Store) Save(out Outbox) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.Path() + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path())
}

func (s Store) AddPending(opt AddBatchOptions) (BatchEntry, error) {
	out, err := s.Load()
	if err != nil {
		return BatchEntry{}, err
	}
	now := time.Now().UTC()
	entry := BatchEntry{
		BatchID:               strings.TrimSpace(opt.BatchID),
		File:                  strings.TrimSpace(opt.File),
		Source:                strings.TrimSpace(opt.Source),
		Input:                 strings.TrimSpace(opt.Input),
		RecordCount:           opt.RecordCount,
		Status:                StatusPending,
		CreatedAt:             now,
		OriginConsentRevision: opt.OriginConsentRevision,
		OldestRecordAt:        opt.OldestRecordAt.UTC(),
		NewestRecordAt:        opt.NewestRecordAt.UTC(),
	}
	if entry.BatchID == "" {
		return BatchEntry{}, errors.New("missing batch id")
	}
	if entry.File == "" {
		return BatchEntry{}, errors.New("missing batch file")
	}
	if entry.RecordCount < 0 {
		return BatchEntry{}, errors.New("record count cannot be negative")
	}
	for idx := range out.Batches {
		if out.Batches[idx].BatchID == entry.BatchID {
			if out.Batches[idx].CreatedAt.IsZero() {
				out.Batches[idx].CreatedAt = now
			}
			out.Batches[idx].File = entry.File
			out.Batches[idx].Source = entry.Source
			out.Batches[idx].Input = entry.Input
			out.Batches[idx].RecordCount = entry.RecordCount
			if !entry.NewestRecordAt.IsZero() {
				out.Batches[idx].OldestRecordAt = entry.OldestRecordAt
				out.Batches[idx].NewestRecordAt = entry.NewestRecordAt
			}
			out.Batches[idx].Status = StatusPending
			out.Batches[idx].SyncedAt = time.Time{}
			out.Batches[idx].ReceiptStatus = ""
			out.Batches[idx].AcceptedRecords = 0
			out.Batches[idx].RejectedRecords = 0
			if out.Batches[idx].OriginConsentRevision == 0 {
				out.Batches[idx].OriginConsentRevision = opt.OriginConsentRevision
			}
			if err := s.Save(out); err != nil {
				return BatchEntry{}, err
			}
			return out.Batches[idx], nil
		}
	}
	out.Batches = append(out.Batches, entry)
	if err := s.Save(out); err != nil {
		return BatchEntry{}, err
	}
	return entry, nil
}

func (s Store) NextPending() (BatchEntry, bool, error) {
	out, err := s.Load()
	if err != nil {
		return BatchEntry{}, false, err
	}
	for _, entry := range out.Batches {
		if entry.Status == StatusPending {
			return entry, true, nil
		}
	}
	return BatchEntry{}, false, nil
}

// PendingByID returns the named pending batch. It lets a caller that already
// chose a batch (for example by the drain's recent-data priority) hand that
// exact choice to an uploader that would otherwise reselect the oldest one.
func (s Store) PendingByID(batchID string) (BatchEntry, bool, error) {
	out, err := s.Load()
	if err != nil {
		return BatchEntry{}, false, err
	}
	for _, entry := range out.Batches {
		if entry.BatchID == strings.TrimSpace(batchID) && entry.Status == StatusPending {
			return entry, true, nil
		}
	}
	return BatchEntry{}, false, nil
}

func (s Store) MarkAttempt(batchID string, at time.Time) error {
	out, err := s.Load()
	if err != nil {
		return err
	}
	for idx := range out.Batches {
		if out.Batches[idx].BatchID == batchID {
			out.Batches[idx].LastAttemptAt = at.UTC()
			return s.Save(out)
		}
	}
	return nil
}

func (s Store) MarkSynced(receipt Receipt) error {
	out, err := s.Load()
	if err != nil {
		return err
	}
	for idx := range out.Batches {
		if out.Batches[idx].BatchID == receipt.BatchID {
			out.Batches[idx].Status = StatusSynced
			out.Batches[idx].ReceiptStatus = strings.TrimSpace(receipt.Status)
			out.Batches[idx].AcceptedRecords = receipt.AcceptedRecords
			out.Batches[idx].RejectedRecords = receipt.RejectedRecords
			out.Batches[idx].SyncedAt = receipt.ReceivedAt.UTC()
			if out.Batches[idx].SyncedAt.IsZero() {
				out.Batches[idx].SyncedAt = time.Now().UTC()
			}
			return s.Save(out)
		}
	}
	return nil
}

// MarkReorganized transitions a batch to StatusReorganized after a scope
// reorganization moved its records elsewhere. It is idempotent: replaying the
// same target is a no-op, while a conflicting second target is an error (the
// caller must fail closed instead of silently forking the batch). Marking an
// already-synced batch is rejected: an ACKed batch is immutable.
func (s Store) MarkReorganized(batchID, into string, revision int64, at time.Time) error {
	out, err := s.Load()
	if err != nil {
		return err
	}
	for idx := range out.Batches {
		if out.Batches[idx].BatchID != batchID {
			continue
		}
		switch out.Batches[idx].Status {
		case StatusReorganized:
			if out.Batches[idx].ReorganizedInto != strings.TrimSpace(into) || out.Batches[idx].ReorganizedRevision != revision {
				return fmt.Errorf("batch %s is already reorganized into %s (revision %d), refusing to reorganize into %s (revision %d)",
					batchID, out.Batches[idx].ReorganizedInto, out.Batches[idx].ReorganizedRevision, into, revision)
			}
			return nil
		case StatusSynced:
			return fmt.Errorf("batch %s is already synced; synced batches are immutable", batchID)
		}
		out.Batches[idx].Status = StatusReorganized
		out.Batches[idx].ReorganizedInto = strings.TrimSpace(into)
		out.Batches[idx].ReorganizedRevision = revision
		out.Batches[idx].ReorganizedAt = at.UTC()
		return s.Save(out)
	}
	return fmt.Errorf("batch %s not found in outbox", batchID)
}
