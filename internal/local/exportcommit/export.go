package exportcommit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/source/pipeline"
	"toktrail-collector/internal/source/registry"
)

const exportJournalFileName = "export-transaction.json"

type ExportOptions struct {
	StateDir    string
	Prepared    pipeline.PreparedExport
	Source      string
	Input       string
	CommittedAt time.Time
}

type ExportResult struct {
	BatchID     string
	Output      string
	Records     int
	OutboxPath  string
	CursorPath  string
	Recovered   bool
	CommittedAt time.Time
}

type exportJournal struct {
	Output      string    `json:"output"`
	BatchID     string    `json:"batchId"`
	Payload     string    `json:"payload"`
	Source      string    `json:"source"`
	Input       string    `json:"input"`
	RecordCount int       `json:"recordCount"`
	CommittedAt time.Time `json:"committedAt"`
	// OldestAt/NewestAt are the batch's record time bounds, persisted so the
	// upload queue can prefer recent data.
	OldestAt *time.Time `json:"oldestAt,omitempty"`
	NewestAt *time.Time `json:"newestAt,omitempty"`
	// MessageUpdates freezes the per-message pending intervals of interval
	// sources (claude-code-jsonl) together with this batch, so a crash
	// between batch write and progress write cannot double count.
	MessageUpdates []progress.MessagePendingUpdate `json:"messageUpdates,omitempty"`
}

func CommitExport(opt ExportOptions) (ExportResult, error) {
	stateDir := strings.TrimSpace(opt.StateDir)
	if stateDir == "" {
		return ExportResult{}, errors.New("missing state dir")
	}
	if recovered, err := Recover(stateDir); err != nil {
		return ExportResult{}, err
	} else if recovered.BatchID != "" {
		// Recovery is deliberately completed before the new transaction starts.
	}
	if opt.Prepared.Records > 0 {
		chunks, err := pipeline.SplitPreparedExport(opt.Prepared)
		if err != nil {
			return ExportResult{}, err
		}
		if len(chunks) > 1 {
			var lastResult ExportResult
			totalRecords := 0
			for _, chunk := range chunks {
				chunkOpt := opt
				chunkOpt.Prepared = chunk
				res, err := CommitExport(chunkOpt)
				if err != nil {
					return ExportResult{}, err
				}
				lastResult = res
				totalRecords += res.Records
			}
			lastResult.Records = totalRecords
			return lastResult, nil
		}
		if len(chunks) == 1 {
			opt.Prepared = chunks[0]
		}
	}
	// Recheck source integrity at the transaction boundary: local state may
	// have changed after export preparation, before this commit acquires it.
	if err := registry.ValidateCommit(opt.Source, stateDir); err != nil {
		return ExportResult{}, err
	}
	journal, err := journalFromOptions(opt)
	if err != nil {
		return ExportResult{}, err
	}
	if err := writeJournal(stateDir, journal); err != nil {
		return ExportResult{}, err
	}
	if err := applyJournal(stateDir, journal); err != nil {
		return ExportResult{}, err
	}
	if err := removeJournal(stateDir); err != nil {
		return ExportResult{}, err
	}
	return resultFromJournal(stateDir, journal, false), nil
}

func Recover(stateDir string) (ExportResult, error) {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return ExportResult{}, errors.New("missing state dir")
	}
	journal, ok, err := readJournal(stateDir)
	if err != nil || !ok {
		return ExportResult{}, err
	}
	if err := applyJournal(stateDir, journal); err != nil {
		return ExportResult{}, err
	}
	if err := removeJournal(stateDir); err != nil {
		return ExportResult{}, err
	}
	return resultFromJournal(stateDir, journal, true), nil
}

func JournalPath(stateDir string) string {
	return filepath.Join(strings.TrimSpace(stateDir), exportJournalFileName)
}

func journalFromOptions(opt ExportOptions) (exportJournal, error) {
	prepared := opt.Prepared
	journal := exportJournal{
		Output:         strings.TrimSpace(prepared.Output),
		BatchID:        strings.TrimSpace(prepared.BatchID),
		Payload:        string(prepared.Payload),
		Source:         strings.TrimSpace(opt.Source),
		Input:          strings.TrimSpace(opt.Input),
		RecordCount:    prepared.Records,
		CommittedAt:    opt.CommittedAt.UTC(),
		MessageUpdates: prepared.MessageUpdates,
		OldestAt:       prepared.OldestAt,
		NewestAt:       prepared.NewestAt,
	}
	if journal.CommittedAt.IsZero() {
		journal.CommittedAt = time.Now().UTC()
	}
	if journal.Output == "" {
		return exportJournal{}, errors.New("missing output file")
	}
	if journal.BatchID == "" {
		return exportJournal{}, errors.New("missing batch id")
	}
	if journal.Payload == "" {
		return exportJournal{}, errors.New("missing batch payload")
	}
	if journal.RecordCount < 0 {
		return exportJournal{}, errors.New("record count cannot be negative")
	}
	return journal, nil
}

func writeJournal(stateDir string, journal exportJournal) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	path := JournalPath(stateDir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJournal(stateDir string) (exportJournal, bool, error) {
	b, err := os.ReadFile(JournalPath(stateDir))
	if errors.Is(err, os.ErrNotExist) {
		return exportJournal{}, false, nil
	}
	if err != nil {
		return exportJournal{}, false, err
	}
	var journal exportJournal
	if err := json.Unmarshal(b, &journal); err != nil {
		return exportJournal{}, false, err
	}
	if journal.Output == "" || journal.BatchID == "" || journal.Payload == "" {
		return exportJournal{}, false, fmt.Errorf("invalid export transaction journal %s", JournalPath(stateDir))
	}
	return journal, true, nil
}

func applyJournal(stateDir string, journal exportJournal) error {
	if err := writeBatchAtomically(journal.Output, []byte(journal.Payload)); err != nil {
		return err
	}
	addOpts := outbox.AddBatchOptions{
		BatchID:     journal.BatchID,
		File:        journal.Output,
		Source:      journal.Source,
		Input:       journal.Input,
		RecordCount: journal.RecordCount,
	}
	if journal.OldestAt != nil {
		addOpts.OldestRecordAt = *journal.OldestAt
	}
	if journal.NewestAt != nil {
		addOpts.NewestRecordAt = *journal.NewestAt
	}
	if _, err := outbox.New(stateDir).AddPending(addOpts); err != nil {
		return err
	}
	_, err := progress.New(stateDir).Advance(progress.AdvanceOptions{
		Source:      journal.Source,
		Input:       journal.Input,
		BatchID:     journal.BatchID,
		RecordCount: journal.RecordCount,
		AdvancedAt:  journal.CommittedAt,
	})
	if err != nil {
		return err
	}
	if len(journal.MessageUpdates) > 0 {
		// Freezing the message intervals last keeps crash replay idempotent:
		// the same journal re-applies the same pending state per batch.
		return progress.New(stateDir).ApplyMessagePending(journal.Source, journal.BatchID, journal.MessageUpdates)
	}
	return nil
}

func writeBatchAtomically(path string, payload []byte) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func removeJournal(stateDir string) error {
	err := os.Remove(JournalPath(stateDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func resultFromJournal(stateDir string, journal exportJournal, recovered bool) ExportResult {
	return ExportResult{
		BatchID:     journal.BatchID,
		Output:      journal.Output,
		Records:     journal.RecordCount,
		OutboxPath:  outbox.New(stateDir).Path(),
		CursorPath:  progress.New(stateDir).Path(),
		Recovered:   recovered,
		CommittedAt: journal.CommittedAt,
	}
}
