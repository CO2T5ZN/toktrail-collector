// Package scanledger remembers, per source file, the content state that was
// already exported, so a periodic scan does not JSON-decode an unchanged
// history again. A real history directory is several gigabytes; decoding
// all of it every thirty minutes is what made a two-minute run expire
// before it ever reached an export commit.
//
// Scope and safety: the ledger asserts only "this file's content is byte
// identical to what was already exported, so it yields no new records".
// Records are therefore never re-emitted for a skipped file, which means a
// ledger entry may be advanced ONLY after every record parsed from that
// file has been safely committed to the outbox (see collection's commit
// hook). Advancing at parse time would drop records whenever a later
// export failed.
//
// Identity is content, never timestamps: size and modification time are
// recorded for diagnosis, but a skip requires a matching content digest.
// A file rewritten in place with an identical size is therefore re-parsed,
// and a file that merely has an unchanged mtime is not trusted.
//
// The ledger is a cache, not a source of truth: a missing, unreadable or
// stale entry just means "parse this file". The dedupe/known-set check
// downstream stays the authority for not counting a record twice.
package scanledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FileState is one file's exported content state.
type FileState struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
	// ModTimeNS is recorded for diagnosis only; it never decides a skip.
	ModTimeNS int64 `json:"mtimeNs"`
	// Digest is the hex SHA-256 of the whole file content at the time its
	// records were committed.
	Digest string `json:"digest"`
}

// Store persists one source's file states inside the state directory.
type Store struct{ dir string }

func New(dir string) Store { return Store{dir: strings.TrimSpace(dir)} }

func (s Store) Path(source string) string {
	return filepath.Join(s.dir, "scan-ledger-"+safeSourceName(source)+".json")
}

type ledgerFile struct {
	Version string      `json:"version"`
	Entries []FileState `json:"entries"`
}

// Load returns the known states keyed by path. existed reports whether the
// file was present; a corrupt ledger is reported as an error so the caller
// can rebuild it rather than silently trusting half of it.
func (s Store) Load(source string) (map[string]FileState, bool, error) {
	b, err := os.ReadFile(s.Path(source))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]FileState{}, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	var file ledgerFile
	if err := json.Unmarshal(b, &file); err != nil {
		return nil, true, err
	}
	states := make(map[string]FileState, len(file.Entries))
	for _, entry := range file.Entries {
		if strings.TrimSpace(entry.Path) == "" || entry.Digest == "" {
			continue
		}
		states[entry.Path] = entry
	}
	return states, true, nil
}

// Save atomically replaces the source's ledger with the given states.
func (s Store) Save(source string, states map[string]FileState) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	file := ledgerFile{Version: "1"}
	paths := make([]string, 0, len(states))
	for path := range states {
		paths = append(paths, path)
	}
	// A stable order keeps the file diffable and byte-identical for an
	// unchanged scan.
	sort.Strings(paths)
	for _, path := range paths {
		file.Entries = append(file.Entries, states[path])
	}
	b, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.Path(source) + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path(source))
}

// Digest identifies one file's current content. It streams the file, so a
// multi-gigabyte history file costs sequential I/O but no JSON decoding —
// the expensive part a skip is meant to avoid.
func Digest(path string) (FileState, error) {
	info, err := os.Stat(path)
	if err != nil {
		return FileState{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return FileState{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return FileState{}, err
	}
	return FileState{
		Path:      path,
		Size:      info.Size(),
		ModTimeNS: info.ModTime().UnixNano(),
		Digest:    hex.EncodeToString(h.Sum(nil)),
	}, nil
}

// Unchanged reports whether the stored state still describes the file's
// content. Both the size and the digest must match: the digest is the
// authority, the size merely avoids a read when it already differs.
func Unchanged(prior FileState, current FileState) bool {
	if prior.Digest == "" || current.Digest == "" {
		return false
	}
	if prior.Size != current.Size {
		return false
	}
	return prior.Digest == current.Digest
}

func safeSourceName(source string) string {
	replacer := strings.NewReplacer("/", "-", "\\", "-", "..", "-", " ", "-")
	return replacer.Replace(strings.TrimSpace(source))
}

// Inspect digests one file and reports whether its content is unchanged
// since prior. A digest failure never proves freshness, so it returns
// unchanged=false and the error; callers treat that as "parse it".
func Inspect(path string, prior map[string]FileState) (FileState, bool, error) {
	current, err := Digest(path)
	if err != nil {
		return FileState{}, false, err
	}
	if priorState, ok := prior[path]; ok && Unchanged(priorState, current) {
		return current, true, nil
	}
	return current, false, nil
}
