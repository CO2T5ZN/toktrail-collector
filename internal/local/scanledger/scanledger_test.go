package scanledger

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Save/Load round-trips the file states in a stable order.
func TestStoreRoundTripAndOrdering(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)
	states := map[string]FileState{
		"/b.jsonl": {Path: "/b.jsonl", Size: 2, Digest: "d2"},
		"/a.jsonl": {Path: "/a.jsonl", Size: 1, Digest: "d1"},
	}
	if err := store.Save("codex-jsonl", states); err != nil {
		t.Fatal(err)
	}
	loaded, existed, err := store.Load("codex-jsonl")
	if err != nil || !existed {
		t.Fatalf("load = (%v, %v)", existed, err)
	}
	if len(loaded) != 2 || loaded["/a.jsonl"].Digest != "d1" || loaded["/b.jsonl"].Digest != "d2" {
		t.Fatalf("states did not round-trip: %#v", loaded)
	}
	// A rewrite with the same content is byte-identical (deterministic order).
	first, err := os.ReadFile(store.Path("codex-jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save("codex-jsonl", states); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(store.Path("codex-jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("an unchanged save must be byte-identical")
	}
}

// A missing ledger is "no prior state", never an error.
func TestStoreMissingIsNotAnError(t *testing.T) {
	store := New(t.TempDir())
	states, existed, err := store.Load("codex-jsonl")
	if err != nil || existed || len(states) != 0 {
		t.Fatalf("missing ledger = (%#v, %v, %v)", states, existed, err)
	}
}

// A corrupt ledger is an error so the caller rebuilds it instead of trusting
// a truncated state map.
func TestStoreCorruptIsAnError(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)
	if err := os.WriteFile(store.Path("codex-jsonl"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load("codex-jsonl"); err == nil {
		t.Fatal("a corrupt ledger must be reported, got nil")
	}
}

// Only content decides a skip: an unchanged modification time with different
// content is a change, and a touched but identical file is not.
func TestUnchangedIsContentOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.jsonl")
	if err := os.WriteFile(path, []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := Digest(path)
	if err != nil {
		t.Fatal(err)
	}
	// A later timestamp with identical bytes still counts as unchanged.
	later := time.Now().Add(2 * time.Hour)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	touched, err := Digest(path)
	if err != nil {
		t.Fatal(err)
	}
	if touched.ModTimeNS == first.ModTimeNS {
		t.Fatalf("the test must actually change the mtime")
	}
	if !Unchanged(first, touched) {
		t.Fatalf("an identical file with a new mtime must stay unchanged")
	}
	// Same length, different bytes: a change, even though size matches.
	if err := os.WriteFile(path, []byte("two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rewritten, err := Digest(path)
	if err != nil {
		t.Fatal(err)
	}
	if rewritten.Size != first.Size {
		t.Fatalf("the fixture must keep the same size (got %d vs %d)", rewritten.Size, first.Size)
	}
	if Unchanged(first, rewritten) {
		t.Fatalf("a same-size rewrite must not be treated as unchanged")
	}
}

// Inspect reports unchanged only against a prior entry with the same digest.
func TestInspectAgainstPrior(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.jsonl")
	if err := os.WriteFile(path, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	state, unchanged, err := Inspect(path, nil)
	if err != nil || unchanged {
		t.Fatalf("no prior state must parse, got (%v, %v)", unchanged, err)
	}
	prior := map[string]FileState{path: state}
	if _, unchanged, err := Inspect(path, prior); err != nil || !unchanged {
		t.Fatalf("a matching prior state must skip, got (%v, %v)", unchanged, err)
	}
	if err := os.WriteFile(path, []byte("y\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, unchanged, err := Inspect(path, prior); err != nil || unchanged {
		t.Fatalf("changed content must parse, got (%v, %v)", unchanged, err)
	}
	// A missing file is an error, never a skip.
	if _, unchanged, err := Inspect(filepath.Join(dir, "missing.jsonl"), prior); err == nil || unchanged {
		t.Fatalf("a missing file must report an error, got (%v, %v)", unchanged, err)
	}
}
