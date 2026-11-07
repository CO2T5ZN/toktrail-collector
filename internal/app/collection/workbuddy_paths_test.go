package collection

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/managedconsent"
)

func TestManagedWorkBuddyDirectoryLayouts(t *testing.T) {
	for _, tc := range []struct {
		name               string
		primary, alternate bool
		existing, disabled bool
		want               string
	}{
		{"alternate only", false, true, false, false, ".workbuddy"},
		{"preferred only", true, false, false, false, ".workbuddy-ai"},
		{"both", true, true, false, false, ".workbuddy-ai"},
		{"neither", false, false, false, false, ""},
		{"keep existing alternate when preferred appears", true, true, true, false, ".workbuddy"},
		{"honor disabled alternate when preferred appears", true, true, true, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			store := grants.New(t.TempDir())
			primary := filepath.Join(home, ".workbuddy-ai", "projects")
			alternate := filepath.Join(home, ".workbuddy", "projects")
			for path, present := range map[string]bool{primary: tc.primary, alternate: tc.alternate} {
				if present {
					if err := os.MkdirAll(path, 0o700); err != nil {
						t.Fatal(err)
					}
				}
			}
			if tc.existing {
				if _, err := store.Enable("workbuddy-jsonl", alternate); err != nil {
					t.Fatal(err)
				}
				if tc.disabled {
					if _, _, err := store.Disable("workbuddy-jsonl", alternate); err != nil {
						t.Fatal(err)
					}
				}
			}
			view := managedconsent.View{ConsentRevision: 1, AllowedTools: []string{"WorkBuddy"}, DeviceGrantManaged: true}
			for attempt := 0; attempt < 2; attempt++ {
				added, pending, err := mergeManagedGrants(store, view, home, nil)
				if err != nil {
					t.Fatal(err)
				}
				if tc.disabled {
					if !strings.Contains(pending["WorkBuddy"], "manually disabled") || len(added) != 0 {
						t.Fatalf("disabled grant bypassed: added=%v pending=%v", added, pending)
					}
				} else if tc.want == "" {
					if !strings.HasPrefix(pending["WorkBuddy"], "default directory not found:") {
						t.Fatalf("missing directory not reported: %v", pending)
					}
				} else if len(pending) != 0 {
					t.Fatalf("available layout must not remain pending: %v", pending)
				}
				enabled, err := store.Enabled()
				if err != nil {
					t.Fatal(err)
				}
				if tc.want == "" {
					if len(enabled) != 0 {
						t.Fatalf("unexpected grants: %+v", enabled)
					}
				} else if len(enabled) != 1 || enabled[0].Input != filepath.Join(home, tc.want, "projects") {
					t.Fatalf("unexpected selected layout: %+v", enabled)
				}
				if attempt > 0 && len(added) != 0 {
					t.Fatalf("repeated sync must not add duplicate grants: %v", added)
				}
			}
		})
	}
}

func TestManagedWorkBuddyFallbackDoesNotHideProbeErrors(t *testing.T) {
	for _, failingLayout := range []string{".workbuddy-ai", ".workbuddy"} {
		t.Run(failingLayout, func(t *testing.T) {
			home := t.TempDir()
			probe := func(path string) (bool, error) {
				if path == filepath.Join(home, failingLayout, "projects") {
					return false, os.ErrPermission
				}
				return true, nil
			}
			view := managedconsent.View{ConsentRevision: 1, AllowedTools: []string{"WorkBuddy"}}
			_, _, err := mergeManagedGrants(grants.New(t.TempDir()), view, home, probe)
			if !errors.Is(err, os.ErrPermission) {
				t.Fatalf("probe failure must surface, got %v", err)
			}
		})
	}
}
