package diagnostic

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toktrail-collector/internal/scheduler"
)

func TestBackgroundTaskCheck(t *testing.T) {
	state := t.TempDir()
	launcher := filepath.Join(t.TempDir(), scheduler.WindowsBackgroundBinary)
	if err := os.WriteFile(launcher, []byte("synthetic helper"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		info   scheduler.WindowsTaskInfo
		err    error
		want   CheckStatus
		phrase string
	}{
		{"unqueryable", scheduler.WindowsTaskInfo{}, errors.New("synthetic query failure"), CheckWarn, "could not be verified"},
		{"absent", scheduler.WindowsTaskInfo{}, nil, CheckSkipped, "no scheduled task"},
		{"legacy", scheduler.WindowsTaskInfo{Registered: true}, nil, CheckWarn, "service refresh"},
		{"missing helper", scheduler.WindowsTaskInfo{Registered: true, Background: true, Launcher: launcher + ".missing"}, nil, CheckFail, "missing"},
		{"directory instead of helper", scheduler.WindowsTaskInfo{Registered: true, Background: true, Launcher: state}, nil, CheckFail, "regular file"},
		{"background ready", scheduler.WindowsTaskInfo{Registered: true, Background: true, Launcher: launcher}, nil, CheckOK, filepath.Join(state, "logs")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := backgroundTaskCheck(tc.info, tc.err, state)
			if got.Status != tc.want || !strings.Contains(got.Detail, tc.phrase) {
				t.Fatalf("check=%+v want status=%s phrase=%q", got, tc.want, tc.phrase)
			}
		})
	}
}
