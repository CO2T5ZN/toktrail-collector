package connect

import (
	"testing"

	"toktrail-collector/internal/app/collection"
)

func TestBacklogProgressWhenCursorSkipped(t *testing.T) {
	pass := collection.Result{PendingRemaining: 3, DrainStopped: "server paused"}
	if backlogPassMadeProgress(pass, 3, 2, true) {
		t.Fatal("skipped cursor queue and paused device must not report progress")
	}
	pass.SyncedBatches = 1
	if !backlogPassMadeProgress(pass, 3, 2, true) {
		t.Fatal("a synced device batch must count as progress")
	}
}
