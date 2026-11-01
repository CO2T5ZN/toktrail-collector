package cursorsync_test

import (
	"context"
	"os"
	"testing"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/local/cursoroutbox"
)

func TestStoppedDrainFailsClosedWhenPendingCountIsUnreadable(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	seedPendingBatch(t, h.dir, "paused-corrupt-count", 1)
	h.srv.setIngestCode("source_paused")
	h.srv.setIngestHook(func() {
		if err := os.WriteFile(cursoroutbox.New(h.dir).Path(), []byte("{"), 0600); err != nil {
			t.Errorf("corrupt synthetic ledger: %v", err)
		}
	})
	result, err := cursorsync.Sync(context.Background(), h.options(), syncGate())
	if err == nil || result.Outcome != cursorsync.RoundError {
		t.Fatalf("unreadable pending queue must fail closed: outcome=%s err=%v", result.Outcome, err)
	}
	if _, _, posts, _, _ := h.srv.stats(); posts != 1 {
		t.Fatalf("expected one attempted POST before stopped recount, got %d", posts)
	}
}
