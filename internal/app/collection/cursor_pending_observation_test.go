package collection

import (
	"testing"

	"toktrail-collector/internal/app/cursorsync"
)

func TestPreserveCursorPendingRecordsObservation(t *testing.T) {
	for _, n := range []int{0, 3} {
		result := cursorsync.Result{PendingRemaining: 9}
		drain := cursorQueueDrain{agg: &result}
		drain.preservePending(n, true)
		if !result.PendingCounted || result.PendingRemaining != n {
			t.Fatalf("reported measured count must be retained: %+v", result)
		}
	}
}
