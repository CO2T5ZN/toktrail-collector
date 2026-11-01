// Reflected-credential defense for the cursor account source, end to
// end: a hostile TokTrail server can answer the enable call (which
// presents the long-lived device secret) with a source whose strings
// mirror that secret — the accountsource trust boundary refuses such a
// source wholesale, so no permit is persisted, nothing uploads, and no
// later status output can print the credential. The same defense covers
// the source STATE the server reports on the self view: an
// unrecognized state renders as the fixed word "unknown", never the raw
// text. Everything here is synthetic: a local fake TokTrail server
// reflecting the synthetic device secret, a fake credential, verify and
// pull — no real user state is ever touched.
package cursorsync_test

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/cursor/accountsource"
	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/cursor/usage"
	"toktrail-collector/internal/local/cursoroutbox"
	"toktrail-collector/internal/local/cursorsource"
	syncclient "toktrail-collector/internal/syncclient"
)

// poisonedSource returns the default source with one field replaced by
// the reflected device secret.
func poisonedSource(field, value string) protocol.Source {
	s := defaultSource()
	switch field {
	case "sourceInstanceId":
		s.SourceInstanceID = value
	case "sourceType":
		s.SourceType = value
	case "state":
		s.State = value
	}
	return s
}

// TestCursorEnableRefusesMirroredSourceEndToEnd: a malicious 201 that
// plants the device secret into any source string is refused at the
// accountsource boundary — the round fails with the fixed sentinel
// (never echoing the credential), no permit is written to disk, the
// credential verification happened but nothing was pulled and nothing
// was uploaded. The self view stays clean (only the enable answer
// carries the mirror), so the refusal provably comes from the enable
// trust boundary itself.
func TestCursorEnableRefusesMirroredSourceEndToEnd(t *testing.T) {
	cases := []struct {
		name  string
		field string
		value string
	}{
		{"secret as the source instance id", "sourceInstanceId", testDeviceSecret},
		{"secret embedded in the source instance id", "sourceInstanceId", "src-inst-" + testDeviceSecret},
		{"uppercase secret as the source instance id", "sourceInstanceId", strings.ToUpper(testDeviceSecret)},
		{"secret as the source type", "sourceType", testDeviceSecret},
		{"secret as the state", "state", testDeviceSecret},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			// Clean self view; only the enable answer carries the
			// mirrored credential.
			h.srv.setSource(defaultSource())
			h.srv.setEnableSource(poisonedSource(tc.field, tc.value))
			confirm := &fakeConfirm{answer: true}
			requireNoPermit(t, h.dir)

			res, err := cursorsync.Enable(context.Background(), h.options(), confirm.confirm)
			if !errors.Is(err, accountsource.ErrMirroredCredential) {
				t.Fatalf("the mirrored enable response must be refused with the accountsource sentinel: %v", err)
			}
			if strings.Contains(err.Error(), testDeviceSecret) || strings.Contains(err.Error(), strings.ToUpper(testDeviceSecret)) {
				t.Fatalf("the refusal must never echo the credential: %v", err)
			}
			if res.ServerEnabled {
				t.Fatalf("a refused enable must not report a server-enabled source: %+v", res)
			}
			// Nothing persisted: no permit file exists afterwards.
			requireNoPermit(t, h.dir)
			// Nothing uploaded and nothing pulled: the round stopped at
			// the refused enable.
			if _, _, ingest, _, _ := h.srv.stats(); ingest != 0 {
				t.Fatalf("no batch may be uploaded, ingest=%d", ingest)
			}
			if calls := h.pull.callLog(); len(calls) != 0 {
				t.Fatalf("no upstream pull may happen, got %d", len(calls))
			}
		})
	}
}

// TestCursorEnableSelfViewMirrorFailsClosedEarlier pins the layering: a
// credential mirrored into the SELF view (not just the enable answer)
// is refused even earlier by the syncclient self-snapshot guard — the
// round fails closed before the enable call, nothing is persisted and
// nothing uploads, with a fixed message that never names the mirror.
func TestCursorEnableSelfViewMirrorFailsClosedEarlier(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(poisonedSource("state", testDeviceSecret))
	confirm := &fakeConfirm{answer: true}
	requireNoPermit(t, h.dir)

	_, err := cursorsync.Enable(context.Background(), h.options(), confirm.confirm)
	if !errors.Is(err, syncclient.ErrSelfProtocol) {
		t.Fatalf("a self-view mirror must be refused by the snapshot guard: %v", err)
	}
	if strings.Contains(err.Error(), testDeviceSecret) || strings.Contains(err.Error(), strings.ToUpper(testDeviceSecret)) {
		t.Fatalf("the refusal must never echo the credential: %v", err)
	}
	requireNoPermit(t, h.dir)
	if _, _, ingest, _, _ := h.srv.stats(); ingest != 0 {
		t.Fatalf("no batch may be uploaded, ingest=%d", ingest)
	}
	if calls := h.pull.callLog(); len(calls) != 0 {
		t.Fatalf("no upstream pull may happen, got %d", len(calls))
	}
}

// TestCursorSyncUnknownSourceStateRendersFixedUnknown: a source state
// the collector does not recognize skips the round with the fixed
// unknown-state message, never echoing the raw value into the Skipped
// diagnostics that connect and the CLI print. (A state that reflects
// the device secret never reaches this layer: syncclient's fetchSelf
// guard fails the self check closed first, so the fixture uses a benign
// unrecognized state.)
func TestCursorSyncUnknownSourceStateRendersFixedUnknown(t *testing.T) {
	h := newHarness(t)
	poisoned := defaultSource()
	poisoned.State = "some-unrecognized-server-state"
	h.srv.setSource(poisoned)
	h.writeLicense(t, activeLicenseForA())

	res, err := cursorsync.Sync(context.Background(), h.options(), syncGate())
	if err != nil {
		t.Fatalf("an unknown state is a skip, not a failure: %v", err)
	}
	if res.Skipped != "the cursor source is in an unknown server state" {
		t.Fatalf("the skip reason must be the fixed unknown-state message, got %q", res.Skipped)
	}
	if strings.Contains(res.Skipped, testDeviceSecret) {
		t.Fatalf("the raw state must never be echoed: %q", res.Skipped)
	}
	if res.Outcome != cursorsync.RoundAuthWithheld {
		t.Fatalf("an unknown state classifies as an authorization verdict, got %q", res.Outcome)
	}
	if res.SyncedBatches != 0 {
		t.Fatalf("nothing may be uploaded: %+v", res)
	}
	if _, _, ingest, _, _ := h.srv.stats(); ingest != 0 {
		t.Fatalf("no batch may be uploaded, ingest=%d", ingest)
	}
	if calls := h.pull.callLog(); len(calls) != 0 {
		t.Fatalf("no upstream pull may happen, got %d", len(calls))
	}
}

// requireNoPermit asserts no cursor permit exists in the state
// directory.
func requireNoPermit(t *testing.T, dir string) {
	t.Helper()
	if _, ok, err := cursorsource.New(dir).Load(); err == nil && ok {
		t.Fatal("no cursor permit may be persisted")
	}
}

// TestCursorDrainRetryPreflightOldPermitSourceIDNeverEchoed: a permit
// persisted before the reflection boundary may carry a credential a
// malicious server mirrored under an EARLIER device binding — text that
// no longer matches the current secret, so the self-view guard passes
// and the round runs. When the retry preflight then finds the source no
// longer designated, the refusal names no id: the historical (possibly
// credential-shaped) text never travels into the Note diagnostics that
// connect and the CLI print.
func TestCursorDrainRetryPreflightOldPermitSourceIDNeverEchoed(t *testing.T) {
	// A credential-shaped id from a previous binding: not the current
	// secret, so no guard refuses it — exactly an old polluted permit.
	const staleMirroredID = "stale-mirrored-secret-4d5e6f7a8b9c0d1e"
	h := newHarness(t)
	poisoned := defaultSource()
	poisoned.SourceInstanceID = staleMirroredID
	h.srv.setSource(poisoned)
	license := activeLicenseForA()
	license.SourceInstanceID = staleMirroredID
	h.writeLicense(t, license)
	seedPendingBatchForSource(t, h.dir, "cursor-old-permit-1", 1, staleMirroredID)
	// The first POST fails transiently; the server drops the source
	// before the retry preflight re-fetches the self view.
	h.srv.setIngestScript(scriptedIngest{status: http.StatusServiceUnavailable})
	h.srv.setIngestHook(func() { h.srv.dropSource() })

	opt := h.options()
	opt.Retry = retryPolicy(h.clock, 2)
	res, err := cursorsync.DrainPending(context.Background(), opt, syncGate())
	if err != nil {
		t.Fatalf("the drift must stop the round, not fail it: %v", err)
	}
	if res.Outcome != cursorsync.RoundFenceStop {
		t.Fatalf("the undesignated source must stop the round as a drift, got %q", res.Outcome)
	}
	if !strings.Contains(res.Skipped, "stopped") || res.Note == "" {
		t.Fatalf("the stop must be reported: %+v", res)
	}
	if strings.Contains(res.Skipped, staleMirroredID) || strings.Contains(res.Note, staleMirroredID) {
		t.Fatalf("the historical source id must never be echoed: skipped=%q note=%q", res.Skipped, res.Note)
	}
	if res.SyncedBatches != 0 || res.PendingRemaining != 1 {
		t.Fatalf("nothing may be acknowledged: %+v", res)
	}
	if _, _, ingest, _, _ := h.srv.stats(); ingest != 1 {
		t.Fatalf("only the first POST may happen, ingest=%d", ingest)
	}
}

// seedPendingBatchForSource persists a pending batch bound to an
// arbitrary source id (the shared helper hardcodes src_inst_1), fence 1.
func seedPendingBatchForSource(t *testing.T, dir, batchID string, n int, sourceID string) {
	t.Helper()
	records := make([]protocol.Event, 0, n)
	for i := 0; i < n; i++ {
		records = append(records, protocol.Event{
			EventKey:       protocol.EventKeyPrefix + strings.Repeat("0", 63) + strconv.Itoa(i+1),
			Revision:       1,
			Kind:           "event",
			OccurredAt:     baseTime.Format(time.RFC3339Nano),
			Tool:           protocol.Tool,
			AdapterVersion: usage.AdapterVersion,
			SourceType:     protocol.SourceType,
		})
	}
	batch := protocol.Batch{BatchID: batchID, SourceInstanceID: sourceID, Records: records}
	encoded, err := protocol.EncodeBatch(batch)
	if err != nil {
		t.Fatalf("encode seed batch: %v", err)
	}
	if _, err := cursoroutbox.New(dir).AddBatch(batch, 1, encoded); err != nil {
		t.Fatalf("seed pending batch: %v", err)
	}
}
