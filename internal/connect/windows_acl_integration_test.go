//go:build windows

package connect

// A real end-to-end Windows ACL test for the connect-side
// default-directory probe fail-closed contract: the Windows twin of
// TestConnectProbePermissionErrorFailsClosed, whose os.Chmod(0o000)
// trick only bites on Unix (POSIX mode bits do not exist on Windows,
// so chmod there cannot make the probe fail with permission denied).
//
// The test is OPT-IN because it mutates a real NTFS ACL: it runs only
// when TOKTRAIL_WINDOWS_ACL_E2E=1 is set in the environment. Once
// opted in it never skips past a mechanism it relies on — every step
// (the deny taking effect, the fail-closed run, the ACL restoration)
// is a hard assertion, so a Windows or filesystem combination that
// does not honor the deny fails the test loudly instead of reporting
// a fabricated pass. No real account or production service is
// involved: the connect URL points at the same in-process httptest
// pair probeFailServers builds.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// windowsACLEnv is the opt-in switch for the real Windows ACL test.
const windowsACLEnv = "TOKTRAIL_WINDOWS_ACL_E2E"

// TestConnectProbeWindowsACLDenyFailsClosed pins the honest-error
// contract with a REAL deny ACE: the tool's default input directory
// exists but is unreadable for the very user running the collector, so
// connect must fail the run with the probe error (wrapping
// os.ErrPermission) instead of reporting a fabricated not_detected
// status, posting tool statuses, or recording grants.
//
// Why the deny mask is exactly (RD,RA,X,S) on the LEAF directory the
// probe stats (never on a parent):
//
//   - RD (list directory) and X (traverse) carry the "deny read or
//     traverse" half the regression is about.
//   - RA (read attributes) and S (synchronize) are what actually makes
//     os.Stat fail on Windows. Go's os.Stat first tries
//     GetFileAttributesEx and then falls back to CreateFile with a
//     desired access of 0, and a zero-access open would normally slip
//     past any DACL — but Win32 CreateFile implicitly requests
//     SYNCHRONIZE and FILE_READ_ATTRIBUTES on every open, and the
//     attribute query needs FILE_READ_ATTRIBUTES as well, so denying
//     RA+S is expected to close both paths with ERROR_ACCESS_DENIED,
//     which Go reports as os.ErrPermission.
//   - Denying traverse on the PARENT instead would be unreliable: with
//     the default "Bypass traverse checking" user right
//     (SeChangeNotifyPrivilege, granted to Everyone by default) the
//     traverse ACE — deny included — is simply not evaluated, so a
//     parent deny cannot be relied on to block the probe.
//
// Restoration safety: the mask deliberately contains no DELETE,
// READ_CONTROL, WRITE_DAC or WRITE_OWNER. The object owner always
// holds implicit READ_CONTROL and WRITE_DAC that a DACL deny cannot
// strip (unless an OWNER_RIGHTS ACE exists, which icacls never
// writes), and the ACL-repair APIs request exactly those rights, so
// the same user can always remove the deny again. The restore runs
// from t.Cleanup — registered BEFORE the deny is applied, so LIFO
// ordering restores the ACL before t.TempDir's own removal — through
// a fallback chain, and it proves the recovery with os.Stat before
// declaring success.
func TestConnectProbeWindowsACLDenyFailsClosed(t *testing.T) {
	if os.Getenv(windowsACLEnv) != "1" {
		t.Skipf("set %s=1 to run the real Windows ACL deny integration test", windowsACLEnv)
	}

	icaclsPath, err := exec.LookPath("icacls")
	if err != nil {
		t.Fatalf("icacls is required to apply the deny ACE: %v", err)
	}
	u, err := user.Current()
	if err != nil {
		t.Fatalf("resolve the current user for the deny ACE: %v", err)
	}
	if u.Uid == "" {
		t.Fatal("the current user has no SID to deny")
	}
	// icacls treats a leading '*' as a raw SID, which avoids account
	// name resolution ambiguity (domain vs MicrosoftAccount spellings).
	denyTrustee := "*" + u.Uid

	// The denied path lives exclusively inside this test's t.TempDir()
	// tree, and the icacls commands below touch only this one leaf
	// directory, so the whole test's blast radius is a single
	// per-test-unique, empty, disposable directory.
	home := t.TempDir()
	qwenProjects := filepath.Join(home, ".qwen", "projects")
	if err := os.MkdirAll(qwenProjects, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(qwenProjects); err != nil {
		t.Fatalf("baseline os.Stat must succeed before the deny is applied, got %v", err)
	}

	// restore removes the deny ACE again and proves the recovery with
	// os.Stat. denyApplied flips on right before the /deny command
	// runs, so even an icacls failure that partially applied schedules
	// the restore; when nothing was applied, the removals are no-ops
	// and the final /reset simply re-applies the inherited default.
	var denyApplied bool
	restore := func() error {
		if !denyApplied {
			return nil
		}
		type icaclsAttempt struct {
			label string
			args  []string
		}
		attempts := []icaclsAttempt{
			{"remove the deny ACE by SID", []string{qwenProjects, "/remove:d", denyTrustee}},
		}
		if u.Username != "" {
			attempts = append(attempts, icaclsAttempt{"remove the deny ACE by account name", []string{qwenProjects, "/remove:d", u.Username}})
		}
		attempts = append(attempts, icaclsAttempt{"reset the ACL to the inherited default", []string{qwenProjects, "/reset"}})

		var errs []error
		for _, attempt := range attempts {
			out, runErr := exec.Command(icaclsPath, attempt.args...).CombinedOutput()
			if runErr == nil {
				_, statErr := os.Stat(qwenProjects)
				if statErr == nil {
					denyApplied = false
					return nil // restored and verified
				}
				runErr = fmt.Errorf("icacls reported success but the directory is still not statable: %w", statErr)
			}
			errs = append(errs, fmt.Errorf("%s: %v (icacls output: %q)", attempt.label, runErr, out))
		}
		return errors.Join(errs...)
	}
	// Registered before the deny exists (LIFO: this runs before
	// t.TempDir's own removal), so any exit path — including every
	// t.Fatalf below — restores the ACL before the cleanup removes the
	// tree.
	t.Cleanup(func() {
		if err := restore(); err != nil {
			t.Errorf("restoring the ACL failed; %s may need manual repair (icacls %s /remove:d %s): %v",
				qwenProjects, qwenProjects, denyTrustee, err)
		}
	})

	// Apply the deny for the current user on the probe's exact target
	// directory. See the function comment for why the mask must carry
	// RA and S in addition to the read/traverse bits.
	denyApplied = true
	if out, denyErr := exec.Command(icaclsPath, qwenProjects, "/deny", denyTrustee+":(RD,RA,X,S)").CombinedOutput(); denyErr != nil {
		t.Fatalf("icacls failed to apply the deny ACE (the temp directory is likely not NTFS): %v — output: %q", denyErr, out)
	}

	// The load-bearing verification: the deny must REALLY make os.Stat
	// fail with a permission error for this very user. A Windows or
	// filesystem combination that does not honor the deny fails here
	// instead of pressing on to a fabricated pass.
	if _, err := os.Stat(qwenProjects); err == nil {
		t.Fatal("the deny ACE must make os.Stat fail with a permission error, but os.Stat succeeded — refusing to report a pass the ACL does not deliver")
	} else if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("the deny ACE must make os.Stat fail with os.ErrPermission, got %v", err)
	}

	// The connect run over the denied directory must fail closed with
	// the probe error, must not report a fabricated not_detected tool
	// status, and must not record a grant over the failed probe.
	connectURL, toolStatusPosts := probeFailServers(t, []string{"Qwen Code"})
	stateDir := t.TempDir()
	_, err = Run(context.Background(), Options{
		URL:        connectURL,
		StateDir:   stateDir,
		HomeDir:    home,
		HTTPClient: http.DefaultClient,
	})
	if err == nil {
		t.Fatal("an ACL-denied default-directory probe must fail connect")
	}
	if !strings.Contains(err.Error(), "probe default directory for tool") || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("the probe error must surface verbatim, got %v", err)
	}
	if *toolStatusPosts != 0 {
		t.Fatalf("a denied probe must not report a fabricated not_detected status, got %d posts", *toolStatusPosts)
	}
	noGrantRecorded(t, stateDir, "qwen")

	// Restore on the happy path too (not only via Cleanup), so the
	// recovery itself is asserted, with a hard failure if it does not
	// hold. After this the Cleanup restore is a verified no-op.
	if err := restore(); err != nil {
		t.Fatalf("failed to restore the ACL after the run: %v", err)
	}
}
