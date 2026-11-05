package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"toktrail-collector/internal/distribution"
)

func generateTestPubKey(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := distribution.PublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pub, pem
}

func testManifest(version string) *distribution.Manifest {
	return &distribution.Manifest{
		Schema:      distribution.ManifestSchema,
		Product:     distribution.ProductName,
		Version:     version,
		GeneratedAt: "2026-10-24T00:00:00Z",
		Artifacts: []distribution.Artifact{
			{
				OS:                    "darwin",
				Arch:                  "arm64",
				InstallerBinary:       "toktrail-release-" + version + "-darwin-arm64",
				InstallerBinarySha256: strings.Repeat("a", 64),
			},
			{
				OS:                    "darwin",
				Arch:                  "amd64",
				InstallerBinary:       "toktrail-release-" + version + "-darwin-amd64",
				InstallerBinarySha256: strings.Repeat("b", 64),
			},
			{
				OS:                    "linux",
				Arch:                  "arm64",
				InstallerBinary:       "toktrail-release-" + version + "-linux-arm64",
				InstallerBinarySha256: strings.Repeat("c", 64),
			},
			{
				OS:                    "linux",
				Arch:                  "amd64",
				InstallerBinary:       "toktrail-release-" + version + "-linux-amd64",
				InstallerBinarySha256: strings.Repeat("d", 64),
			},
			{
				OS:                    "windows",
				Arch:                  "amd64",
				InstallerBinary:       "toktrail-release-" + version + "-windows-amd64.exe",
				InstallerBinarySha256: strings.Repeat("e", 64),
			},
			{
				OS:                    "windows",
				Arch:                  "arm64",
				InstallerBinary:       "toktrail-release-" + version + "-windows-arm64.exe",
				InstallerBinarySha256: strings.Repeat("f", 64),
			},
		},
	}
}

func TestScriptStaticInvariants(t *testing.T) {
	dir := t.TempDir()
	_, pubPEM := generateTestPubKey(t)
	m := testManifest("v1.2.3")

	paths, err := EmitInstallScripts(dir, m, pubPEM)
	if err != nil {
		t.Fatalf("EmitInstallScripts: %v", err)
	}

	var shPath, ps1Path string
	for _, p := range paths {
		if strings.HasSuffix(p, ".sh") {
			shPath = p
		} else if strings.HasSuffix(p, ".ps1") {
			ps1Path = p
		}
	}
	if shPath == "" || ps1Path == "" {
		t.Fatalf("expected both .sh and .ps1 scripts, got %v", paths)
	}

	shContent, err := os.ReadFile(shPath)
	if err != nil {
		t.Fatal(err)
	}
	shStr := string(shContent)

	// POSIX script invariants:
	// 1. Must NOT use exec before installer (so EXIT trap cleanup runs).
	if strings.Contains(shStr, "exec \"$TMP") || strings.Contains(shStr, "exec $TMP") {
		t.Errorf("POSIX install script still uses exec to run installer, preventing cleanup trap")
	}
	// 2. Must register EXIT trap for cleanup.
	if !strings.Contains(shStr, "trap cleanup EXIT") {
		t.Errorf("POSIX install script missing 'trap cleanup EXIT'")
	}
	// 3. Must guard TMP against empty and non-absolute before rm -rf.
	if !strings.Contains(shStr, "/*)") || !strings.Contains(shStr, "rm -rf \"$TMP\"") {
		t.Errorf("POSIX install script missing guarded rm -rf for absolute TMP")
	}
	// 4. Must pin the public key.
	if !strings.Contains(shStr, pubPEM) {
		t.Errorf("POSIX install script missing pinned public key")
	}
	// 5. Must default BASE_URL to the official GitHub release download root.
	wantDefaultBase := "https://github.com/lich0821/toktrail-collector/releases/download/" + m.Version
	if !strings.Contains(shStr, wantDefaultBase) {
		t.Errorf("POSIX install script missing default GitHub base URL %q", wantDefaultBase)
	}
	// 6. Must default INSTALL_DIR under $HOME/.toktrail/bin.
	if !strings.Contains(shStr, "$HOME/.toktrail/bin") {
		t.Errorf("POSIX install script missing default install dir $HOME/.toktrail/bin")
	}
	// 7. Must support --connect and reject unknown flags without evaluating the link.
	if !strings.Contains(shStr, "--connect") {
		t.Errorf("POSIX install script missing --connect support")
	}
	if strings.Contains(shStr, "eval") {
		t.Errorf("POSIX install script must not eval the connect link")
	}
	// 8. Must support --upgrade and reject the connect combination.
	if !strings.Contains(shStr, "--upgrade") {
		t.Errorf("POSIX install script missing --upgrade support")
	}
	if !strings.Contains(shStr, "--upgrade and --connect are mutually exclusive") {
		t.Errorf("POSIX install script missing --upgrade/--connect mutual exclusion")
	}
	// 9. Upgrade mode must not default the install directory.
	if !strings.Contains(shStr, "the pinned installer discovers the existing") {
		t.Errorf("POSIX install script missing upgrade-mode install-dir discovery comment")
	}

	ps1Content, err := os.ReadFile(ps1Path)
	if err != nil {
		t.Fatal(err)
	}
	ps1Str := string(ps1Content)

	// PowerShell script invariants:
	// 1. Must have try / finally block.
	if !strings.Contains(ps1Str, "try {") || !strings.Contains(ps1Str, "finally {") {
		t.Errorf("PowerShell install script missing try / finally block")
	}
	// 2. Finally block must remove $tmp.
	if !strings.Contains(ps1Str, "Remove-Item -Recurse -Force $tmp") {
		t.Errorf("PowerShell install script missing cleanup in finally block")
	}
	// 3. Must propagate installer and curl failure exit codes.
	if !strings.Contains(ps1Str, "$LASTEXITCODE") {
		t.Errorf("PowerShell install script missing $LASTEXITCODE propagation")
	}
	// 4. Must default -BaseUrl to the official GitHub release download root.
	if !strings.Contains(ps1Str, wantDefaultBase) {
		t.Errorf("PowerShell install script missing default GitHub base URL %q", wantDefaultBase)
	}
	// 5. Must default -InstallDir under .toktrail\bin.
	if !strings.Contains(ps1Str, ".toktrail\\bin") {
		t.Errorf("PowerShell install script missing default install dir under .toktrail\\bin")
	}
	// 6. Must support -ConnectUrl.
	if !strings.Contains(ps1Str, "-ConnectUrl") && !strings.Contains(ps1Str, "$ConnectUrl") {
		t.Errorf("PowerShell install script missing -ConnectUrl support")
	}
	if strings.Contains(ps1Str, "Invoke-Expression") {
		t.Errorf("PowerShell install script must not Invoke-Expression the connect link")
	}
	// 7. Must support -Upgrade and reject the connect combination.
	if !strings.Contains(ps1Str, "[switch]$Upgrade") {
		t.Errorf("PowerShell install script missing -Upgrade switch")
	}
	if !strings.Contains(ps1Str, "-Upgrade and -ConnectUrl are mutually exclusive") {
		t.Errorf("PowerShell install script missing -Upgrade/-ConnectUrl mutual exclusion")
	}
	if !strings.Contains(ps1Str, "$PSBoundParameters.ContainsKey('InstallDir')") {
		t.Errorf("PowerShell install script missing explicit-InstallDir detection for upgrade mode")
	}
}

func TestPOSIXScriptBehavioralCleanup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping POSIX shell execution test on Windows")
	}

	dir := t.TempDir()
	serverDir := filepath.Join(dir, "dist")
	if err := os.MkdirAll(serverDir, 0o755); err != nil {
		t.Fatal(err)
	}

	version := "v0.9.9"
	_, pubPEM := generateTestPubKey(t)

	// Determine tool file name for current test runner host.
	var osName, archName string
	switch runtime.GOOS {
	case "darwin":
		osName = "darwin"
	case "linux":
		osName = "linux"
	default:
		t.Skipf("unsupported test OS: %s", runtime.GOOS)
	}
	switch runtime.GOARCH {
	case "arm64":
		archName = "arm64"
	case "amd64":
		archName = "amd64"
	default:
		t.Skipf("unsupported test ARCH: %s", runtime.GOARCH)
	}

	toolFile := fmt.Sprintf("toktrail-release-%s-%s-%s", version, osName, archName)
	fakeToolPath := filepath.Join(serverDir, toolFile)
	recordTmpFile := filepath.Join(dir, "recorded_tmp.txt")

	// Fake installer: writes the directory containing itself (TMP) to recordTmpFile and exits.
	fakeScript := fmt.Sprintf(`#!/bin/sh
set -eu
MY_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "$MY_DIR" > %q
if [ "${FAIL_INSTALLER:-0}" = "1" ]; then
  exit 42
fi
exit 0
`, recordTmpFile)

	if err := os.WriteFile(fakeToolPath, []byte(fakeScript), 0o755); err != nil {
		t.Fatal(err)
	}

	// Calculate hash of fakeToolPath.
	h := sha256.Sum256([]byte(fakeScript))
	toolHash := hex.EncodeToString(h[:])

	m := testManifest(version)
	for i := range m.Artifacts {
		if m.Artifacts[i].OS == osName && m.Artifacts[i].Arch == archName {
			m.Artifacts[i].InstallerBinarySha256 = toolHash
		}
	}

	scriptPaths, err := EmitInstallScripts(serverDir, m, pubPEM)
	if err != nil {
		t.Fatalf("EmitInstallScripts: %v", err)
	}

	var installScript string
	for _, p := range scriptPaths {
		if strings.HasSuffix(p, ".sh") {
			installScript = p
			break
		}
	}
	if installScript == "" {
		t.Fatal("install.sh not emitted")
	}

	// 1. Success case: verify installer runs, returns 0, and TMP directory is cleaned up.
	baseURL := "file://" + filepath.ToSlash(serverDir)
	cmd := exec.Command("/bin/sh", installScript, baseURL, filepath.Join(dir, "install_target"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("install.sh failed: %v\nOutput: %s", err, out)
	}

	recBytes, err := os.ReadFile(recordTmpFile)
	if err != nil {
		t.Fatalf("fake installer was not invoked: %v", err)
	}
	recordedTmp := strings.TrimSpace(string(recBytes))
	if recordedTmp == "" {
		t.Fatal("recordedTmp is empty")
	}
	if _, err := os.Stat(recordedTmp); !os.IsNotExist(err) {
		t.Errorf("TMP directory %s still exists after successful installer run; cleanup trap failed", recordedTmp)
	}

	// 2. Failure case: verify installer failure propagates exit code, and TMP directory is STILL cleaned up.
	os.Remove(recordTmpFile)
	cmdFail := exec.Command("/bin/sh", installScript, baseURL, filepath.Join(dir, "install_target"))
	cmdFail.Env = append(os.Environ(), "FAIL_INSTALLER=1")
	outFail, errFail := cmdFail.CombinedOutput()
	if errFail == nil {
		t.Fatalf("expected install.sh to fail with exit 42, but succeeded. Output: %s", outFail)
	}
	if exitErr, ok := errFail.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 42 {
			t.Errorf("expected exit code 42, got %d", exitErr.ExitCode())
		}
	} else {
		t.Errorf("unexpected error type: %v", errFail)
	}

	recBytesFail, err := os.ReadFile(recordTmpFile)
	if err != nil {
		t.Fatalf("fake installer was not invoked on failure test: %v", err)
	}
	recordedTmpFail := strings.TrimSpace(string(recBytesFail))
	if _, err := os.Stat(recordedTmpFail); !os.IsNotExist(err) {
		t.Errorf("TMP directory %s still exists after failed installer run; cleanup trap failed", recordedTmpFail)
	}
}

// connectTestFixture renders the install.sh for a fake installer that places
// a fake "toktrail" binary (a shell script) at the chosen install dir. The
// fake toktrail records any "connect <url>" invocation and can be told to
// fail via the CONNECT_FAIL env var, without ever using a real ticket/link.
func connectTestFixture(t *testing.T) (installScript, baseURL, connectRecordFile string, workDir string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("skipping POSIX shell execution test on Windows")
	}

	dir := t.TempDir()
	serverDir := filepath.Join(dir, "dist")
	if err := os.MkdirAll(serverDir, 0o755); err != nil {
		t.Fatal(err)
	}

	version := "v0.9.9"
	_, pubPEM := generateTestPubKey(t)

	var osName, archName string
	switch runtime.GOOS {
	case "darwin":
		osName = "darwin"
	case "linux":
		osName = "linux"
	default:
		t.Skipf("unsupported test OS: %s", runtime.GOOS)
	}
	switch runtime.GOARCH {
	case "arm64":
		archName = "arm64"
	case "amd64":
		archName = "amd64"
	default:
		t.Skipf("unsupported test ARCH: %s", runtime.GOARCH)
	}

	toolFile := fmt.Sprintf("toktrail-release-%s-%s-%s", version, osName, archName)
	fakeToolPath := filepath.Join(serverDir, toolFile)
	connectRecordFile = filepath.Join(dir, "recorded_connect.txt")

	// Fake installer: on "install ... -install-dir DIR" creates DIR and
	// writes a fake toktrail binary there. The fake toktrail binary, when
	// run as "connect <url>", records the url and exits with
	// $CONNECT_FAIL (default 0).
	fakeInstaller := fmt.Sprintf(`#!/bin/sh
set -eu
INSTALL_DIR=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-install-dir" ]; then
    INSTALL_DIR="$arg"
  fi
  prev="$arg"
done
[ -n "$INSTALL_DIR" ] || { echo "fake installer: missing -install-dir" >&2; exit 1; }
mkdir -p "$INSTALL_DIR"
cat > "$INSTALL_DIR/toktrail" <<FAKEEOF
#!/bin/sh
set -eu
if [ "\${1:-}" = "connect" ]; then
  echo "\$2" > %q
  exit "\${CONNECT_FAIL:-0}"
fi
echo "unsupported fake toktrail command: \$*" >&2
exit 1
FAKEEOF
chmod 0755 "$INSTALL_DIR/toktrail"
exit 0
`, connectRecordFile)

	if err := os.WriteFile(fakeToolPath, []byte(fakeInstaller), 0o755); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(fakeInstaller))
	toolHash := hex.EncodeToString(h[:])

	m := testManifest(version)
	for i := range m.Artifacts {
		if m.Artifacts[i].OS == osName && m.Artifacts[i].Arch == archName {
			m.Artifacts[i].InstallerBinarySha256 = toolHash
		}
	}

	scriptPaths, err := EmitInstallScripts(serverDir, m, pubPEM)
	if err != nil {
		t.Fatalf("EmitInstallScripts: %v", err)
	}
	for _, p := range scriptPaths {
		if strings.HasSuffix(p, ".sh") {
			installScript = p
			break
		}
	}
	if installScript == "" {
		t.Fatal("install.sh not emitted")
	}
	baseURL = "file://" + filepath.ToSlash(serverDir)
	return installScript, baseURL, connectRecordFile, dir
}

// TestConnectFlagInvokesInstalledBinary verifies --connect runs the
// just-installed toktrail binary's "connect" subcommand with the given
// link, using an absolute path, after a successful install. No real
// ticket/link value is used anywhere; a placeholder stands in for it.
func TestConnectFlagInvokesInstalledBinary(t *testing.T) {
	installScript, baseURL, connectRecordFile, dir := connectTestFixture(t)
	installTarget := filepath.Join(dir, "install_target")
	const placeholderLink = "TEST_TICKET_PLACEHOLDER"

	cmd := exec.Command("/bin/sh", installScript, baseURL, installTarget, "--connect", placeholderLink)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("install.sh --connect failed: %v\nOutput: %s", err, out)
	}

	recorded, err := os.ReadFile(connectRecordFile)
	if err != nil {
		t.Fatalf("connect was not invoked: %v", err)
	}
	if got := strings.TrimSpace(string(recorded)); got != placeholderLink {
		t.Errorf("connect invoked with %q, want %q", got, placeholderLink)
	}
}

// TestConnectFlagAfterLongOption verifies the --connect=LINK form works too.
func TestConnectFlagEqualsForm(t *testing.T) {
	installScript, baseURL, connectRecordFile, dir := connectTestFixture(t)
	installTarget := filepath.Join(dir, "install_target")
	const placeholderLink = "TEST_TICKET_PLACEHOLDER"

	cmd := exec.Command("/bin/sh", installScript, baseURL, installTarget, "--connect="+placeholderLink)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("install.sh --connect=LINK failed: %v\nOutput: %s", err, out)
	}

	recorded, err := os.ReadFile(connectRecordFile)
	if err != nil {
		t.Fatalf("connect was not invoked: %v", err)
	}
	if got := strings.TrimSpace(string(recorded)); got != placeholderLink {
		t.Errorf("connect invoked with %q, want %q", got, placeholderLink)
	}
}

// TestConnectFlagFailurePropagates verifies a failing "toktrail connect"
// exit code propagates as the install script's own exit code, even though
// the binary installation itself already succeeded.
func TestConnectFlagFailurePropagates(t *testing.T) {
	installScript, baseURL, _, dir := connectTestFixture(t)
	installTarget := filepath.Join(dir, "install_target")
	const placeholderLink = "TEST_TICKET_PLACEHOLDER"

	cmd := exec.Command("/bin/sh", installScript, baseURL, installTarget, "--connect", placeholderLink)
	cmd.Env = append(os.Environ(), "CONNECT_FAIL=13")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected install.sh to fail with exit 13, but succeeded. Output: %s", out)
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("unexpected error type: %v", err)
	}
	if exitErr.ExitCode() != 13 {
		t.Errorf("exit code = %d, want 13", exitErr.ExitCode())
	}
	// The binary must still be installed; only connect failed.
	if _, statErr := os.Stat(filepath.Join(installTarget, "toktrail")); statErr != nil {
		t.Errorf("toktrail binary missing after connect failure: %v", statErr)
	}
}

// TestConnectFlagValidation verifies strict validation of the --connect
// flag and unknown arguments, without ever invoking the installer.
func TestConnectFlagValidation(t *testing.T) {
	installScript, baseURL, _, dir := connectTestFixture(t)
	installTarget := filepath.Join(dir, "install_target")

	cases := []struct {
		name string
		args []string
	}{
		{"missing connect value", []string{baseURL, installTarget, "--connect"}},
		{"empty connect value via equals", []string{baseURL, installTarget, "--connect="}},
		{"unknown flag", []string{baseURL, installTarget, "--bogus"}},
		{"extra positional argument", []string{baseURL, installTarget, "unexpected-extra"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("/bin/sh", append([]string{installScript}, tc.args...)...)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("expected install.sh to reject arguments, but succeeded. Output: %s", out)
			}
		})
	}
}

// upgradeTestFixture renders the install.sh pinned to a fake installer that
// records every argument it receives, so tests can assert how upgrade mode
// invokes the pinned installer without any real downloads or builds.
func upgradeTestFixture(t *testing.T) (installScript, baseURL, recordFile string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("skipping POSIX shell execution test on Windows")
	}

	dir := t.TempDir()
	serverDir := filepath.Join(dir, "dist")
	if err := os.MkdirAll(serverDir, 0o755); err != nil {
		t.Fatal(err)
	}

	version := "v0.9.9"
	_, pubPEM := generateTestPubKey(t)

	var osName, archName string
	switch runtime.GOOS {
	case "darwin":
		osName = "darwin"
	case "linux":
		osName = "linux"
	default:
		t.Skipf("unsupported test OS: %s", runtime.GOOS)
	}
	switch runtime.GOARCH {
	case "arm64":
		archName = "arm64"
	case "amd64":
		archName = "amd64"
	default:
		t.Skipf("unsupported test ARCH: %s", runtime.GOARCH)
	}

	toolFile := fmt.Sprintf("toktrail-release-%s-%s-%s", version, osName, archName)
	fakeToolPath := filepath.Join(serverDir, toolFile)
	recordFile = filepath.Join(dir, "recorded_args.txt")

	// Fake installer: records one argument per line, then exits 0.
	fakeInstaller := fmt.Sprintf(`#!/bin/sh
set -eu
printf '%%s\n' "$@" > %q
exit 0
`, recordFile)

	if err := os.WriteFile(fakeToolPath, []byte(fakeInstaller), 0o755); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(fakeInstaller))
	toolHash := hex.EncodeToString(h[:])

	m := testManifest(version)
	for i := range m.Artifacts {
		if m.Artifacts[i].OS == osName && m.Artifacts[i].Arch == archName {
			m.Artifacts[i].InstallerBinarySha256 = toolHash
		}
	}

	scriptPaths, err := EmitInstallScripts(serverDir, m, pubPEM)
	if err != nil {
		t.Fatalf("EmitInstallScripts: %v", err)
	}
	for _, p := range scriptPaths {
		if strings.HasSuffix(p, ".sh") {
			installScript = p
			break
		}
	}
	if installScript == "" {
		t.Fatal("install.sh not emitted")
	}
	baseURL = "file://" + filepath.ToSlash(serverDir)
	return installScript, baseURL, recordFile
}

func recordedArgs(t *testing.T, recordFile string) []string {
	t.Helper()
	data, err := os.ReadFile(recordFile)
	if err != nil {
		t.Fatalf("fake installer was not invoked: %v", err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// TestPOSIXScriptUpgradeModeInvokesInstallerWithoutDefaultInstallDir
// verifies --upgrade runs the pinned installer's upgrade subcommand and
// forwards no -install-dir unless one is explicitly given (the installer
// then discovers the existing binary on PATH itself).
func TestPOSIXScriptUpgradeModeInvokesInstallerWithoutDefaultInstallDir(t *testing.T) {
	installScript, baseURL, recordFile := upgradeTestFixture(t)

	cmd := exec.Command("/bin/sh", installScript, "--upgrade", baseURL)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install.sh --upgrade failed: %v\nOutput: %s", err, out)
	}
	args := recordedArgs(t, recordFile)
	if len(args) == 0 || args[0] != "upgrade" {
		t.Fatalf("installer invoked as %q, want subcommand \"upgrade\"", args)
	}
	for _, want := range []string{"-base-url", "-version", "-pubkey"} {
		if !containsArg(args, want) {
			t.Errorf("upgrade invocation missing %s: %q", want, args)
		}
	}
	if containsArg(args, "-install-dir") {
		t.Errorf("upgrade mode must not forward a default -install-dir: %q", args)
	}
}

// TestPOSIXScriptUpgradeModeForwardsExplicitInstallDir verifies an explicit
// directory is forwarded in upgrade mode.
func TestPOSIXScriptUpgradeModeForwardsExplicitInstallDir(t *testing.T) {
	installScript, baseURL, recordFile := upgradeTestFixture(t)
	dir := t.TempDir()

	cmd := exec.Command("/bin/sh", installScript, "--upgrade", baseURL, dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install.sh --upgrade with install dir failed: %v\nOutput: %s", err, out)
	}
	args := recordedArgs(t, recordFile)
	if args[0] != "upgrade" {
		t.Fatalf("installer invoked as %q, want subcommand \"upgrade\"", args)
	}
	if !containsArg(args, "-install-dir") {
		t.Fatalf("explicit install dir not forwarded: %q", args)
	}
	for i, a := range args {
		if a == "-install-dir" && i+1 < len(args) && args[i+1] != dir {
			t.Errorf("-install-dir = %q, want %q", args[i+1], dir)
		}
	}
}

// TestPOSIXScriptUpgradeRejectsConnect verifies --upgrade and --connect are
// mutually exclusive and the installer is never invoked.
func TestPOSIXScriptUpgradeRejectsConnect(t *testing.T) {
	installScript, baseURL, recordFile := upgradeTestFixture(t)

	cmd := exec.Command("/bin/sh", installScript, "--upgrade", baseURL, "--connect", "TEST_TICKET_PLACEHOLDER")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected install.sh --upgrade --connect to fail, succeeded. Output: %s", out)
	}
	if !strings.Contains(string(out), "mutually exclusive") {
		t.Errorf("failure should explain the mutual exclusion, got: %s", out)
	}
	if _, statErr := os.Stat(recordFile); !os.IsNotExist(statErr) {
		t.Error("the pinned installer must not be invoked when --upgrade --connect is rejected")
	}
}

// TestPOSIXScriptInstallModeStillDefaultsInstallDir verifies install mode
// keeps forwarding the (defaulted or given) install directory.
func TestPOSIXScriptInstallModeStillDefaultsInstallDir(t *testing.T) {
	installScript, baseURL, recordFile := upgradeTestFixture(t)
	dir := filepath.Join(t.TempDir(), "target")

	cmd := exec.Command("/bin/sh", installScript, baseURL, dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install.sh failed: %v\nOutput: %s", err, out)
	}
	args := recordedArgs(t, recordFile)
	if args[0] != "install" {
		t.Fatalf("installer invoked as %q, want subcommand \"install\"", args)
	}
	if !containsArg(args, "-install-dir") {
		t.Fatalf("install mode must forward -install-dir: %q", args)
	}
}

// The documented install runs the script through a pipe
// (`curl … | sh -s -- …`). In that shape the collector inherits the script
// pipeline as stdin, so a confirmation prompt that read stdin would see EOF
// or — under shells that parse incrementally — program text. This test
// executes the emitted script exactly that way and pins both facts the
// collector's terminal-based confirmation relies on:
//
//   - the collector's stdin is NOT a terminal;
//   - reading it yields no answer and, specifically, never runs the
//     install script's remaining text as if it were a typed answer.
func TestConnectFromPipeShapeNeverFeedsScriptTextToCollector(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell pipeline test")
	}
	installScript, baseURL, recordFile, dir := connectTestFixture(t)
	installTarget := filepath.Join(dir, "install_target")
	const placeholderLink = "TEST_TICKET_PLACEHOLDER"

	// Rebuild the script with the fake collector replaced by one that
	// reports its stdin: is it a tty, and does reading it produce the
	// trailing script text?
	raw, err := os.ReadFile(installScript)
	if err != nil {
		t.Fatal(err)
	}
	scriptText := string(raw)
	probe := filepath.Join(dir, "probe.sh")
	// The probe reads one line from stdin and records what it saw.
	probeBody := `#!/bin/sh
if [ -t 0 ]; then echo "tty=yes" > ` + recordFile + `.stdin; else echo "tty=no" > ` + recordFile + `.stdin; fi
if IFS= read -r line; then echo "read=$line" >> ` + recordFile + `.stdin; else echo "read=EOF" >> ` + recordFile + `.stdin; fi
`
	if err := os.WriteFile(probe, []byte(probeBody), 0o755); err != nil {
		t.Fatal(err)
	}
	// Point the emitted `connect` call at the probe instead of the fake
	// binary: the call shape (`"$ABS_INSTALL_DIR/toktrail" connect "$CONNECT_URL"`)
	// is what matters, so rewriting the installed binary path is enough.
	scriptText = strings.ReplaceAll(scriptText,
		`"$ABS_INSTALL_DIR/toktrail" connect "$CONNECT_URL"`,
		`"`+probe+`"`)
	if !strings.Contains(scriptText, probe) {
		t.Fatal("could not redirect the connect call to the stdin probe")
	}
	// A trailing line AFTER the connect call is what an incrementally
	// parsing shell would let the collector swallow; it must still run.
	scriptText += "echo TRAILING_LINE_RAN\n"

	cmd := exec.Command("/bin/sh", "-s", "--", baseURL, installTarget, "--connect", placeholderLink)
	cmd.Stdin = strings.NewReader(scriptText)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("piped install failed: %v\nOutput: %s", err, out)
	}
	if !strings.Contains(string(out), "TRAILING_LINE_RAN") {
		t.Fatalf("the trailing script line must still run; the collector consumed script text.\nOutput:\n%s", out)
	}
	report, err := os.ReadFile(recordFile + ".stdin")
	if err != nil {
		t.Fatalf("the probe did not run: %v", err)
	}
	reportText := string(report)
	if !strings.Contains(reportText, "tty=no") {
		t.Fatalf("under the pipe shape the collector's stdin must not be a terminal, got:\n%s", reportText)
	}
	if !strings.Contains(reportText, "read=EOF") {
		t.Fatalf("reading the inherited stdin must yield no answer (never script text), got:\n%s", reportText)
	}
}
