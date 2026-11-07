package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the real Windows registry API used by the generated installer.
// Redirect only its Environment key to a unique test subtree: the real user
// PATH is never read or changed, and the subtree is removed in finally.
func TestPowerShellInstallerRegistryPath(t *testing.T) {
	_, pubPEM := generateTestPubKey(t)
	paths, err := EmitInstallScripts(t.TempDir(), testManifest("v1.2.3"), pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	var script string
	for _, path := range paths {
		if strings.HasSuffix(path, ".ps1") {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			script = string(raw)
		}
	}
	start := strings.Index(script, "  # PATH setup.")
	end := strings.Index(script, "\n  if ($ConnectUrl)")
	if start < 0 || end <= start {
		t.Fatal("generated installer PATH block not found")
	}
	block := strings.NewReplacer("'Environment'", "$testKeyPath", "\"Environment\"", "$testKeyPath").Replace(script[start:end])
	if strings.Contains(strings.ToUpper(block), "HKCU:") {
		t.Fatal("PATH block must use the redirected registry API, never the real HKCU provider path")
	}
	for _, tc := range []struct {
		name string
		kind string
		deny bool
	}{
		{"expandable PATH", "ExpandString", false},
		{"literal PATH", "String", false},
		{"write failure continues", "ExpandString", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			keyPath := fmt.Sprintf("Software\\TokTrailInstallerTest-%x", sha256.Sum256([]byte(dir)))
			pathBlock := block
			if tc.deny {
				pathBlock = strings.ReplaceAll(pathBlock, "$envKey.SetValue('Path', $newPath, $kind)", "throw 'synthetic registry write denied'")
			}
			quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
			body := "$ErrorActionPreference = 'Stop'\n" +
				"$testKeyPath = " + quote(keyPath) + "\n" +
				"$InstallDir = " + quote(dir) + "\n" +
				"$Upgrade = $false\n$NoPathSetup = $false\n$env:TOKTRAIL_SKIP_PATH_SETUP = ''\n$env:Path = ''\n" +
				"function Read-Host { return 'y' }\n" +
				"$original = '%USERPROFILE%\\existing'\n" +
				"$originalKind = [Microsoft.Win32.RegistryValueKind]::" + tc.kind + "\n" +
				"try {\n" +
				"  $seed = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($testKeyPath)\n" +
				"  try { $seed.SetValue('Path', $original, $originalKind) } finally { $seed.Dispose() }\n" +
				pathBlock + "\n" +
				"  $check = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($testKeyPath)\n" +
				"  try {\n" +
				"    $actual = $check.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)\n" +
				"    $expected = "
			if tc.deny {
				body += "$original\n"
			} else {
				body += "$installPath + ';' + $original\n"
			}
			body += "    if ($actual -cne $expected) { throw 'PATH content was not preserved or updated' }\n" +
				"    if ($check.GetValueKind('Path') -ne $originalKind) { throw 'PATH registry kind changed' }\n" +
				"  } finally { $check.Dispose() }\n" +
				"  Write-Output 'PATH-CONTINUATION-PASSED'\n" +
				"} finally {\n" +
				"  if (-not $testKeyPath.StartsWith('Software\\TokTrailInstallerTest-')) { throw 'unexpected test key' }\n" +
				"  [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($testKeyPath, $false)\n" +
				"}\n"
			file := filepath.Join(dir, "path-test.ps1")
			if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", file)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("PATH registry test failed: %v\n%s", err, out)
			}
			if !strings.Contains(string(out), "PATH-CONTINUATION-PASSED") {
				t.Fatalf("installer did not continue after PATH setup:\n%s", out)
			}
			if tc.deny && !strings.Contains(string(out), "could not update your user PATH; installation will continue") {
				t.Fatalf("PATH failure was not reported:\n%s", out)
			}
		})
	}
}
