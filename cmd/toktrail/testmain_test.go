package main

import (
	"os"
	"testing"
)

// TestMain keeps the package's tests off the public network.
//
// `toktrail upgrade --check` resolves "latest" from the GitHub API when nothing
// else names a release. In CI that request can be rate limited (it returned 403
// on a hosted macOS runner, which is how this guard came to exist), so the base
// URL points at an address that cannot answer unless a test overrides it. A test
// that needs the lookup installs its own stub server; a test that merely forgot
// an explicit --to now fails locally and fast instead of depending on GitHub.
func TestMain(m *testing.M) {
	if releaseLatestAPIBase == "https://api.github.com" {
		releaseLatestAPIBase = "http://127.0.0.1:1"
	}
	os.Exit(m.Run())
}
