package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// The production publication step is a Bash block in the workflow. Exercise
// that exact block with a fake gh executable, without creating a release.
func TestReleaseWorkflowPublishesWithCorrectFlags(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the release publication job runs on Linux with Bash")
	}
	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	const step = "      - name: Publish GitHub Release\n"
	const runBlock = "        run: |\n"
	i := strings.Index(string(workflow), step)
	if i < 0 {
		t.Fatal("GitHub Release publication step not found")
	}
	body := string(workflow[i+len(step):])
	i = strings.Index(body, runBlock)
	if i < 0 {
		t.Fatal("GitHub Release publication command not found")
	}
	var script strings.Builder
	for _, line := range strings.Split(body[i+len(runBlock):], "\n") {
		if line == "" {
			script.WriteByte('\n')
			continue
		}
		if !strings.HasPrefix(line, "          ") {
			break
		}
		script.WriteString(strings.TrimPrefix(line, "          "))
		script.WriteByte('\n')
	}

	for _, tc := range []struct {
		name       string
		version    string
		prerelease bool
		ghExit     int
	}{
		{"stable", "v0.4.0", false, 0},
		{"prerelease", "v0.4.0-rc.1", true, 0},
		{"upload failure", "v0.4.0", false, 17},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			assets := filepath.Join(dir, "dist", tc.version)
			if err := os.MkdirAll(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(assets, 0o755); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"manifest.json", "manifest.json.sig"} {
				if err := os.WriteFile(filepath.Join(assets, name), []byte("fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			fakeGH := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$GH_ARGS\"\nexit \"$GH_EXIT\"\n"
			if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(fakeGH), 0o755); err != nil {
				t.Fatal(err)
			}
			argsFile := filepath.Join(dir, "args.txt")
			cmd := exec.Command("bash", "-c", script.String())
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "GH_ARGS="+argsFile, "GH_EXIT="+strconv.Itoa(tc.ghExit), "RELEASE_VERSION="+tc.version)
			out, err := cmd.CombinedOutput()
			if tc.ghExit == 0 && err != nil {
				t.Fatalf("publication block failed: %v\n%s", err, out)
			}
			if tc.ghExit != 0 {
				exitErr, ok := err.(*exec.ExitError)
				if !ok || exitErr.ExitCode() != tc.ghExit {
					t.Fatalf("publication block error = %v, want exit %d\n%s", err, tc.ghExit, out)
				}
			}
			data, err := os.ReadFile(argsFile)
			if err != nil {
				t.Fatal(err)
			}
			args := strings.Split(strings.TrimSpace(string(data)), "\n")
			want := []string{"release", "create", tc.version, "dist/" + tc.version + "/manifest.json", "dist/" + tc.version + "/manifest.json.sig", "--verify-tag", "--generate-notes", "--title", tc.version}
			if tc.prerelease {
				want = append(want, "--prerelease", "--latest=false")
			}
			if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
				t.Fatalf("gh arguments = %q, want %q", args, want)
			}
		})
	}
}
