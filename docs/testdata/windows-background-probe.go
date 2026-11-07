//go:build windows

// A local-only manual test probe. It never binds, scans a home directory or
// accesses the network. It is not part of official collector installations.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) != 4 || os.Args[1] != "periodic" || os.Args[2] != "--state-dir" {
		os.Exit(91)
	}
	state := os.Args[3]
	if !filepath.IsAbs(state) {
		os.Exit(92)
	}
	console, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleWindow").Call()
	data, _ := json.MarshalIndent(map[string]any{"pid": os.Getpid(), "consoleHandle": uint64(console), "startedAt": time.Now().Format(time.RFC3339)}, "", "  ")
	if err := os.WriteFile(filepath.Join(state, "probe.json"), data, 0o600); err != nil {
		os.Exit(93)
	}
	fmt.Println("WINDOWLESS-PROBE stdout")
	fmt.Fprintln(os.Stderr, "WINDOWLESS-PROBE stderr")
	if raw, err := os.ReadFile(filepath.Join(state, "probe-output-bytes.txt")); err == nil {
		if count, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && count >= 0 && count <= 8*1024*1024 {
			payload := strings.Repeat("P", count)
			fmt.Fprint(os.Stdout, payload)
			fmt.Fprint(os.Stderr, payload)
		}
	}
	delay := 1500 * time.Millisecond
	if raw, err := os.ReadFile(filepath.Join(state, "probe-delay-ms.txt")); err == nil {
		if ms, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && ms >= 0 && ms <= 120000 {
			delay = time.Duration(ms) * time.Millisecond
		}
	}
	time.Sleep(delay)
	os.Exit(7)
}
