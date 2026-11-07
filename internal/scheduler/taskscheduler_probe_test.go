package scheduler

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Build a synthetic console collector and the real GUI launcher. The probe
// reads only its private state path, so running the real task cannot scan a
// runner's home or upload anything.
func buildWindowsTaskProbe(t *testing.T, root string) string {
	t.Helper()
	source := `package main
import("encoding/json";"fmt";"os";"path/filepath";"syscall")
func main(){
 if len(os.Args)!=4 || os.Args[1]!="periodic" || os.Args[2]!="--state-dir" { os.Exit(91) }
 h,_,_:=syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleWindow").Call()
 data,_:=json.Marshal(map[string]any{"pid":os.Getpid(),"console":uint64(h)})
 if err:=os.WriteFile(filepath.Join(os.Args[3],"background-probe.json"),data,0600);err!=nil{os.Exit(92)}
 fmt.Println("synthetic background stdout")
 fmt.Fprintln(os.Stderr,"synthetic background stderr")
 os.Exit(7)
}`
	file := filepath.Join(root, "background_probe.go")
	if err := os.WriteFile(file, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "synthetic collector.exe")
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	for _, args := range [][]string{
		{"build", "-o", binary, file},
		{"build", "-ldflags=-H=windowsgui", "-o", WindowsBackgroundPath(binary), "../../cmd/toktrail-background"},
	} {
		if out, err := exec.CommandContext(ctx, "go", args...).CombinedOutput(); err != nil {
			t.Fatalf("build Windows task probe: %v\n%s", err, out)
		}
	}
	return binary
}

func runWindowsTaskProbe(t *testing.T, cfg TaskConfig, taskName string) {
	t.Helper()
	if err := (ExecRunner{}).Run("schtasks", "/Run", "/TN", taskName); err != nil {
		t.Fatalf("run scheduled background probe: %v", err)
	}
	deadline := time.NewTimer(45 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("scheduled background probe did not finish with exit code 7")
		case <-tick.C:
			raw, err := os.ReadFile(filepath.Join(cfg.StateDir, "background-probe.json"))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			var probe struct {
				PID     int    `json:"pid"`
				Console uint64 `json:"console"`
			}
			if err := json.Unmarshal(raw, &probe); err != nil {
				continue
			}
			if probe.PID == 0 || probe.Console != 0 {
				t.Fatalf("scheduled child must have no console: %+v", probe)
			}
			command := "$ErrorActionPreference='Stop'; [Console]::Write((Get-ScheduledTaskInfo -TaskName '" + strings.TrimPrefix(taskName, "\\") + "').LastTaskResult)"
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command)
			configureSchedulerCommand(cmd)
			out, stderr, err := captureSchedulerOutput(cmd)
			cancel()
			if err != nil {
				t.Fatalf("query task result: %v\nstdout: %q\nstderr: %q", err, out, stderr)
			}
			if strings.TrimSpace(string(out)) != "7" {
				continue
			}
			for name, want := range map[string]string{"periodic.out.log": "synthetic background stdout", "periodic.err.log": "synthetic background stderr"} {
				raw, err := os.ReadFile(filepath.Join(cfg.StateDir, "logs", name))
				if err != nil || !strings.Contains(string(raw), want) {
					t.Fatalf("missing captured background log %s: err=%v content=%q", name, err, raw)
				}
			}
			return
		}
	}
}
