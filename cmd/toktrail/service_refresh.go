package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/scheduler"
)

// Refresh changes only an existing Windows task action. Unlike service install,
// it takes no grants, does not bind or collect, and preserves the task schedule.
func runServiceRefresh(args []string) error {
	fs := flag.NewFlagSet("service refresh", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "state directory of the existing task")
	dryRun := fs.Bool("dry-run", false, "show the migrated task XML without changing the task")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("service refresh accepts flags only")
	}
	if runtime.GOOS != "windows" {
		return fmt.Errorf("service refresh is only needed for Windows scheduled tasks")
	}
	dir := *stateDir
	if dir == "" {
		var err error
		dir, err = statedir.DefaultDir()
		if err != nil {
			return err
		}
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	if !*dryRun {
		lock, err := runlock.Acquire(dir)
		if err != nil {
			return fmt.Errorf("cannot refresh while the collector state is busy; wait for the current collection to finish: %w", err)
		}
		defer lock.Close()
	}
	info, err := scheduler.RefreshWindows(scheduler.InstallOptions{
		Config: scheduler.TaskConfig{Platform: "windows", StateDir: dir, Binary: binary, HomeDir: home, Interval: scheduler.DefaultInterval},
		DryRun: *dryRun, Out: os.Stdout,
	})
	if err != nil {
		return err
	}
	if *dryRun {
		return nil
	}
	identity, _ := scheduler.TaskIdentity(dir)
	fmt.Printf("service=%s background=%t\n", identity, info.Background)
	fmt.Println("scheduled collection uses the windowless launcher; existing triggers, account, grants and binding are preserved")
	fmt.Printf("logs=%s\n", filepath.Join(dir, "logs"))
	return nil
}
