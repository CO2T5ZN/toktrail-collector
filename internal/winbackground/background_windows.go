//go:build windows

package winbackground

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// defaultMaxLogBytes caps one active log stream before rotation; one
// archived generation is kept (see rotatingLog), bounding each stream at
// roughly twice this. The periodic entry writes one concise result line
// per run (plus ~30s heartbeats only on an interactive terminal), so
// 1 MiB holds months of scheduled runs.
const defaultMaxLogBytes = 1 << 20

// maxLogBytes is the working copy of defaultMaxLogBytes. It is a
// variable only so the Windows rotation test can shrink it; production
// never changes it.
var maxLogBytes = int64(defaultMaxLogBytes)

// procThreadAttributeJobList binds a job-object handle list at process
// creation time (Windows 10 version 1709+; x/sys does not ship the
// constant yet). The value points at an array of job handles whose byte
// size is passed alongside, and makes CreateProcess place the new
// process in those jobs atomically.
const procThreadAttributeJobList = 0x0002000D

// collectorCreationFlags is the exact CreateProcess flag set for the
// collector: CREATE_NO_WINDOW is the no-console contract (the collector
// can never flash a console, whether the helper itself has one or not);
// EXTENDED_STARTUPINFO_PRESENT enables the StartupInfoEx attribute list
// that carries the job binding; CREATE_UNICODE_ENVIRONMENT matches the
// environment block handling.
const collectorCreationFlags = windows.CREATE_NO_WINDOW |
	windows.EXTENDED_STARTUPINFO_PRESENT |
	windows.CREATE_UNICODE_ENVIRONMENT

// runCollector is the Windows implementation of the package contract:
// start the collector hidden and directly inside a kill-on-close job,
// capture its streams into the state directory's rotating logs, and
// forward its real exit code. Every failure emits one of the fixed
// phrases; nothing echoes paths, arguments, or raw system errors.
func runCollector(o options) int {
	logsDir := filepath.Join(o.stateDir, logsDirName)
	if err := os.MkdirAll(logsDir, 0o700); err != nil {
		reportFailure("failed to prepare the collector log directory")
		return ExitLaunchFailure
	}
	// The logs directory must be a real directory inside the state
	// directory: a symlink there would redirect log writes elsewhere.
	if info, err := os.Lstat(logsDir); err != nil || !info.IsDir() {
		reportFailure("failed to prepare the collector log directory")
		return ExitLaunchFailure
	}
	outLog, err := openRotating(filepath.Join(logsDir, outLogName), maxLogBytes)
	if err != nil {
		reportFailure("failed to open the collector output log")
		return ExitLaunchFailure
	}
	defer outLog.Close()
	errLog, err := openRotating(filepath.Join(logsDir, errLogName), maxLogBytes)
	if err != nil {
		reportFailure("failed to open the collector error log")
		return ExitLaunchFailure
	}
	defer errLog.Close()

	// note records a helper failure on stderr and, best effort, in the
	// state directory's error log, so a GUI-only deployment (no captured
	// helper stderr) still leaves a trace.
	note := func(phrase string) {
		reportFailure(phrase)
		_, _ = errLog.Write([]byte(logLine(phrase)))
	}

	job, err := createKillOnCloseJob()
	if err != nil {
		note("failed to create the collector supervision job")
		return ExitLaunchFailure
	}
	// closeJob closes the helper's only job handle exactly once. On the
	// normal path it runs right after the collector's exit code has been
	// captured: kill-on-close then terminates anything the collector
	// left behind (job membership is inherited, so grandchildren die
	// too), which is also what releases the stdio pipes a lingering
	// descendant could otherwise keep open.
	jobClosed := false
	closeJob := func() {
		if !jobClosed {
			jobClosed = true
			_ = windows.CloseHandle(job)
		}
	}
	defer closeJob()

	child, err := startSupervisedCollector(job, o)
	if err != nil {
		note("failed to start the collector")
		return ExitLaunchFailure
	}

	// Copy the collector's piped streams into the rotating logs while it
	// runs; the goroutines end at EOF when the child (and its inherited
	// write ends) are gone.
	var copier sync.WaitGroup
	copier.Add(2)
	copyErrors := make(chan error, 2)
	stopOnStreamFailure := func() { _ = windows.TerminateJobObject(job, uint32(ExitLaunchFailure)) }
	go func() {
		defer copier.Done()
		copyErrors <- copyStream(outLog, child.stdout, stopOnStreamFailure)
	}()
	go func() {
		defer copier.Done()
		copyErrors <- copyStream(errLog, child.stderr, stopOnStreamFailure)
	}()

	// Lifecycle marker, written only after the process really exists so
	// the log never claims a start that failed. A failing marker write
	// fails the run closed: without a working error log the helper can
	// neither capture the collector's diagnostics nor prove supervision,
	// so the just-started child is stopped and failure is reported.
	if err := errLog.writeLine(logLine("collector started")); err != nil {
		_ = child.terminate()
		_, _ = child.wait()
		closeJob()
		copier.Wait()
		child.close()
		note("failed to record the collector start; the collector was stopped")
		return ExitLaunchFailure
	}

	// Capture the collector's real exit code first, then converge the
	// job: a descendant still holding the stdio pipes must not be able
	// to hang the helper, and the captured code is forwarded untouched.
	code, err := child.wait()
	if err != nil {
		closeJob()
		copier.Wait()
		child.close()
		note("failed to observe the collector's exit")
		return ExitLaunchFailure
	}
	closeJob()
	copier.Wait()
	child.close()
	stdoutErr, stderrErr := <-copyErrors, <-copyErrors
	if stdoutErr != nil || stderrErr != nil {
		note("failed to capture the collector output; the collector was stopped")
		return ExitLaunchFailure
	}
	// Record how the run ended (fixed phrase plus the numeric result
	// only). A failing marker write must not silently report success:
	// the log contract is broken, so the run fails closed even though
	// the collector itself finished; the periodic entry is idempotent,
	// so the next scheduled run simply collects again.
	if err := errLog.writeLine(logLine(fmt.Sprintf("collector finished exit=%d", code))); err != nil {
		note("failed to record the collector result")
		return ExitLaunchFailure
	}
	return code
}

// collectorArgv is the exact argument array the collector is launched
// with: the complete-exit scheduled entry, nothing else on the command
// line (no server URLs, no secrets).
func collectorArgv(o options) []string {
	return []string{o.collector, "periodic", "--state-dir", o.stateDir}
}

// supervisedCollector is a collector child spawned directly into the
// supervision job. It owns the waitable process handle, the parent-side
// pipe read ends, and the NUL stdin file; the caller must wait (or
// terminate+wait), then close.
type supervisedCollector struct {
	process windows.Handle
	stdout  *os.File
	stderr  *os.File
	nullIn  *os.File
}

// newInheritablePipe creates an anonymous pipe whose both ends are
// inheritable, so the write end can serve as a child's stdio.
func newInheritablePipe() (r *os.File, w windows.Handle, err error) {
	var read, write windows.Handle
	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		InheritHandle:      1,
		SecurityDescriptor: nil,
	}
	if err := windows.CreatePipe(&read, &write, sa, 0); err != nil {
		return nil, 0, err
	}
	return os.NewFile(uintptr(read), "toktrail-collector-pipe"), write, nil
}

// startSupervisedCollector spawns `<collector> periodic --state-dir ...`
// hidden and directly inside job.
//
// The job binding uses PROC_THREAD_ATTRIBUTE_JOB_LIST, so CreateProcess
// places the child in the job atomically at creation: there is no window
// in which an aborted helper could leave an unsupervised child behind,
// and no way a transient collector (a scheduler probe that exits within
// microseconds) can exit before the binding lands — the classic
// create-then-AssignProcessToJobObject race does not exist here.
//
// The collector is launched by exact application path with an escaped
// argument array (syscall.EscapeArg) — CreateProcess never consults a
// shell. stdin is the NUL device (immediate EOF for any read); stdout
// and stderr are inheritable pipes whose read ends are returned for the
// caller to copy into the rotating logs. The environment is inherited
// from the helper; the working directory is pinned to the state
// directory so the child cannot depend on the helper's (possibly later
// deleted) working directory.
func startSupervisedCollector(job windows.Handle, o options) (c *supervisedCollector, err error) {
	var (
		nullIn           *os.File
		stdoutR, stderrR *os.File
		stdoutW, stderrW windows.Handle
		attrList         *windows.ProcThreadAttributeListContainer
	)
	// release drops every resource this function opened on failure; on
	// success the ownership of the surviving handles moves into the
	// returned child.
	release := func() {
		if attrList != nil {
			attrList.Delete()
		}
		if nullIn != nil {
			nullIn.Close()
		}
		if stdoutR != nil {
			stdoutR.Close()
		}
		if stderrR != nil {
			stderrR.Close()
		}
		if stdoutW != 0 {
			windows.CloseHandle(stdoutW)
		}
		if stderrW != 0 {
			windows.CloseHandle(stderrW)
		}
	}
	defer func() {
		if err != nil {
			release()
		}
	}()

	nullIn, err = os.Open(os.DevNull)
	if err != nil {
		return nil, err
	}
	// Everything the child inherits must be marked inheritable.
	if err = windows.SetHandleInformation(windows.Handle(nullIn.Fd()), windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
		return nil, err
	}
	stdoutR, stdoutW, err = newInheritablePipe()
	if err != nil {
		return nil, err
	}
	stderrR, stderrW, err = newInheritablePipe()
	if err != nil {
		return nil, err
	}

	// Build the attribute list that binds the job at creation time. The
	// list (and the job handle it points at) must stay alive until
	// CreateProcess returns; it is freed immediately after.
	attrList, err = windows.NewProcThreadAttributeList(2)
	if err != nil {
		return nil, err
	}
	if err = attrList.Update(procThreadAttributeJobList, unsafe.Pointer(&job), unsafe.Sizeof(job)); err != nil {
		return nil, err
	}
	stdio := []windows.Handle{windows.Handle(nullIn.Fd()), stdoutW, stderrW}
	if err = attrList.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&stdio[0]), uintptr(len(stdio))*unsafe.Sizeof(stdio[0])); err != nil {
		return nil, err
	}

	si := &windows.StartupInfoEx{}
	si.Cb = uint32(unsafe.Sizeof(*si))
	si.Flags = windows.STARTF_USESTDHANDLES | windows.STARTF_USESHOWWINDOW
	si.ShowWindow = windows.SW_HIDE
	si.StdInput = windows.Handle(nullIn.Fd())
	si.StdOutput = stdoutW
	si.StdErr = stderrW
	si.ProcThreadAttributeList = attrList.List()

	argv := collectorArgv(o)
	var cmdline strings.Builder
	for i, arg := range argv {
		if i > 0 {
			cmdline.WriteByte(' ')
		}
		cmdline.WriteString(syscall.EscapeArg(arg))
	}
	appUTF16, err := windows.UTF16PtrFromString(o.collector)
	if err != nil {
		return nil, err
	}
	cmdUTF16, err := windows.UTF16PtrFromString(cmdline.String())
	if err != nil {
		return nil, err
	}
	dirUTF16, err := windows.UTF16PtrFromString(o.stateDir)
	if err != nil {
		return nil, err
	}
	var pi windows.ProcessInformation
	err = windows.CreateProcess(
		appUTF16, // exact application path: no PATH search, no shell
		cmdUTF16, // escaped argument array as one command line
		nil, nil, // process/thread security: inherit
		true, // inherit the stdio handles
		collectorCreationFlags,
		nil,      // environment: inherit the helper's
		dirUTF16, // working directory: the state directory
		&si.StartupInfo,
		&pi,
	)
	if err != nil {
		return nil, err
	}
	_ = windows.CloseHandle(pi.Thread)
	attrList.Delete()
	attrList = nil
	// The child owns its inherited copies now; closing the parent's
	// write ends is what delivers EOF to the copy goroutines once the
	// child exits.
	windows.CloseHandle(stdoutW)
	stdoutW = 0
	windows.CloseHandle(stderrW)
	stderrW = 0
	return &supervisedCollector{
		process: pi.Process,
		stdout:  stdoutR,
		stderr:  stderrR,
		nullIn:  nullIn,
	}, nil
}

// wait blocks until the collector exits and returns its real exit code.
func (c *supervisedCollector) wait() (int, error) {
	event, err := windows.WaitForSingleObject(c.process, windows.INFINITE)
	if err != nil {
		return 0, err
	}
	if event != windows.WAIT_OBJECT_0 {
		return 0, errors.New("unexpected wait result")
	}
	var code uint32
	if err := windows.GetExitCodeProcess(c.process, &code); err != nil {
		return 0, err
	}
	return int(code), nil
}

// terminate kills the collector (used only on fail-closed paths, before
// reporting a helper failure).
func (c *supervisedCollector) terminate() error {
	return windows.TerminateProcess(c.process, 1)
}

// close releases the process handle, the pipe read ends, and the NUL
// stdin file.
func (c *supervisedCollector) close() {
	_ = windows.CloseHandle(c.process)
	c.stdout.Close()
	c.stderr.Close()
	c.nullIn.Close()
}

// createKillOnCloseJob creates a Windows Job Object whose members are
// terminated when its last handle closes. The helper holds the only
// handle for the whole run, so a helper that is killed, crashes, or ends
// abnormally takes the collector with it — no orphaned collector can
// outlive its supervisor.
func createKillOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		_ = windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}
