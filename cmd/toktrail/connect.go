package main

import (
	"context"

	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/app/cursorsync"

	"toktrail-collector/internal/bind"
	"toktrail-collector/internal/connect"
	"toktrail-collector/internal/console"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/scheduler"
	"toktrail-collector/internal/syncbudget"
	"toktrail-collector/internal/syncretry"
)

var connectSchedulerRunner scheduler.Runner // injectable for tests

// connectCursorOptions is the production wiring of connect's cursor
// phase (the same providers cursorSyncOptions builds). It is a
// variable solely so CLI integration tests can inject synthetic
// auth/verify/pull providers, mirroring periodicCursorOptions;
// production always uses cursorSyncOptions and never reads a real
// credential during flag wiring.
var connectCursorOptions = cursorSyncOptions

// connectUsage is the connect command's static usage text. It is
// printed verbatim instead of the flag package's own usage: the flag
// package renders DEFAULT VALUES (including environment-derived server
// URLs and state directory paths) and error details that quote raw
// argument values — none of that may reach the output stream.
const connectUsage = `usage: toktrail connect [flags] '<URL>'

flags:
  --state-dir string        local TokTrail state directory (also TOKTRAIL_HOME)
  --device-name string      optional device name override
  --interval duration       scheduled collection interval (minimum 1m)
  --max-total-batches int   max total batches to POST during connect sync across the device, account-source and history queues (0=default 1000)
  --sync-timeout duration   overall connect sync time limit, covering the source scan and the uploads (default 10m); the interactive confirmation wait is not counted
  --progress-json           emit collection progress events as JSON Lines on stderr (never stdout); filter lines by the JSON "type":"collection_progress" discriminator
  --json                    print the run's stable result (stop_reason and phase counts) as a single JSON object on stdout; human output and prompts move to stderr
  --verbose                 show detailed per-tool, per-batch and per-pass output (never secrets: no URLs, tickets or credentials)
  --replace-state           when this machine's existing local TokTrail data belongs to a different account or device than the connect link authorizes, archive it (nothing is retransmitted) and start fresh under this link without asking; without this flag an interactive confirmation asks first
`

// errConnectFlagValue is the fixed, value-free error a failed connect
// flag parse returns: the flag package's own error quotes the raw
// argument value verbatim (a pasted value may carry a ticket, a URL or
// an absolute path), so it is never surfaced. The failure semantics —
// a non-nil error (exit code 1) and the --json usage-error emission —
// are unchanged.
var errConnectFlagValue = errors.New("invalid flag or flag value; run 'toktrail help' for usage")

func runConnect(args []string) error {
	return runConnectIO(args, os.Stdout, os.Stderr)
}

// runConnectIO runs the connect command with explicit output writers.
// The stream DIRECTION is unchanged: by default (no --json) every human
// text — the progressive setup log and the interactive first-time
// cursor confirmation — goes to stdout; the default text itself is the
// concise phased English the user asked for (--verbose adds detail).
// With --json, stdout carries EXACTLY one JSON
// object (the stable §6.5 result, printed on every exit path
// including errors), while the human text AND the interactive prompts
// move to stderr: prompts stay interactive (they still read stdin and
// write the human stream), and the machine stream stays parseable.
// The returned error, and therefore the process exit code, is
// identical with and without --json.
//
// Display: the default human output is concise English — phase
// transitions, phase outcomes and the honest incompleteness
// boundaries, plus a heartbeat line roughly every thirty seconds
// while a long phase runs (readable on a TTY and in a redirect alike).
// --verbose adds the per-tool, per-batch and per-pass detail and the
// closed-set diagnostic codes, never a secret. The final result block
// renders the same closed-set summary the --json object carries; it
// never repeats the run error's text (main's "connect failed:" line
// owns the error, so pre-run errors are never lost).
func runConnectIO(args []string, stdout, stderr io.Writer) error {
	started := time.Now()
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	// The flag package's own output (usage with environment-derived
	// defaults, errors quoting raw values) is discarded; the static
	// usage above and fixed safe errors replace it.
	fs.SetOutput(io.Discard)
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	deviceName := fs.String("device-name", "", "optional device name override")
	interval := fs.Duration("interval", scheduler.DefaultInterval, "scheduled collection interval (minimum 1m)")
	maxTotalBatches := fs.Int("max-total-batches", 0, "max total batches to POST during connect sync across the device, account-source and history queues (0=default 1000)")
	syncTimeout := fs.Duration("sync-timeout", 10*time.Minute, "overall connect sync time limit, covering the source scan and the uploads; the interactive confirmation wait is not counted")
	progressJSON := fs.Bool("progress-json", false, "emit collection progress events as JSON Lines on stderr (never stdout); stderr may also carry human text and prompts — filter lines by the JSON \"type\":\"collection_progress\" discriminator")
	jsonOut := fs.Bool("json", false, "print the run's stable §6.5 result (stop_reason and phase counts) as a single JSON object on stdout; human output and prompts move to stderr")
	verbose := fs.Bool("verbose", false, "show detailed per-tool, per-batch and per-pass output (never secrets: no URLs, tickets or credentials)")
	replaceState := fs.Bool("replace-state", false, "when this machine's existing local TokTrail data belongs to a different account or device than the connect link authorizes, archive it (nothing is retransmitted) and start fresh under this link without asking")
	if err := fs.Parse(args); err != nil {
		// Flag parsing failed before the flags were readable; a literal
		// --json in the raw arguments is the best-effort signal to still
		// emit the result object for the usage error.
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stderr, connectUsage)
			if jsonWantsEmission(fs, *jsonOut, args) {
				emitResultJSON(stdout, connect.SummarizeNotRun(err, elapsedMS(started)))
			}
			// The help request keeps its chain and its exit semantics;
			// the wrapper only gives main's unified failure line a fixed
			// safe text instead of the generic fallback.
			return safeDisplayError(err, "help requested")
		}
		if jsonWantsEmission(fs, *jsonOut, args) {
			emitResultJSON(stdout, connect.SummarizeNotRun(err, elapsedMS(started)))
		}
		// The original parse error stays on the chain (errors.Is/As,
		// the exit code); only its display text is replaced, because it
		// quotes the raw argument value verbatim.
		return safeDisplayError(err, errConnectFlagValue.Error())
	}
	// The serialized stderr sink: progress events always go to stderr,
	// and under --json the human stream (prompts included) shares it —
	// one mutex serializes every write so JSONL lines never interleave
	// with human text or prompts. With progress off the plain writer is
	// kept. stdout is never touched by progress events: under --json it
	// stays exactly one JSON result object; the JSONL event structure is
	// unchanged by the display layer.
	stderrSink := io.Writer(stderr)
	var progress func(collection.ProgressEvent)
	if *progressJSON {
		stderrSink = newSerializedWriter(stderr)
		progress = writeCollectionProgressJSON(stderrSink)
	}
	// The human stream (and the interactive prompt writer): stdout by
	// default (the historical behavior); stderr under --json.
	human := io.Writer(stdout)
	if *jsonOut {
		human = stderrSink
	}
	// The human heartbeat: with the machine JSONL stream off, long
	// phases stay visibly alive — one natural-language line roughly
	// every thirty seconds, from observed counters only. The wrapper
	// serializes the emitter goroutine's lines against the main
	// goroutine's, and DROPS heartbeat lines while an interactive
	// prompt holds the stream open (the command is waiting on stdin).
	var hs *humanStream
	var stopHeartbeat func()
	if !*progressJSON {
		hs = newHumanStream(human)
		// Only a terminal gets heartbeat lines; everything else stays
		// quiet so installation and CI logs remain readable.
		sink := stdout
		if *jsonOut {
			sink = stderr
		}
		hs.quiet = !isTerminalWriter(sink)
		human = hs
		// The coupled heartbeat: event-driven lines from the progress
		// stream plus a fast fallback ticker for the phases no internal
		// emitter covers (the config fetch and bind). Stopped (and
		// joined) before the final summary renders, so no line
		// interleaves it.
		ticker := time.NewTicker(connect.HeartbeatFallbackTick)
		defer ticker.Stop()
		progress, stopHeartbeat = connect.StartHeartbeat(hs, 0, nil, ticker.C)
		defer stopHeartbeat()
	}
	// notRun fails a pre-orchestration error (validation, state
	// directory, wiring): the summary reports not_attempted / not_run
	// phases and the error's own verdict, never a fabricated state. The
	// command's own fixed-literal validation texts are kept verbatim
	// (they echo no argument values); any other pre-run error - whose
	// text may quote local paths - is wrapped with the fixed generic
	// display through the package's safeDisplayError, keeping
	// errors.Is/As intact.
	notRun := func(err error) error {
		if *jsonOut {
			emitResultJSON(stdout, connect.SummarizeNotRun(err, elapsedMS(started)))
		}
		return safeDisplayError(err, err.Error())
	}
	notRunUnknown := func(err error) error {
		if *jsonOut {
			emitResultJSON(stdout, connect.SummarizeNotRun(err, elapsedMS(started)))
		}
		return safeDisplayError(err, "connect did not start (details withheld; run 'toktrail doctor' to inspect the local state)")
	}
	if *maxTotalBatches < 0 {
		return notRun(errors.New("--max-total-batches must be non-negative"))
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return notRun(errors.New("usage: toktrail connect [flags] '<URL>'"))
	}
	connectURL := rest[0]
	dir := *stateDir
	if dir == "" {
		var err error
		dir, err = statedir.DefaultDir()
		if err != nil {
			return notRunUnknown(err)
		}
	}
	if *syncTimeout <= 0 {
		return notRun(errors.New("--sync-timeout must be positive"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), *syncTimeout)
	defer cancel()
	// Account-level cursor wiring: the desktop credential reader and the
	// pinned-host Cursor API client. Construction reads no credential;
	// the integrated first-time confirmation happens only when the server
	// authorization names Cursor and no local permit exists.
	cursorOpts, err := connectCursorOptions(dir, "", nil)
	if err != nil {
		return notRunUnknown(err)
	}
	// The cursor round's human lines and its interactive confirmation
	// belong on the human stream, never on the JSON machine stream.
	cursorOpts.Out = human
	result, err := connect.Run(ctx, connect.Options{
		URL:                 connectURL,
		StateDir:            dir,
		DeviceName:          *deviceName,
		Interval:            *interval,
		SchedulerRunner:     connectSchedulerRunner,
		Cursor:              cursorOpts,
		CursorConfirm:       cursorConfirmResume(nil, hs),
		StateReplaceConfirm: stateReplaceConfirmFor(*replaceState, hs),
		Out:                 human,
		Verbose:             *verbose,
		MaxTotalBatches:     *maxTotalBatches,
		Progress:            progress,
	})
	// The final result block: the same closed-set verdict the --json
	// object carries, rendered as concise natural language. It never
	// repeats the error text — main's "connect failed:" line owns it —
	// so the pre-run errors above are never lost and never duplicated.
	if stopHeartbeat != nil {
		stopHeartbeat()
	}
	summary := connect.SummarizeRun(result, err, ctx.Err(), elapsedMS(started))
	if *jsonOut {
		emitResultJSON(stdout, summary)
	}
	connect.RenderRunSummary(human, summary, *verbose)
	if err != nil {
		// The error's display text is the closed-set verdict phrase,
		// refined only by RELIABLE sentinel classification (a local
		// permission denial, an unreachable network) - never the raw
		// error text, which may embed paths, endpoints or unvetted
		// server strings. The chain, and therefore errors.Is/As and
		// the exit code, are untouched.
		return safeDisplayError(err, runFailureDisplayText(err, connect.StopReasonPhrase(summary.StopReason)))
	}
	return nil
}

// runFailureDisplayText refines a failed run's safe display text with
// the sentinel classifications that are reliable and path-free: a local
// source access denial (os.ErrPermission, e.g. the early default-
// directory probe before any summary scan exists) and an unreachable
// network (net.Error, DNS included). Everything else keeps the
// closed-set fallback phrase; no raw text, no paths, no URLs.
func runFailureDisplayText(err error, fallback string) string {
	// Every bind refusal has a closed-set category (the server's own code is
	// whitelisted into it), so the display can always say what happened. Only
	// the 409 ticket case used to be mapped; a reused or expired link therefore
	// printed "an unexpected error occurred".
	var bindErr *bind.Error
	if errors.As(err, &bindErr) {
		if phrase := bindErr.DisplayPhrase(); phrase != "" {
			return phrase
		}
	}
	switch {
	case errors.Is(err, connect.ErrStateAuthorizationMismatch),
		errors.Is(err, connect.ErrStateOwnershipMismatch),
		errors.Is(err, connect.ErrUnboundSyncedHistory),
		errors.Is(err, connect.ErrRebindIdentityChange):
		// The detailed error text embeds server-controlled identifiers
		// and never reaches the display; this fixed phrase carries the
		// actionable core: the local synced history cannot be moved to
		// the account/device this link authorizes (for example when the
		// previous account was deleted server-side), so the user must
		// start from a fresh state directory.
		return "this machine's existing TokTrail data belongs to a different account or device than this connect link authorizes, so it cannot be reused as-is; rerun connect and confirm the state replacement at the prompt (or pass --replace-state) to archive the existing data and start fresh under this link, or use --state-dir with a new directory"
	case errors.Is(err, os.ErrPermission):
		// The reason only: main's unified line already carries the
		// "connect failed:"/"resync failed:" prefix.
		return "local source access denied; check the permissions of the affected directory"
	case isRunDeadlineExpired(err):
		// The run's own time limit, not a network fault: the device is
		// reachable and whatever was confirmed stays confirmed. Saying
		// "the server could not be reached" here sent users to debug a
		// healthy server.
		return "the run's time limit was reached with work remaining; the remaining work stays queued and continues on the next run (raise --sync-timeout to give one run more time)"
	case isRequestTimeout(err):
		return "a request timed out before the server answered; check connectivity and the server status"
	case isNetworkUnreachable(err):
		return "the server could not be reached; check connectivity and the server status"
	default:
		return fallback
	}
}

// isRunDeadlineExpired reports whether err is the run's own deadline:
// the connect sync budget deadline, a past-deadline retry stop, or the
// run context expiring. These are NOT network faults — the device may be
// perfectly reachable — and must not be displayed as one.
func isRunDeadlineExpired(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, syncbudget.ErrDeadlineExceeded) ||
		errors.Is(err, syncretry.ErrRetryPastDeadline)
}

// isRequestTimeout reports a single request that timed out (net.Error with
// Timeout() true). It is checked before isNetworkUnreachable because
// context.DeadlineExceeded also satisfies net.Error; only the ordering
// keeps the two verdicts apart.
func isRequestTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// isNetworkUnreachable reports whether err carries a net.Error (a DNS
// or dial failure class). Only the reliable type assertion classifies;
// everything else stays generic.
func isNetworkUnreachable(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr)
}

// stateReplaceConfirmFor builds the state-replacement confirmation the
// connect run uses at its ownership guards: --replace-state pre-confirms
// (the non-interactive override, printing the fixed notice and the
// forced-by line), anything else gets the interactive prompt with
// heartbeat gating resumed the moment it returns. A declined or
// unavailable prompt keeps the guards' fail-closed refusal.
func stateReplaceConfirmFor(forced bool, hs *humanStream) cursorsync.ConfirmFunc {
	if forced {
		return func(notice string, out io.Writer) (bool, error) {
			fmt.Fprintln(out, notice)
			fmt.Fprintln(out, "state replacement forced by --replace-state")
			return true, nil
		}
	}
	return cursorConfirmResume(stateReplacePrompt, hs)
}

// stateReplacePrompt asks the interactive state-replacement question.
// It reads the answer from the controlling terminal through the shared
// console helper: under the documented `curl … | sh` install, stdin
// carries the install script, so a stdin read would answer for nobody
// (EOF, or the next script line under incrementally parsing shells).
// Only an explicit y/yes confirms; a missing terminal returns
// console.ErrNoInteractiveTerminal, which the connect flow reports as
// "not confirmed" (the ownership guards then fail closed with their
// actionable guidance and --replace-state stays the explicit
// non-interactive channel).
func stateReplacePrompt(notice string, out io.Writer) (bool, error) {
	fmt.Fprintln(out, notice)
	return console.Confirm(out, "Replace the existing local TokTrail state and start fresh under this connect link? [y/N] ")
}

// cursorConfirmResume wraps the run's interactive confirmation hook so
// the human stream's prompt gating resumes the moment the confirmation
// returns (answered, declined or failed): the terminal's echo of the
// answer never passes through the stream writer, so the open prompt
// line would otherwise keep dropping heartbeat lines through the whole
// - potentially long - first sync that follows. The answer itself is
// never echoed and nothing is ever auto-confirmed; a nil base keeps
// the production DefaultConfirm, and a nil stream keeps the hook
// untouched.
func cursorConfirmResume(base cursorsync.ConfirmFunc, hs *humanStream) cursorsync.ConfirmFunc {
	if hs == nil {
		return base
	}
	return func(notice string, out io.Writer) (bool, error) {
		confirm := base
		if confirm == nil {
			confirm = cursorsync.DefaultConfirm
		}
		confirmed, err := confirm(notice, out)
		// Close the prompt's display line (a newline only - the answer
		// is never echoed) so heartbeat gating resumes.
		hs.CompletePromptLine()
		return confirmed, err
	}
}

// humanStream serializes the human output of the connect and resync
// commands and gates heartbeat lines on open prompts.
//
//   - Serialization: heartbeat lines arrive from a progress emitter
//     goroutine while the command's main goroutine writes phase lines
//     and prompts; one mutex keeps every write whole, so a redirected
//     (non-TTY) log stays line-readable.
//   - Prompt gating: an interactive prompt is written WITHOUT a
//     trailing newline (the command then waits on stdin). While the
//     stream holds such an open line, heartbeat lines are DROPPED
//     instead of interleaved into the prompt — progress pauses for the
//     whole confirmation wait. CompletePromptLine closes the prompt's
//     display line (a newline only — the user's answer is never
//     echoed) once the confirmation returns, so heartbeats resume.
type humanStream struct {
	mu           sync.Mutex
	w            io.Writer
	lineComplete bool
	// quiet suppresses heartbeat lines entirely. A redirected stream
	// (install log, CI, scheduled task) gains nothing from a repeated
	// "still working" line every few seconds; the final summary and any
	// error still render. Phase lines and prompts are unaffected.
	quiet bool
}

func newHumanStream(w io.Writer) *humanStream {
	return &humanStream{w: w, lineComplete: true}
}

func (s *humanStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.w.Write(p)
	if len(p) > 0 {
		s.lineComplete = p[len(p)-1] == '\n'
	}
	return n, err
}

// WriteHeartbeatLine writes one heartbeat line unless an interactive
// prompt currently holds the stream open: while the command waits on
// stdin, progress lines are dropped rather than interleaved into the
// prompt.
func (s *humanStream) WriteHeartbeatLine(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.quiet {
		// Dropped by design: the stream is not a terminal, so the
		// heartbeat would only be log noise. Reported as written so the
		// emitter does not treat it as a failure.
		return len(p), nil
	}
	if !s.lineComplete {
		// Prompt in flight: the heartbeat is dropped, never injected
		// into the prompt's line.
		return 0, nil
	}
	n, err := s.w.Write(p)
	if len(p) > 0 {
		s.lineComplete = p[len(p)-1] == '\n'
	}
	return n, err
}

// CompletePromptLine closes a prompt's display line — a newline only,
// the user's answer is never echoed — so heartbeat gating resumes
// after an interactive confirmation returns.
func (s *humanStream) CompletePromptLine() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.lineComplete {
		s.lineComplete = true
		_, _ = s.w.Write([]byte("\n"))
	}
}
