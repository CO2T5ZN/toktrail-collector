package main

import (
	"context"

	"errors"
	"flag"
	"io"
	"os"
	"time"
	"toktrail-collector/internal/app/collection"

	"toktrail-collector/internal/connect"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/scheduler"
)

var connectSchedulerRunner scheduler.Runner // injectable for tests

// connectCursorOptions is the production wiring of connect's cursor
// phase (the same providers cursorSyncOptions builds). It is a
// variable solely so CLI integration tests can inject synthetic
// auth/verify/pull providers, mirroring periodicCursorOptions;
// production always uses cursorSyncOptions and never reads a real
// credential during flag wiring.
var connectCursorOptions = cursorSyncOptions

func runConnect(args []string) error {
	return runConnectIO(args, os.Stdout, os.Stderr)
}

// runConnectIO runs the connect command with explicit output writers.
// By default (no --json) every human text — the progressive setup log
// and the interactive first-time cursor confirmation — goes to stdout
// exactly as before. With --json, stdout carries EXACTLY one JSON
// object (the stable §6.5 result, printed on every exit path
// including errors), while the human text AND the interactive prompts
// move to stderr: prompts stay interactive (they still read stdin and
// write the human stream), and the machine stream stays parseable.
// The returned error, and therefore the process exit code, is
// identical with and without --json.
func runConnectIO(args []string, stdout, stderr io.Writer) error {
	started := time.Now()
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	deviceName := fs.String("device-name", "", "optional device name override")
	interval := fs.Duration("interval", scheduler.DefaultInterval, "scheduled collection interval (minimum 1m)")
	maxTotalBatches := fs.Int("max-total-batches", 0, "max total batches to POST during connect sync across the device, account-source and history queues (0=default 1000)")
	progressJSON := fs.Bool("progress-json", false, "emit collection progress events as JSON Lines on stderr (never stdout); stderr may also carry human text and prompts — filter lines by the JSON \"type\":\"collection_progress\" discriminator")
	jsonOut := fs.Bool("json", false, "print the run's stable §6.5 result (stop_reason and phase counts) as a single JSON object on stdout; human output and prompts move to stderr")
	if err := fs.Parse(args); err != nil {
		// Flag parsing failed before the flags were readable; a literal
		// --json in the raw arguments is the best-effort signal to still
		// emit the result object for the usage error.
		if jsonWantsEmission(fs, *jsonOut, args) {
			emitResultJSON(stdout, connect.SummarizeNotRun(err, elapsedMS(started)))
		}
		return err
	}
	// The serialized stderr sink: progress events always go to stderr,
	// and under --json the human stream (prompts included) shares it —
	// one mutex serializes every write so JSONL lines never interleave
	// with human text or prompts. With progress off the plain writer is
	// kept and the output is byte-identical to the historical behavior.
	// stdout is never touched by progress events: under --json it stays
	// exactly one JSON result object.
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
	emit := func(result connect.Result, err error, ctxErr error) {
		if *jsonOut {
			emitResultJSON(stdout, connect.SummarizeRun(result, err, ctxErr, elapsedMS(started)))
		}
	}
	// notRun fails a pre-orchestration error (validation, state
	// directory, wiring): the summary reports not_attempted / not_run
	// phases and the error's own verdict, never a fabricated state.
	notRun := func(err error) error {
		if *jsonOut {
			emitResultJSON(stdout, connect.SummarizeNotRun(err, elapsedMS(started)))
		}
		return err
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
			return notRun(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	// Account-level cursor wiring: the desktop credential reader and the
	// pinned-host Cursor API client. Construction reads no credential;
	// the integrated first-time confirmation happens only when the server
	// authorization names Cursor and no local permit exists.
	cursorOpts, err := connectCursorOptions(dir, "", nil)
	if err != nil {
		return notRun(err)
	}
	// The cursor round's human lines and its interactive confirmation
	// belong on the human stream, never on the JSON machine stream.
	cursorOpts.Out = human
	result, err := connect.Run(ctx, connect.Options{
		URL:             connectURL,
		StateDir:        dir,
		DeviceName:      *deviceName,
		Interval:        *interval,
		SchedulerRunner: connectSchedulerRunner,
		Cursor:          cursorOpts,
		Out:             human,
		MaxTotalBatches: *maxTotalBatches,
		Progress:        progress,
	})
	emit(result, err, ctx.Err())
	return err
}
