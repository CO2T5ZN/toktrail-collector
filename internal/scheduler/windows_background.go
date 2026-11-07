package scheduler

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const WindowsBackgroundBinary = "toktrail-background.exe"

func WindowsBackgroundPath(binary string) string {
	return filepath.Join(filepath.Dir(binary), WindowsBackgroundBinary)
}

func windowsBackgroundArguments(binary, stateDir string) string {
	return "--collector " + windowsQuoteArg(binary) + " --state-dir " + windowsQuoteArg(stateDir)
}

// WindowsTaskInfo describes the collector behind a registered Exec action.
// Both the old console action and the new background action are recognized.
type WindowsTaskInfo struct {
	Registered bool
	Background bool
	Collector  string
	Launcher   string
}

type windowsTaskDocument struct {
	XMLName    xml.Name `xml:"Task"`
	URI        string   `xml:"RegistrationInfo>URI"`
	Principals []struct {
		UserID    string `xml:"UserId"`
		LogonType string `xml:"LogonType"`
		RunLevel  string `xml:"RunLevel"`
	} `xml:"Principals>Principal"`
	Actions struct {
		Exec []struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

func windowsXMLDecoder(text string) *xml.Decoder {
	d := xml.NewDecoder(strings.NewReader(text))
	// schtasks returns UTF-16 bytes, already decoded by our caller.
	d.CharsetReader = func(charset string, r io.Reader) (io.Reader, error) {
		if strings.EqualFold(charset, "utf-16") || strings.EqualFold(charset, "utf-8") {
			return r, nil
		}
		return nil, fmt.Errorf("unsupported task XML encoding")
	}
	return d
}

func parseWindowsTask(text, stateDir string) (WindowsTaskInfo, windowsTaskDocument, error) {
	var doc windowsTaskDocument
	decoder := windowsXMLDecoder(text)
	if err := decoder.Decode(&doc); err != nil {
		return WindowsTaskInfo{}, doc, fmt.Errorf("invalid registered task XML: %w", err)
	}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return WindowsTaskInfo{}, doc, fmt.Errorf("invalid registered task XML: %w", err)
		}
		if chars, ok := token.(xml.CharData); ok && strings.TrimSpace(string(chars)) == "" {
			continue
		}
		if _, ok := token.(xml.Comment); ok {
			continue
		}
		return WindowsTaskInfo{}, doc, errors.New("registered task XML has trailing content")
	}
	if len(doc.Actions.Exec) != 1 {
		return WindowsTaskInfo{}, doc, errors.New("registered task must have exactly one Exec action")
	}
	a := doc.Actions.Exec[0]
	args, err := splitWindowsArguments(a.Arguments)
	if err != nil {
		return WindowsTaskInfo{}, doc, err
	}
	info := WindowsTaskInfo{Registered: true}
	if strings.EqualFold(filepath.Base(a.Command), WindowsBackgroundBinary) {
		if len(args) != 4 || args[0] != "--collector" || args[2] != "--state-dir" || !sameWindowsPath(args[3], stateDir) {
			return WindowsTaskInfo{}, doc, errors.New("background task arguments do not match this state directory")
		}
		if !filepath.IsAbs(args[1]) || !sameWindowsPath(WindowsBackgroundPath(args[1]), a.Command) {
			return WindowsTaskInfo{}, doc, errors.New("background task collector and launcher are not in the same directory")
		}
		info.Background, info.Collector, info.Launcher = true, args[1], a.Command
	} else {
		if len(args) != 3 || args[0] != "periodic" || args[1] != "--state-dir" || !sameWindowsPath(args[2], stateDir) {
			return WindowsTaskInfo{}, doc, errors.New("legacy task arguments do not match this state directory")
		}
		info.Collector = a.Command
	}
	return info, doc, nil
}

func sameWindowsPath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

// splitWindowsArguments follows the quoting emitted by windowsQuoteArg, without
// invoking a shell or expanding environment variables.
func splitWindowsArguments(command string) ([]string, error) {
	var args []string
	for i := 0; i < len(command); {
		for i < len(command) && (command[i] == ' ' || command[i] == '\t') {
			i++
		}
		if i == len(command) {
			break
		}
		var arg strings.Builder
		quoted := false
		for i < len(command) {
			if !quoted && (command[i] == ' ' || command[i] == '\t') {
				break
			}
			slashes := 0
			for i < len(command) && command[i] == '\\' {
				slashes++
				i++
			}
			if i < len(command) && command[i] == '"' {
				arg.WriteString(strings.Repeat("\\", slashes/2))
				if slashes%2 == 1 {
					arg.WriteByte('"')
				} else {
					quoted = !quoted
				}
				i++
			} else {
				arg.WriteString(strings.Repeat("\\", slashes))
				if i == len(command) || (!quoted && (command[i] == ' ' || command[i] == '\t')) {
					break
				}
				arg.WriteByte(command[i])
				i++
			}
		}
		if quoted {
			return nil, errors.New("unterminated registered task argument")
		}
		args = append(args, arg.String())
	}
	return args, nil
}

// checkedWindowsTask validates authoritative XML fields instead of looking for
// a path substring in serialized XML. Equivalent entity encodings are accepted;
// mentions in descriptions/comments cannot authorize a foreign Exec action.
func checkedWindowsTask(text, identity, marker string) (WindowsTaskInfo, error) {
	info, doc, err := parseWindowsTask(text, marker)
	if err != nil {
		return WindowsTaskInfo{}, err
	}
	if doc.URI != windowsTaskName(identity) {
		return WindowsTaskInfo{}, errors.New("registered task URI does not match the collector task identity")
	}
	return info, nil
}

func WindowsTaskStatus(cfg TaskConfig) (WindowsTaskInfo, error) {
	info, _, err := readWindowsTask(cfg, ExecRunner{})
	return info, err
}

func readWindowsTask(cfg TaskConfig, runner Runner) (WindowsTaskInfo, string, error) {
	if cfg.Platform != "windows" {
		return WindowsTaskInfo{}, "", errors.New("Windows task inspection requires Windows configuration")
	}
	plan, err := RenderUninstall(cfg)
	if err != nil {
		return WindowsTaskInfo{}, "", err
	}
	name := windowsTaskName(plan.TaskName)
	out, err := runCommandOutput(runner, "schtasks", "/Query", "/TN", name, "/XML")
	if err != nil {
		if isTaskNotFound(err) {
			return WindowsTaskInfo{}, "", nil
		}
		return WindowsTaskInfo{}, "", fmt.Errorf("windows scheduled task query failed: %w", err)
	}
	text := decodeUTF16LEOrUTF8(out)
	info, err := checkedWindowsTask(text, plan.TaskName, plan.Marker)
	if err != nil {
		return WindowsTaskInfo{}, "", fmt.Errorf("scheduled task ownership check failed: %w", err)
	}
	return info, text, nil
}

// RefreshWindows migrates only the Exec action of an existing owned task.
// It preserves the original trigger, principal, settings, identity and state.
// A failed registration is followed by an attempt to restore the exact old XML.
func RefreshWindows(opt InstallOptions) (WindowsTaskInfo, error) {
	cfg := opt.Config
	runner := opt.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	info, oldXML, err := readWindowsTask(cfg, runner)
	if err != nil {
		return WindowsTaskInfo{}, err
	}
	if !info.Registered {
		return info, errors.New("no scheduled task is registered for this state directory; run connect or service install first")
	}
	if !sameWindowsPath(info.Collector, cfg.Binary) {
		return info, errors.New("the task uses another collector installation; run service refresh from its collector")
	}
	_, doc, err := parseWindowsTask(oldXML, cfg.StateDir)
	if err != nil {
		return info, err
	}
	userID, err := windowsPrincipalUserID()
	if err != nil {
		return info, err
	}
	if len(doc.Principals) != 1 || !strings.EqualFold(doc.Principals[0].UserID, userID) || doc.Principals[0].LogonType != "InteractiveToken" || doc.Principals[0].RunLevel != "LeastPrivilege" {
		return info, errors.New("task principal differs from the current least-privilege interactive user; refusing to change it")
	}
	newXML, err := replaceWindowsExec(oldXML, cfg.Binary, cfg.StateDir)
	if err != nil {
		return info, err
	}
	if opt.DryRun {
		_, err := fmt.Fprintln(discardIfNil(opt.Out), newXML)
		return info, err
	}
	if err := validateBackgroundLauncher(cfg.Binary); err != nil {
		return info, err
	}
	if info.Background {
		return info, nil
	}
	identity, err := TaskIdentity(cfg.StateDir)
	if err != nil {
		return info, err
	}
	file, err := os.CreateTemp("", "toktrail-refresh-*.task.xml")
	if err != nil {
		return info, err
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return info, err
	}
	defer os.Remove(path)
	writeXML := func(text string) error { return os.WriteFile(path, encodeUTF16LEWithBOM(text), 0o600) }
	if err := writeXML(newXML); err != nil {
		return info, err
	}
	register := func() error {
		return runner.Run("schtasks", "/Create", "/F", "/XML", path, "/TN", windowsTaskName(identity))
	}
	if err := register(); err != nil {
		if writeErr := writeXML(oldXML); writeErr != nil {
			return info, fmt.Errorf("task refresh failed (%v); cannot prepare restoration: %w", err, writeErr)
		}
		if restoreErr := register(); restoreErr != nil {
			return info, fmt.Errorf("task refresh failed (%v); original task restoration also failed: %w", err, restoreErr)
		}
		return info, fmt.Errorf("task refresh failed; the original definition was restored: %w", err)
	}
	return WindowsTaskInfo{Registered: true, Background: true, Collector: cfg.Binary, Launcher: WindowsBackgroundPath(cfg.Binary)}, nil
}

func validateBackgroundLauncher(binary string) error {
	path := WindowsBackgroundPath(binary)
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("background launcher is unavailable; install the complete Windows release before registering or refreshing the task: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("background launcher must be a regular file beside the collector")
	}
	return nil
}

func replaceWindowsExec(text, binary, stateDir string) (string, error) {
	d := windowsXMLDecoder(text)
	var stack []string
	start, end := int64(-1), int64(-1)
	for {
		before := d.InputOffset()
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "Exec" && len(stack) == 2 && stack[0] == "Task" && stack[1] == "Actions" {
				if start >= 0 {
					return "", errors.New("multiple Exec actions cannot be refreshed")
				}
				start = before
			}
			stack = append(stack, t.Name.Local)
		case xml.EndElement:
			if t.Name.Local == "Exec" && len(stack) == 3 && stack[1] == "Actions" {
				end = d.InputOffset()
			}
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	if start < 0 || end <= start {
		return "", errors.New("registered task Exec action was not found")
	}
	replacement := "<Exec>\n      <Command>" + xmlEscape(WindowsBackgroundPath(binary)) + "</Command>\n      <Arguments>" + xmlEscape(windowsBackgroundArguments(binary, stateDir)) + "</Arguments>\n    </Exec>"
	return text[:start] + replacement + text[end:], nil
}
