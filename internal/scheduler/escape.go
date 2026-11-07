package scheduler

import (
	"strings"
	"unicode/utf8"
)

// xmlEscape escapes a string for inclusion in XML element content or a
// double-quoted attribute value, covering & < > " ' and stripping control
// characters (including newlines) that do not belong in paths or unit
// values.
func xmlEscape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&apos;")
		default:
			if r < 0x20 || r == utf8.RuneError {
				continue
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

// systemdEscapeArg quotes one ExecStart argument following systemd's
// quoting rules: arguments containing whitespace or quotes are wrapped in
// double quotes, with backslash and double-quote escaped. systemd splits
// ExecStart itself (no shell), so this is quoting for systemd's parser,
// not for a shell.
func systemdEscapeArg(arg string) string {
	// Control characters never belong in a path or unit value; strip them
	// before deciding whether quoting is needed.
	var clean strings.Builder
	clean.Grow(len(arg))
	for _, r := range arg {
		if r < 0x20 {
			continue
		}
		clean.WriteRune(r)
	}
	arg = clean.String()
	if arg == "" {
		return `""`
	}
	needsQuote := strings.ContainsAny(arg, " \t\"'\\")
	if !needsQuote {
		return arg
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range arg {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// windowsQuoteArg quotes one argument for the Windows Task Scheduler Exec
// action Arguments string using standard command-line quoting: wrapped in
// double quotes when it contains whitespace, with internal quotes doubled.
func windowsQuoteArg(arg string) string {
	var clean strings.Builder
	for _, r := range arg {
		if r >= 0x20 {
			clean.WriteRune(r)
		}
	}
	arg = clean.String()
	if arg != "" && !strings.ContainsAny(arg, " \t\"") {
		return arg
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for _, r := range arg {
		if r == '\\' {
			slashes++
			continue
		}
		if r == '"' {
			b.WriteString(strings.Repeat("\\", 2*slashes+1))
		} else {
			b.WriteString(strings.Repeat("\\", slashes))
		}
		slashes = 0
		b.WriteRune(r)
	}
	b.WriteString(strings.Repeat("\\", 2*slashes))
	b.WriteByte('"')
	return b.String()
}
