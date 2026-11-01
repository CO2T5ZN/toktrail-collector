package jsonl

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

const MaxLineBytes = 16 * 1024 * 1024

type Options struct {
	SkipHiddenFiles bool
}

type Line struct {
	File   string
	Number int
	Text   string
}

func Files(path string, opt Options) ([]string, error) {
	return FilesContext(context.Background(), path, opt)
}

func FilesContext(ctx context.Context, path string, opt Options) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	clean := strings.TrimSpace(path)
	info, err := os.Stat(clean)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{clean}, nil
	}
	var files []string
	if err := filepath.WalkDir(clean, func(p string, d fs.DirEntry, err error) error {
		if cancelErr := ctx.Err(); cancelErr != nil {
			return cancelErr
		}
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if opt.SkipHiddenFiles && strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		if strings.EqualFold(filepath.Ext(p), ".jsonl") {
			files = append(files, p)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func WalkLines(path string, fn func(Line) error) error {
	return WalkLinesContext(context.Background(), path, fn)
}

func WalkLinesContext(ctx context.Context, path string, fn func(Line) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), MaxLineBytes)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if err := fn(Line{File: path, Number: lineNo, Text: line}); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return scanner.Err()
}

func DecodeObject(line string) (map[string]any, error) {
	if !utf8.ValidString(line) {
		return nil, errors.New("invalid UTF-8 in JSON")
	}
	raw := map[string]any{}
	decoder := json.NewDecoder(strings.NewReader(line))
	// UseNumber keeps integer counters as json.Number so values above 2^53
	// are not silently rounded through float64.
	decoder.UseNumber()
	if err := decoder.Decode(&raw); err != nil {
		return nil, err
	}
	// json.Unmarshal rejected trailing data; Decode alone does not, so a
	// second Decode must report io.EOF to keep the same strictness.
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("trailing data after JSON value")
	}
	return raw, nil
}
