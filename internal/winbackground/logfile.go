package winbackground

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// rotatedSuffix is the archived generation's suffix: periodic.out.log
// rotates to periodic.out.log.1. Exactly one generation is kept, which
// bounds each stream's disk use.
const rotatedSuffix = ".1"

// errClosed reports writes after Close.
var errClosed = errors.New("log writer is closed")

// rotatingLog appends with a fixed byte cap, splitting large writes across
// rotations. One archived generation is kept, so logs produced by this writer
// occupy at most 2*maxBytes per stream regardless of pipe chunking. Previously
// oversized external logs are preserved once when reopened, then rotated out.
//
// Rotation also happens at open time when an existing file already
// meets the cap, so a long-lived state directory cannot keep growing an
// already-full log across helper runs.
//
// A rotatingLog is safe for concurrent use: on Windows the child's
// stream copier goroutine and the helper's own failure notes can both
// write to the error stream.
type rotatingLog struct {
	path     string
	maxBytes int64

	mu   sync.Mutex
	file *os.File
	size int64
}

// openRotating opens (creating if needed) path for appending with
// rotation at maxBytes. The path (and its archive slot) must be a
// regular file or not exist: a symlink or any other non-regular file
// would redirect log writes outside the state directory, so it is
// rejected instead of followed.
func openRotating(path string, maxBytes int64) (*rotatingLog, error) {
	if maxBytes <= 0 {
		return nil, errors.New("maxBytes must be positive")
	}
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("log path %s is not a regular file", path)
		}
		if info.Size() >= maxBytes {
			l := &rotatingLog{path: path, maxBytes: maxBytes}
			if err := l.rotate(); err != nil {
				return nil, err
			}
			return l, nil
		}
	case os.IsNotExist(err):
		// A fresh log is created below.
	default:
		return nil, err
	}
	l := &rotatingLog{path: path, maxBytes: maxBytes}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

// open opens the active file for appending and seeds the size counter.
// The caller must hold l.mu.
func (l *rotatingLog) open() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.file = f
	l.size = info.Size()
	return nil
}

// rotate archives the active file: the previous generation is deleted,
// the active file (if any) is renamed to <path>.1, and a fresh active
// file is opened. The archive slot must be a regular file or not exist —
// a symlink or other non-regular file there is refused rather than
// followed or clobbered. The caller must hold l.mu.
func (l *rotatingLog) rotate() error {
	rotated := l.path + rotatedSuffix
	if info, err := os.Lstat(rotated); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("rotated log path %s is not a regular file", rotated)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(rotated); err != nil && !os.IsNotExist(err) {
		return err
	}
	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		if err != nil {
			return err
		}
	}
	if err := os.Rename(l.path, rotated); err != nil && !os.IsNotExist(err) {
		return err
	}
	return l.open()
}

// Write appends p to the active file, rotating first when the active
// file has reached its size cap.
func (l *rotatingLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return 0, errClosed
	}
	written := 0
	for len(p) > 0 {
		if l.size >= l.maxBytes {
			if err := l.rotate(); err != nil {
				return written, err
			}
		}
		chunk := int64(len(p))
		if available := l.maxBytes - l.size; chunk > available {
			chunk = available
		}
		n, err := l.file.Write(p[:int(chunk)])
		written += n
		l.size += int64(n)
		p = p[n:]
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

// Close closes the active file. The archived generation, if any, is
// left in place for diagnosis.
func (l *rotatingLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

// writeLine appends one complete line and reports the write error, so
// lifecycle markers cannot fail silently (a broken marker write must
// fail the run closed, not exit 0).
func (l *rotatingLog) writeLine(line string) error {
	if !strings.HasSuffix(line, "\n") {
		line += "\n"
	}
	_, err := l.Write([]byte(line))
	return err
}
