package main

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// logName is the agent's log on Windows, in host.Paths.Logs.
const logName = "agent.log"

// openServiceLog checks the agent's state folder, then opens the log in it
// and logs there: the folder is the agent's own only once checked. What
// the check moved aside is logged once the log is open. Without a log, the
// service logs nowhere, since a service has no console.
func (e *env) openServiceLog() (*logFile, error) {
	var early bytes.Buffer
	e.log = slog.New(slog.NewTextHandler(&early, nil))
	err := e.openStore()
	var lf *logFile
	if err == nil {
		lf, err = openLog(filepath.Join(e.paths.Logs(), logName), 10<<20)
	}
	if err != nil {
		e.log = slog.New(slog.NewTextHandler(io.Discard, nil))
		return nil, err
	}
	_, _ = lf.Write(early.Bytes())
	e.log = slog.New(slog.NewTextHandler(lf, nil))
	return lf, nil
}

// logFile appends to a log file and starts it afresh once it passes max
// bytes, keeping the previous one as <name>.1. On Linux the journal keeps
// the log; a Windows service has nowhere else to write.
type logFile struct {
	mu   sync.Mutex
	path string
	max  int64
	f    *os.File
	size int64
}

func openLog(path string, maxBytes int64) (*logFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	l := &logFile{path: path, max: maxBytes}
	return l, l.open()
}

func (l *logFile) open() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // the agent's log
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	l.f, l.size = f, st.Size()
	return nil
}

func (l *logFile) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return 0, os.ErrClosed
	}
	if l.size > 0 && l.size+int64(len(p)) > l.max {
		_ = l.f.Close()
		l.f = nil
		_ = os.Rename(l.path, l.path+".1")
		if err := l.open(); err != nil {
			return 0, err
		}
	}
	n, err := l.f.Write(p)
	l.size += int64(n)
	return n, err
}

// Close closes the file.
func (l *logFile) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
