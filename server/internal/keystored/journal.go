package keystored

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/keystore"
)

const logDirName = "log"
const logFileName = "keystore.log"

// journal is the keystore's own append-only, hash-chained log (ADR-0081
// section 7). The server reaches it only through the log operation, which
// reads; nothing the server sends can change or drop a line.
type journal struct {
	mu     sync.Mutex
	path   string
	f      *os.File
	seq    int64
	prev   string
	broken bool
	now    func() time.Time
}

// openJournal loads the log, checking its chain. A log that does not verify
// is kept as it is (the evidence) and the keystore refuses reads until a
// person looks at it.
func openJournal(dir string, now func() time.Time) (*journal, []keystore.LogEntry, error) {
	d := filepath.Join(dir, logDirName)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return nil, nil, err
	}
	j := &journal{path: filepath.Join(d, logFileName), now: now}
	entries, err := readLog(j.path)
	if err != nil {
		return nil, nil, err
	}
	prev, seq, verr := keystore.VerifyLog("", 0, entries)
	if verr != nil {
		j.broken = true
	}
	j.prev, j.seq = prev, seq
	f, err := os.OpenFile(j.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // the keystore's own state directory
	if err != nil {
		return nil, nil, err
	}
	j.f = f
	return j, entries, nil
}

func readLog(path string) ([]keystore.LogEntry, error) {
	b, err := os.ReadFile(path) //nolint:gosec // the keystore's own state directory
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []keystore.LogEntry
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var e keystore.LogEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			// Keep what parsed; the chain check then fails on the gap.
			out = append(out, keystore.LogEntry{Seq: -1})
			continue
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// append writes one entry and syncs it. It fails when the log is broken or
// cannot be written: an operation that returns a key must not go on then.
func (j *journal) append(e keystore.LogEntry) (keystore.LogEntry, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.broken {
		return e, errors.New("the keystore's log does not verify")
	}
	e.Seq = j.seq + 1
	e.At = j.now().UTC().Round(0)
	e.Prev = j.prev
	e.Hash = keystore.SumLog(e)
	b, err := json.Marshal(e)
	if err != nil {
		return e, err
	}
	if _, err := j.f.Write(append(b, '\n')); err != nil {
		return e, fmt.Errorf("writing the log: %w", err)
	}
	if err := j.f.Sync(); err != nil {
		return e, fmt.Errorf("syncing the log: %w", err)
	}
	j.seq, j.prev = e.Seq, e.Hash
	return e, nil
}

// since returns up to limit entries with a sequence number above seq, and
// the hash of the entry just before the first (empty from the start).
func (j *journal) since(seq int64, limit int) (prev string, out []keystore.LogEntry, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.broken {
		return "", nil, errors.New("the keystore's log does not verify")
	}
	all, err := readLog(j.path)
	if err != nil {
		return "", nil, err
	}
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	for _, e := range all {
		if e.Seq <= seq {
			prev = e.Hash
			continue
		}
		if len(out) < limit {
			out = append(out, e)
		}
	}
	return prev, out, nil
}

func (j *journal) close() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.f != nil {
		_ = j.f.Close()
		j.f = nil
	}
}
