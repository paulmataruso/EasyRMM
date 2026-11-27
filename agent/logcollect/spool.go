// Package logcollect is the log collector of ADR-0060, slice 2: the part of
// the agent that runs as a process of its own (`easyrmm-agent collect`)
// without the device's key, network access or rights to change anything. It
// reads Windows event channels, Linux's journal and auditd's log from its own
// positions, redacts EasyRMM's tokens, seals the events into compressed
// blocks (internal/logblock) and writes them to a spool directory. The agent
// reads the spool and uploads the blocks (Uploader); the collector never
// sends anything.
package logcollect

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/logblock"
)

// DefaultSpoolBytes is how much the spool holds before the oldest blocks go.
const DefaultSpoolBytes = 256 << 20

const (
	blockExt    = ".blk"
	cursorsFile = "cursors.json"
	lastSeqFile = "last.seq"
)

// Spool is a directory of sealed blocks, one file each, named by sequence.
// The collector writes it and the agent reads it and deletes what the server
// acknowledged; both only add or remove whole files, so neither sees a
// partial block.
type Spool struct {
	Dir string
	// MaxBytes bounds the blocks held; zero means DefaultSpoolBytes.
	MaxBytes int64
	// Now is replaced by tests.
	Now func() time.Time

	mu sync.Mutex
}

// Open makes the directory, readable by its owner only.
func (s *Spool) Open() error {
	if s.Dir == "" {
		return errors.New("logcollect: no spool directory")
	}
	return os.MkdirAll(s.Dir, 0o700)
}

func (s *Spool) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Spool) max() int64 {
	if s.MaxBytes > 0 {
		return s.MaxBytes
	}
	return DefaultSpoolBytes
}

// Put writes a sealed block and returns its sequence. Sequences rise even if
// the spool is emptied, since they start at the clock's microseconds, so a
// wiped spool never makes the server ignore new blocks as old. When the spool
// is over its size the oldest blocks are dropped and counted in dropped.
func (s *Spool) Put(b *logblock.Sealed) (seq int64, dropped int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	last := s.readLast()
	seq = max(last+1, s.now().UnixMicro())
	blk := agentproto.CollectedBlock{
		Seq: seq, Source: b.Source, Class: b.Class, Start: b.Start, End: b.End,
		Count: b.Count, Raw: b.Raw, Codec: b.Codec, Data: b.Data,
	}
	data, err := json.Marshal(blk)
	if err != nil {
		return 0, 0, err
	}
	if err := writeAtomic(filepath.Join(s.Dir, lastSeqFile), []byte(strconv.FormatInt(seq, 10))); err != nil {
		return 0, 0, err
	}
	if err := writeAtomic(filepath.Join(s.Dir, name(seq)), data); err != nil {
		return 0, 0, err
	}
	return seq, s.trim(), nil
}

func name(seq int64) string { return fmt.Sprintf("%020d%s", seq, blockExt) }

func (s *Spool) readLast() int64 {
	b, err := os.ReadFile(filepath.Join(s.Dir, lastSeqFile))
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n
}

type entry struct {
	seq  int64
	path string
	size int64
}

func (s *Spool) entries() ([]entry, error) {
	des, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, err
	}
	var out []entry
	for _, de := range des {
		n := de.Name()
		if de.IsDir() || !strings.HasSuffix(n, blockExt) {
			continue
		}
		seq, err := strconv.ParseInt(strings.TrimSuffix(n, blockExt), 10, 64)
		if err != nil {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		out = append(out, entry{seq, filepath.Join(s.Dir, n), info.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].seq < out[j].seq })
	return out, nil
}

// trim drops the oldest blocks while the spool is over its size, keeping the
// newest one, and returns how many it dropped.
func (s *Spool) trim() int {
	es, err := s.entries()
	if err != nil {
		return 0
	}
	var total int64
	for _, e := range es {
		total += e.size
	}
	dropped := 0
	for len(es) > 1 && total > s.max() {
		if os.Remove(es[0].path) == nil {
			total -= es[0].size
			dropped++
		}
		es = es[1:]
	}
	return dropped
}

// Pending returns up to n blocks, oldest first. A file that cannot be read
// or parsed is removed: it would block every later one.
func (s *Spool) Pending(n int) ([]agentproto.CollectedBlock, error) {
	es, err := s.entries()
	if err != nil {
		return nil, err
	}
	var out []agentproto.CollectedBlock
	for _, e := range es {
		if len(out) >= n {
			break
		}
		data, err := os.ReadFile(e.path)
		var b agentproto.CollectedBlock
		if err == nil {
			err = json.Unmarshal(data, &b)
		}
		if err != nil || b.Seq != e.seq {
			_ = os.Remove(e.path)
			continue
		}
		out = append(out, b)
	}
	return out, nil
}

// Ack deletes every block up to and including seq.
func (s *Spool) Ack(seq int64) error {
	es, err := s.entries()
	if err != nil {
		return err
	}
	var first error
	for _, e := range es {
		if e.seq > seq {
			break
		}
		if err := os.Remove(e.path); err != nil && !errors.Is(err, os.ErrNotExist) && first == nil {
			first = err
		}
	}
	return first
}

// Size is how many blocks and bytes the spool holds.
func (s *Spool) Size() (blocks int, bytes int64) {
	es, _ := s.entries()
	for _, e := range es {
		bytes += e.size
	}
	return len(es), bytes
}

// Cursors are the collector's positions, by source, kept in the spool.
type Cursors map[string]string

// LoadCursors reads them; a missing or damaged file is no positions.
func (s *Spool) LoadCursors() Cursors {
	c := Cursors{}
	b, err := os.ReadFile(filepath.Join(s.Dir, cursorsFile))
	if err != nil || json.Unmarshal(b, &c) != nil {
		return Cursors{}
	}
	return c
}

// SaveCursors writes them atomically.
func (s *Spool) SaveCursors(c Cursors) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.Dir, cursorsFile), b)
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
