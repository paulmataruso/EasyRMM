// Package logship keeps the EasyRMM agent's log records, and those it reads
// from the EasyPatch agent's log and MeshAgent's, in a file of limited size
// and sends them to the server in signed batches (ADR-0069, Part L).
package logship

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// DefaultMaxBytes is the size the buffer file may reach (20 MB).
const DefaultMaxBytes = 20 << 20

// File names in the buffer's directory.
const (
	bufferFile = "shipping.buf"
	seqFile    = "shipping.seq"
)

// Buffer holds records not yet acknowledged by the server, one JSON record
// a line, in a file. When the file would pass its limit the oldest records
// are dropped and counted. A record's sequence number rises with each one
// and across restarts, so the server stores no record twice.
type Buffer struct {
	mu   sync.Mutex
	dir  string
	max  int64
	f    *os.File // appends
	size int64
	// head is the offset of the first record not yet acknowledged: what
	// is before it is acknowledged and waits for a compaction.
	head    int64
	seq     int64 // the last sequence assigned
	acked   int64 // the last sequence acknowledged
	dropped int64 // records dropped and not yet reported
}

// OpenBuffer opens the buffer in dir, creating the directory. now seeds
// the first sequence: microseconds since 1970, so that a device whose
// state was lost never reuses a sequence the server holds.
func OpenBuffer(dir string, maxBytes int64, now time.Time) (*Buffer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	b := &Buffer{dir: dir, max: maxBytes}
	raw, err := os.ReadFile(filepath.Join(dir, seqFile)) //nolint:gosec // the agent's own file in its state folder
	if err == nil {
		b.acked, _ = strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	}
	b.seq = b.acked
	// Find the first unacknowledged record and the highest sequence.
	if err := b.scan(); err != nil {
		return nil, err
	}
	if b.seq == 0 {
		b.seq = now.UnixMicro()
	}
	if err := b.openAppend(); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *Buffer) path() string { return filepath.Join(b.dir, bufferFile) }

// scan reads the whole file once: head becomes the offset of the first
// record above acked, seq the highest sequence seen.
func (b *Buffer) scan() error {
	f, err := os.Open(b.path())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	r := bufio.NewReaderSize(f, 64<<10)
	var off int64
	headSet := false
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			var rec agentproto.LogRecord
			if json.Unmarshal(line, &rec) == nil {
				b.seq = max(b.seq, rec.Seq)
				if rec.Seq > b.acked && !headSet {
					b.head, headSet = off, true
				}
			}
			off += int64(len(line))
		}
		if err != nil {
			break
		}
	}
	b.size = off
	if !headSet {
		b.head = off
	}
	return nil
}

func (b *Buffer) openAppend() error {
	f, err := os.OpenFile(b.path(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // the agent's own buffer in its state folder
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	b.f, b.size = f, st.Size()
	return nil
}

// Close closes the file.
func (b *Buffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.f == nil {
		return nil
	}
	err := b.f.Close()
	b.f = nil
	return err
}

// Append stores a record, giving it the next sequence number, and returns
// that. The record's own Seq is ignored.
func (b *Buffer) Append(r agentproto.LogRecord) (int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.f == nil {
		return 0, os.ErrClosed
	}
	r.Seq = b.seq + 1
	line, err := json.Marshal(r)
	if err != nil {
		return 0, err
	}
	line = append(line, '\n')
	if int64(len(line)) > b.max {
		b.dropped++
		return 0, nil
	}
	if b.size+int64(len(line)) > b.max {
		if err := b.makeRoom(int64(len(line))); err != nil {
			return 0, err
		}
	}
	n, err := b.f.Write(line)
	b.size += int64(n)
	if err != nil {
		return 0, err
	}
	b.seq = r.Seq
	return r.Seq, nil
}

// makeRoom drops the oldest records until need bytes fit, and a tenth of
// the file more so that this does not happen at every record. The
// acknowledged ones go first, uncounted.
func (b *Buffer) makeRoom(need int64) error {
	cut, skipped, err := b.skipOldest(need)
	if err != nil {
		return err
	}
	if err := b.rewriteFrom(cut); err != nil {
		return err
	}
	b.dropped += skipped
	return nil
}

// skipOldest finds the offset to keep the file from, so that need bytes fit
// with a tenth of the file to spare, and how many records that drops. The
// file is closed before it returns: Windows will not replace an open one.
func (b *Buffer) skipOldest(need int64) (cut, skipped int64, err error) {
	cut = b.head // acknowledged bytes are free to go
	limit := b.max - b.max/10
	if b.size-cut+need <= limit {
		return cut, 0, nil
	}
	f, err := os.Open(b.path())
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(cut, io.SeekStart); err != nil {
		return 0, 0, err
	}
	r := bufio.NewReaderSize(f, 64<<10)
	for b.size-cut+need > limit {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			cut += int64(len(line))
			if json.Valid(bytes.TrimSpace(line)) {
				skipped++
			}
		}
		if err != nil {
			break
		}
	}
	return cut, skipped, nil
}

// rewriteFrom replaces the file with its bytes from offset on.
func (b *Buffer) rewriteFrom(offset int64) error {
	if b.f != nil {
		_ = b.f.Close()
		b.f = nil
	}
	tmp := filepath.Join(b.dir, bufferFile+".tmp")
	if err := copyFrom(b.path(), tmp, offset); err != nil {
		_ = os.Remove(tmp)
		_ = b.openAppend()
		return err
	}
	if err := os.Rename(tmp, b.path()); err != nil {
		_ = os.Remove(tmp)
		_ = b.openAppend()
		return err
	}
	b.head = 0
	return b.openAppend()
}

func copyFrom(src, dst string, offset int64) error {
	in, err := os.Open(src) //nolint:gosec // the agent's own buffer in its state folder
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			in = nil
		} else {
			return err
		}
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) //nolint:gosec // the agent's own buffer in its state folder
	if err != nil {
		return err
	}
	if in != nil {
		defer func() { _ = in.Close() }()
		if _, err := in.Seek(offset, io.SeekStart); err != nil {
			_ = out.Close()
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			_ = out.Close()
			return err
		}
	}
	return out.Close()
}

// Next returns the oldest unacknowledged records, at most maxRecords and
// about maxBytes of JSON, and how many records were dropped since the
// last acknowledged batch.
func (b *Buffer) Next(maxRecords, maxBytes int) ([]agentproto.LogRecord, int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	f, err := os.Open(b.path())
	if err != nil {
		return nil, b.dropped
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(b.head, io.SeekStart); err != nil {
		return nil, b.dropped
	}
	r := bufio.NewReaderSize(f, 64<<10)
	var out []agentproto.LogRecord
	used := 0
	for len(out) < maxRecords && used < maxBytes {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			var rec agentproto.LogRecord
			if json.Unmarshal(line, &rec) == nil && rec.Seq > b.acked {
				out = append(out, rec)
				used += len(line)
			}
		}
		if err != nil {
			break
		}
	}
	return out, b.dropped
}

// Ack drops the records up to seq, which the server has taken care of, and
// the dropped count it reported.
func (b *Buffer) Ack(seq, dropped int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dropped = max(b.dropped-dropped, 0)
	if seq <= b.acked {
		return nil
	}
	b.acked = seq
	if err := os.WriteFile(filepath.Join(b.dir, seqFile), []byte(strconv.FormatInt(seq, 10)+"\n"), 0o600); err != nil {
		return err
	}
	off, err := b.pastAcked(seq)
	if err != nil {
		return err
	}
	b.head = off
	// Compact once the acknowledged part is most of the file, or a megabyte.
	if b.head > 0 && (b.head >= b.size || b.head >= 1<<20) {
		return b.rewriteFrom(b.head)
	}
	return nil
}

// pastAcked returns the offset of the first record above seq, closing the
// file before it returns.
func (b *Buffer) pastAcked(seq int64) (int64, error) {
	f, err := os.Open(b.path())
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(b.head, io.SeekStart); err != nil {
		return 0, err
	}
	r := bufio.NewReaderSize(f, 64<<10)
	off := b.head
	for {
		line, err := r.ReadBytes('\n')
		if len(line) == 0 || line[len(line)-1] != '\n' {
			break
		}
		var rec agentproto.LogRecord
		if json.Unmarshal(line, &rec) == nil && rec.Seq > seq {
			break
		}
		off += int64(len(line))
		if err != nil {
			break
		}
	}
	return off, nil
}

// Pending reports the buffer's size in bytes and how many records it has
// dropped and not yet reported.
func (b *Buffer) Pending() (bytes, dropped int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.size - b.head, b.dropped
}
