package logcollect

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/internal/logblock"
)

// Audit reads auditd's log through descriptors the agent opened and passed
// (the log is readable by root only, and the collector has no privilege). The
// files come oldest first, the current one last. The cursor is
// "<inode>:<offset>": reading continues in the file with that inode from that
// offset, so a rotation (the file renamed, its inode kept) loses nothing. It
// reads with ReadAt, so the descriptors' shared offsets never matter.
type Audit struct {
	// Files returns the descriptors.
	Files func() ([]*os.File, error)
	// Close has the reader close the descriptors after each read: they are
	// fresh ones the agent passed.
	Close bool
}

const chunk = 1 << 20

// Name implements Reader.
func (*Audit) Name() string { return "audit" }

// Read implements Reader.
func (a *Audit) Read(_ context.Context, cursor string, since time.Time, limit int) ([]logblock.Event, string, error) {
	files, err := a.Files()
	if err != nil {
		return nil, cursor, err
	}
	if a.Close {
		defer func() {
			for _, f := range files {
				_ = f.Close()
			}
		}()
	}
	type pos struct {
		f   *os.File
		ino uint64
		sz  int64
	}
	var ps []pos
	for _, f := range files {
		ino, sz, err := inodeSize(f)
		if err != nil {
			continue
		}
		ps = append(ps, pos{f, ino, sz})
	}
	wantIno, wantOff := parseAuditCursor(cursor)
	skipping := false
	if wantIno != 0 {
		for _, p := range ps {
			if p.ino == wantIno {
				skipping = true
			}
		}
	}
	var evs []logblock.Event
	next := cursor
	for _, p := range ps {
		off := int64(0)
		if skipping {
			if p.ino != wantIno {
				continue
			}
			skipping = false
			off = min(wantOff, p.sz) // a truncated file starts over below
			if wantOff > p.sz {
				off = 0
			}
		}
		for off < p.sz && len(evs) < limit {
			buf := make([]byte, min(p.sz-off, chunk))
			n, err := p.f.ReadAt(buf, off)
			if n == 0 {
				if err != nil && err != io.EOF {
					return evs, next, err
				}
				break
			}
			buf = buf[:n]
			consumed := 0
			for len(evs) < limit {
				i := bytes.IndexByte(buf[consumed:], '\n')
				if i < 0 {
					break // an incomplete line waits for the rest
				}
				line := buf[consumed : consumed+i]
				consumed += i + 1
				if e, ok := ParseAudit(string(line)); ok && !e.Time.Before(since) {
					evs = append(evs, e)
				}
			}
			if consumed == 0 {
				if n < chunk {
					break // the last line has no end yet
				}
				consumed = n // a line longer than a chunk: skip it rather than stall
			}
			off += int64(consumed)
			next = fmt.Sprintf("%d:%d", p.ino, off)
		}
		if len(evs) >= limit {
			break
		}
		next = fmt.Sprintf("%d:%d", p.ino, off)
	}
	return evs, next, nil
}

func parseAuditCursor(c string) (ino uint64, off int64) {
	a, b, ok := strings.Cut(c, ":")
	if !ok {
		return 0, 0
	}
	ino, _ = strconv.ParseUint(a, 10, 64)
	off, _ = strconv.ParseInt(b, 10, 64)
	return ino, off
}

// ParseAudit parses one auditd record: "type=SYSCALL msg=audit(1700000000.123:456):
// key=value ...". It never keeps an EXECVE record's arguments in the message:
// they go to the sensitive field "cmdline" (ADR-0060: command lines need
// log.view_sensitive).
func ParseAudit(line string) (logblock.Event, bool) {
	rest, ok := strings.CutPrefix(line, "type=")
	if !ok {
		return logblock.Event{}, false
	}
	typ, rest, ok := strings.Cut(rest, " ")
	if !ok {
		return logblock.Event{}, false
	}
	rest, ok = strings.CutPrefix(rest, "msg=audit(")
	if !ok {
		return logblock.Event{}, false
	}
	stamp, body, ok := strings.Cut(rest, "): ")
	if !ok {
		stamp, body, _ = strings.Cut(rest, "):")
	}
	ts, serial, _ := strings.Cut(stamp, ":")
	sec, frac, _ := strings.Cut(ts, ".")
	s, err := strconv.ParseInt(sec, 10, 64)
	if err != nil {
		return logblock.Event{}, false
	}
	ms, _ := strconv.ParseInt((frac + "000")[:3], 10, 64)
	e := logblock.Event{
		Time: time.Unix(s, ms*int64(time.Millisecond)).UTC(), Source: SourceAudit, ID: typ,
		Level: "info", Fields: map[string]string{"serial": serial},
	}
	kv := splitKV(body)
	for _, k := range []string{"auid", "uid", "ses", "pid", "exe", "comm", "key", "res", "acct", "addr", "hostname", "terminal", "syscall", "success"} {
		if v, ok := kv[k]; ok {
			e.Fields[k] = strings.Trim(v, `"`)
		}
	}
	if strings.Contains(kv["res"], "fail") || strings.HasPrefix(typ, "ANOM_") || kv["success"] == "no" {
		e.Level = "warn"
	}
	if typ == "EXECVE" {
		e.Message = "EXECVE"
		e.Sensitive = map[string]string{"cmdline": execve(kv)}
		return e, true
	}
	e.Message = typ + " " + body
	return e, true
}

// splitKV reads key=value pairs, a value being quoted or running to a space.
func splitKV(s string) map[string]string {
	out := map[string]string{}
	for len(s) > 0 {
		s = strings.TrimLeft(s, " ")
		eq := strings.IndexByte(s, '=')
		if eq < 0 {
			break
		}
		k := s[:eq]
		s = s[eq+1:]
		var v string
		if strings.HasPrefix(s, `"`) {
			end := strings.IndexByte(s[1:], '"')
			if end < 0 {
				v, s = s, ""
			} else {
				v, s = s[:end+2], s[end+2:]
			}
		} else if sp := strings.IndexByte(s, ' '); sp >= 0 {
			v, s = s[:sp], s[sp+1:]
		} else {
			v, s = s, ""
		}
		if !strings.ContainsAny(k, " ") {
			out[k] = v
		}
	}
	return out
}

// execve joins a0, a1, ... of an EXECVE record, decoding the hex auditd uses
// for arguments with spaces or unprintable bytes.
func execve(kv map[string]string) string {
	n, _ := strconv.Atoi(kv["argc"])
	n = min(n, 64)
	var parts []string
	for i := range n {
		v := kv["a"+strconv.Itoa(i)]
		if q := strings.Trim(v, `"`); len(q) != len(v) {
			parts = append(parts, q)
		} else if b, ok := unhex(v); ok {
			parts = append(parts, string(b))
		} else {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, " ")
}

func unhex(s string) ([]byte, bool) {
	if len(s) == 0 || len(s)%2 != 0 {
		return nil, false
	}
	b := make([]byte, len(s)/2)
	for i := range b {
		v, err := strconv.ParseUint(s[2*i:2*i+2], 16, 8)
		if err != nil {
			return nil, false
		}
		if v == 0 {
			v = ' ' // auditd separates a command line's arguments with NULs
		}
		b[i] = byte(v)
	}
	return b, true
}
