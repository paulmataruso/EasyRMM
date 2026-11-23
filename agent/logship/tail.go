package logship

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/logredact"
)

// Limits of reading a log file.
const (
	// firstRead is how much of a file's end is read the first time the
	// agent sees it.
	firstRead = 32 << 10
	// perPoll is the most bytes one poll reads of a file.
	perPoll = 256 << 10
)

// Tail reads the new lines of another program's log file. The file's
// records get Source. Where it left off is kept in Offsets, so that a
// restart neither misses nor repeats lines.
type Tail struct {
	Source string
	Path   string
	// Offsets keeps the offsets of all tails in one file; nil keeps them
	// in memory only.
	Offsets *Offsets

	off  int64
	seen bool
}

// Offsets is where each tail stopped, persisted as JSON.
type Offsets struct {
	Path string
	mu   sync.Mutex
	m    map[string]int64
}

// OpenOffsets reads the offsets file; a missing or damaged one is empty.
func OpenOffsets(dir string) *Offsets {
	o := &Offsets{Path: filepath.Join(dir, "shipping.tails"), m: map[string]int64{}}
	if raw, err := os.ReadFile(o.Path); err == nil {
		_ = json.Unmarshal(raw, &o.m)
		if o.m == nil {
			o.m = map[string]int64{}
		}
	}
	return o
}

func (o *Offsets) get(path string) (int64, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	v, ok := o.m[path]
	return v, ok
}

func (o *Offsets) set(path string, off int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.m[path] = off
	raw, _ := json.Marshal(o.m)
	_ = os.WriteFile(o.Path, raw, 0o600)
}

// header matches the start of a record of the EasyPatch agent's log:
// "2026-11-23T10:00:00.123Z INF Category: message".
var header = regexp.MustCompile(`^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z)\s+(TRC|DBG|INF|WRN|ERR|CRT)\s+(.*)$`)

var levelOf = map[string]string{
	"TRC": agentproto.LogDebug, "DBG": agentproto.LogDebug, "INF": agentproto.LogInfo,
	"WRN": agentproto.LogWarn, "ERR": agentproto.LogError, "CRT": agentproto.LogError,
}

// Poll reads what the file gained since the last poll and calls emit for
// each record, redacted. A file that is missing is skipped; one that shrank
// was replaced, and is read from its start. The first time a file is seen
// only its last 32 KiB are read.
func (t *Tail) Poll(emit func(agentproto.LogRecord)) {
	f, err := os.Open(t.Path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		return
	}
	if !t.seen {
		t.seen = true
		if off, ok := t.Offsets.lookup(t.Path); ok {
			t.off = off
		} else {
			t.off = max(st.Size()-firstRead, 0)
		}
	}
	if st.Size() < t.off {
		t.off = 0
	}
	if st.Size() == t.off {
		return
	}
	if _, err := f.Seek(t.off, io.SeekStart); err != nil {
		return
	}
	buf, _ := io.ReadAll(io.LimitReader(f, perPoll))
	if len(buf) == 0 {
		return
	}
	// Only whole lines: the writer may be in the middle of one.
	end := strings.LastIndexByte(string(buf), '\n') + 1
	if end == 0 {
		if int64(len(buf)) < perPoll {
			return
		}
		end = len(buf) // a line longer than a poll reads
	}
	chunk := string(buf[:end])
	t.off += int64(end)
	t.Offsets.store(t.Path, t.off)
	t.emitLines(chunk, emit)
}

// lookup and store tolerate a nil Offsets.
func (o *Offsets) lookup(path string) (int64, bool) {
	if o == nil {
		return 0, false
	}
	return o.get(path)
}

func (o *Offsets) store(path string, off int64) {
	if o != nil {
		o.set(path, off)
	}
}

// emitLines turns a chunk of lines into records: a line that starts a
// record of the EasyPatch format begins one, and others (a stack trace)
// continue the one before.
func (t *Tail) emitLines(chunk string, emit func(agentproto.LogRecord)) {
	var cur *agentproto.LogRecord
	flush := func() {
		if cur != nil {
			cur.Message = Clip(logredact.Text(cur.Message), agentproto.MaxLogMessage)
			emit(*cur)
			cur = nil
		}
	}
	for line := range strings.SplitSeq(strings.TrimRight(chunk, "\r\n"), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if m := header.FindStringSubmatch(line); m != nil {
			flush()
			at, _ := time.Parse(time.RFC3339Nano, m[1])
			cur = &agentproto.LogRecord{Time: at, Source: t.Source, Level: levelOf[m[2]], Message: m[3]}
			continue
		}
		if cur != nil && strings.HasSuffix(t.Source, "easypatch") {
			if len(cur.Message) < agentproto.MaxLogMessage {
				cur.Message += "\n" + line
			}
			continue
		}
		flush()
		cur = &agentproto.LogRecord{Time: time.Now().UTC(), Source: t.Source, Level: agentproto.LogInfo, Message: line}
	}
	flush()
}
