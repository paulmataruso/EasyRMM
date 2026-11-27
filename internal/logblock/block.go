// Package logblock is the format of a block of collected logs (ADR-0060): a
// batch's events of one source, normalised to JSON lines and compressed,
// with a summary of facts kept beside it. The collector on a computer seals
// blocks and the server opens them to search and to compute their facts;
// both share this package.
//
// Blocks use DEFLATE (Go's standard library, no new dependency) and name
// their codec, so that a better one can be added without rewriting what is
// stored.
package logblock

import (
	"bufio"
	"bytes"
	"compress/flate"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// CodecDeflate is the codec of blocks sealed today.
const CodecDeflate = "deflate"

// Limits that bound what a block may hold, enforced when sealing and again
// when the server opens one it was sent.
const (
	MaxEvents   = 20000
	MaxRaw      = 16 << 20
	MaxMessage  = 8 << 10
	MaxFields   = 40
	MaxFieldVal = 2 << 10
	topIDs      = 20
)

// Retention classes (ADR-0060): how long a block is kept.
const (
	ClassSecurity    = "security"
	ClassOperational = "operational"
	ClassDebug       = "debug"
)

// Retention is how long each class is kept.
var Retention = map[string]time.Duration{
	ClassSecurity:    365 * 24 * time.Hour,
	ClassOperational: 90 * 24 * time.Hour,
	ClassDebug:       7 * 24 * time.Hour,
}

// Classes lists the classes, longest kept first.
func Classes() []string { return []string{ClassSecurity, ClassOperational, ClassDebug} }

// ValidClass says whether c is a retention class.
func ValidClass(c string) bool { _, ok := Retention[c]; return ok }

// ClassFor is the class of a source, by its name: the security, audit and
// sign-in sources are kept longest, debug ones shortest.
func ClassFor(source string) string {
	switch {
	case strings.HasSuffix(source, ".security"), strings.HasSuffix(source, ".audit"), strings.HasSuffix(source, ".auth"):
		return ClassSecurity
	case strings.HasSuffix(source, ".debug"):
		return ClassDebug
	}
	return ClassOperational
}

// Event is one log event, normalised.
type Event struct {
	Time    time.Time `json:"t"`
	Source  string    `json:"s"`
	Level   string    `json:"l,omitempty"`
	ID      string    `json:"id,omitempty"`
	Message string    `json:"m"`
	// Fields are what anyone with log.view may see; Sensitive holds command
	// lines and script text, which need log.view_sensitive.
	Fields    map[string]string `json:"f,omitempty"`
	Sensitive map[string]string `json:"x,omitempty"`
}

// HourFact counts the events of one hour and level.
type HourFact struct {
	Hour  time.Time `json:"hour"`
	Level string    `json:"level"`
	Count int       `json:"count"`
	Bytes int       `json:"bytes"`
}

// Facts is a block's summary.
type Facts struct {
	Count  int            `json:"count"`
	Levels map[string]int `json:"levels"`
	IDs    map[string]int `json:"ids,omitempty"`
	Hourly []HourFact     `json:"hourly"`
}

// Sealed is a block before it has a sequence.
type Sealed struct {
	Source, Class string
	Start, End    time.Time
	Count, Raw    int
	Codec         string
	Data          []byte
	Facts         Facts
}

// Seal sorts events by time, cuts what is too long, and compresses them.
func Seal(source, class string, events []Event) (*Sealed, error) {
	if len(events) == 0 {
		return nil, errors.New("logblock: no events to seal")
	}
	if len(events) > MaxEvents {
		return nil, fmt.Errorf("logblock: %d events is over the limit of %d", len(events), MaxEvents)
	}
	if !ValidClass(class) {
		return nil, fmt.Errorf("logblock: unknown class %q", class)
	}
	evs := append([]Event(nil), events...)
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].Time.Before(evs[j].Time) })
	var raw, comp bytes.Buffer
	zw, err := flate.NewWriter(&comp, flate.DefaultCompression)
	if err != nil {
		return nil, err
	}
	facts := Facts{Levels: map[string]int{}, IDs: map[string]int{}}
	type hk struct {
		h time.Time
		l string
	}
	hours := map[hk]*HourFact{}
	for i := range evs {
		e := evs[i]
		e.Time = e.Time.UTC()
		e.Source = source
		e.Message = cut(e.Message, MaxMessage)
		e.Fields = limitMap(e.Fields)
		e.Sensitive = limitMap(e.Sensitive)
		line, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		raw.Write(line)
		raw.WriteByte('\n')
		if raw.Len() > MaxRaw {
			return nil, fmt.Errorf("logblock: the events are over %d bytes", MaxRaw)
		}
		lv := e.Level
		if lv == "" {
			lv = "info"
		}
		facts.Levels[lv]++
		if e.ID != "" {
			facts.IDs[e.ID]++
		}
		k := hk{e.Time.Truncate(time.Hour), lv}
		f := hours[k]
		if f == nil {
			f = &HourFact{Hour: k.h, Level: lv}
			hours[k] = f
		}
		f.Count++
		f.Bytes += len(line)
		evs[i] = e
	}
	if _, err := zw.Write(raw.Bytes()); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	facts.Count = len(evs)
	facts.IDs = topN(facts.IDs, topIDs)
	for _, f := range hours {
		facts.Hourly = append(facts.Hourly, *f)
	}
	sort.Slice(facts.Hourly, func(i, j int) bool {
		a, b := facts.Hourly[i], facts.Hourly[j]
		if !a.Hour.Equal(b.Hour) {
			return a.Hour.Before(b.Hour)
		}
		return a.Level < b.Level
	})
	return &Sealed{
		Source: source, Class: class,
		Start: evs[0].Time, End: evs[len(evs)-1].Time,
		Count: len(evs), Raw: raw.Len(), Codec: CodecDeflate, Data: comp.Bytes(), Facts: facts,
	}, nil
}

// Open decompresses a block's events. It never reads more than MaxRaw bytes,
// so a block that inflates to more is refused, and it ignores lines that are
// not events, so a damaged block costs only its bad lines.
func Open(codec string, data []byte) ([]Event, error) {
	if codec != CodecDeflate {
		return nil, fmt.Errorf("logblock: unknown codec %q", codec)
	}
	zr := flate.NewReader(bytes.NewReader(data))
	defer zr.Close()
	cr := &countReader{r: io.LimitReader(zr, MaxRaw+1)}
	sc := bufio.NewScanner(cr)
	sc.Buffer(make([]byte, 64<<10), MaxRaw)
	var out []Event
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			out = append(out, e)
		}
		if len(out) > MaxEvents {
			return nil, errors.New("logblock: too many events")
		}
	}
	if cr.n > MaxRaw {
		return nil, errors.New("logblock: the block is over the size limit")
	}
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("logblock: reading a block: %w", err)
	}
	return out, nil
}

type countReader struct {
	r io.Reader
	n int
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 { // do not cut inside a rune
		n--
	}
	return s[:n]
}

func limitMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]string, min(len(m), MaxFields))
	for _, k := range keys {
		if len(out) == MaxFields {
			break
		}
		out[cut(k, 64)] = cut(m[k], MaxFieldVal)
	}
	return out
}

func topN(m map[string]int, n int) map[string]int {
	if len(m) <= n {
		return m
	}
	type kv struct {
		k string
		v int
	}
	all := make([]kv, 0, len(m))
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].v != all[j].v {
			return all[i].v > all[j].v
		}
		return all[i].k < all[j].k
	})
	out := make(map[string]int, n)
	for _, e := range all[:n] {
		out[e.k] = e.v
	}
	return out
}
