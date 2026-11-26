package eventrules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Result line types.
const (
	LineBegin    = "begin"
	LineChannel  = "channel"
	LineCrash    = "crash"
	LinePos      = "pos"
	LineEvent    = "event"
	LineProvider = "provider"
	LineError    = "error"
	LineEnd      = "end"
)

// States of a channel in a result (ADR-0068, States).
const (
	StateOK          = "ok"
	StateNotFound    = "not_found"
	StateDenied      = "denied"
	StateUnavailable = "unavailable"
)

// Codes of an Error line.
const (
	ErrCodeNotFound    = "not_found"
	ErrCodeDenied      = "access_denied"
	ErrCodeRefused     = "refused"
	ErrCodeUnavailable = "unavailable"
	ErrCodeFailed      = "failed"
)

// Why a page ended (End.StoppedBy).
const (
	StopEnd    = "end"    // the whole range was searched
	StopPage   = "page"   // the page is full
	StopBytes  = "bytes"  // the page's bytes
	StopRead   = "read"   // the events-read bound
	StopTime   = "time"   // the builtin's own time limit
	StopCancel = "cancel" // canceled from the server
)

// Begin is the first line: what was asked and what ran it.
type Begin struct {
	T            string `json:"t"`
	V            int    `json:"v"`
	Op           string `json:"op"`
	Rules        int    `json:"rules"`
	AgentVersion string `json:"agentVersion"`
	Arch         string `json:"arch,omitempty"`
	// Clock is the computer's clock when the run began.
	Clock string `json:"clock"`
}

// ChannelInfo is one channel of a channel list (ADR-0068, Channels).
type ChannelInfo struct {
	T         string `json:"t"`
	Name      string `json:"name"`
	Type      string `json:"type"` // admin, operational, analytic, debug
	Enabled   bool   `json:"enabled"`
	Classic   bool   `json:"classic,omitempty"`
	MaxSize   int64  `json:"maxSize,omitempty"`
	Retention bool   `json:"retention,omitempty"`
	// AutoBackup says the log is archived when full.
	AutoBackup bool `json:"autoBackup,omitempty"`
	// Count, Size, Oldest and Full are for Admin and Operational channels.
	Count  *int64 `json:"count,omitempty"`
	Size   *int64 `json:"size,omitempty"`
	Oldest string `json:"oldest,omitempty"`
	Full   *bool  `json:"full,omitempty"`
	// State is "" or "denied" where Windows refused to say.
	State string `json:"state,omitempty"`
}

// Crash is the computer's CrashOnAuditFail value.
type Crash struct {
	T     string `json:"t"`
	Value int    `json:"value"`
	// Set is false where the value is not there.
	Set bool `json:"set"`
}

// Pos is one channel's state in a query: whether it could be read, and the
// log's creation time and oldest record as this page found them.
type Pos struct {
	T         string `json:"t"`
	Channel   string `json:"channel"`
	State     string `json:"state"`
	Reason    string `json:"reason,omitempty"`
	Created   string `json:"created,omitempty"`
	Oldest    int64  `json:"oldest,omitempty"`
	OldestAt  string `json:"oldestAt,omitempty"`
	Ascending bool   `json:"ascending,omitempty"`
	// Cleared and Overwritten say the log was cleared, or wrapped past the
	// cursor, since the first page.
	Cleared     bool `json:"cleared,omitempty"`
	Overwritten bool `json:"overwritten,omitempty"`
}

// Event is one event of a page (ADR-0068, Fields): the builtin's reading of
// its XML, which the server reads again.
type Event struct {
	T            string   `json:"t"`
	Log          string   `json:"log"`
	Channel      string   `json:"channel"`
	Record       int64    `json:"record"`
	Provider     string   `json:"provider"`
	ProviderGUID string   `json:"providerGuid,omitempty"`
	ID           int      `json:"id"`
	Qualifiers   *int     `json:"qualifiers,omitempty"`
	Version      int      `json:"version"`
	Level        int      `json:"level"`
	LevelName    string   `json:"levelName,omitempty"`
	Task         int      `json:"task"`
	TaskName     string   `json:"taskName,omitempty"`
	Opcode       int      `json:"opcode"`
	OpcodeName   string   `json:"opcodeName,omitempty"`
	Keywords     string   `json:"keywords"` // 0x…, 16 digits
	KeywordNames []string `json:"keywordNames,omitempty"`
	Time         string   `json:"time"`
	// Offset is the computer's offset from UTC at that instant, in seconds.
	Offset   *int    `json:"offset,omitempty"`
	Computer string  `json:"computer"`
	UserSID  string  `json:"userSid,omitempty"`
	User     string  `json:"user,omitempty"`
	PID      int     `json:"pid,omitempty"`
	TID      int     `json:"tid,omitempty"`
	Data     []Datum `json:"data,omitempty"`
	// DataDropped counts values over the 256 an event keeps.
	DataDropped int `json:"dataDropped,omitempty"`
	// Message is the formatted message; MessageNote says why there is none,
	// or that it is incomplete or in English.
	Message       string `json:"message,omitempty"`
	MessageNote   string `json:"messageNote,omitempty"`
	MessageHidden bool   `json:"messageHidden,omitempty"`
	MessageCut    bool   `json:"messageCut,omitempty"`
	// Hidden names the fields withheld.
	Hidden []string `json:"hidden,omitempty"`
	XML    string   `json:"xml"`
	// TooLarge says the line was cut to its System element.
	TooLarge bool `json:"tooLarge,omitempty"`
}

// Level, task, opcode and keyword of a provider's metadata, with the display
// name Windows gives it.
type MetaItem struct {
	Name    string `json:"name,omitempty"`
	Value   uint64 `json:"value"`
	Display string `json:"display,omitempty"`
}

// ProviderLine describes one provider (ADR-0068, Queries).
type ProviderLine struct {
	T        string     `json:"t"`
	Name     string     `json:"name"`
	GUID     string     `json:"guid,omitempty"`
	Levels   []MetaItem `json:"levels,omitempty"`
	Tasks    []MetaItem `json:"tasks,omitempty"`
	Opcodes  []MetaItem `json:"opcodes,omitempty"`
	Keywords []MetaItem `json:"keywords,omitempty"`
}

// ErrorLine says the operation could not read what was asked.
type ErrorLine struct {
	T       string `json:"t"`
	Code    string `json:"code"`
	Channel string `json:"channel,omitempty"`
	Message string `json:"message"`
}

// End is the last line. A result without it was cut.
type End struct {
	T        string `json:"t"`
	Complete bool   `json:"complete"`
	Returned int    `json:"returned"`
	Read     int    `json:"read"`
	// StoppedBy is one of the Stop constants.
	StoppedBy string `json:"stoppedBy"`
	// SearchedBack is the time of the last event read, when a bound stopped
	// the page before the range's start.
	SearchedBack string `json:"searchedBack,omitempty"`
	Hidden       int    `json:"hiddenEvents,omitempty"`
	Unreadable   int    `json:"unreadable,omitempty"`
	// Redacted and Dropped are the server's counts, not the builtin's.
	Redacted int     `json:"redacted,omitempty"`
	Dropped  int     `json:"dropped,omitempty"`
	Cursor   *Cursor `json:"cursor,omitempty"`
	Clock    string  `json:"clock,omitempty"`
}

// Result is a decoded result file.
type Result struct {
	Begin    Begin
	Crash    *Crash
	Channels []ChannelInfo
	Pos      []Pos
	Provider *ProviderLine
	Events   []Event
	Errors   []ErrorLine
	End      *End
}

// ErrResult is a result that does not decode.
var ErrResult = errors.New("eventrules: the result is not valid")

func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("more than one document on a line")
	}
	return nil
}

// ParseLines decodes the lines of a result file: strictly, the begin line
// first, at most one end line and nothing after it. A result cut before its
// end line decodes, with End nil.
func ParseLines(lines [][]byte) (*Result, error) {
	bad := func(i int, why string) error { return fmt.Errorf("%w: line %d: %s", ErrResult, i+1, why) }
	res := &Result{}
	if len(lines) == 0 {
		return nil, fmt.Errorf("%w: it is empty", ErrResult)
	}
	for i, l := range lines {
		if !agentproto.ValidRegistryText(l) {
			return nil, bad(i, "it holds a NUL or a lone surrogate")
		}
		var head struct {
			T string `json:"t"`
		}
		if err := json.Unmarshal(l, &head); err != nil {
			return nil, bad(i, "not JSON")
		}
		if (i == 0) != (head.T == LineBegin) {
			return nil, bad(i, "the begin line is first and only first")
		}
		if res.End != nil {
			return nil, bad(i, "a line after the end")
		}
		var err error
		switch head.T {
		case LineBegin:
			err = decodeStrict(l, &res.Begin)
		case LineChannel:
			var v ChannelInfo
			err = decodeStrict(l, &v)
			res.Channels = append(res.Channels, v)
		case LineCrash:
			var v Crash
			err = decodeStrict(l, &v)
			res.Crash = &v
		case LinePos:
			var v Pos
			err = decodeStrict(l, &v)
			res.Pos = append(res.Pos, v)
		case LineEvent:
			var v Event
			err = decodeStrict(l, &v)
			res.Events = append(res.Events, v)
		case LineProvider:
			var v ProviderLine
			err = decodeStrict(l, &v)
			res.Provider = &v
		case LineError:
			var v ErrorLine
			err = decodeStrict(l, &v)
			res.Errors = append(res.Errors, v)
		case LineEnd:
			var v End
			err = decodeStrict(l, &v)
			res.End = &v
		default:
			return nil, bad(i, "a line of an unknown type")
		}
		if err != nil {
			return nil, bad(i, err.Error())
		}
	}
	return res, nil
}

// Lines writes the result as the lines to store, in the order a reader
// needs: begin, crash, channels, positions, provider, events, errors, end.
func (r *Result) Lines() ([]json.RawMessage, error) {
	var out []json.RawMessage
	add := func(v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		out = append(out, b)
		return nil
	}
	if err := add(r.Begin); err != nil {
		return nil, err
	}
	if r.Crash != nil {
		if err := add(*r.Crash); err != nil {
			return nil, err
		}
	}
	for _, v := range r.Channels {
		if err := add(v); err != nil {
			return nil, err
		}
	}
	for _, v := range r.Pos {
		if err := add(v); err != nil {
			return nil, err
		}
	}
	if r.Provider != nil {
		if err := add(*r.Provider); err != nil {
			return nil, err
		}
	}
	for _, v := range r.Events {
		if err := add(v); err != nil {
			return nil, err
		}
	}
	for _, v := range r.Errors {
		if err := add(v); err != nil {
			return nil, err
		}
	}
	if r.End != nil {
		if err := add(*r.End); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Verdict is what the server's check of a result found.
type Verdict struct {
	// Violations are rules the result breaks (a Security event when none was
	// allowed, a log or time the input did not ask for): the run fails and is
	// recorded as eventlog.refused_on_device.
	Violations []string
	// Redacted counts events whose values the server hid that the builtin let
	// through; Dropped counts events a text query dropped because of that.
	Redacted, Dropped int
}

func hex16(v uint64) string { return fmt.Sprintf("0x%016x", v) }

// compare checks the builtin's fields against the XML they were read from.
func compare(e *Event, p *Parsed) string {
	switch {
	case e.Record != p.Record:
		return "the record number differs from the XML's"
	case e.Provider != p.Provider || e.ProviderGUID != p.ProviderGUID:
		return "the provider differs from the XML's"
	case e.ID != p.ID, e.Version != p.Version, e.Level != p.Level, e.Task != p.Task, e.Opcode != p.Opcode:
		return "an ID, version, level, task or opcode differs from the XML's"
	case !equalQualifiers(e.Qualifiers, p.Qualifiers):
		return "the qualifiers differ from the XML's"
	case strings.ToLower(e.Keywords) != hex16(p.Keywords):
		return "the keywords differ from the XML's"
	case e.Time != p.Time:
		return "the time differs from the XML's"
	case e.Computer != p.Computer || e.UserSID != p.UserSID || e.PID != p.PID || e.TID != p.TID:
		return "the computer, user or process differs from the XML's"
	case e.Channel != p.Channel:
		return "the channel differs from the XML's"
	}
	if e.TooLarge {
		if len(e.Data) != 0 || len(p.Data) != 0 {
			return "an event cut to its System element holds data"
		}
		return ""
	}
	if len(e.Data)+e.DataDropped < len(p.Data) || len(e.Data) > len(p.Data) {
		return "the number of values differs from the XML's"
	}
	for i, d := range e.Data {
		x := p.Data[i]
		if d.Name != x.Name || d.Path != x.Path {
			return "a value's name differs from the XML's"
		}
		if d.Hidden {
			if x.Value != HiddenMarker {
				return "a value is hidden in the fields but not in the XML"
			}
			if d.Value != "" {
				return "a hidden value holds text"
			}
		} else if d.Value != x.Value {
			return "a value differs from the XML's"
		}
	}
	return ""
}

func equalQualifiers(a, b *int) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// CheckResult checks a decoded result against the input that asked for it,
// as the server does before it keeps one (ADR-0068, Where it is enforced).
// It changes res in place: values and messages the server's rules hide and
// the builtin's did not are replaced by the marker in the fields and the XML,
// and on a text query the events that needed it are dropped. A returned
// error is a result that does not match its input or its own XML: the run
// fails and nothing is kept. Violations are counted separately.
func CheckResult(in Input, res *Result, now time.Time) (Verdict, error) {
	var v Verdict
	b := res.Begin
	if b.V != ResultVersion || b.Op != in.Op {
		return v, errors.New("it is for another operation or version")
	}
	switch in.Op {
	case OpChannels:
		if len(res.Events)+len(res.Pos) > 0 || res.Provider != nil {
			return v, errors.New("it holds lines a channel list does not")
		}
		if len(res.Channels) > MaxChannelList {
			return v, errors.New("it lists too many channels")
		}
		return v, nil
	case OpProvider:
		if len(res.Events)+len(res.Pos)+len(res.Channels) > 0 {
			return v, errors.New("it holds lines a provider read does not")
		}
		if res.Provider != nil && !EqualFold(res.Provider.Name, in.Provider) {
			return v, errors.New("it describes another provider")
		}
		return v, nil
	}
	if len(res.Channels) > 0 || res.Provider != nil {
		return v, errors.New("it holds lines an event query does not")
	}
	asked := map[string]bool{}
	for _, c := range in.Channels {
		asked[Fold(c)] = true
	}
	for _, p := range res.Pos {
		if !asked[Fold(p.Channel)] {
			return v, errors.New("it reports a log the query did not ask for")
		}
	}
	if in.Op == OpEvent && len(res.Events) > 1 {
		return v, errors.New("it holds more than the event asked for")
	}
	if in.Op == OpQuery && len(res.Events) > PageEvents {
		return v, errors.New("it has more events than a page holds")
	}
	violate := func(s string) {
		if !slices.Contains(v.Violations, s) {
			v.Violations = append(v.Violations, s)
		}
	}
	clock, _ := time.Parse(time.RFC3339Nano, b.Clock)
	if clock.IsZero() {
		clock = now
	}
	from, to := in.Time.Window(clock)
	slack := 5 * time.Minute
	asc := map[string]bool{}
	for _, p := range res.Pos {
		asc[Fold(p.Channel)] = p.Ascending
	}
	kept := res.Events[:0]
	for i := range res.Events {
		e := res.Events[i]
		if !asked[Fold(e.Log)] {
			violate("an event from a log the query did not ask for")
			continue
		}
		p, err := ParseXML(e.XML)
		if err != nil {
			return v, errors.New("an event's XML cannot be read")
		}
		if why := compare(&e, p); why != "" {
			return v, errors.New(why)
		}
		if !in.Sensitive && (IsSecurity(p.Channel) || IsSecurity(e.Log)) {
			violate("a Security event in a result for a query that was not asked for sensitive data")
			continue
		}
		if in.Op == OpEvent && e.Record != in.Record {
			violate("an event other than the record asked for")
			continue
		}
		if in.Op == OpQuery {
			if t, err := time.Parse(time.RFC3339Nano, p.Time); err == nil {
				if !from.IsZero() && t.Before(from.Add(-slack)) || !to.IsZero() && t.After(to.Add(slack)) {
					violate("an event outside the time range asked for")
					continue
				}
			}
			if c := in.Cursor.For(e.Log); c != nil && c.Record > 0 {
				if asc[Fold(e.Log)] && e.Record <= c.Record || !asc[Fold(e.Log)] && e.Record >= c.Record {
					violate("an event the previous page already returned")
					continue
				}
			}
		}
		changed := false
		if !in.Sensitive {
			sens := p.Sensitive(p.Channel)
			var hide []int
			for _, idx := range sens {
				if p.Data[idx].Value != HiddenMarker {
					hide = append(hide, idx)
				}
			}
			msgShown := e.Message != "" || p.HasMessage && p.Message != HiddenMarker && p.Message != ""
			if len(hide) > 0 || len(sens) > 0 && msgShown {
				for _, idx := range sens {
					if idx < len(e.Data) {
						e.Data[idx] = Datum{Name: e.Data[idx].Name, Path: e.Data[idx].Path, Hidden: true}
					}
					e.Hidden = appendUnique(e.Hidden, fieldName(p.Data[idx]))
				}
				e.XML = p.Redact(e.XML, hide, len(sens) > 0)
				e.Message, e.MessageNote, e.MessageHidden = "", "", true
				changed = true
			}
		}
		if changed {
			v.Redacted++
			if in.Text != "" {
				// The text may have matched what was hidden, and the event's
				// presence alone would say so.
				v.Dropped++
				continue
			}
		}
		kept = append(kept, e)
	}
	res.Events = kept
	if res.End != nil {
		res.End.Returned = len(kept)
		res.End.Redacted, res.End.Dropped = v.Redacted, v.Dropped
	}
	return v, nil
}

func fieldName(d Datum) string {
	if d.Name != "" {
		return d.Name
	}
	return "value"
}

func appendUnique(s []string, v string) []string {
	if slices.Contains(s, v) {
		return s
	}
	return append(s, v)
}

// FormatKeywords is the 16-digit hexadecimal form of a keyword mask.
func FormatKeywords(v uint64) string { return hex16(v) }

// ParseKeywords reads the hexadecimal form.
func ParseKeywords(s string) (uint64, error) {
	return strconv.ParseUint(strings.TrimPrefix(strings.ToLower(s), "0x"), 16, 64)
}
