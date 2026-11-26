// Package winevent is the agent's event viewer (ADR-0068): the builtin
// "easyrmm-agent builtin eventlog", which reads a Windows computer's event
// logs through the Event Log API and writes JSON lines the server checks
// again. This file is the engine, with no Windows in it: it takes a Backend,
// which is wevtapi on a computer and an in-memory log in the tests.
package winevent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/eventrules"
)

// Errors a Backend returns, which the engine turns into states.
var (
	ErrNotFound  = errors.New("winevent: not found")
	ErrDenied    = errors.New("winevent: access denied")
	ErrCancelled = errors.New("winevent: canceled")
	// ErrAnalytic is an enabled circular Analytic or Debug channel, which
	// Windows reads only while it is disabled.
	ErrAnalytic = errors.New("winevent: analytic log enabled")
	// ErrService is an Event Log service that is not running.
	ErrService = errors.New("winevent: the Event Log service is not running")
	// ErrTooComplex is a filter Windows refused as too complex.
	ErrTooComplex = errors.New("winevent: filter too complex")
)

// Meta is what Windows' formatting adds to an event: the names of its level,
// task, opcode and keywords, and its message.
type Meta struct {
	LevelName, TaskName, OpcodeName string
	KeywordNames                    []string
	Message                         string
	// MessageNote is why there is no message, or that it is incomplete or in
	// English.
	MessageNote string
}

// Raw is one event as the reader hands it over: its XML, and a way to format
// it that is called only when its names or message are wanted.
type Raw struct {
	XML  string
	Meta func(provider string, withMessage bool) Meta
}

// Batch is some events and the release of their handles, which the engine
// calls once it has written them.
type Batch struct {
	Events  []Raw
	Release func()
}

// Stream is one open query.
type Stream interface {
	// Next returns up to n events, or io.EOF with none left.
	Next(n int) (Batch, error)
	Close()
}

// LogInfo is a log's state: when it was created, its oldest record and
// whether it is read oldest first.
type LogInfo struct {
	Created   time.Time
	Oldest    int64
	OldestAt  time.Time
	Ascending bool
	// Known says Created and Oldest were given; Analytic and Debug logs give
	// none.
	Known bool
}

// Backend is what the engine needs of Windows.
type Backend interface {
	Channels(ctx context.Context) ([]eventrules.ChannelInfo, error)
	// CrashOnAuditFail is the value read from the registry; set is false when
	// it is not there.
	CrashOnAuditFail() (value int, set bool)
	LogInfo(channel string) (LogInfo, error)
	Open(channel, queryXML string, reverse bool) (Stream, error)
	Provider(name string) (*eventrules.ProviderLine, error)
	// Account resolves a SID, within the time the backend allows.
	Account(sid string) (string, bool)
	// Offset is the computer's offset from UTC at an instant, in seconds.
	Offset(t time.Time) (int, bool)
	Now() time.Time
	// Cancel asks every open query to stop (EvtCancel); safe from another
	// goroutine.
	Cancel()
}

// Options are what a run is given besides its input.
type Options struct {
	AgentVersion, Arch string
	// Deadline is how long the run works before it writes what it has and
	// ends; zero is the operation's own limit.
	Deadline time.Duration
}

const (
	batchSize      = 32
	maxAccounts    = 64
	maxPageHandles = batchSize
)

type lineWriter struct {
	w io.Writer
	n int
}

func (l *lineWriter) write(v any) error {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return err
	}
	n, err := l.w.Write(b.Bytes())
	l.n += n
	return err
}

func marshalLine(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

// Run does one operation of the input and writes its lines to w. ctx ends
// when the child's input closes or its own limit is reached; the backend's
// queries are canceled from outside. Whatever ends the run, the lines
// written so far end in an end line where the run could write one.
func Run(ctx context.Context, in eventrules.Input, be Backend, w io.Writer, opt Options) error {
	if err := in.Check(); err != nil {
		return err
	}
	lw := &lineWriter{w: w}
	now := be.Now().UTC()
	if err := lw.write(eventrules.Begin{T: eventrules.LineBegin, V: eventrules.ResultVersion, Op: in.Op, Rules: eventrules.Version,
		AgentVersion: opt.AgentVersion, Arch: opt.Arch, Clock: now.Format(time.RFC3339Nano)}); err != nil {
		return err
	}
	if !in.Sensitive {
		for _, c := range in.Channels {
			if eventrules.IsSecurity(c) {
				return lw.write(eventrules.ErrorLine{T: eventrules.LineError, Code: eventrules.ErrCodeRefused, Channel: c,
					Message: "Refused by EasyRMM: the Security log and its archives need permission to see the Security log."})
			}
		}
	}
	switch in.Op {
	case eventrules.OpChannels:
		return runChannels(ctx, be, lw)
	case eventrules.OpProvider:
		return runProvider(in, be, lw)
	}
	r := &run{in: in, be: be, lw: lw, opt: opt, start: time.Now(), accounts: map[string]string{}}
	return r.query(ctx)
}

func runChannels(ctx context.Context, be Backend, lw *lineWriter) error {
	if v, set := be.CrashOnAuditFail(); set {
		if err := lw.write(eventrules.Crash{T: eventrules.LineCrash, Value: v, Set: true}); err != nil {
			return err
		}
	} else if err := lw.write(eventrules.Crash{T: eventrules.LineCrash}); err != nil {
		return err
	}
	chans, err := be.Channels(ctx)
	if err != nil {
		return writeFailure(lw, "", err)
	}
	if len(chans) > eventrules.MaxChannelList {
		chans = chans[:eventrules.MaxChannelList]
	}
	for _, c := range chans {
		c.T = eventrules.LineChannel
		if err := lw.write(c); err != nil {
			return err
		}
	}
	return lw.write(eventrules.End{T: eventrules.LineEnd, Complete: true, Returned: len(chans), StoppedBy: eventrules.StopEnd,
		Clock: be.Now().UTC().Format(time.RFC3339Nano)})
}

func runProvider(in eventrules.Input, be Backend, lw *lineWriter) error {
	p, err := be.Provider(in.Provider)
	if err != nil {
		return writeFailure(lw, "", err)
	}
	p.T = eventrules.LineProvider
	if err := lw.write(*p); err != nil {
		return err
	}
	return lw.write(eventrules.End{T: eventrules.LineEnd, Complete: true, StoppedBy: eventrules.StopEnd})
}

// writeFailure writes the error line for a backend error and ends the run.
func writeFailure(lw *lineWriter, channel string, err error) error {
	e := eventrules.ErrorLine{T: eventrules.LineError, Channel: channel}
	switch {
	case errors.Is(err, ErrNotFound):
		e.Code, e.Message = eventrules.ErrCodeNotFound, "There is no such "+orWord(channel, "log or provider")+" on this computer."
	case errors.Is(err, ErrDenied):
		e.Code, e.Message = eventrules.ErrCodeDenied, "Access denied to "+orWord(channel, "it")+"."
	case errors.Is(err, ErrService):
		e.Code, e.Message = eventrules.ErrCodeUnavailable, "The Event Log service is not running."
	case errors.Is(err, ErrTooComplex):
		e.Code, e.Message = eventrules.ErrCodeFailed, "Windows refused the filter as too complex: use fewer IDs or providers."
	case errors.Is(err, ErrCancelled):
		e.Code, e.Message = eventrules.ErrCodeFailed, "The query was canceled."
	default:
		e.Code, e.Message = eventrules.ErrCodeFailed, truncate("Windows could not read it: "+err.Error(), 512)
	}
	if err := lw.write(e); err != nil {
		return err
	}
	return lw.write(eventrules.End{T: eventrules.LineEnd, StoppedBy: eventrules.StopEnd})
}

func orWord(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// source is one channel's stream, with the event next in line.
type source struct {
	channel   string
	stream    Stream
	buf       []Raw
	release   func()
	head      *Raw
	headP     *eventrules.Parsed
	headTime  time.Time
	done      bool
	ascending bool
	last      int64 // the last record consumed from it
	info      LogInfo
	pos       eventrules.Pos
}

type run struct {
	in       eventrules.Input
	be       Backend
	lw       *lineWriter
	opt      Options
	start    time.Time
	accounts map[string]string
	lookups  int
	// Counters of the page.
	read, returned, bytes, hiddenEvents, unreadable int
	failures                                        []eventrules.Pos
}

func (r *run) deadline() time.Duration {
	if r.opt.Deadline > 0 {
		return r.opt.Deadline
	}
	return eventrules.QuerySeconds * time.Second
}

func (r *run) query(ctx context.Context) error {
	in := r.in
	channels := eventrules.DedupeChannels(in.Channels)
	var srcs []*source
	var posLines []eventrules.Pos
	for _, ch := range channels {
		s := &source{channel: ch, pos: eventrules.Pos{T: eventrules.LinePos, Channel: ch, State: eventrules.StateOK}}
		info, err := r.be.LogInfo(ch)
		switch {
		case errors.Is(err, ErrNotFound):
			s.pos.State, s.pos.Reason = eventrules.StateNotFound, "No log named "+ch+" on this computer."
		case errors.Is(err, ErrDenied):
			s.pos.State, s.pos.Reason = eventrules.StateDenied, "Access denied to "+ch+"."
		case errors.Is(err, ErrService):
			s.pos.State, s.pos.Reason = eventrules.StateUnavailable, "The Event Log service is not running."
		case errors.Is(err, ErrAnalytic):
			s.pos.State, s.pos.Reason = eventrules.StateUnavailable, "Windows reads this log only while it is disabled."
		case err != nil:
			s.pos.State, s.pos.Reason = eventrules.StateUnavailable, truncate("Windows could not open the log: "+err.Error(), 256)
		}
		if s.pos.State != eventrules.StateOK {
			posLines = append(posLines, s.pos)
			continue
		}
		s.info, s.ascending = info, info.Ascending
		if s.ascending && len(channels) > 1 {
			s.pos.State, s.pos.Reason = eventrules.StateUnavailable, "Analytic and debug logs are read alone, oldest first: choose only "+ch+"."
			posLines = append(posLines, s.pos)
			continue
		}
		s.pos.Ascending = s.ascending
		if info.Known {
			s.pos.Created, s.pos.Oldest = info.Created.UTC().Format(time.RFC3339Nano), info.Oldest
			if !info.OldestAt.IsZero() {
				s.pos.OldestAt = info.OldestAt.UTC().Format(time.RFC3339Nano)
			}
		}
		var after int64
		if c := in.Cursor.For(ch); c != nil {
			after = c.Record
			if c.Done {
				s.done = true
			}
			if c.Created != "" && info.Known && c.Created != s.pos.Created {
				s.pos.Cleared, s.done = true, true
			} else if c.Oldest > 0 && info.Known && info.Oldest > c.Record && !s.ascending && c.Record > 0 {
				s.pos.Overwritten = true
			}
			s.last = c.Record
		}
		if !s.done {
			q, err := eventrules.BuildQuery(in, ch, eventrules.QueryOptions{After: after, Ascending: s.ascending, Record: in.Record, Now: r.be.Now()})
			if err != nil {
				return writeFailure(r.lw, ch, err)
			}
			st, err := r.be.Open(ch, q, !s.ascending)
			switch {
			case errors.Is(err, ErrAnalytic):
				s.pos.State, s.pos.Reason = eventrules.StateUnavailable, "Windows reads this log only while it is disabled."
				posLines = append(posLines, s.pos)
				continue
			case errors.Is(err, ErrNotFound), errors.Is(err, ErrDenied), errors.Is(err, ErrService), errors.Is(err, ErrTooComplex):
				if errors.Is(err, ErrTooComplex) {
					return writeFailure(r.lw, ch, err)
				}
				s.pos.State = map[bool]string{true: eventrules.StateNotFound, false: eventrules.StateDenied}[errors.Is(err, ErrNotFound)]
				if errors.Is(err, ErrService) {
					s.pos.State = eventrules.StateUnavailable
				}
				s.pos.Reason = "Windows could not open " + ch + "."
				posLines = append(posLines, s.pos)
				continue
			case err != nil:
				return writeFailure(r.lw, ch, err)
			}
			s.stream = st
		}
		srcs = append(srcs, s)
	}
	defer func() {
		for _, s := range srcs {
			s.closeBatch()
			if s.stream != nil {
				s.stream.Close()
			}
		}
	}()
	for _, p := range posLines {
		if err := r.lw.write(p); err != nil {
			return err
		}
	}
	for _, s := range srcs {
		if err := r.lw.write(s.pos); err != nil {
			return err
		}
	}
	return r.merge(ctx, srcs)
}

func (s *source) closeBatch() {
	if s.release != nil {
		s.release()
		s.release = nil
	}
	s.buf = nil
}

// advance puts the channel's next event in head, reading a batch when its
// buffer is empty. It reports false when the channel has no more.
func (r *run) advance(ctx context.Context, s *source) (bool, error) {
	for s.head == nil {
		if s.done || s.stream == nil {
			return false, nil
		}
		if len(s.buf) == 0 {
			s.closeBatch()
			if err := ctx.Err(); err != nil {
				return false, err
			}
			b, err := s.stream.Next(batchSize)
			if errors.Is(err, io.EOF) {
				s.done = true
				return false, nil
			}
			if err != nil {
				return false, err
			}
			s.buf, s.release = b.Events, b.Release
			if len(s.buf) == 0 {
				continue
			}
		}
		raw := s.buf[0]
		s.buf = s.buf[1:]
		raw.XML = agentproto.SafeText(strings.ToValidUTF8(raw.XML, "\uFFFD"))
		p, err := eventrules.ParseXML(raw.XML)
		if err != nil {
			// The event is read and cannot be shown: counted, never silent.
			r.unreadable++
			r.read++
			continue
		}
		t, _ := time.Parse(time.RFC3339Nano, p.Time)
		s.head, s.headP, s.headTime = &raw, p, t
	}
	return true, nil
}

// merge takes the newest head of the channels each time, writes it if it
// matches, and ends the page at a bound.
func (r *run) merge(ctx context.Context, srcs []*source) error {
	in := r.in
	limit := eventrules.PageEvents
	byteBudget := eventrules.PageBytes
	timeLimit := r.deadline()
	stopped := ""
	var searchedBack time.Time
	for stopped == "" {
		switch {
		case ctx.Err() != nil:
			stopped = eventrules.StopCancel
		case time.Since(r.start) >= timeLimit:
			stopped = eventrules.StopTime
		case r.read >= eventrules.MaxRead:
			stopped = eventrules.StopRead
		case r.returned >= limit:
			stopped = eventrules.StopPage
		case r.bytes >= byteBudget:
			stopped = eventrules.StopBytes
		}
		if stopped != "" {
			break
		}
		var pick *source
		for _, s := range srcs {
			ok, err := r.advance(ctx, s)
			if err != nil {
				if errors.Is(err, ErrCancelled) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					stopped = eventrules.StopCancel
					break
				}
				if s.pos.State == eventrules.StateOK {
					s.pos.State, s.pos.Reason = eventrules.StateUnavailable, truncate(err.Error(), 256)
					r.failures = append(r.failures, s.pos)
				}
				s.done, s.stream = true, nil
				continue
			}
			if !ok {
				continue
			}
			switch {
			case pick == nil:
				pick = s
			case s.ascending:
				if s.headTime.Before(pick.headTime) {
					pick = s
				}
			case s.headTime.After(pick.headTime):
				pick = s
			}
		}
		if stopped != "" {
			break
		}
		if pick == nil {
			stopped = eventrules.StopEnd
			break
		}
		raw, p := *pick.head, pick.headP
		pick.head, pick.headP = nil, nil
		prev := pick.last
		pick.last = p.Record
		r.read++
		searchedBack = pick.headTime
		if !in.Sensitive && (eventrules.IsSecurity(p.Channel) || eventrules.IsSecurity(pick.channel)) {
			// A Security event that came by another log (ForwardedEvents).
			r.hiddenEvents++
			continue
		}
		ev, ok, err := r.event(pick, raw, p)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		line, err := marshalLine(ev)
		if err != nil {
			return err
		}
		line = append(line, '\n')
		if r.bytes+len(line) > byteBudget && r.returned > 0 {
			// It does not fit: it is read again by the next page, so the
			// cursor stays before it.
			pick.last = prev
			stopped = eventrules.StopBytes
			break
		}
		if _, err := r.lw.w.Write(line); err != nil {
			return err
		}
		r.bytes += len(line)
		r.returned++
	}
	return r.finish(srcs, stopped, searchedBack)
}

func (r *run) finish(srcs []*source, stopped string, searchedBack time.Time) error {
	for _, f := range r.failures {
		if err := r.lw.write(f); err != nil {
			return err
		}
	}
	cur := &eventrules.Cursor{}
	more := false
	for _, s := range srcs {
		c := eventrules.ChannelCursor{Channel: s.channel, Record: s.last, Created: s.pos.Created, Oldest: s.pos.Oldest, Done: s.done && s.head == nil && len(s.buf) == 0}
		if !c.Done {
			more = true
		}
		cur.Channels = append(cur.Channels, c)
	}
	end := eventrules.End{T: eventrules.LineEnd, Returned: r.returned, Read: r.read, StoppedBy: stopped, Hidden: r.hiddenEvents,
		Unreadable: r.unreadable, Cursor: cur, Clock: r.be.Now().UTC().Format(time.RFC3339Nano),
		Complete: stopped != eventrules.StopCancel && stopped != eventrules.StopTime}
	if stopped == eventrules.StopRead || stopped == eventrules.StopTime || stopped == eventrules.StopPage && more {
		if !searchedBack.IsZero() {
			end.SearchedBack = searchedBack.UTC().Format(time.RFC3339Nano)
		}
	}
	return r.lw.write(end)
}

func hexOf(v uint64) string { return eventrules.FormatKeywords(v) }

// event builds the line of one event: its fields from its XML, the names and
// message from Windows, what the caller may not see hidden, and every bound
// applied. ok is false for an event the text filter does not match.
func (r *run) event(s *source, raw Raw, p *eventrules.Parsed) (eventrules.Event, bool, error) {
	in := r.in
	base := raw.XML
	ev := eventrules.Event{T: eventrules.LineEvent, Log: s.channel, Channel: p.Channel, Record: p.Record, Provider: p.Provider,
		ProviderGUID: p.ProviderGUID, ID: p.ID, Qualifiers: p.Qualifiers, Version: p.Version, Level: p.Level, Task: p.Task,
		Opcode: p.Opcode, Keywords: hexOf(p.Keywords), Time: p.Time, Computer: p.Computer, UserSID: p.UserSID, PID: p.PID, TID: p.TID}
	if t := s.headTimeOf(p); !t.IsZero() {
		if off, ok := r.be.Offset(t); ok {
			ev.Offset = &off
		}
	}
	if p.UserSID != "" {
		ev.User = r.account(p.UserSID)
	}
	data := slices.Clone(p.Data)
	if len(data) > eventrules.MaxValues {
		ev.DataDropped = len(data) - eventrules.MaxValues
		data = data[:eventrules.MaxValues]
	}
	sens := p.Sensitive(p.Channel)
	hide := !in.Sensitive && len(sens) > 0
	meta := Meta{}
	if raw.Meta != nil {
		meta = raw.Meta(p.Provider, true)
	}
	ev.LevelName, ev.TaskName, ev.OpcodeName, ev.KeywordNames = meta.LevelName, meta.TaskName, meta.OpcodeName, meta.KeywordNames
	if ev.LevelName == "" { // a provider Windows has no metadata for: the standard names
		ev.LevelName = standardLevel[ev.Level]
	}
	ev.Message, ev.MessageNote = meta.Message, meta.MessageNote
	if ev.Message == "" && p.HasMessage {
		ev.Message = p.Message
	}
	var hideIdx []int
	if hide {
		hideIdx = sens
		for _, idx := range sens {
			if idx < len(data) {
				data[idx] = eventrules.Datum{Name: data[idx].Name, Path: data[idx].Path, Hidden: true}
			}
			ev.Hidden = appendUniq(ev.Hidden, fieldLabel(p.Data[idx]))
		}
		ev.Message, ev.MessageNote, ev.MessageHidden = "", "", true
	}
	ev.Data = data
	if in.Text != "" && !matches(in.Text, ev) {
		return ev, false, nil
	}
	// Text from computers is shown as text; what JSON cannot hold is made visible.
	ev.Message = agentproto.SafeText(ev.Message)
	ev.MessageNote = agentproto.SafeText(ev.MessageNote)
	pageLimit, msgCut, valCut := eventrules.PageLineBytes, eventrules.PageMessageChars, eventrules.PageValueChars
	if in.Op == eventrules.OpEvent {
		pageLimit, msgCut, valCut = eventrules.EventLineBytes, eventrules.EventMessageChars, eventrules.EventValueChars
	}
	const unlimited = 1 << 30
	ev.XML = p.Rewrite(base, hideIdx, hide, unlimited, unlimited)
	fits := func() bool {
		b, err := marshalLine(ev)
		return err == nil && len(b) <= pageLimit
	}
	// Cut in the ADR's order until it fits: the message, then each value, each
	// cut made alike in the fields and in the XML; last, the System element.
	if !fits() {
		if m, cut := eventrules.CutText(ev.Message, msgCut); cut {
			ev.Message, ev.MessageCut = m, true
		}
		ev.XML = p.Rewrite(base, hideIdx, hide, unlimited, msgCut)
	}
	if !fits() {
		ev.XML = p.Rewrite(base, hideIdx, hide, valCut, msgCut)
		for i := range ev.Data {
			if v, cut := eventrules.CutText(ev.Data[i].Value, valCut); cut {
				ev.Data[i].Value, ev.Data[i].Cut = v, true
			}
		}
	}
	if !fits() {
		ev.XML = eventrules.SystemOnly(base)
		ev.Data, ev.DataDropped, ev.Message, ev.TooLarge = nil, 0, "", true
		ev.MessageNote = "too large for the list: open it"
		if in.Op == eventrules.OpEvent {
			ev.MessageNote = "too large to show here"
		}
		ev.Hidden = nil
		if _, err := eventrules.ParseXML(ev.XML); err != nil {
			return ev, false, fmt.Errorf("an event's System element cannot be read: %w", err)
		}
	}
	return ev, true, nil
}

func (s *source) headTimeOf(p *eventrules.Parsed) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, p.Time)
	return t
}

func (r *run) account(sid string) string {
	if v, ok := r.accounts[sid]; ok {
		return v
	}
	if r.lookups >= maxAccounts {
		return ""
	}
	r.lookups++
	name, ok := r.be.Account(sid)
	if !ok {
		name = ""
	}
	r.accounts[sid] = name
	return name
}

func fieldLabel(d eventrules.Datum) string {
	if d.Name != "" {
		return d.Name
	}
	return "value"
}

func appendUniq(s []string, v string) []string {
	if slices.Contains(s, v) {
		return s
	}
	return append(s, v)
}

// matches is the text filter: a substring of the message or a data value,
// ignoring case, never against what the caller may not see.
func matches(text string, ev eventrules.Event) bool {
	if !ev.MessageHidden && eventrules.ContainsFold(ev.Message, text) {
		return true
	}
	for _, d := range ev.Data {
		if !d.Hidden && eventrules.ContainsFold(d.Value, text) {
			return true
		}
	}
	return false
}

// standardLevel names the levels Windows defines itself.
var standardLevel = map[int]string{0: "Information", 1: "Critical", 2: "Error", 3: "Warning", 4: "Information", 5: "Verbose"}
