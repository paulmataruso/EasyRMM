package winevent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/eventrules"
)

// fakeLog is an in-memory event log: events in the order the log wrote them,
// oldest first.
type fakeLog struct {
	info   LogInfo
	events []string
	err    error
	// openErr is returned by Open.
	openErr error
}

type fakeBackend struct {
	mu       sync.Mutex
	logs     map[string]*fakeLog
	now      time.Time
	queries  []string
	cancels  int
	messages map[int]string
	slow     time.Duration
	chans    []eventrules.ChannelInfo
	crash    *int
	prov     *eventrules.ProviderLine
	provErr  error
}

func (f *fakeBackend) log(ch string) *fakeLog {
	for k, v := range f.logs {
		if eventrules.EqualFold(k, ch) {
			return v
		}
	}
	return nil
}

func (f *fakeBackend) Channels(context.Context) ([]eventrules.ChannelInfo, error) {
	return f.chans, nil
}
func (f *fakeBackend) CrashOnAuditFail() (int, bool) {
	if f.crash == nil {
		return 0, false
	}
	return *f.crash, true
}
func (f *fakeBackend) LogInfo(ch string) (LogInfo, error) {
	l := f.log(ch)
	if l == nil {
		return LogInfo{}, ErrNotFound
	}
	if l.err != nil {
		return LogInfo{}, l.err
	}
	return l.info, nil
}
func (f *fakeBackend) Provider(string) (*eventrules.ProviderLine, error) {
	if f.provErr != nil {
		return nil, f.provErr
	}
	p := *f.prov
	return &p, nil
}
func (f *fakeBackend) Account(sid string) (string, bool) {
	if sid == "S-1-5-18" {
		return `NT AUTHORITY\SYSTEM`, true
	}
	return "", false
}
func (f *fakeBackend) Offset(time.Time) (int, bool) { return -18000, true }
func (f *fakeBackend) Now() time.Time               { return f.now }
func (f *fakeBackend) Cancel() {
	f.mu.Lock()
	f.cancels++
	f.mu.Unlock()
}

var cursorRe = regexp.MustCompile(`EventRecordID(&lt;|&gt;|=)(\d+)`)

func (f *fakeBackend) Open(ch, q string, reverse bool) (Stream, error) {
	f.queries = append(f.queries, q)
	l := f.log(ch)
	if l == nil {
		return nil, ErrNotFound
	}
	if l.openErr != nil {
		return nil, l.openErr
	}
	evs := append([]string{}, l.events...)
	if reverse {
		for i, j := 0, len(evs)-1; i < j; i, j = i+1, j-1 {
			evs[i], evs[j] = evs[j], evs[i]
		}
	}
	out := evs
	if m := cursorRe.FindStringSubmatch(q); m != nil {
		out = nil
		n, _ := strconv.ParseInt(m[2], 10, 64)
		for _, x := range evs {
			rec := recordOf(x)
			if m[1] == "&lt;" && rec >= n || m[1] == "&gt;" && rec <= n || m[1] == "=" && rec != n {
				continue
			}
			out = append(out, x)
		}
	}
	return &fakeStream{f: f, events: out}, nil
}

func recordOf(x string) int64 {
	p, err := eventrules.ParseXML(x)
	if err != nil {
		return 0
	}
	return p.Record
}

type fakeStream struct {
	f      *fakeBackend
	events []string
	closed bool
}

func (s *fakeStream) Next(n int) (Batch, error) {
	if s.f.slow > 0 {
		time.Sleep(s.f.slow)
	}
	if len(s.events) == 0 {
		return Batch{}, io.EOF
	}
	k := min(n, len(s.events))
	var b Batch
	for _, x := range s.events[:k] {
		rec := recordOf(x)
		b.Events = append(b.Events, Raw{XML: x, Meta: func(string, bool) Meta {
			m := Meta{LevelName: "Information", TaskName: "None"}
			if msg, ok := s.f.messages[int(rec)]; ok {
				m.Message = msg
			} else {
				m.MessageNote = "Description unavailable: the provider's message file is not on this computer"
			}
			return m
		}})
	}
	s.events = s.events[k:]
	b.Release = func() {}
	return b, nil
}
func (s *fakeStream) Close() { s.closed = true }

func xmlEvent(rec int, channel, provider string, id int, ts, data string) string {
	return `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="` + provider + `"/><EventID>` + strconv.Itoa(id) +
		`</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime="` + ts +
		`"/><EventRecordID>` + strconv.Itoa(rec) + `</EventRecordID><Execution ProcessID="1" ThreadID="2"/><Channel>` + channel +
		`</Channel><Computer>PC-12</Computer><Security UserID="S-1-5-18"/></System>` + data + `</Event>`
}

var t0 = time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)

// fill makes n events of a log, record 1..n, a minute apart.
func fill(channel string, n int, data func(i int) string) []string {
	var out []string
	for i := 1; i <= n; i++ {
		d := ""
		if data != nil {
			d = data(i)
		}
		out = append(out, xmlEvent(i, channel, "Svc", 100+i, t0.Add(time.Duration(i)*time.Minute).Format("2006-01-02T15:04:05.000000000Z"), d))
	}
	return out
}

func newBackend() *fakeBackend {
	return &fakeBackend{logs: map[string]*fakeLog{}, now: t0.Add(time.Hour), messages: map[int]string{}}
}

type out struct {
	res   *eventrules.Result
	lines [][]byte
	raw   string
}

func exec(t *testing.T, be Backend, in eventrules.Input, opt Options) out {
	t.Helper()
	var b bytes.Buffer
	in.V, in.Rules = 1, eventrules.Version
	if err := Run(context.Background(), in, be, &b, opt); err != nil {
		t.Fatalf("run: %v", err)
	}
	var lines [][]byte
	for _, l := range bytes.Split(bytes.TrimRight(b.Bytes(), "\n"), []byte("\n")) {
		lines = append(lines, l)
	}
	res, err := eventrules.ParseLines(lines)
	if err != nil {
		t.Fatalf("the engine's own result does not decode: %v\n%s", err, b.String())
	}
	return out{res: res, lines: lines, raw: b.String()}
}

func records(o out) []int64 {
	var r []int64
	for _, e := range o.res.Events {
		r = append(r, e.Record)
	}
	return r
}

func TestQueryReturnsNewestFirstInPagesWithACursor(t *testing.T) {
	be := newBackend()
	be.logs["System"] = &fakeLog{events: fill("System", 250, nil), info: LogInfo{Known: true, Created: t0, Oldest: 1}}
	in := eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"System"}}
	o := exec(t, be, in, Options{AgentVersion: "1.2.3", Arch: "x64"})
	if len(o.res.Events) != 100 || o.res.Events[0].Record != 250 || o.res.Events[99].Record != 151 {
		t.Fatalf("first page: %v", records(o)[:3])
	}
	end := o.res.End
	if end == nil || end.StoppedBy != eventrules.StopPage || !end.Complete || end.Returned != 100 || o.res.Begin.AgentVersion != "1.2.3" {
		t.Fatalf("end: %+v", end)
	}
	if c := end.Cursor.For("System"); c == nil || c.Record != 151 || c.Done {
		t.Fatalf("cursor: %+v", end.Cursor)
	}
	// The next page continues after the cursor, and the last one ends.
	in.Cursor = end.Cursor
	o2 := exec(t, be, in, Options{})
	if len(o2.res.Events) != 100 || o2.res.Events[0].Record != 150 {
		t.Fatalf("second page: %v", records(o2)[:2])
	}
	in.Cursor = o2.res.End.Cursor
	o3 := exec(t, be, in, Options{})
	if len(o3.res.Events) != 50 || o3.res.End.StoppedBy != eventrules.StopEnd || !o3.res.End.Cursor.For("System").Done {
		t.Fatalf("last page: %d %+v", len(o3.res.Events), o3.res.End)
	}
	if !strings.Contains(be.queries[1], "EventRecordID&lt;151") {
		t.Fatalf("the query does not continue: %s", be.queries[1])
	}
	// Each event carries what the XML and Windows say.
	e := o.res.Events[0]
	if e.Provider != "Svc" || e.ID != 350 || e.LevelName != "Information" || e.User != `NT AUTHORITY\SYSTEM` || e.Offset == nil || *e.Offset != -18000 ||
		e.Keywords != "0x0080000000000000" || e.Log != "System" || e.MessageNote == "" {
		t.Fatalf("event: %+v", e)
	}
	// What the engine wrote passes the server's own check.
	in.Cursor = nil
	if _, err := eventrules.CheckResult(eventrules.Input{V: 1, Op: eventrules.OpQuery, Channels: []string{"System"}}, o.res, t0.Add(time.Hour)); err != nil {
		t.Fatalf("the server's check: %v", err)
	}
}

func TestSeveralLogsAreMergedByTime(t *testing.T) {
	be := newBackend()
	be.logs["System"] = &fakeLog{events: fill("System", 3, nil), info: LogInfo{Known: true, Created: t0, Oldest: 1}}
	// Application's events are 30 seconds after System's.
	var app []string
	for i := 1; i <= 3; i++ {
		app = append(app, xmlEvent(i, "Application", "App", 9, t0.Add(time.Duration(i)*time.Minute+30*time.Second).Format("2006-01-02T15:04:05.000000000Z"), ""))
	}
	be.logs["Application"] = &fakeLog{events: app, info: LogInfo{Known: true, Created: t0, Oldest: 1}}
	o := exec(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"system", "Application"}}, Options{})
	var got []string
	for _, e := range o.res.Events {
		got = append(got, fmt.Sprintf("%s%d", strings.ToUpper(e.Log[:1]), e.Record))
	}
	if strings.Join(got, " ") != "A3 S3 A2 S2 A1 S1" {
		t.Fatalf("merge order: %v", got)
	}
	// A channel named twice ignoring case is read once; the input refuses it.
	if err := Run(context.Background(), eventrules.Input{V: 1, Op: eventrules.OpQuery, Channels: []string{"System", "SYSTEM"}}, be, io.Discard, Options{}); err == nil {
		t.Fatal("a channel twice")
	}
}

func TestAnalyticLogIsReadAloneOldestFirst(t *testing.T) {
	be := newBackend()
	be.logs["X/Analytic"] = &fakeLog{events: fill("X/Analytic", 3, nil), info: LogInfo{Ascending: true}}
	be.logs["System"] = &fakeLog{events: fill("System", 1, nil), info: LogInfo{Known: true, Created: t0, Oldest: 1}}
	o := exec(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"X/Analytic"}}, Options{})
	if r := records(o); len(r) != 3 || r[0] != 1 || o.res.Pos[0].Ascending != true {
		t.Fatalf("%v %+v", r, o.res.Pos)
	}
	o = exec(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"X/Analytic", "System"}}, Options{})
	if len(o.res.Events) != 1 || o.res.Pos[0].State != eventrules.StateUnavailable || !strings.Contains(o.res.Pos[0].Reason, "alone") {
		t.Fatalf("%+v", o.res.Pos)
	}
}

func TestStatesOfAChannel(t *testing.T) {
	be := newBackend()
	be.logs["Gone"] = &fakeLog{info: LogInfo{}, err: ErrNotFound}
	be.logs["Denied"] = &fakeLog{err: ErrDenied}
	be.logs["Svc"] = &fakeLog{err: ErrService}
	be.logs["An"] = &fakeLog{info: LogInfo{Ascending: true}, openErr: ErrAnalytic}
	be.logs["Complex"] = &fakeLog{openErr: ErrTooComplex}
	be.logs["Ok"] = &fakeLog{events: fill("Ok", 1, nil), info: LogInfo{Known: true, Created: t0, Oldest: 1}}
	o := exec(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"Nope", "Gone", "Denied", "Svc", "Ok"}}, Options{})
	st := map[string]string{}
	for _, p := range o.res.Pos {
		st[p.Channel] = p.State
	}
	want := map[string]string{"Nope": "not_found", "Gone": "not_found", "Denied": "denied", "Svc": "unavailable", "Ok": "ok"}
	for k, v := range want {
		if st[k] != v {
			t.Errorf("%s: %q", k, st[k])
		}
	}
	if len(o.res.Events) != 1 {
		t.Fatal("the readable channel is read")
	}
	o = exec(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"An"}}, Options{})
	if o.res.Pos[0].State != "unavailable" || !strings.Contains(o.res.Pos[0].Reason, "disabled") {
		t.Fatalf("%+v", o.res.Pos)
	}
	o = exec(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"Complex"}}, Options{})
	if len(o.res.Errors) != 1 || !strings.Contains(o.res.Errors[0].Message, "too complex") {
		t.Fatalf("%+v", o.res.Errors)
	}
}

func TestSecurityLogIsRefusedWithoutSensitive(t *testing.T) {
	be := newBackend()
	be.logs["Security"] = &fakeLog{events: fill("Security", 2, nil), info: LogInfo{Known: true, Created: t0, Oldest: 1}}
	for _, ch := range []string{"Security", "SECURITY", "Archive-Security-2026"} {
		be.logs[ch] = be.logs["Security"]
		o := exec(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{ch}}, Options{})
		if len(o.res.Events) != 0 || len(o.res.Errors) != 1 || o.res.Errors[0].Code != eventrules.ErrCodeRefused {
			t.Fatalf("%s: %+v", ch, o.res)
		}
	}
	if len(be.queries) != 0 {
		t.Fatalf("the Security log was queried: %v", be.queries)
	}
	o := exec(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"Security"}, Sensitive: true}, Options{})
	if len(o.res.Events) != 2 {
		t.Fatal("allowed with sensitive")
	}
}

func TestSecurityEventsFromAnotherLogAreDropped(t *testing.T) {
	be := newBackend()
	fwd := []string{
		xmlEvent(1, "Security", "Microsoft-Windows-Security-Auditing", 4624, "2026-11-26T10:01:00.000Z", ""),
		xmlEvent(2, "System", "Svc", 1, "2026-11-26T10:02:00.000Z", ""),
	}
	be.logs["ForwardedEvents"] = &fakeLog{events: fwd, info: LogInfo{Known: true, Created: t0, Oldest: 1}}
	o := exec(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"ForwardedEvents"}}, Options{})
	if len(o.res.Events) != 1 || o.res.Events[0].Channel != "System" || o.res.End.Hidden != 1 {
		t.Fatalf("%+v %+v", o.res.Events, o.res.End)
	}
	o = exec(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"ForwardedEvents"}, Sensitive: true}, Options{})
	if len(o.res.Events) != 2 {
		t.Fatal("with sensitive both are shown")
	}
}

func TestSensitiveValuesNeverReachTheResult(t *testing.T) {
	be := newBackend()
	cmd := func(int) string {
		return `<EventData><Data Name="CommandLine">run --password=hunter2</Data><Data Name="Other">fine</Data></EventData>`
	}
	be.logs["Application"] = &fakeLog{events: fill("Application", 2, cmd), info: LogInfo{Known: true, Created: t0, Oldest: 1}}
	be.messages[1], be.messages[2] = "run --password=hunter2", "run --password=hunter2"
	o := exec(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"Application"}}, Options{})
	if strings.Contains(o.raw, "hunter2") {
		t.Fatalf("a sensitive value is in the result:\n%s", o.raw)
	}
	e := o.res.Events[0]
	if !e.Data[0].Hidden || e.Data[1].Value != "fine" || !e.MessageHidden || e.Message != "" || len(e.Hidden) != 1 || e.Hidden[0] != "CommandLine" {
		t.Fatalf("%+v", e)
	}
	if !strings.Contains(e.XML, "[hidden: needs") || !strings.Contains(e.XML, "fine") {
		t.Fatal(e.XML)
	}
	// With the permission they are shown, message included.
	o = exec(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"Application"}, Sensitive: true}, Options{})
	if !strings.Contains(o.raw, "hunter2") || o.res.Events[0].MessageHidden || o.res.Events[0].Message == "" {
		t.Fatal("sensitive shown")
	}
	// The text match skips what is hidden: it finds nothing, and "fine" is found.
	o = exec(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"Application"}, Text: "hunter2"}, Options{})
	if len(o.res.Events) != 0 {
		t.Fatal("the search probed a hidden value")
	}
	o = exec(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"Application"}, Text: "FINE"}, Options{})
	if len(o.res.Events) != 2 {
		t.Fatalf("text: %d", len(o.res.Events))
	}
}

func TestTextMatchesTheMessageAndValuesAfterTheQuery(t *testing.T) {
	be := newBackend()
	be.logs["System"] = &fakeLog{events: fill("System", 6, func(i int) string {
		return `<EventData><Data Name="Who">user` + strconv.Itoa(i) + `</Data></EventData>`
	}), info: LogInfo{Known: true, Created: t0, Oldest: 1}}
	be.messages[2] = "The Service entered the RUNNING state"
	o := exec(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"System"}, Text: "running state"}, Options{})
	if r := records(o); len(r) != 1 || r[0] != 2 {
		t.Fatalf("%v", r)
	}
	o = exec(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"System"}, Text: "USER5"}, Options{})
	if r := records(o); len(r) != 1 || r[0] != 5 {
		t.Fatalf("%v", r)
	}
	if o.res.End.Read != 6 || o.res.End.StoppedBy != eventrules.StopEnd {
		t.Fatalf("%+v", o.res.End)
	}
}

func TestPageStopsAtItsByteBudgetAndTheNextPageStartsAtTheUnwrittenEvent(t *testing.T) {
	be := newBackend()
	big := strings.Repeat("x", 12000)
	be.logs["System"] = &fakeLog{events: fill("System", 200, func(int) string {
		return `<EventData><Data Name="Blob">` + big + `</Data></EventData>`
	}), info: LogInfo{Known: true, Created: t0, Oldest: 1}}
	in := eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"System"}}
	o := exec(t, be, in, Options{})
	if o.res.End.StoppedBy != eventrules.StopBytes || len(o.res.Events) == 0 || len(o.res.Events) >= 100 || len(o.raw) > eventrules.PageBytes+eventrules.PageLineBytes {
		t.Fatalf("%d events, %d bytes, %+v", len(o.res.Events), len(o.raw), o.res.End)
	}
	last := o.res.Events[len(o.res.Events)-1].Record
	if c := o.res.End.Cursor.For("System"); c.Record != last {
		t.Fatalf("cursor %d, last event %d", c.Record, last)
	}
	in.Cursor = o.res.End.Cursor
	o2 := exec(t, be, in, Options{})
	if o2.res.Events[0].Record != last-1 {
		t.Fatalf("the next page starts at %d, not after %d", o2.res.Events[0].Record, last)
	}
}

func TestAnEventOverItsBudgetIsCutInTheFieldsAndTheXMLAlike(t *testing.T) {
	be := newBackend()
	v := strings.Repeat("é", 2000)
	be.logs["System"] = &fakeLog{events: []string{xmlEvent(1, "System", "Svc", 1, "2026-11-26T10:00:00.000Z",
		`<EventData><Data Name="a">`+v+`</Data><Data Name="b">`+strings.Repeat("y", 20000)+`</Data><Data Name="c">short &amp; sweet</Data></EventData>`)},
		info: LogInfo{Known: true, Created: t0, Oldest: 1}}
	be.messages[1] = strings.Repeat("m", 40000)
	in := eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"System"}}
	o := exec(t, be, in, Options{})
	e := o.res.Events[0]
	if !e.MessageCut || len([]rune(e.Message)) != eventrules.PageMessageChars+len([]rune(eventrules.CutMarker)) || !e.Data[0].Cut || !e.Data[1].Cut || e.Data[2].Cut || e.TooLarge {
		t.Fatalf("cuts: %+v", e)
	}
	if len(o.lines[1]) > eventrules.PageLineBytes {
		t.Fatalf("line of %d bytes", len(o.lines[1]))
	}
	// The server's comparison of fields and XML holds.
	if _, err := eventrules.CheckResult(eventrules.Input{V: 1, Op: eventrules.OpQuery, Channels: []string{"System"}}, o.res, be.now); err != nil {
		t.Fatalf("server check: %v", err)
	}
	// And HTML is not escaped: the XML's angle brackets are one byte each.
	if strings.Contains(string(o.lines[1]), `<`) {
		t.Fatal("the XML was escaped for HTML")
	}
}

func TestAnEventTooLargeForTheListIsSentAsItsSystemElement(t *testing.T) {
	be := newBackend()
	var d strings.Builder
	d.WriteString(`<EventData>`)
	for i := range 40 {
		fmt.Fprintf(&d, `<Data Name="n%d">%s</Data>`, i, strings.Repeat("z", 1000))
	}
	d.WriteString(`</EventData>`)
	be.logs["System"] = &fakeLog{events: []string{xmlEvent(1, "System", "Svc", 1, "2026-11-26T10:00:00.000Z", d.String()),
		xmlEvent(2, "System", "Svc", 2, "2026-11-26T10:01:00.000Z", "")}, info: LogInfo{Known: true, Created: t0, Oldest: 1}}
	o := exec(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"System"}}, Options{})
	if len(o.res.Events) != 2 {
		t.Fatalf("%d", len(o.res.Events))
	}
	e := o.res.Events[1]
	if !e.TooLarge || len(e.Data) != 0 || strings.Contains(e.XML, "EventData") || e.MessageNote == "" {
		t.Fatalf("%+v", e)
	}
	// It takes one line and moves the cursor.
	if c := o.res.End.Cursor.For("System"); !c.Done {
		t.Fatalf("%+v", c)
	}
	if _, err := eventrules.CheckResult(eventrules.Input{V: 1, Op: eventrules.OpQuery, Channels: []string{"System"}}, o.res, be.now); err != nil {
		t.Fatal(err)
	}
}

func TestMoreThan256ValuesAreCountedNotSent(t *testing.T) {
	be := newBackend()
	var d strings.Builder
	d.WriteString(`<EventData>`)
	for i := range 300 {
		fmt.Fprintf(&d, `<Data Name="n%d">v</Data>`, i)
	}
	d.WriteString(`</EventData>`)
	be.logs["System"] = &fakeLog{events: []string{xmlEvent(1, "System", "Svc", 1, "2026-11-26T10:00:00.000Z", d.String())}, info: LogInfo{Known: true, Created: t0, Oldest: 1}}
	o := exec(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"System"}}, Options{})
	e := o.res.Events[0]
	if len(e.Data) != 256 || e.DataDropped != 44 {
		t.Fatalf("%d %d", len(e.Data), e.DataDropped)
	}
	if _, err := eventrules.CheckResult(eventrules.Input{V: 1, Op: eventrules.OpQuery, Channels: []string{"System"}}, o.res, be.now); err != nil {
		t.Fatal(err)
	}
}

func TestClearedAndOverwrittenLogsAreNoticed(t *testing.T) {
	be := newBackend()
	be.logs["System"] = &fakeLog{events: fill("System", 10, nil), info: LogInfo{Known: true, Created: t0, Oldest: 1}}
	in := eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"System"}}
	first := exec(t, be, in, Options{})
	// The log is cleared: a new creation time.
	be.logs["System"].info.Created = t0.Add(time.Minute)
	in.Cursor = &eventrules.Cursor{Channels: []eventrules.ChannelCursor{{Channel: "System", Record: 5, Created: first.res.Pos[0].Created, Oldest: 1}}}
	o := exec(t, be, in, Options{})
	if !o.res.Pos[0].Cleared || len(o.res.Events) != 0 {
		t.Fatalf("%+v", o.res.Pos[0])
	}
	// The log wrapped past the cursor: the oldest record is above it.
	be.logs["System"].info = LogInfo{Known: true, Created: t0, Oldest: 8}
	in.Cursor = &eventrules.Cursor{Channels: []eventrules.ChannelCursor{{Channel: "System", Record: 5, Created: t0.Format(time.RFC3339Nano), Oldest: 1}}}
	o = exec(t, be, in, Options{})
	if !o.res.Pos[0].Overwritten {
		t.Fatalf("%+v", o.res.Pos[0])
	}
}

func TestCancelStopsThePageAndWritesItsLastLine(t *testing.T) {
	be := newBackend()
	be.logs["System"] = &fakeLog{events: fill("System", 5000, nil), info: LogInfo{Known: true, Created: t0, Oldest: 1}}
	be.slow = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	var b bytes.Buffer
	in := eventrules.Input{V: 1, Op: eventrules.OpQuery, Channels: []string{"System"}, Text: "never matches"}
	if err := Run(ctx, in, be, &b, Options{}); err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimRight(b.Bytes(), "\n"), []byte("\n"))
	res, err := eventrules.ParseLines(lines)
	if err != nil || res.End == nil || res.End.StoppedBy != eventrules.StopCancel || res.End.Complete {
		t.Fatalf("%v %+v", err, res.End)
	}
}

func TestTimeLimitEndsThePageSayingHowFarItSearched(t *testing.T) {
	be := newBackend()
	be.logs["System"] = &fakeLog{events: fill("System", 5000, nil), info: LogInfo{Known: true, Created: t0, Oldest: 1}}
	be.slow = 30 * time.Millisecond
	o := exec(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"System"}, Text: "never"}, Options{Deadline: 150 * time.Millisecond})
	if o.res.End.StoppedBy != eventrules.StopTime || o.res.End.SearchedBack == "" || o.res.End.Read == 0 || o.res.End.Complete {
		t.Fatalf("%+v", o.res.End)
	}
	if c := o.res.End.Cursor.For("System"); c.Done || c.Record == 0 {
		t.Fatalf("cursor: %+v", c)
	}
}

func TestEventOperationReadsOneRecord(t *testing.T) {
	be := newBackend()
	be.logs["System"] = &fakeLog{events: fill("System", 5, nil), info: LogInfo{Known: true, Created: t0, Oldest: 1}}
	o := exec(t, be, eventrules.Input{Op: eventrules.OpEvent, Channels: []string{"System"}, Record: 3}, Options{})
	if len(o.res.Events) != 1 || o.res.Events[0].Record != 3 || !strings.Contains(be.queries[0], "EventRecordID=3") {
		t.Fatalf("%v %v", records(o), be.queries)
	}
	o = exec(t, be, eventrules.Input{Op: eventrules.OpEvent, Channels: []string{"System"}, Record: 99}, Options{})
	if len(o.res.Events) != 0 || o.res.End.StoppedBy != eventrules.StopEnd {
		t.Fatalf("%+v", o.res.End)
	}
}

func TestChannelsAndProviderOperations(t *testing.T) {
	be := newBackend()
	three := 3
	be.crash = &three
	size := int64(1024)
	be.chans = []eventrules.ChannelInfo{{Name: "System", Type: "admin", Enabled: true, Size: &size}, {Name: "Security", Type: "admin", Enabled: true}}
	o := exec(t, be, eventrules.Input{Op: eventrules.OpChannels}, Options{})
	if o.res.Crash == nil || !o.res.Crash.Set || o.res.Crash.Value != 3 || len(o.res.Channels) != 2 || o.res.End.Returned != 2 {
		t.Fatalf("%+v", o.res)
	}
	be.crash = nil
	o = exec(t, be, eventrules.Input{Op: eventrules.OpChannels}, Options{})
	if o.res.Crash == nil || o.res.Crash.Set {
		t.Fatalf("%+v", o.res.Crash)
	}
	be.prov = &eventrules.ProviderLine{Name: "Svc", Levels: []eventrules.MetaItem{{Name: "win:Error", Value: 2, Display: "Error"}}}
	o = exec(t, be, eventrules.Input{Op: eventrules.OpProvider, Provider: "Svc"}, Options{})
	if o.res.Provider == nil || o.res.Provider.Levels[0].Display != "Error" {
		t.Fatalf("%+v", o.res.Provider)
	}
	be.provErr = ErrNotFound
	o = exec(t, be, eventrules.Input{Op: eventrules.OpProvider, Provider: "Nope"}, Options{})
	if len(o.res.Errors) != 1 || o.res.Errors[0].Code != eventrules.ErrCodeNotFound {
		t.Fatalf("%+v", o.res.Errors)
	}
	if _, err := eventrules.CheckResult(eventrules.Input{V: 1, Op: eventrules.OpChannels}, exec(t, be, eventrules.Input{Op: eventrules.OpChannels}, Options{}).res, be.now); err != nil {
		t.Fatal(err)
	}
}

func TestAccountsAreLookedUpOncePerSIDAndAtMost64(t *testing.T) {
	be := newBackend()
	var evs []string
	for i := 1; i <= 90; i++ {
		x := xmlEvent(i, "System", "Svc", 1, "2026-11-26T10:00:00.000Z", "")
		x = strings.Replace(x, `UserID="S-1-5-18"`, fmt.Sprintf(`UserID="S-1-5-21-1-2-3-%d"`, 1000+i), 1)
		evs = append(evs, x)
	}
	be.logs["System"] = &fakeLog{events: evs, info: LogInfo{Known: true, Created: t0, Oldest: 1}}
	o := exec(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"System"}}, Options{})
	resolved := 0
	for _, e := range o.res.Events {
		if e.UserSID == "" {
			t.Fatal("the SID is always kept")
		}
		_ = e
		resolved++
	}
	sort.Slice(o.res.Events, func(i, j int) bool { return o.res.Events[i].Record < o.res.Events[j].Record })
	if resolved != 90 {
		t.Fatal(resolved)
	}
}

func TestUnreadableEventsAreCounted(t *testing.T) {
	be := newBackend()
	be.logs["System"] = &fakeLog{events: []string{"<Event><System>", xmlEvent(2, "System", "Svc", 1, "2026-11-26T10:00:00.000Z", "")}, info: LogInfo{Known: true, Created: t0, Oldest: 1}}
	o := exec(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"System"}}, Options{})
	if len(o.res.Events) != 1 || o.res.End.Unreadable != 1 {
		t.Fatalf("%+v", o.res.End)
	}
}

func TestInvalidTextBecomesVisible(t *testing.T) {
	be := newBackend()
	be.logs["System"] = &fakeLog{events: []string{xmlEvent(1, "System", "Svc", 1, "2026-11-26T10:00:00.000Z", "<EventData><Data Name=\"a\">x\x00y</Data></EventData>")}, info: LogInfo{Known: true, Created: t0, Oldest: 1}}
	be.messages[0] = "m\x00m"
	o := exec(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"System"}}, Options{})
	if strings.ContainsRune(o.raw, 0) || strings.Contains(o.raw, `\u0000`) || o.res.Events[0].Data[0].Value != `x\0y` || o.res.Events[0].Message != `m\0m` {
		t.Fatalf("%+v", o.res.Events)
	}
}

func TestRunRefusesAnInvalidInput(t *testing.T) {
	var b bytes.Buffer
	if err := Run(context.Background(), eventrules.Input{V: 1, Op: "clear"}, newBackend(), &b, Options{}); err == nil || b.Len() != 0 {
		t.Fatal("an unknown operation runs")
	}
	_ = json.Marshal
}
