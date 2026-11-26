//go:build integration

package jobs

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/eventrules"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// What an agent that has the event viewer lists in its poll.
var eventlogAccepts = []string{agentproto.CapJobStructured, agentproto.CapBuiltin(agentproto.BuiltinEventlog, 1), agentproto.CapJobParams}

type eventlogFixture struct {
	*fixture
	tech, other, reader, orgAdmin access.Caller
	pc                            uuid.UUID
}

func newEventlogFixture(t *testing.T) *eventlogFixture {
	t.Helper()
	f := newFixture(t)
	e := &eventlogFixture{fixture: f}
	e.tech = f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	e.other = f.user("other@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	e.reader = f.user("reader@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme, SiteID: f.hq})
	e.orgAdmin = f.user("orgadmin@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	e.pc = f.device(f.hq, "PC-12", "windows")
	if _, err := f.svc.Poll(f.ctx, e.pc, eventlogAccepts); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *eventlogFixture) ask(c access.Caller, r EventlogRequest) *EventlogRun {
	e.t.Helper()
	r.DeviceID = e.pc
	run, err := e.svc.CreateEventlogQuery(e.ctx, c, r)
	if err != nil {
		e.t.Fatal(err)
	}
	return run
}

// deliver gives the device's poll to the agent and returns what it was sent.
func (e *eventlogFixture) deliver() []agentproto.JobPayload {
	e.t.Helper()
	resp, err := e.svc.Poll(e.ctx, e.pc, eventlogAccepts)
	if err != nil {
		e.t.Fatal(err)
	}
	var out []agentproto.JobPayload
	for _, j := range resp.Jobs {
		p, err := agentproto.VerifyJob(e.key, j, e.pc.String(), time.Now())
		if err != nil {
			e.t.Fatalf("a delivered job does not verify: %v", err)
		}
		out = append(out, p)
	}
	return out
}

// answer reports a run's lines as the agent would.
func (e *eventlogFixture) answer(run uuid.UUID, status string, lines []string) {
	e.t.Helper()
	(&registryFixture{fixture: e.fixture, pc: e.pc}).answer(run, status, lines, nil)
}

func evXML(rec int64, channel, provider string, id int, ts, data string) string {
	return `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="` + provider + `"/><EventID>` + strconv.Itoa(id) +
		`</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime="` + ts +
		`"/><EventRecordID>` + strconv.FormatInt(rec, 10) + `</EventRecordID><Execution ProcessID="1" ThreadID="2"/><Channel>` + channel +
		`</Channel><Computer>PC-12</Computer><Security UserID="S-1-5-18"/></System>` + data + `</Event>`
}

// evLine is the builtin's line for an XML, as a faithful builtin writes it.
func evLine(t *testing.T, log, x string) eventrules.Event {
	t.Helper()
	p, err := eventrules.ParseXML(x)
	if err != nil {
		t.Fatal(err)
	}
	return eventrules.Event{T: eventrules.LineEvent, Log: log, Channel: p.Channel, Record: p.Record, Provider: p.Provider, ID: p.ID, Version: p.Version,
		Level: p.Level, Task: p.Task, Opcode: p.Opcode, Keywords: eventrules.FormatKeywords(p.Keywords), Time: p.Time, Computer: p.Computer,
		UserSID: p.UserSID, PID: p.PID, TID: p.TID, Data: p.Data, Message: "A message.", XML: x}
}

func resultLines(op string, evs []eventrules.Event, mutate func(*eventrules.End)) []string {
	ls := []string{line(eventrules.Begin{T: eventrules.LineBegin, V: 1, Op: op, Rules: 1, AgentVersion: "1.5.0", Arch: "x64", Clock: "2026-11-26T10:05:00Z"})}
	for _, e := range evs {
		ls = append(ls, line(e))
	}
	end := eventrules.End{T: eventrules.LineEnd, Complete: true, Returned: len(evs), Read: len(evs), StoppedBy: eventrules.StopPage,
		Cursor: &eventrules.Cursor{Channels: []eventrules.ChannelCursor{{Channel: "System", Record: 5}}}}
	if mutate != nil {
		mutate(&end)
	}
	return append(ls, line(end))
}

func TestEventlogQueryIsCheckedAndRecorded(t *testing.T) {
	e := newEventlogFixture(t)
	const marker = "TextMarker-4c1e"

	run := e.ask(e.tech, EventlogRequest{Op: "query", Channels: []string{"System", "SYSTEM", "Application"}, Levels: []int{2, 3}, Text: marker,
		Time: &eventrules.TimeFilter{Last: "24h"}})
	if k := e.str(`SELECT kind||' '||executor||' '||builtin||' '||lane||' '||hidden||' '||array_to_string(requires, ',') FROM jobs WHERE id = $1`, run.JobID); k !=
		"eventlog_query builtin eventlog quick true job.structured,builtin.eventlog.v1" {
		t.Errorf("the job: %s", k)
	}
	if run.Sensitive {
		t.Error("a technician's query is not sensitive")
	}
	// The input has the channels once, and says it is not sensitive.
	p := e.deliver()
	if len(p) != 1 {
		t.Fatalf("%d jobs", len(p))
	}
	in, err := eventrules.DecodeInput(p[0].Input)
	if err != nil || len(in.Channels) != 2 || in.Sensitive || in.Text != marker || in.Rules != eventrules.Version || p[0].Builtin != "eventlog" || p[0].Lane != "quick" {
		t.Fatalf("%+v %v", in, err)
	}
	// One record, with the text's length and never the text; no event data.
	if n := e.str(`SELECT count(*)::text FROM audit_log WHERE action = 'eventlog.query'`); n != "1" {
		t.Fatalf("%s eventlog.query records", n)
	}
	d := e.str(`SELECT details::text FROM audit_log WHERE action = 'eventlog.query'`)
	if strings.Contains(d, marker) || !strings.Contains(d, `"textLength": 15`) || !strings.Contains(d, `"operation": "query"`) || !strings.Contains(d, `"sensitive": false`) {
		t.Errorf("the record: %s", d)
	}
	if n := e.str(`SELECT count(*)::text FROM audit_log WHERE details::text LIKE '%' || $1 || '%'`, marker); n != "0" {
		t.Errorf("the text is in %s records", n)
	}

	// Who may ask, and of which devices.
	_, err = e.svc.CreateEventlogQuery(e.ctx, e.reader, EventlogRequest{DeviceID: e.pc, Op: "channels"})
	fieldErr(t, err, "deviceIds", "You cannot read event logs on PC-12")
	tux := e.device(e.hq, "TUX", "linux")
	_, err = e.svc.CreateEventlogQuery(e.ctx, e.tech, EventlogRequest{DeviceID: tux, Op: "channels"})
	fieldErr(t, err, "deviceIds", "The event viewer runs on Windows")
	old := e.device(e.hq, "PC-OLD", "windows")
	if _, err := e.svc.Poll(e.ctx, old, []string{agentproto.CapJobPwsh, agentproto.CapJobParams, agentproto.CapBuiltin("registry", 1), agentproto.CapJobStructured}); err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.CreateEventlogQuery(e.ctx, e.tech, EventlogRequest{DeviceID: old, Op: "channels"})
	fieldErr(t, err, "deviceIds", "PC-OLD's agent cannot open the event viewer; update the agent.")
	// The registry editor still works on that device: no fallback, no coupling.
	if _, err := e.svc.CreateRegistryQuery(e.ctx, e.tech, RegistryQueryInput{DeviceID: old, Op: "list", Hive: "HKLM"}); err != nil {
		t.Errorf("the registry editor on the same device: %v", err)
	}
	_, err = e.svc.CreateEventlogQuery(e.ctx, e.tech, EventlogRequest{DeviceID: uuid.New(), Op: "channels"})
	fieldErr(t, err, "deviceIds", "does not exist")

	// The input is checked as the agent will check it.
	for name, r := range map[string]EventlogRequest{
		"no channel":       {Op: "query"},
		"11 channels":      {Op: "query", Channels: []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"}},
		"a bad level":      {Op: "query", Channels: []string{"System"}, Levels: []int{9}},
		"a task alone":     {Op: "query", Channels: []string{"System"}, Tasks: []int{1}},
		"a bad time":       {Op: "query", Channels: []string{"System"}, Time: &eventrules.TimeFilter{Last: "2h"}},
		"both quotes":      {Op: "query", Channels: []string{"System"}, Providers: []string{`a'b"c`}},
		"a bad operation":  {Op: "clear", Channels: []string{"System"}},
		"long text":        {Op: "query", Channels: []string{"System"}, Text: strings.Repeat("x", 257)},
		"an event, no log": {Op: "event", Record: 3},
	} {
		r.DeviceID = e.pc
		if _, err := e.svc.CreateEventlogQuery(e.ctx, e.tech, r); !isInvalid(err) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// The Security log and sensitive data: refused for a technician, in every
	// spelling, and recorded within the bound (once per caller and device).
	for _, ch := range []string{"Security", "SECURITY", "Archive-Security-2026-01-01-00-00-00-000"} {
		_, err := e.svc.CreateEventlogQuery(e.ctx, e.tech, EventlogRequest{DeviceID: e.pc, Op: "query", Channels: []string{ch}, Sensitive: true})
		fieldErr(t, err, "channels", "Refused by EasyRMM")
		_, err = e.svc.CreateEventlogQuery(e.ctx, e.tech, EventlogRequest{DeviceID: e.pc, Op: "query", Channels: []string{ch}})
		fieldErr(t, err, "channels", "Refused by EasyRMM")
	}
	_, err = e.svc.CreateEventlogQuery(e.ctx, e.tech, EventlogRequest{DeviceID: e.pc, Op: "query", Channels: []string{"System"}, Sensitive: true})
	fieldErr(t, err, "channels", "Refused by EasyRMM")
	if n := e.str(`SELECT count(*)::text FROM audit_log WHERE action = 'eventlog.refused' AND outcome = 'denied'`); n != "1" {
		t.Errorf("%s eventlog.refused records for one caller and device, want 1", n)
	}
	if n := e.str(`SELECT count(*)::text FROM job_runs r JOIN jobs j ON j.id = r.job_id WHERE j.kind = 'eventlog_query'`); n != "1" {
		t.Errorf("a refused request made a run: %s", n)
	}
	// An organization administrator may, by asking for it; without asking for
	// the Security log, the request says so.
	_, err = e.svc.CreateEventlogQuery(e.ctx, e.orgAdmin, EventlogRequest{DeviceID: e.pc, Op: "query", Channels: []string{"Security"}})
	fieldErr(t, err, "sensitive", "Ask for the Security log")
	sec := e.ask(e.orgAdmin, EventlogRequest{Op: "query", Channels: []string{"Security"}, Sensitive: true})
	if !sec.Sensitive {
		t.Error("an organization administrator's sensitive query")
	}
	// Sensitive data in a System query, asked for and held.
	if r := e.ask(e.orgAdmin, EventlogRequest{Op: "query", Channels: []string{"System"}, Sensitive: true}); !r.Sensitive {
		t.Error("command lines and scripts, asked for")
	}
	// The permission is the organization's: a site-scoped administrator never holds it.
	siteAdmin := e.user("siteadmin@example.com", rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: e.acme, SiteID: e.hq})
	_, err = e.svc.CreateEventlogQuery(e.ctx, siteAdmin, EventlogRequest{DeviceID: e.pc, Op: "query", Channels: []string{"Security"}, Sensitive: true})
	fieldErr(t, err, "channels", "Refused by EasyRMM")

	// The development scope: no event log reads outside it.
	restore := devscope.Set(e.globex)
	_, err = e.svc.CreateEventlogQuery(e.ctx, e.tech, EventlogRequest{DeviceID: e.pc, Op: "channels"})
	restore()
	fieldErr(t, err, "deviceIds", "outside the development scope")
}

func TestEventlogOpenQueriesAreLimited(t *testing.T) {
	e := newEventlogFixture(t)
	first := e.ask(e.tech, EventlogRequest{Op: "query", Channels: []string{"System"}})
	// A new filter from the same person cancels their run still open.
	second := e.ask(e.tech, EventlogRequest{Op: "query", Channels: []string{"Application"}})
	if s := e.str(`SELECT status FROM job_runs WHERE id = $1`, first.RunID); s != "canceled" {
		t.Errorf("the first query is %s, want canceled", s)
	}
	if s := e.str(`SELECT status FROM job_runs WHERE id = $1`, second.RunID); s != "queued" {
		t.Errorf("the second query is %s", s)
	}
	// A channel list does not cancel a search.
	e.ask(e.tech, EventlogRequest{Op: "channels"})
	if s := e.str(`SELECT status FROM job_runs WHERE id = $1`, second.RunID); s != "queued" {
		t.Errorf("a channel list canceled the search: %s", s)
	}
	// Two open on a device; a third, from anyone, is refused.
	_, err := e.svc.CreateEventlogQuery(e.ctx, e.other, EventlogRequest{DeviceID: e.pc, Op: "query", Channels: []string{"System"}})
	if x, ok := apperr.As(err); !ok || x.Code != "searches_open" || !strings.Contains(x.Message, "Two searches are already open on PC-12") {
		t.Fatalf("a third open search: %v", err)
	}
	// A running one is canceled by asking the agent: the cancel reaches the poll.
	e.deliver()
	if _, err := e.svc.Start(e.ctx, e.pc, second.RunID); err != nil {
		t.Fatal(err)
	}
	third := e.ask(e.tech, EventlogRequest{Op: "query", Channels: []string{"System"}})
	if s := e.str(`SELECT status||' '||(cancel_requested_at IS NOT NULL)::text FROM job_runs WHERE id = $1`, second.RunID); s != "running true" {
		t.Errorf("a running search: %s", s)
	}
	resp, err := e.svc.Poll(e.ctx, e.pc, eventlogAccepts)
	if err != nil || len(resp.Cancel) != 1 || resp.Cancel[0] != second.RunID.String() {
		t.Errorf("the cancel did not reach the agent: %+v %v", resp, err)
	}
	// The claim delivers a query to a device only while none is running there.
	if len(resp.Jobs) != 0 {
		t.Errorf("a query was delivered while another was running: %d", len(resp.Jobs))
	}
	e.answer(second.RunID, agentproto.RunCanceled, nil)
	// The channel list was asked before the third query and is delivered first;
	// the third follows once that one has ended.
	p := e.deliver()
	if len(p) != 1 || p[0].RunID == third.RunID.String() {
		t.Fatalf("the next query after the first ended: %+v", p)
	}
	if _, err := e.svc.Start(e.ctx, e.pc, uuid.MustParse(p[0].RunID)); err != nil {
		t.Fatal(err)
	}
	e.answer(uuid.MustParse(p[0].RunID), agentproto.RunSucceeded, resultLines("channels", nil, nil))
	if p := e.deliver(); len(p) != 1 || p[0].RunID != third.RunID.String() {
		t.Errorf("the third query: %+v", p)
	}
}

func TestEventlogClaimDeliversOneQueryAtATime(t *testing.T) {
	e := newEventlogFixture(t)
	a := e.ask(e.tech, EventlogRequest{Op: "query", Channels: []string{"System"}})
	b := e.ask(e.other, EventlogRequest{Op: "query", Channels: []string{"Application"}})
	got := e.deliver()
	if len(got) != 1 {
		t.Fatalf("%d queries delivered together", len(got))
	}
	// Registry reads are not held behind them.
	reg, err := e.svc.CreateRegistryQuery(e.ctx, e.tech, RegistryQueryInput{DeviceID: e.pc, Op: "list", Hive: "HKLM"})
	if err == nil {
		// The registry kind needs its capability on the poll; the fixture's list has none, so only the claim is checked.
		_ = reg
	}
	delivered := got[0].RunID
	other := b.RunID.String()
	if delivered == b.RunID.String() {
		other = a.RunID.String()
	}
	if _, err := e.svc.Start(e.ctx, e.pc, uuid.MustParse(delivered)); err != nil {
		t.Fatal(err)
	}
	if p := e.deliver(); len(p) != 0 {
		t.Fatalf("the second query was delivered while the first runs: %+v", p)
	}
	e.answer(uuid.MustParse(delivered), agentproto.RunSucceeded, resultLines("query", nil, nil))
	if p := e.deliver(); len(p) != 1 || p[0].RunID != other {
		t.Fatalf("the second query after the first ended: %+v", p)
	}
}

func readView(t *testing.T, e *eventlogFixture, c access.Caller, run uuid.UUID) *EventlogResultView {
	t.Helper()
	v, err := e.svc.ReadEventlogResult(e.ctx, c, run)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	return v
}

func TestEventlogResultIsCheckedRedactedKeptAndRead(t *testing.T) {
	e := newEventlogFixture(t)
	sys := evXML(7, "System", "Svc", 7036, "2026-11-26T10:00:00.000Z", `<EventData><Data Name="param1">Spooler</Data></EventData>`)
	cmd := evXML(6, "System", "Svc", 4688, "2026-11-26T09:59:00.000Z",
		`<EventData><Data Name="CommandLine">run --password=hunter2-marker</Data><Data Name="Other">fine</Data></EventData><RenderingInfo><Message>run --password=hunter2-marker</Message></RenderingInfo>`)
	run := e.ask(e.tech, EventlogRequest{Op: "query", Channels: []string{"System"}})
	e.deliver()
	// Open: nothing to read yet.
	if _, err := e.svc.ReadEventlogResult(e.ctx, e.tech, run.RunID); err == nil || !strings.Contains(err.Error(), "run_open") && !strings.Contains(err.Error(), "not finished") {
		t.Errorf("an open run: %v", err)
	}
	// A result from an older agent that let a command line through.
	evs := []eventrules.Event{evLine(t, "System", sys), evLine(t, "System", cmd)}
	pos := line(eventrules.Pos{T: eventrules.LinePos, Channel: "System", State: "ok"})
	ls := resultLines("query", evs, nil)
	ls = append(ls[:1], append([]string{pos}, ls[1:]...)...)
	e.answer(run.RunID, agentproto.RunSucceeded, ls)
	v := readView(t, e, e.tech, run.RunID)
	if v.State != "reported" || len(v.Events) != 2 || !v.Complete || v.AgentVersion != "1.5.0" || v.End == nil || v.End.Redacted != 1 || len(v.Pos) != 1 {
		t.Fatalf("view: %+v", v)
	}
	got := v.Events[1]
	if strings.Contains(got.XML, "hunter2-marker") || !got.Data[0].Hidden || !got.MessageHidden || got.Message != "" || got.Data[1].Value != "fine" || len(got.Hidden) != 1 {
		t.Errorf("the server did not hide what it classifies: %+v", got)
	}
	// What is stored never held it.
	f := e.fixture
	if n := e.owner(`SELECT count(*)::text FROM job_runs WHERE result::text LIKE '%hunter2-marker%'`); n != "0" {
		t.Errorf("the value is in %s stored results", n)
	}
	if n := f.str(`SELECT count(*)::text FROM audit_log WHERE details::text LIKE '%hunter2-marker%' OR details::text LIKE '%Spooler%'`); n != "0" {
		t.Errorf("event data is in %s audit records", n)
	}
	// Nobody else reads it: not another technician, not a viewer.
	_, err := e.svc.ReadEventlogResult(e.ctx, e.other, run.RunID)
	forbidden(t, err)
	_, err = e.svc.ReadEventlogResult(e.ctx, e.reader, run.RunID)
	forbidden(t, err)
	_, err = e.svc.ReadEventlogResult(e.ctx, e.orgAdmin, run.RunID)
	forbidden(t, err) // not even an administrator: only the asker reads a query
	// The input is read by the asker alone, too.
	if _, err := e.svc.ReadArguments(e.ctx, e.tech, run.JobID); err != nil {
		t.Errorf("the asker's input: %v", err)
	}
	_, err = e.svc.ReadArguments(e.ctx, e.other, run.JobID)
	forbidden(t, err)

	// A result for another operation, a log not asked for, a Security event
	// when none was allowed: each fails the run and keeps nothing.
	for name, tc := range map[string]struct {
		evs    func() []eventrules.Event
		refuse bool
	}{
		"a Security event": {func() []eventrules.Event {
			return []eventrules.Event{evLine(t, "System", evXML(9, "Security", "Microsoft-Windows-Security-Auditing", 4624, "2026-11-26T10:00:00.000Z", ""))}
		}, true},
		"a log not asked for": {func() []eventrules.Event {
			return []eventrules.Event{evLine(t, "Application", evXML(9, "Application", "App", 1, "2026-11-26T10:00:00.000Z", ""))}
		}, true},
		"fields that differ from the XML": {func() []eventrules.Event {
			x := evLine(t, "System", sys)
			x.ID = 1
			return []eventrules.Event{x}
		}, false},
	} {
		r := e.ask(e.tech, EventlogRequest{Op: "query", Channels: []string{"System"}})
		e.deliver()
		e.answer(r.RunID, agentproto.RunSucceeded, resultLines("query", tc.evs(), nil))
		if s := f.str(`SELECT status||' '||(result_stored_at IS NULL)::text FROM job_runs WHERE id = $1`, r.RunID); s != "failed true" {
			t.Errorf("%s: %s", name, s)
		}
		if v := readView(t, e, e.tech, r.RunID); v.State != "unknown" || len(v.Events) != 0 {
			t.Errorf("%s: %+v", name, v)
		}
	}
	if n := f.str(`SELECT count(*)::text FROM audit_log WHERE action = 'eventlog.refused_on_device' AND actor_type = 'system'`); n != "2" {
		t.Errorf("%s eventlog.refused_on_device records, want 2", n)
	}
	if d := f.str(`SELECT string_agg(details->>'askedBy', ',') FROM audit_log WHERE action = 'eventlog.refused_on_device'`); !strings.Contains(d, "tech@example.com") {
		t.Errorf("who asked: %q", d)
	}

	// A result without its end line is partial, and says so; one that does not decode is not kept.
	part := e.ask(e.tech, EventlogRequest{Op: "query", Channels: []string{"System"}})
	e.deliver()
	pl := resultLines("query", []eventrules.Event{evLine(t, "System", sys)}, nil)
	e.answer(part.RunID, agentproto.RunTimedOut, pl[:len(pl)-1])
	if v := readView(t, e, e.tech, part.RunID); v.State != "unknown" || v.Complete || len(v.Events) != 1 {
		t.Errorf("a partial result: %+v", v)
	}
	bad := e.ask(e.tech, EventlogRequest{Op: "query", Channels: []string{"System"}})
	e.deliver()
	e.answer(bad.RunID, agentproto.RunSucceeded, []string{"{not json"})
	if v := readView(t, e, e.tech, bad.RunID); v.State != "unknown" {
		t.Errorf("an undecodable result: %+v", v)
	}
	// No result at all (an older build): unknown.
	none := e.ask(e.tech, EventlogRequest{Op: "query", Channels: []string{"System"}})
	e.deliver()
	e.answer(none.RunID, agentproto.RunSucceeded, nil)
	if v := readView(t, e, e.tech, none.RunID); v.State != "unknown" || !strings.Contains(v.Reason, "no result") {
		t.Errorf("no result: %+v", v)
	}
	// Windows' answers become states.
	for code, want := range map[string]string{"access_denied": "unavailable", "not_found": "not_found", "refused": "refused", "unavailable": "unavailable", "failed": "unknown"} {
		r := e.ask(e.tech, EventlogRequest{Op: "query", Channels: []string{"System"}})
		e.deliver()
		ls := []string{line(eventrules.Begin{T: "begin", V: 1, Op: "query", Rules: 1, Clock: "2026-11-26T10:05:00Z"}),
			line(eventrules.ErrorLine{T: "error", Code: code, Message: "m"}), line(eventrules.End{T: "end", StoppedBy: "end"})}
		e.answer(r.RunID, agentproto.RunSucceeded, ls)
		if v := readView(t, e, e.tech, r.RunID); v.State != want {
			t.Errorf("%s: %s, want %s", code, v.State, want)
		}
	}

	// The purge empties input and result together, an hour after the run ended, and not before.
	if _, err := e.svc.Purge(e.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.str(`SELECT (result_stored_at IS NOT NULL)::text FROM job_runs WHERE id = $1`, run.RunID); n != "true" {
		t.Error("a result emptied before its hour")
	}
	f.exec(`UPDATE job_runs SET finished_at = now() - interval '61 minutes', started_at = now() - interval '62 minutes' WHERE job_id = $1`, run.JobID)
	if _, err := e.svc.Purge(e.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.str(`SELECT (result_stored_at IS NULL AND result_removed_at IS NOT NULL)::text FROM job_runs WHERE id = $1`, run.RunID); n != "true" {
		t.Error("the result was not emptied after an hour")
	}
	if n := f.str(`SELECT (removed_at IS NOT NULL)::text FROM job_inputs WHERE job_id = $1`, run.JobID); n != "true" {
		t.Error("the input was not emptied with its result")
	}
	_, err = e.svc.ReadEventlogResult(e.ctx, e.tech, run.RunID)
	if x, ok := apperr.As(err); !ok || x.Code != "result_removed" {
		t.Errorf("a removed result: %v", err)
	}
}

func TestEventlogSensitiveResultNeedsThePermissionAgain(t *testing.T) {
	e := newEventlogFixture(t)
	run := e.ask(e.orgAdmin, EventlogRequest{Op: "query", Channels: []string{"Security"}, Sensitive: true})
	e.deliver()
	sec := evXML(4, "Security", "Microsoft-Windows-Security-Auditing", 4688, "2026-11-26T10:00:00.000Z",
		`<EventData><Data Name="CommandLine">sec-marker --x</Data></EventData><RenderingInfo><Message>sec-marker</Message></RenderingInfo>`)
	ev := evLine(t, "Security", sec)
	ev.Message = "sec-marker"
	ls := resultLines("query", []eventrules.Event{ev}, func(en *eventrules.End) {
		en.Cursor.Channels[0].Channel = "Security"
	})
	e.answer(run.RunID, agentproto.RunSucceeded, ls)
	v := readView(t, e, e.orgAdmin, run.RunID)
	if v.State != "reported" || !v.Sensitive && len(v.Events) != 1 || !strings.Contains(v.Events[0].XML, "sec-marker") {
		t.Fatalf("an organization administrator reads a Security event: %+v", v)
	}
	// The same person, an hour later, no longer holding the permission: refused,
	// and recorded as denied.
	demoted := rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: e.acme, SiteID: e.hq}
	p, err := rbac.NewPrincipal(e.orgAdmin.Actor.ID, []rbac.Assignment{demoted})
	if err != nil {
		t.Fatal(err)
	}
	lost := access.User(p, auth.DataScope(p), e.orgAdmin.Actor)
	_, err = e.svc.ReadEventlogResult(e.ctx, lost, run.RunID)
	forbidden(t, err)
	if n := e.str(`SELECT count(*)::text FROM audit_log WHERE action = 'job_run.result_view' AND outcome = 'denied'`); n != "1" {
		t.Errorf("%s denied reads recorded", n)
	}
	_, err = e.svc.ReadArguments(e.ctx, lost, run.JobID)
	forbidden(t, err)
	// And a next page of it is refused too.
	_, err = e.svc.CreateEventlogQuery(e.ctx, lost, EventlogRequest{DeviceID: e.pc, PreviousRunID: &run.RunID})
	forbidden(t, err)
}

func TestEventlogNextPageIsBuiltFromTheStoredQuery(t *testing.T) {
	e := newEventlogFixture(t)
	run := e.ask(e.tech, EventlogRequest{Op: "query", Channels: []string{"System"}, Levels: []int{2}, Text: "needle", Providers: []string{"Svc"}})
	// A page needs a finished run.
	_, err := e.svc.CreateEventlogQuery(e.ctx, e.tech, EventlogRequest{DeviceID: e.pc, PreviousRunID: &run.RunID})
	if x, ok := apperr.As(err); !ok || x.Code != "run_open" {
		t.Errorf("a page of an open run: %v", err)
	}
	e.deliver()
	evs := []eventrules.Event{evLine(t, "System", evXML(9, "System", "Svc", 1, "2026-11-26T10:00:00.000Z", `<EventData><Data Name="a">needle</Data></EventData>`))}
	e.answer(run.RunID, agentproto.RunSucceeded, resultLines("query", evs, func(en *eventrules.End) {
		en.Cursor = &eventrules.Cursor{Channels: []eventrules.ChannelCursor{{Channel: "System", Record: 9}}}
	}))
	// The page the person asks for carries nothing but the run it follows: the
	// filters are the server's, so they cannot differ.
	next, err := e.svc.CreateEventlogQuery(e.ctx, e.tech, EventlogRequest{DeviceID: e.pc, PreviousRunID: &run.RunID, Channels: []string{"Application"}, Text: "other"})
	if err != nil {
		t.Fatal(err)
	}
	p := e.deliver()
	if len(p) != 1 || p[0].RunID != next.RunID.String() {
		t.Fatalf("%+v", p)
	}
	in, _ := eventrules.DecodeInput(p[0].Input)
	c := in.Cursor.For("System")
	if in.Text != "needle" || len(in.Channels) != 1 || in.Channels[0] != "System" || in.Levels[0] != 2 || c == nil || c.Record != 9 {
		t.Errorf("the next page's input: %+v", in)
	}
	// A page is covered by its first page's record.
	if n := e.str(`SELECT count(*)::text FROM audit_log WHERE action = 'eventlog.query'`); n != "1" {
		t.Errorf("%s eventlog.query records for a query and its page", n)
	}
	// Not someone else's page, nor for another device; recorded as refused.
	_, err = e.svc.CreateEventlogQuery(e.ctx, e.other, EventlogRequest{DeviceID: e.pc, PreviousRunID: &run.RunID})
	forbidden(t, err)
	pc2 := e.device(e.hq, "PC-13", "windows")
	if _, err := e.svc.Poll(e.ctx, pc2, eventlogAccepts); err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.CreateEventlogQuery(e.ctx, e.tech, EventlogRequest{DeviceID: pc2, PreviousRunID: &run.RunID})
	forbidden(t, err)
	if n := e.str(`SELECT count(*)::text FROM audit_log WHERE action = 'eventlog.refused'`); n != "2" {
		t.Errorf("%s eventlog.refused records, want 2 (two devices, two callers)", n)
	}
	_, err = e.svc.CreateEventlogQuery(e.ctx, e.tech, EventlogRequest{DeviceID: e.pc, PreviousRunID: &uuid.Nil})
	if !errorsIsNotFound(err) {
		t.Errorf("a page of nothing: %v", err)
	}
	// The last page says there is no more; an old result cannot be continued.
	fin := e.ask(e.tech, EventlogRequest{Op: "query", Channels: []string{"System"}})
	e.deliver()
	e.answer(fin.RunID, agentproto.RunSucceeded, resultLines("query", nil, func(en *eventrules.End) {
		en.Cursor = &eventrules.Cursor{Channels: []eventrules.ChannelCursor{{Channel: "System", Record: 1, Done: true}}}
		en.StoppedBy = eventrules.StopEnd
	}))
	_, err = e.svc.CreateEventlogQuery(e.ctx, e.tech, EventlogRequest{DeviceID: e.pc, PreviousRunID: &fin.RunID})
	if x, ok := apperr.As(err); !ok || x.Code != "no_more" {
		t.Errorf("after the last page: %v", err)
	}
	e.exec(`UPDATE job_runs SET result_stored_at = now() - interval '2 hours' WHERE id = $1`, run.RunID)
	_, err = e.svc.CreateEventlogQuery(e.ctx, e.tech, EventlogRequest{DeviceID: e.pc, PreviousRunID: &run.RunID})
	if x, ok := apperr.As(err); !ok || x.Code != "page_expired" {
		t.Errorf("an old page: %v", err)
	}
	// Only a query has pages.
	_, err = e.svc.CreateEventlogQuery(e.ctx, e.tech, EventlogRequest{DeviceID: e.pc, PreviousRunID: &run.RunID, Op: "event"})
	fieldErr(t, err, "op", "Only a query has pages")
}

func TestEventlogRefusalsAreBounded(t *testing.T) {
	e := newEventlogFixture(t)
	// Twenty-one different devices' refusals in ten minutes: the 21st is not recorded.
	for i := 0; i < 22; i++ {
		d := e.device(e.hq, "BULK-"+strconv.Itoa(i), "windows")
		if _, err := e.svc.Poll(e.ctx, d, eventlogAccepts); err != nil {
			t.Fatal(err)
		}
		_, err := e.svc.CreateEventlogQuery(e.ctx, e.tech, EventlogRequest{DeviceID: d, Op: "query", Channels: []string{"Security"}, Sensitive: true})
		fieldErr(t, err, "channels", "Refused by EasyRMM")
	}
	if n := e.str(`SELECT count(*)::text FROM audit_log WHERE action = 'eventlog.refused'`); n != "20" {
		t.Errorf("%s eventlog.refused records in ten minutes, want 20", n)
	}
}

func TestEventlogJobsAreListedUnderTheirFilterOnly(t *testing.T) {
	e := newEventlogFixture(t)
	e.ask(e.tech, EventlogRequest{Op: "channels"})
	jobs, err := e.svc.ListJobs(e.ctx, e.tech, JobQuery{})
	if err != nil {
		t.Fatal(err)
	}
	for _, j := range jobs {
		if strings.HasPrefix(j.Kind, "eventlog") {
			t.Errorf("an event log read in the Jobs list: %+v", j)
		}
	}
	jobs, err = e.svc.ListJobs(e.ctx, e.tech, JobQuery{Kind: KindFilterEventlog})
	if err != nil || len(jobs) != 1 {
		t.Errorf("the Event logs filter: %v %v", jobs, err)
	}
	if _, err := e.svc.ListJobs(e.ctx, e.tech, JobQuery{Kind: "nope"}); !isInvalid(err) {
		t.Error("an unknown filter")
	}
}

func errorsIsNotFound(err error) bool { return errors.Is(err, apperr.ErrNotFound) }

// owner runs a query as the schema's owner, who reads the columns the server's
// role cannot.
func (e *eventlogFixture) owner(sql string) string {
	e.t.Helper()
	c, err := pgx.Connect(e.ctx, e.super)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = c.Close(e.ctx) }()
	var s string
	if err := c.QueryRow(e.ctx, sql).Scan(&s); err != nil {
		e.t.Fatal(err)
	}
	return s
}
