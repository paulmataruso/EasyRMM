package eventrules

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"
	"time"
)

const procXML = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/><EventID>4688</EventID><Version>2</Version><Level>0</Level><Task>13312</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2026-11-26T10:00:00.123456700Z"/><EventRecordID>42</EventRecordID><Correlation/><Execution ProcessID="4" ThreadID="8"/><Channel>Security</Channel><Computer>PC-12.example.test</Computer><Security/></System><EventData><Data Name="NewProcessName">C:\x\a.exe</Data><Data Name="CommandLine">a.exe --token=s3cret &amp; more</Data></EventData><RenderingInfo Culture="en-US"><Message>A new process has been created. a.exe --token=s3cret</Message></RenderingInfo></Event>`

func sysXML(rec int64, channel, provider string, id int, ts string, data string) string {
	return `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="` + provider + `"/><EventID Qualifiers="16384">` +
		itoa(id) + `</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime="` + ts +
		`"/><EventRecordID>` + itoa(int(rec)) + `</EventRecordID><Execution ProcessID="1" ThreadID="2"/><Channel>` + channel +
		`</Channel><Computer>PC-12</Computer><Security UserID="S-1-5-18"/></System>` + data + `</Event>`
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

// eventOf builds the builtin's line for an XML, the way a faithful builtin does.
func eventOf(t *testing.T, log, x string) Event {
	t.Helper()
	p, err := ParseXML(x)
	if err != nil {
		t.Fatal(err)
	}
	return Event{T: LineEvent, Log: log, Channel: p.Channel, Record: p.Record, Provider: p.Provider, ProviderGUID: p.ProviderGUID,
		ID: p.ID, Qualifiers: p.Qualifiers, Version: p.Version, Level: p.Level, Task: p.Task, Opcode: p.Opcode,
		Keywords: FormatKeywords(p.Keywords), Time: p.Time, Computer: p.Computer, UserSID: p.UserSID, PID: p.PID, TID: p.TID,
		Data: p.Data, Message: p.Message, XML: x}
}

func TestParseXMLReadsSystemAndData(t *testing.T) {
	p, err := ParseXML(procXML)
	if err != nil {
		t.Fatal(err)
	}
	if p.Record != 42 || p.ID != 4688 || p.Channel != "Security" || p.Provider != "Microsoft-Windows-Security-Auditing" ||
		p.Keywords != 0x8020000000000000 || p.PID != 4 || p.TID != 8 || p.Computer != "PC-12.example.test" {
		t.Fatalf("system: %+v", p)
	}
	if len(p.Data) != 2 || p.Data[1].Name != "CommandLine" || p.Data[1].Value != "a.exe --token=s3cret & more" {
		t.Fatalf("data: %+v", p.Data)
	}
	if !p.HasMessage || !strings.HasPrefix(p.Message, "A new process") {
		t.Fatalf("message: %q", p.Message)
	}
	if _, err := ParseXML("<Event><System>"); err == nil {
		t.Fatal("a cut XML parses")
	}
	if _, err := ParseXML("not xml"); err == nil {
		t.Fatal("text parses")
	}
}

func TestParseXMLUserDataAndUnnamed(t *testing.T) {
	x := sysXML(5, "Microsoft-Windows-WMI-Activity/Operational", "Microsoft-Windows-WMI-Activity", 5861, "2026-11-26T10:00:00.000Z",
		`<UserData><Operation_New><Namespace>root</Namespace><CONSUMER>evil</CONSUMER></Operation_New></UserData>`)
	p, err := ParseXML(x)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Data) != 2 || p.Data[1].Path != "Operation_New/CONSUMER" || p.Data[1].Name != "CONSUMER" {
		t.Fatalf("userdata: %+v", p.Data)
	}
	if got := p.Sensitive(p.Channel); len(got) != 1 || got[0] != 1 {
		t.Fatalf("sensitive: %v", got)
	}
	cl := sysXML(6, "Windows PowerShell", "PowerShell", 400, "2026-11-26T10:00:00.000Z", `<EventData><Data>Available</Data><Data>HostApplication=powershell -c x</Data></EventData>`)
	p, _ = ParseXML(cl)
	if len(p.Sensitive("Windows PowerShell")) != 2 || len(p.Sensitive("Application")) != 0 {
		t.Fatal("classic PowerShell log values are all sensitive, and only there")
	}
}

func TestSensitiveFieldClassification(t *testing.T) {
	for _, c := range []struct {
		ch, prov, name string
		want           bool
	}{
		{"Security", "x", "CommandLine", true},
		{"Application", "x", "commandline", true},
		{"Application", "x", "ScriptBlockText", true},
		{"Application", "x", "Payload", true},
		{"Application", "x", "NewProcessName", false},
		{"Microsoft-Windows-Shell-Core/Operational", "Microsoft-Windows-Shell-Core", "Command", true},
		{"System", "Service Control Manager", "Command", false},
		{"Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", "Details", true},
		{"System", "Other", "Details", false},
		{"Microsoft-Windows-Bits-Client/Operational", "Microsoft-Windows-Bits-Client", "url", true},
		{"System", "Other", "url", false},
	} {
		if got := SensitiveField(c.ch, c.prov, c.name); got != c.want {
			t.Errorf("%+v: %v", c, got)
		}
	}
}

func TestSecurityChannelsCompareIgnoringCase(t *testing.T) {
	for _, n := range []string{"Security", "SECURITY", "security", "Archive-Security-2026-01-01-00-00-00-000", "archive-SECURITY-x"} {
		if !IsSecurity(n) {
			t.Errorf("%q is the Security log", n)
		}
	}
	for _, n := range []string{"System", "Security-Mitigations/Kernel Mode", "Microsoft-Windows-Security-Auditing"} {
		if IsSecurity(n) {
			t.Errorf("%q is not", n)
		}
	}
	if got := DedupeChannels([]string{"System", "SYSTEM", "Application"}); len(got) != 2 || got[0] != "System" {
		t.Fatalf("dedupe: %v", got)
	}
	if ValidChannel("a|b") == nil || ValidChannel("") == nil || ValidChannel(" x") == nil || ValidChannel("Microsoft-Windows-X/Operational") != nil {
		t.Fatal("channel names")
	}
}

func TestRedactReplacesOnlyTheValuesAndTheMessage(t *testing.T) {
	p, _ := ParseXML(procXML)
	out := p.Redact(procXML, p.Sensitive("Application"), true)
	if strings.Contains(out, "s3cret") || strings.Count(out, "[hidden: needs") != 2 {
		t.Fatalf("not redacted: %s", out)
	}
	if !strings.Contains(out, `C:\x\a.exe`) || !strings.HasSuffix(out, "</Event>") {
		t.Fatalf("the rest changed: %s", out)
	}
	if _, err := ParseXML(out); err != nil {
		t.Fatalf("redacted XML does not parse: %v", err)
	}
}

func TestCutXMLMatchesCutText(t *testing.T) {
	x := sysXML(1, "Application", "X", 1, "2026-11-26T10:00:00Z", `<EventData><Data Name="a">`+strings.Repeat("é&amp;", 40)+`</Data></EventData>`)
	p, _ := ParseXML(x)
	out := p.CutXML(x, 10, 100)
	q, err := ParseXML(out)
	if err != nil {
		t.Fatal(err)
	}
	want, ok := CutText(p.Data[0].Value, 10)
	if !ok || q.Data[0].Value != want || !strings.HasSuffix(want, CutMarker) {
		t.Fatalf("%q vs %q", q.Data[0].Value, want)
	}
	if got := SystemOnly(x); !strings.Contains(got, "<System>") || strings.Contains(got, "EventData") || !strings.HasSuffix(got, "</Event>") {
		t.Fatalf("system only: %s", got)
	}
}

func TestBuildQuery(t *testing.T) {
	in := Input{V: 1, Op: OpQuery, Channels: []string{"System"}, Levels: []int{2, 4}, IDs: []IDRange{{From: 41}, {From: 100, To: 200}},
		ExcludeIDs: []IDRange{{From: 7036}}, Providers: []string{"Service Control Manager"}, Keywords: "9232379236109516800",
		Time: &TimeFilter{Last: "24h"}}
	q, err := BuildQuery(in, "System", QueryOptions{After: 500})
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{`<Query Id="0" Path="System">`, `Level=2 or Level=4 or Level=0`, `EventID=41`, `EventID&gt;=100 and EventID&lt;=200`,
		`Provider[@Name='Service Control Manager']`, `band(Keywords,9232379236109516800)`, `timediff(@SystemTime) &lt;= 86400000`,
		`EventRecordID&lt;500`, `<Suppress Path="System">`, `EventID=7036`} {
		if !strings.Contains(q, w) {
			t.Errorf("missing %q in %s", w, q)
		}
	}
	// Ascending channels continue upward; one record asks for it by number.
	q, _ = BuildQuery(Input{V: 1, Op: OpQuery}, "Microsoft-Windows-X/Analytic", QueryOptions{After: 3, Ascending: true})
	if !strings.Contains(q, "EventRecordID&gt;3") {
		t.Error(q)
	}
	q, _ = BuildQuery(Input{V: 1, Op: OpEvent}, "System", QueryOptions{Record: 9})
	if !strings.Contains(q, "EventRecordID=9") {
		t.Error(q)
	}
	// A value cannot become XPath or XML.
	evil := `x' or 1=1 or Provider[@Name='`
	q, err = BuildQuery(Input{V: 1, Op: OpQuery, Providers: []string{evil}}, "System", QueryOptions{})
	if err != nil || !strings.Contains(q, `Provider[@Name="x' or 1=1`) {
		t.Fatalf("%v %s", err, q)
	}
	// The query is well-formed XML whose Select text is the XPath as built:
	// the value stays inside its one string, whatever it holds.
	var doc struct {
		Select string `xml:"Query>Select"`
	}
	if err := xml.Unmarshal([]byte(q), &doc); err != nil || !strings.Contains(doc.Select, `Provider[@Name="x' or 1=1 or Provider[@Name='"]`) {
		t.Fatalf("%v %q", err, doc.Select)
	}
	if q, err = BuildQuery(Input{V: 1, Op: OpQuery, Providers: []string{"a</Select><Select>&<>"}}, "System", QueryOptions{}); err != nil || strings.Count(q, "<Select") != 1 {
		t.Fatalf("%v %s", err, q)
	}
	if _, err = BuildQuery(Input{V: 1, Op: OpQuery, Providers: []string{`a'b"c`}}, "System", QueryOptions{}); err == nil {
		t.Fatal("a value with both quotes is refused")
	}
	if _, err = BuildQuery(in, "Sys<tem", QueryOptions{}); err == nil {
		t.Fatal("a refused channel name")
	}
	q, _ = BuildQuery(Input{V: 1, Op: OpQuery, Time: &TimeFilter{From: "2026-11-01T00:00:00Z", To: "2026-11-02T00:00:00Z"}}, "System", QueryOptions{})
	if !strings.Contains(q, "2026-11-01T00:00:00.000Z") || !strings.Contains(q, "2026-11-02T00:00:00.000Z") {
		t.Error(q)
	}
}

func TestInputCheck(t *testing.T) {
	ok := Input{V: 1, Op: OpQuery, Rules: 1, Channels: []string{"System"}}
	if err := ok.Check(); err != nil {
		t.Fatal(err)
	}
	bad := map[string]Input{
		"version":     {V: 2, Op: OpQuery, Channels: []string{"System"}},
		"op":          {V: 1, Op: "clear"},
		"no channel":  {V: 1, Op: OpQuery},
		"11 channels": {V: 1, Op: OpQuery, Channels: []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"}},
		"twice":       {V: 1, Op: OpQuery, Channels: []string{"System", "system"}},
		"level":       {V: 1, Op: OpQuery, Channels: []string{"System"}, Levels: []int{9}},
		"task":        {V: 1, Op: OpQuery, Channels: []string{"System"}, Tasks: []int{1}},
		"range":       {V: 1, Op: OpQuery, Channels: []string{"System"}, IDs: []IDRange{{From: 9, To: 3}}},
		"mask":        {V: 1, Op: OpQuery, Channels: []string{"System"}, Keywords: "0x10"},
		"time":        {V: 1, Op: OpQuery, Channels: []string{"System"}, Time: &TimeFilter{Last: "2h"}},
		"both":        {V: 1, Op: OpQuery, Channels: []string{"System"}, Time: &TimeFilter{Last: "1h", From: "2026-01-01T00:00:00Z"}},
		"text":        {V: 1, Op: OpQuery, Channels: []string{"System"}, Text: strings.Repeat("x", 257)},
		"event":       {V: 1, Op: OpEvent, Channels: []string{"System"}},
		"filters":     {V: 1, Op: OpChannels, Text: "x"},
		"provider":    {V: 1, Op: OpProvider},
	}
	for n, in := range bad {
		if err := in.Check(); err == nil {
			t.Errorf("%s passes", n)
		}
	}
	if (Input{V: 1, Op: OpQuery, Channels: []string{"security"}}).Refusal() == "" {
		t.Error("the Security log is refused without sensitive data")
	}
	if (Input{V: 1, Op: OpQuery, Channels: []string{"security"}, Sensitive: true}).Refusal() != "" {
		t.Error("and allowed with it")
	}
	if _, err := DecodeInput([]byte(`{"v":1,"op":"channels","extra":1}`)); err == nil {
		t.Error("unknown fields are refused")
	}
	if _, err := DecodeInput([]byte(`{"v":1,"op":"channels"} {}`)); err == nil {
		t.Error("two documents are refused")
	}
}

func lines(t *testing.T, vs ...any) [][]byte {
	t.Helper()
	var out [][]byte
	for _, v := range vs {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	}
	return out
}

func resultOf(t *testing.T, op string, evs ...Event) *Result {
	t.Helper()
	vs := []any{Begin{T: LineBegin, V: 1, Op: op, Rules: 1, Clock: "2026-11-26T10:05:00Z"}}
	for _, e := range evs {
		vs = append(vs, e)
	}
	vs = append(vs, End{T: LineEnd, Complete: true, Returned: len(evs), StoppedBy: StopEnd})
	r, err := ParseLines(lines(t, vs...))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestParseLinesIsStrict(t *testing.T) {
	good := lines(t, Begin{T: LineBegin, V: 1, Op: OpQuery}, End{T: LineEnd})
	if _, err := ParseLines(good); err != nil {
		t.Fatal(err)
	}
	for n, ls := range map[string][][]byte{
		"empty":        nil,
		"no begin":     {[]byte(`{"t":"end"}`)},
		"after end":    append(append([][]byte{}, good...), []byte(`{"t":"error","code":"x","message":"y"}`)),
		"unknown line": {good[0], []byte(`{"t":"bogus"}`)},
		"unknown key":  {good[0], []byte(`{"t":"end","surprise":1}`)},
		"nul":          {good[0], []byte(`{"t":"error","code":"x","message":"a\u0000b"}`)},
		"not json":     {good[0], []byte(`{`)},
	} {
		if _, err := ParseLines(ls); err == nil {
			t.Errorf("%s decodes", n)
		}
	}
	// A cut result has no end.
	r, err := ParseLines(good[:1])
	if err != nil || r.End != nil {
		t.Fatalf("cut: %v %v", err, r)
	}
	ls, err := resultOf(t, OpQuery).Lines()
	if err != nil || len(ls) != 2 {
		t.Fatalf("%v %d", err, len(ls))
	}
}

var now = time.Date(2026, 11, 26, 10, 5, 0, 0, time.UTC)

func TestCheckResultRefusesWhatWasNotAsked(t *testing.T) {
	in := Input{V: 1, Op: OpQuery, Rules: 1, Channels: []string{"Application"}}
	app := sysXML(7, "Application", "App", 1000, "2026-11-26T09:59:00Z", `<EventData><Data Name="x">y</Data></EventData>`)
	res := resultOf(t, OpQuery, eventOf(t, "Application", app))
	if v, err := CheckResult(in, res, now); err != nil || len(v.Violations) != 0 || len(res.Events) != 1 {
		t.Fatalf("a faithful result: %v %+v", err, v)
	}
	// A Security event in a result for an input without sensitive data.
	sec := resultOf(t, OpQuery, eventOf(t, "Application", procXML))
	v, err := CheckResult(in, sec, now)
	if err != nil || len(v.Violations) != 1 || len(sec.Events) != 0 {
		t.Fatalf("security: %v %+v", err, v)
	}
	// A log the input did not name.
	other := resultOf(t, OpQuery, eventOf(t, "System", app))
	if v, _ = CheckResult(in, other, now); len(v.Violations) != 1 {
		t.Fatalf("log: %+v", v)
	}
	// A time outside a custom range.
	in2 := in
	in2.Time = &TimeFilter{From: "2026-11-25T00:00:00Z", To: "2026-11-25T23:00:00Z"}
	late := resultOf(t, OpQuery, eventOf(t, "Application", app))
	if v, _ = CheckResult(in2, late, now); len(v.Violations) != 1 {
		t.Fatalf("time: %+v", v)
	}
	// An event the previous page returned.
	in3 := in
	in3.Cursor = &Cursor{Channels: []ChannelCursor{{Channel: "Application", Record: 7}}}
	rep := resultOf(t, OpQuery, eventOf(t, "Application", app))
	if v, _ = CheckResult(in3, rep, now); len(v.Violations) != 1 {
		t.Fatalf("cursor: %+v", v)
	}
	// With sensitive data allowed a Security event stands.
	in4 := Input{V: 1, Op: OpQuery, Channels: []string{"Security"}, Sensitive: true}
	ok := resultOf(t, OpQuery, eventOf(t, "Security", procXML))
	if v, err = CheckResult(in4, ok, now); err != nil || len(v.Violations) != 0 || len(ok.Events) != 1 || strings.Contains(ok.Events[0].XML, "hidden") {
		t.Fatalf("sensitive: %v %+v", err, v)
	}
}

func TestCheckResultComparesFieldsWithTheXML(t *testing.T) {
	in := Input{V: 1, Op: OpQuery, Channels: []string{"Application"}}
	app := sysXML(7, "Application", "App", 1000, "2026-11-26T09:59:00Z", `<EventData><Data Name="x">y</Data></EventData>`)
	for n, mutate := range map[string]func(*Event){
		"record":   func(e *Event) { e.Record = 8 },
		"id":       func(e *Event) { e.ID = 1 },
		"provider": func(e *Event) { e.Provider = "Other" },
		"time":     func(e *Event) { e.Time = "2026-11-26T09:00:00Z" },
		"channel":  func(e *Event) { e.Channel = "System" },
		"value":    func(e *Event) { e.Data[0].Value = "z" },
		"name":     func(e *Event) { e.Data[0].Name = "q" },
		"extra":    func(e *Event) { e.Data = append(e.Data, Datum{Name: "n", Value: "v"}) },
		"keywords": func(e *Event) { e.Keywords = "0x0000000000000001" },
		"hidden":   func(e *Event) { e.Data[0] = Datum{Name: "x", Hidden: true} },
		"xml":      func(e *Event) { e.XML = "<Event>" },
	} {
		e := eventOf(t, "Application", app)
		mutate(&e)
		if _, err := CheckResult(in, resultOf(t, OpQuery, e), now); err == nil {
			t.Errorf("%s: a result that does not match its XML is kept", n)
		}
	}
	if _, err := CheckResult(in, resultOf(t, OpEvent), now); err == nil {
		t.Error("another operation")
	}
}

func TestCheckResultHidesWhatAnOlderAgentLetThrough(t *testing.T) {
	in := Input{V: 1, Op: OpQuery, Channels: []string{"Application"}}
	cmd := sysXML(9, "Application", "App", 4688, "2026-11-26T09:59:00Z", `<EventData><Data Name="CommandLine">run --password=hunter2</Data><Data Name="Other">fine</Data></EventData><RenderingInfo><Message>run --password=hunter2</Message></RenderingInfo>`)
	res := resultOf(t, OpQuery, eventOf(t, "Application", cmd))
	v, err := CheckResult(in, res, now)
	if err != nil || v.Redacted != 1 || v.Dropped != 0 || len(res.Events) != 1 {
		t.Fatalf("%v %+v", err, v)
	}
	e := res.Events[0]
	if strings.Contains(e.XML, "hunter2") || !e.Data[0].Hidden || e.Data[0].Value != "" || e.Data[1].Value != "fine" || !e.MessageHidden || e.Message != "" {
		t.Fatalf("not hidden: %+v", e)
	}
	if len(e.Hidden) != 1 || e.Hidden[0] != "CommandLine" {
		t.Fatalf("hidden names: %v", e.Hidden)
	}
	if res.End.Redacted != 1 {
		t.Fatal("the end line counts it")
	}
	// On a text query the event is dropped, since the text may have matched it.
	inT := in
	inT.Text = "hunter2"
	res = resultOf(t, OpQuery, eventOf(t, "Application", cmd))
	v, err = CheckResult(inT, res, now)
	if err != nil || v.Dropped != 1 || len(res.Events) != 0 || res.End.Dropped != 1 {
		t.Fatalf("text: %v %+v", err, v)
	}
	// With the permission nothing is hidden.
	inS := in
	inS.Sensitive = true
	res = resultOf(t, OpQuery, eventOf(t, "Application", cmd))
	if v, _ = CheckResult(inS, res, now); v.Redacted != 0 || !strings.Contains(res.Events[0].XML, "hunter2") {
		t.Fatal("sensitive allowed")
	}
	// A builtin that already hid it is not counted.
	p, _ := ParseXML(cmd)
	e2 := eventOf(t, "Application", cmd)
	e2.XML = p.Redact(cmd, p.Sensitive("Application"), true)
	e2.Data[0] = Datum{Name: "CommandLine", Hidden: true}
	e2.Message, e2.MessageHidden, e2.Hidden = "", true, []string{"CommandLine"}
	res = resultOf(t, OpQuery, e2)
	if v, err = CheckResult(in, res, now); err != nil || v.Redacted != 0 {
		t.Fatalf("already hidden: %v %+v", err, v)
	}
}

func TestCheckResultOtherOperations(t *testing.T) {
	ch := Input{V: 1, Op: OpChannels}
	r := resultOf(t, OpChannels)
	r.Channels = []ChannelInfo{{T: LineChannel, Name: "System"}}
	if _, err := CheckResult(ch, r, now); err != nil {
		t.Fatal(err)
	}
	r.Events = []Event{{}}
	if _, err := CheckResult(ch, r, now); err == nil {
		t.Fatal("events in a channel list")
	}
	pr := resultOf(t, OpProvider)
	pr.Provider = &ProviderLine{T: LineProvider, Name: "Other"}
	if _, err := CheckResult(Input{V: 1, Op: OpProvider, Provider: "Svc"}, pr, now); err == nil {
		t.Fatal("another provider")
	}
	ev := Input{V: 1, Op: OpEvent, Channels: []string{"Application"}, Record: 7}
	app := sysXML(8, "Application", "App", 1, "2026-11-26T09:59:00Z", ``)
	er := resultOf(t, OpEvent, eventOf(t, "Application", app))
	if v, _ := CheckResult(ev, er, now); len(v.Violations) != 1 {
		t.Fatalf("another record: %+v", v)
	}
}

func TestTooLargeEventHoldsNoData(t *testing.T) {
	in := Input{V: 1, Op: OpQuery, Channels: []string{"Application"}}
	full := sysXML(7, "Application", "App", 1000, "2026-11-26T09:59:00Z", `<EventData><Data Name="x">y</Data></EventData>`)
	e := eventOf(t, "Application", SystemOnly(full))
	e.TooLarge = true
	if _, err := CheckResult(in, resultOf(t, OpQuery, e), now); err != nil {
		t.Fatalf("an event cut to System: %v", err)
	}
	e.Data = []Datum{{Name: "x", Value: "y"}}
	if _, err := CheckResult(in, resultOf(t, OpQuery, e), now); err == nil {
		t.Fatal("a cut event with data")
	}
}

func TestFoldAndContains(t *testing.T) {
	if !EqualFold("Straße", "STRASSE") && !EqualFold("ǅ", "ǆ") {
		t.Fatal("fold")
	}
	if !ContainsFold("Hello World", "O WOR") || ContainsFold("abc", "abd") {
		t.Fatal("contains")
	}
}
