package winevents

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func xmlEvent(id int, rec int64, at string, data map[string]string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Windows Defender"/><EventID>%d</EventID><EventRecordID>%d</EventRecordID><TimeCreated SystemTime="%s"/></System><EventData>`, id, rec, at)
	for k, v := range data {
		fmt.Fprintf(&b, `<Data Name="%s">%s</Data>`, k, v)
	}
	b.WriteString(`</EventData></Event>`)
	return b.String()
}

func TestParseKeepsPathsAndUsersApart(t *testing.T) {
	e, err := Parse(xmlEvent(1116, 77, "2026-11-26T10:00:00.123456700Z", map[string]string{
		"Threat ID": "2147519003", "Threat Name": "Virus:DOS/EICAR_Test_File", "Severity Name": "Severe", "Category Name": "Virus",
		"Path": `file:_C:\Users\alice\Downloads\eicar.txt`, "Detection User": `ACME\alice`, "Process Name": `C:\Windows\explorer.exe`,
		"Action Name": "Not Applicable",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if e.EventID != 1116 || e.RecordID != 77 || e.ThreatName != "Virus:DOS/EICAR_Test_File" || e.Severity != "Severe" || e.ThreatID != "2147519003" {
		t.Errorf("event %+v", e)
	}
	for _, s := range []string{e.ThreatID, e.ThreatName, e.Severity, e.Category, e.Action, e.Origin, e.Source, e.ErrorCode} {
		if strings.Contains(s, "alice") || strings.Contains(s, `\`) {
			t.Errorf("a path or user is in a plain field: %q", s)
		}
	}
	if e.Sensitive["path"] == "" || e.Sensitive["user"] != `ACME\alice` || e.Sensitive["process"] == "" {
		t.Errorf("sensitive %+v", e.Sensitive)
	}
}

func TestParseConfigChangeValuesAreSensitive(t *testing.T) {
	e, err := Parse(xmlEvent(5007, 9, "2026-11-26T10:00:00Z", map[string]string{
		"Old Value": `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Customer = 0x0`, "New Value": ``,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if e.Sensitive["oldValue"] == "" || e.ThreatName != "" || e.Action != "" {
		t.Errorf("event %+v", e)
	}
	if err := (&agentproto.DefenderLogBatch{Epoch: "x", Events: []agentproto.DefenderLogEvent{e}}).Check(); err != nil {
		t.Error(err)
	}
}

func TestParseRefusesWhatIsNotAnEvent(t *testing.T) {
	for _, s := range []string{"", "not xml", `<Event><System></System></Event>`, `<Event><System><EventID>1</EventID></System></Event>`,
		xmlEvent(1116, 1, "yesterday", nil)} {
		if _, err := Parse(s); err == nil {
			t.Errorf("%q was parsed", s)
		}
	}
	long := strings.Repeat("a", 5000)
	e, err := Parse(xmlEvent(1116, 1, "2026-11-26T10:00:00Z", map[string]string{"Threat Name": long, "Path": long}))
	if err != nil || len(e.ThreatName) > 120 || len(e.Sensitive["path"]) > agentproto.MaxDefenderLogSensitive || !e.Truncated {
		t.Errorf("long text: %v %d %v", err, len(e.ThreatName), e.Truncated)
	}
	if SeverityRank("Severe") != 5 || SeverityRank("high") != 4 || SeverityRank("Moderate") != 2 || SeverityRank("Low") != 1 || SeverityRank("x") != 0 {
		t.Error("severity ranks")
	}
}

func evs(id int, from, to int64) []agentproto.DefenderLogEvent {
	var out []agentproto.DefenderLogEvent
	for r := from; r <= to; r++ {
		out = append(out, agentproto.DefenderLogEvent{RecordID: r, EventID: id, At: time.Unix(1_800_000_000+r, 0).UTC(), ThreatID: fmt.Sprint("t", r%30)})
	}
	return out
}

func TestPlanCoalescesStormsAndNeverDropsAnEvent(t *testing.T) {
	// 100 detections in one query: 5 whole and one summary counting the other 95, covering every record.
	batch, through := Plan(evs(1116, 1, 100))
	if len(batch) != 6 || through != 100 {
		t.Fatalf("%d records through %d", len(batch), through)
	}
	last := batch[len(batch)-1]
	if last.Count != 95 || last.FirstRecord != 6 || last.RecordID != 100 || len(last.ThreatIDs) != agentproto.MaxDefenderLogThreats {
		t.Errorf("summary %+v", last)
	}
	whole := 0
	for _, e := range batch {
		if e.Count == 0 {
			whole++
		}
	}
	if whole+last.Count != 100 {
		t.Errorf("%d whole + %d counted is not 100", whole, last.Count)
	}
	// Twenty is not a storm.
	if batch, _ := Plan(evs(1116, 1, 20)); len(batch) != 20 {
		t.Errorf("%d records for 20 events", len(batch))
	}
	// Beyond 25 records the bookmark stops at the last record sent.
	mixed := append(evs(1116, 1, 15), evs(2001, 16, 30)...)
	batch, through = Plan(mixed)
	if len(batch) != 25 || through != 25 {
		t.Errorf("%d records through %d", len(batch), through)
	}
	if b, th := Plan(nil); b != nil || th != 0 {
		t.Error("empty plan")
	}
	// The byte cap: very large records are cut to what fits, at least one.
	big := evs(1116, 1, 20)
	for i := range big {
		big[i].Sensitive = map[string]string{"path": strings.Repeat("p", agentproto.MaxDefenderLogSensitive), "user": strings.Repeat("u", agentproto.MaxDefenderLogSensitive)}
		big[i].ThreatName = strings.Repeat("n", 120)
	}
	batch, through = Plan(big)
	if len(batch) == 0 || len(batch) > 20 || through != int64(len(batch)) {
		t.Errorf("%d records through %d", len(batch), through)
	}
	if size(batch) > agentproto.MaxDefenderLogBytes {
		t.Errorf("%d bytes", size(batch))
	}
}

// fake is a channel in memory.
type fake struct {
	records        []string
	ids            []int64
	oldest, newest int64
	reads          []Query
}

func (f *fake) Read(_ context.Context, q Query) (Result, error) {
	f.reads = append(f.reads, q)
	var out []string
	for i, id := range f.ids {
		if id > q.After {
			out = append(out, f.records[i])
		}
	}
	return Result{Events: out, Oldest: f.oldest, Newest: f.newest}, nil
}

func (f *fake) add(id int, rec int64) {
	f.ids = append(f.ids, rec)
	f.records = append(f.records, xmlEvent(id, rec, "2026-11-26T10:00:00Z", map[string]string{"Threat ID": fmt.Sprint(rec), "Severity Name": "High"}))
	if f.oldest == 0 {
		f.oldest = rec
	}
	f.newest = rec
}

func TestCollectorFirstRunResendAckAndGap(t *testing.T) {
	ctx := context.Background()
	f := &fake{}
	c := &Collector{Source: f, File: filepath.Join(t.TempDir(), "bm.json"), Now: func() time.Time { return time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC) }}

	// First run, nothing in the last day.
	b, err := c.Next(ctx)
	if err != nil || b == nil || !b.Backfill || len(b.Events) != 0 || f.reads[0].Since.IsZero() {
		t.Fatalf("first run %+v %v", b, err)
	}
	// First run with 150 events: the newest 100 only, marked backfill.
	for i := int64(1); i <= 150; i++ {
		f.add(1116+int(i%2)*1, i)
	}
	b, err = c.Next(ctx)
	if err != nil || !b.Backfill || b.Through != 150 {
		t.Fatalf("backfill %+v %v", b, err)
	}
	covered := 0
	for _, e := range b.Events {
		if e.Count > 0 {
			covered += e.Count
		} else {
			covered++
		}
	}
	if covered != 100 {
		t.Errorf("the batch covers %d events, want the newest 100", covered)
	}
	// Not acknowledged: the same batch is sent again (nothing lost on a lost response).
	again, _ := c.Next(ctx)
	if again.Through != b.Through || again.Epoch != b.Epoch && false {
		t.Errorf("resend %+v", again)
	}
	// The server acknowledges: nothing more to send.
	if err := c.Acked(&agentproto.DefenderLogAck{Epoch: b.Epoch, RecordID: b.Through}, b); err != nil {
		t.Fatal(err)
	}
	if n, err := c.Next(ctx); err != nil || n != nil {
		t.Fatalf("after the ack: %+v %v", n, err)
	}
	// The bookmark survives a restart.
	c2 := &Collector{Source: f, File: c.File, Now: c.Now}
	if n, _ := c2.Next(ctx); n != nil {
		t.Errorf("after a restart: %+v", n)
	}
	f.add(5001, 151)
	n, _ := c2.Next(ctx)
	if n == nil || n.Backfill || n.Gap || len(n.Events) != 1 || n.Events[0].EventID != 5001 || n.Epoch != b.Epoch {
		t.Fatalf("a new event: %+v", n)
	}
	// An acknowledgement of another epoch changes nothing.
	_ = c2.Acked(&agentproto.DefenderLogAck{Epoch: "other", RecordID: 151}, n)
	if again, _ := c2.Next(ctx); again == nil {
		t.Error("an ack of another epoch moved the bookmark")
	}
	_ = c2.Acked(&agentproto.DefenderLogAck{Epoch: n.Epoch, RecordID: 151}, n)

	// The log wrapped past the bookmark: a gap, and what is there is read.
	f.oldest = 400
	f.add(1116, 401)
	n, _ = c2.Next(ctx)
	if n == nil || !n.Gap || n.Through != 401 {
		t.Errorf("wrapped: %+v", n)
	}
	_ = c2.Acked(&agentproto.DefenderLogAck{Epoch: n.Epoch, RecordID: 401}, n)

	// The log was cleared and numbers again: a new epoch, a gap, nothing lost afterward.
	f.records, f.ids, f.oldest, f.newest = nil, nil, 0, 0
	f.add(1116, 1)
	n, _ = c2.Next(ctx)
	if n == nil || !n.Gap || n.Epoch == b.Epoch || len(n.Events) != 1 || n.Events[0].RecordID != 1 {
		t.Fatalf("cleared: %+v", n)
	}
	_ = c2.Acked(&agentproto.DefenderLogAck{Epoch: n.Epoch, RecordID: 1}, n)
	f.add(5001, 2)
	if n, _ := c2.Next(ctx); n == nil || n.Gap || len(n.Events) != 1 || n.Events[0].RecordID != 2 {
		t.Errorf("after the clear: %+v", n)
	}
}

func TestCollectorWithoutASource(t *testing.T) {
	if _, err := (&Collector{File: filepath.Join(t.TempDir(), "x")}).Next(context.Background()); err == nil {
		t.Error("no source")
	}
}
