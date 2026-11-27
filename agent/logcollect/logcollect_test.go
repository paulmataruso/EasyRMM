package logcollect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/logblock"
)

type fakeReader struct {
	name   string
	events []logblock.Event // all of them; the cursor is an index
	err    error
}

func (f *fakeReader) Name() string { return f.name }
func (f *fakeReader) Read(_ context.Context, cursor string, _ time.Time, limit int) ([]logblock.Event, string, error) {
	if f.err != nil {
		return nil, cursor, f.err
	}
	var at int
	if cursor != "" {
		_, _ = fmt.Sscanf(cursor, "%d", &at)
	}
	end := min(at+limit, len(f.events))
	return f.events[at:end], fmt.Sprint(end), nil
}

func newSpool(t *testing.T) *Spool {
	t.Helper()
	s := &Spool{Dir: filepath.Join(t.TempDir(), "spool")}
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	return s
}

func events(n int, source string) []logblock.Event {
	out := make([]logblock.Event, n)
	base := time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)
	for i := range out {
		out[i] = logblock.Event{Time: base.Add(time.Duration(i) * time.Second), Source: source, Message: fmt.Sprintf("event %d", i), ID: "7"}
	}
	return out
}

func TestCollectorWritesBlocksAndMovesCursorsAfter(t *testing.T) {
	sp := newSpool(t)
	r := &fakeReader{name: "r", events: events(25, "linux.journal")}
	c := &Collector{Readers: []Reader{r}, Spool: sp, BatchEvents: 10}
	if n := c.Pass(context.Background()); n != 3 {
		t.Fatalf("wrote %d blocks, want 3 (10+10+5)", n)
	}
	if got := sp.LoadCursors()["r"]; got != "25" {
		t.Fatalf("cursor %q", got)
	}
	// Nothing new: nothing written, and a second pass reads from the cursor.
	if n := c.Pass(context.Background()); n != 0 {
		t.Fatalf("a quiet pass wrote %d", n)
	}
	blocks, err := sp.Pending(10)
	if err != nil || len(blocks) != 3 {
		t.Fatalf("pending: %v %d", err, len(blocks))
	}
	for i := 1; i < len(blocks); i++ {
		if blocks[i].Seq <= blocks[i-1].Seq {
			t.Fatal("sequences do not rise")
		}
	}
	evs, err := logblock.Open(blocks[0].Codec, blocks[0].Data)
	if err != nil || len(evs) != 10 || evs[0].Message != "event 0" {
		t.Fatalf("block 0: %v %d", err, len(evs))
	}
}

func TestCollectorGroupsSourcesAndClasses(t *testing.T) {
	sp := newSpool(t)
	evs := append(events(2, SourceAuth), events(3, SourceJournal)...)
	c := &Collector{Readers: []Reader{&fakeReader{name: "j", events: evs}}, Spool: sp}
	if n := c.Pass(context.Background()); n != 2 {
		t.Fatalf("wrote %d", n)
	}
	blocks, _ := sp.Pending(10)
	classes := map[string]string{}
	for _, b := range blocks {
		classes[b.Source] = b.Class
	}
	if classes[SourceAuth] != logblock.ClassSecurity || classes[SourceJournal] != logblock.ClassOperational {
		t.Fatalf("classes: %v", classes)
	}
}

func TestCollectorRedactsTokens(t *testing.T) {
	sp := newSpool(t)
	e := logblock.Event{Time: time.Now(), Source: SourceJournal, Message: "enroll with ert_abcdef123456 now",
		Fields: map[string]string{"password": "hunter2"}, Sensitive: map[string]string{"cmdline": "tool --password hunter2"}}
	c := &Collector{Readers: []Reader{&fakeReader{name: "j", events: []logblock.Event{e}}}, Spool: sp}
	c.Pass(context.Background())
	blocks, _ := sp.Pending(1)
	got, _ := logblock.Open(blocks[0].Codec, blocks[0].Data)
	all := got[0].Message + got[0].Fields["password"] + got[0].Sensitive["cmdline"]
	if strings.Contains(all, "ert_abcdef") || strings.Contains(all, "hunter2") {
		t.Fatalf("secrets kept: %+v", got[0])
	}
}

func TestCollectorKeepsCursorOnFailure(t *testing.T) {
	sp := newSpool(t)
	good := &fakeReader{name: "good", events: events(1, SourceJournal)}
	bad := &fakeReader{name: "bad", err: errors.New("boom")}
	c := &Collector{Readers: []Reader{bad, good}, Spool: sp}
	if n := c.Pass(context.Background()); n != 1 {
		t.Fatalf("the failing reader stopped the others: %d", n)
	}
	if _, ok := sp.LoadCursors()["bad"]; ok {
		t.Fatal("a failed reader's cursor moved")
	}
}

func TestSpoolSequencesSurviveAWipe(t *testing.T) {
	sp := newSpool(t)
	b, _ := logblock.Seal(SourceJournal, logblock.ClassOperational, events(1, SourceJournal))
	s1, _, _ := sp.Put(b)
	if err := sp.Ack(s1); err != nil {
		t.Fatal(err)
	}
	if n, _ := sp.Size(); n != 0 {
		t.Fatal("ack kept the block")
	}
	s2, _, _ := sp.Put(b)
	if s2 <= s1 {
		t.Fatalf("sequence fell: %d after %d", s2, s1)
	}
	// Even with the bookkeeping file gone, the clock keeps them rising.
	_ = os.Remove(filepath.Join(sp.Dir, lastSeqFile))
	s3, _, _ := sp.Put(b)
	if s3 <= s2 {
		t.Fatalf("sequence fell after a wipe: %d after %d", s3, s2)
	}
}

func TestSpoolDropsOldestOverItsSize(t *testing.T) {
	sp := newSpool(t)
	sp.MaxBytes = 1
	b, _ := logblock.Seal(SourceJournal, logblock.ClassOperational, events(50, SourceJournal))
	var last int64
	var dropped int
	for range 4 {
		var d int
		var err error
		last, d, err = sp.Put(b)
		if err != nil {
			t.Fatal(err)
		}
		dropped += d
	}
	blocks, _ := sp.Pending(10)
	if len(blocks) != 1 || blocks[0].Seq != last || dropped != 3 {
		t.Fatalf("kept %d blocks, dropped %d", len(blocks), dropped)
	}
}

func TestSpoolRemovesDamagedFiles(t *testing.T) {
	sp := newSpool(t)
	if err := os.WriteFile(filepath.Join(sp.Dir, name(5)), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	blocks, err := sp.Pending(5)
	if err != nil || len(blocks) != 0 {
		t.Fatalf("%v %d", err, len(blocks))
	}
	if n, _ := sp.Size(); n != 0 {
		t.Fatal("the damaged block stays and would stop every later one")
	}
}

func TestUploaderSendsInOrderAndDeletesWhatIsAcknowledged(t *testing.T) {
	sp := newSpool(t)
	b, _ := logblock.Seal(SourceJournal, logblock.ClassOperational, events(2, SourceJournal))
	var seqs []int64
	for range 10 {
		s, _, _ := sp.Put(b)
		seqs = append(seqs, s)
	}
	var calls [][]int64
	u := &Uploader{Spool: sp, Send: func(_ context.Context, bt agentproto.CollectedBatch) (agentproto.CollectedAck, error) {
		var got []int64
		for _, x := range bt.Blocks {
			got = append(got, x.Seq)
		}
		calls = append(calls, got)
		return agentproto.CollectedAck{Seq: got[len(got)-1]}, nil
	}}
	n, err := u.Once(context.Background())
	if err != nil || n != 10 {
		t.Fatalf("%d %v", n, err)
	}
	if len(calls) != 2 || len(calls[0]) != agentproto.MaxCollectedBlocks || calls[0][0] != seqs[0] || calls[1][1] != seqs[9] {
		t.Fatalf("calls: %v", calls)
	}
	if left, _ := sp.Size(); left != 0 {
		t.Fatal("blocks left")
	}
}

func TestUploaderKeepsBlocksWhenTheServerFails(t *testing.T) {
	sp := newSpool(t)
	b, _ := logblock.Seal(SourceJournal, logblock.ClassOperational, events(1, SourceJournal))
	_, _, _ = sp.Put(b)
	u := &Uploader{Spool: sp, Send: func(context.Context, agentproto.CollectedBatch) (agentproto.CollectedAck, error) {
		return agentproto.CollectedAck{}, ErrUnsupported
	}}
	if _, err := u.Once(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if left, _ := sp.Size(); left != 1 {
		t.Fatal("a failed upload deleted the block")
	}
	u.Send = func(context.Context, agentproto.CollectedBatch) (agentproto.CollectedAck, error) {
		return agentproto.CollectedAck{Seq: 0}, nil
	}
	if _, err := u.Once(context.Background()); err == nil {
		t.Fatal("an answer that acknowledges nothing is not progress")
	}
}

const journalLine = `{"__CURSOR":"s=abc;i=1","__REALTIME_TIMESTAMP":"1764234000123456","PRIORITY":"4","MESSAGE":"Failed password for root","SYSLOG_IDENTIFIER":"sshd","_PID":"812","_SYSTEMD_UNIT":"ssh.service"}`

func TestParseJournal(t *testing.T) {
	e, cur, ok := ParseJournal([]byte(journalLine))
	if !ok || cur != "s=abc;i=1" {
		t.Fatal("not parsed")
	}
	if e.Source != SourceAuth || e.Level != "warn" || e.ID != "sshd" || e.Fields["unit"] != "ssh.service" || e.Fields["pid"] != "812" {
		t.Fatalf("%+v", e)
	}
	if e.Time.UnixMicro() != 1764234000123456 {
		t.Fatalf("time %v", e.Time)
	}
	bin := `{"__CURSOR":"c","__REALTIME_TIMESTAMP":"1","MESSAGE":[1,2,3]}`
	if e, _, ok := ParseJournal([]byte(bin)); !ok || !strings.Contains(e.Message, "binary") || e.Source != SourceJournal {
		t.Fatalf("binary message: %+v", e)
	}
	for _, bad := range []string{"", "not json", `{"MESSAGE":"x"}`} {
		if _, _, ok := ParseJournal([]byte(bad)); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestJournalReaderUsesCursorAndStopsAtTheLimit(t *testing.T) {
	var gotArgs []string
	lines := strings.Join([]string{
		strings.Replace(journalLine, "s=abc;i=1", "c1", 1),
		strings.Replace(journalLine, "s=abc;i=1", "c2", 1),
		strings.Replace(journalLine, "s=abc;i=1", "c3", 1),
	}, "\n")
	j := &Journal{Run: func(_ context.Context, _ string, args ...string) (io.ReadCloser, func() error, error) {
		gotArgs = args
		return io.NopCloser(strings.NewReader(lines)), func() error { return nil }, nil
	}}
	evs, next, err := j.Read(context.Background(), "c0", time.Now(), 2)
	if err != nil || len(evs) != 2 || next != "c2" {
		t.Fatalf("%v %d %q", err, len(evs), next)
	}
	if !contains(gotArgs, "--after-cursor=c0") {
		t.Fatalf("args %v", gotArgs)
	}
	_, _, _ = j.Read(context.Background(), "", time.Unix(100, 0), 2)
	if !contains(gotArgs, "--since=@100") {
		t.Fatalf("args %v", gotArgs)
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func TestParseAudit(t *testing.T) {
	e, ok := ParseAudit(`type=USER_LOGIN msg=audit(1764234000.123:456): pid=900 uid=0 auid=1000 ses=3 msg='op=login acct="bob" exe="/usr/sbin/sshd" addr=10.0.0.5 res=failed'`)
	if !ok || e.ID != "USER_LOGIN" || e.Level != "warn" || e.Fields["serial"] != "456" || e.Fields["auid"] != "1000" {
		t.Fatalf("%+v ok=%v", e, ok)
	}
	if e.Time.Unix() != 1764234000 || e.Time.Nanosecond() != 123*1_000_000 {
		t.Fatalf("time %v", e.Time)
	}
	x, ok := ParseAudit(`type=EXECVE msg=audit(1764234001.000:457): argc=3 a0="curl" a1="-u" a2=757365723A70617373`)
	if !ok || x.Message != "EXECVE" || x.Sensitive["cmdline"] != "curl -u user:pass" {
		t.Fatalf("%+v", x)
	}
	for _, bad := range []string{"", "hello", "type=X", "type=X foo"} {
		if _, ok := ParseAudit(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

func auditLine(serial int) string {
	return fmt.Sprintf("type=USER_AUTH msg=audit(1764234000.000:%d): pid=1 res=success\n", serial)
}

func TestAuditReaderFollowsRotationByInode(t *testing.T) {
	dir := t.TempDir()
	cur := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(cur, []byte(auditLine(1)+auditLine(2)+"type=USER_AUTH msg=audit(17"), 0o600); err != nil {
		t.Fatal(err)
	}
	var open []*os.File
	a := &Audit{Files: func() ([]*os.File, error) {
		for _, f := range open {
			_ = f.Close()
		}
		open = nil
		des, _ := os.ReadDir(dir)
		var names []string
		for _, de := range des {
			names = append(names, de.Name())
		}
		// audit.log.1 is older than audit.log
		ordered := []string{}
		if contains(names, "audit.log.1") {
			ordered = append(ordered, "audit.log.1")
		}
		ordered = append(ordered, "audit.log")
		for _, n := range ordered {
			f, err := os.Open(filepath.Join(dir, n))
			if err != nil {
				return nil, err
			}
			open = append(open, f)
		}
		return open, nil
	}}
	since := time.Unix(0, 0)
	evs, c1, err := a.Read(context.Background(), "", since, 100)
	if err != nil || len(evs) != 2 {
		t.Fatalf("first read: %v %d (the partial line must wait)", err, len(evs))
	}
	// The rest of the third line arrives, then the file rotates and a new
	// one starts: nothing is read twice and nothing is lost.
	f, _ := os.OpenFile(cur, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString("64234000.000:3): pid=1 res=success\n" + auditLine(4))
	_ = f.Close()
	if err := os.Rename(cur, filepath.Join(dir, "audit.log.1")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cur, []byte(auditLine(5)), 0o600); err != nil {
		t.Fatal(err)
	}
	evs, c2, err := a.Read(context.Background(), c1, since, 100)
	if err != nil {
		t.Fatal(err)
	}
	var serials []string
	for _, e := range evs {
		serials = append(serials, e.Fields["serial"])
	}
	if strings.Join(serials, ",") != "3,4,5" {
		t.Fatalf("serials %v", serials)
	}
	evs, _, _ = a.Read(context.Background(), c2, since, 100)
	if len(evs) != 0 {
		t.Fatalf("read again: %d", len(evs))
	}
	// A limit pauses and resumes mid-file.
	evs, c3, _ := a.Read(context.Background(), "", since, 2)
	if len(evs) != 2 {
		t.Fatalf("limit: %d", len(evs))
	}
	evs, _, _ = a.Read(context.Background(), c3, since, 100)
	if len(evs) != 3 {
		t.Fatalf("resume: %d", len(evs))
	}
	for _, f := range open {
		_ = f.Close()
	}
}

func TestParseWindowsEvent(t *testing.T) {
	x := `<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><Level>0</Level>` +
		`<Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime="2026-11-27T10:00:00.5Z"/><EventRecordID>991</EventRecordID><Computer>pc1</Computer></System>` +
		`<EventData><Data Name="TargetUserName">bob</Data><Data Name="CommandLine">cmd /c whoami</Data><Data Name="Empty"></Data></EventData></Event>`
	e, rec, err := ParseWindowsEvent(x, "windows.security")
	if err != nil || rec != 991 {
		t.Fatalf("%v %d", err, rec)
	}
	if e.ID != "4625" || e.Level != "warn" || e.Fields["TargetUserName"] != "bob" || e.Sensitive["CommandLine"] != "cmd /c whoami" || e.Fields["computer"] != "pc1" {
		t.Fatalf("%+v", e)
	}
	if _, ok := e.Fields["CommandLine"]; ok {
		t.Fatal("a command line is in the open fields")
	}
	if _, _, err := ParseWindowsEvent("<nope", "x"); err == nil {
		t.Fatal("bad xml parsed")
	}
}

func TestUnitIsConfined(t *testing.T) {
	u := Unit("/usr/local/bin/easyrmm-agent", "easyrmm-agent.service")
	for _, want := range []string{
		"DynamicUser=yes", "CapabilityBoundingSet=\n", "NoNewPrivileges=yes", "ProtectSystem=strict",
		"RestrictAddressFamilies=AF_UNIX", "IPAddressDeny=any", "CPUQuota=20%", "MemoryMax=256M",
		"SupplementaryGroups=systemd-journal", "PartOf=easyrmm-agent.service", "InaccessiblePaths=/var/lib/easyrmm-agent",
		"ExecStart=/usr/local/bin/easyrmm-agent collect --spool /var/lib/easyrmm-collect",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q", want)
		}
	}
}

func TestInstallAndRemoveUnit(t *testing.T) {
	var calls []string
	old := Systemctl
	Systemctl = func(args ...string) error { calls = append(calls, strings.Join(args, " ")); return nil }
	defer func() { Systemctl = old }()
	path := filepath.Join(t.TempDir(), UnitName)
	if err := InstallUnit(path, "/x/agent", "easyrmm-agent.service"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "/x/agent collect") {
		t.Fatal("unit not written")
	}
	if err := RemoveUnit(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("unit kept")
	}
	if err := RemoveUnit(path); err != nil {
		t.Fatal("removing a unit that is gone is an error:", err)
	}
	if len(calls) != 4 {
		t.Fatalf("calls %v", calls)
	}
}
