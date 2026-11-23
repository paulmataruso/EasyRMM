package logship

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func rec(msg string) agentproto.LogRecord {
	return agentproto.LogRecord{Time: time.Now(), Source: "agent", Level: "info", Message: msg}
}

func openBuf(t *testing.T, dir string, max int64) *Buffer {
	t.Helper()
	b, err := OpenBuffer(dir, max, time.Unix(1000, 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func TestBufferSequencesAckAndRestart(t *testing.T) {
	dir := t.TempDir()
	b := openBuf(t, dir, DefaultMaxBytes)
	for i := range 5 {
		seq, err := b.Append(rec(fmt.Sprint("m", i)))
		if err != nil {
			t.Fatal(err)
		}
		if want := time.Unix(1000, 0).UnixMicro() + int64(i) + 1; seq != want {
			t.Errorf("sequence %d, want %d", seq, want)
		}
	}
	recs, _ := b.Next(3, 1<<20)
	if len(recs) != 3 || recs[0].Message != "m0" || recs[2].Message != "m2" {
		t.Fatalf("Next = %+v", recs)
	}
	if err := b.Ack(recs[1].Seq, 0); err != nil {
		t.Fatal(err)
	}
	if recs, _ = b.Next(10, 1<<20); len(recs) != 3 || recs[0].Message != "m2" {
		t.Fatalf("after ack %+v", recs)
	}
	// A restart keeps what was not acknowledged, and the sequence continues.
	_ = b.Close()
	b = openBuf(t, dir, DefaultMaxBytes)
	if recs, _ = b.Next(10, 1<<20); len(recs) != 3 || recs[0].Message != "m2" {
		t.Fatalf("after restart %+v", recs)
	}
	seq, _ := b.Append(rec("m5"))
	if want := time.Unix(1000, 0).UnixMicro() + 6; seq != want {
		t.Errorf("sequence after restart %d, want %d", seq, want)
	}
	// All acknowledged: the file is emptied, and the next sequence still rises.
	recs, _ = b.Next(10, 1<<20)
	if err := b.Ack(recs[len(recs)-1].Seq, 0); err != nil {
		t.Fatal(err)
	}
	if n, _ := b.Pending(); n != 0 {
		t.Errorf("%d bytes pending after everything was acknowledged", n)
	}
	_ = b.Close()
	b = openBuf(t, dir, DefaultMaxBytes)
	if seq, _ = b.Append(rec("m6")); seq != time.Unix(1000, 0).UnixMicro()+7 {
		t.Errorf("sequence after an emptied buffer: %d", seq)
	}
}

func TestBufferDropsTheOldestAndCounts(t *testing.T) {
	b := openBuf(t, t.TempDir(), 4000)
	msg := strings.Repeat("x", 100)
	for i := range 100 {
		if _, err := b.Append(rec(fmt.Sprintf("%03d %s", i, msg))); err != nil {
			t.Fatal(err)
		}
	}
	size, dropped := b.Pending()
	if size > 4000 || dropped == 0 {
		t.Fatalf("size %d, dropped %d", size, dropped)
	}
	recs, d := b.Next(500, 1<<20)
	if d != dropped || len(recs) == 0 {
		t.Fatalf("Next: %d records, dropped %d", len(recs), d)
	}
	if !strings.HasPrefix(recs[len(recs)-1].Message, "099") || int64(len(recs))+dropped != 100 {
		t.Errorf("the newest must stay: last %q, kept %d, dropped %d", recs[len(recs)-1].Message[:3], len(recs), dropped)
	}
	// Reported once: the next batch's acknowledgement clears the count.
	if err := b.Ack(recs[len(recs)-1].Seq, d); err != nil {
		t.Fatal(err)
	}
	if _, dropped = b.Pending(); dropped != 0 {
		t.Errorf("dropped %d after it was reported", dropped)
	}
}

func TestBufferSkipsADamagedTail(t *testing.T) {
	dir := t.TempDir()
	b := openBuf(t, dir, DefaultMaxBytes)
	_, _ = b.Append(rec("one"))
	_ = b.Close()
	f, _ := os.OpenFile(filepath.Join(dir, bufferFile), os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`{"seq":99,"mess`) // a write cut off by a crash
	_ = f.Close()
	b = openBuf(t, dir, DefaultMaxBytes)
	if recs, _ := b.Next(10, 1<<20); len(recs) != 1 || recs[0].Message != "one" {
		t.Errorf("%+v", recs)
	}
}

func TestHandlerLevelRedactionAndGroups(t *testing.T) {
	b := openBuf(t, t.TempDir(), DefaultMaxBytes)
	s := New(b)
	var out bytes.Buffer
	log := slog.New(NewHandler(slog.NewTextHandler(&out, nil), s)).With("device", "pc1").WithGroup("job")
	log.Debug("not logged at info")
	log.Info("enrolling with ert_AbCdEf0123456789", "token", "abc", "path", `C:\x`, slog.Group("g", "n", 3))
	log.Error("failed", "error", errors.New("boom"))
	recs, _ := b.Next(10, 1<<20)
	if len(recs) != 2 {
		t.Fatalf("%d records: %+v", len(recs), recs)
	}
	r := recs[0]
	if r.Source != "agent" || r.Level != "info" || strings.Contains(r.Message, "AbCdEf") || r.Attrs["job.token"] != "***" ||
		r.Attrs["job.path"] != `C:\x` || r.Attrs["job.g.n"] != "3" || r.Attrs["device"] != "pc1" {
		t.Errorf("record = %+v", r)
	}
	if recs[1].Level != "error" || recs[1].Attrs["job.error"] != "boom" {
		t.Errorf("error record = %+v", recs[1])
	}
	if strings.Contains(out.String(), "not logged") || !strings.Contains(out.String(), "enrolling") {
		t.Errorf("the underlying log: %q", out.String())
	}
	// Verbose: Debug is logged too.
	s.Apply(&agentproto.LogInstructions{VerboseUntil: time.Now().Add(time.Hour).Unix()})
	log.Debug("now logged")
	if recs, _ = b.Next(10, 1<<20); len(recs) != 3 || recs[2].Level != "debug" {
		t.Errorf("verbose: %+v", recs)
	}
	if !strings.Contains(out.String(), "now logged") {
		t.Error("the underlying log lacks the debug line")
	}
}

func TestApplyClampsAndEnds(t *testing.T) {
	s := New(openBuf(t, t.TempDir(), DefaultMaxBytes))
	now := time.Unix(1_800_000_000, 0)
	s.Now = func() time.Time { return now }
	s.Apply(&agentproto.LogInstructions{VerboseUntil: now.Add(1000 * time.Hour).Unix(), FollowUntil: now.Add(1000 * time.Hour).Unix()})
	if !s.verboseUntil.Equal(now.Add(24 * time.Hour)) {
		t.Errorf("verbose until %v: never longer than 24 hours", s.verboseUntil)
	}
	if !s.followUntil.Equal(now.Add(15 * time.Minute)) {
		t.Errorf("follow until %v: never longer than 15 minutes", s.followUntil)
	}
	if s.Level.Level() != slog.LevelDebug || !s.following(now) {
		t.Error("verbose and following should be on")
	}
	// The agent ends verbose mode by itself, with no word from the server.
	now = now.Add(24*time.Hour + time.Second)
	s.settle(now)
	if s.Level.Level() != slog.LevelInfo || s.following(now) {
		t.Error("verbose mode did not end by itself")
	}
	// A past or absent instruction is off.
	s.Apply(&agentproto.LogInstructions{VerboseUntil: now.Add(-time.Hour).Unix()})
	s.Apply(nil)
	if s.Level.Level() != slog.LevelInfo {
		t.Error("level after nothing")
	}
	var nilShipper *Shipper
	nilShipper.Apply(nil) // a missing buffer leaves a nil Shipper that does nothing
}

type fakeServer struct {
	mu      sync.Mutex
	batches []agentproto.LogBatch
	fail    error
	logs    *agentproto.LogInstructions
}

func (f *fakeServer) send(_ context.Context, b agentproto.LogBatch) (agentproto.LogAck, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return agentproto.LogAck{}, f.fail
	}
	f.batches = append(f.batches, b)
	var ack agentproto.LogAck
	for _, r := range b.Records {
		ack.Seq = max(ack.Seq, r.Seq)
	}
	ack.Logs = f.logs
	return ack, nil
}

func TestFlushSendsAcknowledgesAndKeepsWhatFailed(t *testing.T) {
	b := openBuf(t, t.TempDir(), DefaultMaxBytes)
	s := New(b)
	s.defaults()
	for i := range 1200 {
		_, _ = b.Append(rec(fmt.Sprint("m", i)))
	}
	srv := &fakeServer{fail: errors.New("offline")}
	if err := s.Flush(context.Background(), srv.send, 5); err == nil {
		t.Fatal("no error while the server is unreachable")
	}
	srv.fail = nil
	if err := s.Flush(context.Background(), srv.send, 5); err != nil {
		t.Fatal(err)
	}
	if len(srv.batches) != 3 || len(srv.batches[0].Records) != agentproto.MaxLogBatch || len(srv.batches[2].Records) != 200 {
		t.Fatalf("%d batches", len(srv.batches))
	}
	if srv.batches[0].Records[0].Message != "m0" || srv.batches[2].Records[199].Message != "m1199" {
		t.Error("records were not sent in order, all of them")
	}
	if n, _ := b.Pending(); n != 0 {
		t.Errorf("%d bytes left after everything was acknowledged", n)
	}
	// Dropped records are reported once.
	b.dropped = 5
	_ = s.Flush(context.Background(), srv.send, 1)
	if last := srv.batches[len(srv.batches)-1]; last.Dropped != 5 || len(last.Records) != 0 {
		t.Errorf("batch %+v", last)
	}
	if _, d := b.Pending(); d != 0 {
		t.Errorf("dropped %d after it was reported", d)
	}
}

func TestRunSendsEverySecondWhileFollowedAndStopsWithAFlush(t *testing.T) {
	b := openBuf(t, t.TempDir(), DefaultMaxBytes)
	s := New(b)
	s.Every, s.FollowEvery = time.Hour, 10*time.Millisecond
	srv := &fakeServer{logs: &agentproto.LogInstructions{FollowUntil: time.Now().Add(time.Minute).Unix()}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx, srv.send); close(done) }()
	// Following starts on the server's word, which wakes the loop at once.
	s.Apply(&agentproto.LogInstructions{FollowUntil: time.Now().Add(time.Minute).Unix()})
	count := func() int { srv.mu.Lock(); defer srv.mu.Unlock(); return len(srv.batches) }
	for i := range 5 {
		_, _ = b.Append(rec(fmt.Sprint("m", i)))
		deadline := time.Now().Add(2 * time.Second)
		for count() <= i && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if count() < 5 {
		t.Fatalf("%d batches while followed", count())
	}
	// A record written just before the end is sent by the final flush.
	srv.mu.Lock()
	srv.logs = nil
	srv.mu.Unlock()
	s.Apply(nil)
	_, _ = b.Append(rec("last"))
	cancel()
	<-done
	srv.mu.Lock()
	defer srv.mu.Unlock()
	var found bool
	for _, bt := range srv.batches {
		for _, r := range bt.Records {
			found = found || r.Message == "last"
		}
	}
	if !found {
		t.Error("the last record was not flushed")
	}
}

func TestUnsupportedServerBacksOff(t *testing.T) {
	b := openBuf(t, t.TempDir(), DefaultMaxBytes)
	s := New(b)
	s.defaults()
	_, _ = b.Append(rec("x"))
	srv := &fakeServer{fail: ErrUnsupported}
	if wait := s.step(context.Background(), srv.send); wait != 10*time.Minute {
		t.Errorf("wait %v after a 404", wait)
	}
	srv.fail = errors.New("500")
	if w1, w2 := s.step(context.Background(), srv.send), s.step(context.Background(), srv.send); w2 <= w1 || w2 > 5*time.Minute {
		t.Errorf("waits %v then %v: should back off, within 5 minutes", w1, w2)
	}
}

func TestTailReadsNewLinesRotationAndContinuations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	write := func(s string, flag int) {
		f, err := os.OpenFile(path, flag|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString(s)
		_ = f.Close()
	}
	var got []agentproto.LogRecord
	emit := func(r agentproto.LogRecord) { got = append(got, r) }
	offsets := OpenOffsets(dir)
	tl := &Tail{Source: "easypatch", Path: path, Offsets: offsets}
	tl.Poll(emit) // no file yet
	write("2026-11-23T10:00:00.000Z INF Boot: started\n2026-11-23T10:00:01.000Z WRN Net: slow token=abc\n", os.O_APPEND)
	tl.Poll(emit)
	if len(got) != 2 || got[0].Level != "info" || got[0].Source != "easypatch" || got[1].Level != "warn" || strings.Contains(got[1].Message, "abc") ||
		got[0].Time.Format(time.RFC3339) != "2026-11-23T10:00:00Z" {
		t.Fatalf("first read: %+v", got)
	}
	// A line being written is read once it is whole; a stack trace continues its record.
	write("2026-11-23T10:00:02.000Z ERR Job: failed", os.O_APPEND)
	tl.Poll(emit)
	if len(got) != 2 {
		t.Fatalf("a partial line was read: %+v", got[2:])
	}
	write("\n   at Foo.Bar()\n   at Baz()\n", os.O_APPEND)
	tl.Poll(emit)
	if len(got) != 3 || got[2].Level != "error" || got[2].Message != "Job: failed\n   at Foo.Bar()\n   at Baz()" {
		t.Fatalf("continuation: %+v", got[2:])
	}
	// A restart continues where the tail stopped: nothing is repeated.
	tl2 := &Tail{Source: "easypatch", Path: path, Offsets: OpenOffsets(dir)}
	tl2.Poll(emit)
	if len(got) != 3 {
		t.Errorf("repeated after a restart: %+v", got[3:])
	}
	// The file was replaced by a shorter one: read from its start.
	write("2026-11-23T11:00:00.000Z INF New: file\n", os.O_TRUNC)
	tl2.Poll(emit)
	if len(got) != 4 || got[3].Message != "New: file" {
		t.Errorf("rotation: %+v", got[3:])
	}
	// A long file seen for the first time is read from its last 32 KiB only.
	big := filepath.Join(dir, "big.log")
	var sb strings.Builder
	for i := range 3000 {
		fmt.Fprintf(&sb, "line %d of a log MeshAgent wrote\n", i)
	}
	_ = os.WriteFile(big, []byte(sb.String()), 0o600)
	got = nil
	(&Tail{Source: "meshagent", Path: big}).Poll(emit)
	if len(got) == 0 || len(got) > 1200 || got[len(got)-1].Message != "line 2999 of a log MeshAgent wrote" || got[0].Source != "meshagent" {
		t.Errorf("first read of a long file: %d records, last %q", len(got), got[len(got)-1].Message)
	}
	// Level text in a line of another program is left alone: MeshAgent lines are Info.
	if got[0].Level != "info" {
		t.Errorf("level %q", got[0].Level)
	}
}

func TestClip(t *testing.T) {
	if got := Clip("héllo", 2); got != "h" {
		t.Errorf("Clip cut inside a character: %q", got)
	}
	if got := Clip("日本語", 4); got != "日" {
		t.Errorf("Clip = %q", got)
	}
	if got := Clip("abc", 10); got != "abc" {
		t.Errorf("Clip = %q", got)
	}
}
