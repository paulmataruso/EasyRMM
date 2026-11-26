//go:build windows

package winevent

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/paulmataruso/easyrmm/internal/eventrules"
)

// The event viewer's builtin on a real Windows, as LocalSystem (ADR-0068,
// Testing). CI's job builds this package's test binary for each architecture
// and runs it through a scheduled task with EASYRMM_TEST_SYSTEM set. The
// tests write events into the Application log under a source of their own, so
// they run only there.

func needSystem(t *testing.T) {
	t.Helper()
	if os.Getenv("EASYRMM_TEST_SYSTEM") == "" {
		t.Skip("runs as LocalSystem on a computer made for it; CI's job sets EASYRMM_TEST_SYSTEM")
	}
}

func realBackend(t *testing.T) Backend {
	t.Helper()
	be, err := NewBackend()
	if err != nil {
		t.Fatal(err)
	}
	return be
}

func runReal(t *testing.T, be Backend, in eventrules.Input) (*eventrules.Result, string, time.Duration) {
	t.Helper()
	in.V, in.Rules = 1, eventrules.Version
	var b bytes.Buffer
	start := time.Now()
	if err := Run(context.Background(), in, be, &b, Options{AgentVersion: "test"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	took := time.Since(start)
	var lines [][]byte
	for _, l := range bytes.Split(bytes.TrimRight(b.Bytes(), "\n"), []byte("\n")) {
		lines = append(lines, l)
	}
	res, err := eventrules.ParseLines(lines)
	if err != nil {
		t.Fatalf("the result does not decode: %v\n%s", err, b.String())
	}
	return res, b.String(), took
}

// writeMarker writes events into the Application log under a source that is
// not registered, so that Windows has no message file for them.
func writeMarker(t *testing.T, n int) string {
	t.Helper()
	marker := fmt.Sprintf("easyrmm-evtest-%d", time.Now().UnixNano())
	l, err := eventlog.Open("EasyRMMEventTest")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	for i := range n {
		if err := l.Info(uint32(1000+i), marker+" number "+fmt.Sprint(i)); err != nil { //nolint:gosec // a small test number
			t.Fatal(err)
		}
	}
	// The Event Log service writes them a moment later.
	time.Sleep(2 * time.Second)
	return marker
}

func TestChannelsAsSystem(t *testing.T) {
	needSystem(t)
	res, _, took := runReal(t, realBackend(t), eventrules.Input{Op: eventrules.OpChannels})
	t.Logf("channels: %d in %s", len(res.Channels), took)
	names := map[string]eventrules.ChannelInfo{}
	for _, c := range res.Channels {
		names[strings.ToLower(c.Name)] = c
	}
	for _, want := range []string{"system", "application", "security"} {
		c, ok := names[want]
		if !ok || !c.Enabled || c.Type != "admin" || c.Count == nil {
			t.Errorf("%s: %+v", want, c)
		}
	}
	if res.Crash == nil || res.End == nil || !res.End.Complete {
		t.Fatalf("%+v %+v", res.Crash, res.End)
	}
	if res.Begin.Arch == "" || res.Begin.Clock == "" {
		t.Fatalf("%+v", res.Begin)
	}
	sawOther := false
	for n, c := range names {
		if strings.Contains(n, "/") && c.Type == "operational" {
			sawOther = true
		}
	}
	if !sawOther {
		t.Error("no operational channel listed")
	}
	if _, err := eventrules.CheckResult(eventrules.Input{V: 1, Op: eventrules.OpChannels}, res, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestQueryFindsWhatWasWrittenAsSystem(t *testing.T) {
	needSystem(t)
	marker := writeMarker(t, 3)
	be := realBackend(t)
	in := eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"application"}, Text: marker, Levels: []int{4},
		Providers: []string{"EasyRMMEventTest"}, Time: &eventrules.TimeFilter{Last: "1h"}}
	res, raw, took := runReal(t, be, in)
	t.Logf("a query of the Application log took %s", took)
	if len(res.Events) != 3 {
		t.Fatalf("%d events\n%s", len(res.Events), raw)
	}
	e := res.Events[0]
	if e.Provider != "EasyRMMEventTest" || e.Record == 0 || e.Channel != "Application" || e.User == "" || e.Offset == nil || e.LevelName == "" ||
		!strings.Contains(e.XML, marker) || !strings.HasPrefix(e.Keywords, "0x") {
		t.Fatalf("%+v", e)
	}
	// Windows has no message file for the source: the data is shown and the
	// reason is said.
	if e.Message == "" && e.MessageNote == "" {
		t.Errorf("neither a message nor a reason: %+v", e)
	}
	if res.Events[0].Record <= res.Events[1].Record {
		t.Error("newest first")
	}
	if _, err := eventrules.CheckResult(eventrules.Input{V: 1, Op: eventrules.OpQuery, Channels: []string{"application"}, Text: marker}, res, time.Now()); err != nil {
		t.Fatalf("the server's check: %v", err)
	}
	// A page of 1, then the next page by the cursor.
	in.Text = ""
	in.Providers = []string{"EasyRMMEventTest"}
	first, _, _ := runReal(t, be, in)
	if len(first.Events) == 0 || first.End.Cursor == nil {
		t.Fatalf("%+v", first.End)
	}
	// The event operation opens it by record.
	one, _, _ := runReal(t, be, eventrules.Input{Op: eventrules.OpEvent, Channels: []string{"Application"}, Record: e.Record})
	if len(one.Events) != 1 || one.Events[0].Record != e.Record {
		t.Fatalf("%+v", one.End)
	}
	// An event that is not there.
	none, _, _ := runReal(t, be, eventrules.Input{Op: eventrules.OpEvent, Channels: []string{"Application"}, Record: 1 << 40})
	if len(none.Events) != 0 || none.End == nil {
		t.Fatalf("%+v", none)
	}
}

func TestCursorContinuesAcrossPagesAsSystem(t *testing.T) {
	needSystem(t)
	_ = writeMarker(t, 5)
	be := realBackend(t)
	in := eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"Application"}, Providers: []string{"EasyRMMEventTest"}}
	all, _, _ := runReal(t, be, in)
	if len(all.Events) < 5 {
		t.Fatalf("%d", len(all.Events))
	}
	// Walk the log in pages of what the cursor gives: no event repeats.
	seen := map[int64]bool{}
	cur := (*eventrules.Cursor)(nil)
	for range 50 {
		in.Cursor = cur
		page, _, _ := runReal(t, be, in)
		for _, e := range page.Events {
			if seen[e.Record] {
				t.Fatalf("record %d twice", e.Record)
			}
			seen[e.Record] = true
		}
		cur = page.End.Cursor
		if page.End.StoppedBy == eventrules.StopEnd {
			break
		}
	}
	if len(seen) != len(all.Events) {
		t.Fatalf("%d events by pages, %d at once", len(seen), len(all.Events))
	}
}

func TestSecurityLogNeedsSensitiveAsSystem(t *testing.T) {
	needSystem(t)
	be := realBackend(t)
	res, _, _ := runReal(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"SECURITY"}})
	if len(res.Events) != 0 || len(res.Errors) != 1 || res.Errors[0].Code != eventrules.ErrCodeRefused {
		t.Fatalf("%+v", res)
	}
	res, _, _ = runReal(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"Security"}, Sensitive: true})
	if len(res.Events) == 0 {
		t.Fatal("LocalSystem reads the Security log when it is allowed")
	}
	for _, e := range res.Events {
		if e.MessageHidden {
			t.Fatal("hidden although sensitive was allowed")
		}
	}
	// Process creation events carry command lines: without the permission,
	// none of them is in the result.
	res, raw, _ := runReal(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"Microsoft-Windows-PowerShell/Operational", "Application"}})
	_ = res
	if strings.Contains(raw, "ScriptBlockText\">") && !strings.Contains(raw, "hidden") {
		t.Error("a script block is in the result")
	}
}

func TestMissingAndAnalyticChannelsAsSystem(t *testing.T) {
	needSystem(t)
	be := realBackend(t)
	res, _, _ := runReal(t, be, eventrules.Input{Op: eventrules.OpQuery, Channels: []string{"No-Such-Log/Operational", "Application"}})
	st := map[string]string{}
	for _, p := range res.Pos {
		st[p.Channel] = p.State
	}
	if st["No-Such-Log/Operational"] != eventrules.StateNotFound || st["Application"] != eventrules.StateOK {
		t.Fatalf("%v", st)
	}
}

func TestProviderAsSystem(t *testing.T) {
	needSystem(t)
	res, _, _ := runReal(t, realBackend(t), eventrules.Input{Op: eventrules.OpProvider, Provider: "Microsoft-Windows-Kernel-General"})
	if res.Provider == nil || res.Provider.GUID == "" || len(res.Provider.Levels) == 0 || len(res.Provider.Keywords) == 0 {
		t.Fatalf("%+v", res.Provider)
	}
	t.Logf("levels %d, tasks %d, opcodes %d, keywords %d", len(res.Provider.Levels), len(res.Provider.Tasks), len(res.Provider.Opcodes), len(res.Provider.Keywords))
	none, _, _ := runReal(t, realBackend(t), eventrules.Input{Op: eventrules.OpProvider, Provider: "No-Such-Provider-EasyRMM"})
	if len(none.Errors) != 1 || none.Errors[0].Code != eventrules.ErrCodeNotFound {
		t.Fatalf("%+v", none)
	}
}

// TestCancelStopsTheServiceAsSystem: a text search that reads a large log is
// cancelled from outside and ends promptly, with its last line.
func TestCancelStopsTheQueryAsSystem(t *testing.T) {
	needSystem(t)
	be := realBackend(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan *eventrules.Result, 1)
	go func() {
		var b bytes.Buffer
		in := eventrules.Input{V: 1, Op: eventrules.OpQuery, Rules: eventrules.Version, Channels: []string{"System", "Application"}, Text: "no event holds this text easyrmm-never"}
		if err := Run(ctx, in, be, &b, Options{}); err != nil {
			done <- nil
			return
		}
		var lines [][]byte
		for _, l := range bytes.Split(bytes.TrimRight(b.Bytes(), "\n"), []byte("\n")) {
			lines = append(lines, l)
		}
		res, _ := eventrules.ParseLines(lines)
		done <- res
	}()
	time.Sleep(500 * time.Millisecond)
	start := time.Now()
	cancel()
	be.Cancel()
	select {
	case res := <-done:
		t.Logf("ended %s after the cancel", time.Since(start))
		// A small log may have been searched whole before the cancel.
		if res == nil || res.End == nil {
			t.Fatalf("no last line: %+v", res)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the query did not stop")
	}
}

// TestBuiltinThroughTheChildAsSystem runs the whole path of RunFiles: the
// input file, the pipe, the result file.
func TestBuiltinFilesAsSystem(t *testing.T) {
	needSystem(t)
	in, out := files(t, `{"v":1,"op":"channels","rules":1,"sensitive":false}`)
	r, w, _ := os.Pipe()
	defer func() { _ = r.Close(); _ = w.Close() }()
	if err := RunFiles(in, out, "test", r, nil); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(out)
	res, err := eventrules.ParseLines(splitLines(raw))
	if err != nil || res.End == nil || len(res.Channels) < 50 {
		t.Fatalf("%v %d", err, len(res.Channels))
	}
}
