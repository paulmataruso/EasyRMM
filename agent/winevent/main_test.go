package winevent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/eventrules"
)

func files(t *testing.T, input string) (in, out string) {
	t.Helper()
	dir := t.TempDir()
	in, out = filepath.Join(dir, "input.json"), filepath.Join(dir, "result.jsonl")
	if err := os.WriteFile(in, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	return in, out
}

func TestRunFilesReadsTheInputAndWritesTheResult(t *testing.T) {
	be := newBackend()
	be.logs["System"] = &fakeLog{events: fill("System", 3, nil), info: LogInfo{Known: true, Created: t0, Oldest: 1}}
	in, out := files(t, `{"v":1,"op":"query","rules":1,"sensitive":false,"channels":["System"]}`)
	r, w, _ := os.Pipe()
	defer func() { _ = r.Close(); _ = w.Close() }()
	if err := RunFiles(in, out, "9.9.9", r, be); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(out)
	res, err := eventrules.ParseLines(splitLines(raw))
	if err != nil || len(res.Events) != 3 || res.End == nil || res.Begin.AgentVersion != "9.9.9" {
		t.Fatalf("%v %+v", err, res)
	}
	if be.cancels != 1 {
		// The watchdog cancels when the run is over and its context ends.
		t.Logf("cancels: %d", be.cancels)
	}
}

func TestClosingTheInputCancelsTheRun(t *testing.T) {
	be := newBackend()
	be.logs["System"] = &fakeLog{events: fill("System", 5000, nil), info: LogInfo{Known: true, Created: t0, Oldest: 1}}
	be.slow = 20 * time.Millisecond
	in, out := files(t, `{"v":1,"op":"query","rules":1,"sensitive":false,"channels":["System"],"text":"never"}`)
	r, w, _ := os.Pipe()
	time.AfterFunc(200*time.Millisecond, func() { _ = w.Close() })
	start := time.Now()
	if err := RunFiles(in, out, "1", r, be); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(out)
	res, err := eventrules.ParseLines(splitLines(raw))
	if err != nil || res.End == nil || res.End.StoppedBy != eventrules.StopCancel || time.Since(start) > 5*time.Second {
		t.Fatalf("%v %+v after %s", err, res, time.Since(start))
	}
	be.mu.Lock()
	n := be.cancels
	be.mu.Unlock()
	if n == 0 {
		t.Fatal("the queries were not canceled (EvtCancel)")
	}
}

func TestRunFilesRefusesBadInput(t *testing.T) {
	be := newBackend()
	for _, bad := range []string{`{"v":1,"op":"clear"}`, `{"v":1,"op":"query","extra":true}`, ``, `{"v":1,"op":"query","channels":["a|b"]}`} {
		in, out := files(t, bad)
		if err := RunFiles(in, out, "1", nil, be); err == nil {
			t.Errorf("%q runs", bad)
		}
	}
	if err := RunFiles(filepath.Join(t.TempDir(), "missing"), "x", "1", nil, be); err == nil {
		t.Error("a missing input")
	}
	t.Setenv("EASYRMM_JOB_INPUT", "")
	if err := Main("1"); err == nil || !strings.Contains(err.Error(), "started by the agent") {
		t.Errorf("Main: %v", err)
	}
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		out = append(out, []byte(l))
	}
	return out
}
