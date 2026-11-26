//go:build unix

package jobs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func payload(shell, script string, args ...string) agentproto.JobPayload {
	return agentproto.JobPayload{
		V: 1, RunID: "11111111-1111-4111-8111-111111111111", JobID: "22222222-2222-4222-8222-222222222222", DeviceID: "d",
		Shell: shell, Script: script, Args: args, TimeoutSeconds: 30, ExpiresAt: time.Now().Add(time.Hour),
	}
}

func TestExecuteReportsOutputAndExitCode(t *testing.T) {
	root := t.TempDir()
	res := Execute(context.Background(), payload("sh", `printf 'out:%s|%s\n' "$1" "$2"; echo "env:$EASYRMM_RUN_ID:$LANG:$HOME" >&2; pwd; exit 0`, "one", "two words"), root)
	if res.Status != agentproto.RunSucceeded || res.ExitCode == nil || *res.ExitCode != 0 {
		t.Fatalf("result %+v", res)
	}
	if !strings.HasPrefix(res.Stdout, "out:one|two words\n") {
		t.Errorf("stdout %q", res.Stdout)
	}
	// The script ran in its own directory, which is gone afterwards.
	dir := strings.TrimSpace(strings.TrimPrefix(res.Stdout, "out:one|two words\n"))
	if filepath.Dir(dir) != root {
		t.Errorf("working directory %q not under %q", dir, root)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("working directory left behind: %v", err)
	}
	if res.Stderr != "env:11111111-1111-4111-8111-111111111111:C.UTF-8:"+dir+"\n" {
		t.Errorf("stderr %q", res.Stderr)
	}
	if res.StartedAt.IsZero() || res.FinishedAt.Before(res.StartedAt) {
		t.Errorf("times %v %v", res.StartedAt, res.FinishedAt)
	}

	res = Execute(context.Background(), payload("sh", "echo failing >&2; exit 3"), root)
	if res.Status != agentproto.RunFailed || res.ExitCode == nil || *res.ExitCode != 3 || res.Stderr != "failing\n" {
		t.Errorf("failure %+v", res)
	}
	// The agent's environment does not leak into scripts.
	t.Setenv("EASYRMM_SECRET_TEST", "leak")
	res = Execute(context.Background(), payload("sh", `echo "[$EASYRMM_SECRET_TEST]"`), root)
	if res.Stdout != "[]\n" {
		t.Errorf("environment leaked: %q", res.Stdout)
	}
}

func TestExecuteStopsAtTheTimeoutAndOnCancel(t *testing.T) {
	old := KillGrace
	KillGrace = 2 * time.Second
	t.Cleanup(func() { KillGrace = old })
	root := t.TempDir()

	p := payload("sh", "echo started; sleep 30 & wait")
	p.TimeoutSeconds = 1
	start := time.Now()
	res := Execute(context.Background(), p, root)
	if res.Status != agentproto.RunTimedOut || res.ExitCode != nil || res.Stdout != "started\n" {
		t.Errorf("timeout %+v", res)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v to stop", d)
	}

	// A script that ignores SIGTERM is killed after the grace period.
	p = payload("sh", "trap '' TERM; echo stubborn; while :; do sleep 1; done")
	ctx, cancel := context.WithCancelCause(context.Background())
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel(errCanceled)
	}()
	res = Execute(ctx, p, root)
	if res.Status != agentproto.RunCanceled || res.Stdout != "stubborn\n" {
		t.Errorf("cancel %+v", res)
	}

	// Stopping the agent fails the run.
	ctx, stop := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		stop()
	}()
	res = Execute(ctx, payload("sh", "sleep 30"), root)
	if res.Status != agentproto.RunFailed || !strings.Contains(res.Error, "agent stopped") {
		t.Errorf("agent stop %+v", res)
	}
}

func TestExecuteWithoutTheInterpreter(t *testing.T) {
	old := searchPath
	searchPath = []string{t.TempDir()}
	t.Cleanup(func() { searchPath = old })
	res := Execute(context.Background(), payload("python3", "print(1)"), t.TempDir())
	if res.Status != agentproto.RunFailed || res.Error != "Python3 is not installed on this device." {
		t.Errorf("%+v", res)
	}
}

func TestCaptureKeepsHeadAndTail(t *testing.T) {
	c := newCapture()
	c.headSize, c.tailSize = 8, 8
	_, _ = c.Write([]byte("short"))
	if s, cut := c.Text(); s != "short" || cut {
		t.Errorf("%q %v", s, cut)
	}
	_, _ = c.Write([]byte("123"))   // head full: "short123"
	_, _ = c.Write([]byte("abcde")) // tail "abcde"
	if s, cut := c.Text(); s != "short123abcde" || cut {
		t.Errorf("%q %v", s, cut)
	}
	_, _ = c.Write([]byte("fghijkl"))
	s, cut := c.Text()
	if !cut || s != "short123\n\n[… 4 bytes omitted …]\n\nefghijkl" {
		t.Errorf("%q %v", s, cut)
	}
	// One write larger than the tail.
	c2 := newCapture()
	c2.headSize, c2.tailSize = 2, 4
	_, _ = c2.Write([]byte("0123456789"))
	if s, _ := c2.Text(); s != "01\n\n[… 4 bytes omitted …]\n\n6789" {
		t.Errorf("%q", s)
	}
}

func TestCaptureNeverSplitsCharactersOrKeepsNUL(t *testing.T) {
	c := newCapture()
	c.headSize, c.tailSize = 4, 4
	_, _ = c.Write([]byte("ab€x\x00y€z€")) // € is 3 bytes
	s, cut := c.Text()
	if !cut || !utf8.ValidString(s) || strings.ContainsRune(s, 0) || strings.ContainsRune(s, utf8.RuneError) {
		t.Errorf("%q", s)
	}
	if !strings.HasPrefix(s, "ab\n") || !strings.HasSuffix(s, "\n\nz€") {
		t.Errorf("cuts in the wrong place: %q", s)
	}
	c = newCapture()
	_, _ = c.Write([]byte{'o', 'k', 0xff, 0x00})
	if s, _ := c.Text(); s != "ok�" {
		t.Errorf("%q", s)
	}
}

func TestCaptureOfLargeOutputStaysWithinTheLimit(t *testing.T) {
	c := newCapture()
	chunk := []byte(strings.Repeat("x", 4096))
	for range 200 {
		_, _ = c.Write(chunk)
	}
	s, cut := c.Text()
	if !cut || len(s) > agentproto.MaxStreamBytes || !strings.Contains(s, "bytes omitted") {
		t.Errorf("len %d cut %v", len(s), cut)
	}
	// Binary output that grows when repaired is cut to the limit.
	c = newCapture()
	_, _ = c.Write([]byte(strings.Repeat("\xff", agentproto.StreamHead)))
	if s, _ := c.Text(); len(s) > agentproto.MaxStreamBytes || !utf8.ValidString(s) {
		t.Errorf("len %d", len(s))
	}
}

// Params reach the script on standard input only (ADR-0073): its argv and
// environment, read from /proc by the script itself, never hold them.
func TestExecuteDeliversParamsOnStdinOnly(t *testing.T) {
	const secret = "hunter2-Zq9"
	p := payload("sh", `cat; echo
echo "argv:$(tr '\0' ' ' < /proc/$$/cmdline)"
echo "env:$(tr '\0' ' ' < /proc/$$/environ)"
ls -l /proc/$$/fd/0 | sed 's/.*-> //'`, "x")
	p.V, p.Params = agentproto.JobPayloadVersionParams, []byte(`{"name":"a","password":"`+secret+`"}`)
	res := Execute(context.Background(), p, t.TempDir())
	if res.Status != agentproto.RunSucceeded {
		t.Fatalf("result %+v", res)
	}
	lines := strings.Split(res.Stdout, "\n")
	if lines[0] != string(p.Params) {
		t.Errorf("stdin = %q", lines[0])
	}
	rest := strings.Join(lines[1:], "\n")
	if strings.Contains(rest, secret) || strings.Contains(rest, `"name"`) {
		t.Errorf("params outside stdin: %q", rest)
	}
	if !strings.Contains(rest, "argv:") || !strings.Contains(rest, "pipe:") {
		t.Errorf("stdin is not a pipe, or argv unread: %q", rest)
	}
	if strings.Contains(res.Stderr, secret) {
		t.Errorf("stderr: %q", res.Stderr)
	}
	// Without params the script's stdin is empty, as before.
	res = Execute(context.Background(), payload("sh", "cat; echo done"), t.TempDir())
	if res.Stdout != "done\n" {
		t.Errorf("stdin without params: %q", res.Stdout)
	}
}
