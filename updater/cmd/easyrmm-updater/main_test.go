package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/updater/internal/host"
)

func runTest(t *testing.T, euid int, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runWith(args, env{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, euid: euid,
		newUpdater: func(*host.Config, *slog.Logger) *host.Updater {
			t.Fatal("an updater was made")
			return nil
		},
	})
	return code, stdout.String(), stderr.String()
}

func TestRunUsage(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{nil, 2, "usage: easyrmm-updater"},
		{[]string{"--nonsense"}, 2, "usage"},
		{[]string{"frobnicate"}, 2, `unknown command "frobnicate"`},
		{[]string{"status", "extra"}, 2, "status takes 0 arguments"},
		{[]string{"check", "--verbose"}, 2, "flag provided but not defined"},
		{[]string{"upgrade", "v1.0.0", "v1.1.0"}, 2, "upgrade takes 1 arguments"},
		{[]string{"upgrade", "--automatic", "v1.0.0"}, 2, "takes no version"},
		{[]string{"upgrade", "--automatic", "--deployment-repaired"}, 2, "only an operator says so"},
		{[]string{"status", "--deployment-repaired"}, 2, "flag provided but not defined"},
		{[]string{"upgrade", "--deployment-repaired"}, 1, "runs as root"},
		{[]string{"rollback", "--deployment-repaired", "--yes"}, 1, "runs as root"},
		{[]string{"upgrade", "latest"}, 2, "latest"},
		{[]string{"rollback", "v1.0.0"}, 2, "rollback takes 0 arguments"},
		{[]string{"upgrade", "v1.1.0"}, 1, "runs as root"},
		{[]string{"rollback", "--yes"}, 1, "runs as root"},
		{[]string{"status"}, 1, "runs as root"},
	} {
		code, _, stderr := runTest(t, 1000, tc.args...)
		if code != tc.code || !strings.Contains(stderr, tc.want) {
			t.Errorf("%v: exit %d, %q; want %d, %q", tc.args, code, stderr, tc.code, tc.want)
		}
	}
	code, stdout, _ := runTest(t, 1000, "version")
	if code != 0 || stdout != Version+testBuildNote+"\n" {
		t.Errorf("version: %d %q", code, stdout)
	}
}

func TestRunConfiguration(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "updater.conf")
	code, _, stderr := runTest(t, 0, "--config", missing, "status")
	if code != 1 || !strings.Contains(stderr, "configuration:") {
		t.Errorf("a missing configuration: %d %q", code, stderr)
	}
	// The tests' files are not root's: refused.
	path := filepath.Join(t.TempDir(), "updater.conf")
	if err := os.WriteFile(path, []byte("deployment = /d\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(path, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	if code, _, stderr := runTest(t, 0, "--config", path, "check"); code != 1 || !strings.Contains(stderr, "does not belong to root") {
		t.Errorf("another user's configuration: %d %q", code, stderr)
	}
}

func TestBy(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	if got := by(); got != "root on the host" {
		t.Errorf("by = %q", got)
	}
	t.Setenv("SUDO_USER", "paul")
	if got := by(); got != "root on the host (sudo from paul)" {
		t.Errorf("by = %q", got)
	}
	t.Setenv("SUDO_USER", "x\ny")
	if got := by(); got != "root on the host" {
		t.Errorf("by = %q", got)
	}
}

// The journal gets one entry per record, in journald's native protocol.
func TestJournalHandler(t *testing.T) {
	var conn bytes.Buffer
	var text bytes.Buffer
	log := slog.New(teeHandler{slog.NewTextHandler(&text, nil), newJournalHandler(&conn)})
	log.With("attempt", "ab12").WithGroup("g").Error("attempt ended", "reason", "line one\nline two")
	log.Warn("w")
	log.Info("i")
	entries := strings.SplitAfter(conn.String(), "MESSAGE=")
	if len(entries) != 4 {
		t.Fatalf("entries: %q", conn.String())
	}
	first := strings.SplitN(conn.String(), "\n", 4)
	if first[0] != "SYSLOG_IDENTIFIER=easyrmm-updater" || first[1] != "PRIORITY=3" ||
		!strings.Contains(first[2], `msg="attempt ended" attempt=ab12 g.reason="line one\nline two"`) || strings.Contains(first[2], "time=") {
		t.Errorf("first entry: %q", first)
	}
	if !strings.Contains(conn.String(), "PRIORITY=4\nMESSAGE=level=WARN msg=w\n") || !strings.Contains(conn.String(), "PRIORITY=6\nMESSAGE=level=INFO msg=i\n") {
		t.Errorf("entries: %q", conn.String())
	}
	if !strings.Contains(text.String(), "time=") || strings.Count(text.String(), "\n") != 3 {
		t.Errorf("text: %q", text.String())
	}
	if priority(slog.LevelDebug) != "7" {
		t.Error("debug")
	}
	if (teeHandler{slog.NewTextHandler(&text, nil), newJournalHandler(&conn)}).Enabled(context.Background(), slog.LevelDebug) {
		t.Error("debug enabled")
	}
	// A journal that cannot be written: the error is the handler's.
	h := teeHandler{slog.NewTextHandler(&text, nil), newJournalHandler(failingWriter{})}
	if err := h.Handle(context.Background(), slog.Record{Message: "x"}); err == nil {
		t.Error("a journal that fails")
	}
	h = teeHandler{newJournalHandler(failingWriter{}), slog.NewTextHandler(&text, nil)}
	if err := h.Handle(context.Background(), slog.Record{Message: "x"}); err == nil {
		t.Error("a journal that fails")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("no journal") }

// Without journald, or under systemd (whose journal takes the service's
// output), the updater logs only to its output.
func TestNewLogger(t *testing.T) {
	var out bytes.Buffer
	t.Setenv("JOURNAL_STREAM", "8:1234")
	newLogger(&out).Info("x", "k", "v")
	if !strings.Contains(out.String(), "msg=x k=v") {
		t.Errorf("output %q", out.String())
	}
	if _, ok := newLogger(&out).Handler().(*slog.TextHandler); !ok {
		t.Error("under systemd, a journal handler")
	}
	t.Setenv("JOURNAL_STREAM", "")
	l := newLogger(&out)
	if _, err := os.Stat(journalSocket); err != nil {
		if _, ok := l.Handler().(*slog.TextHandler); !ok {
			t.Error("without a journal, a journal handler")
		}
	} else if _, ok := l.Handler().(teeHandler); !ok {
		t.Error("with a journal, no journal handler")
	}
}

// Ctrl-C and systemd's stop cancel the attempt's context, which an attempt
// heeds only until it stops the deployment; a hang-up does nothing.
func TestStopSignals(t *testing.T) {
	var out syncBuffer
	ctx, stop := stopSignals(context.Background(), slog.New(slog.NewTextHandler(&out, nil)))
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if ctx.Err() != nil {
		t.Fatal("a hang-up canceled the attempt")
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("SIGTERM did not cancel the attempt")
	}
	if !strings.Contains(out.String(), "runs on to its end") {
		t.Errorf("log %q", out.String())
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// The commands, with an updater whose deployment is not there: each says
// why, changing nothing.
func TestCommands(t *testing.T) {
	dir := t.TempDir()
	u := newUpdater(&host.Config{Deployment: filepath.Join(dir, "deploy"), Channel: "stable", Hours: host.Hours{From: 0, To: 24}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	u.StateDir = filepath.Join(dir, "state")
	var stdout, stderr bytes.Buffer
	e := env{stdin: strings.NewReader("no\n"), stdout: &stdout, stderr: &stderr}
	ctx := context.Background()
	for _, c := range []*command{{name: "status"}, {name: "check"}, {name: "rollback"}, {name: "rollback", yes: true}} {
		stderr.Reset()
		if code := c.run(ctx, u, e, u.Log); code != 1 || stderr.Len() == 0 {
			t.Errorf("%s: exit %d, %q", c.name, code, stderr.String())
		}
	}
	// Automatic upgrades are off: nothing to do.
	if code := (&command{name: "upgrade", automatic: true}).run(ctx, u, e, u.Log); code != 0 {
		t.Errorf("upgrade --automatic: exit %d", code)
	}
	if code := (&command{name: "upgrade"}).run(ctx, u, e, u.Log); code != 1 {
		t.Errorf("upgrade without Docker's answer: exit %d", code)
	}
}
