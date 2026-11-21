package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// logs collects what a Hold logs, from its own goroutine too.
type logs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *logs) count(s string) int { return strings.Count(l.String(), s) }

func newLogger() (*slog.Logger, *logs) {
	l := &logs{}
	return slog.New(slog.NewTextHandler(l, nil)), l
}

// response is one request to a held or serving server.
type response struct {
	status      int
	retryAfter  string
	contentType string
	body        string
}

// serve puts the hold in front of a handler that answers "served", on a
// real listener, as the edge does.
func serve(t *testing.T, h *Hold) func(accept string) response {
	t.Helper()
	srv := httptest.NewServer(h.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "served")
	})))
	t.Cleanup(srv.Close)
	return func(accept string) response {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/api/v1/health", nil)
		if err != nil {
			t.Fatal(err)
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return response{resp.StatusCode, resp.Header.Get("Retry-After"), resp.Header.Get("Content-Type"), string(b)}
	}
}

// wantHeld checks the answers of a held server: a JSON error for clients,
// plain text for a browser, both 503 with Retry-After.
func wantHeld(t *testing.T, get func(string) response) {
	t.Helper()
	r := get("application/json")
	var body struct {
		Error struct{ Code, Message string }
	}
	if err := json.Unmarshal([]byte(r.body), &body); err != nil {
		t.Fatalf("held: %q is not JSON: %v", r.body, err)
	}
	if r.status != http.StatusServiceUnavailable || r.retryAfter != "60" || body.Error.Code != "held" || body.Error.Message != heldMessage {
		t.Fatalf("held: %+v", r)
	}
	r = get("text/html,application/xhtml+xml;q=0.9")
	if r.status != http.StatusServiceUnavailable || r.retryAfter != "60" || !strings.HasPrefix(r.contentType, "text/plain") || r.body != heldMessage+"\n" {
		t.Fatalf("held, to a browser: %+v", r)
	}
}

func wantServed(t *testing.T, get func(string) response) {
	t.Helper()
	if r := get(""); r.status != http.StatusOK || r.body != "served" || r.retryAfter != "" {
		t.Fatalf("not held: %+v", r)
	}
}

// eventually waits for cond, as Run looks at the file on its own schedule.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: timed out", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func run(t *testing.T, h *Hold) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.Run(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Run did not stop")
		}
	})
}

func TestWithoutTheUpdater(t *testing.T) {
	log, l := newLogger()
	before := time.Now()
	h := NewHold(filepath.Join(t.TempDir(), "no-such-directory"), log)
	if h.Held() {
		t.Fatal("held without the status directory")
	}
	since, serving := h.ServingSince()
	if !serving || since.Before(before) || since.After(time.Now()) {
		t.Fatalf("serving since %v, %v; want from its start", since, serving)
	}
	wantServed(t, serve(t, h))
	if l.count("level=") != 0 {
		t.Fatalf("logged without the updater: %s", l.String())
	}
}

func TestHoldWhileRunning(t *testing.T) {
	dir := t.TempDir()
	log, l := newLogger()
	h := NewHold(dir, log)
	h.interval = 10 * time.Millisecond
	get := serve(t, h)
	clock := time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)
	h.mu.Lock()
	h.now = func() time.Time { return clock }
	h.mu.Unlock()
	start, _ := h.ServingSince()
	run(t, h)
	wantServed(t, get)

	// The updater writes the file: the server is held within a moment.
	hold := filepath.Join(dir, HoldFile)
	if err := os.WriteFile(hold, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	eventually(t, "entering hold", h.Held)
	wantHeld(t, get)
	if _, serving := h.ServingSince(); serving {
		t.Fatal("serving while held")
	}
	if l.count("held by the updater") != 1 {
		t.Fatalf("entering hold not logged once: %s", l.String())
	}

	// It removes it: the server serves again, from that moment.
	h.mu.Lock()
	clock = clock.Add(7 * time.Minute)
	h.mu.Unlock()
	if err := os.Remove(hold); err != nil {
		t.Fatal(err)
	}
	eventually(t, "leaving hold", func() bool { return !h.Held() })
	wantServed(t, get)
	since, serving := h.ServingSince()
	if !serving || !since.Equal(clock) || !since.After(start) {
		t.Fatalf("serving since %v, %v; want %v, when the hold ended", since, serving, clock)
	}
	if l.count("no longer held by the updater") != 1 {
		t.Fatalf("leaving hold not logged once: %s", l.String())
	}
}

func TestHeldFromStart(t *testing.T) {
	dir := t.TempDir()
	// A link counts: it is an entry named hold, wherever it points.
	if err := os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(dir, HoldFile)); err != nil {
		t.Fatal(err)
	}
	log, l := newLogger()
	h := NewHold(dir, log)
	if !h.Held() {
		t.Fatal("not held with the file there before the start")
	}
	wantHeld(t, serve(t, h))
	if _, serving := h.ServingSince(); serving {
		t.Fatal("serving while held from the start")
	}
	if l.count("held by the updater") != 1 {
		t.Fatalf("hold at the start not logged: %s", l.String())
	}
}

func TestCannotTellHolds(t *testing.T) {
	// The status directory's path names a file, so the hold file cannot be
	// looked at: not "not there", so the server is held.
	parent := t.TempDir()
	dir := filepath.Join(parent, "status")
	if err := os.WriteFile(dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	log, l := newLogger()
	h := NewHold(dir, log)
	if !h.Held() {
		t.Fatal("not held although the file could not be looked at")
	}
	wantHeld(t, serve(t, h))
	h.check()
	if n := l.count("cannot tell whether the updater holds the server"); n != 1 {
		t.Fatalf("the same error logged %d times: %s", n, l.String())
	}

	// Once the directory is there, without the file, the server serves.
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	h.check()
	if h.Held() {
		t.Fatal("still held with the directory there and no file")
	}
	// The error coming back is logged again.
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h.check()
	if !h.Held() || l.count("cannot tell whether the updater holds the server") != 2 {
		t.Fatalf("a new failure: held %v, %s", h.Held(), l.String())
	}
}
