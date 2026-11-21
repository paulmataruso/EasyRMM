// Package updater is the server's side of the updater on the host
// (ADR-0052). The updater writes its status into a directory that belongs
// to root and that Compose mounts read-only into the server; the server
// reads it and never writes it.
package updater

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

// HoldFile is the file in the status directory that holds the server while
// it exists: the updater writes it before it starts a new version and
// removes it once the upgrade is confirmed.
const HoldFile = "hold"

// RetryAfter is how many seconds a held server asks clients to wait.
const RetryAfter = 60

// heldMessage is what a held server answers.
const heldMessage = "EasyRMM is being upgraded. Try again in a few minutes."

// Hold follows the hold file. While it exists the server answers its
// health check and nothing else: every request to its edge gets 503 with
// Retry-After. It also tells when the server last began serving: when its
// listeners opened, or when a hold ended.
type Hold struct {
	path     string
	log      *slog.Logger
	now      func() time.Time
	interval time.Duration

	// held is read on every request; mu orders its changes and guards the
	// rest.
	held    atomic.Bool
	mu      sync.Mutex
	since   time.Time
	failure string // the error last logged, so that a lasting one is logged once
}

// NewHold reads the hold file in dir before the server opens its
// listeners. A server that is not held begins serving now. Without the
// directory or the file nothing is held.
func NewHold(dir string, log *slog.Logger) *Hold {
	h := &Hold{path: filepath.Join(dir, HoldFile), log: log, now: time.Now, interval: time.Second}
	h.since = h.now()
	h.check()
	return h
}

// Run follows the file, looking every second, until ctx ends.
func (h *Hold) Run(ctx context.Context) {
	tick := time.NewTicker(h.interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			h.check()
		}
	}
}

// check looks at the file. An error other than its absence holds the
// server: the updater may have written it.
func (h *Hold) check() {
	_, err := os.Lstat(h.path)
	held := err == nil
	h.mu.Lock()
	defer h.mu.Unlock()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		held = true
		if msg := err.Error(); msg != h.failure {
			h.failure = msg
			h.log.Error("cannot tell whether the updater holds the server, so it is held", "file", h.path, "error", err)
		}
	} else {
		h.failure = ""
	}
	if held == h.held.Load() {
		return
	}
	h.held.Store(held)
	if held {
		h.log.Warn("held by the updater: answering the health check only", "file", h.path)
		return
	}
	h.since = h.now()
	h.log.Info("no longer held by the updater: serving", "file", h.path)
}

// Held reports whether the server is held.
func (h *Hold) Held() bool { return h.held.Load() }

// ServingSince reports when the server last began serving, and false while
// it is held.
func (h *Hold) ServingSince() (time.Time, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.since, !h.held.Load()
}

// Handler passes requests to next, and answers 503 with Retry-After while
// the server is held: a JSON error, or plain text for a browser.
func (h *Hold) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.held.Load() {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Retry-After", strconv.Itoa(RetryAfter))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, heldMessage+"\n")
			return
		}
		httpapi.WriteJSON(w, http.StatusServiceUnavailable, httpapi.ErrorBody{Error: httpapi.ErrorDetail{Code: "held", Message: heldMessage}})
	})
}
