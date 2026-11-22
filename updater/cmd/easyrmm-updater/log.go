package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
)

// journalSocket is journald's native socket.
const journalSocket = "/run/systemd/journal/socket"

// newLogger logs to w and, when the updater does not run as a systemd
// service (whose output journald already takes), to the journal too, so
// that every attempt is in the journal however it was started:
// journalctl -t easyrmm-updater.
func newLogger(w io.Writer) *slog.Logger {
	text := slog.NewTextHandler(w, nil)
	if os.Getenv("JOURNAL_STREAM") != "" {
		return slog.New(text)
	}
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "unixgram", journalSocket)
	if err != nil {
		return slog.New(text)
	}
	return slog.New(teeHandler{text, newJournalHandler(conn)})
}

// teeHandler hands each record to both handlers.
type teeHandler struct{ a, b slog.Handler }

func (t teeHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return t.a.Enabled(ctx, l) || t.b.Enabled(ctx, l)
}

func (t teeHandler) Handle(ctx context.Context, r slog.Record) error {
	errA := t.a.Handle(ctx, r.Clone())
	errB := t.b.Handle(ctx, r)
	if errA != nil {
		return errA
	}
	return errB
}

func (t teeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return teeHandler{t.a.WithAttrs(attrs), t.b.WithAttrs(attrs)}
}

func (t teeHandler) WithGroup(name string) slog.Handler {
	return teeHandler{t.a.WithGroup(name), t.b.WithGroup(name)}
}

// journalHandler sends each record to journald as one entry, in
// journald's native protocol, with its priority and the updater's name.
type journalHandler struct {
	conn  io.Writer
	state *journalState
	text  slog.Handler
}

// journalState is shared by a handler and those made from it with
// WithAttrs and WithGroup: the text handler writes into buf, under mu.
type journalState struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func newJournalHandler(conn io.Writer) journalHandler {
	st := &journalState{}
	// The time is journald's own.
	text := slog.NewTextHandler(&st.buf, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})
	return journalHandler{conn: conn, state: st, text: text}
}

func (j journalHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return j.text.Enabled(ctx, l)
}

func (j journalHandler) Handle(ctx context.Context, r slog.Record) error {
	j.state.mu.Lock()
	defer j.state.mu.Unlock()
	j.state.buf.Reset()
	if err := j.text.Handle(ctx, r); err != nil {
		return err
	}
	// The text handler writes one line, its newlines quoted.
	msg := strings.TrimSuffix(j.state.buf.String(), "\n")
	entry := "SYSLOG_IDENTIFIER=easyrmm-updater\nPRIORITY=" + priority(r.Level) + "\nMESSAGE=" + msg + "\n"
	_, err := io.WriteString(j.conn, entry)
	return err
}

func (j journalHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return journalHandler{conn: j.conn, state: j.state, text: j.text.WithAttrs(attrs)}
}

func (j journalHandler) WithGroup(name string) slog.Handler {
	return journalHandler{conn: j.conn, state: j.state, text: j.text.WithGroup(name)}
}

// priority is syslog's priority for a level.
func priority(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "3"
	case l >= slog.LevelWarn:
		return "4"
	case l >= slog.LevelInfo:
		return "6"
	default:
		return "7"
	}
}
