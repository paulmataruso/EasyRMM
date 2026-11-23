package logship

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/logredact"
)

// Handler is a slog.Handler that writes through to another handler, which
// keeps the agent's log where it always was (the journal, or the log file
// on Windows), and hands each record to the Shipper too. It logs at the
// Shipper's level: Info, or Debug while the device is verbose.
type Handler struct {
	inner  slog.Handler
	ship   *Shipper
	attrs  []slog.Attr
	groups []string
}

// NewHandler returns the handler for the Shipper in front of inner.
func NewHandler(inner slog.Handler, s *Shipper) *Handler { return &Handler{inner: inner, ship: s} }

// Enabled reports whether a record of level is logged.
func (h *Handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.ship.Level.Level()
}

// Handle logs the record and queues it for the server.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	err := h.inner.Handle(ctx, r)
	h.ship.add(h.convert(r))
	return err
}

// WithAttrs returns a handler whose records carry attrs too.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	n := *h
	n.inner = h.inner.WithAttrs(attrs)
	n.attrs = append(append([]slog.Attr(nil), h.attrs...), qualify(h.groups, attrs)...)
	return &n
}

// WithGroup returns a handler that names later attributes under name.
func (h *Handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	n := *h
	n.inner = h.inner.WithGroup(name)
	n.groups = append(append([]string(nil), h.groups...), name)
	return &n
}

// qualify prefixes the attributes' names with the groups they are in.
func qualify(groups []string, attrs []slog.Attr) []slog.Attr {
	if len(groups) == 0 {
		return attrs
	}
	prefix := strings.Join(groups, ".") + "."
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = slog.Attr{Key: prefix + a.Key, Value: a.Value}
	}
	return out
}

// convert makes the record the server stores, redacted and bounded.
func (h *Handler) convert(r slog.Record) agentproto.LogRecord {
	rec := agentproto.LogRecord{
		Time:    r.Time.UTC(),
		Source:  agentproto.LogSourceAgent,
		Level:   levelName(r.Level),
		Message: Clip(logredact.Text(r.Message), agentproto.MaxLogMessage),
	}
	if rec.Time.IsZero() {
		rec.Time = time.Now().UTC()
	}
	add := func(prefix string, a slog.Attr) {
		flatten(prefix, a, func(k, v string) {
			if len(rec.Attrs) >= agentproto.MaxLogAttributes {
				return
			}
			if rec.Attrs == nil {
				rec.Attrs = map[string]string{}
			}
			k = Clip(k, agentproto.MaxLogAttrName)
			rec.Attrs[k] = logredact.Attr(k, Clip(v, agentproto.MaxLogAttrValue))
		})
	}
	for _, a := range h.attrs {
		add("", a)
	}
	r.Attrs(func(a slog.Attr) bool {
		for _, a := range qualify(h.groups, []slog.Attr{a}) {
			add("", a)
		}
		return true
	})
	return rec
}

// flatten calls emit for an attribute, or for each of a group's members
// named group.key.
func flatten(prefix string, a slog.Attr, emit func(k, v string)) {
	v := a.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		p := prefix
		if a.Key != "" {
			p += a.Key + "."
		}
		for _, m := range v.Group() {
			flatten(p, m, emit)
		}
		return
	}
	if a.Key == "" {
		return
	}
	emit(prefix+a.Key, v.String())
}

func levelName(l slog.Level) string {
	switch {
	case l < slog.LevelInfo:
		return agentproto.LogDebug
	case l < slog.LevelWarn:
		return agentproto.LogInfo
	case l < slog.LevelError:
		return agentproto.LogWarn
	}
	return agentproto.LogError
}

// Clip cuts s to at most n bytes at a character boundary.
func Clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !validTail(s) {
		s = s[:len(s)-1]
	}
	return s
}

// validTail reports whether s does not end in half a character.
func validTail(s string) bool {
	for i := len(s) - 1; i >= 0 && i >= len(s)-4; i-- {
		c := s[i]
		if c < 0x80 {
			return true
		}
		if c >= 0xC0 {
			need := 2
			switch {
			case c >= 0xF0:
				need = 4
			case c >= 0xE0:
				need = 3
			}
			return len(s)-i >= need
		}
	}
	return true
}
