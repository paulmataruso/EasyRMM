package tlscert

import (
	"context"
	"log/slog"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// zapLogger gives CertMagic, which logs through zap, a logger that writes to
// the server's log. CertMagic logs names, times and errors; it never logs a
// key. Its debug lines are dropped.
func zapLogger(log *slog.Logger) *zap.Logger {
	return zap.New(&slogCore{log: log.With("component", "certmagic")})
}

type slogCore struct {
	log    *slog.Logger
	fields []zapcore.Field
}

func (c *slogCore) Enabled(l zapcore.Level) bool { return l >= zapcore.InfoLevel }

func (c *slogCore) With(f []zapcore.Field) zapcore.Core {
	return &slogCore{log: c.log, fields: append(append([]zapcore.Field{}, c.fields...), f...)}
}

func (c *slogCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(e.Level) {
		return ce.AddCore(e, c)
	}
	return ce
}

func (c *slogCore) Write(e zapcore.Entry, fields []zapcore.Field) error {
	enc := zapcore.NewMapObjectEncoder()
	for _, f := range c.fields {
		f.AddTo(enc)
	}
	for _, f := range fields {
		f.AddTo(enc)
	}
	attrs := make([]any, 0, len(enc.Fields)*2)
	for k, v := range enc.Fields {
		attrs = append(attrs, k, v)
	}
	level := slog.LevelInfo
	switch {
	case e.Level >= zapcore.ErrorLevel:
		level = slog.LevelError
	case e.Level == zapcore.WarnLevel:
		level = slog.LevelWarn
	}
	c.log.Log(context.Background(), level, e.Message, attrs...)
	return nil
}

func (c *slogCore) Sync() error { return nil }
