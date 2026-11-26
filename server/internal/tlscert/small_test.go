package tlscert

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"math/big"
	"strings"
	"testing"
)

func TestZapLoggerWritesToTheServersLog(t *testing.T) {
	var buf bytes.Buffer
	zl := zapLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	zl.Debug("dropped")
	zl.With(zapString("a", "1")).Info("kept", zapString("name", "rmm.test"))
	zl.Warn("careful")
	zl.Error("broken")
	_ = zl.Sync()
	out := buf.String()
	if strings.Contains(out, "dropped") || !strings.Contains(out, "kept") || !strings.Contains(out, "name=rmm.test") || !strings.Contains(out, "a=1") ||
		!strings.Contains(out, "level=WARN") || !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "component=certmagic") {
		t.Fatalf("the log: %s", out)
	}
}

func TestSmallHelpers(t *testing.T) {
	if clip("abcdef", 4) != "abc…" || clip("ab", 4) != "ab" {
		t.Error("clip")
	}
	if orDefault("", "80") != "80" || orDefault("8080", "80") != "8080" {
		t.Error("orDefault")
	}
	if hostOfURL("https://acme.test/dir") != "acme.test" || hostOfURL("::bad::") == "" {
		t.Error("hostOfURL")
	}
	if got := serialHex(&x509.Certificate{SerialNumber: big.NewInt(255)}); got != "ff" {
		t.Error(got)
	}
	if got := serialHex(&x509.Certificate{Raw: []byte("x")}); len(got) != 16 {
		t.Error(got)
	}
	s := New(Deps{}, Settings{})
	held := false
	s.SetHeld(func() bool { return held })
	if err := s.permit(Row{}, kindRetry, t0); err != nil {
		t.Error(err)
	}
	held = true
	if err := s.permit(Row{}, kindRetry, t0); !errors.Is(err, ErrHeld) {
		t.Error(err)
	}
	// A service without alerts or an audit log does not fail.
	s.publish(context.Background(), Event{Key: "tls:x"})
	s.auditSystem(context.Background(), "tls.import", "", nil)
	if s.Managed("x.test") || s.set.Instance != "server" || s.set.Interval == 0 {
		t.Error("defaults")
	}
	if _, err := s.GetCertificate(nil); err == nil {
		t.Error("a service that has not started served a certificate")
	}
	if s.set.roots() != nil {
		t.Error("roots without a file are the system's")
	}
	if (Settings{RootsPEM: []byte(testCAPEM(t))}).roots() == nil {
		t.Error("roots with a file")
	}
	if got := s.Storage().Lost("none"); got == nil {
		t.Error("Lost")
	} else {
		select {
		case <-got:
		default:
			t.Error("a lock not held is lost")
		}
	}
	if _, err := s.Check(context.Background(), "x.test"); !errors.Is(err, ErrNoName) {
		t.Error("check of an unmanaged name")
	}
}
