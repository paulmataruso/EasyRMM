package devscope

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestAllowed(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	if !Allowed(a) || !Allowed(uuid.Nil) || Active() {
		t.Fatal("with no scope, everything is allowed")
	}
	restore := Set(a)
	if !Active() || !Allowed(a) || Allowed(b) || Allowed(uuid.Nil) {
		t.Error("scope a: only a is allowed")
	}
	if org, ok := Org(); !ok || org != a {
		t.Errorf("Org = %v %v", org, ok)
	}
	restore()
	if Active() || !Allowed(b) {
		t.Error("restore removes the scope")
	}
	Set(a)()
	restore = Set(a)
	Set(uuid.Nil)
	if Active() {
		t.Error("Set(uuid.Nil) removes the scope")
	}
	restore()
}

func TestLogSaysWhichScopeApplies(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	Log(log)
	if !strings.Contains(buf.String(), "not set") {
		t.Errorf("unset: %q", buf.String())
	}
	org := uuid.New()
	defer Set(org)()
	buf.Reset()
	Log(log)
	if !strings.Contains(buf.String(), org.String()) || !strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("set: %q", buf.String())
	}
}
