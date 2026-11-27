package logblock

import (
	"strings"
	"testing"
	"time"
)

func TestSealOpenRoundTrip(t *testing.T) {
	base := time.Date(2026, 11, 27, 10, 30, 0, 0, time.UTC)
	evs := []Event{
		{Time: base.Add(40 * time.Minute), Level: "warn", ID: "4625", Message: "later", Fields: map[string]string{"user": "bob"}},
		{Time: base, Level: "info", ID: "4624", Message: "first", Sensitive: map[string]string{"cmd": "x --y"}},
		{Time: base.Add(time.Minute), Message: "no level", ID: "4624"},
	}
	b, err := Seal("windows.security", ClassSecurity, evs)
	if err != nil {
		t.Fatal(err)
	}
	if b.Count != 3 || !b.Start.Equal(base) || !b.End.Equal(base.Add(40*time.Minute)) {
		t.Fatalf("bounds: %+v", b)
	}
	if b.Facts.Levels["info"] != 2 || b.Facts.Levels["warn"] != 1 || b.Facts.IDs["4624"] != 2 {
		t.Fatalf("facts: %+v", b.Facts)
	}
	// 10:30 and 10:31 info share the 10:00 row; 11:10 warn is the 11:00 row.
	if len(b.Facts.Hourly) != 2 || b.Facts.Hourly[0].Count != 2 {
		t.Fatalf("hourly: %+v", b.Facts.Hourly)
	}
	got, err := Open(b.Codec, b.Data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Message != "first" || got[0].Sensitive["cmd"] != "x --y" || got[2].Fields["user"] != "bob" {
		t.Fatalf("events: %+v", got)
	}
	if got[0].Source != "windows.security" {
		t.Fatalf("source %q", got[0].Source)
	}
}

func TestSealCompresses(t *testing.T) {
	var evs []Event
	for i := range 2000 {
		evs = append(evs, Event{Time: time.Unix(int64(1_700_000_000+i), 0), Message: "An account was successfully logged on. Logon Type: 3"})
	}
	b, err := Seal("windows.security", ClassSecurity, evs)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Data)*5 > b.Raw {
		t.Fatalf("poor compression: %d of %d", len(b.Data), b.Raw)
	}
}

func TestSealRefuses(t *testing.T) {
	if _, err := Seal("a", ClassDebug, nil); err == nil {
		t.Error("empty block sealed")
	}
	if _, err := Seal("a", "forever", []Event{{}}); err == nil {
		t.Error("unknown class sealed")
	}
}

func TestSealCutsLongMessagesOnARune(t *testing.T) {
	msg := strings.Repeat("é", MaxMessage) // two bytes each
	b, err := Seal("linux.journal", ClassOperational, []Event{{Time: time.Now(), Message: msg}})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := Open(b.Codec, b.Data)
	if len(got) != 1 || len(got[0].Message) > MaxMessage || strings.ContainsRune(got[0].Message, '�') {
		t.Fatal("message not cut cleanly")
	}
}

func TestOpenIsBounded(t *testing.T) {
	if _, err := Open("lz4", nil); err == nil {
		t.Error("unknown codec opened")
	}
	// An event stream that inflates past the limit is refused: a few KiB of
	// compressed repeats stand for far more than MaxRaw.
	b, _ := Seal("x.y", ClassDebug, []Event{{Time: time.Now(), Message: "m"}})
	if _, err := Open(b.Codec, b.Data[:len(b.Data)/2]); err == nil {
		t.Error("a truncated block opened without error")
	}
}

func TestClassFor(t *testing.T) {
	for src, want := range map[string]string{
		"windows.security": ClassSecurity, "linux.audit": ClassSecurity, "linux.auth": ClassSecurity,
		"windows.system": ClassOperational, "linux.journal": ClassOperational, "app.debug": ClassDebug,
	} {
		if got := ClassFor(src); got != want {
			t.Errorf("%s: %s, want %s", src, got, want)
		}
	}
}
