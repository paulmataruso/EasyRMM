package auditfwd

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
)

// rfc5424 splits a message into PRI, VERSION, TIMESTAMP, HOSTNAME, APP-NAME,
// PROCID, MSGID, STRUCTURED-DATA and MSG.
var rfc5424 = regexp.MustCompile(`^<(\d{1,3})>(1) (\S+) (\S+) (\S+) (\S+) (\S+) ((?:\[(?:[^\]\\]|\\.)*\])+|-) (.*)$`)

func parse(t *testing.T, m string) []string {
	t.Helper()
	p := rfc5424.FindStringSubmatch(m)
	if p == nil {
		t.Fatalf("not an RFC 5424 message: %q", m)
	}
	return p[1:]
}

func sample() stored {
	actor := uuid.MustParse("6f1f3c47-1a2b-4c3d-8e9f-001122334455")
	org := uuid.MustParse("7a2b3c4d-0000-4000-8000-000000000001")
	ip := netip.MustParseAddr("192.0.2.10")
	return stored{
		Entry: audit.Entry{
			ID: 42, OccurredAt: time.Date(2026, 11, 16, 7, 53, 1, 123456000, time.FixedZone("x", 3600)),
			ActorType: audit.ActorUser, ActorID: &actor, ActorLabel: "tech@msp.example", OrganizationID: &org,
			Action: "device.remote_session", TargetType: "device", TargetID: "pc-01", Outcome: audit.Success,
			SourceIP: &ip, UserAgent: "Mozilla/5.0", Details: map[string]any{"kind": "terminal", "note": "ünïcode \"quoted\""},
		},
		prevHash: []byte{0xab, 0xcd}, entryHash: []byte{0x01, 0x02, 0x03},
	}
}

func TestMessage(t *testing.T) {
	f := newFormatter(13, "rmm.example.com", "1.4.0")
	m, err := f.message(sample(), maxFrame)
	if err != nil {
		t.Fatal(err)
	}
	p := parse(t, string(m))
	want := []string{"110", "1", "2026-11-16T06:53:01.123456Z", "rmm.example.com", "easyrmm", "-", "device.remote_session", `[origin software="EasyRMM" swVersion="1.4.0"]`}
	for i, w := range want {
		if p[i] != w {
			t.Errorf("field %d = %q, want %q", i, p[i], w)
		}
	}
	if strings.HasPrefix(p[8], "\xef\xbb\xbf") {
		t.Error("MSG starts with a byte order mark")
	}
	var r map[string]any
	if err := json.Unmarshal([]byte(p[8]), &r); err != nil {
		t.Fatalf("MSG is not JSON: %v", err)
	}
	if r["id"] != float64(42) || r["action"] != "device.remote_session" || r["actorLabel"] != "tech@msp.example" ||
		r["sourceIp"] != "192.0.2.10" || r["outcome"] != "success" || r["entryHash"] != "010203" || r["prevHash"] != "abcd" ||
		r["organizationId"] != "7a2b3c4d-0000-4000-8000-000000000001" {
		t.Errorf("record %v", r)
	}
	if d := r["details"].(map[string]any); d["note"] != "ünïcode \"quoted\"" {
		t.Errorf("details %v", d)
	}

	// Severity follows the outcome; the facility is the administrator's.
	s := sample()
	s.Outcome, s.prevHash, s.Details = audit.Failure, nil, nil
	m, _ = newFormatter(16, "h", "v").message(s, maxFrame)
	if p := parse(t, string(m)); p[0] != "133" || strings.Contains(p[8], "prevHash") || !strings.Contains(p[8], `"details":{}`) {
		t.Errorf("failure: %q", m)
	}
	s.Outcome = audit.Denied
	m, _ = newFormatter(4, "h", "v").message(s, maxFrame)
	if p := parse(t, string(m)); p[0] != "36" {
		t.Errorf("denied PRI %q", p[0])
	}
}

func TestMessageFitsItsTransport(t *testing.T) {
	s := sample()
	s.Details = map[string]any{"script": strings.Repeat("x", 12000)}
	s.UserAgent = strings.Repeat("u", 500)
	f := newFormatter(13, "h", "v")
	full, _ := f.message(s, maxFrame)
	if !strings.Contains(string(full), strings.Repeat("x", 12000)) {
		t.Fatal("stream message lost its details")
	}
	short, _ := f.message(s, maxDatagram)
	if len(short) > maxDatagram {
		t.Fatalf("datagram of %d bytes", len(short))
	}
	var r map[string]any
	_ = json.Unmarshal([]byte(parse(t, string(short))[8]), &r)
	d := r["details"].(map[string]any)
	if d["truncated"] != true || d["size"].(float64) < 12000 || len(r["userAgent"].(string)) != 256 || r["entryHash"] != "010203" {
		t.Errorf("shortened record %v", r)
	}
}

func TestHeaderFields(t *testing.T) {
	for in, want := range map[string]string{
		"":                      "-",
		"rmm host":              "rmm_host",
		"hôte":                  "h__te",
		strings.Repeat("a", 40): strings.Repeat("a", 32),
	} {
		if got := headerField(in, 32); got != want {
			t.Errorf("headerField(%q) = %q, want %q", in, got, want)
		}
	}
	if got := sdEscape(`a"b]c\d`); got != `a\"b\]c\\d` {
		t.Errorf("sdEscape = %q", got)
	}
	f := newFormatter(13, "", strings.Repeat("9", 60))
	if f.hostname != "-" || !strings.Contains(f.sd, `swVersion="`+strings.Repeat("9", 48)+`"]`) {
		t.Errorf("formatter %+v", f)
	}
	if f := newFormatter(13, "h", ""); !strings.Contains(f.sd, `swVersion="dev"`) {
		t.Errorf("no version: %s", f.sd)
	}
	if got := string(frame([]byte("<14>1 hello"))); got != "11 <14>1 hello" {
		t.Errorf("frame = %q", got)
	}
}

func TestValidHost(t *testing.T) {
	for _, h := range []string{"collector.example.com", "siem", "10.0.0.5", "2001:db8::1", "a-b.example.com."} {
		if !validHost(h) {
			t.Errorf("%q refused", h)
		}
	}
	for _, h := range []string{"https://siem", "siem:514", "-bad.example.com", "two words", "a..b", strings.Repeat("a", 64) + ".com"} {
		if validHost(h) {
			t.Errorf("%q accepted", h)
		}
	}
}
