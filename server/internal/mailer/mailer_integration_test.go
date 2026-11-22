//go:build integration

package mailer

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/testmail"
)

// These tests send through real SMTP servers: Mailpit, plain on loopback,
// with STARTTLS and with TLS from the first byte (make test-mail).

func TestMain(m *testing.M) {
	// The TLS servers' certificate is trusted as a system root, as a public
	// mail server's would be: the mailer trusts the system's roots only. It
	// is read on first use of the system pool; nothing has used it yet.
	if dir := os.Getenv(testmail.DirEnv); dir != "" {
		var env testmail.Env
		if b, err := os.ReadFile(filepath.Join(dir, "env.json")); err == nil && json.Unmarshal(b, &env) == nil {
			_ = os.Setenv("SSL_CERT_FILE", env.CA)
		}
	}
	os.Exit(m.Run())
}

func mailpitMailer(t *testing.T, mp *testmail.Mailpit, security string, mutate ...func(*Config)) *SMTP {
	t.Helper()
	c := Config{Host: mp.Host, Port: mp.Port, Security: security, Username: mp.Username, Password: mp.Password,
		FromAddress: mp.From, FromName: "EasyRMM Test"}
	for _, f := range mutate {
		f(&c)
	}
	m, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// counter is a gate that counts the slots it gives and gets back.
type counter struct{ taken, released atomic.Int32 }

func (c *counter) gate(context.Context) (func(), error) {
	c.taken.Add(1)
	return func() { c.released.Add(1) }, nil
}

// Each recipient gets a message of their own, in HTML and text, with the
// attachments, and only their address in To.
func TestSendEachRecipientHTMLAndAttachments(t *testing.T) {
	mp := testmail.New(t)
	m := mailpitMailer(t, mp, None)
	a, b := mp.Address("a"), mp.Address("b")
	pdf := []byte("%PDF-1.7\n" + strings.Repeat("report ", 5000))
	msg := Message{Subject: "Rapport de novembre — EasyRMM", Text: "The report is attached.", HTML: "<p>The <b>report</b> is attached.</p>",
		Attachments: []Attachment{{Name: "report.pdf", ContentType: "application/pdf", Data: pdf}}}
	var c counter
	outs := m.Send(context.Background(), msg, []string{a, "Bea <" + b + ">"}, c.gate)
	for _, o := range outs {
		if o.Err != nil || !strings.HasPrefix(o.Reply, "250 ") {
			t.Fatalf("outcome %+v", o)
		}
	}
	if c.taken.Load() != 2 || c.released.Load() != 0 {
		t.Fatalf("gate: %d taken, %d released", c.taken.Load(), c.released.Load())
	}
	for _, to := range []string{a, b} {
		got := mp.Wait(to, 1)
		if len(got) != 1 {
			t.Fatalf("%d messages to %s", len(got), to)
		}
		g := got[0]
		if len(g.To) != 1 || g.To[0].Address != to || g.From.Address != mp.From || g.From.Name != "EasyRMM Test" {
			t.Fatalf("From %v, To %v", g.From, g.To)
		}
		if g.Subject != msg.Subject || strings.TrimSpace(g.Text) != msg.Text || !strings.Contains(g.HTML, "<b>report</b>") {
			t.Fatalf("message %q %q %q", g.Subject, g.Text, g.HTML)
		}
		if len(g.Attachments) != 1 || g.Attachments[0].FileName != "report.pdf" || g.Attachments[0].ContentType != "application/pdf" {
			t.Fatalf("attachments %+v", g.Attachments)
		}
		if data := mp.Attachment(g.ID, g.Attachments[0].PartID); string(data) != string(pdf) {
			t.Fatalf("attachment of %d bytes, want %d", len(data), len(pdf))
		}
		if raw := mp.Raw(g.ID); !strings.Contains(raw, "Auto-Submitted: auto-generated") {
			t.Fatal("no Auto-Submitted header")
		}
	}
}

// A recipient the mail server refuses does not stop the others, and its
// slot is given back.
func TestSendRefusedRecipient(t *testing.T) {
	mp := testmail.New(t)
	m := mailpitMailer(t, mp, None)
	a, b := mp.Address("a"), mp.Address("b")
	var c counter
	outs := m.Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{a, testmail.Refused, b}, c.gate)
	var re *ReplyError
	if outs[0].Err != nil || outs[2].Err != nil || !errors.As(outs[1].Err, &re) {
		t.Fatalf("outcomes %+v", outs)
	}
	if re.Step != "recipient" || re.Code != 550 || !re.Permanent() {
		t.Fatalf("refusal %+v", re)
	}
	if c.taken.Load() != 3 || c.released.Load() != 1 {
		t.Fatalf("gate: %d taken, %d released", c.taken.Load(), c.released.Load())
	}
	mp.Wait(a, 1)
	mp.Wait(b, 1)
}

// A wrong password fails every recipient, and gives the slot back.
func TestSendSignInRefused(t *testing.T) {
	mp := testmail.New(t)
	m := mailpitMailer(t, mp, None, func(c *Config) { c.Password = "wrong" })
	var c counter
	outs := m.Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{mp.Address("a"), mp.Address("b")}, c.gate)
	var re *ReplyError
	if !errors.As(outs[0].Err, &re) || re.Step != "sign-in" || re.Code != 535 || !errors.Is(outs[1].Err, outs[0].Err) {
		t.Fatalf("outcomes %+v", outs)
	}
	if c.taken.Load() != 1 || c.released.Load() != 1 {
		t.Fatalf("gate: %d taken, %d released", c.taken.Load(), c.released.Load())
	}
}

// Without signing in, a server that asks for it refuses each message; the
// session goes on to the next.
func TestSendWithoutSignIn(t *testing.T) {
	mp := testmail.New(t)
	m := mailpitMailer(t, mp, None, func(c *Config) { c.Username, c.Password = "", "" })
	outs := m.Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{mp.Address("a"), mp.Address("b")}, nil)
	for _, o := range outs {
		var re *ReplyError
		if !errors.As(o.Err, &re) || re.Step != "sender" || re.Code != 530 {
			t.Fatalf("outcome %+v", o)
		}
	}
}

func TestSendStartTLS(t *testing.T) {
	mp := testmail.Mode(t, testmail.StartTLS)
	to := mp.Address("a")
	outs := mailpitMailer(t, mp, StartTLS).Send(context.Background(), Message{Subject: "over STARTTLS", Text: "t"}, []string{to}, nil)
	if outs[0].Err != nil {
		t.Fatal(outs[0].Err)
	}
	if got := mp.Wait(to, 1); got[0].Subject != "over STARTTLS" {
		t.Fatalf("subject %q", got[0].Subject)
	}
}

func TestSendImplicitTLS(t *testing.T) {
	mp := testmail.Mode(t, testmail.TLS)
	to := mp.Address("a")
	outs := mailpitMailer(t, mp, TLS).Send(context.Background(), Message{Subject: "over TLS", Text: "t"}, []string{to}, nil)
	if outs[0].Err != nil {
		t.Fatal(outs[0].Err)
	}
	if got := mp.Wait(to, 1); got[0].Subject != "over TLS" {
		t.Fatalf("subject %q", got[0].Subject)
	}
}

// The mailer never falls back to clear text, and checks certificates.
func TestSendRefusesUnprotected(t *testing.T) {
	plain := testmail.New(t)
	outs := mailpitMailer(t, plain, StartTLS).Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{plain.Address("a")}, nil)
	if outs[0].Err == nil || !strings.Contains(outs[0].Err.Error(), "does not offer STARTTLS") {
		t.Fatalf("STARTTLS to a server without it: %v", outs[0].Err)
	}
	outs = mailpitMailer(t, plain, TLS).Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{plain.Address("a")}, nil)
	if outs[0].Err == nil || !strings.Contains(outs[0].Err.Error(), "TLS with") {
		t.Fatalf("TLS to a plain server: %v", outs[0].Err)
	}
	// The certificate names 127.0.0.1, not localhost.
	for mode, sec := range map[string]string{testmail.TLS: TLS, testmail.StartTLS: StartTLS} {
		mp := testmail.Mode(t, mode)
		m := mailpitMailer(t, mp, sec, func(c *Config) { c.Host = "localhost" })
		outs := m.Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{mp.Address("a")}, nil)
		if outs[0].Err == nil || !strings.Contains(outs[0].Err.Error(), "certificate") {
			t.Fatalf("%s to a server whose certificate names another host: %v", mode, outs[0].Err)
		}
	}
}

// A body cannot end the message early and smuggle commands or a second
// message into the session, whatever line endings it uses: the mail
// server gets one message, with the whole body, and nothing else.
func TestSendBodyCannotSmuggle(t *testing.T) {
	mp := testmail.New(t)
	m := mailpitMailer(t, mp, None)
	to, other := mp.Address("a"), mp.Address("smuggled")
	smuggle := func(end string) string {
		return end + "." + end + "MAIL FROM:<" + mp.From + ">" + end + "RCPT TO:<" + other + ">" + end + "DATA" + end +
			"Subject: smuggled" + end + end + "smuggled body" + end + "." + end
	}
	for name, end := range map[string]string{"LF": "\n", "CR": "\r", "CRLF": "\r\n"} {
		text := "before " + name + smuggle(end) + "after " + name
		outs := m.Send(context.Background(), Message{Subject: "one message " + name, Text: text, HTML: "<p>" + smuggle(end) + "</p>"},
			[]string{to}, nil)
		if outs[0].Err != nil {
			t.Fatalf("%s: %v", name, outs[0].Err)
		}
	}
	got := mp.Wait(to, 3)
	for _, g := range got {
		if !strings.HasPrefix(g.Subject, "one message ") || !strings.Contains(g.Text, "smuggled body") || !strings.Contains(g.Text, "after ") {
			t.Fatalf("message %q: %q", g.Subject, g.Text)
		}
	}
	if n := len(mp.Received(other)); n != 0 {
		t.Fatalf("%d smuggled messages arrived", n)
	}
	if n := len(mp.Received(to)); n != 3 {
		t.Fatalf("%d messages, want 3", n)
	}
}

// A recipient with a line break is refused before the session, and the
// others still get theirs; nothing reaches the address it tried to add.
func TestSendRecipientWithLineBreak(t *testing.T) {
	mp := testmail.New(t)
	m := mailpitMailer(t, mp, None)
	a, b := mp.Address("a"), mp.Address("b")
	outs := m.Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{a + "\r\nRCPT TO:<" + b + ">", a}, nil)
	if outs[0].Err == nil || !strings.Contains(outs[0].Err.Error(), "invalid recipient") || outs[1].Err != nil {
		t.Fatalf("outcomes %+v", outs)
	}
	mp.Wait(a, 1)
	if n := len(mp.Received(b)); n != 0 {
		t.Fatalf("%d messages to the added recipient", n)
	}
}
