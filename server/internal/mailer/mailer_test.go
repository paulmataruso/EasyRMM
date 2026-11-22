package mailer

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/netip"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// These tests need no mail server: they cover the configuration, the
// message as composed, and a server that never answers. The integration
// tests send through real ones (Mailpit).

func cfg(mutate ...func(*Config)) Config {
	c := Config{Host: "127.0.0.1", Port: 25, Security: None, FromAddress: "rmm@example.com", FromName: "EasyRMM"}
	for _, f := range mutate {
		f(&c)
	}
	return c
}

func TestNewValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*Config)
		want   string
	}{
		"no host":           {func(c *Config) { c.Host = "" }, "no mail server"},
		"port zero":         {func(c *Config) { c.Port = 0 }, "out of range"},
		"port too high":     {func(c *Config) { c.Port = 65536 }, "out of range"},
		"sender with name":  {func(c *Config) { c.FromAddress = "EasyRMM <rmm@example.com>" }, "sender's address"},
		"sender not mail":   {func(c *Config) { c.FromAddress = "rmm" }, "sender's address"},
		"name with newline": {func(c *Config) { c.FromName = "Easy\nRMM" }, "control character"},
		"unknown security":  {func(c *Config) { c.Security = "ssl" }, "unknown security"},
		"plain to remote":   {func(c *Config) { c.Host = "smtp.example.com" }, "only allowed to a relay on loopback"},
		"plain to private":  {func(c *Config) { c.Host = "10.0.0.5" }, "only allowed to a relay on loopback"},
		"user with newline": {func(c *Config) { c.Username, c.Password = "a\r\nRCPT", "x" }, "line break"},
		"password with NUL": {func(c *Config) { c.Username, c.Password = "a", "x\x00y" }, "line break"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(cfg(tc.mutate))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New: %v, want %q", err, tc.want)
			}
		})
	}
	for _, host := range []string{"localhost", "LOCALHOST", "127.0.0.1", "127.0.0.53", "::1"} {
		if _, err := New(cfg(func(c *Config) { c.Host = host })); err != nil {
			t.Errorf("plain SMTP to %s: %v", host, err)
		}
	}
	for _, sec := range []string{StartTLS, TLS} {
		m, err := New(cfg(func(c *Config) { c.Host, c.Security, c.Port = "smtp.example.com", sec, 587 }))
		if err != nil {
			t.Fatalf("%s to a remote server: %v", sec, err)
		}
		if m.cfg.Timeout != DefaultTimeout || m.Address() != "smtp.example.com:587" {
			t.Fatalf("timeout %v, address %s", m.cfg.Timeout, m.Address())
		}
	}
	m, _ := New(cfg(func(c *Config) { c.Host = "::1" }))
	if m.Address() != "[::1]:25" {
		t.Fatalf("address %s", m.Address())
	}
}

func TestBareAddressAndLoopback(t *testing.T) {
	for s, want := range map[string]bool{
		"rmm@example.com":              true,
		"first.last+tag@example.co":    true,
		"":                             false,
		"rmm":                          false,
		"<rmm@example.com>":            false,
		"EasyRMM <rmm@example.com>":    false,
		"a@example.org, c@example.net": false,
		" rmm@example.com":             false,
		strings.Repeat("a", 250) + "@example.org": false,
	} {
		if BareAddress(s) != want {
			t.Errorf("BareAddress(%q) = %v", s, !want)
		}
	}
	for h, want := range map[string]bool{"localhost": true, "127.0.0.1": true, "127.1.2.3": true, "::1": true,
		"10.0.0.1": false, "example.com": false, "localhost.example.com": false, "": false} {
		if Loopback(h) != want {
			t.Errorf("Loopback(%q) = %v", h, !want)
		}
	}
}

// parse reads a composed message back.
func parse(t *testing.T, data []byte) *mail.Message {
	t.Helper()
	if bytes.Contains(bytes.ReplaceAll(data, []byte("\r\n"), nil), []byte("\n")) {
		t.Fatal("a line ends in LF alone")
	}
	for _, line := range strings.Split(string(data), "\r\n") {
		if len(line) > 998 {
			t.Fatalf("a line of %d characters", len(line))
		}
	}
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func readQP(t *testing.T, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(quotedprintable.NewReader(r))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestComposeText(t *testing.T) {
	m, _ := New(cfg())
	to := &mail.Address{Name: "Zoë", Address: "zoe@example.org"}
	subject := "Réinitialisez votre mot de passe EasyRMM — " + strings.Repeat("très long ", 12)
	data := m.compose(to, Message{Subject: subject, Text: "Line one\nLine two é\n"}, time.Date(2026, 11, 21, 8, 0, 0, 0, time.UTC))
	for _, line := range strings.Split(string(data[:bytes.Index(data, []byte("\r\n\r\n"))]), "\r\n") {
		if len(line) > 78 {
			t.Errorf("header line of %d characters: %q", len(line), line)
		}
	}
	msg := parse(t, data)
	h := msg.Header
	var dec mime.WordDecoder
	got, err := dec.DecodeHeader(h.Get("Subject"))
	if err != nil || got != subject {
		t.Fatalf("subject %q (%v)", got, err)
	}
	if from, _ := h.AddressList("From"); len(from) != 1 || from[0].Name != "EasyRMM" || from[0].Address != "rmm@example.com" {
		t.Fatalf("From %v", from)
	}
	if rcpt, _ := h.AddressList("To"); len(rcpt) != 1 || rcpt[0].Name != "Zoë" || rcpt[0].Address != "zoe@example.org" {
		t.Fatalf("To %v", rcpt)
	}
	if d, err := h.Date(); err != nil || !d.Equal(time.Date(2026, 11, 21, 8, 0, 0, 0, time.UTC)) {
		t.Fatalf("Date %v %v", d, err)
	}
	if id := h.Get("Message-ID"); !strings.HasPrefix(id, "<") || !strings.HasSuffix(id, "@example.com>") || len(id) != len("<@example.com>")+32 {
		t.Fatalf("Message-ID %q", id)
	}
	if h.Get("Auto-Submitted") != "auto-generated" || h.Get("MIME-Version") != "1.0" {
		t.Fatalf("headers %v", h)
	}
	if h.Get("Content-Type") != "text/plain; charset=utf-8" || h.Get("Content-Transfer-Encoding") != "quoted-printable" {
		t.Fatalf("content headers %v", h)
	}
	if body := readQP(t, msg.Body); body != "Line one\r\nLine two é\r\n" {
		t.Fatalf("body %q", body)
	}
	// Each message gets its own ID.
	again := m.compose(to, Message{Subject: "s", Text: "t"}, time.Now())
	if parse(t, again).Header.Get("Message-ID") == h.Get("Message-ID") {
		t.Fatal("two messages with one Message-ID")
	}
}

// part is one part of a multipart body.
type part struct {
	Header textproto.MIMEHeader
	Body   []byte
}

// FileName is the attachment's file name.
func (p part) FileName() string {
	_, params, _ := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
	return params["filename"]
}

// parts reads a multipart body.
func parts(t *testing.T, contentType string, body io.Reader) []part {
	t.Helper()
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.HasPrefix(mt, "multipart/") {
		t.Fatalf("content type %q (%v)", contentType, err)
	}
	r := multipart.NewReader(body, params["boundary"])
	var out []part
	for {
		p, err := r.NextRawPart()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(p)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, part{Header: p.Header, Body: b})
	}
}

func TestComposeHTMLAndAttachments(t *testing.T) {
	m, _ := New(cfg())
	pdf := bytes.Repeat([]byte("%PDF-1.7 \x00\xff"), 200)
	msg := Message{Subject: "Monthly report", Text: "See the report.", HTML: "<p>See the <b>report</b>.</p>",
		Attachments: []Attachment{{Name: "report november.pdf", ContentType: "application/pdf", Data: pdf}, {Name: "data.bin", Data: []byte{1, 2, 3}}}}
	data := m.compose(&mail.Address{Address: "a@example.org"}, msg, time.Now())
	top := parse(t, data)
	mixed := parts(t, top.Header.Get("Content-Type"), top.Body)
	if !strings.HasPrefix(top.Header.Get("Content-Type"), "multipart/mixed;") || len(mixed) != 3 {
		t.Fatalf("%s with %d parts", top.Header.Get("Content-Type"), len(mixed))
	}
	alt := parts(t, mixed[0].Header.Get("Content-Type"), bytes.NewReader(mixed[0].Body))
	if !strings.HasPrefix(mixed[0].Header.Get("Content-Type"), "multipart/alternative;") || len(alt) != 2 {
		t.Fatalf("body %s with %d parts", mixed[0].Header.Get("Content-Type"), len(alt))
	}
	if alt[0].Header.Get("Content-Type") != "text/plain; charset=utf-8" || readQP(t, bytes.NewReader(alt[0].Body)) != "See the report." {
		t.Fatalf("text part %v %q", alt[0].Header, alt[0].Body)
	}
	if alt[1].Header.Get("Content-Type") != "text/html; charset=utf-8" || readQP(t, bytes.NewReader(alt[1].Body)) != msg.HTML {
		t.Fatalf("HTML part %v %q", alt[1].Header, alt[1].Body)
	}
	for i, a := range msg.Attachments {
		p := mixed[i+1]
		if p.FileName() != a.Name || p.Header.Get("Content-Transfer-Encoding") != "base64" {
			t.Fatalf("attachment %d: %v", i, p.Header)
		}
		mt, params, _ := mime.ParseMediaType(p.Header.Get("Content-Type"))
		want := a.ContentType
		if want == "" {
			want = "application/octet-stream"
		}
		if mt != want || params["name"] != a.Name {
			t.Fatalf("attachment %d type %q %v", i, mt, params)
		}
		for _, line := range strings.Split(strings.TrimRight(string(p.Body), "\r\n"), "\r\n") {
			if len(line) > 76 {
				t.Fatalf("base64 line of %d characters", len(line))
			}
		}
		got, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(p.Body), "\r\n", ""))
		if err != nil || !bytes.Equal(got, a.Data) {
			t.Fatalf("attachment %d content differs (%v)", i, err)
		}
	}

	// Text alone with an attachment: the text is the first part.
	data = m.compose(&mail.Address{Address: "a@example.org"}, Message{Subject: "s", Text: "t", Attachments: msg.Attachments[1:]}, time.Now())
	top = parse(t, data)
	mixed = parts(t, top.Header.Get("Content-Type"), top.Body)
	if len(mixed) != 2 || mixed[0].Header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("%d parts, first %v", len(mixed), mixed[0].Header)
	}
}

func TestMessageCheck(t *testing.T) {
	for name, tc := range map[string]struct {
		msg  Message
		want string
	}{
		"subject line break":  {Message{Subject: "a\r\nBcc: x@example.com"}, "line break"},
		"subject too long":    {Message{Subject: strings.Repeat("é", MaxSubject+1)}, "longer than"},
		"not UTF-8":           {Message{Subject: "s", Text: "\xff"}, "not UTF-8"},
		"attachment no name":  {Message{Attachments: []Attachment{{Data: []byte("x")}}}, "attachment name"},
		"attachment path":     {Message{Attachments: []Attachment{{Name: "../x.pdf"}}}, "attachment name"},
		"attachment newline":  {Message{Attachments: []Attachment{{Name: "x\n.pdf"}}}, "attachment name"},
		"attachment type":     {Message{Attachments: []Attachment{{Name: "x.pdf", ContentType: "not a type"}}}, "media type"},
		"attachments too big": {Message{Attachments: []Attachment{{Name: "a", Data: make([]byte, MaxAttachments/2+1)}, {Name: "b", Data: make([]byte, MaxAttachments/2)}}}, "more than"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := tc.msg.check(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("check: %v, want %q", err, tc.want)
			}
		})
	}
	if err := (Message{Subject: strings.Repeat("é", MaxSubject), Attachments: []Attachment{{Name: "a.pdf", ContentType: "application/pdf"}}}).check(); err != nil {
		t.Fatal(err)
	}
}

// A message that cannot be sent, a recipient who cannot be written, and a
// gate that refuses all fail without connecting.
func TestSendWithoutConnecting(t *testing.T) {
	m, _ := New(cfg(func(c *Config) { c.Port = 1 }))
	m.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("dialed")
		return nil, nil
	}
	outs := m.Send(context.Background(), Message{Subject: "a\nb"}, []string{"a@example.org", "b@example.org"}, nil)
	if len(outs) != 2 || outs[0].Err == nil || outs[1].Err == nil || outs[1].To != "b@example.org" {
		t.Fatalf("outcomes %+v", outs)
	}
	gated := 0
	refuse := errors.New("limit reached")
	outs = m.Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{"not an address", "a@example.org"}, func(context.Context) (func(), error) {
		gated++
		return nil, refuse
	})
	if !strings.Contains(outs[0].Err.Error(), "invalid recipient") || !errors.Is(outs[1].Err, refuse) || gated != 1 {
		t.Fatalf("outcomes %+v, gate asked %d times", outs, gated)
	}
	// A recipient carrying a line break, which would add a command to the
	// session, is refused before anything is sent.
	for _, to := range []string{"a@example.org\r\nRCPT TO:<b@example.org>", "a@example.org\nRCPT TO:<b@example.org>",
		"\"a\r\nRCPT TO:<b@example.org>\"@example.org", "A <a@example.org>\r\nRCPT TO:<b@example.org>"} {
		outs = m.Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{to}, func(context.Context) (func(), error) {
			t.Fatalf("gate asked for %q", to)
			return nil, nil
		})
		if outs[0].Err == nil || !strings.Contains(outs[0].Err.Error(), "invalid recipient") {
			t.Fatalf("%q: %+v", to, outs[0])
		}
	}
	if !errors.Is(FirstError(outs), outs[0].Err) || FirstError([]Outcome{{To: "a"}}) != nil {
		t.Fatal("FirstError")
	}
}

// silent accepts connections and never says anything.
func silent(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// A server that never answers fails the message within the timeout, and
// the gate's slot is given back.
func TestSendTimeoutAndCancel(t *testing.T) {
	port := silent(t)
	m, _ := New(cfg(func(c *Config) { c.Port, c.Timeout = port, 300*time.Millisecond }))
	released := 0
	gate := func(context.Context) (func(), error) { return func() { released++ }, nil }
	start := time.Now()
	outs := m.Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{"a@example.org", "b@example.org"}, gate)
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("took %s", took)
	}
	if outs[0].Err == nil || outs[1].Err == nil || released != 1 {
		t.Fatalf("outcomes %+v, released %d", outs, released)
	}
	var re *ReplyError
	if errors.As(outs[0].Err, &re) || !strings.Contains(outs[0].Err.Error(), "greeting") {
		t.Fatalf("error %v", outs[0].Err)
	}

	// Canceling the context ends a session at once, whatever the timeout.
	m, _ = New(cfg(func(c *Config) { c.Port, c.Timeout = port, time.Minute }))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start = time.Now()
	outs = m.Send(ctx, Message{Subject: "s", Text: "t"}, []string{"a@example.org"}, nil)
	if took := time.Since(start); outs[0].Err == nil || took > 5*time.Second {
		t.Fatalf("outcome %+v after %s", outs[0], took)
	}

	// Nothing listening.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	m, _ = New(cfg(func(c *Config) { c.Port = closed }))
	outs = m.Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{"a@example.org"}, nil)
	if outs[0].Err == nil || !strings.Contains(outs[0].Err.Error(), "connecting to 127.0.0.1:") {
		t.Fatalf("outcome %+v", outs[0])
	}
}

// banner accepts connections and greets each with line.
func banner(t *testing.T, line string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(c, line+"\r\n")
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// Whatever answers on the host and port a test message names, the error
// says only whether it is a mail server, never what it said.
func TestGreetingThatIsNotSMTP(t *testing.T) {
	for line, want := range map[string]string{
		"SSH-2.0-OpenSSH_9.6 internal-build-7":      "is not an SMTP server: it did not greet as one",
		"HTTP/1.1 400 Bad Request internal-build-7": "is not an SMTP server: it did not greet as one",
		"554 internal-build-7 no SMTP service here": "it greeted with 554, not 220",
		"421 internal-build-7 too busy":             "it greeted with 421, not 220",
		"099 internal-build-7":                      "is not an SMTP server: it did not greet as one",
		"220-internal-build-7, and no more":         "waiting for the greeting of 127.0.0.1:",
	} {
		m, _ := New(cfg(func(c *Config) { c.Port, c.Timeout = banner(t, line), time.Second }))
		outs := m.Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{"a@example.org"}, nil)
		err := outs[0].Err
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "internal-build-7") {
			t.Errorf("%q: %v", line, err)
		}
	}
}

// recorder is an SMTP server on loopback that offers PLAIN sign-in but not
// STARTTLS, and records every line it receives.
type recorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *recorder) serve(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				tc := textproto.NewConn(c)
				_ = tc.PrintfLine("220 recorder ESMTP")
				for {
					line, err := tc.ReadLine()
					if err != nil {
						return
					}
					r.mu.Lock()
					r.lines = append(r.lines, line)
					r.mu.Unlock()
					switch cmd := strings.ToUpper(strings.Fields(line + " x")[0]); cmd {
					case "EHLO":
						_ = tc.PrintfLine("250-recorder\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME")
					case "QUIT":
						_ = tc.PrintfLine("221 bye")
						return
					default:
						_ = tc.PrintfLine("250 ok")
					}
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// In STARTTLS mode, a server that does not offer it never sees the
// credentials, nor anything of the message.
func TestNoSignInWithoutSTARTTLS(t *testing.T) {
	var r recorder
	port := r.serve(t)
	m, err := New(cfg(func(c *Config) { c.Port, c.Security, c.Username, c.Password = port, StartTLS, "rmm", "secret-password" }))
	if err != nil {
		t.Fatal(err)
	}
	outs := m.Send(context.Background(), Message{Subject: "private subject", Text: "private text"}, []string{"a@example.org"}, nil)
	if outs[0].Err == nil || !strings.Contains(outs[0].Err.Error(), "does not offer STARTTLS") {
		t.Fatalf("outcome %+v", outs[0])
	}
	plain := base64.StdEncoding.EncodeToString([]byte("\x00rmm\x00secret-password"))
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.lines) != 1 || !strings.HasPrefix(r.lines[0], "EHLO ") {
		t.Fatalf("the server received %q", r.lines)
	}
	for _, l := range r.lines {
		if strings.Contains(l, plain) || strings.Contains(l, "secret-password") || strings.Contains(strings.ToUpper(l), "AUTH") {
			t.Fatalf("the server received %q", l)
		}
	}
}

// fakeDNS is a DNS server on loopback that answers name's A record with
// addr and nothing else, and a resolver that asks it.
func fakeDNS(t *testing.T, name string, addr netip.Addr) *net.Resolver {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			rcode := dnsmessage.RCodeSuccess
			if !strings.EqualFold(q.Name.String(), name+".") {
				rcode = dnsmessage.RCodeNameError
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RCode: rcode})
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()
			if rcode == dnsmessage.RCodeSuccess && q.Type == dnsmessage.TypeA {
				_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
					dnsmessage.AResource{A: addr.As4()})
			}
			if out, err := b.Finish(); err == nil {
				_, _ = pc.WriteTo(out, from)
			}
		}
	}()
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", pc.LocalAddr().String())
	}}
}

// Without encryption, the address actually dialed must be loopback,
// whatever the name: a name that resolves elsewhere is refused before
// anything is sent.
func TestPlainDialsOnlyLoopback(t *testing.T) {
	m, err := New(cfg(func(c *Config) { c.Host, c.Timeout = "localhost", 2*time.Second }))
	if err != nil {
		t.Fatal(err)
	}
	// As if localhost resolved to another machine.
	m.cfg.Host = "relay.example.test"
	m.dialer.Resolver = fakeDNS(t, "relay.example.test", netip.MustParseAddr("192.0.2.25"))
	outs := m.Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{"a@example.org"}, nil)
	if outs[0].Err == nil || !strings.Contains(outs[0].Err.Error(), "only allowed to a relay on loopback, and 192.0.2.25 is not") {
		t.Fatalf("outcome %+v", outs[0])
	}
	// A name that resolves to loopback is dialed.
	port := banner(t, "220 relay ESMTP")
	m, _ = New(cfg(func(c *Config) { c.Host, c.Port, c.Timeout = "localhost", port, 2*time.Second }))
	m.cfg.Host = "relay.example.test"
	m.dialer.Resolver = fakeDNS(t, "relay.example.test", netip.MustParseAddr("127.0.0.1"))
	conn, err := m.dial(context.Background(), "tcp", m.Address())
	if err != nil {
		t.Fatalf("dialing a name on loopback: %v", err)
	}
	_ = conn.Close()
	// The check itself, on the addresses dialed.
	for addr, ok := range map[string]bool{"127.0.0.1:25": true, "127.0.0.53:25": true, "[::1]:25": true, "[::ffff:127.0.0.1]:25": true,
		"10.0.0.5:25": false, "[2001:db8::1]:25": false, "169.254.169.254:25": false} {
		if err := loopbackOnly("tcp", addr, nil); (err == nil) != ok {
			t.Errorf("%s: %v", addr, err)
		}
	}
	// With encryption, the platform's usual check: other addresses are fine.
	m, _ = New(cfg(func(c *Config) { c.Host, c.Security = "smtp.example.com", StartTLS }))
	if err := m.dialer.Control("tcp", "192.0.2.25:587", nil); err != nil {
		t.Fatalf("STARTTLS to another machine: %v", err)
	}
}

func TestReplyErrorAndClip(t *testing.T) {
	e := &ReplyError{Step: "recipient", Code: 550, Text: "5.1.1 no\nsuch   user"}
	if e.Error() != "the mail server refused the recipient: 550 5.1.1 no such user" || !e.Permanent() {
		t.Fatalf("%q", e.Error())
	}
	if (&ReplyError{Code: 451}).Permanent() {
		t.Fatal("451 is not permanent")
	}
	if got := clip(strings.Repeat("é", 10), 5); got != "éé…" {
		t.Fatalf("clip %q", got)
	}
	if got := reply("hello", errors.New("EOF")); !strings.Contains(got.Error(), "mailer: hello: EOF") || errors.Unwrap(got) == nil {
		t.Fatalf("reply %v", got)
	}
	if _, err := (&plainAuth{}).Next(nil, true); err == nil {
		t.Fatal("PLAIN accepted a challenge")
	}
}

func TestLetter(t *testing.T) {
	l := Letter{
		Subject: "Reset <your> password",
		Before:  []string{"Hello <script>alert(1)</script> & welcome."},
		Link:    &Link{Label: "Choose a password", URL: "https://rmm.example.com/reset#token=a&b"},
		After:   []string{"Ignore it otherwise."},
	}
	msg, err := l.Message()
	if err != nil {
		t.Fatal(err)
	}
	if msg.Subject != l.Subject {
		t.Fatalf("subject %q", msg.Subject)
	}
	wantText := "Hello <script>alert(1)</script> & welcome.\n\nhttps://rmm.example.com/reset#token=a&b\n\nIgnore it otherwise.\n"
	if msg.Text != wantText {
		t.Fatalf("text %q", msg.Text)
	}
	for _, want := range []string{"<title>Reset &lt;your&gt; password</title>", "Hello &lt;script&gt;alert(1)&lt;/script&gt; &amp; welcome.",
		`href="https://rmm.example.com/reset#token=a&amp;b"`, ">Choose a password</a>", "Ignore it otherwise."} {
		if !strings.Contains(msg.HTML, want) {
			t.Errorf("HTML lacks %q", want)
		}
	}
	if strings.Contains(msg.HTML, "<script>") {
		t.Fatal("HTML carries a script")
	}
	// A link that is not http(s) is not offered.
	for _, u := range []string{"javascript:alert(1)", "/reset", "mailto:a@example.org", "https://"} {
		if _, err := (Letter{Subject: "s", Link: &Link{Label: "x", URL: u}}).Message(); err == nil {
			t.Fatalf("a letter linking to %q", u)
		}
	}
	// Without a link, no button.
	msg, _ = Letter{Subject: "s", Before: []string{"only text"}}.Message()
	if strings.Contains(msg.HTML, "<a ") || msg.Text != "only text\n" {
		t.Fatalf("letter without a link: %q", msg.Text)
	}
}
