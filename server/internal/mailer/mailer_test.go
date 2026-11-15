package mailer

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// trustedCert is installed as the only system root (SSL_CERT_FILE) before
// any test runs, so the mailer's default TLS verification accepts it.
// untrustedCert is valid for 127.0.0.1 but signed by nobody we trust.
var trustedCert, untrustedCert tls.Certificate

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "mailer-test")
	if err != nil {
		panic(err)
	}
	var pemBytes []byte
	trustedCert, pemBytes = selfSigned()
	untrustedCert, _ = selfSigned()
	path := filepath.Join(dir, "roots.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		panic(err)
	}
	// Read once, on first use of the system pool; nothing has used it yet.
	_ = os.Setenv("SSL_CERT_FILE", path)
	_ = os.Setenv("SSL_CERT_DIR", dir)
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func selfSigned() (tls.Certificate, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "mailer test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// smtpServer is a minimal SMTP server that records one transaction.
type smtpServer struct {
	t        *testing.T
	ln       net.Listener
	greeting string
	starttls bool
	cert     tls.Certificate
	// reject maps a command verb (or "." for end of data) to the reply sent
	// instead of success.
	reject map[string]string

	mu       sync.Mutex
	from     string
	rcpt     string
	auth     string
	authTLS  bool
	data     string
	finished chan struct{}
}

type serverOpts struct {
	implicitTLS bool
	starttls    bool
	cert        *tls.Certificate
	greeting    string
	reject      map[string]string
}

func startServer(t *testing.T, o serverOpts) *smtpServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert := trustedCert
	if o.cert != nil {
		cert = *o.cert
	}
	if o.implicitTLS {
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	}
	s := &smtpServer{t: t, ln: ln, greeting: o.greeting, starttls: o.starttls, cert: cert, reject: o.reject, finished: make(chan struct{})}
	if s.greeting == "" {
		s.greeting = "220 test.local ESMTP ready"
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			close(s.finished)
			return
		}
		defer close(s.finished)
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		s.serve(conn)
	}()
	return s
}

func (s *smtpServer) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *smtpServer) serve(conn net.Conn) {
	_, isTLS := conn.(*tls.Conn)
	tp := textproto.NewConn(conn)
	reply := func(lines ...string) { _ = tp.PrintfLine("%s", strings.Join(lines, "\r\n")) }
	reply(s.greeting)
	if !strings.HasPrefix(s.greeting, "220") {
		return
	}
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb := strings.ToUpper(strings.Fields(line + " x")[0])
		if r, ok := s.reject[verb]; ok {
			reply(r)
			continue
		}
		switch verb {
		case "EHLO":
			lines := []string{"250-test.local"}
			if s.starttls && !isTLS {
				lines = append(lines, "250-STARTTLS")
			}
			reply(append(lines, "250-AUTH PLAIN", "250 8BITMIME")...)
		case "HELO":
			reply("250 test.local")
		case "STARTTLS":
			reply("220 go ahead")
			tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS12})
			if err := tc.Handshake(); err != nil {
				return
			}
			conn, isTLS = tc, true
			tp = textproto.NewConn(tc)
		case "AUTH":
			s.mu.Lock()
			s.auth, s.authTLS = line, isTLS
			s.mu.Unlock()
			reply("235 authenticated")
		case "MAIL":
			s.mu.Lock()
			s.from = line
			s.mu.Unlock()
			reply("250 ok")
		case "RCPT":
			s.mu.Lock()
			s.rcpt = line
			s.mu.Unlock()
			reply("250 ok")
		case "DATA":
			reply("354 send it")
			var b strings.Builder
			for {
				l, err := tp.R.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			s.mu.Lock()
			s.data = b.String()
			s.mu.Unlock()
			if r, ok := s.reject["."]; ok {
				reply(r)
				continue
			}
			reply("250 queued")
		case "QUIT":
			reply("221 bye")
			return
		default:
			reply("502 not implemented")
		}
	}
}

func newMailer(t *testing.T, port int, mode string, mutate ...func(*Config)) *SMTP {
	t.Helper()
	cfg := Config{Host: "127.0.0.1", Port: port, From: "EasyRMM <rmm@msp.example>", TLS: mode, Timeout: 5 * time.Second}
	for _, f := range mutate {
		f(&cfg)
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSendPlainLoopback(t *testing.T) {
	s := startServer(t, serverOpts{})
	m := newMailer(t, s.port(), "none", func(c *Config) { c.Username, c.Password = "relay", "pw" })
	body := "Hello café,\nopen https://rmm.example/reset-password#token=abc\n" + strings.Repeat("x", 120) + "\n"
	if err := m.Send(context.Background(), "Ada <ada@example.com>", "Réinitialiser le mot de passe", body); err != nil {
		t.Fatal(err)
	}
	<-s.finished
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.from != "MAIL FROM:<rmm@msp.example> BODY=8BITMIME" && s.from != "MAIL FROM:<rmm@msp.example>" {
		t.Errorf("MAIL = %q", s.from)
	}
	if s.rcpt != "RCPT TO:<ada@example.com>" {
		t.Errorf("RCPT = %q", s.rcpt)
	}
	wantAuth := "AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00relay\x00pw"))
	if s.auth != wantAuth {
		t.Errorf("AUTH = %q, want %q", s.auth, wantAuth)
	}

	data := s.data
	if strings.Contains(strings.ReplaceAll(data, "\r\n", ""), "\n") {
		t.Errorf("bare LF in message: %q", data)
	}
	head, msgBody, ok := strings.Cut(data, "\r\n\r\n")
	if !ok {
		t.Fatalf("no header/body separator: %q", data)
	}
	headers := map[string]string{}
	for _, l := range strings.Split(head, "\r\n") {
		k, v, _ := strings.Cut(l, ": ")
		headers[k] = v
	}
	checks := map[string]string{
		"From":                      `"EasyRMM" <rmm@msp.example>`,
		"To":                        `"Ada" <ada@example.com>`,
		"Subject":                   "=?utf-8?q?R=C3=A9initialiser_le_mot_de_passe?=",
		"MIME-Version":              "1.0",
		"Content-Type":              "text/plain; charset=utf-8",
		"Content-Transfer-Encoding": "quoted-printable",
		"Auto-Submitted":            "auto-generated",
	}
	for k, v := range checks {
		if headers[k] != v {
			t.Errorf("%s = %q, want %q", k, headers[k], v)
		}
	}
	if id := headers["Message-ID"]; !strings.HasPrefix(id, "<") || !strings.HasSuffix(id, "@msp.example>") || len(id) != len("<>@msp.example")+32 {
		t.Errorf("Message-ID = %q", id)
	}
	if _, err := time.Parse(time.RFC1123Z, headers["Date"]); err != nil {
		t.Errorf("Date = %q: %v", headers["Date"], err)
	}
	if !strings.Contains(msgBody, "caf=C3=A9") {
		t.Errorf("body is not quoted-printable: %q", msgBody)
	}
	if !strings.Contains(msgBody, "#token=3Dabc") {
		t.Errorf("'=' not encoded: %q", msgBody)
	}
	for _, l := range strings.Split(msgBody, "\r\n") {
		if len(l) > 76 {
			t.Errorf("quoted-printable line longer than 76: %q", l)
		}
	}
}

func TestSendStartTLS(t *testing.T) {
	s := startServer(t, serverOpts{starttls: true})
	m := newMailer(t, s.port(), "starttls", func(c *Config) { c.Username, c.Password = "u", "p" })
	if err := m.Send(context.Background(), "ops@example.com", "Hi", "body\r\nwith CRLF already\r\n"); err != nil {
		t.Fatal(err)
	}
	<-s.finished
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.authTLS {
		t.Fatal("credentials were sent before TLS")
	}
	if strings.Contains(s.data, "\r\r\n") {
		t.Fatalf("CRLF was doubled: %q", s.data)
	}
}

func TestSendStartTLSNotOffered(t *testing.T) {
	s := startServer(t, serverOpts{starttls: false})
	m := newMailer(t, s.port(), "starttls")
	err := m.Send(context.Background(), "ops@example.com", "Hi", "body")
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("err = %v, want a STARTTLS refusal", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.from != "" || s.data != "" {
		t.Fatal("mail was sent without TLS")
	}
}

func TestSendStartTLSUntrusted(t *testing.T) {
	s := startServer(t, serverOpts{starttls: true, cert: &untrustedCert})
	m := newMailer(t, s.port(), "starttls")
	if err := m.Send(context.Background(), "ops@example.com", "Hi", "body"); err == nil || !strings.Contains(err.Error(), "starttls") {
		t.Fatalf("err = %v, want starttls failure", err)
	}
}

func TestSendImplicitTLS(t *testing.T) {
	s := startServer(t, serverOpts{implicitTLS: true})
	m := newMailer(t, s.port(), "implicit")
	if err := m.Send(context.Background(), "ops@example.com", "Hi", "body"); err != nil {
		t.Fatal(err)
	}
	<-s.finished
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rcpt != "RCPT TO:<ops@example.com>" {
		t.Fatalf("RCPT = %q", s.rcpt)
	}
}

func TestSendImplicitTLSUntrusted(t *testing.T) {
	s := startServer(t, serverOpts{implicitTLS: true, cert: &untrustedCert})
	m := newMailer(t, s.port(), "implicit")
	err := m.Send(context.Background(), "ops@example.com", "Hi", "body")
	if err == nil || !strings.Contains(err.Error(), "tls handshake") {
		t.Fatalf("err = %v, want a handshake failure", err)
	}
}

func TestSendServerRejections(t *testing.T) {
	cases := []struct {
		name   string
		opts   serverOpts
		user   string
		substr string
	}{
		{"bad greeting", serverOpts{greeting: "554 go away"}, "", "mailer:"},
		{"hello refused", serverOpts{reject: map[string]string{"EHLO": "500 no", "HELO": "500 no"}}, "", "hello"},
		{"auth refused", serverOpts{reject: map[string]string{"AUTH": "535 bad credentials"}}, "user", "authentication"},
		{"sender refused", serverOpts{reject: map[string]string{"MAIL": "550 no"}}, "", "MAIL FROM"},
		{"recipient refused", serverOpts{reject: map[string]string{"RCPT": "550 no such user"}}, "", "RCPT TO"},
		{"data refused", serverOpts{reject: map[string]string{"DATA": "554 no"}}, "", "DATA"},
		{"message refused", serverOpts{reject: map[string]string{".": "554 spam"}}, "", "finishing message"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := startServer(t, c.opts)
			m := newMailer(t, s.port(), "none", func(cfg *Config) { cfg.Username, cfg.Password = c.user, "pw" })
			err := m.Send(context.Background(), "ops@example.com", "Hi", "body")
			if err == nil || !strings.Contains(err.Error(), c.substr) {
				t.Fatalf("err = %v, want it to mention %q", err, c.substr)
			}
		})
	}
}

func TestSendInputValidation(t *testing.T) {
	m := newMailer(t, 25, "none")
	m.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("dialed despite invalid input")
		return nil, nil
	}
	if err := m.Send(context.Background(), "not an address", "Hi", "body"); err == nil || !strings.Contains(err.Error(), "invalid recipient") {
		t.Fatalf("invalid recipient: %v", err)
	}
	if err := m.Send(context.Background(), "ops@example.com", "Hi\r\nBcc: victim@example.com", "body"); err == nil || !strings.Contains(err.Error(), "line break") {
		t.Fatalf("header injection: %v", err)
	}
}

func TestSendDialFailure(t *testing.T) {
	m := newMailer(t, 25, "none")
	m.dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("connection refused") }
	err := m.Send(context.Background(), "ops@example.com", "Hi", "body")
	if err == nil || !strings.Contains(err.Error(), "connecting to 127.0.0.1:25") {
		t.Fatalf("err = %v", err)
	}
}

func TestNewValidation(t *testing.T) {
	cases := []struct {
		cfg Config
		ok  bool
	}{
		{Config{Host: "smtp.example.com", Port: 587, From: "rmm@example.com", TLS: "starttls"}, true},
		{Config{Host: "smtp.example.com", Port: 465, From: "rmm@example.com", TLS: "implicit"}, true},
		{Config{Host: "localhost", Port: 25, From: "rmm@example.com", TLS: "none"}, true},
		{Config{Host: "127.0.0.1", Port: 25, From: "rmm@example.com", TLS: "none"}, true},
		{Config{Host: "::1", Port: 25, From: "rmm@example.com", TLS: "none"}, true},
		{Config{Host: "smtp.example.com", Port: 25, From: "rmm@example.com", TLS: "none"}, false},
		{Config{Host: "10.0.0.5", Port: 25, From: "rmm@example.com", TLS: "none"}, false},
		{Config{Host: "smtp.example.com", Port: 587, From: "rmm@example.com", TLS: "ssl"}, false},
		{Config{Host: "smtp.example.com", Port: 587, From: "not an address", TLS: "starttls"}, false},
	}
	for i, c := range cases {
		m, err := New(c.cfg)
		if (err == nil) != c.ok {
			t.Errorf("case %d (%s/%s): err = %v, want ok=%v", i, c.cfg.Host, c.cfg.TLS, err, c.ok)
		}
		if err == nil && m.cfg.Timeout != 30*time.Second {
			t.Errorf("case %d: default timeout = %v", i, m.cfg.Timeout)
		}
	}
	m, err := New(Config{Host: "localhost", Port: 25, From: "rmm@example.com", TLS: "none", Timeout: time.Second})
	if err != nil || m.cfg.Timeout != time.Second {
		t.Fatalf("explicit timeout: %v %v", m, err)
	}
}

func TestSendHonorsTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			// Never greet: the client must give up at its deadline.
			_, _ = bufio.NewReader(c).ReadString('\n')
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	m := newMailer(t, port, "none", func(c *Config) { c.Timeout = 300 * time.Millisecond })
	start := time.Now()
	if err := m.Send(context.Background(), "ops@example.com", "Hi", "body"); err == nil {
		t.Fatal("expected a timeout")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Send took %v despite a 300ms timeout", d)
	}
}
