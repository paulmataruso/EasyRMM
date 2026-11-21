// Package mailer sends e-mail over SMTP (ADR-0053): each recipient gets a
// message of their own, with only their address in To, all in one session;
// as plain text, or as HTML with a plain-text alternative, with attachments.
//
// It connects over STARTTLS or TLS from the first byte, trusting the
// system's certificate authorities only, or unencrypted to a relay on
// loopback; it dials through netguard, as the platform's other
// integrations do, and signs in with a user name and password (PLAIN) only
// over TLS or to loopback.
package mailer

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/paulmataruso/easyrmm/server/internal/netguard"
)

// Security says how the connection to the mail server is protected.
const (
	// StartTLS connects in plain and requires STARTTLS before anything else.
	StartTLS = "starttls"
	// TLS speaks TLS from the first byte, usually on port 465.
	TLS = "tls"
	// None sends in clear text, only to a relay on loopback.
	None = "none"
)

// DefaultTimeout bounds each step of a session: connecting and signing in,
// and each message.
const DefaultTimeout = 30 * time.Second

// Config is a mail server and the sender.
type Config struct {
	Host     string
	Port     int
	Security string
	// Username and Password sign in with PLAIN; an empty Username does not
	// sign in.
	Username string
	Password string
	// FromAddress is the sender's address, FromName the name shown with it.
	FromAddress string
	FromName    string
	// Timeout bounds each step; DefaultTimeout when zero.
	Timeout time.Duration
}

// SMTP sends mail through one mail server.
type SMTP struct {
	cfg  Config
	from *mail.Address
	// dial is replaceable in tests.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Loopback reports whether host names this machine: localhost, or a
// loopback address.
func Loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// New checks the configuration and builds a mailer.
func New(cfg Config) (*SMTP, error) {
	if cfg.Host == "" {
		return nil, errors.New("mailer: no mail server")
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, fmt.Errorf("mailer: port %d is out of range", cfg.Port)
	}
	if !BareAddress(cfg.FromAddress) {
		return nil, fmt.Errorf("mailer: invalid sender's address %q", cfg.FromAddress)
	}
	if strings.ContainsFunc(cfg.FromName, unicode.IsControl) {
		return nil, errors.New("mailer: the sender's name contains a control character")
	}
	switch cfg.Security {
	case StartTLS, TLS:
	case None:
		if !Loopback(cfg.Host) {
			return nil, errors.New("mailer: unencrypted SMTP is only allowed to a relay on loopback")
		}
	default:
		return nil, fmt.Errorf("mailer: unknown security %q", cfg.Security)
	}
	if strings.ContainsAny(cfg.Username+cfg.Password, "\x00\r\n") {
		return nil, errors.New("mailer: the user name or password contains a line break or NUL")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	d := &net.Dialer{Timeout: cfg.Timeout, Control: netguard.Control}
	return &SMTP{cfg: cfg, from: &mail.Address{Name: cfg.FromName, Address: cfg.FromAddress}, dial: d.DialContext}, nil
}

// Address is the mail server's host and port.
func (m *SMTP) Address() string { return net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port)) }

// BareAddress reports whether s is an e-mail address alone, without a name
// or angle brackets.
func BareAddress(s string) bool {
	if s == "" || len(s) > 254 {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Name == "" && a.Address == s
}

// Gate is asked before each message is sent. It may wait for room under a
// limit, or refuse; release is called when the mail server did not take the
// message, so that it does not count.
type Gate func(ctx context.Context) (release func(), err error)

// Outcome is what became of one recipient's message.
type Outcome struct {
	To string
	// Err is nil when the mail server took the message.
	Err error
	// Reply is the mail server's answer when it took the message.
	Reply string
}

// FirstError is the first recipient's error, or nil when every message was
// taken.
func FirstError(outs []Outcome) error {
	for _, o := range outs {
		if o.Err != nil {
			return o.Err
		}
	}
	return nil
}

// ReplyError is the mail server refusing a command, with its reply.
type ReplyError struct {
	// Step is what was refused: "greeting", "hello", "sign-in", "sender",
	// "recipient", "message".
	Step string
	Code int
	Text string
}

func (e *ReplyError) Error() string {
	return fmt.Sprintf("the mail server refused the %s: %d %s", e.Step, e.Code, clip(e.Text, 300))
}

// Permanent reports whether the reply is a permanent failure (5xx); a 4xx
// reply may succeed later.
func (e *ReplyError) Permanent() bool { return e.Code >= 500 }

// stepError is a failure that is not the mail server's reply: a connection
// that could not be made, a TLS failure, a timeout.
type stepError struct {
	step string
	err  error
}

func (e *stepError) Error() string { return e.step + ": " + e.err.Error() }
func (e *stepError) Unwrap() error { return e.err }

// reply turns a textproto error into a ReplyError for step, and keeps any
// other error as it is.
func reply(step string, err error) error {
	var te *textproto.Error
	if errors.As(err, &te) {
		return &ReplyError{Step: step, Code: te.Code, Text: te.Msg}
	}
	return &stepError{step: "mailer: " + step, err: err}
}

// Send sends msg to each recipient as a message of its own, in one session,
// and returns each recipient's outcome in order. A recipient the mail
// server refuses does not stop the others; a failure to connect, protect
// the connection or sign in fails every recipient not yet sent.
func (m *SMTP) Send(ctx context.Context, msg Message, to []string, gate Gate) []Outcome {
	outs := make([]Outcome, len(to))
	rcpts := make([]*mail.Address, len(to))
	for i, t := range to {
		outs[i].To = t
		a, err := mail.ParseAddress(t)
		if err != nil || strings.ContainsAny(a.Address, "\r\n") {
			outs[i].Err = fmt.Errorf("mailer: invalid recipient %q", t)
			continue
		}
		rcpts[i] = a
	}
	failRest := func(from int, err error) {
		for j := from; j < len(outs); j++ {
			if outs[j].Err == nil && outs[j].Reply == "" {
				outs[j].Err = err
			}
		}
	}
	if err := msg.check(); err != nil {
		failRest(0, err)
		return outs
	}
	var s *session
	defer func() {
		if s != nil {
			s.quit()
		}
	}()
	for i := range to {
		if outs[i].Err != nil {
			continue
		}
		data, err := m.compose(rcpts[i], msg, time.Now())
		if err != nil {
			outs[i].Err = err
			continue
		}
		release := func() {}
		if gate != nil {
			r, err := gate(ctx)
			if err != nil {
				outs[i].Err = err
				continue
			}
			release = r
		}
		if s == nil {
			if s, err = m.open(ctx); err != nil {
				release()
				failRest(i, err)
				return outs
			}
		}
		outs[i].Reply, err = s.deliver(ctx, m.from.Address, rcpts[i].Address, data)
		if err == nil {
			continue
		}
		outs[i].Err = err
		var re *ReplyError
		switch {
		case errors.As(err, &re):
			// Refused: it does not count, and the session goes on.
			release()
			if s.reset() != nil {
				s.close()
				s = nil
			}
		case s.sentData:
			// The connection failed after the message went: it may have been
			// taken, so it counts; the others fail with it.
			s.close()
			s = nil
			failRest(i+1, err)
			return outs
		default:
			release()
			s.close()
			s = nil
			failRest(i+1, err)
			return outs
		}
	}
	return outs
}

// session is one connection to the mail server.
type session struct {
	m    *SMTP
	conn net.Conn
	c    *smtp.Client
	// stop ends the context watch.
	stop func() bool
	// sentData says the current message's content was written.
	sentData bool
}

// deadline is the end of the next step: the timeout, or ctx's deadline if
// sooner.
func (m *SMTP) deadline(ctx context.Context) time.Time {
	d := time.Now().Add(m.cfg.Timeout)
	if cd, ok := ctx.Deadline(); ok && cd.Before(d) {
		return cd
	}
	return d
}

// open connects, protects the connection and signs in.
func (m *SMTP) open(ctx context.Context) (*session, error) {
	addr := m.Address()
	dctx, cancel := context.WithDeadline(ctx, m.deadline(ctx))
	defer cancel()
	conn, err := m.dial(dctx, "tcp", addr)
	if err != nil {
		return nil, &stepError{step: "mailer: connecting to " + addr, err: err}
	}
	_ = conn.SetDeadline(m.deadline(ctx))
	// A canceled ctx ends the session at once.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	fail := func(err error) (*session, error) {
		stop()
		_ = conn.Close()
		return nil, err
	}
	tlsCfg := &tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12}
	if m.cfg.Security == TLS {
		tc := tls.Client(conn, tlsCfg)
		if err := tc.HandshakeContext(dctx); err != nil {
			return fail(&stepError{step: "mailer: TLS with " + addr, err: err})
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		return fail(reply("greeting", err))
	}
	s := &session{m: m, conn: conn, c: c, stop: stop}
	if err := c.Hello(localName); err != nil {
		s.close()
		return nil, reply("hello", err)
	}
	if m.cfg.Security == StartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			s.close()
			return nil, errors.New("mailer: the mail server does not offer STARTTLS; refusing to send credentials or mail in clear text")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			s.close()
			return nil, reply("STARTTLS", err)
		}
	}
	if m.cfg.Username != "" {
		if err := c.Auth(plainAuth{user: m.cfg.Username, password: m.cfg.Password}); err != nil {
			s.close()
			return nil, reply("sign-in", err)
		}
	}
	return s, nil
}

// deliver sends one message to one recipient and returns the mail server's
// answer.
func (s *session) deliver(ctx context.Context, from, to string, data []byte) (string, error) {
	s.sentData = false
	_ = s.conn.SetDeadline(s.m.deadline(ctx))
	if err := s.c.Mail(from); err != nil {
		return "", reply("sender", err)
	}
	if err := s.c.Rcpt(to); err != nil {
		return "", reply("recipient", err)
	}
	// DATA by hand, rather than smtp.Client.Data, to keep the final reply.
	t := s.c.Text
	id, err := t.Cmd("DATA")
	if err != nil {
		return "", reply("message", err)
	}
	t.StartResponse(id)
	_, _, err = t.ReadResponse(354)
	t.EndResponse(id)
	if err != nil {
		return "", reply("message", err)
	}
	w := t.DotWriter()
	_, err = w.Write(data)
	if err == nil {
		err = w.Close()
	}
	s.sentData = true
	if err != nil {
		return "", &stepError{step: "mailer: writing the message", err: err}
	}
	code, text, err := t.ReadResponse(250)
	if err != nil {
		return "", reply("message", err)
	}
	return strconv.Itoa(code) + " " + clip(text, 300), nil
}

// reset clears a refused transaction so the next message can begin.
func (s *session) reset() error { return s.c.Reset() }

// quit ends the session politely.
func (s *session) quit() {
	_ = s.c.Quit()
	s.close()
}

func (s *session) close() {
	s.stop()
	_ = s.c.Close()
}

// plainAuth is PLAIN (RFC 4616). New allows a session without TLS only to
// loopback, so, unlike smtp.PlainAuth, it does not check again, which would
// refuse loopback addresses other than 127.0.0.1 and ::1.
type plainAuth struct{ user, password string }

func (a plainAuth) Start(*smtp.ServerInfo) (string, []byte, error) {
	return "PLAIN", []byte("\x00" + a.user + "\x00" + a.password), nil
}

func (a plainAuth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("mailer: unexpected challenge during PLAIN sign-in")
	}
	return nil, nil
}

// localName is the name given in EHLO.
const localName = "easyrmm.localdomain"

// clip shortens s to at most n bytes on a rune boundary, on one line.
func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

// base64Lines writes data in base64, in lines of 76 characters.
func base64Lines(w io.Writer, data []byte) error {
	enc := base64.StdEncoding.EncodeToString(data)
	for len(enc) > 76 {
		if _, err := io.WriteString(w, enc[:76]+"\r\n"); err != nil {
			return err
		}
		enc = enc[76:]
	}
	_, err := io.WriteString(w, enc+"\r\n")
	return err
}
