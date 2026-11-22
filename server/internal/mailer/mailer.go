// Package mailer sends e-mail over SMTP (ADR-0053): each recipient gets a
// message of their own, with only their address in To, all in one session;
// as plain text, or as HTML with a plain-text alternative, with attachments.
//
// It connects over STARTTLS or TLS from the first byte, trusting the
// system's certificate authorities only, or unencrypted to a relay on
// loopback; it dials through netguard, as the platform's other
// integrations do, and signs in with a user name and password (PLAIN) only
// over TLS or to loopback, or with a Microsoft 365 application's token
// (AUTH XOAUTH2, slice 2) only over TLS.
package mailer

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/netip"
	"net/smtp"
	"net/textproto"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/google/uuid"

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
	// sign in. With OAuth, Username is the mailbox signed in to and
	// Password is empty.
	Username string
	Password string
	// OAuth, when set, signs in with AUTH XOAUTH2 and its tokens: a
	// Microsoft 365 application's (ADR-0053, slice 2). Only over STARTTLS
	// or TLS, and only to a mail server that offers it.
	OAuth TokenSource
	// FromAddress is the sender's address, FromName the name shown with it.
	FromAddress string
	FromName    string
	// Timeout bounds each step; DefaultTimeout when zero.
	Timeout time.Duration
	// RateRetry, when set, has a message the mail server refuses for its
	// rate (ReplyError.RateLimited) tried once more after it, in a new
	// session, its room under the limits kept: such a refusal is not the
	// recipient's (ADR-0053). Account mail waits so; a test message does
	// not.
	RateRetry time.Duration
}

// TokenSource gives the tokens XOAUTH2 signs in with.
type TokenSource interface {
	// Token is a token to sign in with: the one kept, or a new one.
	Token(ctx context.Context) (string, error)
	// Refused drops a token the mail server refused, so that the next
	// Token is a new one.
	Refused(token string)
}

// SMTP sends mail through one mail server.
type SMTP struct {
	cfg  Config
	from *mail.Address
	// dialer connects; dial is its DialContext, replaceable in tests.
	dialer *net.Dialer
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
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
	if cfg.OAuth != nil {
		switch {
		case cfg.Security == None:
			return nil, errors.New("mailer: XOAUTH2 signs in only over STARTTLS or TLS")
		case cfg.Password != "":
			return nil, errors.New("mailer: XOAUTH2 signs in with a token, not a password")
		case !BareAddress(cfg.Username):
			return nil, fmt.Errorf("mailer: the mailbox to sign in to, %q, is not an email address", cfg.Username)
		}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	d := &net.Dialer{Timeout: cfg.Timeout, Control: netguard.Control}
	if cfg.Security == None {
		d.Control = loopbackOnly
	}
	return &SMTP{cfg: cfg, from: &mail.Address{Name: cfg.FromName, Address: cfg.FromAddress}, dialer: d, dial: d.DialContext}, nil
}

// loopbackOnly is the dialer's check without encryption: the address
// actually dialed, after the name is resolved, must be loopback, whatever
// the name said.
func loopbackOnly(network, address string, c syscall.RawConn) error {
	if err := netguard.Control(network, address, c); err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if a, err := netip.ParseAddr(host); err != nil || !a.Unmap().IsLoopback() {
		return fmt.Errorf("unencrypted SMTP is only allowed to a relay on loopback, and %s is not", host)
	}
	return nil
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

// AccountMail says whom a message to someone's own account is counted
// against, under the mail server's limits (ADR-0053).
type AccountMail struct {
	// Self: the person asked for it themselves (a password reset), so it
	// may use the share of the day's limit kept for that alone.
	Self bool
	// Admin is the administrator who sent it (an invitation, a password
	// link).
	Admin uuid.UUID
	// Account is the account it goes to; Organization that account's
	// organization, uuid.Nil for none or several, and for an
	// administrator's mail uuid.Nil when a super administrator sends it,
	// which no organization's limit counts.
	Account      uuid.UUID
	Organization uuid.UUID
}

// Limited is account mail the limits did not let go (ADR-0053): which
// limit, in words, and when there will be room.
type Limited interface {
	error
	// LimitCode names the limit: one of the Limit codes.
	LimitCode() string
	// RetryIn is how long until there is room, 0 when unknown.
	RetryIn() time.Duration
}

// Reservation is room under the limits taken for one message of account
// mail before it is made: Send sends it in that room, or Release gives
// the room back. Either is done once; the other then does nothing.
type Reservation interface {
	Send(ctx context.Context, to string, msg Message) error
	Release()
}

// The limits a message can reach, as Limited names them.
const (
	// LimitAdmin: the administrator's own, an hour.
	LimitAdmin = "admin_mail_limited"
	// LimitOrganization: administrators' mail to one organization's
	// accounts, a day.
	LimitOrganization = "organization_mail_limited"
	// LimitAccount: password emails to one account, whoever asks.
	LimitAccount = "account_mail_limited"
	// LimitOrganizationResets: password resets people ask for, to one
	// organization's accounts, an hour.
	LimitOrganizationResets = "organization_resets_limited"
	// LimitResets: password resets people ask for, on the whole platform,
	// an hour.
	LimitResets = "resets_limited"
	// LimitDay: the day's limit, or the share of it this mail may use.
	LimitDay = "day_limited"
	// LimitMinute: the minute's limit.
	LimitMinute = "minute_limited"
	// LimitAccountWaiting: other mail standing back while account mail
	// waits.
	LimitAccountWaiting = "account_mail_waiting"
)

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
	// Step is what was refused: "hello", "STARTTLS", "sign-in", "sender",
	// "recipient", "message".
	Step string
	Code int
	Text string
	// Hint says what the reply means and what to change, when EasyRMM
	// knows (Exchange Online's replies, hint).
	Hint string
}

func (e *ReplyError) Error() string {
	msg := fmt.Sprintf("the mail server refused the %s: %d %s", e.Step, e.Code, clip(e.Text, 300))
	if e.Hint != "" {
		msg += " → " + e.Hint
	}
	return msg
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
		return &ReplyError{Step: step, Code: te.Code, Text: te.Msg, Hint: hint(step, te.Code, te.Msg, false)}
	}
	return &stepError{step: "mailer: " + step, err: err}
}

// peekConn reads through r, which has looked ahead at the greeting.
type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// smtpReply reports whether b begins as an SMTP reply does: three digits,
// then a space or a hyphen.
func smtpReply(b []byte) bool {
	for _, d := range b[:3] {
		if d < '0' || d > '9' {
			return false
		}
	}
	return b[3] == ' ' || b[3] == '-'
}

// greeting is a greeting that is not SMTP's 220. What the other end said is
// not repeated: whatever answers on a host and port a test message names,
// the error shows only whether it is a mail server.
func greeting(addr string, err error) error {
	var te *textproto.Error
	var pe textproto.ProtocolError
	switch {
	case errors.As(err, &te):
		return fmt.Errorf("mailer: %s is not an SMTP server, or not one taking mail: it greeted with %d, not 220", addr, te.Code)
	case errors.As(err, &pe):
		return fmt.Errorf("mailer: %s is not an SMTP server: it did not greet as one", addr)
	}
	return &stepError{step: "mailer: waiting for the greeting of " + addr, err: err}
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
		data := m.compose(rcpts[i], msg, time.Now())
		var err error
		release := func() {}
		if gate != nil {
			r, err := gate(ctx)
			if err != nil {
				outs[i].Err = err
				continue
			}
			release = r
		}
		for retried := false; ; retried = true {
			if s == nil {
				if s, err = m.open(ctx); err != nil {
					release()
					failRest(i, err)
					return outs
				}
			}
			outs[i].Reply, err = s.deliver(ctx, m.from.Address, rcpts[i].Address, data)
			var re *ReplyError
			if !retried && m.cfg.RateRetry > 0 && errors.As(err, &re) && re.RateLimited() && pause(ctx, m.cfg.RateRetry) == nil {
				// Refused for the mail server's rate: once more, after the
				// wait, in a new session, as Exchange counts connections.
				s.quit()
				s = nil
				continue
			}
			break
		}
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
	// overTLS says the connection is protected: TLS from the first byte, or
	// after STARTTLS.
	overTLS bool
	// signedIn is the mail server's answer to the sign-in, "" without one.
	signedIn string
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

// open connects, protects the connection and signs in. With XOAUTH2, a
// token the mail server refuses (535) is dropped, and one more session is
// tried with a new one, unless the refusal is 5.7.139, which a token does
// not change (SMTP AUTH off, security defaults).
func (m *SMTP) open(ctx context.Context) (*session, error) {
	s, err := m.connect(ctx)
	if err != nil {
		return nil, err
	}
	switch {
	case m.cfg.OAuth != nil:
		err = s.xoauth2(ctx)
		var re *ReplyError
		if errors.As(err, &re) && re.Code == 535 && !strings.Contains(re.Text, "5.7.139") {
			// The client quits after a refused AUTH: a new session.
			s.close()
			if s, err = m.connect(ctx); err != nil {
				return nil, err
			}
			err = s.xoauth2(ctx)
		}
	case m.cfg.Username != "":
		a := &plainAuth{user: m.cfg.Username, password: m.cfg.Password}
		if err = s.c.Auth(a); err != nil {
			err = reply("sign-in", err)
		} else {
			s.signedIn = "235 " + a.answer
		}
	}
	if err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

// connect connects, protects the connection, and says hello.
func (m *SMTP) connect(ctx context.Context) (*session, error) {
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
	overTLS := m.cfg.Security == TLS
	if overTLS {
		tc := tls.Client(conn, tlsCfg)
		if err := tc.HandshakeContext(dctx); err != nil {
			return fail(&stepError{step: "mailer: TLS with " + addr, err: err})
		}
		conn = tc
	}
	// An SMTP greeting begins with three digits and a space or a hyphen;
	// anything else is not read further, nor waited on.
	pc := &peekConn{Conn: conn, r: bufio.NewReader(conn)}
	head, err := pc.r.Peek(4)
	switch {
	case err != nil:
		return fail(&stepError{step: "mailer: waiting for the greeting of " + addr, err: err})
	case !smtpReply(head):
		return fail(fmt.Errorf("mailer: %s is not an SMTP server: it did not greet as one", addr))
	}
	c, err := smtp.NewClient(pc, m.cfg.Host)
	if err != nil {
		return fail(greeting(addr, err))
	}
	s := &session{m: m, conn: conn, c: c, stop: stop, overTLS: overTLS}
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
		s.overTLS = true
	}
	return s, nil
}

// xoauth2 signs in with AUTH XOAUTH2 (ADR-0053, slice 2): only over TLS,
// only when the mail server offers it, with a token from the source; one
// the mail server refuses is dropped.
func (s *session) xoauth2(ctx context.Context) error {
	addr := s.m.Address()
	if !s.overTLS {
		return errors.New("mailer: refusing to send a token without TLS")
	}
	if !s.offers("XOAUTH2") {
		return fmt.Errorf("mailer: %s does not offer sign-in with a token (AUTH XOAUTH2), which signing in with a Microsoft 365 application needs; "+
			"Exchange Online's is smtp.office365.com, port 587, with STARTTLS", addr)
	}
	token, err := s.m.cfg.OAuth.Token(ctx)
	if err != nil {
		return &stepError{step: "mailer: signing in to " + addr + " with a Microsoft 365 application", err: err}
	}
	a := &xoauth2Auth{user: s.m.cfg.Username, token: token}
	if err := s.c.Auth(a); err != nil {
		var te *textproto.Error
		if errors.As(err, &te) && te.Code == 535 {
			s.m.cfg.OAuth.Refused(token)
		}
		return s.reply("sign-in", err)
	}
	s.signedIn = "235 " + a.answer
	return nil
}

// reply is reply, explained knowing how the session signs in.
func (s *session) reply(step string, err error) error {
	err = reply(step, err)
	var re *ReplyError
	if s.m.cfg.OAuth != nil && errors.As(err, &re) {
		re.Hint = hint(step, re.Code, re.Text, true)
	}
	return err
}

// offers reports whether the mail server offers the sign-in mechanism
// mech.
func (s *session) offers(mech string) bool {
	ok, params := s.c.Extension("AUTH")
	return ok && slices.ContainsFunc(strings.Fields(params), func(p string) bool { return strings.EqualFold(p, mech) })
}

// Check connects, protects the connection and signs in as a message would,
// then quits without sending anything: easyrmm-server mail check, and the
// server's check at start (ADR-0053). It says what the mail server
// answered.
func (m *SMTP) Check(ctx context.Context) (string, error) {
	s, err := m.open(ctx)
	if err != nil {
		return "", err
	}
	defer s.quit()
	how := map[string]string{StartTLS: "STARTTLS", TLS: "TLS", None: "no encryption, on loopback"}[m.cfg.Security]
	switch {
	case m.cfg.OAuth != nil:
		return fmt.Sprintf("Connected to %s (%s) and signed in to %s with a Microsoft 365 application's token: %s", m.Address(), how, m.cfg.Username,
			clip(s.signedIn, 300)), nil
	case m.cfg.Username != "":
		return fmt.Sprintf("Connected to %s (%s) and signed in as %s with a password: %s", m.Address(), how, m.cfg.Username, clip(s.signedIn, 300)), nil
	}
	return fmt.Sprintf("Connected to %s (%s); it was not asked to sign in.", m.Address(), how), nil
}

// deliver sends one message to one recipient and returns the mail server's
// answer.
func (s *session) deliver(ctx context.Context, from, to string, data []byte) (string, error) {
	s.sentData = false
	_ = s.conn.SetDeadline(s.m.deadline(ctx))
	if err := s.c.Mail(from); err != nil {
		return "", s.reply("sender", err)
	}
	if err := s.c.Rcpt(to); err != nil {
		return "", s.reply("recipient", err)
	}
	// DATA by hand, rather than smtp.Client.Data, to keep the final reply.
	t := s.c.Text
	id, err := t.Cmd("DATA")
	if err != nil {
		return "", s.reply("message", err)
	}
	t.StartResponse(id)
	_, _, err = t.ReadResponse(354)
	t.EndResponse(id)
	if err != nil {
		return "", s.reply("message", err)
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
		return "", s.reply("message", err)
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

// pause waits d, or until ctx ends.
func pause(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// plainAuth is PLAIN (RFC 4616). New allows a session without TLS only to
// loopback, so, unlike smtp.PlainAuth, it does not check again, which would
// refuse loopback addresses other than 127.0.0.1 and ::1. answer is the
// mail server's answer once it signed in.
type plainAuth struct{ user, password, answer string }

func (a *plainAuth) Start(*smtp.ServerInfo) (string, []byte, error) {
	return "PLAIN", []byte("\x00" + a.user + "\x00" + a.password), nil
}

func (a *plainAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("mailer: unexpected challenge during PLAIN sign-in")
	}
	a.answer = string(fromServer)
	return nil, nil
}

// xoauth2Auth is XOAUTH2, as Microsoft documents it ("Authenticate an
// IMAP, POP or SMTP connection using OAuth"): the initial response
// "user=" mailbox ^A "auth=Bearer " token ^A ^A, base64. A mail server that
// refuses it may first send a challenge (an error in JSON), answered with
// an empty line so that it gives its refusal. answer is the mail server's
// answer once it signed in.
type xoauth2Auth struct{ user, token, answer string }

func (a *xoauth2Auth) Start(*smtp.ServerInfo) (string, []byte, error) {
	return "XOAUTH2", xoauth2Response(a.user, a.token), nil
}

func (a *xoauth2Auth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		return []byte{}, nil
	}
	a.answer = string(fromServer)
	return nil, nil
}

// xoauth2Response is XOAUTH2's initial response, before base64.
func xoauth2Response(user, token string) []byte {
	return []byte("user=" + user + "\x01auth=Bearer " + token + "\x01\x01")
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

// base64Lines writes data in base64, in lines of 76 characters, to a
// writer in memory.
func base64Lines(w io.Writer, data []byte) {
	enc := base64.StdEncoding.EncodeToString(data)
	for len(enc) > 76 {
		_, _ = io.WriteString(w, enc[:76]+"\r\n")
		enc = enc[76:]
	}
	_, _ = io.WriteString(w, enc+"\r\n")
}
