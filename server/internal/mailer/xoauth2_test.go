package mailer

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/m365"
	"github.com/paulmataruso/easyrmm/server/internal/m365/m365test"
	"github.com/paulmataruso/easyrmm/server/internal/testmail"
)

// Signing in with a Microsoft 365 application (ADR-0053, slice 2), against
// stand-ins for Microsoft (m365test): its token endpoint and Exchange
// Online's SMTP. The real ones are checked by hand against a tenant.

func TestMain(m *testing.M) {
	// The mailer trusts the system's roots only: the stand-ins' authority,
	// and Mailpit's for the integration tests, are trusted as theirs. They
	// are read on first use of the system pool; nothing has used it yet.
	if err := m365test.Trust(testmail.CA()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// Microsoft's example, in "Authenticate an IMAP, POP or SMTP connection
// using OAuth", frozen.
func TestXOAUTH2Response(t *testing.T) {
	got := base64.StdEncoding.EncodeToString(xoauth2Response("test@contoso.onmicrosoft.com", "EwBAAl3BAAUFFpUAo7J3Ve0bjLBWZWCclRC3EoAA"))
	if got != "dXNlcj10ZXN0QGNvbnRvc28ub25taWNyb3NvZnQuY29tAWF1dGg9QmVhcmVyIEV3QkFBbDNCQUFVRkZwVUFvN0ozVmUwYmpMQldaV0NjbFJDM0VvQUEBAQ==" {
		t.Fatalf("XOAUTH2 initial response %s", got)
	}
}

// standIn is a stand-in token endpoint and Exchange Online, and a mailer
// signing in to it with the application's secret.
type standIn struct {
	ep     *m365test.TokenEndpoint
	smtp   *m365test.SMTPServer
	source *m365.Source
	log    *bytes.Buffer
	logMu  *sync.Mutex
}

type syncBuffer struct {
	mu *sync.Mutex
	b  *bytes.Buffer
}

func (s syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func newStandIn(t *testing.T, implicitTLS bool) *standIn {
	t.Helper()
	ep := m365test.NewTokenEndpoint(t, nil)
	s := &standIn{ep: ep, smtp: m365test.NewSMTPServer(t, ep.Valid, implicitTLS), log: &bytes.Buffer{}, logMu: &sync.Mutex{}}
	s.source = m365.NewSource(m365.Credentials{TenantID: m365test.TenantID, ClientID: m365test.ClientID, Secret: m365test.Secret, Authority: ep.URL},
		slog.New(slog.NewTextHandler(syncBuffer{s.logMu, s.log}, nil)))
	return s
}

func (s *standIn) mailer(t *testing.T, security string, mutate ...func(*Config)) *SMTP {
	t.Helper()
	c := Config{Host: s.smtp.Host, Port: s.smtp.Port, Security: security, Username: m365test.Mailbox, FromAddress: m365test.Mailbox,
		FromName: "EasyRMM", OAuth: s.source, Timeout: 10 * time.Second}
	for _, f := range mutate {
		f(&c)
	}
	m, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// secretsKept checks that neither the secret nor a token reached err or
// the log.
func (s *standIn) secretsKept(t *testing.T, err error) {
	t.Helper()
	s.logMu.Lock()
	logged := s.log.String()
	s.logMu.Unlock()
	for _, secret := range append(s.ep.Issued(), m365test.Secret) {
		if (err != nil && strings.Contains(err.Error(), secret)) || strings.Contains(logged, secret) {
			t.Fatalf("a secret or token is shown: %v / %s", err, logged)
		}
	}
}

// Over STARTTLS, and over TLS from the first byte, the mailer signs in to
// the mailbox with the application's token, only after TLS, and sends.
func TestXOAUTH2Send(t *testing.T) {
	for name, tc := range map[string]struct {
		implicit bool
		security string
	}{"STARTTLS": {false, StartTLS}, "TLS": {true, TLS}} {
		t.Run(name, func(t *testing.T) {
			s := newStandIn(t, tc.implicit)
			// A server offering XOAUTH2 before TLS still gets no token before.
			s.smtp.Set(func() { s.smtp.AuthBeforeTLS = true })
			m := s.mailer(t, tc.security)
			outs := m.Send(context.Background(), Message{Subject: "over " + name, Text: "t"}, []string{"a@example.org", "b@example.org"}, nil)
			for _, o := range outs {
				if o.Err != nil {
					t.Fatal(o.Err)
				}
			}
			sessions := s.smtp.Sessions()
			if len(sessions) != 1 || len(sessions[0].Messages) != 2 || sessions[0].User != m365test.Mailbox || !s.ep.Valid(sessions[0].Token) {
				t.Fatalf("sessions %+v", sessions)
			}
			for _, overTLS := range sessions[0].AuthOverTLS {
				if !overTLS {
					t.Fatal("a token was sent without TLS")
				}
			}
			if len(s.ep.Requests()) != 1 {
				t.Fatalf("%d token requests", len(s.ep.Requests()))
			}
			// The next sending uses the kept token.
			if outs := m.Send(context.Background(), Message{Subject: "again", Text: "t"}, []string{"a@example.org"}, nil); outs[0].Err != nil ||
				len(s.ep.Requests()) != 1 {
				t.Fatalf("again: %v, %d token requests", outs[0].Err, len(s.ep.Requests()))
			}
			s.secretsKept(t, nil)
		})
	}
}

// Check signs in and quits without sending anything.
func TestXOAUTH2Check(t *testing.T) {
	s := newStandIn(t, false)
	answer, err := s.mailer(t, StartTLS).Check(context.Background())
	if err != nil || !strings.Contains(answer, "signed in to "+m365test.Mailbox+" with a Microsoft 365 application's token: 235 2.7.0 Authentication successful") ||
		!strings.Contains(answer, "(STARTTLS)") {
		t.Fatalf("check: %q, %v", answer, err)
	}
	ss := s.smtp.Sessions()
	if len(ss) != 1 || !ss[0].Quit || len(ss[0].Messages) != 0 {
		t.Fatalf("sessions %+v", ss)
	}
	for _, c := range ss[0].Commands {
		if strings.HasPrefix(c, "MAIL") || strings.HasPrefix(c, "RCPT") || c == "DATA" {
			t.Fatalf("check sent %q", c)
		}
	}
	// A refusal is the check's error.
	s.smtp.Set(func() { s.smtp.SignInReply = m365test.AuthOffMailbox })
	if _, err := s.mailer(t, StartTLS).Check(context.Background()); err == nil || !strings.Contains(err.Error(), "Set-CASMailbox") {
		t.Fatalf("check refused: %v", err)
	}
}

// A token the mail server refuses is dropped, and a new one is tried once,
// in a new session: a token revoked before its end, or a permission given
// since it was made.
func TestXOAUTH2RenewOnce(t *testing.T) {
	s := newStandIn(t, false)
	m := s.mailer(t, StartTLS)
	s.smtp.Set(func() { s.smtp.RefuseSignIns = 1 })
	if outs := m.Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{"a@example.org"}, nil); outs[0].Err != nil {
		t.Fatal(outs[0].Err)
	}
	if n := len(s.ep.Requests()); n != 2 || len(s.smtp.Sessions()) != 2 {
		t.Fatalf("%d token requests, %d sessions", n, len(s.smtp.Sessions()))
	}
	// Refused twice: the error, with what to check; the kept token and one
	// new one, not more.
	s.smtp.Set(func() { s.smtp.RefuseSignIns = 2 })
	outs := m.Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{"a@example.org", "b@example.org"}, nil)
	var re *ReplyError
	if !errors.As(outs[0].Err, &re) || re.Code != 535 || re.Step != "sign-in" || !strings.Contains(re.Hint, "SMTP.SendAsApp") ||
		!strings.Contains(re.Hint, "New-ServicePrincipal") || !strings.Contains(re.Hint, "Add-MailboxPermission") || !errors.Is(outs[1].Err, outs[0].Err) {
		t.Fatalf("outcomes %+v", outs)
	}
	if n := len(s.ep.Requests()); n != 3 {
		t.Fatalf("%d token requests", n)
	}
	s.secretsKept(t, outs[0].Err)
	// A mail server that challenges before refusing (334 then 535) is
	// answered with an empty line, and its refusal shown.
	s.smtp.Set(func() { s.smtp.RefuseSignIns, s.smtp.Challenge = 2, true })
	outs = m.Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{"a@example.org"}, nil)
	if !errors.As(outs[0].Err, &re) || re.Code != 535 {
		t.Fatalf("after a challenge: %v", outs[0].Err)
	}
}

// SMTP AUTH off and security defaults are said so, with the setting that
// changes them; a new token would not help, so none is asked for.
func TestXOAUTH2AuthOff(t *testing.T) {
	for reply, want := range map[string]string{
		m365test.AuthOffTenant:    "Set-TransportConfig -SmtpClientAuthenticationDisabled $false",
		m365test.AuthOffMailbox:   "Set-CASMailbox -Identity <mailbox> -SmtpClientAuthenticationDisabled $false",
		m365test.SecurityDefaults: "security defaults",
		m365test.OtherAuth139:     "",
	} {
		s := newStandIn(t, false)
		s.smtp.Set(func() { s.smtp.SignInReply = reply })
		outs := s.mailer(t, StartTLS).Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{"a@example.org"}, nil)
		var re *ReplyError
		if !errors.As(outs[0].Err, &re) || re.Code != 535 || !strings.Contains(re.Hint, want) || (want == "") != (re.Hint == "") {
			t.Errorf("%s: %v", reply, outs[0].Err)
		}
		if n := len(s.ep.Requests()); n != 1 || len(s.smtp.Sessions()) != 1 {
			t.Errorf("%s: %d token requests, %d sessions", reply, n, len(s.smtp.Sessions()))
		}
	}
}

// Without XOAUTH2 offered, or without TLS, no token is asked for or sent.
func TestXOAUTH2NotOffered(t *testing.T) {
	s := newStandIn(t, false)
	s.smtp.Set(func() { s.smtp.OfferXOAUTH2 = false })
	outs := s.mailer(t, StartTLS).Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{"a@example.org"}, nil)
	if outs[0].Err == nil || !strings.Contains(outs[0].Err.Error(), "does not offer sign-in with a token (AUTH XOAUTH2)") ||
		!strings.Contains(outs[0].Err.Error(), "smtp.office365.com, port 587") {
		t.Fatalf("not offered: %v", outs[0].Err)
	}
	if len(s.ep.Requests()) != 0 {
		t.Fatal("a token was asked for")
	}
	// None is refused outright.
	if _, err := New(Config{Host: "127.0.0.1", Port: 25, Security: None, Username: m365test.Mailbox, FromAddress: m365test.Mailbox, OAuth: s.source}); err == nil ||
		!strings.Contains(err.Error(), "only over STARTTLS or TLS") {
		t.Fatalf("none: %v", err)
	}
	for name, c := range map[string]Config{
		"a password": {Host: "smtp.example.com", Port: 587, Security: StartTLS, Username: m365test.Mailbox, Password: "p", FromAddress: m365test.Mailbox, OAuth: s.source},
		"no mailbox": {Host: "smtp.example.com", Port: 587, Security: StartTLS, Username: "rmm", FromAddress: m365test.Mailbox, OAuth: s.source},
	} {
		if _, err := New(c); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	// A session that is somehow not over TLS never sends one.
	sess := &session{m: &SMTP{cfg: Config{OAuth: s.source}}}
	if err := sess.xoauth2(context.Background()); err == nil || !strings.Contains(err.Error(), "without TLS") {
		t.Fatalf("without TLS: %v", err)
	}
	if len(s.ep.Requests()) != 0 {
		t.Fatal("a token was asked for")
	}
}

// The identity platform's refusal is the sending's error, named as such,
// and nothing is sent to the mail server after its hello.
func TestXOAUTH2TokenRefused(t *testing.T) {
	s := newStandIn(t, false)
	s.ep.Set(func() { s.ep.Refuse = &m365test.BadSecret })
	outs := s.mailer(t, StartTLS).Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{"a@example.org"}, nil)
	err := outs[0].Err
	var te *m365.TokenError
	if !errors.As(err, &te) || !strings.Contains(err.Error(), "with a Microsoft 365 application") || !strings.Contains(err.Error(), "AADSTS7000215") {
		t.Fatalf("token refused: %v", err)
	}
	for _, c := range s.smtp.Sessions()[0].Commands {
		if strings.HasPrefix(c, "AUTH") || strings.HasPrefix(c, "MAIL") {
			t.Fatalf("sent %q", c)
		}
	}
	s.secretsKept(t, err)
}

// Exchange's refusals for rate are told apart from the recipient's, and
// explained; so is a sender the application may not send as.
func TestExchangeReplies(t *testing.T) {
	s := newStandIn(t, false)
	m := s.mailer(t, StartTLS)
	for reply, want := range map[string]struct {
		step, hint string
		rate       bool
	}{
		m365test.ThreadLimit:  {"message", "at most 3 connections", true},
		m365test.DayQuota:     {"message", "10,000", true},
		m365test.SendAsDenied: {"sender", "Add-RecipientPermission", false},
	} {
		s.smtp.Set(func() {
			s.smtp.MailReply, s.smtp.DataReply = "", ""
			if want.step == "sender" {
				s.smtp.MailReply = reply
			} else {
				s.smtp.DataReply = reply
			}
		})
		outs := m.Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{"a@example.org"}, nil)
		var re *ReplyError
		if !errors.As(outs[0].Err, &re) || re.Step != want.step || !strings.Contains(re.Hint, want.hint) || re.RateLimited() != want.rate {
			t.Errorf("%s: %+v", reply, outs[0].Err)
		}
	}
	for text, rate := range map[string]bool{
		"4.7.0 Temporary server error, rate limit exceeded":                        true,
		"5.7.0 Sender throttled due to continuous invalid recipients errors":       false,
		"5.1.1 RESOLVER.ADR.RecipNotFound; not found":                              false,
		"5.7.1 Message rate exceeded for this account, try again later (too many)": true,
	} {
		if (&ReplyError{Code: 450, Text: text}).RateLimited() != rate {
			t.Errorf("%q: rate %v", text, !rate)
		}
	}
	// A password refused by a tenant without basic authentication, or a
	// sender a password's account may not use, are explained too.
	if h := hint("sign-in", 535, "5.7.139 Authentication unsuccessful, basic authentication is disabled.", false); !strings.Contains(h, "Microsoft 365 application") {
		t.Fatalf("basic: %q", h)
	}
	if h := hint("sender", 550, "5.7.60 SMTP; Client does not have permissions to send as this sender", false); !strings.Contains(h, "account's own address") {
		t.Fatalf("send as: %q", h)
	}
	if h := hint("message", 550, "5.7.0 Sender throttled due to continuous invalid recipients errors", false); !strings.Contains(h, "repeated errors") {
		t.Fatalf("throttled: %q", h)
	}
	if h := hint("sign-in", 535, "5.7.139 SmtpClientAuthentication is disabled", true); !strings.Contains(h, "mailbox or for the organization") {
		t.Fatalf("disabled: %q", h)
	}
	if e := (&ReplyError{Step: "sign-in", Code: 535, Text: "5.7.3 x", Hint: "do this"}); e.Error() != "the mail server refused the sign-in: 535 5.7.3 x → do this" {
		t.Fatalf("%q", e.Error())
	}
}

// With RateRetry, a message refused for the mail server's rate is tried
// once more after it, in a new session, its room kept; without it, or
// refused again, it fails.
func TestRateRetry(t *testing.T) {
	s := newStandIn(t, false)
	var taken, released int
	gate := func(context.Context) (func(), error) {
		taken++
		return func() { released++ }, nil
	}
	m := s.mailer(t, StartTLS, func(c *Config) { c.RateRetry = 50 * time.Millisecond })
	s.smtp.Set(func() { s.smtp.DataReply, s.smtp.DataReplyTimes = m365test.ThreadLimit, 1 })
	outs := m.Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{"a@example.org", "b@example.org"}, gate)
	if outs[0].Err != nil || outs[1].Err != nil || taken != 2 || released != 0 || len(s.smtp.Sessions()) != 2 || len(s.smtp.Messages()) != 2 {
		t.Fatalf("retried: %+v, %d taken, %d released, %d sessions", outs, taken, released, len(s.smtp.Sessions()))
	}
	s.smtp.Set(func() { s.smtp.DataReply, s.smtp.DataReplyTimes = m365test.ThreadLimit, 2 })
	outs = m.Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{"a@example.org"}, gate)
	var re *ReplyError
	if !errors.As(outs[0].Err, &re) || !re.RateLimited() || released != 1 {
		t.Fatalf("refused twice: %v, %d released", outs[0].Err, released)
	}
	// Not for rate, or without RateRetry: at once.
	s.smtp.Set(func() { s.smtp.DataReply, s.smtp.DataReplyTimes = "550 5.7.1 refused", 1 })
	if outs := m.Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{"a@example.org"}, nil); outs[0].Err == nil {
		t.Fatal("a refusal not for rate was retried")
	}
	s.smtp.Set(func() { s.smtp.DataReply, s.smtp.DataReplyTimes = m365test.ThreadLimit, 1 })
	if outs := s.mailer(t, StartTLS).Send(context.Background(), Message{Subject: "s", Text: "t"}, []string{"a@example.org"}, nil); outs[0].Err == nil {
		t.Fatal("retried without RateRetry")
	}
	// The wait ends with the context.
	s.smtp.Set(func() { s.smtp.DataReply, s.smtp.DataReplyTimes = m365test.ThreadLimit, 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	slow := s.mailer(t, StartTLS, func(c *Config) { c.RateRetry = time.Hour })
	start := time.Now()
	if outs := slow.Send(ctx, Message{Subject: "s", Text: "t"}, []string{"a@example.org"}, nil); outs[0].Err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("an hour's wait: %v after %s", outs[0].Err, time.Since(start))
	}
}
