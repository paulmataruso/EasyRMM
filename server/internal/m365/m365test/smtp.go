package m365test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Exchange Online's replies, as Microsoft's documentation and forums give
// them, for the stand-in to answer with.
const (
	// SignInRefused is Exchange's answer to a token it does not take
	// ("Authenticate an IMAP, POP or SMTP connection using OAuth").
	SignInRefused = "535 5.7.3 Authentication unsuccessful [STANDIN0001.namprd00.prod.outlook.com]"
	// AuthOffTenant, AuthOffMailbox and SecurityDefaults are refusals with
	// SMTP AUTH off, as Microsoft's forums report them.
	AuthOffTenant    = "535 5.7.139 Authentication unsuccessful, SmtpClientAuthentication is disabled for the Tenant. Visit https://aka.ms/smtp_auth_disabled for more information. [STANDIN0001.namprd00.prod.outlook.com]"
	AuthOffMailbox   = "535 5.7.139 Authentication unsuccessful, SmtpClientAuthentication is disabled for the Mailbox. Visit https://aka.ms/smtp_auth_disabled for more information. [STANDIN0001.namprd00.prod.outlook.com]"
	SecurityDefaults = "535 5.7.139 Authentication unsuccessful, user is locked by your organization's security defaults policy. Contact your administrator. [STANDIN0001.namprd00.prod.outlook.com]"
	// OtherAuth139 is another 5.7.139, shown as given.
	OtherAuth139 = "535 5.7.139 Authentication unsuccessful, the request did not meet the criteria to be authenticated successfully. Contact your administrator. [STANDIN0001.namprd00.prod.outlook.com]"
	// SendAsDenied is Exchange refusing the sender's address.
	SendAsDenied = "550 5.7.60 SMTP; Client does not have permissions to send as this sender [STANDIN0001.namprd00.prod.outlook.com]"
	// ThreadLimit and DayQuota are refusals for rate: too many connections
	// at once, and the mailbox's recipients in 24 hours.
	ThreadLimit = "432 4.3.2 STOREDRV.ClientSubmit; sender thread limit exceeded [Hostname=STANDIN0001.namprd00.prod.outlook.com]"
	DayQuota    = "554 5.2.0 STOREDRV.Submission.Exception:SubmissionQuotaExceededException; Failed to process message due to a permanent exception with message [BeginDiagnosticData]Cannot submit message.[Hostname=STANDIN0001.namprd00.prod.outlook.com]"
)

// Session is one connection to the stand-in SMTP server, as it saw it.
type Session struct {
	// Commands are the commands in order; AUTH's response is not kept.
	Commands []string
	// AuthOverTLS says each AUTH came over TLS.
	AuthOverTLS []bool
	// User and Token are the last XOAUTH2 initial response's.
	User, Token string
	// Messages are the messages taken.
	Messages []string
	Quit     bool
}

// SMTPServer is a stand-in for Exchange Online's SMTP client submission
// (smtp.office365.com): it offers STARTTLS, and AUTH XOAUTH2 only over TLS,
// and takes a token the token endpoint granted, for Mailbox only.
type SMTPServer struct {
	Host string
	Port int
	ln   net.Listener
	tls  *tls.Config

	mu sync.Mutex
	// Valid tells a token granted; Mailbox is the mailbox it may sign in to.
	Valid   func(token string) bool
	Mailbox string
	// OfferXOAUTH2 offers AUTH XOAUTH2 (after TLS); otherwise only LOGIN.
	OfferXOAUTH2 bool
	// AuthBeforeTLS also offers AUTH XOAUTH2 before TLS.
	AuthBeforeTLS bool
	// SignInReply, when set, answers every AUTH; RefuseSignIns answers the
	// next so many with SignInRefused.
	SignInReply   string
	RefuseSignIns int
	// Challenge answers a refused XOAUTH2 with a 334 challenge first, as
	// Google does, before the 535.
	Challenge bool
	// MailReply, RcptReply and DataReply, when set, answer MAIL, RCPT and
	// the end of DATA; DataReplyTimes, when set, has DataReply answer only
	// the next so many messages.
	MailReply, RcptReply, DataReply string
	DataReplyTimes                  int
	sessions                        []*Session
}

// NewSMTPServer starts a stand-in on loopback until the test ends, taking
// the tokens valid says are granted, for Mailbox. With implicitTLS it
// speaks TLS from the first byte; otherwise it requires STARTTLS.
func NewSMTPServer(t testing.TB, valid func(string) bool, implicitTLS bool) *SMTPServer {
	t.Helper()
	cfg := ServerTLS()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if implicitTLS {
		ln = tls.NewListener(ln, cfg)
	}
	s := &SMTPServer{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, ln: ln, tls: cfg, Valid: valid, Mailbox: Mailbox, OfferXOAUTH2: true}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c, implicitTLS)
		}
	}()
	return s
}

// Set changes the server while it serves.
func (s *SMTPServer) Set(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f()
}

// Sessions are the sessions so far, oldest first.
func (s *SMTPServer) Sessions() []Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Session, len(s.sessions))
	for i, ss := range s.sessions {
		out[i] = *ss
		out[i].Commands = append([]string{}, ss.Commands...)
		out[i].Messages = append([]string{}, ss.Messages...)
		out[i].AuthOverTLS = append([]bool{}, ss.AuthOverTLS...)
	}
	return out
}

// Messages are every message taken, in order.
func (s *SMTPServer) Messages() []string {
	var out []string
	for _, ss := range s.Sessions() {
		out = append(out, ss.Messages...)
	}
	return out
}

func (s *SMTPServer) serve(conn net.Conn, overTLS bool) {
	defer conn.Close()
	ss := &Session{}
	s.mu.Lock()
	s.sessions = append(s.sessions, ss)
	s.mu.Unlock()
	tc := textproto.NewConn(conn)
	reply := func(line string) bool { return tc.PrintfLine("%s", line) == nil }
	record := func(cmd string) {
		s.mu.Lock()
		ss.Commands = append(ss.Commands, cmd)
		s.mu.Unlock()
	}
	if !reply("220 STANDIN0001.outlook.test Microsoft ESMTP MAIL Service ready") {
		return
	}
	signedIn := false
	for {
		line, err := tc.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		verb = strings.ToUpper(verb)
		if verb == "AUTH" {
			record("AUTH " + strings.Fields(arg + " x")[0])
		} else {
			record(line)
		}
		s.mu.Lock()
		offer, before, mailbox := s.OfferXOAUTH2, s.AuthBeforeTLS, s.Mailbox
		s.mu.Unlock()
		switch verb {
		case "EHLO":
			ext := []string{"250-STANDIN0001.outlook.test Hello [127.0.0.1]", "250-SIZE 157286400", "250-PIPELINING", "250-8BITMIME"}
			switch {
			case !overTLS:
				ext = append(ext, "250-STARTTLS")
				if before {
					ext = append(ext, "250-AUTH LOGIN XOAUTH2")
				}
			case offer:
				ext = append(ext, "250-AUTH LOGIN XOAUTH2")
			default:
				ext = append(ext, "250-AUTH LOGIN")
			}
			ext = append(ext, "250 SMTPUTF8")
			for _, l := range ext {
				if !reply(l) {
					return
				}
			}
		case "HELO":
			reply("250 STANDIN0001.outlook.test Hello [127.0.0.1]")
		case "STARTTLS":
			if overTLS {
				reply("503 5.5.2 Already in TLS")
				continue
			}
			if !reply("220 2.0.0 SMTP server ready") {
				return
			}
			t := tls.Server(conn, s.tls)
			if t.HandshakeContext(context.Background()) != nil {
				return
			}
			conn, overTLS = t, true
			tc = textproto.NewConn(conn)
			signedIn = false
		case "AUTH":
			signedIn = s.auth(tc, ss, arg, overTLS, mailbox)
		case "MAIL":
			s.mu.Lock()
			r := s.MailReply
			s.mu.Unlock()
			switch {
			case !signedIn:
				reply("530 5.7.57 Client not authenticated to send mail. [STANDIN0001.namprd00.prod.outlook.com]")
			case r != "":
				reply(r)
			default:
				reply("250 2.1.0 Sender OK")
			}
		case "RCPT":
			s.mu.Lock()
			r := s.RcptReply
			s.mu.Unlock()
			if r == "" {
				r = "250 2.1.5 Recipient OK"
			}
			reply(r)
		case "DATA":
			if !reply("354 Start mail input; end with <CRLF>.<CRLF>") {
				return
			}
			body, err := tc.ReadDotBytes()
			if err != nil {
				return
			}
			s.mu.Lock()
			r := s.DataReply
			if r != "" && s.DataReplyTimes > 0 {
				if s.DataReplyTimes--; s.DataReplyTimes == 0 {
					s.DataReply = ""
				}
			}
			if r == "" {
				ss.Messages = append(ss.Messages, string(body))
				r = "250 2.0.0 OK <stand-in@STANDIN0001.outlook.test> [Hostname=STANDIN0001.namprd00.prod.outlook.com]"
			}
			s.mu.Unlock()
			reply(r)
		case "RSET":
			reply("250 2.0.0 Resetting")
		case "NOOP":
			reply("250 2.0.0 OK")
		case "QUIT":
			s.mu.Lock()
			ss.Quit = true
			s.mu.Unlock()
			reply("221 2.0.0 Service closing transmission channel")
			return
		default:
			reply("500 5.3.3 Unrecognized command")
		}
	}
}

// auth answers AUTH, and reports whether it signed in.
func (s *SMTPServer) auth(tc *textproto.Conn, ss *Session, arg string, overTLS bool, mailbox string) bool {
	mech, ir, _ := strings.Cut(arg, " ")
	s.mu.Lock()
	ss.AuthOverTLS = append(ss.AuthOverTLS, overTLS)
	offer, before := s.OfferXOAUTH2, s.AuthBeforeTLS
	s.mu.Unlock()
	if !strings.EqualFold(mech, "XOAUTH2") || (!offer && overTLS) || (!overTLS && !before) {
		_ = tc.PrintfLine("504 5.7.4 Unrecognized authentication type")
		return false
	}
	if ir == "" {
		if tc.PrintfLine("334 ") != nil {
			return false
		}
		var err error
		if ir, err = tc.ReadLine(); err != nil {
			return false
		}
	}
	raw, err := base64.StdEncoding.DecodeString(ir)
	user, token, ok := parseXOAUTH2(string(raw))
	s.mu.Lock()
	ss.User, ss.Token = user, token
	fixed, challenge := s.SignInReply, s.Challenge
	refuse := s.RefuseSignIns > 0
	if refuse && fixed == "" {
		s.RefuseSignIns--
	}
	valid := s.Valid
	s.mu.Unlock()
	switch {
	case fixed != "":
		_ = tc.PrintfLine("%s", fixed)
		return false
	case err == nil && ok && !refuse && strings.EqualFold(user, mailbox) && valid != nil && valid(token):
		_ = tc.PrintfLine("235 2.7.0 Authentication successful")
		return true
	}
	if challenge {
		msg := base64.StdEncoding.EncodeToString([]byte(`{"status":"401","schemes":"bearer","scope":"https://outlook.office365.com/.default"}`))
		if tc.PrintfLine("334 %s", msg) != nil {
			return false
		}
		if l, err := tc.ReadLine(); err != nil || l != "" {
			_ = tc.PrintfLine("501 5.5.2 Expected an empty response")
			return false
		}
	}
	_ = tc.PrintfLine("%s", SignInRefused)
	return false
}

// parseXOAUTH2 reads an XOAUTH2 initial response: "user=" user ^A
// "auth=Bearer " token ^A ^A.
func parseXOAUTH2(s string) (user, token string, ok bool) {
	rest, ok := strings.CutSuffix(s, "\x01\x01")
	if !ok {
		return "", "", false
	}
	u, a, ok := strings.Cut(rest, "\x01")
	if !ok {
		return "", "", false
	}
	user, ok1 := strings.CutPrefix(u, "user=")
	token, ok2 := strings.CutPrefix(a, "auth=Bearer ")
	return user, token, ok1 && ok2
}

// Address is the server's host and port.
func (s *SMTPServer) Address() string { return net.JoinHostPort(s.Host, strconv.Itoa(s.Port)) }
