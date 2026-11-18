// Package mailer sends plain-text e-mail over SMTP.
package mailer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Config configures the SMTP relay.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	// TLS is "starttls" (required STARTTLS), "implicit" (TLS from the first
	// byte, usually port 465) or "none" (only for a relay on loopback).
	TLS string
	// Timeout bounds the whole exchange. Defaults to 30 seconds.
	Timeout time.Duration
}

// SMTP sends mail through a relay.
type SMTP struct {
	cfg  Config
	from *mail.Address
	// dial is replaceable in tests.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// New validates the configuration and builds a mailer.
func New(cfg Config) (*SMTP, error) {
	from, err := mail.ParseAddress(cfg.From)
	if err != nil {
		return nil, fmt.Errorf("mailer: invalid from address: %w", err)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	switch cfg.TLS {
	case "starttls", "implicit":
	case "none":
		if ip := net.ParseIP(cfg.Host); cfg.Host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, errors.New("mailer: unencrypted SMTP is only allowed to a relay on loopback")
		}
	default:
		return nil, fmt.Errorf("mailer: unknown TLS mode %q", cfg.TLS)
	}
	d := &net.Dialer{}
	return &SMTP{cfg: cfg, from: from, dial: d.DialContext}, nil
}

// Send delivers one message.
func (m *SMTP) Send(ctx context.Context, to, subject, body string) error {
	rcpt, err := mail.ParseAddress(to)
	if err != nil {
		return fmt.Errorf("mailer: invalid recipient: %w", err)
	}
	msg, err := m.compose(rcpt, subject, body)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, m.cfg.Timeout)
	defer cancel()
	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))
	conn, err := m.dial(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("mailer: connecting to %s: %w", addr, err)
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	tlsCfg := &tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12}
	if m.cfg.TLS == "implicit" {
		tc := tls.Client(conn, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return fmt.Errorf("mailer: tls handshake: %w", err)
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("mailer: %w", err)
	}
	defer c.Close()
	if err := c.Hello(localName()); err != nil {
		return fmt.Errorf("mailer: hello: %w", err)
	}
	if m.cfg.TLS == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("mailer: the relay does not offer STARTTLS; refusing to send credentials or mail in clear text")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("mailer: starttls: %w", err)
		}
	}
	if m.cfg.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)); err != nil {
			return fmt.Errorf("mailer: authentication: %w", err)
		}
	}
	if err := c.Mail(m.from.Address); err != nil {
		return fmt.Errorf("mailer: MAIL FROM: %w", err)
	}
	if err := c.Rcpt(rcpt.Address); err != nil {
		return fmt.Errorf("mailer: RCPT TO: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("mailer: DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("mailer: writing message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mailer: finishing message: %w", err)
	}
	return c.Quit()
}

func (m *SMTP) compose(to *mail.Address, subject, body string) ([]byte, error) {
	if strings.ContainsAny(subject, "\r\n") {
		return nil, errors.New("mailer: subject contains a line break")
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	domain := m.from.Address[strings.LastIndexByte(m.from.Address, '@')+1:]
	var b bytes.Buffer
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("From", m.from.String())
	h("To", to.String())
	h("Subject", mime.QEncoding.Encode("utf-8", subject))
	h("Date", time.Now().UTC().Format(time.RFC1123Z))
	h("Message-ID", "<"+hex.EncodeToString(id)+"@"+domain+">")
	h("MIME-Version", "1.0")
	h("Content-Type", "text/plain; charset=utf-8")
	h("Content-Transfer-Encoding", "quoted-printable")
	h("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	if _, err := qp.Write([]byte(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n"))); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func localName() string {
	return "easyrmm.localdomain"
}
