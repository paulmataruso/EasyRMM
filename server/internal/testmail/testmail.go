// Package testmail reaches the real SMTP servers integration tests send
// mail to: Mailpit on loopback (make test-mail), read through its API.
//
// make test-mail starts three, all asking for a user name and password and
// refusing recipients at .invalid, so that a test sees one refused: one
// speaking plain SMTP, as to a relay on the same machine, one requiring
// STARTTLS, and one speaking TLS from the first byte, with a certificate
// for 127.0.0.1 only the tests trust. Tests find them through
// EASYRMM_TEST_MAIL_DIR. Each Mailpit value sends from an address of its
// own, and finds its messages by it, so tests running at once never read
// each other's mail.
package testmail

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// DirEnv names the directory make test-mail writes env.json to.
const DirEnv = "EASYRMM_TEST_MAIL_DIR"

// The Mailpit servers, by how they are reached.
const (
	Plain    = "plain"
	StartTLS = "starttls"
	TLS      = "tls"
)

// Refused is a recipient Mailpit refuses.
const Refused = "nobody@refused.invalid"

type server struct {
	SMTP string `json:"smtp"`
	API  string `json:"api"`
}

// Env is env.json.
type Env struct {
	Username string `json:"username"`
	Password string `json:"password"`
	// CA is the certificate the TLS servers present.
	CA       string `json:"ca"`
	Plain    server `json:"plain"`
	StartTLS server `json:"starttls"`
	TLS      server `json:"tls"`
}

// Load reads env.json. Integration tests are compiled only with the
// "integration" build tag; there a missing Mailpit fails the test, so CI
// can never pass without sending real mail.
func Load(t testing.TB) Env {
	t.Helper()
	dir := os.Getenv(DirEnv)
	if dir == "" {
		t.Fatalf("%s is not set; run `make test-mail` and export the printed value", DirEnv)
	}
	b, err := os.ReadFile(filepath.Join(dir, "env.json"))
	if err != nil {
		t.Fatalf("%s: %v", DirEnv, err)
	}
	var e Env
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("%s/env.json: %v", dir, err)
	}
	return e
}

// CA is the certificate the TLS servers present, PEM, for a TestMain to
// trust as a system root (m365test.Trust), as a public mail server's would
// be; nil without make test-mail.
func CA() []byte {
	dir := os.Getenv(DirEnv)
	if dir == "" {
		return nil
	}
	var e Env
	b, err := os.ReadFile(filepath.Join(dir, "env.json"))
	if err != nil || json.Unmarshal(b, &e) != nil {
		return nil
	}
	ca, err := os.ReadFile(e.CA)
	if err != nil {
		return nil
	}
	return ca
}

// Mailpit is one test SMTP server, seen from one test.
type Mailpit struct {
	t        testing.TB
	Host     string
	Port     int
	Username string
	Password string
	// From is the address this test sends from.
	From string
	api  string
	http *http.Client
}

// New is the plain SMTP server.
func New(t testing.TB) *Mailpit { return Mode(t, Plain) }

// Mode is the server reached in the given way: Plain, StartTLS or TLS.
func Mode(t testing.TB, mode string) *Mailpit {
	t.Helper()
	e := Load(t)
	s := map[string]server{Plain: e.Plain, StartTLS: e.StartTLS, TLS: e.TLS}[mode]
	host, port, err := net.SplitHostPort(s.SMTP)
	if err != nil {
		t.Fatalf("Mailpit %s: %v", mode, err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("Mailpit %s: %v", mode, err)
	}
	m := &Mailpit{t: t, Host: host, Port: p, Username: e.Username, Password: e.Password, api: s.API,
		http: &http.Client{Timeout: 10 * time.Second}}
	m.From = m.Address("rmm")
	return m
}

// Address is an address of its own, which Mailpit accepts.
func (m *Mailpit) Address(prefix string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return prefix + "-" + hex.EncodeToString(b) + "@mail.easyrmm.test"
}

// Addr is a sender or recipient as Mailpit reads it.
type Addr struct {
	Name    string `json:"Name"`
	Address string `json:"Address"`
}

// Part is an attachment as Mailpit reads it.
type Part struct {
	PartID      string `json:"PartID"`
	FileName    string `json:"FileName"`
	ContentType string `json:"ContentType"`
	Size        int    `json:"Size"`
}

// Message is a message Mailpit received.
type Message struct {
	ID          string `json:"ID"`
	MessageID   string `json:"MessageID"`
	From        Addr   `json:"From"`
	To          []Addr `json:"To"`
	Subject     string `json:"Subject"`
	Text        string `json:"Text"`
	HTML        string `json:"HTML"`
	Attachments []Part `json:"Attachments"`
}

func (m *Mailpit) get(path string, out any) {
	m.t.Helper()
	res, err := m.http.Get(m.api + path)
	if err != nil {
		m.t.Fatalf("Mailpit: %v", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil || res.StatusCode != http.StatusOK {
		m.t.Fatalf("Mailpit %s: %d %s %v", path, res.StatusCode, body, err)
	}
	if b, ok := out.(*[]byte); ok {
		*b = body
		return
	}
	if err := json.Unmarshal(body, out); err != nil {
		m.t.Fatalf("Mailpit %s: %v", path, err)
	}
}

// Received lists the messages from m.From to the address, newest first.
func (m *Mailpit) Received(to string) []Message { return m.ReceivedFrom(m.From, to) }

// ReceivedFrom lists the messages from one address to another, newest
// first.
func (m *Mailpit) ReceivedFrom(from, to string) []Message {
	m.t.Helper()
	var found struct {
		Messages []struct {
			ID string `json:"ID"`
		} `json:"messages"`
	}
	m.get("/api/v1/search?limit=200&query="+url.QueryEscape(fmt.Sprintf("from:%q to:%q", from, to)), &found)
	out := make([]Message, 0, len(found.Messages))
	for _, s := range found.Messages {
		var full Message
		m.get("/api/v1/message/"+url.PathEscape(s.ID), &full)
		out = append(out, full)
	}
	return out
}

// Wait waits up to 15 seconds for n messages from m.From to the address,
// and returns them, newest first.
func (m *Mailpit) Wait(to string, n int) []Message {
	m.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		got := m.Received(to)
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			m.t.Fatalf("Mailpit: %d messages to %s, want %d", len(got), to, n)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// Raw is a message's source, as it was received.
func (m *Mailpit) Raw(id string) string {
	m.t.Helper()
	var b []byte
	m.get("/api/v1/message/"+url.PathEscape(id)+"/raw", &b)
	return string(b)
}

// Attachment is one attachment's content.
func (m *Mailpit) Attachment(id, part string) []byte {
	m.t.Helper()
	var b []byte
	m.get("/api/v1/message/"+url.PathEscape(id)+"/part/"+url.PathEscape(part), &b)
	return b
}
