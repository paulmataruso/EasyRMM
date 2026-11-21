package mailer

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Limits on what one message carries.
const (
	// MaxSubject is the longest subject, in characters.
	MaxSubject = 200
	// MaxAttachments is the most a message's attachments may hold together,
	// before encoding: a monthly report's PDF is at most 15 MB.
	MaxAttachments = 20 << 20
)

// Message is what is sent: a subject, plain text, and optionally HTML (sent
// with the text as its alternative) and attachments.
type Message struct {
	Subject string
	Text    string
	HTML    string
	// Attachments are sent after the text, each as its own part.
	Attachments []Attachment
}

// Attachment is a file sent with a message.
type Attachment struct {
	// Name is the file's name, as the recipient sees it.
	Name string
	// ContentType is its media type, application/octet-stream when empty.
	ContentType string
	Data        []byte
}

func (msg Message) check() error {
	switch {
	case strings.ContainsAny(msg.Subject, "\r\n"):
		return errors.New("mailer: the subject contains a line break")
	case utf8.RuneCountInString(msg.Subject) > MaxSubject:
		return fmt.Errorf("mailer: the subject is longer than %d characters", MaxSubject)
	case !utf8.ValidString(msg.Subject + msg.Text + msg.HTML):
		return errors.New("mailer: the message is not UTF-8")
	}
	total := 0
	for _, a := range msg.Attachments {
		if a.Name == "" || len(a.Name) > 255 || strings.ContainsFunc(a.Name, unicode.IsControl) || strings.ContainsAny(a.Name, `/\`) {
			return fmt.Errorf("mailer: invalid attachment name %q", a.Name)
		}
		if a.ContentType != "" {
			if _, _, err := mime.ParseMediaType(a.ContentType); err != nil || strings.ContainsAny(a.ContentType, "\r\n") {
				return fmt.Errorf("mailer: invalid media type %q for %s", a.ContentType, a.Name)
			}
		}
		total += len(a.Data)
	}
	if total > MaxAttachments {
		return fmt.Errorf("mailer: the attachments hold %d bytes, more than %d", total, MaxAttachments)
	}
	return nil
}

// compose writes the message to one recipient, with its headers.
func (m *SMTP) compose(to *mail.Address, msg Message, now time.Time) ([]byte, error) {
	var b bytes.Buffer
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("From", m.from.String())
	h("To", to.String())
	h("Subject", fold("Subject", mime.QEncoding.Encode("utf-8", msg.Subject)))
	h("Date", now.UTC().Format(time.RFC1123Z))
	h("Message-ID", "<"+randomHex(16)+"@"+m.from.Address[strings.LastIndexByte(m.from.Address, '@')+1:]+">")
	h("MIME-Version", "1.0")
	// Automatic mail (RFC 3834): out-of-office replies are not sent back.
	h("Auto-Submitted", "auto-generated")
	bodyHeader, bodyContent, err := body(msg)
	if err != nil {
		return nil, err
	}
	if len(msg.Attachments) == 0 {
		for _, k := range []string{"Content-Type", "Content-Transfer-Encoding"} {
			if v := bodyHeader.Get(k); v != "" {
				h(k, v)
			}
		}
		b.WriteString("\r\n")
		b.Write(bodyContent)
		return b.Bytes(), nil
	}
	mw := multipart.NewWriter(&b)
	h("Content-Type", mime.FormatMediaType("multipart/mixed", map[string]string{"boundary": mw.Boundary()}))
	b.WriteString("\r\n")
	w, err := mw.CreatePart(bodyHeader)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(bodyContent); err != nil {
		return nil, err
	}
	for _, a := range msg.Attachments {
		ct := a.ContentType
		if ct == "" {
			ct = "application/octet-stream"
		}
		mt, params, _ := mime.ParseMediaType(ct)
		params["name"] = a.Name
		hdr := textproto.MIMEHeader{}
		hdr.Set("Content-Type", mime.FormatMediaType(mt, params))
		hdr.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": a.Name}))
		hdr.Set("Content-Transfer-Encoding", "base64")
		w, err := mw.CreatePart(hdr)
		if err != nil {
			return nil, err
		}
		if err := base64Lines(w, a.Data); err != nil {
			return nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// body is the text, or the text and its HTML alternative: the headers that
// describe it and its content, for the message itself or a part of it.
func body(msg Message) (textproto.MIMEHeader, []byte, error) {
	hdr := textproto.MIMEHeader{}
	var b bytes.Buffer
	if msg.HTML == "" {
		hdr.Set("Content-Type", "text/plain; charset=utf-8")
		hdr.Set("Content-Transfer-Encoding", "quoted-printable")
		err := writeQP(&b, msg.Text)
		return hdr, b.Bytes(), err
	}
	alt := multipart.NewWriter(&b)
	hdr.Set("Content-Type", mime.FormatMediaType("multipart/alternative", map[string]string{"boundary": alt.Boundary()}))
	for _, p := range []struct{ ct, content string }{{"text/plain; charset=utf-8", msg.Text}, {"text/html; charset=utf-8", msg.HTML}} {
		ph := textproto.MIMEHeader{}
		ph.Set("Content-Type", p.ct)
		ph.Set("Content-Transfer-Encoding", "quoted-printable")
		w, err := alt.CreatePart(ph)
		if err != nil {
			return nil, nil, err
		}
		if err := writeQP(w, p.content); err != nil {
			return nil, nil, err
		}
	}
	if err := alt.Close(); err != nil {
		return nil, nil, err
	}
	return hdr, b.Bytes(), nil
}

// writeQP writes s in quoted-printable, with CRLF line ends.
func writeQP(w io.Writer, s string) error {
	qp := quotedprintable.NewWriter(w)
	if _, err := qp.Write([]byte(strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n"))); err != nil {
		return err
	}
	return qp.Close()
}

// fold folds a header's value at spaces so that no line is longer than 78
// characters (RFC 5322): Go's encoder splits long text into encoded words
// separated by spaces.
func fold(name, value string) string {
	var b strings.Builder
	line := len(name) + 2
	for i, word := range strings.Split(value, " ") {
		switch {
		case i == 0 && line+len(word) > 78:
			// The field's body may begin on the next line.
			b.WriteString("\r\n ")
			line = 1
		case i == 0:
		case line+1+len(word) > 78:
			b.WriteString("\r\n ")
			line = 1
		default:
			b.WriteString(" ")
			line++
		}
		b.WriteString(word)
		line += len(word)
	}
	return b.String()
}

func randomHex(n int) string {
	id := make([]byte, n)
	_, _ = rand.Read(id)
	return hex.EncodeToString(id)
}
