package mailer

import (
	"bytes"
	"fmt"
	"html/template"
	"net/url"
	"strings"
)

// Letter is a short message from EasyRMM to a person: paragraphs, an
// optional link offered as a button, and closing paragraphs. Message
// renders it as plain text and as HTML; the HTML escapes every value by
// its context (html/template).
type Letter struct {
	Subject string
	Before  []string
	Link    *Link
	After   []string
}

// Link is a letter's one link: what its button says, and where it goes.
type Link struct {
	Label string
	URL   string
}

var letterHTML = template.Must(template.New("letter").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Subject}}</title>
</head>
<body style="margin:0;padding:24px 12px;background:#f3f5f8;color:#1b2230;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:15px;line-height:1.55">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:560px;background:#ffffff;border:1px solid #dde2ea;border-radius:8px">
<tr><td style="padding:28px 32px">
<p style="margin:0 0 20px;font-size:12px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:#5b6678">EasyRMM</p>
{{- range .Before}}
<p style="margin:0 0 16px">{{.}}</p>
{{- end}}
{{- with .Link}}
<p style="margin:24px 0"><a href="{{.URL}}" style="display:inline-block;padding:10px 18px;border-radius:6px;background:#4f8cff;color:#06101f;font-weight:600;text-decoration:none">{{.Label}}</a></p>
<p style="margin:0 0 16px;font-size:13px;color:#5b6678">If the button does not open, copy this address into your browser:<br><a href="{{.URL}}" style="color:#2f6bd8;word-break:break-all">{{.URL}}</a></p>
{{- end}}
{{- range .After}}
<p style="margin:0 0 16px">{{.}}</p>
{{- end}}
</td></tr>
</table>
</td></tr></table>
</body>
</html>
`))

// Message renders the letter. Its link must be an absolute http or https
// URL.
func (l Letter) Message() (Message, error) {
	if l.Link != nil {
		u, err := url.Parse(l.Link.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return Message{}, fmt.Errorf("mailer: the letter's link is not an http or https URL")
		}
	}
	var text strings.Builder
	for _, p := range l.Before {
		text.WriteString(p + "\n\n")
	}
	if l.Link != nil {
		text.WriteString(l.Link.URL + "\n\n")
	}
	for _, p := range l.After {
		text.WriteString(p + "\n\n")
	}
	var html bytes.Buffer
	if err := letterHTML.Execute(&html, l); err != nil {
		return Message{}, err
	}
	return Message{Subject: l.Subject, Text: strings.TrimRight(text.String(), "\n") + "\n", HTML: html.String()}, nil
}
