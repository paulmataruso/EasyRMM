// Package logredact removes secrets from log text and attributes
// (ADR-0069, Part L). The agent applies it before a record leaves the
// computer, and the server applies it again before storing one, so a
// record from an older or altered agent is covered too. The rules are
// these: the value of a field named like a secret (token, password,
// secret, key, authorization, cookie), anything shaped like an EasyRMM
// enrollment token (ert_), an EasyPatch token (ept_), a bearer token, or a
// PEM block.
package logredact

import (
	"regexp"
	"strings"
	"unicode"
)

// Mask replaces a redacted value.
const Mask = "***"

var (
	// pem matches a whole PEM block, or the start of one whose end was cut
	// off (a record or a line limit), through the end of the text.
	pem    = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]+-----.*?(?:-----END [A-Z0-9 ]+-----|$)`)
	bearer = regexp.MustCompile(`(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{6,}`)
	// tokens are the prefixed tokens of EasyRMM (ert_) and EasyPatch (ept_).
	tokens = regexp.MustCompile(`\b(ert_|ept_)[A-Za-z0-9_-]{6,}`)
	// field matches name=value, name: value and "name":"value", the value
	// being quoted or running to a delimiter. An authorization value may
	// be a scheme and a credential ("Basic abc", "Bearer abc").
	// flag matches a command-line flag and its value after a space:
	// --password hunter2, -Password hunter2, /password hunter2. The value is
	// quoted or runs to a space, and does not start with another flag.
	flag  = regexp.MustCompile(`(^|[^A-Za-z0-9_./-])(--?|/)([A-Za-z][A-Za-z0-9_.-]*)([ \t]+)("[^"]*"|'[^']*'|[^\s\-/"'][^\s]*)`)
	field = regexp.MustCompile(`(?i)([A-Za-z0-9_.-]+)(["']?\s*[:=]\s*)("(?:[^"\\]|\\.)*"|'[^']*'|(?:basic|bearer|digest|negotiate|token)\s+[^\s,;&}\]]+|[^\s,;&}\]"']+)`)
)

// Text returns s with every secret replaced.
func Text(s string) string {
	if s == "" {
		return s
	}
	s = pem.ReplaceAllString(s, "-----REDACTED KEY-----")
	s = bearer.ReplaceAllString(s, "$1 "+Mask)
	s = tokens.ReplaceAllString(s, "${1}"+Mask)
	s = flag.ReplaceAllStringFunc(s, func(m string) string {
		p := flag.FindStringSubmatch(m)
		if !SecretName(p[3]) {
			return m
		}
		return p[1] + p[2] + p[3] + p[4] + maskLike(p[5])
	})
	return field.ReplaceAllStringFunc(s, func(m string) string {
		p := field.FindStringSubmatch(m)
		if !SecretName(p[1]) {
			return m
		}
		return p[1] + p[2] + maskLike(p[3])
	})
}

// maskLike masks a value, keeping its quotes.
func maskLike(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return string(v[0]) + Mask + string(v[0])
	}
	return Mask
}

// Attr returns the value of an attribute named name: all of it masked when
// the name looks like a secret's, otherwise redacted as text.
func Attr(name, value string) string {
	if SecretName(name) {
		return Mask
	}
	return Text(value)
}

// secretWords are the words that make a field name a secret's.
var secretWords = []string{"token", "password", "passwd", "secret", "authorization", "cookie", "credential", "passphrase"}

// SecretName reports whether a field called name holds a secret: it
// contains one of the words, or has "key" as a word of its own ("api_key",
// "privateKey", "key") or ends with it ("apikey").
func SecretName(name string) bool {
	n := strings.ToLower(name)
	for _, w := range secretWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	if strings.HasSuffix(n, "apikey") || strings.HasSuffix(n, "privatekey") || strings.HasSuffix(n, "secretkey") {
		return true
	}
	for _, w := range words(name) {
		if w == "key" {
			return true
		}
	}
	return false
}

// words splits a name at punctuation and at camelCase boundaries, in lower
// case.
func words(name string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	for i, r := range name {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case unicode.IsUpper(r) && i > 0:
			prev := []rune(name[:i])[len([]rune(name[:i]))-1]
			if unicode.IsLower(prev) || unicode.IsDigit(prev) {
				flush()
			}
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return out
}
