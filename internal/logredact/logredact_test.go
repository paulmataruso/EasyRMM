package logredact

import (
	"strings"
	"testing"
)

func TestText(t *testing.T) {
	// Built in pieces: a whole block in the source would be a private key to a secret scanner.
	pemBlock := "-----BEGIN " + "PRIVATE KEY-----\n" + strings.Repeat("QUJD", 16) + "\n-----END " + "PRIVATE KEY-----"
	for _, tc := range []struct{ name, in, want string }{
		{"plain text is unchanged", "heartbeat sent in 12ms", "heartbeat sent in 12ms"},
		{"empty", "", ""},
		{"enrollment token", "enrolling with ert_AbCdEf0123456789xyz now", "enrolling with ert_*** now"},
		{"easypatch token", "token file holds ept_0123456789abcdefABCDEF-_", "token file holds ept_***"},
		{"bearer header", "Authorization: Bearer eyJhbGciOi.payload.sig", "Authorization: ***"},
		{"bearer alone", "sent bearer abcdef123456 to server", "sent bearer *** to server"},
		{"basic authorization", "authorization=Basic dXNlcjpwYXNz", "authorization=***"},
		{"password key=value", "login password=hunter2 user=bob", "login password=*** user=bob"},
		{"password colon", "password: hunter2", "password: ***"},
		{"quoted json", `{"user":"bob","password":"p w d","n":1}`, `{"user":"bob","password":"***","n":1}`},
		{"single quoted", "secret='abc def'", "secret='***'"},
		{"api key camel", "apiKey=value1 retries=3", "apiKey=*** retries=3"},
		{"key word", "key=abc", "key=***"},
		{"cookie", "Cookie: session=abc123", "Cookie: ***"},
		{"token field", "access_token=abc.def", "access_token=***"},
		{"keyboard is not a key", "keyboard=us layout", "keyboard=us layout"},
		{"monkey is not a key", "monkey=1", "monkey=1"},
		{"flag long", "run.exe --password hunter2 --verbose", "run.exe --password *** --verbose"},
		{"flag powershell", "x.ps1 -Password hunter2 -Name bob", "x.ps1 -Password *** -Name bob"},
		{"flag slash", `setup.exe /password hunter2 /quiet`, `setup.exe /password *** /quiet`},
		{"flag token quoted", `tool --token "a b c" go`, `tool --token "***" go`},
		{"flag secret and key", "tool -secret s3 --api-key k1 -key k2", "tool -secret *** --api-key *** -key ***"},
		{"flag followed by a flag", "tool --password --verbose", "tool --password --verbose"},
		{"flag not secret", "tool --name hunter2", "tool --name hunter2"},
		{"path is not a flag", "open /var/secret hunter", "open /var/secret hunter"},
		{"pem block", "loaded " + pemBlock + " done", "loaded -----REDACTED KEY----- done"},
		{"truncated pem", "bad -----BEGIN RSA PRIVATE KEY-----\nMIIE", "bad -----REDACTED KEY-----"},
		{"several in one line", "ert_aaaaaaaaaa and ept_bbbbbbbbbb and password=x", "ert_*** and ept_*** and password=***"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Text(tc.in); got != tc.want {
				t.Errorf("Text(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestTextLeavesNoSecret(t *testing.T) {
	for _, s := range []string{"ert_SuperSecretValue123", "ept_AnotherSecret456789", "eyJhbGciOiJIUzI1NiJ9.e30.abc123"} {
		for _, in := range []string{"token=" + s, "Authorization: Bearer " + s, `"password":"` + s + `"`} {
			if out := Text(in); strings.Contains(out, s) {
				t.Errorf("Text(%q) = %q still holds the secret", in, out)
			}
		}
	}
}

func TestAttr(t *testing.T) {
	if got := Attr("api_token", "abc"); got != Mask {
		t.Errorf("secret-named attribute: %q", got)
	}
	if got := Attr("path", "ok ert_AbCdEf0123456"); got != "ok ert_***" {
		t.Errorf("text rules apply to other attributes: %q", got)
	}
	for name, want := range map[string]bool{
		"Authorization": true, "setCookie": true, "private_key": true, "privateKey": true, "key": true,
		"Password": true, "client-secret": true, "keyboard": false, "hostname": false, "monkey": false, "turkey": false,
	} {
		if got := SecretName(name); got != want {
			t.Errorf("SecretName(%q) = %v, want %v", name, got, want)
		}
	}
}
