//go:build integration

package app_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/auth/webauthntest"
	"github.com/paulmataruso/easyrmm/server/internal/config"
)

// rawJSON passes the server's options to the software key unchanged.
func rawJSON(r response) []byte { return r.body }

type webauthnOptions struct {
	WebAuthn struct {
		Available bool   `json:"available"`
		Origin    string `json:"origin"`
		Reason    string `json:"reason"`
	} `json:"webauthn"`
}

func TestHTTPSecurityKeysAndPasskeys(t *testing.T) {
	h := newHarness(t, false)
	c := h.client()
	setup, _ := os.ReadFile(filepath.Join(h.dataDir, "setup-token"))
	const pw = "correct horse battery staple"
	c.expect(http.StatusNoContent, "POST", "/api/v1/setup", map[string]string{"token": strings.TrimSpace(string(setup)),
		"email": "admin@msp.example", "displayName": "Ada", "password": pw}, nil)

	var opts webauthnOptions
	c.expect(http.StatusOK, "GET", "/api/v1/auth/options", nil, &opts)
	if !opts.WebAuthn.Available || opts.WebAuthn.Origin != publicOrigin {
		t.Fatalf("options: %+v", opts.WebAuthn)
	}

	// First sign-in: set up a security key instead of an app.
	var s sessionView
	c.expect(http.StatusOK, "POST", "/api/v1/auth/login", map[string]string{"email": "admin@msp.example", "password": pw}, &s)
	c.csrf = s.CSRFToken
	if s.State != "mfa_enrollment" {
		t.Fatalf("state %q", s.State)
	}
	key := webauthntest.New(t, "rmm.test", publicOrigin)
	creation := c.expect(http.StatusOK, "POST", "/api/v1/auth/security-keys/begin", map[string]string{}, nil)
	var added struct {
		Key struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"key"`
		RecoveryCodes []string    `json:"recoveryCodes"`
		Session       sessionView `json:"session"`
	}
	c.expect(http.StatusOK, "POST", "/api/v1/auth/security-keys/finish",
		map[string]any{"name": "YubiKey", "credential": json.RawMessage(key.Create(t, rawJSON(creation)))}, &added)
	if added.Key.Name != "YubiKey" || len(added.RecoveryCodes) != 10 || added.Session.State != "active" || !added.Session.User.MFAEnabled {
		t.Fatalf("added: %+v", added)
	}
	c.csrf = added.Session.CSRFToken
	var list struct {
		Items []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
	}
	c.expect(http.StatusOK, "GET", "/api/v1/auth/security-keys", nil, &list)
	if len(list.Items) != 1 || list.Items[0].ID != added.Key.ID {
		t.Fatalf("list: %+v", list)
	}

	// The last second factor stays.
	if r := c.do("POST", "/api/v1/auth/security-keys/"+added.Key.ID+"/remove", map[string]string{"password": pw}); r.status != http.StatusConflict || r.errorCode(t) != "last_factor" {
		t.Fatalf("remove last: %d %s", r.status, r.body)
	}

	// From the account page the password is needed, and names are checked.
	if r := c.do("POST", "/api/v1/auth/security-keys/begin", map[string]string{"password": "wrong"}); r.status != http.StatusUnprocessableEntity {
		t.Fatalf("wrong password: %d %s", r.status, r.body)
	}
	spare := webauthntest.New(t, "rmm.test", publicOrigin)
	creation = c.expect(http.StatusOK, "POST", "/api/v1/auth/security-keys/begin", map[string]string{"password": pw}, nil)
	answer := json.RawMessage(spare.Create(t, rawJSON(creation)))
	if r := c.do("POST", "/api/v1/auth/security-keys/finish", map[string]any{"name": "", "credential": answer}); r.status != http.StatusUnprocessableEntity {
		t.Fatalf("no name: %d %s", r.status, r.body)
	}
	if r := c.do("POST", "/api/v1/auth/security-keys/finish", map[string]any{"name": "Spare"}); r.status != http.StatusUnprocessableEntity {
		t.Fatalf("no credential: %d %s", r.status, r.body)
	}
	c.expect(http.StatusOK, "POST", "/api/v1/auth/security-keys/finish", map[string]any{"name": "Spare", "credential": answer}, &added)
	if added.RecoveryCodes == nil || len(added.RecoveryCodes) != 0 {
		t.Fatalf("second key brought codes: %+v", added.RecoveryCodes)
	}
	creation = c.expect(http.StatusOK, "POST", "/api/v1/auth/security-keys/begin", map[string]string{"password": pw}, nil)
	if r := c.do("POST", "/api/v1/auth/security-keys/finish", map[string]any{"name": "Spare",
		"credential": json.RawMessage(webauthntest.New(t, "rmm.test", publicOrigin).Create(t, rawJSON(creation)))}); r.status != http.StatusUnprocessableEntity {
		t.Fatalf("same name: %d %s", r.status, r.body)
	}
	if r := c.do("POST", "/api/v1/auth/security-keys/not-a-uuid/remove", map[string]string{"password": pw}); r.status != http.StatusNotFound {
		t.Fatalf("bad id: %d", r.status)
	}
	if r := c.do("POST", "/api/v1/auth/security-keys/"+added.Key.ID+"/remove", map[string]string{"password": "wrong"}); r.status != http.StatusUnprocessableEntity {
		t.Fatalf("remove wrong password: %d", r.status)
	}
	c.expect(http.StatusNoContent, "POST", "/api/v1/auth/security-keys/"+added.Key.ID+"/remove", map[string]string{"password": pw}, nil)
	if r := c.do("POST", "/api/v1/auth/security-keys/"+added.Key.ID+"/remove", map[string]string{"password": pw}); r.status != http.StatusNotFound {
		t.Fatalf("removed twice: %d", r.status)
	}

	// Next sign-in: password, then the key.
	b := h.client()
	b.expect(http.StatusOK, "POST", "/api/v1/auth/login", map[string]string{"email": "admin@msp.example", "password": pw}, &s)
	b.csrf = s.CSRFToken
	if s.State != "mfa_required" {
		t.Fatalf("state %q", s.State)
	}
	if r := b.do("GET", "/api/v1/auth/security-keys", nil); r.status != http.StatusUnauthorized && r.status != http.StatusForbidden {
		t.Fatalf("keys before sign-in finished: %d", r.status)
	}
	b.expect(http.StatusOK, "POST", "/api/v1/auth/mfa/webauthn/begin", nil, nil)
	if r := b.do("POST", "/api/v1/auth/mfa/webauthn/finish", map[string]any{"credential": json.RawMessage(`{"id":"x"}`)}); r.status != http.StatusUnauthorized || r.errorCode(t) != "key_rejected" {
		t.Fatalf("junk answer: %d %s", r.status, r.body)
	}
	assertion := b.expect(http.StatusOK, "POST", "/api/v1/auth/mfa/webauthn/begin", nil, nil)
	b.expect(http.StatusOK, "POST", "/api/v1/auth/mfa/webauthn/finish", map[string]any{"credential": json.RawMessage(key.Get(t, rawJSON(assertion)))}, &s)
	if s.State != "active" || len(s.Permissions) == 0 {
		t.Fatalf("after key: %+v", s)
	}
	b.csrf = s.CSRFToken
	b.expect(http.StatusOK, "GET", "/api/v1/auth/sessions", nil, nil)

	// A passkey alone, from a fresh browser.
	p := h.client()
	assertion = p.expect(http.StatusOK, "POST", "/api/v1/auth/passkey/begin", nil, nil)
	if !strings.Contains(string(assertion.body), `"userVerification":"required"`) {
		t.Fatalf("passkey sign-in must require user verification: %s", assertion.body)
	}
	p.expect(http.StatusOK, "POST", "/api/v1/auth/passkey/finish", map[string]any{"credential": json.RawMessage(key.Get(t, rawJSON(assertion)))}, &s)
	if s.State != "active" || s.User.Email != "admin@msp.example" {
		t.Fatalf("passkey: %+v", s)
	}
	p.csrf = s.CSRFToken
	p.expect(http.StatusOK, "GET", "/api/v1/auth/sessions", nil, nil)
	// Signing in again replaces this browser's session.
	assertion = p.expect(http.StatusOK, "POST", "/api/v1/auth/passkey/begin", nil, nil)
	old := p.csrf
	p.expect(http.StatusOK, "POST", "/api/v1/auth/passkey/finish", map[string]any{"credential": json.RawMessage(key.Get(t, rawJSON(assertion)))}, &s)
	if s.CSRFToken == old {
		t.Fatal("session not replaced")
	}
	p.csrf = s.CSRFToken
	if r := p.do("POST", "/api/v1/auth/passkey/finish", map[string]any{"credential": json.RawMessage(key.Get(t, rawJSON(assertion)))}); r.status != http.StatusUnauthorized {
		t.Fatalf("replayed passkey: %d %s", r.status, r.body)
	}
	if r := p.do("POST", "/api/v1/auth/passkey/finish", map[string]any{"credential": "text"}); r.status != http.StatusUnprocessableEntity {
		t.Fatalf("string credential: %d %s", r.status, r.body)
	}
	// Another site cannot start a passkey sign-in in this browser.
	p.origin = "https://evil.test"
	if r := p.do("POST", "/api/v1/auth/passkey/begin", nil); r.status != http.StatusForbidden {
		t.Fatalf("cross-origin begin: %d", r.status)
	}
}

func TestHTTPSecurityKeysNeedAName(t *testing.T) {
	h := newHarnessWith(t, false, func(c *config.Config) { c.PublicURL, _ = url.Parse("https://192.0.2.10") })
	c := h.client()
	c.origin = "https://192.0.2.10"
	atIP := func(r *http.Request) { r.Host = "192.0.2.10" }
	var opts webauthnOptions
	c.do("GET", "/api/v1/auth/options", nil, atIP).decode(t, &opts)
	if opts.WebAuthn.Available || !strings.Contains(opts.WebAuthn.Reason, "IP address") {
		t.Fatalf("options: %+v", opts.WebAuthn)
	}
	if r := c.do("POST", "/api/v1/auth/passkey/begin", nil, atIP); r.status != http.StatusNotFound || r.errorCode(t) != "webauthn_unavailable" {
		t.Fatalf("passkey on an IP: %d %s", r.status, r.body)
	}
}
