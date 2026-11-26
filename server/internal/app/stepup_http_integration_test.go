//go:build integration

package app_test

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/sso"
	"github.com/paulmataruso/easyrmm/server/internal/sso/ssotest"
)

func TestHTTPStepUp(t *testing.T) {
	h := newHarness(t, false)
	admin := h.client()
	setup, _ := os.ReadFile(filepath.Join(h.dataDir, "setup-token"))
	const pw = "correct horse battery staple"
	admin.expect(http.StatusNoContent, "POST", "/api/v1/setup", map[string]string{"token": strings.TrimSpace(string(setup)),
		"email": "admin@msp.example", "displayName": "Ada", "password": pw}, nil)

	// Signed out: nothing to step up.
	if r := admin.do("POST", "/api/v1/auth/step-up/check", map[string]string{}); r.status != http.StatusUnauthorized || r.errorCode(t) != "unauthenticated" {
		t.Fatalf("signed out: %d %s", r.status, r.body)
	}
	secret := admin.signIn("admin@msp.example", pw, "")

	// A session that has not stepped up is told so, with a code the console knows.
	r := admin.do("POST", "/api/v1/auth/step-up/check", map[string]string{})
	if r.status != http.StatusUnauthorized || r.errorCode(t) != "step_up_required" {
		t.Fatalf("not stepped up: %d %s", r.status, r.body)
	}
	var st struct {
		ValidUntil *time.Time `json:"validUntil"`
		Methods    []string   `json:"methods"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/auth/step-up", nil, &st)
	if st.ValidUntil != nil || len(st.Methods) != 1 || st.Methods[0] != "totp" {
		t.Fatalf("status = %+v", st)
	}

	// Unsafe calls carry the CSRF token like the others.
	if r := admin.do("POST", "/api/v1/auth/step-up/totp", map[string]string{"code": code(t, secret, time.Now().Add(30*time.Second))},
		func(req *http.Request) { req.Header.Del("X-CSRF-Token") }); r.status != http.StatusForbidden || r.errorCode(t) != "csrf_failed" {
		t.Fatalf("no CSRF token: %d %s", r.status, r.body)
	}
	if r := admin.do("POST", "/api/v1/auth/step-up/totp", map[string]string{"code": "000000"}); r.status != http.StatusUnauthorized || r.errorCode(t) != "invalid_code" {
		t.Fatalf("wrong code: %d %s", r.status, r.body)
	}
	if r := admin.do("POST", "/api/v1/auth/step-up/totp", map[string]string{"code": "abcdef-123456"}); r.status != http.StatusUnauthorized || r.errorCode(t) != "recovery_code_refused" {
		t.Fatalf("recovery code: %d %s", r.status, r.body)
	}
	// The enrollment code's step cannot be reused; the next one steps up.
	admin.expect(http.StatusOK, "POST", "/api/v1/auth/step-up/totp", map[string]string{"code": code(t, secret, time.Now().Add(30*time.Second))}, &st)
	if st.ValidUntil == nil || time.Until(*st.ValidUntil) < 4*time.Minute || time.Until(*st.ValidUntil) > 5*time.Minute+5*time.Second {
		t.Fatalf("after step-up: %+v", st)
	}
	admin.expect(http.StatusNoContent, "POST", "/api/v1/auth/step-up/check", map[string]string{}, nil)
}

// A person with an authenticator app and no key, and one who signed in with a password: neither has another way.
func TestHTTPStepUpWhatIsNotThere(t *testing.T) {
	h := newHarness(t, false)
	admin := h.client()
	setup, _ := os.ReadFile(filepath.Join(h.dataDir, "setup-token"))
	const pw = "correct horse battery staple"
	admin.expect(http.StatusNoContent, "POST", "/api/v1/setup", map[string]string{"token": strings.TrimSpace(string(setup)),
		"email": "admin@msp.example", "displayName": "Ada", "password": pw}, nil)
	admin.signIn("admin@msp.example", pw, "")

	// No security key to ask for, and nothing to say to a made-up answer.
	if r := admin.do("POST", "/api/v1/auth/step-up/webauthn/begin", map[string]string{}); r.status != http.StatusConflict || r.errorCode(t) != "no_second_factor" {
		t.Fatalf("begin without keys: %d %s", r.status, r.body)
	}
	if r := admin.do("POST", "/api/v1/auth/step-up/webauthn/finish", map[string]any{}); r.status != http.StatusUnprocessableEntity {
		t.Fatalf("finish without an answer: %d %s", r.status, r.body)
	}
	if r := admin.do("POST", "/api/v1/auth/step-up/webauthn/finish", map[string]any{"credential": map[string]string{"id": "x"}}); r.status != http.StatusUnauthorized || r.errorCode(t) != "key_rejected" {
		t.Fatalf("finish with a made-up answer: %d %s", r.status, r.body)
	}
	// The password session has no provider to go back to.
	if r := admin.do("POST", "/api/v1/auth/step-up/oidc/begin", map[string]string{}); r.status != http.StatusConflict || r.errorCode(t) != "no_second_factor" {
		t.Fatalf("provider step-up without a provider: %d %s", r.status, r.body)
	}
}

func TestHTTPStepUpThroughTheProvider(t *testing.T) {
	dex := ssotest.Get(t)
	h := newHarness(t, false)
	admin := h.client()
	setup, _ := os.ReadFile(filepath.Join(h.dataDir, "setup-token"))
	const pw = "correct horse battery staple"
	admin.expect(http.StatusNoContent, "POST", "/api/v1/setup", map[string]string{"token": strings.TrimSpace(string(setup)),
		"email": "admin@msp.example", "displayName": "Ada", "password": pw}, nil)
	admin.signIn("admin@msp.example", pw, "")
	var p struct {
		ID string `json:"id"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/settings/sso/providers", map[string]any{
		"name": "Dex", "issuer": dex.Issuer, "clientId": dex.ClientID, "clientSecret": dex.ClientSecret,
		"allowedDomains": []string{"sso.test"}, "trustMfa": true, "enabled": true,
	}, &p)
	var org idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations", map[string]any{"name": "Acme"}, &org)
	admin.expect(http.StatusCreated, "POST", "/api/v1/users", map[string]any{"email": ssotest.Alex, "displayName": "Alex",
		"assignments": []map[string]any{{"role": "technician", "organizationId": org.ID}}}, nil)

	// Alex signs in through the provider, which is trusted to ask for the second factor.
	browser := h.client()
	browser.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	r := browser.do("GET", "/api/v1/auth/sso/"+p.ID+"/start", nil)
	back := dex.SignIn(t, r.header.Get("Location"), ssotest.Alex)
	if r = browser.do("GET", back.RequestURI(), nil); r.status != http.StatusSeeOther {
		t.Fatalf("callback: %d %s", r.status, r.body)
	}
	var view sessionView
	browser.expect(http.StatusOK, "GET", "/api/v1/auth/session", nil, &view)
	if view.State != "active" {
		t.Fatalf("state = %q", view.State)
	}
	browser.csrf = view.CSRFToken

	var st struct {
		Methods  []string `json:"methods"`
		Provider string   `json:"provider"`
	}
	browser.expect(http.StatusOK, "GET", "/api/v1/auth/step-up", nil, &st)
	if len(st.Methods) != 1 || st.Methods[0] != "oidc" || st.Provider != "Dex" {
		t.Fatalf("status = %+v", st)
	}
	if r := browser.do("POST", "/api/v1/auth/step-up/check", map[string]string{}); r.errorCode(t) != "step_up_required" {
		t.Fatalf("before: %d %s", r.status, r.body)
	}
	// A code is not how this account steps up.
	if r := browser.do("POST", "/api/v1/auth/step-up/totp", map[string]string{"code": "123456"}); r.status != http.StatusConflict || r.errorCode(t) != "no_second_factor" {
		t.Fatalf("a code: %d %s", r.status, r.body)
	}

	var begin struct {
		AuthURL string `json:"authUrl"`
	}
	browser.expect(http.StatusOK, "POST", "/api/v1/auth/step-up/oidc/begin", map[string]string{"returnTo": "/devices?tab=x"}, &begin)
	u, _ := url.Parse(begin.AuthURL)
	if !strings.HasPrefix(begin.AuthURL, dex.Issuer+"/auth?") || u.Query().Get("prompt") != "login" || u.Query().Get("max_age") != "0" {
		t.Fatalf("authorization URL = %s", begin.AuthURL)
	}
	back = dex.SignIn(t, begin.AuthURL, ssotest.Alex)
	// The session cookie is Strict and does not come back from the provider:
	// the state finds the session.
	stranger := h.client()
	stranger.http.CheckRedirect = browser.http.CheckRedirect
	r = stranger.do("GET", back.RequestURI(), nil)
	if loc := r.header.Get("Location"); r.status != http.StatusSeeOther || loc != publicOrigin+"/devices?stepup=done&tab=x" {
		t.Fatalf("step-up callback: %d %s", r.status, loc)
	}
	browser.expect(http.StatusNoContent, "POST", "/api/v1/auth/step-up/check", map[string]string{}, nil)
	// Used once.
	if r := stranger.do("GET", back.RequestURI(), nil); r.header.Get("Location") != "/login?sso_error=expired" {
		t.Fatalf("replayed callback: %s", r.header.Get("Location"))
	}

	// Someone else's identity at the same provider comes back to the page with the reason.
	browser.expect(http.StatusOK, "POST", "/api/v1/auth/step-up/oidc/begin", map[string]string{"returnTo": "/devices"}, &begin)
	back = dex.SignIn(t, begin.AuthURL, ssotest.Sam)
	r = stranger.do("GET", back.RequestURI(), nil)
	if loc := r.header.Get("Location"); loc != publicOrigin+"/devices?reason=identity&stepup=failed" {
		t.Fatalf("another identity: %s", loc)
	}
	// And one the provider refused.
	browser.expect(http.StatusOK, "POST", "/api/v1/auth/step-up/oidc/begin", map[string]string{}, &begin)
	u, _ = url.Parse(begin.AuthURL)
	r = stranger.do("GET", sso.CallbackPath+"?state="+url.QueryEscape(u.Query().Get("state"))+"&error=access_denied", nil)
	if loc := r.header.Get("Location"); loc != publicOrigin+"/?reason=provider&stepup=failed" {
		t.Fatalf("a refusal: %s", loc)
	}
}
