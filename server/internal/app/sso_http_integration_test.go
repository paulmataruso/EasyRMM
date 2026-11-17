//go:build integration

package app_test

import (
	"context"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/sso"
	"github.com/paulmataruso/easyrmm/server/internal/sso/ssotest"
)

// cookie finds a cookie a response set.
func cookie(r response, name string) *http.Cookie {
	for _, c := range (&http.Response{Header: r.header}).Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestHTTPSingleSignOn(t *testing.T) {
	dex := ssotest.Get(t)
	// IP access gives the console a second address to start from.
	h := newHarnessWith(t, false, func(c *config.Config) {
		c.IPAccess = true
		c.IPAddresses = []netip.Addr{netip.MustParseAddr("203.0.113.10")}
	})
	if publicOrigin != ssotest.AppPublicURL {
		t.Fatalf("the test Dex is registered for %s, the harness serves %s", ssotest.AppPublicURL, publicOrigin)
	}
	admin := h.client()
	setup, _ := os.ReadFile(filepath.Join(h.dataDir, "setup-token"))
	const pw = "correct horse battery staple"
	admin.expect(http.StatusNoContent, "POST", "/api/v1/setup", map[string]string{"token": strings.TrimSpace(string(setup)),
		"email": "admin@msp.example", "displayName": "Ada", "password": pw}, nil)
	admin.signIn("admin@msp.example", pw, "")

	// Settings: the redirect URI to register, then a provider.
	var settings struct {
		RedirectURI string           `json:"redirectUri"`
		Providers   []map[string]any `json:"providers"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/settings/sso", nil, &settings)
	if settings.RedirectURI != publicOrigin+"/api/v1/auth/sso/callback" || len(settings.Providers) != 0 {
		t.Fatalf("settings = %+v", settings)
	}
	if r := admin.do("POST", "/api/v1/settings/sso/providers", map[string]any{"name": "Dex"}); r.status != http.StatusUnprocessableEntity {
		t.Fatalf("incomplete provider: %d %s", r.status, r.body)
	}
	var p struct {
		ID           string `json:"id"`
		ClientSecret string `json:"clientSecret"`
	}
	r := admin.expect(http.StatusCreated, "POST", "/api/v1/settings/sso/providers", map[string]any{
		"name": "Dex", "issuer": dex.Issuer, "clientId": dex.ClientID, "clientSecret": dex.ClientSecret,
		"allowedDomains": []string{"sso.test"}, "enabled": true,
	}, &p)
	if strings.Contains(string(r.body), dex.ClientSecret) {
		t.Fatal("the client secret came back")
	}

	// The sign-in page lists it, signed out.
	anon := h.client()
	var buttons struct {
		Providers []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			StartURL string `json:"startUrl"`
		} `json:"providers"`
	}
	anon.expect(http.StatusOK, "GET", "/api/v1/auth/sso", nil, &buttons)
	if len(buttons.Providers) != 1 || buttons.Providers[0].StartURL != publicOrigin+"/api/v1/auth/sso/"+p.ID+"/start" {
		t.Fatalf("buttons = %+v", buttons)
	}

	// Alex is invited as a technician and has not chosen a password.
	var org struct {
		ID string `json:"id"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations", map[string]any{"name": "Acme"}, &org)
	admin.expect(http.StatusCreated, "POST", "/api/v1/users", map[string]any{"email": ssotest.Alex, "displayName": "Alex",
		"assignments": []map[string]any{{"role": "technician", "organizationId": org.ID}}}, nil)

	browser := h.client()
	browser.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	// Started at another address, the sign-in moves to the public URL first.
	r = browser.do("GET", "/api/v1/auth/sso/"+p.ID+"/start?returnTo=%2Fdevices", nil, func(req *http.Request) { req.Host = "203.0.113.10" })
	if r.status != http.StatusSeeOther || r.header.Get("Location") != publicOrigin+"/api/v1/auth/sso/"+p.ID+"/start?returnTo=%2Fdevices" {
		t.Fatalf("start elsewhere: %d %s", r.status, r.header.Get("Location"))
	}

	r = browser.do("GET", "/api/v1/auth/sso/"+p.ID+"/start?returnTo=%2Fdevices", nil)
	if r.status != http.StatusSeeOther || !strings.HasPrefix(r.header.Get("Location"), dex.Issuer+"/auth?") {
		t.Fatalf("start: %d %s", r.status, r.header.Get("Location"))
	}
	flow := cookie(r, "__Host-easyrmm_sso")
	if flow == nil || !flow.HttpOnly || !flow.Secure || flow.SameSite != http.SameSiteLaxMode || flow.Path != "/" || flow.MaxAge != 600 {
		t.Fatalf("flow cookie = %+v", flow)
	}
	back := dex.SignIn(t, r.header.Get("Location"), ssotest.Alex)
	if back.Scheme+"://"+back.Host != publicOrigin {
		t.Fatalf("Dex sent the browser to %s", back)
	}

	// Someone else's browser with this callback: no sign-in in progress.
	other := h.client()
	other.http.CheckRedirect = browser.http.CheckRedirect
	r = other.do("GET", back.RequestURI(), nil)
	if r.status != http.StatusSeeOther || r.header.Get("Location") != "/login?sso_error=expired" || cookie(r, "__Host-easyrmm_session") != nil {
		t.Fatalf("callback in another browser: %d %s", r.status, r.header.Get("Location"))
	}

	r = browser.do("GET", back.RequestURI(), nil)
	if r.status != http.StatusSeeOther || r.header.Get("Location") != "/login?returnTo=%2Fdevices" {
		t.Fatalf("callback: %d %s %s", r.status, r.header.Get("Location"), r.body)
	}
	if c := cookie(r, "__Host-easyrmm_sso"); c == nil || c.MaxAge >= 0 {
		t.Fatalf("flow cookie not cleared: %+v", c)
	}
	if c := cookie(r, "__Host-easyrmm_session"); c == nil || c.SameSite != http.SameSiteStrictMode || !c.HttpOnly {
		t.Fatalf("session cookie = %+v", c)
	}
	// Used once: the same callback again finds no sign-in in progress.
	if r := browser.do("GET", back.RequestURI(), nil); r.header.Get("Location") != "/login?sso_error=expired" {
		t.Fatalf("replayed callback: %s", r.header.Get("Location"))
	}

	// The session continues like one after a password: Alex sets up a
	// second factor.
	var s sessionView
	browser.expect(http.StatusOK, "GET", "/api/v1/auth/session", nil, &s)
	if s.State != "mfa_enrollment" || s.User.Email != ssotest.Alex {
		t.Fatalf("session = %+v", s)
	}
	browser.csrf = s.CSRFToken
	var enr struct {
		Secret string `json:"secret"`
	}
	browser.expect(http.StatusOK, "POST", "/api/v1/auth/mfa/totp/begin", map[string]string{}, &enr)
	var done struct {
		Session sessionView `json:"session"`
	}
	browser.expect(http.StatusOK, "POST", "/api/v1/auth/mfa/totp/confirm", map[string]string{"code": code(t, enr.Secret, time.Now())}, &done)
	if done.Session.State != "active" {
		t.Fatalf("after enrollment: %+v", done.Session)
	}
	browser.csrf = done.Session.CSRFToken

	// A technician manages their own identities, not the providers.
	if r := browser.do("GET", "/api/v1/settings/sso", nil); r.status != http.StatusForbidden {
		t.Fatalf("technician reading settings: %d", r.status)
	}
	var list struct {
		Items []struct {
			ProviderID   string `json:"providerId"`
			ProviderName string `json:"providerName"`
			Email        string `json:"email"`
		} `json:"items"`
	}
	browser.expect(http.StatusOK, "GET", "/api/v1/auth/identities", nil, &list)
	ids := list.Items
	if len(ids) != 1 || ids[0].ProviderID != p.ID || ids[0].ProviderName != "Dex" || ids[0].Email != ssotest.Alex {
		t.Fatalf("identities = %+v", ids)
	}
	browser.expect(http.StatusNoContent, "DELETE", "/api/v1/auth/identities/"+p.ID, nil, nil)
	browser.expect(http.StatusNotFound, "DELETE", "/api/v1/auth/identities/"+p.ID, nil, nil)

	// Failures land on the sign-in page with a reason it can explain.
	r = browser.do("GET", "/api/v1/auth/sso/not-an-id/start", nil)
	if r.header.Get("Location") != "/login?sso_error=unavailable" {
		t.Fatalf("unknown provider: %s", r.header.Get("Location"))
	}
	stranger := h.client()
	stranger.http.CheckRedirect = browser.http.CheckRedirect
	r = stranger.do("GET", "/api/v1/auth/sso/"+p.ID+"/start", nil)
	back = dex.SignIn(t, r.header.Get("Location"), ssotest.Nobody)
	if r := stranger.do("GET", back.RequestURI(), nil); r.header.Get("Location") != "/login?sso_error=no_account" {
		t.Fatalf("no account: %s", r.header.Get("Location"))
	}

	// Malformed requests.
	for _, c := range []struct {
		method, path string
		body         any
		status       int
	}{
		{"PUT", "/api/v1/settings/sso/providers/not-an-id", map[string]any{}, http.StatusNotFound},
		{"PUT", "/api/v1/settings/sso/providers/" + p.ID, "not an object", http.StatusBadRequest},
		{"PUT", "/api/v1/settings/sso/providers/" + p.ID, map[string]any{"name": ""}, http.StatusUnprocessableEntity},
		{"PUT", "/api/v1/settings/sso/providers/00000000-0000-4000-8000-000000000000", map[string]any{}, http.StatusNotFound},
		{"POST", "/api/v1/settings/sso/providers", "not an object", http.StatusBadRequest},
		{"DELETE", "/api/v1/settings/sso/providers/not-an-id", nil, http.StatusNotFound},
	} {
		if r := admin.do(c.method, c.path, c.body); r.status != c.status {
			t.Errorf("%s %s: %d, want %d: %s", c.method, c.path, r.status, c.status, r.body)
		}
	}
	if r := browser.do("DELETE", "/api/v1/auth/identities/not-an-id", nil); r.status != http.StatusNotFound {
		t.Errorf("unlink with a bad id: %d", r.status)
	}

	// Changing the provider: the stored secret is kept when none is sent.
	admin.expect(http.StatusOK, "PUT", "/api/v1/settings/sso/providers/"+p.ID, map[string]any{
		"name": "Dex", "issuer": dex.Issuer, "clientId": dex.ClientID, "allowedDomains": []string{"sso.test"}, "enabled": false,
	}, nil)
	anon.expect(http.StatusOK, "GET", "/api/v1/auth/sso", nil, &buttons)
	if len(buttons.Providers) != 0 {
		t.Fatalf("a disabled provider is offered: %+v", buttons)
	}
	admin.expect(http.StatusNoContent, "DELETE", "/api/v1/settings/sso/providers/"+p.ID, nil, nil)
	admin.expect(http.StatusNotFound, "DELETE", "/api/v1/settings/sso/providers/"+p.ID, nil, nil)

	var entries struct {
		Items []struct {
			Action string `json:"action"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?limit=200", nil, &entries)
	seen := map[string]bool{}
	for _, e := range entries.Items {
		seen[e.Action] = true
	}
	for _, a := range []string{"sso.provider_create", "sso.provider_update", "sso.provider_delete", "auth.sso_link", "auth.sso_unlink"} {
		if !seen[a] {
			t.Errorf("no %s in the audit log", a)
		}
	}
}

// In the plain-HTTP development mode the flow cookie drops the __Host-
// prefix and Secure, like the session cookie.
func TestHTTPSingleSignOnInsecureCookie(t *testing.T) {
	dex := ssotest.Get(t)
	h := newHarnessWith(t, false, func(c *config.Config) { c.DevInsecureCookie = true })
	p, err := h.deps.SSO.CreateProvider(context.Background(), audit.Actor{Type: audit.ActorSystem, Label: "test"}, sso.ProviderInput{
		Name: "Dex", Issuer: dex.Issuer, ClientID: dex.ClientID, ClientSecret: dex.ClientSecret, AllowedDomains: []string{"sso.test"}, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := h.client()
	c.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	r := c.do("GET", "/api/v1/auth/sso/"+p.ID.String()+"/start", nil)
	flow := cookie(r, "easyrmm_sso")
	if r.status != http.StatusSeeOther || flow == nil || flow.Secure || !flow.HttpOnly || cookie(r, "__Host-easyrmm_sso") != nil {
		t.Fatalf("start: %d, cookie %+v", r.status, flow)
	}
}
