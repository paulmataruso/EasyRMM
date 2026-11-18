//go:build integration

package app_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
)

// relying party is EasyPatch's side of the sign-in, played by a standard
// OpenID Connect client (go-oidc and x/oauth2) talking to the real server.
type relyingParty struct {
	ctx      context.Context
	provider *oidc.Provider
	config   oauth2.Config
}

// routedClient reaches the harness at any host name, as EasyPatch's server
// would reach EasyRMM at its public address.
func (h *harness) routedClient() *http.Client {
	tr := h.srv.Client().Transport.(*http.Transport).Clone()
	addr := h.srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	tr.TLSClientConfig = &tls.Config{RootCAs: tr.TLSClientConfig.RootCAs, ServerName: "example.com", MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: tr}
}

func newRelyingParty(t *testing.T, h *harness, clientID, secret, redirect string) *relyingParty {
	t.Helper()
	ctx := oidc.ClientContext(context.Background(), h.routedClient())
	p, err := oidc.NewProvider(ctx, publicOrigin)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	return &relyingParty{ctx: ctx, provider: p, config: oauth2.Config{
		ClientID: clientID, ClientSecret: secret, Endpoint: p.Endpoint(), RedirectURL: redirect, Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}}
}

// start is the address EasyPatch sends the browser to, as a path on EasyRMM.
func (rp *relyingParty) start(t *testing.T, state, nonce, verifier string) string {
	t.Helper()
	u, err := url.Parse(rp.config.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)))
	if err != nil || u.Scheme+"://"+u.Host != publicOrigin {
		t.Fatalf("authorization URL %s: %v", u, err)
	}
	return u.RequestURI()
}

type idClaims struct {
	Subject       string           `json:"sub"`
	Nonce         string           `json:"nonce"`
	Name          string           `json:"name"`
	Email         string           `json:"email"`
	EmailVerified *bool            `json:"email_verified"`
	AMR           []string         `json:"amr"`
	AuthTime      int64            `json:"auth_time"`
	EasyPatch     easypatch.Access `json:"easypatch"`
}

func (rp *relyingParty) redeem(t *testing.T, code, verifier, nonce string) (idClaims, error) {
	t.Helper()
	tok, err := rp.config.Exchange(rp.ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return idClaims{}, err
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := rp.provider.Verifier(&oidc.Config{ClientID: rp.config.ClientID}).Verify(rp.ctx, raw)
	if err != nil {
		t.Fatalf("verifying the ID token: %v", err)
	}
	var c idClaims
	if err := idt.Claims(&c); err != nil {
		t.Fatal(err)
	}
	if c.Nonce != nonce {
		t.Fatalf("nonce %q, want %q", c.Nonce, nonce)
	}
	return c, nil
}

// callback reads where the provider sent the browser back to EasyPatch.
func callback(t *testing.T, r response, redirect string) url.Values {
	t.Helper()
	loc := r.header.Get("Location")
	if r.status != http.StatusFound || !strings.HasPrefix(loc, redirect+"?") {
		t.Fatalf("expected a redirect to EasyPatch, got %d %q: %s", r.status, loc, r.body)
	}
	u, _ := url.Parse(loc)
	q := u.Query()
	if q.Get("iss") != publicOrigin {
		t.Fatalf("iss = %q", q.Get("iss"))
	}
	return q
}

func noRedirects(c *client) *client {
	c.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

func TestHTTPOpenIDProvider(t *testing.T) {
	h := newHarness(t, false)
	admin, adminSecret := setUp(t, h)
	noRedirects(admin)
	ctx := context.Background()
	acme := orgID(t, admin, "Acme")

	// Nothing answers until EasyPatch is set up as the client.
	anon := noRedirects(h.client())
	for _, p := range []string{"/.well-known/openid-configuration", "/oauth2/jwks", "/oauth2/authorize?client_id=x"} {
		wantStatus(t, anon.do("GET", p, nil), http.StatusNotFound, "not_found")
	}
	type settingsView struct {
		Available   bool   `json:"available"`
		Reason      string `json:"reason"`
		Issuer      string `json:"issuer"`
		RedirectURI string `json:"redirectUri"`
		Client      *struct {
			ClientID    string `json:"clientId"`
			RedirectURI string `json:"redirectUri"`
			CreatedBy   string `json:"createdBy"`
			RotatedAt   string `json:"rotatedAt"`
		} `json:"client"`
	}
	var st settingsView
	admin.expect(http.StatusOK, "GET", "/api/v1/settings/easypatch/sign-in", nil, &st)
	if st.Available || st.Reason == "" || st.Client != nil || st.Issuer != publicOrigin {
		t.Fatalf("before EasyPatch: %+v", st)
	}
	wantStatus(t, admin.do("POST", "/api/v1/settings/easypatch/sign-in", nil), http.StatusConflict, "easypatch_unavailable")

	// An EasyPatch without the capability cannot use it.
	ep := eptest.New(t)
	epOrg := ep.Org("Acme Patch")
	admin.expect(http.StatusOK, "PUT", "/api/v1/settings/easypatch", map[string]string{"url": ep.URL(), "token": ep.Token, "caCert": ep.CAPEM}, nil)
	admin.expect(http.StatusOK, "GET", "/api/v1/settings/easypatch/sign-in", nil, &st)
	if st.Available || !strings.Contains(st.Reason, "update it") {
		t.Fatalf("without the capability: %+v", st)
	}
	ep.Set(func() { ep.Capabilities = []string{easypatch.CapabilityEasyRMMSignIn} })
	admin.expect(http.StatusOK, "POST", "/api/v1/settings/easypatch/check", nil, nil)
	admin.expect(http.StatusOK, "GET", "/api/v1/settings/easypatch/sign-in", nil, &st)
	const redirect = "https://patch.example.com/api/v1/auth/sso/callback"
	if !st.Available || st.RedirectURI != redirect {
		t.Fatalf("with the capability: %+v", st)
	}

	// The client, its secret shown once.
	var created struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		Issuer       string `json:"issuer"`
		RedirectURI  string `json:"redirectUri"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/settings/easypatch/sign-in", nil, &created)
	if !strings.HasPrefix(created.ClientID, "easypatch-") || len(created.ClientSecret) < 40 || created.Issuer != publicOrigin || created.RedirectURI != redirect {
		t.Fatalf("created: %+v", created)
	}
	r := admin.expect(http.StatusOK, "GET", "/api/v1/settings/easypatch/sign-in", nil, &st)
	if st.Client == nil || st.Client.ClientID != created.ClientID || st.Client.CreatedBy != "admin@msp.example" || strings.Contains(string(r.body), created.ClientSecret) {
		t.Fatalf("after creating: %s", r.body)
	}
	wantStatus(t, admin.do("POST", "/api/v1/settings/easypatch/sign-in", nil), http.StatusConflict, "client_exists")

	// Discovery, as a standard client reads it.
	var disc map[string]any
	anon.expect(http.StatusOK, "GET", "/.well-known/openid-configuration", nil, &disc)
	if disc["issuer"] != publicOrigin || disc["token_endpoint"] != publicOrigin+"/oauth2/token" ||
		!slices.Contains(toStrings(disc["token_endpoint_auth_methods_supported"]), "client_secret_post") ||
		!slices.Equal(toStrings(disc["id_token_signing_alg_values_supported"]), []string{"ES256"}) {
		t.Fatalf("discovery: %v", disc)
	}
	rp := newRelyingParty(t, h, created.ClientID, created.ClientSecret, redirect)

	// --- The sign-in -------------------------------------------------------
	verifier := oauth2.GenerateVerifier()
	start := rp.start(t, "state-1", "nonce-1", verifier)

	// EasyPatch's redirect is cross-site: the SameSite=Strict cookie stays
	// behind, so authorize sees no session and sends the browser through
	// EasyRMM's sign-in page.
	r = anon.do("GET", start, nil)
	loc := r.header.Get("Location")
	if r.status != http.StatusFound || !strings.HasPrefix(loc, "/login?returnTo=") {
		t.Fatalf("no session: %d %q", r.status, loc)
	}
	back, _ := url.Parse(loc)
	returnTo := back.Query().Get("returnTo")
	if !strings.HasPrefix(returnTo, "/oauth2/authorize?") || !strings.Contains(returnTo, "bounced=1") {
		t.Fatalf("returnTo = %q", returnTo)
	}
	// Signed out, the second arrival goes back to EasyPatch.
	q := callback(t, anon.do("GET", returnTo, nil), redirect)
	if q.Get("error") != "login_required" || q.Get("state") != "state-1" || q.Has("code") {
		t.Fatalf("second arrival signed out: %v", q)
	}

	// The console's full page load carries the cookie: a code.
	q = callback(t, admin.do("GET", returnTo, nil), redirect)
	if q.Get("state") != "state-1" || q.Get("code") == "" || q.Has("error") {
		t.Fatalf("signed in: %v", q)
	}
	code := q.Get("code")
	claims, err := rp.redeem(t, code, verifier, "nonce-1")
	if err != nil {
		t.Fatal(err)
	}
	var me sessionView
	admin.expect(http.StatusOK, "GET", "/api/v1/auth/session", nil, &me)
	if claims.Subject != me.User.ID || claims.Email != "admin@msp.example" || claims.Name != "Ada Admin" ||
		claims.EmailVerified == nil || *claims.EmailVerified || !slices.Equal(claims.AMR, []string{"pwd", "otp", "mfa"}) || claims.AuthTime == 0 ||
		claims.EasyPatch.Role != easypatch.RoleSuperAdmin || len(claims.EasyPatch.Organizations) != 0 {
		t.Fatalf("claims: %+v", claims)
	}

	// A code works once.
	if _, err := rp.redeem(t, code, verifier, "nonce-1"); !isOAuthError(err, "invalid_grant") {
		t.Fatalf("second redemption: %v", err)
	}
	// It needs its own verifier.
	q = callback(t, admin.do("GET", rp.start(t, "s2", "n2", verifier), nil), redirect)
	if _, err := rp.redeem(t, q.Get("code"), oauth2.GenerateVerifier(), "n2"); !isOAuthError(err, "invalid_grant") {
		t.Fatalf("wrong verifier: %v", err)
	}

	// client_secret_post, and the refusals of the token endpoint.
	q = callback(t, admin.do("GET", rp.start(t, "s3", "n3", verifier), nil), redirect)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "redirect_uri": {redirect},
		"code_verifier": {verifier}, "client_id": {created.ClientID}, "client_secret": {"erms_wrong"}}
	tr := tokenCall(t, h, form, "")
	if tr.status != http.StatusUnauthorized || tr.json["error"] != "invalid_client" {
		t.Fatalf("wrong secret: %d %v", tr.status, tr.json)
	}
	form.Set("client_secret", created.ClientSecret)
	form.Set("redirect_uri", "https://patch.example.com/elsewhere")
	if tr = tokenCall(t, h, form, ""); tr.status != http.StatusBadRequest || tr.json["error"] != "invalid_grant" {
		t.Fatalf("other redirect URI: %d %v", tr.status, tr.json)
	}
	q = callback(t, admin.do("GET", rp.start(t, "s4", "n4", verifier), nil), redirect)
	form.Set("code", q.Get("code"))
	form.Set("redirect_uri", redirect)
	tr = tokenCall(t, h, form, "")
	if tr.status != http.StatusOK || tr.json["id_token"] == nil || tr.json["token_type"] != "Bearer" || tr.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("client_secret_post: %d %v", tr.status, tr.json)
	}
	form.Set("grant_type", "refresh_token")
	if tr = tokenCall(t, h, form, ""); tr.json["error"] != "unsupported_grant_type" {
		t.Fatalf("refresh: %v", tr.json)
	}
	if tr = tokenCall(t, h, form, "application/json"); tr.json["error"] != "invalid_request" {
		t.Fatalf("json body: %v", tr.json)
	}

	// A code lives 60 seconds.
	q = callback(t, admin.do("GET", rp.start(t, "s4b", "n4b", verifier), nil), redirect)
	h.deps.IdP.SetClock(func() time.Time { return time.Now().Add(61 * time.Second) })
	_, err = rp.redeem(t, q.Get("code"), verifier, "n4b")
	h.deps.IdP.SetClock(time.Now)
	if !isOAuthError(err, "invalid_grant") {
		t.Fatalf("expired code: %v", err)
	}
	// Signing out of EasyRMM voids a code not yet redeemed.
	other := noRedirects(h.client())
	other.signIn("admin@msp.example", adminPassword, adminSecret)
	q = callback(t, other.do("GET", rp.start(t, "s4c", "n4c", verifier), nil), redirect)
	other.expect(http.StatusNoContent, "POST", "/api/v1/auth/logout", nil, nil)
	if _, err := rp.redeem(t, q.Get("code"), verifier, "n4c"); !isOAuthError(err, "invalid_grant") {
		t.Fatalf("signed out before redemption: %v", err)
	}

	// --- Refusals at authorize -------------------------------------------
	// Another redirect URI is never followed.
	bad := strings.Replace(rp.start(t, "s", "n", verifier), url.QueryEscape(redirect), url.QueryEscape("https://evil.example/cb"), 1)
	r = admin.do("GET", bad, nil)
	if r.status != http.StatusBadRequest || r.header.Get("Location") != "" || !strings.Contains(string(r.body), "not from the EasyPatch") {
		t.Fatalf("foreign redirect: %d %q", r.status, r.header.Get("Location"))
	}
	// PKCE is required.
	plain := strings.Replace(rp.start(t, "s5", "n5", verifier), "code_challenge_method=S256", "code_challenge_method=plain", 1)
	if q = callback(t, admin.do("GET", plain, nil), redirect); q.Get("error") != "invalid_request" || q.Get("state") != "s5" {
		t.Fatalf("plain PKCE: %v", q)
	}

	// Tess is a technician in Acme, which is linked: ReadOnly there.
	invite(t, h, admin, "tess@acme.example", []map[string]any{{"role": "technician", "organizationId": acme}})
	tess := noRedirects(h.client())
	tess.enroll("tess@acme.example", "a long and unusual passphrase")
	q = callback(t, tess.do("GET", rp.start(t, "s6", "n6", verifier), nil), redirect)
	if q.Get("error") != "access_denied" {
		t.Fatalf("no linked organization yet: %v", q)
	}
	admin.expect(http.StatusNoContent, "PUT", "/api/v1/settings/easypatch/organizations/"+acme, map[string]string{"easyPatchId": epOrg.String()}, nil)
	q = callback(t, tess.do("GET", rp.start(t, "s7", "n7", verifier), nil), redirect)
	claims, err = rp.redeem(t, q.Get("code"), verifier, "n7")
	if err != nil || claims.EasyPatch.Role != easypatch.RoleReadOnly || len(claims.EasyPatch.Organizations) != 1 || claims.EasyPatch.Organizations[0] != epOrg {
		t.Fatalf("technician: %+v %v", claims.EasyPatch, err)
	}
	// Access is decided again when the code is redeemed.
	q = callback(t, tess.do("GET", rp.start(t, "s8", "n8", verifier), nil), redirect)
	admin.expect(http.StatusNoContent, "DELETE", "/api/v1/settings/easypatch/organizations/"+acme, nil, nil)
	if _, err := rp.redeem(t, q.Get("code"), verifier, "n8"); !isOAuthError(err, "invalid_grant") {
		t.Fatalf("access removed before redemption: %v", err)
	}
	admin.expect(http.StatusNoContent, "PUT", "/api/v1/settings/easypatch/organizations/"+acme, map[string]string{"easyPatchId": epOrg.String()}, nil)

	// A session from before sign-in methods were recorded has none: it must
	// sign in again.
	if err := h.db.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE sessions SET amr = '{}' WHERE user_id = (SELECT id FROM users WHERE email = 'tess@acme.example')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if q = callback(t, tess.do("GET", rp.start(t, "s9", "n9", verifier), nil), redirect); q.Get("error") != "access_denied" ||
		!strings.Contains(q.Get("error_description"), "second factor") {
		t.Fatalf("no recorded second factor: %v", q)
	}

	// Only super administrators manage the client.
	wantStatus(t, tess.do("GET", "/api/v1/settings/easypatch/sign-in", nil), http.StatusForbidden, "forbidden")
	wantStatus(t, tess.do("POST", "/api/v1/settings/easypatch/sign-in/rotate", nil), http.StatusForbidden, "forbidden")

	// Rotating the secret stops the old one at once.
	var rotated struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/settings/easypatch/sign-in/rotate", nil, &rotated)
	if rotated.ClientID != created.ClientID || rotated.ClientSecret == created.ClientSecret {
		t.Fatalf("rotated: %+v", rotated)
	}
	q = callback(t, admin.do("GET", rp.start(t, "s10", "n10", verifier), nil), redirect)
	if _, err := rp.redeem(t, q.Get("code"), verifier, "n10"); !isOAuthError(err, "invalid_client") {
		t.Fatalf("old secret: %v", err)
	}
	rp.config.ClientSecret = rotated.ClientSecret
	q = callback(t, admin.do("GET", rp.start(t, "s11", "n11", verifier), nil), redirect)
	if _, err := rp.redeem(t, q.Get("code"), verifier, "n11"); err != nil {
		t.Fatalf("new secret: %v", err)
	}

	// Audit.
	events := auditActions(t, admin, "idp.")
	for _, want := range []string{"idp.client_create/success", "idp.client_rotate/success", "idp.authorize/success", "idp.authorize/denied"} {
		if !slices.Contains(events, want) {
			t.Errorf("audit lacks %s: %v", want, events)
		}
	}

	// Removing the client turns the provider off.
	admin.expect(http.StatusNoContent, "DELETE", "/api/v1/settings/easypatch/sign-in", nil, nil)
	wantStatus(t, anon.do("GET", "/.well-known/openid-configuration", nil), http.StatusNotFound, "not_found")
}

// auditActions lists the audit log's "action/outcome" pairs that start with prefix.
func auditActions(t *testing.T, c *client, prefix string) []string {
	t.Helper()
	var log struct {
		Items []struct {
			Action  string `json:"action"`
			Outcome string `json:"outcome"`
		} `json:"items"`
	}
	c.expect(http.StatusOK, "GET", "/api/v1/audit?limit=500", nil, &log)
	var out []string
	for _, e := range log.Items {
		if strings.HasPrefix(e.Action, prefix) {
			out = append(out, e.Action+"/"+e.Outcome)
		}
	}
	return out
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func isOAuthError(err error, code string) bool {
	var re *oauth2.RetrieveError
	return errors.As(err, &re) && re.ErrorCode == code
}

type tokenResult struct {
	status int
	json   map[string]any
	header http.Header
}

// tokenCall posts to the token endpoint as EasyPatch's server would: no
// browser, no Origin, no CSRF token.
func tokenCall(t *testing.T, h *harness, form url.Values, contentType string) tokenResult {
	t.Helper()
	req, _ := http.NewRequest("POST", publicOrigin+"/oauth2/token", strings.NewReader(form.Encode()))
	if contentType == "" {
		contentType = "application/x-www-form-urlencoded"
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := h.routedClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := tokenResult{status: resp.StatusCode, header: resp.Header}
	_ = json.NewDecoder(resp.Body).Decode(&out.json)
	return out
}
