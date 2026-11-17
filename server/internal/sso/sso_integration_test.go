//go:build integration

package sso_test

import (
	"context"
	"crypto/rand"
	"errors"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/sso"
	"github.com/paulmataruso/easyrmm/server/internal/sso/ssotest"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

type env struct {
	t     *testing.T
	db    *database.DB
	svc   *sso.Service
	auth  *auth.Service
	dex   ssotest.Settings
	now   *time.Time // shared by the copies subtests use
	admin audit.Actor
	meta  auth.RequestMeta
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dex := ssotest.Get(t)
	inst := testdb.New(t)
	key := make([]byte, secrets.KeySize)
	_, _ = rand.Read(key)
	sealer, err := secrets.NewSealer(secrets.Key{ID: "k1", Raw: key})
	if err != nil {
		t.Fatal(err)
	}
	log := audit.New(inst.DB, nil)
	cfg := auth.DefaultConfig()
	cfg.PublicURL = dex.PublicURL
	a := auth.NewService(inst.DB, log, auth.NewHasher(auth.Argon2Params{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32}, 4),
		sealer, nil, cfg)
	pub, _ := url.Parse(dex.PublicURL)
	now := time.Now()
	e := &env{t: t, db: inst.DB, auth: a, dex: dex, now: &now, svc: sso.New(inst.DB, log, sealer, a, pub),
		admin: audit.Actor{Type: audit.ActorUser, ID: uuid.New(), Label: "admin@example.com"},
		meta:  auth.RequestMeta{IP: netip.MustParseAddr("192.0.2.10"), UserAgent: "sso-test"}}
	e.svc.SetClock(func() time.Time { return *e.now })
	return e
}

// run is t.Run with helpers that fail the subtest, not its parent.
func (e *env) run(name string, f func(e *env)) {
	e.t.Run(name, func(t *testing.T) {
		c := *e
		c.t = t
		f(&c)
	})
}

func (e *env) exec(sql string, args ...any) {
	e.t.Helper()
	if err := e.db.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), sql, args...)
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) count(sql string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.ReadTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), sql, args...).Scan(&n)
	}); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *env) user(email string) uuid.UUID {
	e.t.Helper()
	var id uuid.UUID
	if err := e.db.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `INSERT INTO users (email, display_name) VALUES ($1, 'Test User') RETURNING id`, email).Scan(&id)
	}); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *env) provider(mutate func(*sso.ProviderInput)) sso.Provider {
	e.t.Helper()
	in := sso.ProviderInput{Name: "Dex", Issuer: e.dex.Issuer, ClientID: e.dex.ClientID, ClientSecret: e.dex.ClientSecret,
		AllowedDomains: []string{"sso.test"}, Enabled: true}
	if mutate != nil {
		mutate(&in)
	}
	p, err := e.svc.CreateProvider(context.Background(), e.admin, in)
	if err != nil {
		e.t.Fatalf("creating the provider: %v", err)
	}
	return p
}

// signIn goes the whole way: start, Dex's form, callback.
func (e *env) signIn(providerID uuid.UUID, email, returnTo string) (*sso.Result, error) {
	e.t.Helper()
	authURL, sealed, err := e.svc.Start(context.Background(), providerID, returnTo)
	if err != nil {
		e.t.Fatalf("start: %v", err)
	}
	back := e.dex.SignIn(e.t, authURL, email)
	q := back.Query()
	return e.svc.Callback(context.Background(), sso.CallbackInput{Sealed: sealed, State: q.Get("state"), Code: q.Get("code"),
		Error: q.Get("error"), ErrorDescription: q.Get("error_description")}, e.meta)
}

func failureCode(err error) string {
	var f *sso.Failure
	if errors.As(err, &f) {
		return f.Code
	}
	return ""
}

func TestSingleSignOnThroughDex(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	alex := e.user(ssotest.Alex)
	p := e.provider(nil)

	if p.TrustMFA || p.TrustEmail || !p.Enabled || len(p.AllowedDomains) != 1 {
		t.Fatalf("provider = %+v", p)
	}
	if got := e.svc.RedirectURI(); got != ssotest.PublicURL+"/api/v1/auth/sso/callback" {
		t.Fatalf("redirect URI = %s", got)
	}

	// The start step asks for the code flow with PKCE (S256), state and nonce.
	authURL, _, err := e.svc.Start(ctx, p.ID, "/devices?x=1")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authURL)
	q := u.Query()
	if !strings.HasPrefix(authURL, e.dex.Issuer+"/auth?") || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" ||
		q.Get("code_challenge") == "" || q.Get("state") == "" || q.Get("nonce") == "" || q.Get("client_id") != e.dex.ClientID ||
		q.Get("redirect_uri") != e.svc.RedirectURI() || q.Get("scope") != "openid email profile" {
		t.Fatalf("authorization URL = %s", authURL)
	}

	e.run("first sign-in links by verified email, then asks for the second factor set-up", func(e *env) {
		t := e.t
		res, err := e.signIn(p.ID, ssotest.Alex, "/devices?x=1")
		if err != nil {
			t.Fatal(err)
		}
		if res.Session.UserID != alex || res.Session.State != auth.StateMFAEnrollment || res.ReturnTo != "/devices?x=1" {
			t.Fatalf("result = %+v, session = %+v", res, res.Session)
		}
		if n := e.count(`SELECT count(*) FROM user_identities WHERE user_id = $1 AND provider_id = $2 AND email = $3`, alex, p.ID, ssotest.Alex); n != 1 {
			t.Fatalf("identities = %d", n)
		}
		if n := e.count(`SELECT count(*) FROM audit_log WHERE action = 'auth.sso_link' AND target_id = $1`, alex.String()); n != 1 {
			t.Fatalf("link audits = %d", n)
		}
		if n := e.count(`SELECT count(*) FROM audit_log WHERE action = 'auth.login' AND outcome = 'success' AND details->>'method' = 'oidc'
			AND details->>'linked' = 'true' AND details->>'state' = 'mfa_enrollment'`); n != 1 {
			t.Fatalf("login audits = %d", n)
		}
	})

	e.run("the link holds when the email changes", func(e *env) {
		t := e.t
		// Later sign-ins match on the subject alone: rename the EasyRMM
		// account and the identity still reaches it.
		e.exec(`UPDATE users SET email = 'alex.renamed@sso.test' WHERE id = $1`, alex)
		res, err := e.signIn(p.ID, ssotest.Alex, "")
		if err != nil {
			t.Fatal(err)
		}
		if res.Session.UserID != alex || res.ReturnTo != "/" {
			t.Fatalf("result = %+v", res)
		}
		e.exec(`UPDATE users SET email = $2 WHERE id = $1`, alex, ssotest.Alex)
	})

	e.run("a provider trusted for MFA completes the sign-in", func(e *env) {
		t := e.t
		if _, err := e.svc.UpdateProvider(ctx, e.admin, p.ID, sso.ProviderInput{Name: "Dex", Issuer: e.dex.Issuer, ClientID: e.dex.ClientID,
			AllowedDomains: []string{"sso.test"}, TrustMFA: true, Enabled: true}); err != nil {
			t.Fatal(err)
		}
		res, err := e.signIn(p.ID, ssotest.Alex, "")
		if err != nil {
			t.Fatal(err)
		}
		if res.Session.State != auth.StateActive {
			t.Fatalf("state = %s", res.Session.State)
		}
		// The administrator vouched for the provider's second factor.
		if !slices.Equal(res.Session.AMR, []string{"fed", "mfa"}) || res.Session.AuthenticatedAt == nil {
			t.Fatalf("amr %v at %v", res.Session.AMR, res.Session.AuthenticatedAt)
		}
		if n := e.count(`SELECT count(*) FROM users WHERE id = $1 AND last_login_at IS NOT NULL`, alex); n != 1 {
			t.Fatal("last_login_at not set")
		}
	})

	e.run("someone with a second factor is asked for it", func(e *env) {
		t := e.t
		sam := e.user(ssotest.Sam)
		e.exec(`UPDATE users SET totp_secret_sealed = 'sealed', totp_enabled_at = now() WHERE id = $1`, sam)
		if _, err := e.svc.UpdateProvider(ctx, e.admin, p.ID, sso.ProviderInput{Name: "Dex", Issuer: e.dex.Issuer, ClientID: e.dex.ClientID,
			AllowedDomains: []string{"sso.test"}, Enabled: true}); err != nil {
			t.Fatal(err)
		}
		res, err := e.signIn(p.ID, ssotest.Sam, "")
		if err != nil {
			t.Fatal(err)
		}
		if res.Session.UserID != sam || res.Session.State != auth.StateMFARequired || !slices.Equal(res.Session.AMR, []string{"fed"}) {
			t.Fatalf("session = %+v", res.Session)
		}
	})

	e.run("refusals", func(e *env) {
		t := e.t
		dana := e.user(ssotest.Dana)
		e.exec(`UPDATE users SET status = 'disabled' WHERE id = $1`, dana)
		e.user("eve@elsewhere.test")
		for _, c := range []struct{ email, code string }{
			{ssotest.Nobody, sso.FailNoAccount},
			{ssotest.Elsewhere, sso.FailDomain},
			{ssotest.Dana, sso.FailNoAccount}, // a disabled account is never linked
		} {
			_, err := e.signIn(p.ID, c.email, "")
			if got := failureCode(err); got != c.code {
				t.Errorf("%s: failure = %q (%v), want %q", c.email, got, err, c.code)
			}
			if n := e.count(`SELECT count(*) FROM audit_log WHERE action = 'auth.login' AND outcome = 'failure' AND details->>'method' = 'oidc'
				AND details->>'reason' = $1 AND details->>'email' = $2`, c.code, c.email); n != 1 {
				t.Errorf("%s: failure audits = %d", c.email, n)
			}
		}
		if n := e.count(`SELECT count(*) FROM user_identities WHERE user_id = $1`, dana); n != 0 {
			t.Fatal("a disabled account was linked")
		}

		// A linked account that is disabled later is refused by the
		// sign-in itself.
		e.exec(`UPDATE users SET status = 'disabled' WHERE id = $1`, alex)
		if _, err := e.signIn(p.ID, ssotest.Alex, ""); failureCode(err) != sso.FailAccountState {
			t.Fatalf("disabled linked account: %v", err)
		}
		e.exec(`UPDATE users SET status = 'active' WHERE id = $1`, alex)
	})

	e.run("the flow is bound to the browser and used once", func(e *env) {
		t := e.t
		authURL, sealed, err := e.svc.Start(ctx, p.ID, "")
		if err != nil {
			t.Fatal(err)
		}
		back := e.dex.SignIn(t, authURL, ssotest.Alex)
		q := back.Query()
		in := sso.CallbackInput{Sealed: sealed, State: q.Get("state"), Code: q.Get("code")}

		// Login CSRF: someone else's code arrives in a browser with no
		// sign-in of its own, or with another one.
		_, otherSealed, _ := e.svc.Start(ctx, p.ID, "")
		for name, bad := range map[string]sso.CallbackInput{
			"no cookie":      {State: in.State, Code: in.Code},
			"other cookie":   {Sealed: otherSealed, State: in.State, Code: in.Code},
			"other state":    {Sealed: sealed, State: "x" + in.State, Code: in.Code},
			"forged cookie":  {Sealed: sealed[:len(sealed)-4] + "AAAA", State: in.State, Code: in.Code},
			"provider error": {Sealed: sealed, State: in.State, Error: "access_denied", ErrorDescription: "the user said no"},
		} {
			_, err := e.svc.Callback(ctx, bad, e.meta)
			want := sso.FailExpired
			if name == "provider error" {
				want = sso.FailProvider
			}
			if got := failureCode(err); got != want {
				t.Errorf("%s: failure = %q (%v), want %q", name, got, err, want)
			}
		}

		if _, err := e.svc.Callback(ctx, in, e.meta); err != nil {
			t.Fatalf("the real callback: %v", err)
		}
		// Dex refuses a code used twice.
		if _, err := e.svc.Callback(ctx, in, e.meta); failureCode(err) != sso.FailProvider {
			t.Fatalf("replayed code: %v", err)
		}
	})

	e.run("a slow sign-in expires", func(e *env) {
		t := e.t
		authURL, sealed, err := e.svc.Start(ctx, p.ID, "")
		if err != nil {
			t.Fatal(err)
		}
		back := e.dex.SignIn(t, authURL, ssotest.Alex)
		*e.now = time.Now().Add(sso.FlowTTL + time.Second)
		defer func() { *e.now = time.Now() }()
		_, err = e.svc.Callback(ctx, sso.CallbackInput{Sealed: sealed, State: back.Query().Get("state"), Code: back.Query().Get("code")}, e.meta)
		if failureCode(err) != sso.FailExpired {
			t.Fatalf("err = %v", err)
		}
	})

	e.run("a wrong client secret fails the exchange", func(e *env) {
		t := e.t
		bad := e.provider(func(in *sso.ProviderInput) { in.Name, in.ClientSecret = "Dex wrong secret", "not-the-secret" })
		if _, err := e.signIn(bad.ID, ssotest.Alex, ""); failureCode(err) != sso.FailProvider {
			t.Fatalf("err = %v", err)
		}
		if n := e.count(`SELECT count(*) FROM audit_log WHERE action = 'auth.login' AND outcome = 'failure'
			AND details->>'provider' = 'Dex wrong secret' AND details->>'error' LIKE 'code exchange:%'`); n != 1 {
			t.Fatalf("audits = %d", n)
		}
	})

	e.run("a disabled provider", func(e *env) {
		t := e.t
		authURL, sealed, err := e.svc.Start(ctx, p.ID, "")
		if err != nil {
			t.Fatal(err)
		}
		back := e.dex.SignIn(t, authURL, ssotest.Alex)
		if _, err := e.svc.UpdateProvider(ctx, e.admin, p.ID, sso.ProviderInput{Name: "Dex", Issuer: e.dex.Issuer, ClientID: e.dex.ClientID,
			AllowedDomains: []string{"sso.test"}, Enabled: false}); err != nil {
			t.Fatal(err)
		}
		// One already at the provider is refused on return; new ones
		// cannot start, and the sign-in page no longer offers it.
		_, err = e.svc.Callback(ctx, sso.CallbackInput{Sealed: sealed, State: back.Query().Get("state"), Code: back.Query().Get("code")}, e.meta)
		if failureCode(err) != sso.FailUnavailable {
			t.Fatalf("callback: %v", err)
		}
		if _, _, err := e.svc.Start(ctx, p.ID, ""); failureCode(err) != sso.FailUnavailable {
			t.Fatalf("start: %v", err)
		}
		buttons, err := e.svc.Buttons(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range buttons {
			if b.ID == p.ID {
				t.Fatal("a disabled provider is offered")
			}
		}
	})

	e.run("identities: listed, unlinked, deleted with the provider", func(e *env) {
		t := e.t
		list, err := e.svc.Identities(ctx, alex)
		if err != nil || len(list) != 1 || list[0].ProviderID != p.ID || list[0].Email != ssotest.Alex || list[0].LastUsedAt == nil {
			t.Fatalf("identities = %+v, %v", list, err)
		}
		if err := e.svc.Unlink(ctx, e.admin, alex, p.ID); err != nil {
			t.Fatal(err)
		}
		if err := e.svc.Unlink(ctx, e.admin, alex, p.ID); !errors.Is(err, apperr.ErrNotFound) {
			t.Fatalf("second unlink: %v", err)
		}
		e.exec(`INSERT INTO user_identities (provider_id, subject, user_id, email) VALUES ($1, 'sub-1', $2, 'a@sso.test')`, p.ID, alex)
		if err := e.svc.DeleteProvider(ctx, e.admin, p.ID); err != nil {
			t.Fatal(err)
		}
		if n := e.count(`SELECT count(*) FROM user_identities WHERE provider_id = $1`, p.ID); n != 0 {
			t.Fatalf("identities left = %d", n)
		}
		// Alex's, and Sam's from earlier.
		if n := e.count(`SELECT count(*) FROM audit_log WHERE action = 'sso.provider_delete' AND details->>'identities' = '2'`); n != 1 {
			t.Fatalf("delete audits = %d", n)
		}
		if err := e.svc.DeleteProvider(ctx, e.admin, p.ID); !errors.Is(err, apperr.ErrNotFound) {
			t.Fatalf("second delete: %v", err)
		}
	})
}

func TestLinkingRules(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	p := e.provider(nil)
	alex := e.user(ssotest.Alex)

	// Without email_verified, an address is not trusted to link, unless the
	// administrator says the provider's addresses are the organization's.
	for _, v := range []any{nil, false, "false", "yes"} {
		if _, code, err := e.svc.ResolveClaims(ctx, p.ID, "s-unverified", ssotest.Alex, v); err != nil || code != sso.FailUnverified {
			t.Fatalf("email_verified %v: code %q, %v", v, code, err)
		}
	}
	if id, code, err := e.svc.ResolveClaims(ctx, p.ID, "s-string", ssotest.Alex, "true"); err != nil || code != "" || id != alex {
		t.Fatalf(`email_verified "true": %s %q %v`, id, code, err)
	}

	// The account now has an identity at this provider: a second subject
	// with the same address is refused, not linked as well.
	if _, code, _ := e.svc.ResolveClaims(ctx, p.ID, "s-other", ssotest.Alex, true); code != sso.FailLinkedOther {
		t.Fatalf("second subject: %q", code)
	}

	trusted := e.provider(func(in *sso.ProviderInput) { in.Name, in.TrustEmail = "Entra", true })
	if id, code, err := e.svc.ResolveClaims(ctx, trusted.ID, "s-entra", ssotest.Alex, nil); err != nil || code != "" || id != alex {
		t.Fatalf("trusted email: %s %q %v", id, code, err)
	}
	// Upper case from the provider still matches; no email at all does not.
	e.user(ssotest.Sam)
	if _, code, _ := e.svc.ResolveClaims(ctx, trusted.ID, "s-sam", "SAM@SSO.TEST", nil); code != "" {
		t.Fatalf("upper case: %q", code)
	}
	if _, code, _ := e.svc.ResolveClaims(ctx, trusted.ID, "s-none", "", nil); code != sso.FailNoAccount {
		t.Fatalf("no email: %q", code)
	}
}

func TestProviderSettings(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	fields := func(err error) map[string]string {
		ae, ok := apperr.As(err)
		if !ok {
			t.Fatalf("not a validation error: %v", err)
		}
		return ae.Fields
	}

	f := fields(func() error {
		_, err := e.svc.CreateProvider(ctx, e.admin, sso.ProviderInput{Issuer: "http://login.example.com", AllowedDomains: []string{"not a domain", " "}})
		return err
	}())
	for _, k := range []string{"name", "issuer", "clientId", "clientSecret", "allowedDomains"} {
		if f[k] == "" {
			t.Errorf("no problem reported for %s: %v", k, f)
		}
	}
	if !strings.Contains(f["issuer"], "HTTPS") {
		t.Errorf("issuer: %q", f["issuer"])
	}

	// An issuer that is not an OpenID provider is caught when saving.
	_, err := e.svc.CreateProvider(ctx, e.admin, sso.ProviderInput{Name: "Wrong", Issuer: "http://127.0.0.1:9/nothing", ClientID: "x",
		ClientSecret: "y", AllowedDomains: []string{"sso.test"}})
	if fields(err)["issuer"] == "" {
		t.Fatalf("unreachable issuer: %v", err)
	}

	// Nor one at a cloud metadata address (netguard).
	_, err = e.svc.CreateProvider(ctx, e.admin, sso.ProviderInput{Name: "Metadata", Issuer: "https://169.254.169.254/latest", ClientID: "x",
		ClientSecret: "y", AllowedDomains: []string{"sso.test"}})
	if !strings.Contains(fields(err)["issuer"], "link-local") {
		t.Fatalf("metadata issuer: %v", err)
	}

	p := e.provider(func(in *sso.ProviderInput) { in.AllowedDomains = []string{"@SSO.test", "sso.test", "Example.COM"} })
	if strings.Join(p.AllowedDomains, ",") != "sso.test,example.com" {
		t.Fatalf("domains = %v", p.AllowedDomains)
	}
	// The secret is sealed, never stored or returned in the clear.
	if n := e.count(`SELECT count(*) FROM identity_providers WHERE client_secret_sealed LIKE '%' || $1 || '%'`, e.dex.ClientSecret); n != 0 {
		t.Fatal("client secret stored in the clear")
	}
	if _, err := e.svc.CreateProvider(ctx, e.admin, sso.ProviderInput{Name: "Dex", Issuer: e.dex.Issuer, ClientID: "x", ClientSecret: "y",
		AllowedDomains: []string{"sso.test"}}); fields(err)["name"] == "" {
		t.Fatalf("duplicate name: %v", err)
	}
	if _, err := e.svc.UpdateProvider(ctx, e.admin, uuid.New(), sso.ProviderInput{}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("update of a missing provider: %v", err)
	}

	// An empty secret keeps the stored one: sign-in still works.
	if _, err := e.svc.UpdateProvider(ctx, e.admin, p.ID, sso.ProviderInput{Name: "Dex renamed", Issuer: e.dex.Issuer, ClientID: e.dex.ClientID,
		AllowedDomains: []string{"sso.test"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	e.user(ssotest.Alex)
	if _, err := e.signIn(p.ID, ssotest.Alex, ""); err != nil {
		t.Fatalf("sign-in after keeping the secret: %v", err)
	}
	for _, a := range []string{"sso.provider_create", "sso.provider_update"} {
		if n := e.count(`SELECT count(*) FROM audit_log WHERE action = $1`, a); n < 1 {
			t.Errorf("no %s audit", a)
		}
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE details::text LIKE '%' || $1 || '%'`, e.dex.ClientSecret); n != 0 {
		t.Fatal("client secret in the audit log")
	}

	// Updates are checked like new providers: fields, the issuer when it
	// changes, a name another provider has.
	other := e.provider(func(in *sso.ProviderInput) { in.Name = "Other" })
	in := sso.ProviderInput{Name: "Dex renamed", Issuer: e.dex.Issuer, ClientID: e.dex.ClientID, AllowedDomains: []string{"sso.test"}, Enabled: true}
	bad := in
	bad.Name, bad.AllowedDomains = "", nil
	if f := fields(func() error { _, err := e.svc.UpdateProvider(ctx, e.admin, other.ID, bad); return err }()); f["name"] == "" || f["allowedDomains"] == "" {
		t.Fatalf("invalid update: %v", f)
	}
	bad = in
	bad.Issuer = "http://127.0.0.1:9/nothing"
	if f := fields(func() error { _, err := e.svc.UpdateProvider(ctx, e.admin, other.ID, bad); return err }()); f["issuer"] == "" {
		t.Fatalf("unreachable issuer on update: %v", f)
	}
	if f := fields(func() error { _, err := e.svc.UpdateProvider(ctx, e.admin, other.ID, in); return err }()); f["name"] == "" {
		t.Fatalf("taken name on update: %v", f)
	}
	// A new secret replaces the stored one: a wrong one fails the exchange.
	wrong := in
	wrong.Name, wrong.ClientSecret = "Other", "wrong-secret"
	if _, err := e.svc.UpdateProvider(ctx, e.admin, other.ID, wrong); err != nil {
		t.Fatal(err)
	}
	if _, err := e.signIn(other.ID, ssotest.Alex, ""); failureCode(err) != sso.FailProvider {
		t.Fatalf("sign-in with the replaced secret: %v", err)
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action = 'sso.provider_update' AND details->>'secretChanged' = 'true'`); n != 1 {
		t.Fatalf("secret change audits = %d", n)
	}
	if err := e.svc.DeleteProvider(ctx, e.admin, other.ID); err != nil {
		t.Fatal(err)
	}

	// A provider that cannot be reached, or whose secret this server
	// cannot open, cannot start a sign-in; nor can one that does not exist.
	e.exec(`UPDATE identity_providers SET issuer = 'http://127.0.0.1:9/gone', updated_at = now() WHERE id = $1`, p.ID)
	if _, _, err := e.svc.Start(ctx, p.ID, ""); failureCode(err) != sso.FailUnavailable {
		t.Fatalf("unreachable provider: %v", err)
	}
	e.exec(`UPDATE identity_providers SET issuer = $2, client_secret_sealed = 'not sealed', updated_at = now() WHERE id = $1`, p.ID, e.dex.Issuer)
	if _, _, err := e.svc.Start(ctx, p.ID, ""); failureCode(err) != sso.FailUnavailable || !strings.Contains(err.Error(), "secret key") {
		t.Fatalf("unreadable secret: %v", err)
	}
	if _, _, err := e.svc.Start(ctx, uuid.New(), ""); failureCode(err) != sso.FailUnavailable || !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("missing provider: %v", err)
	}

	list, err := e.svc.Providers(ctx)
	if err != nil || len(list) != 1 || list[0].Name != "Dex renamed" {
		t.Fatalf("providers = %+v, %v", list, err)
	}
	buttons, err := e.svc.Buttons(ctx)
	if err != nil || len(buttons) != 1 || buttons[0].StartURL != ssotest.PublicURL+"/api/v1/auth/sso/"+p.ID.String()+"/start" {
		t.Fatalf("buttons = %+v, %v", buttons, err)
	}

	// Return paths stay on this site.
	for in, want := range map[string]string{"/devices?a=1": "/devices?a=1", "//evil.example": "/", "/\\evil": "/", "https://evil.example": "/",
		"": "/", "devices": "/", "/x\r\nSet-Cookie: a": "/"} {
		if got := sso.SafeReturn(in); got != want {
			t.Errorf("SafeReturn(%q) = %q, want %q", in, got, want)
		}
	}
}
