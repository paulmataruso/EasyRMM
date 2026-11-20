//go:build integration

package sso_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/sso"
	"github.com/paulmataruso/easyrmm/server/internal/sso/ssotest"
)

// counting is a transport that counts the requests it carries: the
// deployment's own client must be the one that reaches the provider.
type counting struct{ n atomic.Int64 }

func (c *counting) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n.Add(1)
	return http.DefaultTransport.RoundTrip(r)
}

// TestDeploymentProvider is the provider the deployment sets up from its
// configuration (ADR-0044), here with Dex standing in for Authentik.
func TestDeploymentProvider(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	id := sso.DeploymentProviderID
	audits := func(action string) int {
		return e.count(`SELECT count(*) FROM audit_log WHERE action = $1 AND target_id = $2 AND actor_type = 'system'`, action, id.String())
	}
	load := func() sso.Provider {
		t.Helper()
		ps, err := e.svc.Providers(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range ps {
			if p.ID == id {
				return p
			}
		}
		t.Fatal("the deployment's provider is not listed")
		return sso.Provider{}
	}

	// Without one, nothing happens.
	if err := e.svc.UseDeployment(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM identity_providers`); n != 0 {
		t.Fatalf("providers = %d", n)
	}

	transport := &counting{}
	d := &sso.Deployment{Name: "Authentik", Issuer: e.dex.Issuer, ClientID: e.dex.ClientID, ClientSecret: e.dex.ClientSecret,
		Domains: []string{"SSO.test"}, Client: &http.Client{Transport: transport}}
	if err := e.svc.UseDeployment(ctx, d); err != nil {
		t.Fatal(err)
	}
	p := load()
	if !p.Managed || !p.Enabled || !p.TrustEmail || !p.TrustMFA || p.Name != "Authentik" || !slices.Equal(p.AllowedDomains, []string{"sso.test"}) {
		t.Fatalf("provider = %+v", p)
	}
	if audits("sso.provider_create") != 1 {
		t.Fatal("the creation is not audited as the deployment's")
	}
	// The same configuration at the next start changes nothing.
	if err := e.svc.UseDeployment(ctx, d); err != nil {
		t.Fatal(err)
	}
	if audits("sso.provider_update") != 0 || load().UpdatedAt != p.UpdatedAt {
		t.Fatal("an unchanged configuration was written again")
	}

	e.run("super administrators cannot change or remove it", func(e *env) {
		t := e.t
		_, err := e.svc.UpdateProvider(ctx, e.admin, id, sso.ProviderInput{Name: "Mine", Issuer: e.dex.Issuer, ClientID: "x",
			AllowedDomains: []string{"sso.test"}, Enabled: true})
		if !errors.Is(err, sso.ErrManaged) {
			t.Fatalf("update: %v", err)
		}
		if err := e.svc.DeleteProvider(ctx, e.admin, id); !errors.Is(err, sso.ErrManaged) {
			t.Fatalf("delete: %v", err)
		}
		if ae, ok := apperr.As(sso.ErrManaged); !ok || ae.Kind != apperr.KindConflict {
			t.Fatalf("ErrManaged = %#v", sso.ErrManaged)
		}
	})

	e.run("sign-in links by email, trusts the second factor, and goes through the deployment's client", func(e *env) {
		t := e.t
		alex := e.user(ssotest.Alex)
		before := transport.n.Load()
		res, err := e.signIn(id, ssotest.Alex, "")
		if err != nil {
			t.Fatal(err)
		}
		if res.Session.UserID != alex || res.Session.State != auth.StateActive {
			t.Fatalf("result %+v, session %+v", res, res.Session)
		}
		// Discovery, the token and the keys: all through the deployment's client.
		if transport.n.Load()-before < 2 {
			t.Fatalf("the deployment's client carried %d requests", transport.n.Load()-before)
		}
	})

	e.run("another address's domain is refused", func(e *env) {
		if _, code, err := e.svc.ResolveClaims(ctx, id, "subject-x", "someone@example.com", false); code != "domain" {
			e.t.Fatalf("code %q, err %v", code, err)
		}
	})

	e.run("a changed configuration is applied and audited", func(e *env) {
		t := e.t
		changed := *d
		changed.Domains = []string{"sso.test", "example.com"}
		if err := e.svc.UseDeployment(ctx, &changed); err != nil {
			t.Fatal(err)
		}
		if got := load().AllowedDomains; !slices.Equal(got, []string{"sso.test", "example.com"}) {
			t.Fatalf("domains %v", got)
		}
		changed.ClientSecret = "rotated"
		if err := e.svc.UseDeployment(ctx, &changed); err != nil {
			t.Fatal(err)
		}
		if audits("sso.provider_update") != 2 {
			t.Fatalf("updates audited: %d", audits("sso.provider_update"))
		}
		if err := e.svc.UseDeployment(ctx, d); err != nil {
			t.Fatal(err)
		}
	})

	e.run("it is refused when invalid", func(e *env) {
		bad := *d
		bad.Domains = nil
		if err := e.svc.UseDeployment(ctx, &bad); err == nil {
			e.t.Fatal("no domains accepted")
		}
	})

	e.run("another provider's name is kept apart", func(e *env) {
		t := e.t
		if err := e.svc.UseDeployment(ctx, nil); err != nil {
			t.Fatal(err)
		}
		if err := e.svc.DeleteProvider(ctx, e.admin, id); err != nil {
			t.Fatal(err)
		}
		mine := e.provider(func(in *sso.ProviderInput) { in.Name = "Authentik" })
		if err := e.svc.UseDeployment(ctx, d); err != nil {
			t.Fatal(err)
		}
		if got := load().Name; got != "Authentik (deployment)" {
			t.Fatalf("name %q", got)
		}
		// And it stays that way at the next start.
		before := audits("sso.provider_update")
		if err := e.svc.UseDeployment(ctx, d); err != nil {
			t.Fatal(err)
		}
		if audits("sso.provider_update") != before {
			t.Fatal("the fallback name was rewritten")
		}
		if err := e.svc.DeleteProvider(ctx, e.admin, mine.ID); err != nil {
			t.Fatal(err)
		}
	})

	e.run("taken out of the deployment, it is released, switched off", func(e *env) {
		t := e.t
		if err := e.svc.UseDeployment(ctx, nil); err != nil {
			t.Fatal(err)
		}
		p := load()
		if p.Managed || p.Enabled {
			t.Fatalf("provider %+v", p)
		}
		// A second release finds nothing to do.
		n := audits("sso.provider_update")
		if err := e.svc.UseDeployment(ctx, nil); err != nil || audits("sso.provider_update") != n {
			t.Fatalf("second release: %v", err)
		}
		// A super administrator may now remove it.
		if err := e.svc.DeleteProvider(ctx, e.admin, id); err != nil {
			t.Fatal(err)
		}
	})
}
