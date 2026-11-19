//go:build integration

package app_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/app"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/sso"
)

// TestHTTPAuthentik is EasyRMM's side of Authentik in the deployment
// (ADR-0044): the first administrator, the provider the deployment manages,
// Authentik's name on the edge, and the recovery link. Signing in through
// Authentik itself is make e2e-authentik's.
func TestHTTPAuthentik(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "authentik "+r.Host+" "+r.Header.Get("X-Forwarded-Proto")+" "+r.URL.Path)
	}))
	defer upstream.Close()
	h := newHarnessWith(t, false, func(c *config.Config) {
		c.Authentik = config.Authentik{Hostname: "auth.rmm.test", AdminEmail: "admin@msp.example",
			ClientSecret: strings.Repeat("s", 48), Upstream: upstream.Listener.Addr().String()}
	})
	anon := h.client()

	// The first administrator exists already: no first-run page.
	var setup struct {
		Required bool `json:"required"`
	}
	anon.expect(http.StatusOK, "GET", "/api/v1/setup", nil, &setup)
	if setup.Required {
		t.Fatal("the first-run page is offered")
	}

	// The sign-in page offers Authentik.
	var buttons struct {
		Providers []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			StartURL string `json:"startUrl"`
		} `json:"providers"`
	}
	anon.expect(http.StatusOK, "GET", "/api/v1/auth/sso", nil, &buttons)
	id := sso.DeploymentProviderID.String()
	if len(buttons.Providers) != 1 || buttons.Providers[0].Name != "Authentik" || buttons.Providers[0].StartURL != publicOrigin+"/api/v1/auth/sso/"+id+"/start" {
		t.Fatalf("buttons = %+v", buttons)
	}

	// Authentik's name goes to Authentik, every path.
	r := anon.do("GET", "/application/o/authorize/?client_id=easyrmm", nil, func(req *http.Request) { req.Host = "auth.rmm.test" })
	if r.status != http.StatusOK || string(r.body) != "authentik auth.rmm.test https /application/o/authorize/" {
		t.Fatalf("Authentik's name: %d %s", r.status, r.body)
	}

	// The recover command's link signs the administrator in once.
	var out bytes.Buffer
	cfg := *h.cfg
	sep := "?"
	if strings.Contains(h.db.SuperDSN, "?") {
		sep = "&"
	}
	cfg.DatabaseURL = h.db.SuperDSN + sep + "role=easyrmm_app"
	cfg.DatabaseMigrationURL = h.db.SuperDSN + sep + "role=easyrmm_owner"
	if err := app.Recover(context.Background(), &cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), "", &out); err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`for admin@msp\.example, valid for 15 minutes:\n\n  (https://rmm\.test/recover#token=(\S+))\n`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("output %q", out.String())
	}
	if u, err := url.Parse(m[1]); err != nil || u.Path != auth.RecoveryPath {
		t.Fatalf("link %s: %v", m[1], err)
	}
	browser := h.client()
	var s sessionView
	browser.expect(http.StatusOK, "POST", "/api/v1/auth/recover", map[string]string{"token": m[2]}, &s)
	if s.State != "active" || s.User.Email != "admin@msp.example" {
		t.Fatalf("session %+v", s)
	}
	browser.csrf = s.CSRFToken
	if r := anon.do("POST", "/api/v1/auth/recover", map[string]string{"token": m[2]}); r.status != http.StatusBadRequest || r.errorCode(t) != "invalid_recovery_link" {
		t.Fatalf("used twice: %d %s", r.status, r.body)
	}

	// Settings show the provider, managed, and refuse to change it.
	var settings struct {
		Providers []sso.Provider `json:"providers"`
	}
	browser.expect(http.StatusOK, "GET", "/api/v1/settings/sso", nil, &settings)
	if len(settings.Providers) != 1 || !settings.Providers[0].Managed || !settings.Providers[0].TrustMFA || !settings.Providers[0].TrustEmail ||
		settings.Providers[0].Issuer != "https://auth.rmm.test/application/o/easyrmm/" || strings.Join(settings.Providers[0].AllowedDomains, ",") != "msp.example" {
		t.Fatalf("providers = %+v", settings.Providers)
	}
	r = browser.do("PUT", "/api/v1/settings/sso/providers/"+id, map[string]any{"name": "Mine", "issuer": "https://auth.rmm.test/application/o/easyrmm/",
		"clientId": "easyrmm", "allowedDomains": []string{"msp.example"}, "enabled": true})
	if r.status != http.StatusConflict || r.errorCode(t) != "provider_managed" {
		t.Fatalf("update: %d %s", r.status, r.body)
	}
	if r := browser.do("DELETE", "/api/v1/settings/sso/providers/"+id, nil); r.status != http.StatusConflict {
		t.Fatalf("delete: %d %s", r.status, r.body)
	}

	// An unknown link, and one for another administrator than asked for.
	if r := anon.do("POST", "/api/v1/auth/recover", map[string]string{"token": "nothing"}); r.status != http.StatusBadRequest {
		t.Fatalf("unknown link: %d", r.status)
	}
	if err := app.Recover(context.Background(), &cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), "nobody@msp.example", &out); err == nil ||
		!strings.Contains(err.Error(), "is not an active super administrator") {
		t.Fatalf("another address: %v", err)
	}
	// A disabled account's link is refused at sign-in.
	link, err := auth.IssueRecoveryLink(context.Background(), h.db.DB, audit.New(h.db.DB, nil), "admin@msp.example", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.db.DB.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE users SET status = 'disabled' WHERE email = 'admin@msp.example'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if r := anon.do("POST", "/api/v1/auth/recover", map[string]string{"token": link.Token}); r.status != http.StatusForbidden ||
		r.errorCode(t) != "account_unavailable" {
		t.Fatalf("disabled account: %d %s", r.status, r.body)
	}
	// A database that cannot be reached.
	cfg.DatabaseMigrationURL = "postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=2"
	if err := app.Recover(context.Background(), &cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), "", &out); err == nil {
		t.Fatal("no database, no error")
	}
	cfg.DatabaseMigrationURL = "::not a url"
	if err := app.Recover(context.Background(), &cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), "", &out); err == nil {
		t.Fatal("a broken URL, no error")
	}
}
