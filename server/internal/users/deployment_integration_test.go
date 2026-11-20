//go:build integration

package users_test

import (
	"context"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// TestBootstrapDeployment is the first super administrator of a deployment
// that signs in through its own Authentik (ADR-0044).
func TestBootstrapDeployment(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()

	wantField(t, func() error { _, err := e.svc.BootstrapDeployment(ctx, "not-an-email"); return err }(), "email", "bad email")

	created, err := e.svc.BootstrapDeployment(ctx, " Admin@Example.com ")
	if err != nil || !created {
		t.Fatalf("created %v, %v", created, err)
	}
	if need, err := e.svc.NeedsSetup(ctx); err != nil || need {
		t.Fatalf("the first-run page would still offer itself: %v %v", need, err)
	}
	var id string
	e.scalar(t, `SELECT id::text FROM users WHERE email = 'admin@example.com' AND display_name = 'admin' AND password_hash IS NULL`, &id)
	var roles int
	e.scalar(t, `SELECT count(*) FROM role_assignments WHERE user_id = $1 AND role = $2 AND organization_id IS NULL`, &roles, id, string(rbac.RoleSuperAdmin))
	if roles != 1 {
		t.Fatalf("super administrator assignments = %d", roles)
	}
	var orgs int
	e.scalar(t, `SELECT count(*) FROM organizations`, &orgs)
	if orgs != 0 {
		t.Fatalf("organizations = %d", orgs)
	}
	if acts := e.auditActions(t, ""); acts["setup.complete"] != 1 {
		t.Fatalf("audit: %v", acts)
	}
	// Without a password, the account signs in only through single sign-on.
	if _, _, err := e.auth.Login(ctx, "admin@example.com", goodPassword, meta); err == nil {
		t.Fatal("password sign-in without a password")
	}

	// At every later start nothing happens, whatever the address.
	for _, email := range []string{"admin@example.com", "someone.else@example.com"} {
		created, err = e.svc.BootstrapDeployment(ctx, email)
		if err != nil || created {
			t.Fatalf("%s: created %v, %v", email, created, err)
		}
	}
	var users int
	e.scalar(t, `SELECT count(*) FROM users`, &users)
	if users != 1 {
		t.Fatalf("users = %d", users)
	}
}
