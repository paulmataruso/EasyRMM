//go:build integration

package users_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/internal/users"
)

const goodPassword = "orbit-violet-canyon-42"

var meta = auth.RequestMeta{IP: netip.MustParseAddr("198.51.100.20"), UserAgent: "go-test"}

type captureMailer struct {
	mu   sync.Mutex
	sent []string // to|subject|body
}

func (m *captureMailer) Send(_ context.Context, to, subject, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, to+"|"+subject+"|"+body)
	return nil
}

func (m *captureMailer) all() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.sent...)
}

type env struct {
	db    *database.DB
	auth  *auth.Service
	audit *audit.Logger
	svc   *users.Service
	hash  *auth.Hasher
	mail  *captureMailer // nil when the environment has no mailer
	sys   access.Caller

	orgA, orgB, siteA, siteA2, siteB uuid.UUID
}

func newEnv(t *testing.T, withMail bool) *env {
	t.Helper()
	inst := testdb.New(t)
	key := make([]byte, secrets.KeySize)
	_, _ = rand.Read(key)
	sealer, err := secrets.NewSealer(secrets.Key{ID: "k1", Raw: key})
	if err != nil {
		t.Fatal(err)
	}
	cfg := auth.DefaultConfig()
	cfg.PublicURL = "https://rmm.example.com"
	e := &env{db: inst.DB, audit: audit.New(inst.DB, nil), sys: access.System("test")}
	e.hash = auth.NewHasher(auth.Argon2Params{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32}, 4)
	if withMail {
		e.mail = &captureMailer{}
		e.auth = auth.NewService(inst.DB, e.audit, e.hash, sealer, e.mail, cfg)
	} else {
		e.auth = auth.NewService(inst.DB, e.audit, e.hash, sealer, nil, cfg)
	}
	e.svc = users.New(inst.DB, e.audit, e.auth, e.hash)
	return e
}

func (e *env) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	err := e.db.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), sql, args...)
		return err
	})
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (e *env) scalar(t *testing.T, sql string, dst any, args ...any) {
	t.Helper()
	err := e.db.ReadTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), sql, args...).Scan(dst)
	})
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// tenants creates organizations A and B, sites A1 and A2 in A, and B1 in B.
func (e *env) tenants(t *testing.T) {
	t.Helper()
	err := e.db.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		ctx := context.Background()
		if err := tx.QueryRow(ctx, `INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`).Scan(&e.orgA); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`).Scan(&e.orgB); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, e.orgA).Scan(&e.siteA); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO sites (organization_id, name) VALUES ($1, 'Branch') RETURNING id`, e.orgA).Scan(&e.siteA2); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO sites (organization_id, name) VALUES ($1, 'Plant') RETURNING id`, e.orgB).Scan(&e.siteB)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// user creates an account (with a password unless noPassword) holding the
// given roles.
func (e *env) user(t *testing.T, email string, noPassword bool, as ...rbac.Assignment) uuid.UUID {
	t.Helper()
	var hash *string
	if !noPassword {
		h, err := e.hash.Hash(context.Background(), goodPassword)
		if err != nil {
			t.Fatal(err)
		}
		hash = &h
	}
	var id uuid.UUID
	err := e.db.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		ctx := context.Background()
		name := strings.Split(email, "@")[0]
		if err := tx.QueryRow(ctx, `INSERT INTO users (email, display_name, password_hash) VALUES ($1, $2, $3) RETURNING id`, email, name, hash).Scan(&id); err != nil {
			return err
		}
		for _, a := range as {
			var org, site *uuid.UUID
			if a.OrganizationID != uuid.Nil {
				org = &a.OrganizationID
			}
			if a.SiteID != uuid.Nil {
				site = &a.SiteID
			}
			if _, err := tx.Exec(ctx, `INSERT INTO role_assignments (user_id, role, organization_id, site_id) VALUES ($1, $2, $3, $4)`, id, string(a.Role), org, site); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *env) caller(t *testing.T, id uuid.UUID) access.Caller {
	t.Helper()
	p, err := e.auth.LoadPrincipal(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: id, Label: id.String()[:8] + "@example.com"})
}

func ptr(id uuid.UUID) *uuid.UUID { return &id }

func orgRole(r rbac.Role, org uuid.UUID) rbac.Assignment {
	return rbac.Assignment{Role: r, OrganizationID: org}
}

func siteRole(r rbac.Role, org, site uuid.UUID) rbac.Assignment {
	return rbac.Assignment{Role: r, OrganizationID: org, SiteID: site}
}

func grant(r rbac.Role, org, site uuid.UUID) users.Assignment {
	a := users.Assignment{Role: r}
	if org != uuid.Nil {
		a.OrganizationID = ptr(org)
	}
	if site != uuid.Nil {
		a.SiteID = ptr(site)
	}
	return a
}

// wantKind fails unless err is an apperr of the given kind and code, and
// returns its field messages.
func wantKind(t *testing.T, err error, kind apperr.Kind, code, what string) map[string]string {
	t.Helper()
	ae, ok := apperr.As(err)
	if !ok || ae.Kind != kind || (code != "" && ae.Code != code) {
		t.Fatalf("%s: got %v, want kind %d code %q", what, err, kind, code)
	}
	return ae.Fields
}

func wantField(t *testing.T, err error, field, what string) string {
	t.Helper()
	fields := wantKind(t, err, apperr.KindInvalid, "validation_failed", what)
	msg, ok := fields[field]
	if !ok {
		t.Fatalf("%s: fields %v, want %q", what, fields, field)
	}
	return msg
}

func (e *env) auditActions(t *testing.T, prefix string) map[string]int {
	t.Helper()
	entries, err := e.audit.List(context.Background(), database.System, audit.Query{ActionPrefix: prefix, Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, en := range entries {
		out[en.Action]++
	}
	return out
}

// ---------------------------------------------------------------------------

func TestBootstrap(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	need, err := e.svc.NeedsSetup(ctx)
	if err != nil || !need {
		t.Fatalf("NeedsSetup on empty db: %v %v", need, err)
	}
	good := users.SetupInput{Email: " Admin@MSP.example ", DisplayName: "Ada Admin", Password: goodPassword, OrganizationName: "Acme"}

	bad := good
	bad.Email = "not-an-email"
	wantField(t, func() error { _, err := e.svc.Bootstrap(ctx, bad, meta); return err }(), "email", "bad email")
	bad = good
	bad.DisplayName = " "
	wantField(t, func() error { _, err := e.svc.Bootstrap(ctx, bad, meta); return err }(), "displayName", "empty name")
	bad = good
	bad.OrganizationName = strings.Repeat("o", 201)
	wantField(t, func() error { _, err := e.svc.Bootstrap(ctx, bad, meta); return err }(), "organizationName", "long org")
	bad = good
	bad.Password = "short"
	msg := wantField(t, func() error { _, err := e.svc.Bootstrap(ctx, bad, meta); return err }(), "password", "weak password")
	if msg != auth.PasswordAdvice(auth.ErrPasswordTooShort) {
		t.Fatalf("password advice %q", msg)
	}
	bad.Password = "ada admin long password"
	msg = wantField(t, func() error { _, err := e.svc.Bootstrap(ctx, bad, meta); return err }(), "password", "personal password")
	if msg != auth.PasswordAdvice(auth.ErrPasswordPersonal) {
		t.Fatalf("personal password advice %q", msg)
	}

	id, err := e.svc.Bootstrap(ctx, good, meta)
	if err != nil {
		t.Fatal(err)
	}
	need, err = e.svc.NeedsSetup(ctx)
	if err != nil || need {
		t.Fatalf("NeedsSetup after bootstrap: %v %v", need, err)
	}
	if _, err := e.svc.Bootstrap(ctx, good, meta); !errors.Is(err, users.ErrSetupDone) {
		t.Fatalf("second bootstrap: %v", err)
	}
	u, err := e.svc.Get(ctx, e.sys, id)
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "admin@msp.example" || !u.PasswordSet || len(u.Assignments) != 1 || u.Assignments[0].Role != rbac.RoleSuperAdmin {
		t.Fatalf("bootstrapped user: %+v", u)
	}
	var orgs int
	e.scalar(t, `SELECT count(*) FROM organizations WHERE name = 'Acme'`, &orgs)
	if orgs != 1 {
		t.Fatalf("first organization not created")
	}
	acts := e.auditActions(t, "")
	if acts["setup.complete"] != 1 || acts["organization.create"] != 1 {
		t.Fatalf("audit: %v", acts)
	}
	// The administrator can sign in with the chosen password.
	if _, _, err := e.auth.Login(ctx, "admin@msp.example", goodPassword, meta); err != nil {
		t.Fatalf("login after bootstrap: %v", err)
	}

	// Without an organization name only the user is created.
	e2 := newEnv(t, false)
	good.OrganizationName = ""
	if _, err := e2.svc.Bootstrap(ctx, good, meta); err != nil {
		t.Fatal(err)
	}
	e2.scalar(t, `SELECT count(*) FROM organizations`, &orgs)
	if orgs != 0 {
		t.Fatalf("organizations created without a name: %d", orgs)
	}
}

func TestInvite(t *testing.T) {
	for _, withMail := range []bool{false, true} {
		t.Run(fmt.Sprintf("mail=%v", withMail), func(t *testing.T) {
			e := newEnv(t, withMail)
			ctx := context.Background()
			e.tenants(t)
			super := e.caller(t, e.user(t, "super@msp.example", false, rbac.Assignment{Role: rbac.RoleSuperAdmin}))
			oa := e.caller(t, e.user(t, "olivia@acme.example", false, orgRole(rbac.RoleOrgAdmin, e.orgA)))

			in := func(email string, as ...users.Assignment) users.InviteInput {
				return users.InviteInput{Email: email, DisplayName: "New Person", Assignments: as}
			}
			techA := grant(rbac.RoleTechnician, e.orgA, e.siteA)

			// Validation.
			_, err := e.svc.Invite(ctx, oa, in("bad", techA), meta)
			wantField(t, err, "email", "bad email")
			_, err = e.svc.Invite(ctx, oa, users.InviteInput{Email: "x@acme.example", DisplayName: "", Assignments: []users.Assignment{techA}}, meta)
			wantField(t, err, "displayName", "no name")
			_, err = e.svc.Invite(ctx, oa, users.InviteInput{Email: "x@acme.example", DisplayName: "Line\nBreak", Assignments: []users.Assignment{techA}}, meta)
			wantField(t, err, "displayName", "control name")
			_, err = e.svc.Invite(ctx, oa, in("x@acme.example"), meta)
			wantField(t, err, "assignments", "no roles")
			many := make([]users.Assignment, 101)
			for i := range many {
				many[i] = techA
			}
			_, err = e.svc.Invite(ctx, oa, in("x@acme.example", many...), meta)
			wantField(t, err, "assignments", "too many roles")
			_, err = e.svc.Invite(ctx, oa, in("x@acme.example", techA, techA), meta)
			wantField(t, err, "assignments.1", "duplicate roles")

			// Escalation attempts by an organization administrator.
			for name, a := range map[string]users.Assignment{
				"super admin":       grant(rbac.RoleSuperAdmin, uuid.Nil, uuid.Nil),
				"foreign org":       grant(rbac.RoleTechnician, e.orgB, uuid.Nil),
				"foreign site":      grant(rbac.RoleTechnician, e.orgB, e.siteB),
				"unknown role":      grant("god", e.orgA, uuid.Nil),
				"org admin at site": grant(rbac.RoleOrgAdmin, e.orgA, e.siteA),
				"site without org":  {Role: rbac.RoleTechnician, SiteID: ptr(e.siteA)},
			} {
				_, err := e.svc.Invite(ctx, oa, in("x@acme.example", a), meta)
				wantField(t, err, "assignments.0", name)
			}
			// A site in another organization than claimed (only a super admin
			// gets past the authority check; the database rejects it).
			_, err = e.svc.Invite(ctx, super, in("x@acme.example", grant(rbac.RoleTechnician, e.orgA, e.siteB)), meta)
			wantField(t, err, "assignments", "site not in org")
			_, err = e.svc.Invite(ctx, super, in("x@acme.example", grant(rbac.RoleTechnician, uuid.New(), uuid.Nil)), meta)
			wantField(t, err, "assignments", "unknown org")
			var n int
			e.scalar(t, `SELECT count(*) FROM users WHERE email = 'x@acme.example'`, &n)
			if n != 0 {
				t.Fatal("failed invitation left a user behind")
			}

			// Success.
			res, err := e.svc.Invite(ctx, oa, in(" Tom@Acme.Example ", techA), meta)
			if err != nil {
				t.Fatal(err)
			}
			u := res.User
			if u.Email != "tom@acme.example" || u.PasswordSet || u.Status != "active" || len(u.Assignments) != 1 ||
				u.Assignments[0].OrganizationName != "Acme" || u.Assignments[0].SiteName != "HQ" || !u.CanManage {
				t.Fatalf("invited user: %+v", u)
			}
			if withMail {
				sent := e.mail.all()
				if !res.Emailed || res.Link != "" || len(sent) != 1 || !strings.HasPrefix(sent[0], "tom@acme.example|You have been invited") ||
					!strings.Contains(sent[0], "https://rmm.example.com/welcome#token=") {
					t.Fatalf("emailed invite: %+v %v", res, sent)
				}
			} else if res.Emailed || !strings.HasPrefix(res.Link, "https://rmm.example.com/welcome#token=") {
				t.Fatalf("invite link: %+v", res)
			}
			// The invitation can be redeemed.
			if !withMail {
				tok := strings.TrimPrefix(res.Link, "https://rmm.example.com/welcome#token=")
				if err := e.auth.CompletePasswordReset(ctx, tok, "a brand new passphrase", meta); err != nil {
					t.Fatalf("redeeming invite: %v", err)
				}
			}

			_, err = e.svc.Invite(ctx, oa, in("TOM@acme.example", techA), meta)
			wantField(t, err, "email", "duplicate email")

			entries, err := e.audit.List(ctx, database.System, audit.Query{ActionPrefix: "user.invite"})
			if err != nil || len(entries) != 1 || entries[0].OrganizationID == nil || *entries[0].OrganizationID != e.orgA ||
				entries[0].SiteID == nil || *entries[0].SiteID != e.siteA {
				t.Fatalf("invite audit: %v %+v", err, entries)
			}
		})
	}
}

// people is a populated directory used by several tests.
type people struct {
	super, oa, ob, tech, ro, multi, sa uuid.UUID
}

func (e *env) people(t *testing.T) people {
	t.Helper()
	e.tenants(t)
	return people{
		super: e.user(t, "super@msp.example", false, rbac.Assignment{Role: rbac.RoleSuperAdmin}),
		oa:    e.user(t, "olivia@acme.example", false, orgRole(rbac.RoleOrgAdmin, e.orgA)),
		ob:    e.user(t, "oscar@globex.example", false, orgRole(rbac.RoleOrgAdmin, e.orgB)),
		tech:  e.user(t, "tom.tech@acme.example", false, siteRole(rbac.RoleTechnician, e.orgA, e.siteA)),
		ro:    e.user(t, "rita@acme.example", false, orgRole(rbac.RoleReadOnly, e.orgA)),
		multi: e.user(t, "max@contractor.example", false, orgRole(rbac.RoleTechnician, e.orgA), orgRole(rbac.RoleTechnician, e.orgB)),
		sa:    e.user(t, "sam@acme.example", false, siteRole(rbac.RoleSiteAdmin, e.orgA, e.siteA)),
	}
}

func emails(us []users.User) []string {
	out := make([]string, len(us))
	for i, u := range us {
		out[i] = u.Email
	}
	return out
}

func TestListAndGet(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	p := e.people(t)

	all, next, err := e.svc.List(ctx, e.caller(t, p.super), users.ListQuery{})
	if err != nil || next != "" || len(all) != 7 {
		t.Fatalf("super list: %v %q %v", err, next, emails(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].Email >= all[i].Email {
			t.Fatalf("not sorted: %v", emails(all))
		}
	}

	oa := e.caller(t, p.oa)
	list, _, err := e.svc.List(ctx, oa, users.ListQuery{})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(emails(list), ",")
	if got != "max@contractor.example,olivia@acme.example,rita@acme.example,sam@acme.example,tom.tech@acme.example" {
		t.Fatalf("org admin sees %s", got)
	}
	for _, u := range list {
		switch u.Email {
		case "olivia@acme.example":
			if !u.IsSelf || u.CanManage {
				t.Fatalf("self flags: %+v", u)
			}
		case "max@contractor.example":
			if u.CanManage || u.HiddenAssignments != 1 || len(u.Assignments) != 1 || *u.Assignments[0].OrganizationID != e.orgA {
				t.Fatalf("multi-tenant user: %+v", u)
			}
		default:
			if !u.CanManage {
				t.Fatalf("org admin should manage %s", u.Email)
			}
		}
	}
	if _, err := e.svc.Get(ctx, oa, p.super); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("org admin get super admin: %v", err)
	}
	if _, err := e.svc.Get(ctx, oa, p.ob); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("org admin get foreign admin: %v", err)
	}
	m, err := e.svc.Get(ctx, oa, p.multi)
	if err != nil || m.HiddenAssignments != 1 {
		t.Fatalf("get multi: %v %+v", err, m)
	}

	// Site administrators see users with roles at their sites.
	list, _, err = e.svc.List(ctx, e.caller(t, p.sa), users.ListQuery{})
	if err != nil || strings.Join(emails(list), ",") != "sam@acme.example,tom.tech@acme.example" {
		t.Fatalf("site admin sees %v (%v)", emails(list), err)
	}
	for _, u := range list {
		if u.CanManage {
			t.Fatalf("site admin should not manage %s", u.Email)
		}
	}

	// Technicians may not list users.
	if _, _, err := e.svc.List(ctx, e.caller(t, p.tech), users.ListQuery{}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("technician list: %v", err)
	}

	// Search matches e-mail and display name, case-insensitively.
	list, _, err = e.svc.List(ctx, oa, users.ListQuery{Search: " TECH "})
	if err != nil || len(list) != 1 || list[0].ID != p.tech {
		t.Fatalf("search: %v %v", err, emails(list))
	}
	e.exec(t, `UPDATE users SET display_name = 'Rita Reader' WHERE id = $1`, p.ro)
	list, _, err = e.svc.List(ctx, oa, users.ListQuery{Search: "reader"})
	if err != nil || len(list) != 1 || list[0].ID != p.ro {
		t.Fatalf("search display name: %v %v", err, emails(list))
	}

	// Organization filter.
	list, _, err = e.svc.List(ctx, e.caller(t, p.super), users.ListQuery{OrganizationID: e.orgB})
	if err != nil || strings.Join(emails(list), ",") != "max@contractor.example,oscar@globex.example" {
		t.Fatalf("org filter: %v %v", err, emails(list))
	}

	// Pagination walks every user exactly once.
	var walked []string
	after := ""
	for page := 0; page < 10; page++ {
		items, next, err := e.svc.List(ctx, e.caller(t, p.super), users.ListQuery{Limit: 3, After: after})
		if err != nil {
			t.Fatal(err)
		}
		if len(items) > 3 {
			t.Fatalf("page size %d", len(items))
		}
		walked = append(walked, emails(items)...)
		if next == "" {
			break
		}
		after = next
	}
	if strings.Join(walked, ",") != strings.Join(emails(all), ",") {
		t.Fatalf("pagination walked %v, want %v", walked, emails(all))
	}
	_, _, err = e.svc.List(ctx, oa, users.ListQuery{After: "%%%"})
	wantField(t, err, "after", "bad cursor")

	// System callers see everyone.
	list, _, err = e.svc.List(ctx, e.sys, users.ListQuery{Limit: 500})
	if err != nil || len(list) != 7 {
		t.Fatalf("system list: %v %d", err, len(list))
	}
}

func TestUpdateProfiles(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	p := e.people(t)
	oa := e.caller(t, p.oa)

	u, err := e.svc.UpdateProfile(ctx, oa, p.tech, "  Thomas Tech ")
	if err != nil || u.DisplayName != "Thomas Tech" {
		t.Fatalf("update profile: %v %+v", err, u)
	}
	_, err = e.svc.UpdateProfile(ctx, oa, p.tech, "")
	wantField(t, err, "displayName", "empty name")
	_, err = e.svc.UpdateProfile(ctx, oa, p.tech, strings.Repeat("n", 201))
	wantField(t, err, "displayName", "long name")
	if _, err := e.svc.UpdateProfile(ctx, oa, p.multi, "x"); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("update user with foreign roles: %v", err)
	}
	_, err = e.svc.UpdateProfile(ctx, oa, p.oa, "Me")
	wantKind(t, err, apperr.KindConflict, "self_change", "self update")
	if _, err := e.svc.UpdateProfile(ctx, oa, uuid.New(), "x"); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}

	if err := e.svc.UpdateOwnProfile(ctx, oa.Actor, p.oa, " Olivia O. "); err != nil {
		t.Fatal(err)
	}
	var name string
	e.scalar(t, `SELECT display_name FROM users WHERE id = $1`, &name, p.oa)
	if name != "Olivia O." {
		t.Fatalf("own profile: %q", name)
	}
	if err := e.svc.UpdateOwnProfile(ctx, oa.Actor, p.oa, "\t"); err == nil {
		t.Fatal("blank own name accepted")
	}
	if acts := e.auditActions(t, "user.update"); acts["user.update"] != 2 {
		t.Fatalf("audit: %v", acts)
	}
}

func roleSet(u *users.User) string {
	var parts []string
	for _, a := range u.Assignments {
		s := string(a.Role)
		if a.OrganizationID != nil {
			s += "@" + a.OrganizationName
		}
		if a.SiteID != nil {
			s += "/" + a.SiteName
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ",")
}

func TestSetAssignments(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	p := e.people(t)
	oa := e.caller(t, p.oa)
	super := e.caller(t, p.super)

	// Replaces only the roles within the caller's authority.
	u, err := e.svc.SetAssignments(ctx, oa, p.multi, []users.Assignment{grant(rbac.RoleReadOnly, e.orgA, uuid.Nil)})
	if err != nil {
		t.Fatal(err)
	}
	if roleSet(u) != "read_only@Acme" || u.HiddenAssignments != 1 {
		t.Fatalf("after org admin change: %s hidden=%d", roleSet(u), u.HiddenAssignments)
	}
	full, _ := e.svc.Get(ctx, super, p.multi)
	if roleSet(full) != "read_only@Acme,technician@Globex" {
		t.Fatalf("full roles: %s", roleSet(full))
	}
	// Removing all of her roles is allowed when other roles remain; the
	// change is reported as successful and the user leaves her view.
	u, err = e.svc.SetAssignments(ctx, oa, p.multi, nil)
	if err != nil || len(u.Assignments) != 0 || u.HiddenAssignments != 1 || u.CanManage {
		t.Fatalf("removing the last visible role: %v %+v", err, u)
	}
	if _, err := e.svc.Get(ctx, oa, p.multi); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("user should leave the view after losing the last visible role: %v", err)
	}
	full, _ = e.svc.Get(ctx, super, p.multi)
	if roleSet(full) != "technician@Globex" {
		t.Fatalf("after removal: %s", roleSet(full))
	}

	// Moving a technician between sites.
	u, err = e.svc.SetAssignments(ctx, oa, p.tech, []users.Assignment{grant(rbac.RoleTechnician, e.orgA, e.siteA2), grant(rbac.RoleReadOnly, e.orgA, e.siteA)})
	if err != nil || roleSet(u) != "read_only@Acme/HQ,technician@Acme/Branch" {
		t.Fatalf("moved technician: %v %s", err, roleSet(u))
	}
	_, err = e.svc.SetAssignments(ctx, oa, p.tech, nil)
	wantField(t, err, "assignments", "no roles left")
	_, err = e.svc.SetAssignments(ctx, oa, p.tech, []users.Assignment{grant(rbac.RoleTechnician, e.orgA, uuid.Nil), grant(rbac.RoleTechnician, e.orgA, uuid.Nil)})
	wantField(t, err, "assignments.1", "duplicates")
	_, err = e.svc.SetAssignments(ctx, oa, p.tech, []users.Assignment{grant(rbac.RoleSuperAdmin, uuid.Nil, uuid.Nil)})
	wantField(t, err, "assignments.0", "escalation")
	_, err = e.svc.SetAssignments(ctx, oa, p.tech, make([]users.Assignment, 101))
	wantField(t, err, "assignments", "too many")
	_, err = e.svc.SetAssignments(ctx, oa, p.oa, []users.Assignment{grant(rbac.RoleOrgAdmin, e.orgA, uuid.Nil)})
	wantKind(t, err, apperr.KindConflict, "self_change", "self change")
	if _, err := e.svc.SetAssignments(ctx, oa, uuid.New(), []users.Assignment{grant(rbac.RoleReadOnly, e.orgA, uuid.Nil)}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("missing user: %v", err)
	}
	// A failing grant leaves existing roles untouched.
	_, err = e.svc.SetAssignments(ctx, super, p.tech, []users.Assignment{grant(rbac.RoleTechnician, e.orgA, e.siteB)})
	wantField(t, err, "assignments", "site in wrong org")
	u, _ = e.svc.Get(ctx, super, p.tech)
	if roleSet(u) != "read_only@Acme/HQ,technician@Acme/Branch" {
		t.Fatalf("roles changed by a failed update: %s", roleSet(u))
	}

	// Last super administrator.
	_, err = e.svc.SetAssignments(ctx, e.sys, p.super, []users.Assignment{grant(rbac.RoleOrgAdmin, e.orgA, uuid.Nil)})
	wantKind(t, err, apperr.KindConflict, "last_super_admin", "demote last super admin")
	second := e.user(t, "second@msp.example", false, rbac.Assignment{Role: rbac.RoleSuperAdmin})
	u, err = e.svc.SetAssignments(ctx, e.caller(t, second), p.super, []users.Assignment{grant(rbac.RoleOrgAdmin, e.orgA, uuid.Nil)})
	if err != nil || roleSet(u) != "org_admin@Acme" {
		t.Fatalf("demote with another super admin: %v %s", err, roleSet(u))
	}
	if acts := e.auditActions(t, "user.roles_change"); acts["user.roles_change"] != 4 {
		t.Fatalf("audit: %v", acts)
	}
}

func (e *env) session(t *testing.T, userID uuid.UUID) uuid.UUID {
	t.Helper()
	tok, hash, err := auth.NewToken()
	_ = tok
	if err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	err = e.db.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `INSERT INTO sessions (token_hash, user_id, state, idle_expires_at, expires_at)
			VALUES ($1, $2, 'active', now() + interval '1 hour', now() + interval '2 hours') RETURNING id`, hash, userID).Scan(&id)
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *env) revoked(t *testing.T, sessionID uuid.UUID) bool {
	t.Helper()
	var r bool
	e.scalar(t, `SELECT revoked_at IS NOT NULL FROM sessions WHERE id = $1`, &r, sessionID)
	return r
}

func TestStatusUnlockAndMFAReset(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	p := e.people(t)
	oa := e.caller(t, p.oa)

	sess := e.session(t, p.tech)
	u, err := e.svc.SetStatus(ctx, oa, p.tech, "disabled")
	if err != nil || u.Status != "disabled" {
		t.Fatalf("disable: %v %+v", err, u)
	}
	if !e.revoked(t, sess) {
		t.Fatal("disabling did not revoke the session")
	}
	if u, err = e.svc.SetStatus(ctx, oa, p.tech, "disabled"); err != nil || u.Status != "disabled" {
		t.Fatalf("idempotent disable: %v", err)
	}
	if u, err = e.svc.SetStatus(ctx, oa, p.tech, "active"); err != nil || u.Status != "active" {
		t.Fatalf("enable: %v %+v", err, u)
	}
	_, err = e.svc.SetStatus(ctx, oa, p.tech, "banned")
	wantField(t, err, "status", "invalid status")
	if _, err := e.svc.SetStatus(ctx, oa, p.multi, "disabled"); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("disable user with foreign roles: %v", err)
	}
	_, err = e.svc.SetStatus(ctx, e.sys, p.super, "disabled")
	wantKind(t, err, apperr.KindConflict, "last_super_admin", "disable last super admin")
	acts := e.auditActions(t, "user")
	if acts["user.disable"] != 1 || acts["user.enable"] != 1 {
		t.Fatalf("audit: %v", acts)
	}

	// Unlock.
	e.exec(t, `UPDATE users SET failed_logins = 9, locked_until = now() + interval '1 hour' WHERE id = $1`, p.tech)
	u, _ = e.svc.Get(ctx, oa, p.tech)
	if !u.Locked {
		t.Fatal("user should show as locked")
	}
	if u, err = e.svc.Unlock(ctx, oa, p.tech); err != nil || u.Locked {
		t.Fatalf("unlock: %v %+v", err, u)
	}
	var failed int
	e.scalar(t, `SELECT failed_logins FROM users WHERE id = $1`, &failed, p.tech)
	if failed != 0 {
		t.Fatalf("failed_logins = %d", failed)
	}
	if _, err := e.svc.Unlock(ctx, oa, p.multi); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("unlock foreign: %v", err)
	}

	// MFA reset. A security key alone counts as a second factor (ADR-0032).
	e.exec(t, `INSERT INTO user_webauthn_credentials (user_id, credential_id, name, credential) VALUES ($1, '\x0102', 'YubiKey', '{}')`, p.tech)
	if u, _ := e.svc.Get(ctx, oa, p.tech); !u.MFAEnabled {
		t.Fatal("a security key should count as MFA")
	}
	e.exec(t, `UPDATE users SET totp_secret_sealed = 'sealed', totp_enabled_at = now(), totp_last_step = 5 WHERE id = $1`, p.tech)
	e.exec(t, `INSERT INTO user_recovery_codes (user_id, code_hash) VALUES ($1, '\x01'), ($1, '\x02')`, p.tech)
	sess = e.session(t, p.tech)
	u, _ = e.svc.Get(ctx, oa, p.tech)
	if !u.MFAEnabled {
		t.Fatal("MFA should show as enabled")
	}
	if u, err = e.svc.ResetMFA(ctx, oa, p.tech); err != nil || u.MFAEnabled {
		t.Fatalf("reset mfa: %v %+v", err, u)
	}
	var codes int
	var secret *string
	e.scalar(t, `SELECT count(*) FROM user_recovery_codes WHERE user_id = $1`, &codes, p.tech)
	e.scalar(t, `SELECT totp_secret_sealed FROM users WHERE id = $1`, &secret, p.tech)
	var keys int
	e.scalar(t, `SELECT count(*) FROM user_webauthn_credentials WHERE user_id = $1`, &keys, p.tech)
	if codes != 0 || secret != nil || keys != 0 {
		t.Fatalf("mfa material left: codes=%d secret=%v keys=%d", codes, secret, keys)
	}
	if !e.revoked(t, sess) {
		t.Fatal("MFA reset did not revoke the session")
	}
	_, err = e.svc.ResetMFA(ctx, oa, p.oa)
	wantKind(t, err, apperr.KindConflict, "self_change", "self mfa reset")
	if _, err := e.svc.ResetMFA(ctx, oa, p.super); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("reset invisible user: %v", err)
	}
}

func TestIssuePasswordLink(t *testing.T) {
	for _, withMail := range []bool{false, true} {
		t.Run(fmt.Sprintf("mail=%v", withMail), func(t *testing.T) {
			e := newEnv(t, withMail)
			ctx := context.Background()
			e.tenants(t)
			oa := e.caller(t, e.user(t, "olivia@acme.example", false, orgRole(rbac.RoleOrgAdmin, e.orgA)))
			invited := e.user(t, "new@acme.example", true, orgRole(rbac.RoleTechnician, e.orgA))
			existing := e.user(t, "old@acme.example", false, orgRole(rbac.RoleTechnician, e.orgA))

			res, err := e.svc.IssuePasswordLink(ctx, oa, invited, meta)
			if err != nil {
				t.Fatal(err)
			}
			res2, err := e.svc.IssuePasswordLink(ctx, oa, existing, meta)
			if err != nil {
				t.Fatal(err)
			}
			if withMail {
				sent := e.mail.all()
				if !res.Emailed || !res2.Emailed || res.Link != "" || len(sent) != 2 ||
					!strings.HasPrefix(sent[0], "new@acme.example|You have been invited") || !strings.Contains(sent[0], "/welcome#token=") ||
					!strings.HasPrefix(sent[1], "old@acme.example|Reset your EasyRMM password") || !strings.Contains(sent[1], "/reset-password#token=") {
					t.Fatalf("mailed links: %+v %+v %v", res, res2, sent)
				}
			} else {
				if !strings.HasPrefix(res.Link, "https://rmm.example.com/welcome#token=") || res.Emailed {
					t.Fatalf("invite link: %+v", res)
				}
				if !strings.HasPrefix(res2.Link, "https://rmm.example.com/reset-password#token=") {
					t.Fatalf("reset link: %+v", res2)
				}
				tok := strings.TrimPrefix(res2.Link, "https://rmm.example.com/reset-password#token=")
				if err := e.auth.CompletePasswordReset(ctx, tok, "another long passphrase", meta); err != nil {
					t.Fatalf("using reset link: %v", err)
				}
			}
			if res.User == nil || res.User.ID != invited {
				t.Fatalf("result user: %+v", res.User)
			}

			if _, err := e.svc.SetStatus(ctx, oa, existing, "disabled"); err != nil {
				t.Fatal(err)
			}
			_, err = e.svc.IssuePasswordLink(ctx, oa, existing, meta)
			wantKind(t, err, apperr.KindConflict, "user_disabled", "link for disabled user")
			if acts := e.auditActions(t, "user.password_link"); acts["user.password_link"] != 2 {
				t.Fatalf("audit: %v", acts)
			}
		})
	}
}

func TestDelete(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	p := e.people(t)
	oa := e.caller(t, p.oa)

	if err := e.svc.Delete(ctx, oa, p.tech); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Get(ctx, e.sys, p.tech); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("deleted user still present: %v", err)
	}
	if err := e.svc.Delete(ctx, oa, p.tech); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if err := e.svc.Delete(ctx, oa, p.multi); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("delete user with foreign roles: %v", err)
	}
	wantKind(t, e.svc.Delete(ctx, oa, p.oa), apperr.KindConflict, "self_change", "self delete")
	wantKind(t, e.svc.Delete(ctx, e.sys, p.super), apperr.KindConflict, "last_super_admin", "delete last super admin")

	// A disabled super administrator does not count as a remaining one, but
	// can itself be deleted.
	other := e.user(t, "other@msp.example", false, rbac.Assignment{Role: rbac.RoleSuperAdmin})
	e.exec(t, `UPDATE users SET status = 'disabled' WHERE id = $1`, other)
	wantKind(t, e.svc.Delete(ctx, e.sys, p.super), apperr.KindConflict, "last_super_admin", "only disabled peer")
	if err := e.svc.Delete(ctx, e.caller(t, p.super), other); err != nil {
		t.Fatalf("delete disabled super admin: %v", err)
	}
	second := e.user(t, "second@msp.example", false, rbac.Assignment{Role: rbac.RoleSuperAdmin})
	if err := e.svc.Delete(ctx, e.caller(t, second), p.super); err != nil {
		t.Fatalf("delete super admin with a peer: %v", err)
	}
	entries, err := e.audit.List(ctx, database.System, audit.Query{ActionPrefix: "user.delete"})
	if err != nil || len(entries) != 3 {
		t.Fatalf("delete audit: %v %d", err, len(entries))
	}
	for _, en := range entries {
		if en.Details["email"] == "tom.tech@acme.example" && (en.OrganizationID == nil || *en.OrganizationID != e.orgA) {
			t.Fatalf("delete audit not scoped to the organization: %+v", en)
		}
	}
}
