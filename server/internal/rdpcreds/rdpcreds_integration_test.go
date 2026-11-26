//go:build integration

package rdpcreds_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/rdpcreds"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

const testPassword = "T3st-only P@ss\"word\\ 1234"

type fx struct {
	t          *testing.T
	ctx        context.Context
	db         *database.DB
	super      string
	svc        *rdpcreds.Service
	sealer     *secrets.Sealer
	key        []byte
	acme, hq   uuid.UUID
	globex, gh uuid.UUID
	principals map[uuid.UUID]*rbac.Principal
}

func newFx(t *testing.T) *fx {
	t.Helper()
	inst := testdb.New(t)
	f := &fx{t: t, ctx: context.Background(), db: inst.DB, super: inst.SuperDSN, principals: map[uuid.UUID]*rbac.Principal{}}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	f.key = key
	var err error
	if f.sealer, err = secrets.NewSealer(secrets.Key{ID: "k1", Raw: key}); err != nil {
		t.Fatal(err)
	}
	f.svc = rdpcreds.New(f.db, audit.New(f.db, nil), f.sealer, func(_ context.Context, id uuid.UUID) (*rbac.Principal, error) {
		return f.principals[id], nil
	})
	f.acme = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.hq = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.acme)
	f.globex = f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	f.gh = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Plant') RETURNING id`, f.globex)
	return f
}

func (f *fx) id(sql string, args ...any) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&id) }); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fx) exec(sql string, args ...any) {
	f.t.Helper()
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { _, err := tx.Exec(f.ctx, sql, args...); return err }); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&n) }); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *fx) user(email string, as ...rbac.Assignment) (access.Caller, uuid.UUID) {
	f.t.Helper()
	id := f.id(`INSERT INTO users (email, display_name) VALUES ($1, $1) RETURNING id`, email)
	p, err := rbac.NewPrincipal(id, as)
	if err != nil {
		f.t.Fatal(err)
	}
	f.principals[id] = p
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: id, Label: email}), id
}

func (f *fx) device(org, site uuid.UUID, name, platform string) uuid.UUID {
	return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, mesh_node_id) VALUES ($1, $2, $3, $3, $4, $5) RETURNING id`,
		org, site, name, platform, "node//"+name)
}

// session is an EasyRMM session; stepped says how long ago it stepped up ("" for never).
func (f *fx) session(user uuid.UUID, stepped string) uuid.UUID {
	f.t.Helper()
	tok := make([]byte, 32)
	_, _ = rand.Read(tok)
	id := f.id(`INSERT INTO sessions (token_hash, user_id, state, idle_expires_at, expires_at) VALUES ($1, $2, 'active', now() + interval '1 hour', now() + interval '8 hours') RETURNING id`, tok, user)
	if stepped != "" {
		f.exec(`UPDATE sessions SET stepped_up_at = now() - $2::interval WHERE id = $1`, id, stepped)
	}
	return id
}

func (f *fx) actions(prefix string) []string {
	f.t.Helper()
	var out []string
	err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(f.ctx, `SELECT action || ':' || outcome FROM audit_log WHERE action LIKE $1 ORDER BY id`, prefix+"%")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a string
			if err := rows.Scan(&a); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

func save(pw string) rdpcreds.SaveInput {
	return rdpcreds.SaveInput{Label: "Server admin", Domain: "CORP", Username: "svc-admin", Password: []byte(pw)}
}

func TestSaveListReplaceDelete(t *testing.T) {
	f := newFx(t)
	ann, _ := f.user("ann@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	bob, _ := f.user("bob@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	dev := f.device(f.acme, f.hq, "srv1", "windows")

	cr, err := f.svc.Save(f.ctx, ann, dev, save(testPassword))
	if err != nil {
		t.Fatal(err)
	}
	if cr.Scope != "user" || cr.Username != "svc-admin" || cr.Domain != "CORP" {
		t.Errorf("saved: %+v", cr)
	}
	// Only the sealed form is stored.
	var sealed string
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT sealed_password FROM device_rdp_credentials WHERE id = $1`, cr.ID).Scan(&sealed)
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "T3st") || sealed == "" {
		t.Errorf("stored value: %q", sealed)
	}

	// The list shows the credential to its owner and to nobody else, and no
	// password in any form.
	list, err := f.svc.List(f.ctx, ann, dev)
	if err != nil || len(list) != 1 || list[0].ID != cr.ID {
		t.Fatalf("list: %+v %v", list, err)
	}
	body, _ := json.Marshal(list)
	if bytes.Contains(body, []byte("T3st")) || bytes.Contains(bytes.ToLower(body), []byte("password")) {
		t.Errorf("list body: %s", body)
	}
	if other, err := f.svc.List(f.ctx, bob, dev); err != nil || len(other) != 0 {
		t.Errorf("another person's list: %+v %v", other, err)
	}
	// Another person cannot delete it either.
	if err := f.svc.Delete(f.ctx, bob, dev, cr.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("delete by another person: %v", err)
	}

	// Saving again replaces it, keeping the id, and a bad password is refused.
	again, err := f.svc.Save(f.ctx, ann, dev, rdpcreds.SaveInput{Label: "New", Username: "other", Password: []byte("second-pass")})
	if err != nil || again.ID != cr.ID || again.Username != "other" {
		t.Fatalf("replace: %+v %v", again, err)
	}
	if got := f.count(`SELECT count(*) FROM device_rdp_credentials`); got != 1 {
		t.Errorf("%d rows after a replacement", got)
	}
	if f.count(`SELECT count(*) FROM device_rdp_credentials WHERE rotated_at IS NOT NULL`) != 1 {
		t.Error("rotated_at not set")
	}
	for name, in := range map[string]rdpcreds.SaveInput{
		"no password":  {Username: "u"},
		"no user":      {Password: []byte("x")},
		"nul in pass":  {Username: "u", Password: []byte("a\x00b")},
		"not UTF-8":    {Username: "u", Password: []byte{0xff, 0xfe}},
		"long label":   {Username: "u", Password: []byte("x"), Label: strings.Repeat("l", 101)},
		"long pass":    {Username: "u", Password: bytes.Repeat([]byte("p"), 1025)},
		"long user":    {Username: strings.Repeat("u", 256), Password: []byte("x")},
		"long domain":  {Username: "u", Password: []byte("x"), Domain: strings.Repeat("d", 256)},
		"empty record": {},
	} {
		if _, err := f.svc.Save(f.ctx, ann, dev, in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	if err := f.svc.Delete(f.ctx, ann, dev, cr.ID); err != nil {
		t.Fatal(err)
	}
	if f.count(`SELECT count(*) FROM device_rdp_credentials`) != 0 {
		t.Error("row left after delete")
	}

	// Audit rows: created, replaced, deleted, with the password nowhere.
	got := strings.Join(f.actions("rdp_credential."), " ")
	if got != "rdp_credential.created:success rdp_credential.replaced:success rdp_credential.deleted:success" {
		t.Errorf("audit: %s", got)
	}
	var details string
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT string_agg(details::text, ' ') FROM audit_log`).Scan(&details)
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(details, "T3st") || strings.Contains(details, "second-pass") || strings.Contains(details, "sealed") {
		t.Error("a password or sealed value reached the audit log")
	}
	if !strings.Contains(details, "svc-admin") {
		t.Error("audit rows do not name the account")
	}
}

func TestSavePermissions(t *testing.T) {
	f := newFx(t)
	win := f.device(f.acme, f.hq, "win1", "windows")
	lin := f.device(f.acme, f.hq, "lin1", "linux")
	acmeTech, _ := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	siteTech, _ := f.user("site@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	readOnly, _ := f.user("ro@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	globexTech, _ := f.user("gx@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.globex})
	super, _ := f.user("root@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})

	for name, c := range map[string]access.Caller{"organization technician": acmeTech, "site technician": siteTech, "super administrator": super} {
		if _, err := f.svc.Save(f.ctx, c, win, save("pw-"+name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := f.svc.Save(f.ctx, readOnly, win, save("x")); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("read-only: %v", err)
	}
	if _, err := f.svc.Save(f.ctx, globexTech, win, save("x")); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("another organization: %v", err)
	}
	if _, err := f.svc.Save(f.ctx, acmeTech, lin, save("x")); err == nil {
		t.Error("a Linux device took a credential")
	}
	if _, err := f.svc.Save(f.ctx, access.System("x"), win, save("x")); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("a caller with no person: %v", err)
	}
	if list, _ := f.svc.List(f.ctx, readOnly, win); len(list) != 0 {
		t.Error("read-only saw credentials")
	}
	// The three saves were each the person's own.
	if n := f.count(`SELECT count(DISTINCT user_id) FROM device_rdp_credentials WHERE device_id = $1`, win); n != 3 {
		t.Errorf("%d people with a credential", n)
	}

	// Outside the dev scope nothing is saved or offered.
	restore := devscope.Set(f.globex)
	defer restore()
	if _, err := f.svc.Save(f.ctx, acmeTech, win, save("x")); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("outside the dev scope: %v", err)
	}
	if list, _ := f.svc.List(f.ctx, acmeTech, win); len(list) != 0 {
		t.Error("credentials listed outside the dev scope")
	}
}

func TestRowLevelSecurity(t *testing.T) {
	f := newFx(t)
	ann, _ := f.user("ann@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	dev := f.device(f.acme, f.hq, "srv1", "windows")
	if _, err := f.svc.Save(f.ctx, ann, dev, save("x")); err != nil {
		t.Fatal(err)
	}
	count := func(s database.Scope) int {
		var n int
		if err := f.db.ReadTx(f.ctx, s, func(tx pgx.Tx) error {
			return tx.QueryRow(f.ctx, `SELECT count(*) FROM device_rdp_credentials`).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(database.Scope{Orgs: []uuid.UUID{f.acme}}); n != 1 {
		t.Errorf("own organization sees %d", n)
	}
	if n := count(database.Scope{Orgs: []uuid.UUID{f.globex}}); n != 0 {
		t.Errorf("another organization sees %d", n)
	}
	if n := count(database.Scope{}); n != 0 {
		t.Errorf("an empty scope sees %d", n)
	}
	// And cannot write into a row of another organization.
	err := f.db.InTx(f.ctx, database.Scope{Orgs: []uuid.UUID{f.globex}}, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `INSERT INTO device_rdp_credentials (device_id, organization_id, scope, user_id, label, username, sealed_password)
			VALUES ($1, $2, 'user', $3, 'l', 'u', 's')`, dev, f.acme, uuid.New())
		return err
	})
	if err == nil {
		t.Error("a scope wrote another organization's row")
	}
}

func use(f *fx, cred, device, user, session uuid.UUID, org, site uuid.UUID) rdpcreds.Use {
	return rdpcreds.Use{CredentialID: cred, Session: session, Grant: uuid.New(), User: user, Organization: org, Site: site, Device: device, ClientIP: "192.0.2.5"}
}

func TestOpenForSession(t *testing.T) {
	f := newFx(t)
	ann, annID := f.user("ann@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	_, bobID := f.user("bob@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	dev := f.device(f.acme, f.hq, "srv1", "windows")
	other := f.device(f.acme, f.hq, "srv2", "windows")
	cr, err := f.svc.Save(f.ctx, ann, dev, save(testPassword))
	if err != nil {
		t.Fatal(err)
	}
	denied := func(name string, u rdpcreds.Use) {
		t.Helper()
		o, err := f.svc.OpenForSession(f.ctx, u)
		if !errors.Is(err, rdpcreds.ErrRefused) || o != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	usable := func(session uuid.UUID) rdpcreds.Use { return use(f, cr.ID, dev, annID, session, f.acme, f.hq) }

	// Step-up: none, too old, then fresh.
	denied("no step-up", usable(f.session(annID, "")))
	denied("step-up 6 minutes old", usable(f.session(annID, "6 minutes")))
	fresh := f.session(annID, "10 seconds")
	o, err := f.svc.OpenForSession(f.ctx, usable(fresh))
	if err != nil {
		t.Fatal(err)
	}
	if string(o.Password) != testPassword || o.Username != "svc-admin" || o.Domain != "CORP" {
		t.Errorf("opened: %q %q %q", o.Username, o.Domain, o.Password)
	}
	// A second use in the same session within the window does not ask again.
	if o2, err := f.svc.OpenForSession(f.ctx, usable(fresh)); err != nil || string(o2.Password) != testPassword {
		t.Errorf("second use: %v", err)
	}
	if f.count(`SELECT count(*) FROM device_rdp_credentials WHERE last_used_at IS NOT NULL`) != 1 {
		t.Error("last_used_at not set")
	}

	// Another person's session, a session that is not the person's, another
	// device, an unknown id.
	denied("another person", use(f, cr.ID, dev, bobID, f.session(bobID, "10 seconds"), f.acme, f.hq))
	denied("a session of another person", use(f, cr.ID, dev, annID, f.session(bobID, "10 seconds"), f.acme, f.hq))
	denied("another device", use(f, cr.ID, other, annID, fresh, f.acme, f.hq))
	denied("another organization", use(f, cr.ID, dev, annID, fresh, f.globex, f.gh))
	denied("unknown credential", use(f, uuid.New(), dev, annID, fresh, f.acme, f.hq))

	// Permission removed, person deactivated, outside the dev scope.
	saved := f.principals[annID]
	f.principals[annID], _ = rbac.NewPrincipal(annID, []rbac.Assignment{{Role: rbac.RoleReadOnly, OrganizationID: f.acme}})
	denied("permission removed", usable(fresh))
	f.principals[annID] = saved
	f.exec(`UPDATE users SET status = 'disabled' WHERE id = $1`, annID)
	denied("person disabled", usable(fresh))
	f.exec(`UPDATE users SET status = 'active' WHERE id = $1`, annID)
	restore := devscope.Set(f.globex)
	denied("outside the dev scope", usable(fresh))
	restore()
	if _, err := f.svc.OpenForSession(f.ctx, usable(fresh)); err != nil {
		t.Errorf("after the refusals: %v", err)
	}

	// A sealed value copied to another row, device or person does not open.
	cr2, err := f.svc.Save(f.ctx, access.User(f.principals[bobID], database.Scope{All: true}, audit.Actor{Type: audit.ActorUser, ID: bobID}), other, save("bobs"))
	if err != nil {
		t.Fatal(err)
	}
	f.exec(`UPDATE device_rdp_credentials SET sealed_password = (SELECT sealed_password FROM device_rdp_credentials WHERE id = $1) WHERE id = $2`, cr.ID, cr2.ID)
	denied("sealed value moved to another row", use(f, cr2.ID, other, bobID, f.session(bobID, "10 seconds"), f.acme, f.hq))
	f.exec(`UPDATE device_rdp_credentials SET sealed_password = 'garbage' WHERE id = $1`, cr2.ID)
	denied("garbage", use(f, cr2.ID, other, bobID, f.session(bobID, "10 seconds"), f.acme, f.hq))

	// Shared (device-scope) rows are not enabled.
	f.exec(`DELETE FROM device_rdp_credentials WHERE id = $1`, cr2.ID)
	shared := f.id(`INSERT INTO device_rdp_credentials (device_id, organization_id, scope, label, username, sealed_password) VALUES ($1, $2, 'device', 'l', 'u', 's') RETURNING id`, dev, f.acme)
	denied("shared level", use(f, shared, dev, annID, fresh, f.acme, f.hq))

	// Audit: a use row per use, a denial row per refusal, with the reasons.
	acts := f.actions("rdp_credential.use")
	used, denials := 0, 0
	for _, a := range acts {
		switch a {
		case "rdp_credential.used:success":
			used++
		case "rdp_credential.use_denied:denied":
			denials++
		}
	}
	if used != 3 || denials != 13 {
		t.Errorf("audit: %d uses, %d denials (%v)", used, denials, acts)
	}
	var reasons string
	_ = f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT string_agg(details->>'reason', '|') FROM audit_log WHERE action = 'rdp_credential.use_denied'`).Scan(&reasons)
	})
	for _, want := range []string{"step-up is required", "credential is for another device", "credential belongs to another person", "person is not active", "organization is outside the dev scope", "person no longer holds remote desktop"} {
		if !strings.Contains(reasons, want) {
			t.Errorf("no denial for %q", want)
		}
	}
	var all string
	_ = f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT string_agg(details::text, ' ') FROM audit_log`).Scan(&all)
	})
	if strings.Contains(all, "T3st") || strings.Contains(all, "bobs") {
		t.Error("a password reached the audit log")
	}
}

func TestCascadesAndPurge(t *testing.T) {
	f := newFx(t)
	ann, annID := f.user("ann@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	d1 := f.device(f.acme, f.hq, "srv1", "windows")
	d2 := f.device(f.acme, f.hq, "srv2", "windows")
	d3 := f.device(f.acme, f.hq, "srv3", "windows")
	for _, d := range []uuid.UUID{d1, d2, d3} {
		if _, err := f.svc.Save(f.ctx, ann, d, save("x")); err != nil {
			t.Fatal(err)
		}
	}
	// A device's removal takes its credentials.
	f.exec(`DELETE FROM devices WHERE id = $1`, d1)
	if f.count(`SELECT count(*) FROM device_rdp_credentials`) != 2 {
		t.Error("credentials of a deleted device remain")
	}
	// A move between organizations purges them, each with an audit row.
	err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return rdpcreds.PurgeDevice(f.ctx, tx, audit.New(f.db, nil), audit.SystemActor("test"), d2, f.acme, f.hq, "srv2", "moved")
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.count(`SELECT count(*) FROM device_rdp_credentials WHERE device_id = $1`, d2) != 0 || f.count(`SELECT count(*) FROM device_rdp_credentials`) != 1 {
		t.Error("purge removed the wrong rows")
	}
	if got := f.actions("rdp_credential.purged"); len(got) != 1 {
		t.Errorf("purge audit: %v", got)
	}
	// A person's removal takes theirs.
	f.exec(`DELETE FROM users WHERE id = $1`, annID)
	if f.count(`SELECT count(*) FROM device_rdp_credentials`) != 0 {
		t.Error("credentials of a deleted person remain")
	}
	// An organization's removal takes its credentials' rows with it.
	bob, _ := f.user("bob@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.globex})
	gd := f.device(f.globex, f.gh, "g1", "windows")
	if _, err := f.svc.Save(f.ctx, bob, gd, save("x")); err != nil {
		t.Fatal(err)
	}
	f.exec(`DELETE FROM devices WHERE organization_id = $1`, f.globex)
	f.exec(`DELETE FROM sites WHERE organization_id = $1`, f.globex)
	f.exec(`DELETE FROM organizations WHERE id = $1`, f.globex)
	if f.count(`SELECT count(*) FROM device_rdp_credentials`) != 0 {
		t.Error("credentials of a deleted organization remain")
	}
}

// Credentials sealed under an older key still open after a rotation.
func TestOpensAfterKeyRotation(t *testing.T) {
	f := newFx(t)
	ann, annID := f.user("ann@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	dev := f.device(f.acme, f.hq, "srv1", "windows")
	cr, err := f.svc.Save(f.ctx, ann, dev, save(testPassword))
	if err != nil {
		t.Fatal(err)
	}
	key2 := make([]byte, 32)
	_, _ = rand.Read(key2)
	rotated, err := secrets.NewSealer(secrets.Key{ID: "k2", Raw: key2}, secrets.Key{ID: "k1", Raw: f.key})
	if err != nil {
		t.Fatal(err)
	}
	svc := rdpcreds.New(f.db, audit.New(f.db, nil), rotated, func(context.Context, uuid.UUID) (*rbac.Principal, error) { return f.principals[annID], nil })
	o, err := svc.OpenForSession(f.ctx, use(f, cr.ID, dev, annID, f.session(annID, "1 second"), f.acme, f.hq))
	if err != nil || string(o.Password) != testPassword {
		t.Errorf("after rotation: %v", err)
	}
}
