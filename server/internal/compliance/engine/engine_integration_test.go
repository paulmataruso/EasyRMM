//go:build integration

package engine_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/compliance"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/content"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/engine"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/packs"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/rollup"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

type fixture struct {
	t      *testing.T
	ctx    context.Context
	db     *database.DB
	jobs   *jobs.Service
	svc    *engine.Service
	acme   uuid.UUID
	globex uuid.UUID
	hq     uuid.UUID
	plant  uuid.UUID
	super  string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	inst := testdb.New(t)
	f := &fixture{t: t, ctx: context.Background(), db: inst.DB, super: inst.SuperDSN}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	al := audit.New(inst.DB, time.Now)
	f.jobs = jobs.New(inst.DB, al, priv, 90*24*time.Hour, 30*24*time.Hour, log)
	f.svc = engine.New(inst.DB, f.jobs, al, log)
	f.acme = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.hq = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.acme)
	f.globex = f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	f.plant = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Plant') RETURNING id`, f.globex)
	return f
}

func (f *fixture) loaded() *fixture {
	f.t.Helper()
	if err := f.svc.LoadContent(f.ctx, content.FS, compliance.EditionDev); err != nil {
		f.t.Fatal(err)
	}
	return f
}

func (f *fixture) id(sql string, args ...any) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&id) }); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fixture) exec(sql string, args ...any) {
	f.t.Helper()
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { _, err := tx.Exec(f.ctx, sql, args...); return err }); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) n(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&n) }); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *fixture) str(sql string, args ...any) string {
	f.t.Helper()
	var s string
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&s) }); err != nil {
		f.t.Fatal(err)
	}
	return s
}

func (f *fixture) user(email string, as ...rbac.Assignment) access.Caller {
	f.t.Helper()
	id := f.id(`INSERT INTO users (email, display_name) VALUES ($1, $1) RETURNING id`, email)
	for _, a := range as {
		var org, site *uuid.UUID
		if a.OrganizationID != uuid.Nil {
			org = &a.OrganizationID
		}
		if a.SiteID != uuid.Nil {
			site = &a.SiteID
		}
		f.exec(`INSERT INTO role_assignments (user_id, role, organization_id, site_id) VALUES ($1, $2, $3, $4)`, id, string(a.Role), org, site)
	}
	p, err := rbac.NewPrincipal(id, as)
	if err != nil {
		f.t.Fatal(err)
	}
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: id, Label: email})
}

func (f *fixture) device(org, site uuid.UUID, name, platform string) uuid.UUID {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at)
		VALUES ($1, $2, $3, $3, $4, $5, now(), now()) RETURNING id`, org, site, name, platform, key)
}

// store keeps a module's check result, as the hardening job's result ingester does.
func (f *fixture) store(device uuid.UUID, module, state, detail string) {
	f.exec(`INSERT INTO device_hardening (device_id, module, state, detail, checked_at) VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (device_id, module) DO UPDATE SET state = EXCLUDED.state, detail = EXCLUDED.detail, checked_at = EXCLUDED.checked_at`,
		device, module, state, detail)
}

func (f *fixture) results(scan uuid.UUID, device uuid.UUID) map[string]string {
	f.t.Helper()
	m := map[string]string{}
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(f.ctx, `SELECT control_id, state FROM compliance_results_history WHERE scan_id = $1 AND device_id = $2`, scan, device)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c, s string
			if err := rows.Scan(&c, &s); err != nil {
				return err
			}
			m[c] = s
		}
		return rows.Err()
	}); err != nil {
		f.t.Fatal(err)
	}
	return m
}

func fatal(t *testing.T, err error) {
	t.Helper()
	if e, ok := apperr.As(err); ok && len(e.Fields) > 0 {
		t.Fatalf("%v %v", err, e.Fields)
	}
	t.Fatal(err)
}

func wantErrCode(t *testing.T, err error, code string) {
	t.Helper()
	if e, ok := apperr.As(err); !ok || e.Code != code {
		t.Fatalf("want error %s, got %v", code, err)
	}
}

func orgAdmin(f *fixture, email string, org uuid.UUID) access.Caller {
	return f.user(email, rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: org})
}

// ---- the loader -------------------------------------------------------------------------------

func TestLoadContentStoresTheLibraryAndPacks(t *testing.T) {
	f := newFixture(t)
	if err := f.svc.LoadContent(f.ctx, content.FS, compliance.EditionDev); err != nil {
		t.Fatal(err)
	}
	for _, s := range f.svc.LoadReport() {
		if s.State != packs.StateLoaded {
			t.Errorf("%+v", s)
		}
	}
	for q, want := range map[string]int{
		`SELECT count(*) FROM compliance_controls`:                                            281,
		`SELECT count(*) FROM compliance_controls WHERE apply_supported`:                      -1,
		`SELECT count(*) FROM compliance_frameworks`:                                          13,
		`SELECT count(*) FROM compliance_requirements WHERE framework_key = 'nist-800-171r2'`: 110,
		`SELECT count(*) FROM compliance_requirements WHERE framework_key = 'cmmc-l1'`:        17,
		`SELECT count(*) FROM compliance_profiles`:                                            6,
		`SELECT count(*) FROM compliance_sources`:                                             11,
	} {
		if got := f.n(q); want >= 0 && got != want {
			t.Errorf("%s: %d, want %d", q, got, want)
		}
	}
	if f.n(`SELECT count(*) FROM compliance_mappings`) < 1000 {
		t.Error("the mappings were not stored")
	}
	// Loading again changes nothing.
	if err := f.svc.LoadContent(f.ctx, content.FS, compliance.EditionDev); err != nil {
		t.Fatal(err)
	}
	for _, s := range f.svc.LoadReport() {
		if s.State != packs.StateUnchanged {
			t.Errorf("second load: %+v", s)
		}
	}
	// A control keeps its meaning under its version: a changed definition that keeps the version is refused.
	m := fstest.MapFS{}
	_ = fs.WalkDir(content.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := fs.ReadFile(content.FS, p)
			m[p] = &fstest.MapFile{Data: b}
		}
		return nil
	})
	m["controls/linux.json"].Data = []byte(strings.Replace(string(m["controls/linux.json"].Data), "X11 forwarding off", "X11 forwarding is off", 1))
	mf, notice, _ := content.Update(m)
	m["manifest.json"].Data, m["NOTICE.generated"].Data = mf, notice
	err := f.svc.LoadContent(f.ctx, m, compliance.EditionDev)
	if err == nil || !strings.Contains(err.Error(), "changed without a version bump") {
		t.Errorf("a changed control kept its version: %v", err)
	}
	if got := f.str(`SELECT title FROM compliance_controls WHERE id = 'linux.ssh.x11-forwarding'`); got != "X11 forwarding off" {
		t.Errorf("title is now %q", got)
	}
}

func TestCommercialLoadRefusesRestrictedAndReviewNeeded(t *testing.T) {
	f := newFixture(t)
	m := fstest.MapFS{}
	_ = fs.WalkDir(content.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := fs.ReadFile(content.FS, p)
			m[p] = &fstest.MapFile{Data: b}
		}
		return nil
	})
	body := `{"pack":{"key":"fixture-restricted","version":"1","kind":"framework","title":"A fixture","licence_class":"RESTRICTED","source_id":"nist-csf-2","review_state":"none"},` +
		`"framework":{"key":"fixture-restricted","version":"1","title":"t","publisher":"p","source_id":"nist-csf-2","text_policy":"ids_only"},"requirements":[]}`
	m["packs/fixture-restricted.json"] = &fstest.MapFile{Data: []byte(body)}
	mf, notice, _ := content.Update(m)
	m["manifest.json"].Data, m["NOTICE.generated"].Data = mf, notice
	// A commercial build must carry a signed manifest.
	if err := f.svc.LoadContent(f.ctx, m, compliance.EditionCommercial); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("an unsigned manifest in a commercial build: %v", err)
	}
	// Dev carries the restricted fixture; commercial refuses it, along with the two packs waiting for review.
	if err := f.svc.LoadContent(f.ctx, m, compliance.EditionDev); err != nil {
		t.Fatal(err)
	}
	if f.n(`SELECT count(*) FROM compliance_packs WHERE key = 'fixture-restricted'`) != 1 {
		t.Fatal("dev did not load it")
	}
	g := newFixture(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m["manifest.sig"] = &fstest.MapFile{Data: []byte(hexOf(ed25519.Sign(priv, m["manifest.json"].Data)))}
	old := content.ReleasePublicKey
	content.ReleasePublicKey = hexOf(pub)
	t.Cleanup(func() { content.ReleasePublicKey = old })
	if err := g.svc.LoadContent(g.ctx, m, compliance.EditionCommercial); err != nil {
		t.Fatal(err)
	}
	refused := map[string]string{}
	for _, s := range g.svc.LoadReport() {
		if s.State == packs.StateRefused {
			refused[s.Key] = s.Reason
		}
	}
	if len(refused) != 3 || !strings.Contains(refused["fixture-restricted"], "RESTRICTED is not allowed in a commercial build") ||
		!strings.Contains(refused["cis-xref"], "review is still needed") || !strings.Contains(refused["gdpr-indicative"], "review is still needed") {
		t.Errorf("refused: %v", refused)
	}
	for _, key := range []string{"fixture-restricted", "cis-xref", "gdpr-indicative"} {
		if g.n(`SELECT count(*) FROM compliance_packs WHERE key = $1`, key) != 0 || g.n(`SELECT count(*) FROM compliance_frameworks WHERE key = $1`, key) != 0 {
			t.Errorf("%s reached the database of a commercial build", key)
		}
	}
	if g.n(`SELECT count(*) FROM compliance_packs WHERE licence_class IN ('NONCOMMERCIAL', 'COMMERCIAL_LICENSE_REQUIRED', 'RESTRICTED')`) != 0 ||
		g.n(`SELECT count(*) FROM compliance_mappings WHERE licence_class IN ('NONCOMMERCIAL', 'COMMERCIAL_LICENSE_REQUIRED', 'RESTRICTED')`) != 0 ||
		g.n(`SELECT count(*) FROM compliance_controls WHERE licence_class IN ('NONCOMMERCIAL', 'COMMERCIAL_LICENSE_REQUIRED', 'RESTRICTED')`) != 0 ||
		g.n(`SELECT count(*) FROM compliance_packs WHERE review_state = 'needed'`) != 0 {
		t.Error("a commercial database holds restricted content")
	}
	if g.n(`SELECT count(*) FROM compliance_frameworks`) != 11 {
		t.Errorf("%d frameworks in the commercial database", g.n(`SELECT count(*) FROM compliance_frameworks`))
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

// ---- row-level security and immutability ----------------------------------------------------

func TestSecurityOfTheTables(t *testing.T) {
	f := newFixture(t).loaded()
	win := f.device(f.acme, f.hq, "A-WIN", "windows")
	other := f.device(f.globex, f.plant, "G-LNX", "linux")
	scanA := f.id(`INSERT INTO compliance_scans (organization_id, trigger, selection, state) VALUES ($1, 'manual', '{}', 'done') RETURNING id`, f.acme)
	scanG := f.id(`INSERT INTO compliance_scans (organization_id, trigger, selection, state) VALUES ($1, 'manual', '{}', 'done') RETURNING id`, f.globex)
	f.exec(`INSERT INTO compliance_results_history (organization_id, scan_id, device_id, control_id, control_version, state, checked_at)
		VALUES ($1, $2, $3, 'win.accounts.history', 1, 'in_place', now())`, f.acme, scanA, win)
	f.exec(`INSERT INTO compliance_results_history (organization_id, scan_id, device_id, control_id, control_version, state, checked_at)
		VALUES ($1, $2, $3, 'linux.ssh.x11-forwarding', 1, 'not_in_place', now())`, f.globex, scanG, other)

	acme := database.Scope{Orgs: []uuid.UUID{f.acme}}
	count := func(sc database.Scope, q string) int {
		t.Helper()
		var n int
		if err := f.db.ReadTx(f.ctx, sc, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, q).Scan(&n) }); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// An organization reads its own results and scans, and not another's; the library is global.
	for _, q := range []string{`SELECT count(*) FROM compliance_results_history`, `SELECT count(*) FROM compliance_scans`, `SELECT count(*) FROM compliance_results`} {
		if got := count(acme, q); got != 1 {
			t.Errorf("%s as acme: %d, want 1", q, got)
		}
		if got := count(database.Scope{}, q); got != 0 {
			t.Errorf("%s with no scope: %d, want 0", q, got)
		}
		if got := count(database.System, q); got != 2 {
			t.Errorf("%s as system: %d, want 2", q, got)
		}
	}
	if count(acme, `SELECT count(*) FROM compliance_controls`) != 281 || count(database.Scope{}, `SELECT count(*) FROM compliance_mappings`) < 1000 {
		t.Error("the library is not readable by every scope")
	}
	// The library is read-only to a user's scope; a user's scope writes nothing at all.
	for _, q := range []string{
		`UPDATE compliance_controls SET title = 'x'`,
		`DELETE FROM compliance_controls`,
		`INSERT INTO compliance_sources (id, title, publisher, url, licence_class, licence_note, retrieved_at) VALUES ('rogue', 't', 'p', 'u', 'ORIGINAL', 'n', now())`,
		`UPDATE compliance_packs SET enabled = false`,
		`DELETE FROM compliance_mappings`,
		`UPDATE compliance_scans SET state = 'failed'`,
	} {
		err := f.db.InTx(f.ctx, acme, func(tx pgx.Tx) error {
			tag, err := tx.Exec(f.ctx, q)
			if err == nil && tag.RowsAffected() > 0 {
				t.Errorf("%s changed %d rows as an organization's scope", q, tag.RowsAffected())
			}
			return err
		})
		if err != nil && !database.IsRLSViolation(err) {
			t.Errorf("%s: %v", q, err)
		}
	}
	if err := f.db.InTx(f.ctx, acme, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `INSERT INTO compliance_scans (organization_id, trigger, selection, state) VALUES ($1, 'manual', '{}', 'done')`, f.acme)
		return err
	}); !database.IsRLSViolation(err) {
		t.Errorf("an organization's scope wrote a scan: %v", err)
	}
	// History is never changed, and a direct delete is refused.
	for _, q := range []string{`UPDATE compliance_results_history SET state = 'in_place'`, `DELETE FROM compliance_results_history`} {
		err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { _, err := tx.Exec(f.ctx, q); return err })
		if err == nil || !strings.Contains(err.Error(), "never changed") {
			t.Errorf("%s: %v", q, err)
		}
	}
	// A child cannot name another organization's scan.
	err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `INSERT INTO compliance_results_history (organization_id, scan_id, device_id, control_id, control_version, state, checked_at)
			VALUES ($1, $2, $3, 'win.accounts.guest', 1, 'in_place', now())`, f.globex, scanA, win)
		return err
	})
	if !database.IsForeignKeyViolation(err) {
		t.Errorf("a result of another organization's scan: %v", err)
	}
	err = f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `INSERT INTO compliance_scan_jobs (organization_id, scan_id, device_id) VALUES ($1, $2, $3)`, f.globex, scanA, win)
		return err
	})
	if !database.IsForeignKeyViolation(err) {
		t.Errorf("a scan job of another organization's scan: %v", err)
	}
	// What follows from deleting a parent goes: the history is removed with its scan.
	f.exec(`DELETE FROM compliance_scans WHERE id = $1`, scanG)
	if f.n(`SELECT count(*) FROM compliance_results_history`) != 1 {
		t.Error("the history of a deleted scan stayed")
	}
	// The retention purge says so.
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(f.ctx, `SELECT set_config('easyrmm.compliance_purge', 'on', true)`); err != nil {
			return err
		}
		_, err := tx.Exec(f.ctx, `DELETE FROM compliance_results_history`)
		return err
	}); err != nil || f.n(`SELECT count(*) FROM compliance_results_history`) != 0 {
		t.Errorf("the purge: %v", err)
	}
	// A control and a text-policy trigger: full text only where the framework carries it.
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `UPDATE compliance_requirements SET text_full = 'x' WHERE framework_key = 'hipaa-security'`)
		return err
	}); err == nil || !strings.Contains(err.Error(), "does not carry full text") {
		t.Errorf("full text in an ids-only framework: %v", err)
	}
}

// ---- scans: stored results ----------------------------------------------------------------

const sshStored = `{"settings":[
	{"id":"ssh-permit-root-login","state":"in_place","value":"no","want":"no"},
	{"id":"ssh-permit-empty-passwords","state":"not_in_place","value":"yes","want":"no"},
	{"id":"ssh-x11-forwarding","state":"in_place"}]}`

func TestScanOfStoredResults(t *testing.T) {
	f := newFixture(t).loaded()
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	ro := f.user("ro@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	lnx := f.device(f.acme, f.hq, "A-LNX", "linux")
	lnx2 := f.device(f.acme, f.hq, "A-LNX2", "linux")
	f.store(lnx, "ssh", "partly", sshStored)
	f.store(lnx2, "ssh", "in_place", `{"missing":[]}`) // stored before slice C0: no settings
	f.store(lnx, "kernel", "not_applicable", `{"reason":"a container"}`)

	// The role decides who may scan: read-only holds nothing; the technician does.
	if _, err := f.svc.StartScan(f.ctx, ro, f.acme, engine.ScanInput{Profile: "linux-server-baseline"}); !isNotFound(err) {
		t.Errorf("read-only started a scan: %v", err)
	}
	if _, err := f.svc.Packs(f.ctx, ro, f.acme); !isNotFound(err) {
		t.Errorf("read-only read the packs: %v", err)
	}
	if _, err := f.svc.StartScan(f.ctx, tech, f.acme, engine.ScanInput{Profile: "no-such"}); err == nil {
		t.Error("an unknown profile")
	}
	if _, err := f.svc.StartScan(f.ctx, tech, f.acme, engine.ScanInput{Profile: "linux-server-baseline", DeviceIDs: []uuid.UUID{uuid.New()}}); err == nil {
		t.Error("an unknown device")
	}
	if _, err := f.svc.StartScan(f.ctx, tech, f.acme, engine.ScanInput{Profile: "win-server-baseline"}); err == nil {
		t.Error("a Windows profile for an organization with no Windows computer is not a scan of anything... but the Linux computers are not asked")
	}

	sc, err := f.svc.StartScan(f.ctx, tech, f.acme, engine.ScanInput{Profile: "linux-server-baseline", DeviceIDs: []uuid.UUID{lnx, lnx2}})
	if err != nil {
		t.Fatal(err)
	}
	if sc.State != "done" || sc.ResultHash == nil || sc.Waiting != 0 || sc.FinishedAt == nil {
		t.Fatalf("%+v", sc)
	}
	if f.n(`SELECT count(*) FROM jobs`) != 0 {
		t.Error("a scan of stored results made a job")
	}
	got := f.results(sc.ID, lnx)
	if got["linux.ssh.permit-root-login"] != "in_place" || got["linux.ssh.permit-empty-passwords"] != "not_in_place" || got["linux.ssh.x11-forwarding"] != "in_place" {
		t.Errorf("ssh results: %v", got)
	}
	if got["linux.ssh.ciphers"] != "unknown" || got["linux.fail2ban.enabled"] != "unknown" {
		t.Errorf("settings the check did not report must be unknown: %v", got)
	}
	if got["linux.kernel.kernel-dmesg-restrict"] != "not_applicable" {
		t.Errorf("a module that did not apply: %v", got["linux.kernel.kernel-dmesg-restrict"])
	}
	for id, st := range f.results(sc.ID, lnx2) {
		if st != "unknown" {
			t.Errorf("%s on the computer with no per-setting result: %s", id, st)
		}
	}
	if n := f.n(`SELECT count(*) FROM compliance_results_history WHERE scan_id = $1`, sc.ID); n != 2*109 {
		t.Errorf("%d results, want one per device and control", n)
	}
	if f.n(`SELECT count(*) FROM audit_log WHERE action = 'compliance.scan_start' AND organization_id = $1`, f.acme) != 1 {
		t.Error("the scan is not in the audit log")
	}

	// What the device and the framework show.
	dr, err := f.svc.DeviceResults(f.ctx, tech, lnx)
	if err != nil || len(dr) != 109 {
		t.Fatalf("%d results, %v", len(dr), err)
	}
	words := map[string]string{}
	for _, r := range dr {
		words[r.ControlID] = r.Word
	}
	if words["linux.ssh.permit-root-login"] != compliance.WordMeets || words["linux.ssh.permit-empty-passwords"] != compliance.WordDoesNotMeet || words["linux.ssh.ciphers"] != compliance.WordCannotTell {
		t.Errorf("wording %v", words)
	}
	if _, err := f.svc.DeviceResults(f.ctx, f.user("other@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.globex}), lnx); !isNotFound(err) {
		t.Errorf("another organization read a device's results: %v", err)
	}
	if _, err := f.svc.Scan(f.ctx, f.user("other2@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.globex}), f.acme, sc.ID); !isNotFound(err) {
		t.Errorf("another organization read a scan: %v", err)
	}

	fw, err := f.svc.Framework(f.ctx, tech, f.acme, "nist-800-171r2")
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]rollup.Status{}
	for _, o := range fw.Outcomes {
		status[o.ReqID] = o.Status
	}
	// 3.4.7: services and features are off or not tested on Linux; 3.1.8 has only Windows controls: not assessed.
	if status["3.1.8"] != rollup.NotAssessed || status["3.4.7"] != rollup.NotAssessed || status["3.1.1"] != rollup.NotAssessed || status["3.2.1"] != rollup.NotAssessed {
		t.Errorf("statuses %v", status)
	}
	for id, st := range status {
		if st == rollup.Meets && fw.Coverage.Total == 0 {
			t.Errorf("%s met with no coverage", id)
		}
	}
	if fw.InScope != 2 || fw.ScanID == nil || *fw.ScanID != sc.ID || fw.Disclaimer != compliance.Disclaimer || fw.Coverage.Total != 110 {
		t.Errorf("%+v", fw)
	}
	raw, _ := json.Marshal(fw)
	for _, banned := range []string{"ompliant", "audit-ready", "certified"} {
		if strings.Contains(string(raw), banned) {
			t.Errorf("the roll-up says %q", banned)
		}
	}

	// Stale results never pass: the freshness window ages them.
	f.svc.SetClock(func() time.Time { return time.Now().Add(40 * 24 * time.Hour) })
	dr, _ = f.svc.DeviceResults(f.ctx, tech, lnx)
	for _, r := range dr {
		if r.State != compliance.StateStale || r.Word != compliance.WordCannotTell {
			t.Fatalf("%s is %s after 40 days", r.ControlID, r.State)
		}
	}
}

func isNotFound(err error) bool { return err != nil && apperr.ErrNotFound.Is(err) }

// The roll-up with Windows results: one failing in-scope computer fails the requirement; one out of scope does not.
func TestFrameworkRollUpFromScans(t *testing.T) {
	f := newFixture(t).loaded()
	admin := orgAdmin(f, "admin@example.com", f.acme)
	w1 := f.device(f.acme, f.hq, "W1", "windows")
	w2 := f.device(f.acme, f.hq, "W2", "windows")
	acct := func(history string) string {
		return `{"settings":[{"id":"accounts-history","state":"` + history + `"},{"id":"accounts-complexity","state":"in_place"},{"id":"accounts-min-length","state":"in_place"}]}`
	}
	f.store(w1, "accounts", "in_place", acct("in_place"))
	f.store(w2, "accounts", "partly", acct("not_in_place"))
	sc, err := f.svc.StartScan(f.ctx, admin, f.acme, engine.ScanInput{Profile: "nist-800-171-assessment", DeviceIDs: []uuid.UUID{w1, w2}})
	if err != nil {
		t.Fatal(err)
	}
	fw, err := f.svc.Framework(f.ctx, admin, f.acme, "nist-800-171r2")
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]rollup.Outcome{}
	for _, o := range fw.Outcomes {
		by[o.ReqID] = o
	}
	if by["3.5.8"].Status != rollup.DoesNotMeet || len(by["3.5.8"].Failing) != 1 || by["3.5.8"].Failing[0].DeviceID != w2 || by["3.5.8"].Label != compliance.StatusNotMet {
		t.Errorf("3.5.8: %+v", by["3.5.8"])
	}
	// 3.5.7 needs complexity and length, both in place on both computers.
	if by["3.5.7"].Status != rollup.Meets || by["3.5.7"].Label != compliance.StatusMet {
		t.Errorf("3.5.7: %+v", by["3.5.7"])
	}
	// Narrow the scope to the computer that meets 3.5.8, in a new scan: the other is listed out of scope.
	if _, err := f.svc.StartScan(f.ctx, admin, f.acme, engine.ScanInput{Profile: "nist-800-171-assessment", DeviceIDs: []uuid.UUID{w1}}); err != nil {
		t.Fatal(err)
	}
	fw, _ = f.svc.Framework(f.ctx, admin, f.acme, "nist-800-171r2")
	for _, o := range fw.Outcomes {
		by[o.ReqID] = o
	}
	if by["3.5.8"].Status != rollup.Meets || len(by["3.5.8"].OutOfScopeFailing) != 1 || len(fw.OutOfScope) != 1 || fw.OutOfScope[0] != w2 {
		t.Errorf("3.5.8 with w2 out of scope: %+v (out of scope %v)", by["3.5.8"], fw.OutOfScope)
	}
	// A requirement the scan cannot reach stays not assessed, however green the rest is.
	if by["3.2.1"].Status != rollup.NotAssessed || by["3.1.1"].Status != rollup.NotAssessed {
		t.Errorf("organisational or unchecked requirements: %v %v", by["3.2.1"].Status, by["3.1.1"].Status)
	}
	if sc.ID == uuid.Nil {
		t.Fatal()
	}
	// The pack list shows coverage and the licence state.
	ps, err := f.svc.Packs(f.ctx, admin, f.acme)
	if err != nil || len(ps) != 16 {
		t.Fatalf("%d packs, %v", len(ps), err)
	}
	for _, p := range ps {
		if p.Key == "cis-xref" && (p.Note != compliance.CISNote || p.ReviewState != compliance.ReviewNeeded) {
			t.Errorf("%+v", p)
		}
		if p.Key == "nist-800-171r2" && (p.Coverage == nil || p.Coverage.Total != 110 || p.Coverage.Checked == 0 || p.Coverage.Organisational == 0) {
			t.Errorf("%+v", p.Coverage)
		}
	}
	if cs, err := f.svc.Controls(f.ctx, admin, "windows"); err != nil || len(cs) != 172 {
		t.Errorf("%d windows controls, %v", len(cs), err)
	}
	if ps, err := f.svc.Profiles(f.ctx, admin); err != nil || len(ps) != 6 {
		t.Errorf("%d profiles, %v", len(ps), err)
	}
}

// ---- scans that ask the computers ---------------------------------------------------------

const windowsPlatform = `{"id":"windows","versionId":"10.0.26100.4349","family":"windows","container":"none","support":"full",` +
	`"windows":{"build":26100,"ubr":4349,"displayVersion":"24H2","edition":"ServerStandard","installationType":"Server Core",` +
	`"role":"member_server","joined":"domain","mdm":false,"architecture":"amd64","languageMode":"FullLanguage",` +
	`"owners":{"groupPolicyRecord":"read","groupPolicyPreferences":false,"mdm":false,"mdmWinsOverGp":false,` +
	`"defenderForEndpoint":false,"configMgr":false,"dsc":false,"azureMachineConfiguration":false,` +
	`"osConfig":["SecurityBaseline\\WindowsServer\\2025\\MemberServer"],"tamperProtected":true},` +
	`"checkOnlyReasons":[],"notes":[],"hardening":{"folder":"absent","copySha256":"","warnings":[],"setAside":[]}}}`

const linuxPlatform = `{"id":"ubuntu","versionId":"24.04","family":"debian","container":"none","support":"full"}`

// answer finishes a device's run of a job with a hardening result.
func (f *fixture) answer(job, device uuid.UUID, stdout string) {
	f.t.Helper()
	run := uuid.MustParse(f.str(`SELECT id::text FROM job_runs WHERE job_id = $1 AND device_id = $2`, job, device))
	if _, err := f.jobs.Start(f.ctx, device, run); err != nil {
		f.t.Fatal(err)
	}
	zero := 0
	if err := f.jobs.Result(f.ctx, device, run, agentproto.ResultRequest{Status: jobs.StatusSucceeded, ExitCode: &zero, Stdout: stdout, StartedAt: time.Now()}); err != nil {
		f.t.Fatal(err)
	}
}

// result builds a hardening check's result line that reports every module the job asked for: the modules in
// given as they are, the rest as not applicable.
func result(platform string, windows bool, mods []string, given map[string]string) string {
	var parts []string
	for _, m := range mods {
		if g, ok := given[m]; ok {
			parts = append(parts, g)
		} else if windows {
			parts = append(parts, `{"module":"`+m+`","state":"not_applicable","reason":"not here","settings":[],"managed":[],"notes":[]}`)
		} else {
			parts = append(parts, `{"module":"`+m+`","state":"not_applicable","reason":"not here"}`)
		}
	}
	return jobs.HardeningResultPrefix + `{"version":1,"mode":"check","platform":` + platform + `,"modules":[` + strings.Join(parts, ",") + `]}`
}

func (f *fixture) jobFor(device uuid.UUID, nth int) (id uuid.UUID, modules []string) {
	f.t.Helper()
	var raw []byte
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT j.id, j.hardening->'modules' FROM jobs j JOIN job_runs r ON r.job_id = j.id WHERE r.device_id = $1
			ORDER BY j.created_at, j.id OFFSET $2 LIMIT 1`, device, nth).Scan(&id, &raw)
	}); err != nil {
		f.t.Fatal(err)
	}
	_ = json.Unmarshal(raw, &modules)
	return id, modules
}

func TestScanAsksTheComputers(t *testing.T) {
	f := newFixture(t).loaded()
	admin := orgAdmin(f, "admin@example.com", f.acme)
	lnx := f.device(f.acme, f.hq, "A-LNX", "linux")
	win := f.device(f.acme, f.hq, "A-WIN", "windows")

	sc, err := f.svc.StartScan(f.ctx, admin, f.acme, engine.ScanInput{Profile: "nist-800-171-assessment", Run: true})
	if err != nil {
		fatal(t, err)
	}
	if sc.State != "running" || sc.Waiting != 2 {
		t.Fatalf("%+v", sc)
	}
	// One hardening check per platform, reading the modules the controls name and nothing else.
	if f.n(`SELECT count(*) FROM jobs`) != 2 || f.n(`SELECT count(*) FROM jobs WHERE kind = 'hardening' AND hardening->>'mode' = 'check'`) != 2 {
		t.Fatal("the scan did not make two hardening check jobs")
	}
	wjob, wmods := f.jobFor(win, 0)
	ljob, lmods := f.jobFor(lnx, 0)
	if f.str(`SELECT hardening->>'platform' FROM jobs WHERE id = $1`, wjob) != "windows" || len(wmods) == 0 || len(lmods) == 0 {
		t.Fatalf("%v %v", wmods, lmods)
	}
	for _, m := range wmods {
		if !slicesContains(jobs.WindowsHardeningModules, m) {
			t.Errorf("windows module %s", m)
		}
	}
	if slicesContains(wmods, "bitlocker") == false || slicesContains(wmods, "accounts") == false {
		t.Errorf("windows modules %v", wmods)
	}

	// Nothing has answered: the scan waits and writes nothing.
	again, _ := f.svc.Scan(f.ctx, admin, f.acme, sc.ID)
	if again.State != "running" || f.n(`SELECT count(*) FROM compliance_results_history`) != 0 {
		t.Fatalf("%+v", again)
	}

	f.answer(ljob, lnx, result(linuxPlatform, false, lmods, map[string]string{"ssh": `{"module":"ssh","state":"in_place","settings":[` +
		`{"id":"ssh-ciphers","state":"in_place"},{"id":"ssh-crypto-policy","state":"in_place"}]}`}))
	mid, _ := f.svc.Scan(f.ctx, admin, f.acme, sc.ID)
	if mid.State != "running" || mid.Waiting != 1 {
		t.Fatalf("one computer answered: %+v", mid)
	}
	f.answer(wjob, win, result(windowsPlatform, true, wmods, map[string]string{"accounts": `{"module":"accounts","state":"partly","settings":[` +
		`{"id":"accounts-history","state":"not_in_place","value":"3","want":"24"}],"managed":[],"notes":[]}`}))
	done, err := f.svc.Scan(f.ctx, admin, f.acme, sc.ID)
	if err != nil || done.State != "done" || done.ResultHash == nil || done.Waiting != 0 {
		t.Fatalf("%+v, %v", done, err)
	}
	if r := f.results(sc.ID, lnx); r["linux.ssh.ciphers"] != "in_place" {
		t.Errorf("%v", r["linux.ssh.ciphers"])
	}
	wr := f.results(sc.ID, win)
	if wr["win.accounts.history"] != "not_in_place" || wr["win.accounts.complexity"] != "unknown" {
		t.Errorf("windows: %v %v", wr["win.accounts.history"], wr["win.accounts.complexity"])
	}
	// The same scan is not ingested twice.
	if _, err := f.svc.Scan(f.ctx, admin, f.acme, sc.ID); err != nil {
		t.Fatal(err)
	}
	if n := f.n(`SELECT count(*) FROM compliance_results_history WHERE scan_id = $1 AND device_id = $2 AND control_id = 'win.accounts.history'`, sc.ID, win); n != 1 {
		t.Errorf("%d rows", n)
	}
}

// A result that left settings out for length is never a pass: the scan asks again, one module per job,
// and is partial when it still cannot be complete.
func TestTruncatedResultsAreAskedAgainThenPartial(t *testing.T) {
	f := newFixture(t).loaded()
	admin := orgAdmin(f, "admin@example.com", f.acme)
	win := f.device(f.acme, f.hq, "A-WIN", "windows")
	sc, err := f.svc.StartScan(f.ctx, admin, f.acme, engine.ScanInput{Profile: "win-server-baseline", Run: true})
	if err != nil {
		t.Fatal(err)
	}
	job, mods := f.jobFor(win, 0)
	var parts []string
	for _, m := range mods {
		switch m {
		case "accounts":
			parts = append(parts, `{"module":"accounts","state":"in_place","settings":[],"settingsOmitted":"in_place","managed":[],"notes":[]}`)
		default:
			parts = append(parts, `{"module":"`+m+`","state":"not_applicable","reason":"not here","settings":[],"managed":[],"notes":[]}`)
		}
	}
	f.answer(job, win, jobs.HardeningResultPrefix+`{"version":1,"mode":"check","platform":`+windowsPlatform+`,"modules":[`+strings.Join(parts, ",")+`]}`)
	mid, err := f.svc.Scan(f.ctx, admin, f.acme, sc.ID)
	if err != nil || mid.State != "running" || mid.Waiting != 1 {
		t.Fatalf("%+v, %v", mid, err)
	}
	if got := f.results(sc.ID, win); got["win.accounts.history"] != "" || got["win.uac.on"] != "not_applicable" {
		t.Errorf("the cut-short controls were written, or the rest was not: %v / %v", got["win.accounts.history"], got["win.uac.on"])
	}
	redo, redoMods := f.jobFor(win, 1)
	if len(redoMods) != 1 || redoMods[0] != "accounts" || redo == job {
		t.Fatalf("second job %v", redoMods)
	}
	// Still cut short: the controls stay unknown and the scan is partial.
	f.answer(redo, win, result(windowsPlatform, true, []string{"accounts"}, map[string]string{"accounts": `{"module":"accounts","state":"in_place","settings":[],"settingsOmitted":"all","managed":[],"notes":[]}`}))
	done, err := f.svc.Scan(f.ctx, admin, f.acme, sc.ID)
	if err != nil || done.State != "partial" {
		t.Fatalf("%+v, %v", done, err)
	}
	if got := f.results(sc.ID, win); got["win.accounts.history"] != "unknown" {
		t.Errorf("a control of a result that stayed cut short: %q", got["win.accounts.history"])
	}
}

func TestFailedChecksAreUnknownNotPassing(t *testing.T) {
	f := newFixture(t).loaded()
	admin := orgAdmin(f, "admin@example.com", f.acme)
	lnx := f.device(f.acme, f.hq, "A-LNX", "linux")
	f.store(lnx, "ssh", "in_place", sshStored) // an older result that must not be borrowed
	sc, err := f.svc.StartScan(f.ctx, admin, f.acme, engine.ScanInput{Profile: "linux-server-baseline", Run: true})
	if err != nil {
		t.Fatal(err)
	}
	job, _ := f.jobFor(lnx, 0)
	run := uuid.MustParse(f.str(`SELECT id::text FROM job_runs WHERE job_id = $1`, job))
	if _, err := f.jobs.Start(f.ctx, lnx, run); err != nil {
		t.Fatal(err)
	}
	one := 1
	if err := f.jobs.Result(f.ctx, lnx, run, agentproto.ResultRequest{Status: jobs.StatusFailed, ExitCode: &one, Stderr: "boom", StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	done, err := f.svc.Scan(f.ctx, admin, f.acme, sc.ID)
	if err != nil || done.State != "done" {
		t.Fatalf("%+v, %v", done, err)
	}
	for id, st := range f.results(sc.ID, lnx) {
		if st != "unknown" {
			t.Errorf("%s is %s after a failed check", id, st)
		}
	}
}

// ---- the development scope, scheduling and settings ----------------------------------------------

func TestDevScopeGuardsEveryScan(t *testing.T) {
	f := newFixture(t).loaded()
	adminA := orgAdmin(f, "a@example.com", f.acme)
	adminG := orgAdmin(f, "g@example.com", f.globex)
	f.device(f.acme, f.hq, "A-LNX", "linux")
	f.device(f.globex, f.plant, "G-LNX", "linux")
	weekly := "weekly"
	profile := "linux-server-baseline"
	for _, c := range []struct {
		c   access.Caller
		org uuid.UUID
	}{{adminA, f.acme}, {adminG, f.globex}} {
		if _, err := f.svc.PutSettings(f.ctx, c.c, c.org, engine.Settings{Enabled: true, FreshnessDays: 30, ScanSchedule: &weekly, ScanProfile: &profile}); err != nil {
			t.Fatal(err)
		}
	}
	// The scope names Globex: Acme's hand-started and scheduled scans are both refused, with no scan or job made.
	restore := devscope.Set(f.globex)
	_, err := f.svc.StartScan(f.ctx, adminA, f.acme, engine.ScanInput{Profile: profile, Run: true})
	wantErrCode(t, err, "not_available")
	if n, err := f.svc.Tick(f.ctx); err != nil || n != 1 {
		t.Errorf("tick started %d scans: %v", n, err)
	}
	if f.n(`SELECT count(*) FROM compliance_scans WHERE organization_id = $1`, f.acme) != 0 || f.n(`SELECT count(*) FROM jobs`) != 1 {
		t.Errorf("scans of Acme %d, jobs %d", f.n(`SELECT count(*) FROM compliance_scans WHERE organization_id = $1`, f.acme), f.n(`SELECT count(*) FROM jobs`))
	}
	if f.str(`SELECT trigger FROM compliance_scans WHERE organization_id = $1`, f.globex) != "schedule" {
		t.Error("the scheduled scan of the organization in scope")
	}
	restore()
	// Without a scope Acme is reached, and a week without a scan makes one due; a recent scan does not.
	if n, err := f.svc.Tick(f.ctx); err != nil || n != 1 {
		t.Errorf("tick without a scope started %d: %v", n, err)
	}
	if n, _ := f.svc.Tick(f.ctx); n != 0 {
		t.Errorf("a second tick started %d", n)
	}
	f.svc.SetClock(func() time.Time { return time.Now().Add(8 * 24 * time.Hour) })
	if n, _ := f.svc.Tick(f.ctx); n != 2 {
		t.Errorf("a week later %d scans were due", n)
	}
	// An organization that has not turned it on is not scanned.
	f.exec(`UPDATE compliance_org_settings SET enabled = false`)
	f.svc.SetClock(func() time.Time { return time.Now().Add(20 * 24 * time.Hour) })
	if n, _ := f.svc.Tick(f.ctx); n != 0 {
		t.Errorf("a disabled organization was scanned: %d", n)
	}
}

func TestSettings(t *testing.T) {
	f := newFixture(t).loaded()
	admin := orgAdmin(f, "a@example.com", f.acme)
	tech := f.user("t@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	s, err := f.svc.GetSettings(f.ctx, tech, f.acme)
	if err != nil || s.Enabled || s.FreshnessDays != 30 || s.ScanSchedule != nil {
		t.Errorf("%+v, %v", s, err)
	}
	// Changing settings needs compliance.edit, which a technician does not hold.
	if _, err := f.svc.PutSettings(f.ctx, tech, f.acme, engine.Settings{FreshnessDays: 10}); !isNotFound(err) {
		t.Errorf("%v", err)
	}
	bad := "daily"
	for _, in := range []engine.Settings{{FreshnessDays: 0}, {FreshnessDays: 400}, {FreshnessDays: 30, ScanSchedule: &bad, ScanProfile: &bad}} {
		if _, err := f.svc.PutSettings(f.ctx, admin, f.acme, in); err == nil {
			t.Errorf("%+v was accepted", in)
		}
	}
	weekly, none := "weekly", "no-such-profile"
	if _, err := f.svc.PutSettings(f.ctx, admin, f.acme, engine.Settings{FreshnessDays: 30, ScanSchedule: &weekly}); err == nil {
		t.Error("a schedule without a profile")
	}
	if _, err := f.svc.PutSettings(f.ctx, admin, f.acme, engine.Settings{FreshnessDays: 30, ScanSchedule: &weekly, ScanProfile: &none}); err == nil {
		t.Error("a schedule with an unknown profile")
	}
	got, err := f.svc.PutSettings(f.ctx, admin, f.acme, engine.Settings{Enabled: true, FreshnessDays: 7})
	if err != nil || !got.Enabled || got.FreshnessDays != 7 {
		t.Errorf("%+v, %v", got, err)
	}
	if f.n(`SELECT count(*) FROM audit_log WHERE action = 'compliance.settings_update'`) != 1 {
		t.Error("not audited")
	}
}

func slicesContains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// TestC3ControlsAreInTheLibrary: slice C3's controls are stored with the
// check they read, their tier, and the requirements they bear on, and a
// control that has no fix says so.
func TestC3ControlsAreInTheLibrary(t *testing.T) {
	f := newFixture(t).loaded()
	type want struct {
		id, module, setting, tier string
		apply                     bool
		reqs                      []string
	}
	for _, w := range []want{
		{"win.rights.debug", "rights", "rights-debug", "T0", false, []string{"3.1.5"}},
		{"win.rights.local-admins", "rights", "rights-local-admins", "T0", false, []string{"3.1.5"}},
		{"win.rights.remote-logon", "rights", "rights-remote-logon", "T0", false, []string{"3.1.2"}},
		{"win.rights.security-log", "rights", "rights-security-log", "T0", false, []string{"3.3.9"}},
		{"win.session.legal-caption", "session", "session-legal-caption", "T0", false, []string{"3.1.9"}},
		{"win.session.inactivity-lock", "session", "session-inactivity-lock", "T2", true, []string{"3.1.10"}},
		{"win.session.credential-feedback", "session", "session-credential-feedback", "T2", true, []string{"3.5.11"}},
		{"win.session.fips", "session", "session-fips", "T3", true, []string{"3.13.11"}},
		{"win.rdp.idle-limit", "rdp", "rdp-idle-limit", "T2", true, []string{"3.1.11", "3.13.9"}},
		{"win.rdp.disconnected-limit", "rdp", "rdp-disconnected-limit", "T2", true, []string{"3.1.11", "3.13.9"}},
		{"win.removable.deny-write", "removable", "removable-deny-write", "T2", true, []string{"3.1.21", "3.8.7"}},
		{"win.time.synchronized", "time", "time-synchronized", "T0", false, []string{"3.3.7"}},
		{"win.app-control.enforced", "app-control", "app-control-enforced", "T0", false, []string{"3.4.8"}},
		{"win.mobile-code.script-host", "mobile-code", "mobile-code-script-host", "T2", true, []string{"3.13.13"}},
		{"win.office.internet-macros", "office", "office-internet-macros", "T0", false, []string{"3.13.13"}},
		{"linux.ssh.max-sessions", "ssh", "ssh-max-sessions", "T2", true, []string{"3.13.9"}},
		{"linux.lockout.deny-threshold", "lockout", "lockout-deny-threshold", "T0", false, []string{"3.1.8"}},
	} {
		var module, setting, tier, licence, review string
		var apply bool
		if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(f.ctx, `SELECT executor_ref->>'module', executor_ref->>'setting', risk_tier, apply_supported, licence_class, review_state
				FROM compliance_controls WHERE id = $1`, w.id).Scan(&module, &setting, &tier, &apply, &licence, &review)
		}); err != nil {
			t.Errorf("%s: %v", w.id, err)
			continue
		}
		if module != w.module || setting != w.setting || tier != w.tier || apply != w.apply || licence != "ORIGINAL" || review != "none" {
			t.Errorf("%s: %s %s %s %v %s %s", w.id, module, setting, tier, apply, licence, review)
		}
		for _, r := range w.reqs {
			if f.n(`SELECT count(*) FROM compliance_mappings WHERE framework_key = 'nist-800-171r2' AND req_id = $1 AND control_id = $2`, r, w.id) != 1 {
				t.Errorf("%s is not mapped to 800-171 %s", w.id, r)
			}
		}
	}
	// A control with no fix has advice in its own words, and a fix that
	// restarts the computer says so.
	if got := f.str(`SELECT remediation_text FROM compliance_controls WHERE id = 'win.session.legal-text'`); !strings.Contains(got, "does not write the text") {
		t.Errorf("legal text advice: %q", got)
	}
	if !f.exists(`SELECT needs_restart FROM compliance_controls WHERE id = 'win.session.fips'`) {
		t.Error("FIPS mode needs a restart")
	}
	// Each control a profile names exists, and the baselines carry C3's.
	if n := f.n(`SELECT count(*) FROM compliance_profile_controls pc WHERE NOT EXISTS (SELECT 1 FROM compliance_controls c WHERE c.id = pc.control_id)`); n != 0 {
		t.Errorf("%d profile controls name no control", n)
	}
}

func (f *fixture) exists(sql string) bool {
	f.t.Helper()
	var b bool
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql).Scan(&b) }); err != nil {
		f.t.Fatal(err)
	}
	return b
}

// TestC4ControlsAreInTheLibrary: slice C4's controls are stored with the
// check they read, for domain controllers only, report only, with the
// requirements they bear on; and the domain controller profile names them.
func TestC4ControlsAreInTheLibrary(t *testing.T) {
	f := newFixture(t).loaded()
	type want struct {
		id, setting string
		reqs        []string
	}
	for _, w := range []want{
		{"win.dc.ldap-signing", "dc-ldap-signing", []string{"3.13.8", "3.13.15"}},
		{"win.dc.ldap-channel-binding", "dc-ldap-channel-binding", []string{"3.13.8", "3.13.15"}},
		{"win.dc.kerberos-types", "dc-kerberos-types", []string{"3.13.8"}},
		{"win.dc.kdc-default-types", "dc-kdc-default-types", []string{"3.13.8"}},
		{"win.dc.krbtgt-age", "dc-krbtgt-age", []string{"3.13.10"}},
		{"win.dc.dsrm-logon", "dc-dsrm-logon", []string{"3.1.5"}},
		{"win.dc.password-length", "dc-password-length", []string{"3.5.7"}},
		{"win.dc.password-history", "dc-password-history", []string{"3.5.8"}},
		{"win.dc.lockout-threshold", "dc-lockout-threshold", []string{"3.1.8"}},
		{"win.dc.schema-admins", "dc-schema-admins", []string{"3.1.5"}},
		{"win.dc.stale-accounts", "dc-stale-accounts", []string{"3.5.6"}},
		{"win.dc.time-hierarchy", "dc-time-hierarchy", []string{"3.3.7"}},
		{"win.dc.backup", "dc-backup", []string{"3.8.9"}},
		// Replication and SYSVOL bear on no 800-171 requirement; they are in
		// the domain controller profile only.
		{"win.dc.replication", "dc-replication", nil},
		{"win.dc.sysvol", "dc-sysvol", nil},
	} {
		var module, setting, tier, scope string
		var apply bool
		if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(f.ctx, `SELECT executor_ref->>'module', executor_ref->>'setting', risk_tier, apply_supported, scopes[1]
				FROM compliance_controls WHERE id = $1`, w.id).Scan(&module, &setting, &tier, &apply, &scope)
		}); err != nil {
			t.Errorf("%s: %v", w.id, err)
			continue
		}
		if module != "dc" || setting != w.setting || tier != "T0" || apply || scope != "domain_controller" {
			t.Errorf("%s: %s %s %s %v %s", w.id, module, setting, tier, apply, scope)
		}
		for _, r := range w.reqs {
			if f.n(`SELECT count(*) FROM compliance_mappings WHERE framework_key = 'nist-800-171r2' AND req_id = $1 AND control_id = $2`, r, w.id) != 1 {
				t.Errorf("%s is not mapped to 800-171 %s", w.id, r)
			}
		}
	}
	// None of the 21 has a fix (a change to a domain's settings is not C4's),
	// and each one has advice in its own words.
	if n := f.n(`SELECT count(*) FROM compliance_controls WHERE id LIKE 'win.dc.%'`); n != 21 {
		t.Errorf("%d domain controller controls, want 21", n)
	}
	if n := f.n(`SELECT count(*) FROM compliance_controls WHERE id LIKE 'win.dc.%' AND (apply_supported OR remediation_text NOT LIKE '%EasyRMM%')`); n != 0 {
		t.Errorf("%d domain controller controls with a fix or without advice", n)
	}
	if n := f.n(`SELECT count(*) FROM compliance_profile_controls WHERE profile_key = 'win-domain-controller'`); n != 24 {
		t.Errorf("%d controls in the domain controller profile, want 24", n)
	}
}
