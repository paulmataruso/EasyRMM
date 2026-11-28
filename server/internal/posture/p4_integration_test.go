//go:build integration

package posture_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/compliance"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/rollup"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/posture"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// user is a signed-in caller with the assignments.
func (f *fixture) user(email string, as ...rbac.Assignment) access.Caller {
	f.t.Helper()
	id := f.id(`INSERT INTO users (email, display_name) VALUES ($1, $1) RETURNING id`, email)
	for _, a := range as {
		var org *uuid.UUID
		if a.OrganizationID != uuid.Nil {
			org = &a.OrganizationID
		}
		f.exec(`INSERT INTO role_assignments (user_id, role, organization_id) VALUES ($1, $2, $3)`, id, string(a.Role), org)
	}
	p, err := rbac.NewPrincipal(id, as)
	if err != nil {
		f.t.Fatal(err)
	}
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: id, Label: email})
}

// fake is a posture of a word and score, as Load would give.
func fake(word string, percent int) *posture.Posture {
	return &posture.Posture{Score: rollup.Score{Word: word, Percent: &percent, Failing: 1}}
}

func (f *fixture) openNotices(dev uuid.UUID) int {
	return f.count(`SELECT count(*) FROM notices WHERE kind = $1 AND subject = $2 AND resolved_at IS NULL`, posture.NoticeNoncompliant, dev.String())
}

func TestPolicyWeightsChangeThePosture(t *testing.T) {
	f := newFixture(t)
	d := f.device("web", "linux")
	f.module(d, "ssh", "in_place", 0, `{}`)
	f.module(d, "firewall", "not_in_place", 0, `{"reason":"the firewall is off"}`)
	admin := f.user("admin@example.test", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.org})

	// The defaults: ssh 3 + disk 3 + logs 2 pass, the firewall (3) fails.
	if p := f.load(d, "linux"); p.Word != compliance.WordDoesNotMeet || *p.Percent != 72 {
		t.Fatalf("default: %+v", p)
	}
	// A heavier firewall lowers the score.
	if got, err := f.svc.SetPolicy(f.ctx, admin, f.org, "firewall", 5); err != nil || got.Weight != 5 || got.Default != 3 || !got.Overridden {
		t.Fatalf("set: %+v %v", got, err)
	}
	if p := f.load(d, "linux"); *p.Percent != 61 || p.Reasons[0].Weight != 5 {
		t.Fatalf("weight 5: %+v", p)
	}
	// Weight 0 leaves the control out: the computer meets.
	if _, err := f.svc.SetPolicy(f.ctx, admin, f.org, "firewall", 0); err != nil {
		t.Fatal(err)
	}
	if p := f.load(d, "linux"); p.Word != compliance.WordMeets || *p.Percent != 100 || p.Failing != 0 {
		t.Fatalf("weight 0: %+v", p)
	}
	// A weight of another organization does not reach this one.
	other := f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	f.exec(`INSERT INTO posture_policies (organization_id, control_id, weight) VALUES ($1, 'ssh', 0)`, other)
	if p := f.load(d, "linux"); *p.Percent != 100 || p.Meeting != 3 {
		t.Fatalf("other organization's policy: %+v", p)
	}
	// Reset to the default.
	if err := f.svc.DeletePolicy(f.ctx, admin, f.org, "firewall"); err != nil {
		t.Fatal(err)
	}
	if p := f.load(d, "linux"); p.Word != compliance.WordDoesNotMeet || *p.Percent != 72 {
		t.Fatalf("reset: %+v", p)
	}
	// Resetting what was never set is fine.
	if err := f.svc.DeletePolicy(f.ctx, admin, f.org, "firewall"); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyCRUD(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.test", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.org})
	if l, err := f.svc.ListPolicies(f.ctx, admin, f.org); err != nil || len(l) != 0 {
		t.Fatalf("empty list: %+v %v", l, err)
	}
	if g, err := f.svc.GetPolicy(f.ctx, admin, f.org, "rdp"); err != nil || g.Overridden || g.Weight != 2 || g.Default != 2 || g.UpdatedAt != nil || g.Label != "Remote Desktop" {
		t.Fatalf("default get: %+v %v", g, err)
	}
	if _, err := f.svc.SetPolicy(f.ctx, admin, f.org, "rdp", 1); err != nil {
		t.Fatal(err)
	}
	// An upsert, not a second row.
	if _, err := f.svc.SetPolicy(f.ctx, admin, f.org, "rdp", 4); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SetPolicy(f.ctx, admin, f.org, "smb", 0); err != nil {
		t.Fatal(err)
	}
	l, err := f.svc.ListPolicies(f.ctx, admin, f.org)
	if err != nil || len(l) != 2 || l[0].ControlID != "rdp" || l[0].Weight != 4 || l[1].ControlID != "smb" || l[1].Weight != 0 || l[1].UpdatedAt == nil {
		t.Fatalf("list: %+v %v", l, err)
	}
	if f.count(`SELECT count(*) FROM posture_policies WHERE updated_by IS NOT NULL`) != 2 {
		t.Fatal("who set it is kept")
	}
	// Bad input.
	for _, w := range []int{-1, 6} {
		if _, err := f.svc.SetPolicy(f.ctx, admin, f.org, "rdp", w); err == nil {
			t.Fatalf("weight %d accepted", w)
		}
	}
	if _, err := f.svc.SetPolicy(f.ctx, admin, f.org, "Not A Control", 1); err == nil {
		t.Fatal("a bad control id was accepted")
	}
	if _, err := f.svc.GetPolicy(f.ctx, admin, f.org, "../x"); err == nil {
		t.Fatal("a bad control id was read")
	}
	if err := f.svc.DeletePolicy(f.ctx, admin, f.org, "rdp"); err != nil {
		t.Fatal(err)
	}
	if g, _ := f.svc.GetPolicy(f.ctx, admin, f.org, "rdp"); g.Overridden {
		t.Fatalf("after reset: %+v", g)
	}
}

func TestPolicyNeedsOrgManage(t *testing.T) {
	f := newFixture(t)
	tech := f.user("tech@example.test", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.org})
	elsewhere := f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	otherAdmin := f.user("other@example.test", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: elsewhere})
	for name, c := range map[string]access.Caller{"technician": tech, "another organization's admin": otherAdmin} {
		if _, err := f.svc.ListPolicies(f.ctx, c, f.org); !errors.Is(err, apperr.ErrNotFound) {
			t.Fatalf("%s list: %v", name, err)
		}
		if _, err := f.svc.GetPolicy(f.ctx, c, f.org, "rdp"); !errors.Is(err, apperr.ErrNotFound) {
			t.Fatalf("%s get: %v", name, err)
		}
		if _, err := f.svc.SetPolicy(f.ctx, c, f.org, "rdp", 1); !errors.Is(err, apperr.ErrNotFound) {
			t.Fatalf("%s set: %v", name, err)
		}
		if err := f.svc.DeletePolicy(f.ctx, c, f.org, "rdp"); !errors.Is(err, apperr.ErrNotFound) {
			t.Fatalf("%s delete: %v", name, err)
		}
	}
	if f.count(`SELECT count(*) FROM posture_policies`) != 0 {
		t.Fatal("a refused caller wrote a policy")
	}
}

func TestHistoryRecordsChangesOnly(t *testing.T) {
	f := newFixture(t)
	d := f.device("web", "linux")
	admin := f.user("admin@example.test", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.org})
	rec := func(p *posture.Posture) {
		t.Helper()
		if err := f.svc.RecordHistory(f.ctx, d, p); err != nil {
			t.Fatal(err)
		}
	}
	rows := func() int { return f.count(`SELECT count(*) FROM posture_history WHERE device_id = $1`, d) }

	if err := f.svc.RecordHistory(f.ctx, d, nil); err != nil || rows() != 0 {
		t.Fatalf("nil posture: %v", err)
	}
	f.svc.SetClock(func() time.Time { return time.Now().Add(-3 * time.Hour) })
	rec(fake(compliance.WordMeets, 100))
	// The same word and score, read again however soon or late, adds nothing.
	rec(fake(compliance.WordMeets, 100))
	f.svc.SetClock(time.Now)
	rec(fake(compliance.WordMeets, 100))
	if rows() != 1 {
		t.Fatalf("unchanged: %d rows", rows())
	}
	// A new score with the same word is a change.
	rec(fake(compliance.WordDoesNotMeet, 80))
	rec(fake(compliance.WordDoesNotMeet, 70))
	rec(fake(compliance.WordDoesNotMeet, 70))
	if rows() != 3 {
		t.Fatalf("changes: %d rows", rows())
	}
	// A posture with no score (nothing applies) is told apart from 0.
	none := &posture.Posture{Score: rollup.Score{Word: compliance.WordCannotTell}}
	rec(none)
	rec(none)
	rec(fake(compliance.WordCannotTell, 0))
	if rows() != 5 {
		t.Fatalf("nil percent: %d rows", rows())
	}

	h, err := f.svc.History(f.ctx, admin, d, 0)
	if err != nil || len(h) != 5 {
		t.Fatalf("history: %+v %v", h, err)
	}
	if h[0].Word != compliance.WordCannotTell || h[0].Percent == nil || *h[0].Percent != 0 || h[1].Percent != nil || h[4].Word != compliance.WordMeets || *h[4].Percent != 100 {
		t.Fatalf("newest first: %+v", h)
	}
	for i := 1; i < len(h); i++ {
		if h[i].RecordedAt.After(h[i-1].RecordedAt) {
			t.Fatalf("not newest first at %d", i)
		}
	}
}

func TestHistoryWindowAndPermission(t *testing.T) {
	f := newFixture(t)
	d := f.device("web", "linux")
	admin := f.user("admin@example.test", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.org})
	for _, age := range []string{"1 day", "45 days", "100 days"} {
		f.exec(`INSERT INTO posture_history (device_id, word, percent, failing, cannot_tell, recorded_at) VALUES ($1, 'meets', 100, 0, 0, now() - $2::interval)`, d, age)
	}
	n := func(days int) int {
		t.Helper()
		h, err := f.svc.History(f.ctx, admin, d, days)
		if err != nil {
			t.Fatal(err)
		}
		return len(h)
	}
	if n(0) != 1 || n(-5) != 1 {
		t.Fatal("30 days by default")
	}
	if n(60) != 2 {
		t.Fatal("60 days")
	}
	if n(10000) != 2 {
		t.Fatal("at most 90 days")
	}
	// The history of a computer a caller cannot see is not there.
	nobody := f.user("nobody@example.test")
	if _, err := f.svc.History(f.ctx, nobody, d, 30); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("no permission: %v", err)
	}
	if _, err := f.svc.History(f.ctx, admin, uuid.New(), 30); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("no such computer: %v", err)
	}
	// It goes with the computer.
	f.exec(`DELETE FROM devices WHERE id = $1`, d)
	if f.count(`SELECT count(*) FROM posture_history`) != 0 {
		t.Fatal("history outlived its computer")
	}
}

func TestDeviceReadRecordsHistory(t *testing.T) {
	f := newFixture(t)
	d := f.device("web", "linux")
	f.module(d, "ssh", "in_place", 0, `{}`)
	sys := access.System("test")
	for range 2 {
		if _, err := f.svc.Device(f.ctx, sys, d); err != nil {
			t.Fatal(err)
		}
	}
	if f.count(`SELECT count(*) FROM posture_history WHERE device_id = $1 AND word = 'meets' AND percent = 100`, d) != 1 {
		t.Fatal("a read of a computer's posture notes it once")
	}
	f.module(d, "firewall", "not_in_place", 0, `{}`)
	if _, err := f.svc.Device(f.ctx, sys, d); err != nil {
		t.Fatal(err)
	}
	if f.count(`SELECT count(*) FROM posture_history WHERE device_id = $1`, d) != 2 || f.openNotices(d) != 1 {
		t.Fatal("the change is noted and the notice opened")
	}
}

func TestEvaluateFollowsTheFleet(t *testing.T) {
	f := newFixture(t)
	a := f.device("a", "linux")
	b := f.device("b", "windows")
	f.module(a, "ssh", "in_place", 0, `{}`)
	f.module(b, "uac", "in_place", 0, `{}`)
	mac := f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform) VALUES ($1, $2, 'm', 'm', 'macos') RETURNING id`, f.org, f.site)
	n, err := f.svc.Evaluate(f.ctx)
	if err != nil || n != 2 {
		t.Fatalf("evaluate: %d %v", n, err)
	}
	if f.count(`SELECT count(*) FROM posture_history WHERE device_id = $1`, mac) != 0 || f.count(`SELECT count(*) FROM posture_history`) != 2 {
		t.Fatal("only the computers posture covers are noted")
	}
	// The firewall of one fails; the pass notes it and opens the notice.
	f.module(a, "firewall", "not_in_place", 0, `{}`)
	if _, err := f.svc.Evaluate(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.openNotices(a) != 1 || f.openNotices(b) != 0 || f.count(`SELECT count(*) FROM posture_history`) != 3 {
		t.Fatal("the pass follows the fleet")
	}
}

func TestNoncompliantNotice(t *testing.T) {
	f := newFixture(t)
	d := f.device("web", "linux")
	rec := func(word string, pct int) {
		t.Helper()
		if err := f.svc.RecordHistory(f.ctx, d, fake(word, pct)); err != nil {
			t.Fatal(err)
		}
	}
	// A computer first seen failing was never known to meet: no notice.
	rec(compliance.WordDoesNotMeet, 50)
	if f.openNotices(d) != 0 {
		t.Fatal("a first sighting opened a notice")
	}
	rec(compliance.WordMeets, 100)
	if f.openNotices(d) != 0 {
		t.Fatal("meeting opened a notice")
	}
	// meets -> does not meet opens it, once.
	rec(compliance.WordDoesNotMeet, 60)
	rec(compliance.WordDoesNotMeet, 55)
	if f.openNotices(d) != 1 {
		t.Fatalf("notice not open once: %d", f.openNotices(d))
	}
	var title string
	var org, site, dev uuid.UUID
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT title, organization_id, site_id, device_id FROM notices WHERE kind = $1 AND resolved_at IS NULL`,
			posture.NoticeNoncompliant).Scan(&title, &org, &site, &dev)
	}); err != nil {
		t.Fatal(err)
	}
	if org != f.org || site != f.site || dev != d || title != "Computer no longer meets its security policy: web" {
		t.Fatalf("notice: %q %v %v %v", title, org, site, dev)
	}
	// Not being able to tell is not a recovery.
	rec(compliance.WordCannotTell, 40)
	if f.openNotices(d) != 1 {
		t.Fatal("cannot tell resolved the notice")
	}
	// Meeting again resolves it.
	rec(compliance.WordMeets, 100)
	if f.openNotices(d) != 0 || f.count(`SELECT count(*) FROM notices WHERE kind = $1 AND resolved_at IS NOT NULL`, posture.NoticeNoncompliant) != 1 {
		t.Fatal("meeting did not resolve the notice")
	}
	// And the next failure opens a new one.
	rec(compliance.WordDoesNotMeet, 60)
	if f.openNotices(d) != 1 || f.count(`SELECT count(*) FROM notices WHERE kind = $1`, posture.NoticeNoncompliant) != 2 {
		t.Fatal("a second failure did not open a notice")
	}
}
