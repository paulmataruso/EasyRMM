//go:build integration

package keystore_test

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/keystore"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

func (r *reader) open(kind string) int {
	return mustAtoi(r.t, r.str(`SELECT count(*)::text FROM keystore_alerts WHERE kind = $1 AND resolved_at IS NULL`, kind))
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

// The monitor raises the keystore's condition alerts from its status, closes
// them when the condition ends, mails the administrators once, and does not
// reopen what a person resolved for a day.
func TestMonitorRaisesAndClosesConditions(t *testing.T) {
	r := readFx(t)
	admin, ctx := r.person("root@example.test", rbac.RoleSuperAdmin)
	_, _ = r.person("orgadmin@example.test", rbac.RoleOrgAdmin)

	// The test keystore runs in file mode, the stand-in: a standing warning.
	if err := r.svc.Monitor(r.ctx); err != nil {
		t.Fatal(err)
	}
	if r.open(keystore.AlertFileMode) != 1 || r.open(keystore.AlertUnreachable) != 0 {
		t.Fatalf("file mode alert: %s", r.str(`SELECT string_agg(kind, ',') FROM keystore_alerts`))
	}
	if err := r.svc.Monitor(r.ctx); err != nil || r.open(keystore.AlertFileMode) != 1 {
		t.Fatalf("again: %v", err)
	}
	r.mail.waitFor(t, 1) // the super administrator, once; not the organization's administrator
	if !strings.Contains(r.mail.text[0], "keystore") {
		t.Errorf("mail: %q", r.mail.text[0])
	}

	// A person resolves it; the monitor leaves it for a day.
	alerts, err := r.svc.Alerts(ctx, admin)
	if err != nil || len(alerts) != 1 {
		t.Fatalf("alerts: %+v %v", alerts, err)
	}
	if err := r.svc.ResolveAlert(ctx, admin, alerts[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := r.svc.Monitor(r.ctx); err != nil || r.open(keystore.AlertFileMode) != 0 {
		t.Fatalf("a resolved condition was reopened at once: %v", err)
	}
	if got := r.str(`SELECT resolved_by_label FROM keystore_alerts WHERE kind = $1`, keystore.AlertFileMode); got != "root@example.test" {
		t.Errorf("resolved by %q", got)
	}
	if r.str(`SELECT count(*)::text FROM audit_log WHERE action = $1`, keystore.ActionAlertResolved) != "1" {
		t.Error("the resolution was not audited")
	}
	r.exec(`UPDATE keystore_alerts SET resolved_at = now() - interval '2 days'`)
	if err := r.svc.Monitor(r.ctx); err != nil || r.open(keystore.AlertFileMode) != 1 {
		t.Fatalf("a standing condition must come back after a day: %v", err)
	}
	// Resolving twice is not found.
	if err := r.svc.ResolveAlert(ctx, admin, alerts[0].ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("resolve a closed alert: %v", err)
	}

	// Unreachable: not for a restart, then critical.
	r.stopSocket()
	for range keystore.UnreachableAfter - 1 {
		_ = r.svc.Monitor(r.ctx)
	}
	if r.open(keystore.AlertUnreachable) != 0 {
		t.Fatal("a restart raised an alert")
	}
	_ = r.svc.Monitor(r.ctx)
	if r.open(keystore.AlertUnreachable) != 1 {
		t.Fatal("an unreachable keystore raised nothing")
	}
	r.startSocket()
	if err := r.svc.Monitor(r.ctx); err != nil || r.open(keystore.AlertUnreachable) != 0 {
		t.Fatalf("it came back and the alert stayed: %v", err)
	}
}

// Only the right people see and resolve an alert; an organization's alert is
// its administrators' and nobody else's.
func TestResolveAlertIsScoped(t *testing.T) {
	r := readFx(t)
	orgadmin, octx := r.person("orgadmin@example.test", rbac.RoleOrgAdmin)
	tech, tctx := r.person("tech@example.test", rbac.RoleTechnician)
	root, rctx := r.person("root@example.test", rbac.RoleSuperAdmin)
	r.exec(`INSERT INTO keystore_alerts (organization_id, kind, severity, subject, detail) VALUES ($1, 'escrow_conflict', 'warning', 'x', 'd')`, r.acme)
	r.exec(`INSERT INTO keystore_alerts (organization_id, kind, severity, subject, detail) VALUES (NULL, 'keystore_file_mode', 'warning', 'keystore', 'd')`)
	if got, _ := r.svc.Alerts(octx, orgadmin); len(got) != 1 || got[0].Org == nil {
		t.Fatalf("an org admin sees %+v", got)
	}
	if got, _ := r.svc.Alerts(tctx, tech); len(got) != 0 {
		t.Fatalf("a technician sees %+v", got)
	}
	all, _ := r.svc.Alerts(rctx, root)
	if len(all) != 2 {
		t.Fatalf("a super admin sees %+v", all)
	}
	for _, a := range all {
		if err := r.svc.ResolveAlert(tctx, tech, a.ID); !errors.Is(err, apperr.ErrNotFound) {
			t.Errorf("a technician resolved %s: %v", a.Kind, err)
		}
		if a.Org == nil {
			if err := r.svc.ResolveAlert(octx, orgadmin, a.ID); !errors.Is(err, apperr.ErrNotFound) {
				t.Errorf("an org admin resolved a platform alert: %v", err)
			}
		} else if err := r.svc.ResolveAlert(octx, orgadmin, a.ID); err != nil {
			t.Errorf("an org admin could not resolve their own: %v", err)
		}
	}
	if err := r.svc.ResolveAlert(rctx, root, uuid.New()); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("unknown alert: %v", err)
	}
}

// A conflicting key raises the organization's alert and mails its administrators.
func TestEscrowConflictRaisesAnAlert(t *testing.T) {
	r := readFx(t)
	_, _ = r.person("orgadmin@example.test", rbac.RoleOrgAdmin)
	key, pub := r.instruction(r.dev)
	r.later()
	ans, err := r.svc.Upload(r.ctx, r.dv(r.fx.dev, r.acme, r.hq), netip.Addr{}, r.record(r.dv(r.fx.dev, r.acme, r.hq), key, pub, r.vol, r.prot, password2))
	if err != nil || ans.State != agentproto.EscrowConflict {
		t.Fatalf("conflict: %+v %v", ans, err)
	}
	if r.open(keystore.AlertEscrowConflict) != 1 {
		t.Fatal("no conflict alert")
	}
	r.mail.waitFor(t, 1)
}
