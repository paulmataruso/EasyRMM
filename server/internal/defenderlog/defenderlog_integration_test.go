//go:build integration

package defenderlog_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/defenderlog"
	"github.com/paulmataruso/easyrmm/server/internal/modsnap"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/monitoring"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/defender"
)

type fx struct {
	t        *testing.T
	ctx      context.Context
	db       *database.DB
	mods     *modules.Service
	mon      *monitoring.Service
	store    *defenderlog.Store
	acme, hq uuid.UUID
	dev      uuid.UUID
}

func newFx(t *testing.T) *fx {
	t.Helper()
	inst := testdb.New(t)
	f := &fx{t: t, ctx: context.Background(), db: inst.DB}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	au := audit.New(inst.DB, nil)
	f.mods = modules.New(inst.DB, au, log)
	f.mon = monitoring.New(inst.DB, au, 30*24*time.Hour, 7*24*time.Hour, log)
	f.mon.FollowServing(func() (time.Time, bool) { return time.Now().Add(-24 * time.Hour), true })
	if err := monitoring.RegisterModuleAlerts(defender.AlertKinds()); err != nil {
		t.Fatal(err)
	}
	f.mods.OnRoleRemoved(modsnap.OnRoleRemoved)
	f.mods.OnRoleRemoved(monitoring.RoleRemovedHook)
	f.mods.OnEnabled(monitoring.EnsureDefaults)
	f.mon.UseModules(f.mods)
	f.store = defenderlog.New(inst.DB, f.mods, log)
	f.acme = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.hq = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.acme)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	f.dev = f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at, roles, roles_at)
		VALUES ($1, $2, 'dc1', 'dc1', 'windows', $3, now() - interval '1 day', now(), '[{"name":"defender","state":"present"}]', now()) RETURNING id`, f.acme, f.hq, key)
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

func (f *fx) ingest(b *agentproto.DefenderLogBatch) *agentproto.DefenderLogAck {
	f.t.Helper()
	var ack *agentproto.DefenderLogAck
	err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		if !f.store.Enabled(f.ctx, tx, f.dev, f.acme, f.hq) {
			f.t.Fatal("the module is not enabled for the device")
		}
		var err error
		ack, err = f.store.Ingest(f.ctx, tx, f.dev, f.acme, f.hq, b)
		return err
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return ack
}

func (f *fx) evaluate() {
	f.t.Helper()
	if _, err := f.mon.Evaluate(f.ctx); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) open(kind string) int {
	return f.count(`SELECT count(*) FROM alerts WHERE device_id = $1 AND kind = $2 AND status <> 'resolved'`, f.dev, kind)
}

func ev(rec int64, id int, ago time.Duration, mut func(*agentproto.DefenderLogEvent)) agentproto.DefenderLogEvent {
	e := agentproto.DefenderLogEvent{RecordID: rec, EventID: id, At: time.Now().Add(-ago).UTC()}
	if mut != nil {
		mut(&e)
	}
	return e
}

func batch(through int64, events ...agentproto.DefenderLogEvent) *agentproto.DefenderLogBatch {
	return &agentproto.DefenderLogBatch{Epoch: "e1", Through: through, Events: events}
}

func detection(rec int64, threat, name, severity string, ago time.Duration) agentproto.DefenderLogEvent {
	return ev(rec, 1116, ago, func(e *agentproto.DefenderLogEvent) {
		e.ThreatID, e.ThreatName, e.Severity = threat, name, severity
		e.Sensitive = map[string]string{"path": `C:\Users\alice\Downloads\eicar.txt`, "user": `ACME\alice`}
	})
}

// A severe detection opens the critical policy once (the best match: the
// low-or-moderate policy does not open a second alert), the same batch twice
// stores nothing twice and acknowledges the same, and the action event
// resolves the alert.
func TestThreatAlertLifecycle(t *testing.T) {
	f := newFx(t)
	f.evaluate() // creates the default policies
	b := batch(2, detection(1, "T1", "Virus:DOS/EICAR_Test_File", "Severe", 2*time.Minute), ev(2, 2000, time.Minute, nil))
	ack := f.ingest(b)
	if ack == nil || ack.Epoch != "e1" || ack.RecordID != 2 {
		t.Fatalf("ack %+v", ack)
	}
	f.ingest(b)
	if n := f.count(`SELECT count(*) FROM defender_events WHERE device_id = $1`, f.dev); n != 2 {
		t.Errorf("%d events stored after the same batch twice", n)
	}
	f.evaluate()
	if n := f.open("defender_threat"); n != 1 {
		t.Fatalf("%d open threat alerts, want 1 (the best match)", n)
	}
	if got := f.count(`SELECT count(*) FROM alerts a JOIN alert_policies p ON p.id = a.policy_id WHERE a.device_id = $1 AND a.status <> 'resolved' AND p.default_key = 'threat_high'`, f.dev); got != 1 {
		t.Errorf("the alert is not the high or severe policy's")
	}
	// The detail names the threat and carries no path or user.
	var detail string
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT detail FROM alerts WHERE device_id = $1 AND kind = 'defender_threat' AND status <> 'resolved'`, f.dev).Scan(&detail)
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, "EICAR") || strings.Contains(detail, "alice") || strings.Contains(detail, `\`) {
		t.Errorf("detail %q", detail)
	}
	// Defender acted on it: the alert resolves.
	f.ingest(batch(3, ev(3, 1117, 0, func(e *agentproto.DefenderLogEvent) { e.ThreatID, e.Action = "T1", "Quarantine" })))
	f.evaluate()
	if n := f.open("defender_threat"); n != 0 {
		t.Errorf("%d threat alerts after the action", n)
	}
	// A low threat opens the low policy's alert only, and a failed remediation its own.
	f.ingest(batch(5, detection(4, "T2", "PUA:Win32/Low", "Low", time.Minute), ev(5, 1118, 0, func(e *agentproto.DefenderLogEvent) { e.ThreatID, e.ThreatName = "T3", "Trojan:Win32/X" })))
	f.evaluate()
	if f.open("defender_threat") != 1 || f.open("defender_remediation_failed") != 1 {
		t.Errorf("threat %d, failed remediation %d", f.open("defender_threat"), f.open("defender_remediation_failed"))
	}
	if got := f.count(`SELECT count(*) FROM alerts a JOIN alert_policies p ON p.id = a.policy_id WHERE a.device_id = $1 AND a.status <> 'resolved' AND p.default_key = 'threat_low'`, f.dev); got != 1 {
		t.Error("a low threat is the low policy's alert")
	}
}

// Backfilled events older than an hour are stored and shown but raise nothing;
// recent ones do. EasyRMM's own change window suppresses the alert and keeps the event.
func TestBackfillOursAndConfigChanges(t *testing.T) {
	f := newFx(t)
	f.evaluate()
	old := batch(2, detection(1, "T9", "Old:Detection", "Severe", 20*time.Hour), ev(2, 5007, 20*time.Hour, func(e *agentproto.DefenderLogEvent) {
		e.Sensitive = map[string]string{"oldValue": `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\x = 0x0`}
	}))
	old.Backfill = true
	f.ingest(old)
	f.evaluate()
	if f.count(`SELECT count(*) FROM defender_events WHERE device_id = $1 AND backfill`, f.dev) != 2 || f.open("defender_threat") != 0 || f.open("defender_exclusion_changed") != 0 {
		t.Fatal("a backfilled event from yesterday raised an alert")
	}
	// An exclusion changed by someone else: the alert opens, and the summary never holds the value.
	f.ingest(batch(4, ev(4, 5007, time.Minute, func(e *agentproto.DefenderLogEvent) {
		e.Sensitive = map[string]string{"oldValue": ``, "newValue": `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Customer Acme = 0x0`}
	})))
	f.evaluate()
	if f.open("defender_exclusion_changed") != 1 {
		t.Fatal("an exclusion change did not open the alert")
	}
	var summary, sensitive string
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT summary::text, coalesce(sensitive::text, '') FROM defender_events WHERE device_id = $1 AND record_id = 4`, f.dev).Scan(&summary, &sensitive)
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(summary, "Acme") || strings.Contains(summary, `\`) || !strings.Contains(summary, `"class": "exclusion"`) || !strings.Contains(sensitive, "Acme") {
		t.Errorf("summary %s, sensitive %s", summary, sensitive)
	}
	// A change EasyRMM made: a finished winmod Defender change job around the event's time.
	job := f.id(`INSERT INTO jobs (id, script_name, shell, body, body_sha256, timeout_seconds, expires_at, kind, hidden, winmod)
		VALUES (gen_random_uuid(), 'x', 'powershell', 'x', sha256('x'::bytea), 60, now() + interval '1 day', 'winmod', true,
		'{"module":"defender","action":"defender.preferences_weaken","version":1,"scriptSha256":"x","keepSeconds":60}') RETURNING id`)
	f.exec(`INSERT INTO job_runs (job_id, organization_id, site_id, device_id, status, expires_at, started_at, finished_at, deadline_at)
		VALUES ($1, $2, $3, $4, 'succeeded', now() + interval '1 day', now() - interval '40 seconds', now() - interval '30 seconds', now() + interval '1 hour')`, job, f.acme, f.hq, f.dev)
	f.exec(`UPDATE alerts SET status = 'resolved', resolved_at = now(), resolution = 'manual' WHERE device_id = $1`, f.dev)
	f.ingest(batch(6, ev(5, 5001, 35*time.Second, nil), ev(6, 5007, 33*time.Second, func(e *agentproto.DefenderLogEvent) {
		e.Sensitive = map[string]string{"newValue": `HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 0x1`}
	})))
	if n := f.count(`SELECT count(*) FROM defender_events WHERE device_id = $1 AND ours`, f.dev); n != 2 {
		t.Errorf("%d events tagged ours, want 2", n)
	}
	f.evaluate()
	if f.open("defender_config_changed") != 0 {
		t.Error("EasyRMM's own change opened an alert")
	}
}

// Update failures, health and gaps; a module that is off stores and judges nothing.
func TestUpdateFailureHealthGapAndModuleOff(t *testing.T) {
	f := newFx(t)
	f.evaluate()
	f.ingest(batch(2, ev(1, 2001, 5*time.Hour, nil), ev(2, 3002, time.Minute, nil)))
	f.evaluate()
	// The failing update holds for its grace (240 minutes of readings) before it alerts.
	f.exec(`UPDATE windows_module_conditions SET since = now() - interval '5 hours'`)
	f.evaluate()
	if f.open("defender_update_failed") != 1 || f.open("defender_unhealthy") != 1 {
		t.Errorf("update failed %d, unhealthy %d", f.open("defender_update_failed"), f.open("defender_unhealthy"))
	}
	g := batch(4, ev(3, 2000, 0, nil), ev(4, 3007, 0, nil))
	g.Gap = true
	f.ingest(g)
	f.evaluate()
	if f.open("defender_update_failed") != 0 || f.open("defender_unhealthy") != 0 {
		t.Errorf("update failed %d, unhealthy %d after recovery", f.open("defender_update_failed"), f.open("defender_unhealthy"))
	}
	var tech access.Caller
	{
		uid := f.id(`INSERT INTO users (email, display_name) VALUES ('t@example.com', 't') RETURNING id`)
		p, err := rbac.NewPrincipal(uid, []rbac.Assignment{{Role: rbac.RoleTechnician, OrganizationID: f.acme}})
		if err != nil {
			t.Fatal(err)
		}
		tech = access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: uid, Label: "t"})
	}
	list, err := f.store.List(f.ctx, f.mods, tech, f.dev, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 4 || list.Gap == nil {
		t.Fatalf("%d events, gap %v", len(list.Items), list.Gap)
	}

	// Sensitive text only for who holds view_sensitive.
	f.ingest(batch(5, detection(5, "T1", "Virus:DOS/EICAR_Test_File", "Severe", 0)))
	for who, want := range map[string]bool{"technician": false, "org_admin": true} {
		uid := f.id(`INSERT INTO users (email, display_name) VALUES ($1, 'x') RETURNING id`, who+"@example.com")
		p, err := rbac.NewPrincipal(uid, []rbac.Assignment{{Role: rbac.Role(who), OrganizationID: f.acme}})
		if err != nil {
			t.Fatal(err)
		}
		c := access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: uid, Label: who})
		list, err := f.store.List(f.ctx, f.mods, c, f.dev, 50)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(list)
		if got := strings.Contains(string(raw), "alice"); got != want {
			t.Errorf("%s sees the user name = %v, want %v", who, got, want)
		}
		if strings.Contains(string(raw), `"summary"`) && strings.Contains(strings.SplitN(string(raw), `"sensitive"`, 2)[0], "alice") {
			t.Errorf("%s: a summary holds the user name", who)
		}
	}

	// Module off: nothing is enabled, nothing is judged, open alerts resolve.
	f.ingest(batch(6, detection(6, "T7", "Second:Threat", "High", 0)))
	f.evaluate()
	if f.open("defender_threat") == 0 {
		t.Fatal("no threat alert to turn off")
	}
	if err := f.mods.SetEnabled(f.ctx, adminCaller(t, f), modules.AtOrganization, f.acme, modules.Defender, false); err != nil {
		t.Fatal(err)
	}
	err = f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		if f.store.Enabled(f.ctx, tx, f.dev, f.acme, f.hq) {
			t.Error("the log is enabled with the module off")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	f.evaluate()
	if f.open("defender_threat") != 0 {
		t.Error("a threat alert stayed open with the module off")
	}
}

func adminCaller(t *testing.T, f *fx) access.Caller {
	t.Helper()
	uid := f.id(`INSERT INTO users (email, display_name) VALUES ('admin@example.com', 'a') RETURNING id`)
	p, err := rbac.NewPrincipal(uid, []rbac.Assignment{{Role: rbac.RoleSuperAdmin}})
	if err != nil {
		t.Fatal(err)
	}
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: uid, Label: "admin"})
}

// Retention: paths and users go after 30 days, the row after 90.
func TestRetention(t *testing.T) {
	f := newFx(t)
	f.ingest(batch(2, detection(1, "T1", "A", "High", time.Minute), detection(2, "T2", "B", "High", time.Minute)))
	f.exec(`UPDATE defender_events SET received_at = now() - interval '31 days' WHERE record_id = 1`)
	f.exec(`UPDATE defender_events SET received_at = now() - interval '91 days' WHERE record_id = 2`)
	if err := f.store.Cleanup(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM defender_events WHERE device_id = $1`, f.dev); n != 1 {
		t.Errorf("%d rows after cleanup, want 1", n)
	}
	if n := f.count(`SELECT count(*) FROM defender_events WHERE device_id = $1 AND sensitive IS NOT NULL`, f.dev); n != 0 {
		t.Errorf("%d rows keep their sensitive text past 30 days", n)
	}
	// A device removed takes its events with it.
	f.exec(`DELETE FROM devices WHERE id = $1`, f.dev)
	if n := f.count(`SELECT count(*) FROM defender_events`); n != 0 {
		t.Errorf("%d events remain after the device was deleted", n)
	}
}
