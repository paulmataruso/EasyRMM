//go:build integration

package agents

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// ADR-0056 slice 2: the installer recorded, devices on the server's build,
// and Uninstalled (ADR-0053).

func (f *updates) heartbeatAs(d *Device, sha, installer string) *agentproto.UpdatePayload {
	f.t.Helper()
	resp, err := f.svc.Heartbeat(f.ctx, d, netip.MustParseAddr("192.0.2.10"), agentproto.HeartbeatRequest{
		Facts:     agentproto.Facts{Hostname: "h", Platform: "linux", Arch: "amd64", AgentVersion: "v1", AgentSHA256: sha},
		Installer: installer,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	if resp.Update == nil {
		return nil
	}
	p, err := agentproto.VerifyUpdate(f.pub, *resp.Update, d.ID.String(), f.clock)
	if err != nil {
		f.t.Fatalf("instruction: %v", err)
	}
	return &p
}

func (f *updates) text(sql string, args ...any) (s string) {
	f.t.Helper()
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, sql, args...).Scan(&s)
	}); err != nil {
		f.t.Fatal(err)
	}
	return s
}

func TestInstallerRecorded(t *testing.T) {
	f := newUpdates(t, "new build", "v2")
	d, _ := f.enroll(f.hq, "pc-1")
	installer := func() string {
		return f.text(`SELECT coalesce(installer, '') FROM devices WHERE id = $1`, d.ID)
	}
	f.heartbeatAs(d, sum("new build"), "")
	if got := installer(); got != "" {
		t.Fatalf("installer %q before any report", got)
	}
	f.heartbeatAs(d, sum("new build"), "deb")
	if got := installer(); got != "deb" {
		t.Fatalf("installer %q", got)
	}
	// A heartbeat that says none (an older agent, or a server that is not
	// level 2 for it) changes nothing; a value that is no package kind is
	// ignored.
	f.heartbeatAs(d, sum("new build"), "")
	f.heartbeatAs(d, sum("new build"), "zip")
	if got := installer(); got != "deb" {
		t.Fatalf("installer %q after heartbeats that named none", got)
	}
	f.heartbeatAs(d, sum("new build"), "rpm")
	if got := installer(); got != "rpm" {
		t.Fatalf("installer %q after another package took over", got)
	}
}

func TestNewDeviceOnTheServersBuild(t *testing.T) {
	f := newUpdates(t, "new build", "v2")
	ran := func(d *Device) bool {
		return f.count(`SELECT count(*) FROM devices WHERE id = $1 AND ran_server_build_at IS NOT NULL`, d.ID) == 1
	}

	// Under When asked a new device is updated at its first heartbeat.
	if _, err := f.svc.SetUpdatePolicy(f.ctx, f.sys, UpdatePolicy{Mode: UpdateManual, MaxConcurrent: 5}); err != nil {
		t.Fatal(err)
	}
	d, _ := f.enroll(f.hq, "pc-new")
	if ran(d) {
		t.Fatal("a device enrolled after the migration is not new")
	}
	p := f.heartbeatAs(d, oldSHA, "msi")
	if p == nil || p.SHA256 != sum("new build") {
		t.Fatalf("a new device was not told to update under When asked: %+v", p)
	}
	// It comes back on the server's build: the column is set.
	if p := f.heartbeatAs(d, sum("new build"), "msi"); p != nil {
		t.Fatal("told to update again")
	}
	if !ran(d) {
		t.Fatal("the column is not set after a heartbeat on the served build")
	}
	// Held by the mode from now on: another build is not pushed.
	f.serve("newer build", "v3")
	if p := f.heartbeatAs(d, sum("new build"), "msi"); p != nil {
		t.Fatalf("When asked did not hold a device that had run the server's build: %+v", p)
	}
	// A rollback to an older build leaves it set, too.
	f.serve("new build", "v2")
	f.heartbeatAs(d, oldSHA, "msi")
	if !ran(d) {
		t.Fatal("the column was cleared")
	}
	if p := f.heartbeatAs(d, oldSHA, "msi"); p != nil {
		t.Fatalf("held device updated under When asked: %+v", p)
	}

	// Off holds a new device as well.
	if _, err := f.svc.SetUpdatePolicy(f.ctx, f.sys, UpdatePolicy{Mode: UpdateOff, MaxConcurrent: 5}); err != nil {
		t.Fatal(err)
	}
	n, _ := f.enroll(f.hq, "pc-off")
	if p := f.heartbeatAs(n, oldSHA, ""); p != nil {
		t.Fatalf("a new device was updated under Off: %+v", p)
	}
	if ran(n) {
		t.Fatal("column set for a device on another build")
	}
}

func TestMigrationLeavesEnrolledDevicesNotNew(t *testing.T) {
	// testdb applies every migration to an empty database, so the backfill is
	// shown by replaying its statement on a device that is new.
	f := newUpdates(t, "new build", "v2")
	d, _ := f.enroll(f.hq, "pc-old-enrollment")
	if f.count(`SELECT count(*) FROM devices WHERE id = $1 AND ran_server_build_at IS NULL`, d.ID) != 1 {
		t.Fatal("expected a new device")
	}
	f.exec(`UPDATE devices SET ran_server_build_at = now() WHERE agent_public_key IS NOT NULL`)
	if _, err := f.svc.SetUpdatePolicy(f.ctx, f.sys, UpdatePolicy{Mode: UpdateManual, MaxConcurrent: 5}); err != nil {
		t.Fatal(err)
	}
	if p := f.heartbeatAs(d, oldSHA, ""); p != nil {
		t.Fatalf("a device enrolled before the migration was updated under When asked: %+v", p)
	}
}

func TestUninstalledReport(t *testing.T) {
	f := newUpdates(t, "new build", "v2")
	d, _ := f.enroll(f.hq, "pc-gone")
	ip := netip.MustParseAddr("192.0.2.10")
	f.heartbeatAs(d, sum("new build"), "deb")

	if err := f.svc.Uninstalled(f.ctx, d, ip, agentproto.UninstalledReport{Installer: "zip"}); !errors.Is(err, ErrBadReport) {
		t.Fatalf("a report naming no package kind: %v", err)
	}
	if err := f.svc.Uninstalled(f.ctx, d, ip, agentproto.UninstalledReport{Installer: "deb"}); err != nil {
		t.Fatal(err)
	}
	// Marked, not deleted; the installer says how; one notice, audited.
	if f.count(`SELECT count(*) FROM devices WHERE id = $1 AND agent_uninstalled_at IS NOT NULL AND agent_uninstalled_installer = 'deb'`, d.ID) != 1 {
		t.Fatal("device not marked Uninstalled with its installer")
	}
	if n := f.count(`SELECT count(*) FROM notices WHERE kind = $1 AND subject = $2 AND resolved_at IS NULL AND device_id = $3 AND detail LIKE '%DEB package%'`,
		NoticeAgentUninstalled, d.ID.String(), d.ID); n != 1 {
		t.Fatalf("%d open notices", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.agent_uninstalled' AND device_id = $1`, d.ID); n != 1 {
		t.Fatalf("%d audit rows", n)
	}
	// Said again (a second removal script, a retry): still one notice.
	if err := f.svc.Uninstalled(f.ctx, d, ip, agentproto.UninstalledReport{}); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM notices WHERE kind = $1 AND subject = $2 AND resolved_at IS NULL`, NoticeAgentUninstalled, d.ID.String()); n != 1 {
		t.Fatalf("%d open notices after a second report", n)
	}
	// An agent that comes back (restored from a backup) clears the mark and
	// resolves the notice.
	f.heartbeatAs(d, sum("new build"), "deb")
	if f.count(`SELECT count(*) FROM devices WHERE id = $1 AND agent_uninstalled_at IS NULL AND agent_uninstalled_installer IS NULL`, d.ID) != 1 {
		t.Fatal("the mark survived a heartbeat")
	}
	if n := f.count(`SELECT count(*) FROM notices WHERE kind = $1 AND subject = $2 AND resolved_at IS NULL`, NoticeAgentUninstalled, d.ID.String()); n != 0 {
		t.Fatalf("%d open notices after the agent came back", n)
	}
}

func TestUninstalledResolvesAlerts(t *testing.T) {
	f := newUpdates(t, "new build", "v2")
	d, _ := f.enroll(f.hq, "pc-alerts")
	pol := f.uuid(`INSERT INTO alert_policies (organization_id, name, kind, minutes, severity) VALUES ($1, 'Offline', 'offline', 5, 'warning') RETURNING id`, f.org)
	f.exec(`INSERT INTO alerts (policy_id, device_id, name, kind, minutes, severity, value, last_value)
		VALUES ($1, $2, 'Offline', 'offline', 5, 'warning', 1, 1)`, pol, d.ID)
	if err := f.svc.Uninstalled(f.ctx, d, netip.MustParseAddr("192.0.2.10"), agentproto.UninstalledReport{}); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM alerts WHERE device_id = $1 AND status = 'resolved' AND resolution = 'uninstalled'`, d.ID); n != 1 {
		t.Fatalf("%d alerts resolved as uninstalled", n)
	}
}

func TestRemovedWithoutRequestMarksTheDevice(t *testing.T) {
	f := newUpdates(t, "new build", "v2")
	d, _ := f.enroll(f.hq, "pc-unasked")
	ip := netip.MustParseAddr("192.0.2.10")
	// Nobody asked for the removal: the report marks the device instead of
	// deleting it.
	if err := f.svc.Removed(f.ctx, d, ip, agentproto.RemovedReport{ID: "made up", Removed: true}); err != nil {
		t.Fatal(err)
	}
	if f.count(`SELECT count(*) FROM devices WHERE id = $1 AND agent_uninstalled_at IS NOT NULL`, d.ID) != 1 {
		t.Fatal("device deleted or not marked")
	}
	if n := f.count(`SELECT count(*) FROM notices WHERE kind = $1 AND subject = $2 AND resolved_at IS NULL`, NoticeAgentUninstalled, d.ID.String()); n != 1 {
		t.Fatalf("%d open notices", n)
	}
}
