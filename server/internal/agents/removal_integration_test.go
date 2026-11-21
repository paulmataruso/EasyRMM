//go:build integration

package agents

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

var agentIP = netip.MustParseAddr("192.0.2.10")

// uninstallOf sends d's heartbeat and returns its uninstall instruction,
// verified, or nil; it fails the test if the answer carries an update too.
func (f *updates) uninstallOf(d *Device) *agentproto.UninstallPayload {
	f.t.Helper()
	resp, err := f.svc.Heartbeat(f.ctx, d, agentIP, agentproto.HeartbeatRequest{
		Facts: agentproto.Facts{Hostname: "h", Platform: "linux", Arch: "amd64", AgentVersion: "v1", AgentSHA256: oldSHA},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	if resp.Uninstall == nil {
		return nil
	}
	if resp.Update != nil {
		f.t.Error("an update came with the uninstall instruction")
	}
	p, err := agentproto.VerifyUninstall(f.pub, *resp.Uninstall, d.ID.String(), f.clock)
	if err != nil {
		f.t.Fatalf("instruction: %v", err)
	}
	if !p.ExpiresAt.Equal(f.clock.Add(UninstallValid)) {
		f.t.Errorf("expires %v", p.ExpiresAt)
	}
	return &p
}

func (f *updates) removalOf(id uuid.UUID) *devices.Removal {
	f.t.Helper()
	d, err := devices.Lookup(f.ctx, f.db, f.sys, id)
	if err != nil {
		f.t.Fatal(err)
	}
	return d.Removal
}

func (f *updates) audited(action string, id uuid.UUID) int {
	f.t.Helper()
	return f.count(`SELECT count(*) FROM audit_log WHERE action = $1 AND device_id = $2`, action, id)
}

func TestDeviceRemoval(t *testing.T) {
	f := newUpdates(t, "new build", "v2")
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: f.org, SiteID: f.hq})
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.org, SiteID: f.hq})
	d, key := f.enroll(f.hq, "pc-1")
	f.beat(d, "pc-1", nodeHex())
	node := f.nodeOf(d.ID)
	d = f.auth(d.ID.String(), key)

	// Technicians may not remove devices; a device elsewhere is not found.
	if _, err := f.svc.RequestRemoval(f.ctx, tech, d.ID); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("technician: %v", err)
	}
	if _, err := f.svc.RequestRemoval(f.ctx, admin, uuid.New()); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("unknown device: %v", err)
	}
	if dev, _ := devices.Lookup(f.ctx, f.db, tech, d.ID); dev.Removal != nil {
		t.Error("removal before anyone asked")
	}

	// A site administrator asks: the device waits for its agent.
	if st, err := f.svc.RequestRemoval(f.ctx, admin, d.ID); err != nil || st != RemovalAsked {
		t.Fatalf("request: %q %v", st, err)
	}
	if r := f.removalOf(d.ID); r == nil || r.SentAt != nil || r.Error != "" {
		t.Fatalf("removal %+v", r)
	}
	p1 := f.uninstallOf(d)
	if p1 == nil {
		t.Fatal("no instruction")
	}
	if r := f.removalOf(d.ID); r.SentAt == nil {
		t.Error("sending not recorded")
	}
	// Repeated while nothing is reported, for the same removal.
	if p := f.uninstallOf(d); p == nil || p.ID != p1.ID {
		t.Errorf("repeat %+v", p)
	}

	// The agent could not remove its service: recorded, and not sent again.
	if err := f.svc.Removed(f.ctx, d, agentIP, agentproto.RemovedReport{ID: "another", Error: "stale"}); err != nil {
		t.Fatal(err)
	}
	if r := f.removalOf(d.ID); r.Error != "" {
		t.Errorf("a report of another removal counted: %+v", r)
	}
	if err := f.svc.Removed(f.ctx, d, agentIP, agentproto.RemovedReport{ID: p1.ID, Error: "access\x00 denied"}); err != nil {
		t.Fatal(err)
	}
	if r := f.removalOf(d.ID); r.Error != "access denied" || r.ReportedAt == nil {
		t.Errorf("failure %+v", r)
	}
	if p := f.uninstallOf(d); p != nil {
		t.Error("sent again after a failure")
	}
	if n := f.audited("device.removal_failed", d.ID); n != 1 {
		t.Errorf("failure audited %d times", n)
	}

	// Asking again sends a new instruction.
	if _, err := f.svc.RequestRemoval(f.ctx, admin, d.ID); err != nil {
		t.Fatal(err)
	}
	p2 := f.uninstallOf(d)
	if p2 == nil || p2.ID == p1.ID {
		t.Fatalf("second request %+v", p2)
	}
	if r := f.removalOf(d.ID); r.Error != "" || r.ReportedAt != nil {
		t.Errorf("second request %+v", r)
	}

	// Canceled: nothing more is sent. Only a removal can be canceled.
	if err := f.svc.CancelRemoval(f.ctx, tech, d.ID); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("technician cancels: %v", err)
	}
	if err := f.svc.CancelRemoval(f.ctx, admin, d.ID); err != nil {
		t.Fatal(err)
	}
	if p := f.uninstallOf(d); p != nil || f.removalOf(d.ID) != nil {
		t.Error("still removing after canceling")
	}
	var ae *apperr.Error
	if err := f.svc.CancelRemoval(f.ctx, admin, d.ID); !errors.As(err, &ae) || ae.Code != "not_removing" {
		t.Errorf("canceling twice: %v", err)
	}

	// Asked once more, the agent removes itself; MeshAgent stays behind. The
	// device goes; its node is remembered for MeshCentral's sync, its key
	// is not.
	if _, err := f.svc.RequestRemoval(f.ctx, admin, d.ID); err != nil {
		t.Fatal(err)
	}
	p3 := f.uninstallOf(d)
	linked := f.mesh.linked
	if err := f.svc.Removed(f.ctx, d, agentIP, agentproto.RemovedReport{ID: p3.ID, Removed: true, Error: "MeshAgent was not removed: busy"}); err != nil {
		t.Fatal(err)
	}
	if _, err := devices.Lookup(f.ctx, f.db, f.sys, d.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("device after removal: %v", err)
	}
	if n := f.count(`SELECT count(*) FROM retired_devices WHERE device_id = $1 AND mesh_node_id = $2 AND agent_public_key IS NULL
			AND expires_at > now() + interval '89 days'`, d.ID, node); n != 1 {
		t.Errorf("retired rows %d", n)
	}
	if f.mesh.linked == linked {
		t.Error("MeshCentral's sync not asked to run")
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.remove' AND device_id = $1 AND actor_type = 'agent'
			AND details->>'confirmed' = 'true' AND details->>'error' LIKE 'MeshAgent was not removed%'`, d.ID); n != 1 {
		t.Errorf("removal audited %d times", n)
	}
	for _, a := range []string{"device.removal_request", "device.removal_cancel"} {
		if n := f.audited(a, d.ID); n == 0 {
			t.Errorf("%s not audited", a)
		}
	}
	// The agent is gone for good: its key opens nothing.
	if _, err := f.svc.BeginSigned(f.ctx, header(t, key, d.ID, f.clock)); !errors.Is(err, ErrUnknownDevice) {
		t.Errorf("removed agent: %v", err)
	}
	// A late report of the same removal finds no device.
	if err := f.svc.Removed(f.ctx, d, agentIP, agentproto.RemovedReport{ID: p3.ID, Removed: true}); !errors.Is(err, ErrUnknownDevice) {
		t.Errorf("late report: %v", err)
	}
}

// An agent whose removal was canceled after it started uninstalling still
// has its device deleted when it reports.
func TestRemovalReportAfterCancel(t *testing.T) {
	f := newUpdates(t, "new build", "v2")
	d, _ := f.enroll(f.hq, "pc-1")
	if _, err := f.svc.RequestRemoval(f.ctx, f.sys, d.ID); err != nil {
		t.Fatal(err)
	}
	p := f.uninstallOf(d)
	if err := f.svc.CancelRemoval(f.ctx, f.sys, d.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Removed(f.ctx, d, agentIP, agentproto.RemovedReport{ID: p.ID, Removed: true}); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM devices WHERE id = $1`, d.ID); n != 0 {
		t.Error("device kept")
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.remove' AND device_id = $1 AND details->>'removalCanceled' = 'true'`, d.ID); n != 1 {
		t.Errorf("audited %d", n)
	}
	// No node and no agent to wait for: nothing remembered.
	if n := f.count(`SELECT count(*) FROM retired_devices WHERE device_id = $1`, d.ID); n != 0 {
		t.Errorf("retired rows %d", n)
	}
}

func header(t *testing.T, key []byte, id uuid.UUID, at time.Time) string {
	t.Helper()
	h, err := agentproto.Sign(key, id.String(), "POST", agentproto.PathHeartbeat, []byte(`{}`), at)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestForcedRemoval(t *testing.T) {
	f := newUpdates(t, "new build", "v2")
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: f.org, SiteID: f.hq})
	d, key := f.enroll(f.hq, "pc-2")
	f.beat(d, "pc-2", nodeHex())
	node := f.nodeOf(d.ID)
	if _, err := f.svc.RequestRemoval(f.ctx, admin, d.ID); err != nil {
		t.Fatal(err)
	}

	// Removed without waiting: the device goes, its agent and node are
	// remembered, and the patching side is told.
	told := 0
	f.svc.OnRemoved(func() { told++ })
	if err := f.svc.ForceRemove(f.ctx, admin, d.ID); err != nil {
		t.Fatal(err)
	}
	if told != 1 {
		t.Errorf("told %d times", told)
	}
	if n := f.count(`SELECT count(*) FROM devices WHERE id = $1`, d.ID); n != 0 {
		t.Fatal("device kept")
	}
	if n := f.count(`SELECT count(*) FROM retired_devices WHERE device_id = $1 AND agent_public_key IS NOT NULL AND mesh_node_id = $2 AND name = 'pc-2'`,
		d.ID, node); n != 1 {
		t.Fatalf("retired rows %d", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.remove' AND device_id = $1 AND details->>'forced' = 'true'
			AND details ? 'removalRequested'`, d.ID); n != 1 {
		t.Errorf("forced removal audited %d times", n)
	}
	if err := f.svc.ForceRemove(f.ctx, admin, d.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("removing twice: %v", err)
	}

	// The agent comes back: it is let in for its uninstall instruction
	// only, once per request.
	h := header(t, key, d.ID, f.clock)
	rd, err := f.svc.Authenticate(f.ctx, h, "POST", agentproto.PathHeartbeat, []byte(`{}`))
	if err != nil || !rd.Retired || rd.Hostname != "pc-2" || rd.SiteID != f.hq {
		t.Fatalf("retired agent: %+v %v", rd, err)
	}
	if _, err := f.svc.Authenticate(f.ctx, h, "POST", agentproto.PathHeartbeat, []byte(`{}`)); !errors.Is(err, ErrReplay) {
		t.Errorf("replay: %v", err)
	}
	retired := func() *agentproto.UninstallPayload {
		t.Helper()
		resp, err := f.svc.RetiredHeartbeat(f.ctx, rd)
		if err != nil {
			t.Fatal(err)
		}
		if resp.JobKey != f.svc.jobKey || resp.MeshAgent.Available || resp.Update != nil {
			t.Errorf("answer %+v", resp)
		}
		if resp.Uninstall == nil {
			return nil
		}
		p, err := agentproto.VerifyUninstall(f.pub, *resp.Uninstall, d.ID.String(), f.clock)
		if err != nil {
			t.Fatal(err)
		}
		return &p
	}
	p := retired()
	if p == nil || p.ID != d.ID.String() {
		t.Fatalf("instruction %+v", p)
	}

	// It cannot remove its service: asked again only after RetiredRetry.
	if err := f.svc.Removed(f.ctx, rd, agentIP, agentproto.RemovedReport{ID: p.ID, Error: "busy"}); err != nil {
		t.Fatal(err)
	}
	if retired() != nil {
		t.Error("asked again at once")
	}
	f.clock = f.clock.Add(RetiredRetry + time.Second)
	if p = retired(); p == nil {
		t.Fatal("not asked again")
	}

	// It removes itself: no longer waited for, its node still is.
	if err := f.svc.Removed(f.ctx, rd, agentIP, agentproto.RemovedReport{ID: p.ID, Removed: true}); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM retired_devices WHERE device_id = $1 AND agent_public_key IS NULL AND cleaned_at IS NOT NULL
			AND mesh_node_id = $2`, d.ID, node); n != 1 {
		t.Errorf("cleaned rows %d", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.retired_cleanup' AND device_id = $1`, d.ID); n != 2 {
		t.Errorf("cleanup audited %d times", n)
	}
	if _, err := f.svc.BeginSigned(f.ctx, header(t, key, d.ID, f.clock)); !errors.Is(err, ErrUnknownDevice) {
		t.Errorf("cleaned agent: %v", err)
	}
	if err := f.svc.Removed(f.ctx, rd, agentIP, agentproto.RemovedReport{Removed: true}); err != nil {
		t.Errorf("a second report: %v", err)
	}
	if _, err := f.svc.RetiredHeartbeat(f.ctx, &Device{ID: uuid.New(), Retired: true}); !errors.Is(err, ErrUnknownDevice) {
		t.Errorf("unknown retired device: %v", err)
	}

	// The nonces of retired agents expire like the others, and the rows go
	// after RetiredFor.
	f.exec(`UPDATE retired_agent_nonces SET expires_at = now() - interval '1 minute'`)
	f.exec(`UPDATE retired_devices SET removed_at = now() - interval '91 days', expires_at = now() - interval '1 day'`)
	if err := f.svc.Cleanup(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM retired_devices`) + f.count(`SELECT count(*) FROM retired_agent_nonces`); n != 0 {
		t.Errorf("%d rows after the cleanup", n)
	}
}

// A device with no EasyRMM agent, discovered through MeshCentral, is
// removed at once; a device enrolled since on the same computer keeps the
// MeshAgent node.
func TestDiscoveredDeviceRemoval(t *testing.T) {
	f := newUpdates(t, "new build", "v2")
	hex := nodeHex()
	node, err := agentproto.MeshNodeKey(hex)
	if err != nil {
		t.Fatal(err)
	}
	id := f.uuid(`INSERT INTO devices (organization_id, site_id, name, hostname, os_description, platform, mesh_node_id)
		VALUES ($1, $2, 'found', 'found', 'Linux', 'linux', $3) RETURNING id`, f.org, f.hq, node)
	if st, err := f.svc.RequestRemoval(f.ctx, f.sys, id); err != nil || st != RemovalDone {
		t.Fatalf("request: %q %v", st, err)
	}
	if n := f.count(`SELECT count(*) FROM devices WHERE id = $1`, id); n != 0 {
		t.Fatal("device kept")
	}
	if n := f.count(`SELECT count(*) FROM retired_devices WHERE device_id = $1 AND mesh_node_id = $2 AND agent_public_key IS NULL`, id, node); n != 1 {
		t.Fatalf("retired rows %d", n)
	}
	// Another site's device reporting the node does not keep it.
	other, _ := f.enroll(f.other, "elsewhere")
	f.beat(other, "elsewhere", hex)
	if n := f.count(`SELECT count(*) FROM retired_devices WHERE mesh_node_id = $1`, node); n != 1 {
		t.Error("a device of another site took the node")
	}
	// MeshCentral's sync undoes that link: the node is in this site's group.
	f.exec(`UPDATE devices SET mesh_node_id = NULL WHERE id = $1`, other.ID)
	again, _ := f.enroll(f.hq, "found")
	f.beat(again, "found", hex)
	if f.nodeOf(again.ID) != node {
		t.Fatal("not linked")
	}
	if n := f.count(`SELECT count(*) FROM retired_devices WHERE device_id = $1 AND mesh_node_id IS NULL`, id); n != 1 {
		t.Error("the enrolled device does not keep its node")
	}
}
