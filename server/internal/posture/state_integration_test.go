//go:build integration

package posture_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/devscope"
)

// snapshot stores a defender.status result as the Windows modules keep it.
func (f *fixture) snapshot(dev uuid.UUID, data string, age time.Duration) {
	f.t.Helper()
	f.exec(`DELETE FROM windows_module_snapshots WHERE device_id = $1 AND action = 'defender.status'`, dev)
	f.exec(`INSERT INTO windows_module_snapshots (device_id, module, action, params_hash, taken_at, data)
		VALUES ($1, 'defender', 'defender.status', '', now() - $2::interval, $3::jsonb)`, dev, age.String(), data)
}

func controlState(t *testing.T, reasons []reasonView, id string) (reasonView, bool) {
	t.Helper()
	for _, r := range reasons {
		if r.ControlID == id {
			return r, true
		}
	}
	return reasonView{}, false
}

type reasonView struct{ ControlID, State, Detail string }

func (f *fixture) reasons(dev uuid.UUID, platform string) []reasonView {
	f.t.Helper()
	var out []reasonView
	for _, r := range f.load(dev, platform).Reasons {
		out = append(out, reasonView{r.ControlID, r.State, r.Detail})
	}
	return out
}

func TestLinuxDiskEncryptionControl(t *testing.T) {
	f := newFixture(t)
	d := f.device("lx", "linux")
	f.module(d, "ssh", "in_place", 0, `{}`)
	if p := f.load(d, "linux"); p.Word != "meets" || *p.Percent != 100 {
		t.Fatalf("encrypted root: %+v", p)
	}

	// A report with no encrypted volume fails; it is not "cannot tell".
	f.volumes(d, "linux", "")
	p := f.load(d, "linux")
	r, ok := controlState(t, f.reasons(d, "linux"), "disk-encryption")
	if !ok || r.State != "not_in_place" || p.Word != "does not meet" || *p.Percent != 62 || p.Failing != 1 {
		t.Fatalf("no encrypted volume: %+v %+v", p, r)
	}

	// Never reported: cannot tell, and never passing.
	f.exec(`DELETE FROM device_volume_reports WHERE device_id = $1`, d)
	f.exec(`DELETE FROM device_encrypted_volumes WHERE device_id = $1`, d)
	r, _ = controlState(t, f.reasons(d, "linux"), "disk-encryption")
	if r.State != "unknown" || f.load(d, "linux").Word != "cannot tell" {
		t.Fatalf("never reported: %+v", r)
	}

	// A report older than the organization's window is stale.
	f.volumes(d, "linux", "luks2")
	f.exec(`UPDATE device_volume_reports SET reported_at = now() - interval '40 days' WHERE device_id = $1`, d)
	f.exec(`UPDATE device_encrypted_volumes SET reported_at = now() - interval '40 days' WHERE device_id = $1`, d)
	if r, _ = controlState(t, f.reasons(d, "linux"), "disk-encryption"); r.State != "stale" {
		t.Fatalf("old report: %+v", r)
	}

	// BitLocker rows say nothing about a Linux computer.
	f.volumes(d, "linux", "")
	f.exec(`INSERT INTO device_encrypted_volumes (device_id, volume_id, organization_id, site_id, kind, mount, status)
		VALUES ($1, 'bl', $2, $3, 'bitlocker', '/', 'encrypted')`, d, f.org, f.site)
	if r, _ = controlState(t, f.reasons(d, "linux"), "disk-encryption"); r.State != "not_in_place" {
		t.Fatalf("a BitLocker row counted on Linux: %+v", r)
	}
}

func TestWindowsBitLockerStateControl(t *testing.T) {
	f := newFixture(t)
	d := f.device("win", "windows")
	f.module(d, "firewall", "in_place", 0, `{}`)
	if p := f.load(d, "windows"); p.Word != "meets" {
		t.Fatalf("encrypted system volume: %+v", p)
	}
	for status, want := range map[string]string{"encrypting": "partly", "decrypted": "not_in_place", "": "not_in_place"} {
		f.volumes(d, "windows", status)
		r, ok := controlState(t, f.reasons(d, "windows"), "disk-encryption")
		if !ok || r.State != want {
			t.Errorf("status %q: %+v, want %s", status, r, want)
		}
	}
	// Another volume encrypted does not make the system volume so.
	f.volumes(d, "windows", "")
	f.exec(`INSERT INTO device_encrypted_volumes (device_id, volume_id, organization_id, site_id, kind, mount, status)
		VALUES ($1, 'dv', $2, $3, 'bitlocker', 'D:', 'encrypted')`, d, f.org, f.site)
	if r, _ := controlState(t, f.reasons(d, "windows"), "disk-encryption"); r.State != "not_in_place" {
		t.Fatalf("D: encrypted: %+v", r)
	}
}

func TestWindowsDefenderHealthControl(t *testing.T) {
	f := newFixture(t)
	d := f.device("win", "windows")
	f.module(d, "firewall", "in_place", 0, `{}`)

	// No snapshot (the module is off): the control is not there, and nothing is claimed.
	if _, ok := controlState(t, f.reasons(d, "windows"), "defender-health"); ok || len(f.reasons(d, "windows")) != 0 {
		t.Fatalf("a control with no snapshot: %+v", f.reasons(d, "windows"))
	}
	before := *f.load(d, "windows").Percent

	f.snapshot(d, `{"realTimeProtectionEnabled":true,"antivirusEnabled":true,"runningMode":"Normal","signatureAgeDays":1,"quickScanAgeDays":2}`, 0)
	p := f.load(d, "windows")
	if p.Word != "meets" || p.Applicable != 11 || p.Passing != 11 {
		t.Fatalf("healthy Defender weighs 3: %+v (before %d)", p, before)
	}

	f.snapshot(d, `{"realTimeProtectionEnabled":false,"signatureAgeDays":12,"quickScanAgeDays":2}`, 0)
	r, ok := controlState(t, f.reasons(d, "windows"), "defender-health")
	if !ok || r.State != "not_in_place" || r.Detail != "Real-time protection is off. Signatures are 12 days old." {
		t.Fatalf("real-time off: %+v", r)
	}
	if p := f.load(d, "windows"); p.Word != "does not meet" || *p.Percent != 72 {
		t.Fatalf("score with Defender failing: %+v", p)
	}

	f.snapshot(d, `{"realTimeProtectionEnabled":true,"runningMode":"Passive mode"}`, 0)
	if p := f.load(d, "windows"); p.NotApplicable != 1 || p.Word != "meets" {
		t.Fatalf("passive mode leaves the score: %+v", p)
	}

	f.snapshot(d, `{"realTimeProtectionEnabled":true,"signatureAgeDays":1,"quickScanAgeDays":2}`, 40*24*time.Hour)
	if r, _ := controlState(t, f.reasons(d, "windows"), "defender-health"); r.State != "stale" {
		t.Fatalf("an old snapshot: %+v", r)
	}

	// A Linux computer has no Defender, whatever a snapshot row says.
	l := f.device("lx", "linux")
	f.snapshot(l, `{"realTimeProtectionEnabled":false}`, 0)
	if _, ok := controlState(t, f.reasons(l, "linux"), "defender-health"); ok {
		t.Fatal("Defender health on a Linux computer")
	}
}

func TestStateControlsFollowTheDevScope(t *testing.T) {
	f := newFixture(t)
	d := f.device("win", "windows")
	f.snapshot(d, `{"realTimeProtectionEnabled":false}`, 0)
	f.volumes(d, "windows", "")
	if f.load(d, "windows") == nil {
		t.Fatal("no posture inside the scope")
	}
	defer devscope.Set(uuid.New())()
	if p := f.load(d, "windows"); p != nil {
		t.Fatalf("posture outside the dev scope: %+v", p)
	}
}
