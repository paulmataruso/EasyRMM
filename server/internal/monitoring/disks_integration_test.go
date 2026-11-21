//go:build integration

package monitoring

import (
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/hardware"
)

// Disk health alerts (ADR-0065): readings go in through the hardware
// service, as the agent API stores them.

var (
	read    = agentproto.Read
	notKept = agentproto.NotRead(agentproto.FactUnsupported, agentproto.ReasonNotKept)
)

func nvmeDisk(name, serial string, criticalWarning int64) agentproto.DiskHealth {
	return agentproto.DiskHealth{
		Name: name, Model: "Example NVMe 1TB", Serial: serial, State: agentproto.FactRead, Protocol: agentproto.ProtocolNVMe,
		Route: "nvme", ReadAt: time.Now(), CriticalWarning: read(criticalWarning), SMARTStatus: notKept, Thresholds: notKept,
		Temperature: read(40), TemperatureLimit: read(70), Wear: read(3), AvailableSpare: read(100), AvailableSpareThreshold: read(10),
		MediaErrors: read(0), ReallocatedSectors: notKept, PendingSectors: notKept, UncorrectableSectors: notKept,
		DriveErrors: read(0), PowerOnHours: read(1200), DataWritten: read(5000), UnsafeShutdowns: read(4), PowerMode: notKept,
	}
}

func ataDisk(name, serial string, status, reallocated, pending int64) agentproto.DiskHealth {
	return agentproto.DiskHealth{
		Name: name, Model: "Example SSD 500GB", Serial: serial, State: agentproto.FactRead, Protocol: agentproto.ProtocolATA,
		Route: "sg", ReadAt: time.Now(), CriticalWarning: notKept, SMARTStatus: read(status), Thresholds: read(0),
		Temperature: read(35), TemperatureLimit: notKept, Wear: read(10), AvailableSpare: notKept, AvailableSpareThreshold: notKept,
		MediaErrors: notKept, ReallocatedSectors: read(reallocated), PendingSectors: read(pending), UncorrectableSectors: read(0),
		DriveErrors: read(0), PowerOnHours: read(9000), DataWritten: notKept, UnsafeShutdowns: notKept, PowerMode: read(0xff),
	}
}

func asleepDisk(name, model, serial string) agentproto.DiskHealth {
	return agentproto.DiskHealth{Name: name, Model: model, Serial: serial, State: agentproto.FactUnknown, Reason: agentproto.ReasonAsleep}
}

type diskFixture struct {
	*fixture
	hw *hardware.Service
}

func newDiskFixture(t *testing.T) *diskFixture {
	f := &diskFixture{fixture: newFixture(t)}
	f.hw = hardware.New(f.db, 7*24*time.Hour, 730*24*time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.exec(`UPDATE alert_policies SET enabled = false`)
	return f
}

func (f *diskFixture) report(device uuid.UUID, disks ...agentproto.DiskHealth) {
	f.t.Helper()
	body, err := json.Marshal(agentproto.HardwareReport{Disks: disks})
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.hw.Record(f.ctx, device, body); err != nil {
		f.t.Fatal(err)
	}
}

// enable turns on the shared disk health policy with check.
func (f *diskFixture) enable(check string) {
	f.exec(`UPDATE alert_policies SET enabled = true WHERE kind = 'disk_health' AND check_name = $1`, check)
}

// diskAlert is the unresolved alert on a disk, by its name.
func (f *diskFixture) diskAlert(device uuid.UUID, policy, label string) *Alert {
	f.t.Helper()
	for _, a := range f.alerts(FilterActive) {
		if a.DeviceID == device && a.Name == policy && a.SubjectLabel == label {
			return a
		}
	}
	return nil
}

func TestDiskFailingAlerts(t *testing.T) {
	f := newDiskFixture(t)
	f.enable(CheckFailing)
	dev := f.device(f.acme, f.hq, "srv-01", 0)
	f.report(dev, nvmeDisk("nvme0n1", "N1", 1<<3), ataDisk("sda", "A1", agentproto.SMARTThresholdExceeded, 0, 0), nvmeDisk("nvme1n1", "N2", 0))

	// Two failing disks: two alerts, each about its disk.
	if r := f.evaluate(); r.Opened != 2 {
		t.Fatalf("opened %d", r.Opened)
	}
	n := f.diskAlert(dev, "Disk failing", "nvme0n1 · Example NVMe 1TB")
	s := f.diskAlert(dev, "Disk failing", "sda · Example SSD 500GB")
	if n == nil || s == nil {
		t.Fatalf("alerts %+v", f.alerts(FilterActive))
	}
	if n.Kind != KindDiskHealth || n.CheckName == nil || *n.CheckName != CheckFailing || n.Severity != SeverityCritical || n.Value != 1 ||
		n.Detail != "NVMe critical warning: media read-only" || len(n.Subject) != 32 || n.Subject == s.Subject || n.Threshold != nil {
		t.Errorf("nvme0n1's alert %+v", n)
	}
	if s.Detail != "SMART status: threshold exceeded" {
		t.Errorf("sda's alert %+v", s)
	}
	if r := f.evaluate(); r.Opened != 0 || r.Resolved != 0 {
		t.Fatalf("again: %+v", r)
	}
	// Acknowledging one leaves the other as it was.
	if _, err := f.svc.Acknowledge(f.ctx, f.super, n.ID); err != nil {
		t.Fatal(err)
	}
	if a := f.diskAlert(dev, "Disk failing", s.SubjectLabel); a == nil || a.Status != "open" {
		t.Fatalf("the other disk's alert %+v", a)
	}
	if a := f.diskAlert(dev, "Disk failing", n.SubjectLabel); a == nil || a.Status != "acknowledged" {
		t.Fatalf("acknowledged %+v", a)
	}

	// A reading that cannot tell changes nothing; one clear reading is not
	// enough; two are.
	f.report(dev, asleepDisk("nvme0n1", "Example NVMe 1TB", "N1"), ataDisk("sda", "A1", agentproto.SMARTThresholdExceeded, 0, 0))
	if r := f.evaluate(); r.Resolved != 0 || f.diskAlert(dev, "Disk failing", n.SubjectLabel) == nil {
		t.Fatalf("after an unknown reading: %+v", r)
	}
	f.report(dev, nvmeDisk("nvme0n1", "N1", 0), ataDisk("sda", "A1", agentproto.SMARTThresholdExceeded, 0, 0))
	if r := f.evaluate(); r.Resolved != 0 {
		t.Fatalf("resolved after one clear reading: %+v", r)
	}
	f.report(dev, asleepDisk("nvme0n1", "Example NVMe 1TB", "N1"), ataDisk("sda", "A1", agentproto.SMARTThresholdExceeded, 0, 0))
	f.report(dev, nvmeDisk("nvme0n1", "N1", 0), ataDisk("sda", "A1", agentproto.SMARTThresholdExceeded, 0, 0))
	if r := f.evaluate(); r.Resolved != 1 || f.diskAlert(dev, "Disk failing", n.SubjectLabel) != nil {
		t.Fatalf("after two clear readings: %+v", r)
	}
	got, err := f.svc.GetAlert(f.ctx, f.super, n.ID)
	if err != nil || got.Resolution != "cleared" || got.Detail != "Not failing" || got.LastValue != 0 {
		t.Fatalf("resolved %+v %v", got, err)
	}
	if f.diskAlert(dev, "Disk failing", s.SubjectLabel) == nil {
		t.Fatal("the other disk's alert resolved too")
	}

	// Resolved by hand while the disk is failing: it opens again.
	if _, err := f.svc.Resolve(f.ctx, f.super, s.ID); err != nil {
		t.Fatal(err)
	}
	if r := f.evaluate(); r.Opened != 1 {
		t.Fatalf("after resolving by hand: %+v", r)
	}

	// A policy that no longer covers the device resolves as for any kind.
	if _, err := f.svc.UpdatePolicy(f.ctx, f.super, *s.PolicyID, PolicyPatch{Enabled: ref(false)}); err != nil {
		t.Fatal(err)
	}
	if a := f.diskAlert(dev, "Disk failing", s.SubjectLabel); a != nil {
		t.Fatalf("still open after the policy was turned off: %+v", a)
	}
}

func TestDiskCountAlerts(t *testing.T) {
	f := newDiskFixture(t)
	dev := f.device(f.acme, f.hq, "srv-01", 0)
	errs := f.policy(f.super, PolicyInput{OrganizationID: &f.acme, Name: "Acme disk errors", Kind: KindDiskHealth,
		CheckName: ref(CheckErrors), Threshold: ref(2), Minutes: 600, Severity: SeverityWarning})
	if errs.Minutes != DiskMinutes {
		t.Errorf("an errors check's minutes: %d", errs.Minutes)
	}
	f.report(dev, ataDisk("sda", "A1", agentproto.SMARTPassed, 3, 0), nvmeDisk("nvme0n1", "N1", 0))
	f.evaluate()
	a := f.diskAlert(dev, "Acme disk errors", "sda · Example SSD 500GB")
	if a == nil || a.Value != 3 || a.Detail != "Reallocated sectors 3" || *a.Threshold != 2 {
		t.Fatalf("errors alert %+v", a)
	}
	// NVMe media errors count too.
	nv := nvmeDisk("nvme0n1", "N1", 0)
	nv.MediaErrors = read(7)
	f.report(dev, ataDisk("sda", "A1", agentproto.SMARTPassed, 4, 0), nv)
	f.evaluate()
	if b := f.diskAlert(dev, "Acme disk errors", "nvme0n1 · Example NVMe 1TB"); b == nil || b.Value != 7 || b.Detail != "Media errors 7" {
		t.Fatalf("media errors alert %+v", b)
	}
	if a = f.diskAlert(dev, "Acme disk errors", "sda · Example SSD 500GB"); a.LastValue != 4 || a.Detail != "Reallocated sectors 4" {
		t.Errorf("updated %+v", a)
	}

	// A higher threshold is a changed condition: resolved, not raised again.
	if _, err := f.svc.UpdatePolicy(f.ctx, f.super, errs.ID, PolicyPatch{Threshold: ref(10)}); err != nil {
		t.Fatal(err)
	}
	if f.lastResolution(dev) != "policy_changed" {
		t.Errorf("resolution %q", f.lastResolution(dev))
	}
	if r := f.evaluate(); r.Opened != 0 {
		t.Errorf("opened %d below the new threshold", r.Opened)
	}

	// Pending sectors: counts that fall again, so the alert resolves.
	if _, err := f.svc.UpdatePolicy(f.ctx, f.super, errs.ID, PolicyPatch{CheckName: ref(CheckPending), Threshold: ref(1), Name: ref("Pending")}); err != nil {
		t.Fatal(err)
	}
	f.report(dev, ataDisk("sda", "A1", agentproto.SMARTPassed, 4, 8))
	f.evaluate()
	p := f.diskAlert(dev, "Pending", "sda · Example SSD 500GB")
	if p == nil || p.Value != 8 || p.Detail != "Pending sectors 8, uncorrectable sectors 0" || *p.CheckName != CheckPending {
		t.Fatalf("pending alert %+v", p)
	}
	// Changing the check resolves its alerts as a changed condition.
	if _, err := f.svc.UpdatePolicy(f.ctx, f.super, errs.ID, PolicyPatch{CheckName: ref(CheckErrors), Threshold: ref(50)}); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.svc.GetAlert(f.ctx, f.super, p.ID); got.Resolution != "policy_changed" {
		t.Errorf("after changing the check: %+v", got)
	}
	if _, err := f.svc.UpdatePolicy(f.ctx, f.super, errs.ID, PolicyPatch{CheckName: ref(CheckPending), Threshold: ref(1)}); err != nil {
		t.Fatal(err)
	}
	f.evaluate()
	p = f.diskAlert(dev, "Pending", "sda · Example SSD 500GB")
	f.report(dev, ataDisk("sda", "A1", agentproto.SMARTPassed, 4, 0))
	f.report(dev, ataDisk("sda", "A1", agentproto.SMARTPassed, 4, 0))
	if r := f.evaluate(); r.Resolved != 1 {
		t.Fatalf("pending sectors read again: %+v", r)
	}
	if got, _ := f.svc.GetAlert(f.ctx, f.super, p.ID); got.Resolution != "cleared" || got.Detail != "Pending sectors 0, uncorrectable sectors 0" {
		t.Errorf("resolved %+v", got)
	}

	// Wear.
	f.enable(CheckWear)
	worn := nvmeDisk("nvme0n1", "N1", 0)
	worn.Wear = read(91)
	f.report(dev, worn)
	f.evaluate()
	if w := f.diskAlert(dev, "Disk wearing out", "nvme0n1 · Example NVMe 1TB"); w == nil || w.Value != 91 ||
		w.Detail != "91% of rated endurance used" {
		t.Fatalf("wear alert %+v", w)
	}
}

func TestDiskTemperatureAlerts(t *testing.T) {
	f := newDiskFixture(t)
	f.enable(CheckTemperature) // the drive's own limit, 60 minutes
	dev := f.device(f.acme, f.hq, "srv-01", 0)
	hot := func(c int64) agentproto.DiskHealth {
		d := nvmeDisk("nvme0n1", "N1", 0)
		d.Temperature = read(c)
		return d
	}
	// One reading at the limit is not enough.
	f.report(dev, hot(72))
	if r := f.evaluate(); r.Opened != 0 {
		t.Fatalf("opened on one reading")
	}
	// A reading below it before the policy's hour does not count; one
	// within the hour keeps it closed.
	cool := func(ago string) {
		f.exec(`INSERT INTO device_disk_health_samples (device_id, disk_key, at, state, judged, temperature, temperature_limit)
			SELECT device_id, disk_key, now() - interval '`+ago+`', 'healthy', true, 69, 70 FROM device_disk_health WHERE device_id = $1`, dev)
	}
	cool("61 minutes")
	cool("30 minutes")
	f.report(dev, hot(73))
	if r := f.evaluate(); r.Opened != 0 {
		t.Fatalf("opened with a reading below the limit in the window")
	}
	f.exec(`DELETE FROM device_disk_health_samples WHERE device_id = $1 AND temperature = 69 AND at > now() - interval '60 minutes'`, dev)
	if r := f.evaluate(); r.Opened != 1 {
		t.Fatalf("every reading of the hour at or above the limit: %+v", r)
	}
	a := f.diskAlert(dev, "Disk too hot", "nvme0n1 · Example NVMe 1TB")
	if a == nil || a.Value != 73 || a.Detail != "73 °C; the drive's own limit 70 °C" || a.Threshold != nil || a.Minutes != 60 {
		t.Fatalf("temperature alert %+v", a)
	}
	// 66 °C is not 5 °C below the limit; 65 °C twice is.
	f.report(dev, hot(66))
	f.report(dev, hot(65))
	if r := f.evaluate(); r.Resolved != 0 {
		t.Fatalf("resolved with a reading 4 °C below")
	}
	f.report(dev, hot(65))
	if r := f.evaluate(); r.Resolved != 1 {
		t.Fatalf("not resolved after two readings 5 °C below")
	}

	// A threshold in °C applies to a drive without a limit of its own.
	if _, err := f.svc.UpdatePolicy(f.ctx, f.super, *a.PolicyID, PolicyPatch{Threshold: ref(50), Minutes: ref(30)}); err != nil {
		t.Fatal(err)
	}
	warm := ataDisk("sda", "A1", agentproto.SMARTPassed, 0, 0)
	warm.Temperature = read(55)
	f.report(dev, warm)
	f.report(dev, warm)
	f.evaluate()
	if b := f.diskAlert(dev, "Disk too hot", "sda · Example SSD 500GB"); b == nil || b.Detail != "55 °C; threshold 50 °C" || *b.Threshold != 50 {
		t.Fatalf("threshold alert %+v", b)
	}
	// Back to the drive's own limit: the drive without one is not judged.
	p, err := f.svc.UpdatePolicy(f.ctx, f.super, *a.PolicyID, PolicyPatch{DriveLimit: ref(true)})
	if err != nil || p.Threshold != nil {
		t.Fatalf("drive limit %+v %v", p, err)
	}
	f.report(dev, warm)
	f.report(dev, warm)
	if r := f.evaluate(); r.Opened != 0 {
		t.Errorf("opened on a drive without a limit: %+v", r)
	}
}

func TestDiskGone(t *testing.T) {
	f := newDiskFixture(t)
	f.enable(CheckFailing)
	dev := f.device(f.acme, f.hq, "srv-01", 0)
	f.report(dev, nvmeDisk("nvme0n1", "N1", 1), ataDisk("sda", "A1", agentproto.SMARTThresholdExceeded, 0, 0),
		nvmeDisk("nvme1n1", "N2", 0))
	f.evaluate()
	label := "nvme0n1 · Example NVMe 1TB"
	a := f.diskAlert(dev, "Disk failing", label)
	if a == nil {
		t.Fatal("no alert")
	}
	inventory := func(at string, disks ...string) {
		t.Helper()
		var list []map[string]string
		for _, d := range disks {
			list = append(list, map[string]string{"name": d, "model": "Example SSD 500GB", "serial": "A1"})
		}
		b, _ := json.Marshal(map[string]any{"disks": list})
		f.exec(`INSERT INTO device_inventory (device_id, hash, data, received_at) VALUES ($1, repeat('a', 64), $2, `+at+`)
			ON CONFLICT (device_id) DO UPDATE SET data = EXCLUDED.data, received_at = EXCLUDED.received_at`, dev, b)
	}

	// Left out of a report: missing, its alert stays, nothing opens on it.
	f.report(dev, nvmeDisk("nvme1n1", "N2", 0))
	if r := f.evaluate(); r.Opened != 0 || r.Resolved != 0 || f.diskAlert(dev, "Disk failing", label) == nil {
		t.Fatalf("missing: %+v", r)
	}
	// Resolved by hand, a missing disk's alert stays resolved: its last
	// reading was failing, but nothing opens on a missing disk.
	sda := f.diskAlert(dev, "Disk failing", "sda · Example SSD 500GB")
	if _, err := f.svc.Resolve(f.ctx, f.super, sda.ID); err != nil {
		t.Fatal(err)
	}
	if r := f.evaluate(); r.Opened != 0 || f.diskAlert(dev, "Disk failing", sda.SubjectLabel) != nil {
		t.Fatalf("after resolving a missing disk's alert by hand: %+v", r)
	}
	// 13 days, and an inventory without either disk since: nothing yet.
	f.exec(`UPDATE device_disk_health SET missing_since = now() - interval '13 days' WHERE missing_since IS NOT NULL`)
	inventory("now()")
	if r := f.evaluate(); r.Resolved != 0 {
		t.Fatalf("resolved after 13 days")
	}
	// 14 days, but the latest inventory came before the disk went missing.
	f.exec(`UPDATE device_disk_health SET missing_since = now() - interval '14 days' WHERE missing_since IS NOT NULL`)
	inventory("now() - interval '15 days'")
	if r := f.evaluate(); r.Resolved != 0 {
		t.Fatalf("resolved with an older inventory")
	}
	// 14 days, and a later inventory that still lists sda: only nvme0n1 is
	// gone.
	inventory("now() - interval '1 day'", "sda")
	if r := f.evaluate(); r.Resolved != 1 {
		t.Fatalf("subject gone: %+v", r)
	}
	got, err := f.svc.GetAlert(f.ctx, f.super, a.ID)
	if err != nil || got.Resolution != "subject_gone" {
		t.Fatalf("resolved %+v %v", got, err)
	}
	if n := f.count(`SELECT count(*) FROM device_disk_health WHERE device_id = $1`, dev); n != 2 {
		t.Errorf("%d disks left, want sda (still in the inventory) and nvme1n1", n)
	}
	if n := f.count(`SELECT count(*) FROM device_disk_health_samples WHERE device_id = $1 AND disk_key = $2`, dev, a.Subject); n == 0 {
		t.Error("the gone disk's history went with it")
	}
	if got, _ := f.svc.GetAlert(f.ctx, f.super, sda.ID); got.Resolution != "manual" {
		t.Errorf("sda's alert %+v", got)
	}
}

func TestDiskPolicies(t *testing.T) {
	f := newFixture(t)
	in := func(check *string, threshold *int, minutes int) PolicyInput {
		return PolicyInput{Name: "Disks", Kind: KindDiskHealth, CheckName: check, Threshold: threshold, Minutes: minutes, Severity: SeverityWarning}
	}
	for name, c := range map[string]struct {
		in    PolicyInput
		field string
	}{
		"no check":                {in(nil, nil, 30), "checkName"},
		"unknown check":           {in(ref("smart"), nil, 30), "checkName"},
		"errors without a count":  {in(ref(CheckErrors), nil, 30), "threshold"},
		"pending above 100":       {in(ref(CheckPending), ref(101), 30), "threshold"},
		"wear without a percent":  {in(ref(CheckWear), nil, 30), "threshold"},
		"temperature over 100":    {in(ref(CheckTemperature), ref(120), 60), "threshold"},
		"temperature for 10 mins": {in(ref(CheckTemperature), nil, 10), "minutes"},
	} {
		if _, err := f.svc.CreatePolicy(f.ctx, f.super, c.in); !invalid(err, c.field) {
			t.Errorf("%s: %v", name, err)
		}
	}
	p := f.policy(f.super, in(ref(CheckFailing), ref(5), 900))
	if p.Threshold != nil || p.Minutes != DiskMinutes || *p.CheckName != CheckFailing {
		t.Errorf("failing %+v", p)
	}
	// Away from disk health, the check goes.
	up, err := f.svc.UpdatePolicy(f.ctx, f.super, p.ID, PolicyPatch{Kind: ref(KindCPU), Threshold: ref(90)})
	if err != nil || up.CheckName != nil {
		t.Fatalf("to processor: %+v %v", up, err)
	}
	if _, err := f.svc.UpdatePolicy(f.ctx, f.super, p.ID, PolicyPatch{Kind: ref(KindDiskHealth)}); !invalid(err, "checkName") {
		t.Errorf("disk health without a check: %v", err)
	}
	up, err = f.svc.UpdatePolicy(f.ctx, f.super, p.ID, PolicyPatch{Kind: ref(KindDiskHealth), CheckName: ref(CheckTemperature), Minutes: ref(45)})
	if err != nil || *up.CheckName != CheckTemperature || *up.Threshold != 90 || up.Minutes != 45 {
		t.Fatalf("to temperature: %+v %v", up, err)
	}
	// Both changes of check are audited as such.
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'alert_policy.update' AND details->'changes' ? 'checkName'`); n != 2 {
		t.Errorf("%d check changes audited", n)
	}
}
