//go:build integration

package monitoring

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/inventory"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// interval makes a device's agent use an interval, with the online window
// the heartbeat would have set (ADR-0058).
func (f *fixture) interval(device uuid.UUID, seconds int) {
	f.t.Helper()
	f.exec(`UPDATE devices SET agent_heartbeat_seconds = $2, agent_online_until = agent_last_seen_at + make_interval(secs => 3 * $2) WHERE id = $1`, device, seconds)
}

// sampleAt stores one measurement the given seconds ago.
func (f *fixture) sampleAt(device uuid.UUID, agoSeconds int, cpu, memory, disk float64) {
	f.t.Helper()
	f.exec(`INSERT INTO device_metric_samples (device_id, at, cpu_percent, memory_percent, swap_percent, disk_percent, load1)
		VALUES ($1, now() - make_interval(secs => $2), $3, $4, 0, $5, 0.5)`, device, agoSeconds, cpu, memory, disk)
}

func (f *fixture) agoSeconds(device uuid.UUID, secs int) {
	f.t.Helper()
	f.exec(`UPDATE devices SET agent_last_seen_at = now() - make_interval(secs => $2), agent_online_until = now() - make_interval(secs => $2) + make_interval(secs => 3 * agent_heartbeat_seconds) WHERE id = $1`, device, secs)
}

// Offline at 300 seconds: a device counts as offline after three
// intervals, so no alert opens before 15 minutes and one does after, even
// for a policy of 3 minutes.
func TestOfflinePolicyAtThreeHundredSeconds(t *testing.T) {
	f := newFixture(t)
	f.exec(`UPDATE alert_policies SET enabled = false`)
	f.policy(f.super, PolicyInput{Name: "Offline", Kind: KindOffline, Minutes: MinOfflineMinutes, Severity: SeverityCritical})
	slow := f.device(f.acme, f.hq, "slow", 0)
	fast := f.device(f.acme, f.hq, "fast", 0)
	f.interval(slow, 300)
	// 10 minutes quiet: the slow device has missed two intervals, the fast
	// one ten.
	f.agoSeconds(slow, 10*60)
	f.agoSeconds(fast, 10*60)
	f.evaluate()
	if f.alertOn(slow, "Offline") != nil {
		t.Error("an alert opened for a 300-second device after 10 minutes")
	}
	if f.alertOn(fast, "Offline") == nil {
		t.Error("no alert for the 60-second device after 10 minutes")
	}
	// 14 minutes 50 seconds: still within three intervals. 15 minutes 10
	// seconds: beyond.
	f.agoSeconds(slow, 14*60+50)
	f.evaluate()
	if f.alertOn(slow, "Offline") != nil {
		t.Error("an alert opened before three intervals")
	}
	f.agoSeconds(slow, 15*60+10)
	f.evaluate()
	if a := f.alertOn(slow, "Offline"); a == nil || a.Value < 15 {
		t.Errorf("no alert after three intervals: %+v", a)
	}
	// It checks in again and the alert resolves.
	f.agoSeconds(slow, 5)
	f.evaluate()
	if f.alertOn(slow, "Offline") != nil {
		t.Error("the alert stayed open for a device that checked in")
	}
}

// Processor, memory and disk at 300 seconds: a window expects N x 60 / 300
// measurements, opens with at least half of them, rounded up, and resolves
// on the latest; with heartbeats jittered a tenth either way.
func TestMetricPoliciesAtThreeHundredSeconds(t *testing.T) {
	f := newFixture(t)
	f.exec(`UPDATE alert_policies SET enabled = false`)
	f.policy(f.super, PolicyInput{Name: "CPU", Kind: KindCPU, Threshold: ref(90), Minutes: 15, Severity: SeverityWarning})
	f.policy(f.super, PolicyInput{Name: "Memory", Kind: KindMemory, Threshold: ref(90), Minutes: 15, Severity: SeverityWarning})
	f.policy(f.super, PolicyInput{Name: "Disk", Kind: KindDisk, Threshold: ref(90), Minutes: 5, Severity: SeverityWarning})
	// A device whose measurements arrive every 300 seconds, plus or minus a
	// tenth: a 15-minute window expects 3 and needs 2; a 5-minute window
	// (never shorter than 1.2 intervals) needs its latest.
	for _, jitter := range []int{-30, 0, 30} {
		f := f
		d := f.device(f.acme, f.hq, "dev", 0)
		f.interval(d, 300)
		f.exec(`UPDATE devices SET agent_last_seen_at = now(), agent_online_until = now() + interval '15 minutes' WHERE id = $1`, d)
		f.exec(`DELETE FROM device_metric_samples WHERE device_id = $1`, d)
		// One measurement: a device that has just come back. The 15-minute
		// policies wait; the disk policy judges it.
		f.sampleAt(d, 20, 95, 95, 95)
		f.evaluate()
		if f.alertOn(d, "CPU") != nil || f.alertOn(d, "Memory") != nil {
			t.Fatalf("jitter %d: a 15-minute policy opened on one measurement", jitter)
		}
		if f.alertOn(d, "Disk") == nil {
			t.Fatalf("jitter %d: the 5-minute disk policy did not judge its latest measurement", jitter)
		}
		// Two, a jittered interval apart: half of 3, rounded up.
		f.sampleAt(d, 20+300+jitter, 95, 95, 95)
		f.evaluate()
		if f.alertOn(d, "CPU") == nil || f.alertOn(d, "Memory") == nil {
			t.Fatalf("jitter %d: no alert on 2 of 3 expected measurements", jitter)
		}
		// The latest measurement falls, but the one before it is still inside
		// the 6-minute window (never under 1.2 intervals): nothing resolves
		// early.
		f.exec(`DELETE FROM device_metric_samples WHERE device_id = $1`, d)
		f.sampleAt(d, 20, 10, 10, 10)
		f.sampleAt(d, 20+300+jitter, 95, 95, 95)
		f.evaluate()
		for _, name := range []string{"CPU", "Memory", "Disk"} {
			if f.alertOn(d, name) == nil && name != "Disk" {
				t.Fatalf("jitter %d: the %s alert resolved with a high measurement still in its window", jitter, name)
			}
		}
		// Once the old one is out of the window, the latest decides.
		f.exec(`DELETE FROM device_metric_samples WHERE device_id = $1`, d)
		f.sampleAt(d, 20, 10, 10, 10)
		f.sampleAt(d, 400+jitter, 95, 95, 95)
		f.evaluate()
		for _, name := range []string{"CPU", "Memory", "Disk"} {
			if f.alertOn(d, name) != nil {
				t.Fatalf("jitter %d: the %s alert stayed open after the latest measurement fell", jitter, name)
			}
		}
		f.exec(`DELETE FROM alerts`)
		f.exec(`DELETE FROM devices WHERE id = $1`, d)
	}
}

// A window never opens early: the measurement outside a 15-minute window
// does not count, and a 60-second device keeps today's rule.
func TestMetricWindowsKeepTodaysRuleAtSixtySeconds(t *testing.T) {
	f := newFixture(t)
	f.exec(`UPDATE alert_policies SET enabled = false`)
	f.policy(f.super, PolicyInput{Name: "CPU", Kind: KindCPU, Threshold: ref(90), Minutes: 15, Severity: SeverityWarning})
	f.policy(f.super, PolicyInput{Name: "CPU1", Kind: KindCPU, Threshold: ref(90), Minutes: 1, Severity: SeverityWarning})
	d := f.device(f.acme, f.hq, "dev", 0)
	// 7 measurements are not 8, the half of 15 rounded up.
	f.samples(d, 7, 99, 10, 10)
	f.evaluate()
	if f.alertOn(d, "CPU") != nil {
		t.Fatal("7 of 15 minutes opened an alert")
	}
	f.samples(d, 8, 99, 10, 10)
	f.evaluate()
	if f.alertOn(d, "CPU") == nil {
		t.Fatal("8 of 15 minutes did not open an alert")
	}
	// The one-minute window is 72 seconds: a measurement 70 seconds old
	// still counts, and the one policy opens on it.
	f.exec(`DELETE FROM alerts`)
	f.exec(`DELETE FROM device_metric_samples WHERE device_id = $1`, d)
	f.sampleAt(d, 70, 99, 10, 10)
	f.evaluate()
	if f.alertOn(d, "CPU1") == nil {
		t.Fatal("a 1-minute policy missed a measurement 70 seconds old")
	}
	f.exec(`DELETE FROM alerts`)
	f.exec(`DELETE FROM device_metric_samples WHERE device_id = $1`, d)
	f.sampleAt(d, 75, 99, 10, 10)
	f.evaluate()
	if f.alertOn(d, "CPU1") != nil {
		t.Fatal("a 1-minute policy counted a measurement 75 seconds old")
	}
}

// A device back from an outage at 300 seconds, its heartbeats 10 seconds
// apart, stores one measurement and raises no metric alert.
func TestDeviceBackFromAnOutageRaisesNoMetricAlert(t *testing.T) {
	f := newFixture(t)
	f.exec(`UPDATE alert_policies SET enabled = false`)
	f.policy(f.super, PolicyInput{Name: "CPU", Kind: KindCPU, Threshold: ref(90), Minutes: 15, Severity: SeverityWarning})
	f.policy(f.super, PolicyInput{Name: "Memory", Kind: KindMemory, Threshold: ref(90), Minutes: 15, Severity: SeverityWarning})
	d := f.device(f.acme, f.hq, "back", 0)
	f.interval(d, 300)
	inv := inventory.New(f.db, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for i := 0; i < 4; i++ {
		// Heartbeats 10 seconds apart that carry metrics: the server keeps
		// the first.
		if err := inv.RecordMetrics(f.ctx, d, agentproto.Metrics{CPUPercent: 99, MemoryTotal: 100, MemoryUsed: 99}); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.count(`SELECT count(*) FROM device_metric_samples WHERE device_id = $1`, d); n != 1 {
		t.Fatalf("%d samples stored from heartbeats seconds apart", n)
	}
	f.evaluate()
	if len(f.alerts(FilterAll)) != 0 {
		t.Fatalf("alerts opened on one measurement: %+v", f.alerts(FilterAll))
	}
}

// A policy's page lists the devices whose interval makes it wait longer
// than its minutes, with how long, and leaves out the ones it does not
// affect (ADR-0058).
func TestSlowDevicesOfAPolicy(t *testing.T) {
	f := newFixture(t)
	f.exec(`UPDATE alert_policies SET enabled = false`)
	offline := f.policy(f.super, PolicyInput{Name: "Offline", Kind: KindOffline, Minutes: 10, Severity: SeverityCritical})
	cpu := f.policy(f.super, PolicyInput{Name: "CPU", Kind: KindCPU, Threshold: ref(90), Minutes: 5, Severity: SeverityWarning})
	cpu1 := f.policy(f.super, PolicyInput{Name: "CPU1", Kind: KindCPU, Threshold: ref(90), Minutes: 1, Severity: SeverityWarning})
	a := f.device(f.acme, f.hq, "a-300", 0)
	b := f.device(f.acme, f.hq, "b-120", 0)
	c := f.device(f.acme, f.branch, "c-60", 0)
	other := f.device(f.globex, f.plant, "d-300", 0)
	bare := f.id(`INSERT INTO devices (organization_id, site_id, name) VALUES ($1, $2, 'no-agent') RETURNING id`, f.acme, f.hq)
	f.interval(a, 300)
	f.interval(b, 120)
	f.interval(other, 300)

	items, total, err := f.svc.SlowDevices(f.ctx, f.super, offline.ID)
	if err != nil {
		t.Fatal(err)
	}
	// 10 minutes of Offline: 300 seconds waits 15; 120 seconds waits 6, no
	// longer than the 10.
	if total != 2 || len(items) != 2 || items[0].DeviceID != a || items[0].WaitMinutes != 15 || items[1].DeviceID != other {
		t.Fatalf("offline: %d %+v", total, items)
	}
	// 5 minutes of processor: a window of at least 1.2 intervals, so 6
	// minutes at 300 seconds; 120 seconds is 2.4, within the 5.
	items, total, err = f.svc.SlowDevices(f.ctx, f.super, cpu.ID)
	if err != nil || total != 2 || items[0].WaitMinutes != 6 || items[0].HeartbeatSeconds != 300 {
		t.Fatalf("cpu: %d %+v %v", total, items, err)
	}
	// One minute: the window is never under 1.2 intervals, so even 60
	// seconds waits 72 (shown as 2 minutes); a device without the agent is
	// not listed.
	items, total, err = f.svc.SlowDevices(f.ctx, f.super, cpu1.ID)
	if err != nil || total != 4 {
		t.Fatalf("cpu1: %d %+v %v", total, items, err)
	}
	for _, it := range items {
		if it.DeviceID == bare {
			t.Errorf("a device without the agent listed: %+v", it)
		}
		if it.DeviceID == c && it.WaitMinutes != 2 {
			t.Errorf("the 60-second device waits %d minutes", it.WaitMinutes)
		}
	}
	// Someone who sees one organization only sees its devices; a policy they
	// cannot see is not found.
	acme := f.user("acme@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	items, total, err = f.svc.SlowDevices(f.ctx, acme, offline.ID)
	if err != nil || total != 1 || items[0].DeviceID != a {
		t.Fatalf("acme sees: %d %+v %v", total, items, err)
	}
	if _, _, err := f.svc.SlowDevices(f.ctx, f.super, uuid.New()); err == nil {
		t.Error("a policy that does not exist was found")
	}
}
