//go:build integration

package hardware_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/hardware"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

type fixture struct {
	t     *testing.T
	ctx   context.Context
	inst  *testdb.Instance
	db    *database.DB
	svc   *hardware.Service
	acme  uuid.UUID
	hq    uuid.UUID
	other uuid.UUID
	plant uuid.UUID
	super access.Caller
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	inst := testdb.New(t)
	f := &fixture{t: t, ctx: context.Background(), inst: inst, db: inst.DB}
	f.svc = hardware.New(inst.DB, 7*24*time.Hour, 730*24*time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.acme = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.hq = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.acme)
	f.other = f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	f.plant = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Plant') RETURNING id`, f.other)
	f.super = f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
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

func (f *fixture) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&n) }); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *fixture) user(email string, as ...rbac.Assignment) access.Caller {
	f.t.Helper()
	id := f.id(`INSERT INTO users (email, display_name) VALUES ($1, $1) RETURNING id`, email)
	p, err := rbac.NewPrincipal(id, as)
	if err != nil {
		f.t.Fatal(err)
	}
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: id, Label: email})
}

func (f *fixture) device(org, site uuid.UUID, name string) uuid.UUID {
	f.t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at)
		VALUES ($1, $2, $3, $3, 'linux', $4, now() - interval '1 day', now()) RETURNING id`, org, site, name, key)
}

// report sends disks as the device's hardware report.
func (f *fixture) report(device uuid.UUID, disks ...agentproto.DiskHealth) {
	f.t.Helper()
	body, err := json.Marshal(agentproto.HardwareReport{Disks: disks})
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.svc.Record(f.ctx, device, body); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) disks(c access.Caller, device uuid.UUID) map[string]*hardware.Disk {
	f.t.Helper()
	list, err := f.svc.Disks(f.ctx, c, device)
	if err != nil {
		f.t.Fatal(err)
	}
	out := map[string]*hardware.Disk{}
	for _, d := range list {
		out[d.Name] = d
	}
	return out
}

var (
	read    = agentproto.Read
	notKept = agentproto.NotRead(agentproto.FactUnsupported, agentproto.ReasonNotKept)
)

func nvme(name, serial string, criticalWarning int64) agentproto.DiskHealth {
	return agentproto.DiskHealth{
		Name: name, Model: "Example NVMe 1TB", Serial: serial, State: agentproto.FactRead, Protocol: agentproto.ProtocolNVMe,
		Route: "nvme", ReadAt: time.Now(), CriticalWarning: read(criticalWarning), SMARTStatus: notKept, Thresholds: notKept,
		Temperature: read(40), TemperatureLimit: read(70), Wear: read(3), AvailableSpare: read(100), AvailableSpareThreshold: read(10),
		MediaErrors: read(0), ReallocatedSectors: notKept, PendingSectors: notKept, UncorrectableSectors: notKept,
		DriveErrors: read(0), PowerOnHours: read(1200), DataWritten: read(5000), UnsafeShutdowns: read(4), PowerMode: notKept,
	}
}

func ata(name, serial string, status, reallocated int64) agentproto.DiskHealth {
	t := uint8(36)
	return agentproto.DiskHealth{
		Name: name, Model: "Example SSD 500GB", Serial: serial, State: agentproto.FactRead, Protocol: agentproto.ProtocolATA,
		Route: "sg", ReadAt: time.Now(), CriticalWarning: notKept, SMARTStatus: read(status), Thresholds: read(0),
		Temperature: read(35), TemperatureLimit: read(60), Wear: read(10), AvailableSpare: notKept, AvailableSpareThreshold: notKept,
		MediaErrors: notKept, ReallocatedSectors: read(reallocated), PendingSectors: read(0), UncorrectableSectors: read(0),
		DriveErrors: read(0), PowerOnHours: read(9000), DataWritten: notKept, UnsafeShutdowns: notKept, PowerMode: read(0xff),
		Attributes: []agentproto.Attribute{{ID: 5, Flags: 0x33, Value: 100, Worst: 100, Threshold: &t, Raw: uint64(reallocated)}},
	}
}

func notRead(name, serial, state, reason string) agentproto.DiskHealth {
	return agentproto.DiskHealth{Name: name, Model: "Example HDD 4TB", Serial: serial, State: state, Reason: reason, ReadAt: time.Now()}
}

// key is a disk's identity as ADR-0065 defines it, computed here apart
// from the database's easyrmm_disk_key.
func key(name, model, serial string) string {
	s := "disk\n" + model + "\n" + serial
	if serial == "" {
		s = "name\n" + name
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:16])
}

func TestRecordAndShow(t *testing.T) {
	f := newFixture(t)
	dev := f.device(f.acme, f.hq, "srv-01")

	f.report(dev,
		nvme("nvme0n1", "N1", 0),
		ata("sda", "A1", agentproto.SMARTPassed, 3),
		notRead("sdb", "R1", agentproto.FactUnavailable, agentproto.ReasonRAIDController),
		notRead("vda", "", agentproto.FactUnsupported, agentproto.ReasonVirtualDisk),
		notRead("sdc", "S1", agentproto.FactUnknown, agentproto.ReasonAsleep),
		nvme("nvme0n1", "N1", 0), // listed twice: kept once
	)
	disks := f.disks(f.super, dev)
	if len(disks) != 5 {
		t.Fatalf("disks %v", disks)
	}
	for name, want := range map[string]struct{ state, reason, detail string }{
		"nvme0n1": {hardware.StateHealthy, "", ""},
		"sda":     {hardware.StateWarning, hardware.RuleReallocated, "Reallocated sectors 3"},
		"sdb":     {hardware.StateUnavailable, agentproto.ReasonRAIDController, ""},
		"vda":     {hardware.StateUnsupported, agentproto.ReasonVirtualDisk, ""},
		"sdc":     {hardware.StateUnknown, agentproto.ReasonAsleep, ""},
	} {
		d := disks[name]
		if d == nil || d.State != want.state || d.Reason != want.reason || d.Detail != want.detail {
			t.Errorf("%s = %+v, want %+v", name, d, want)
		}
	}
	n := disks["nvme0n1"]
	if n.Key != key("nvme0n1", "Example NVMe 1TB", "N1") || n.Unstable || n.Protocol != "nvme" || n.Route != "nvme" || n.FactsAt == nil ||
		len(n.Facts) != 17 || n.JudgedLevel == nil || *n.JudgedLevel != hardware.StateHealthy || n.Since != 0 || n.MissingSince != nil {
		t.Errorf("nvme0n1 = %+v", n)
	}
	if v := disks["vda"]; v.Key != key("vda", "", "") || !v.Unstable || len(v.Facts) != 0 || v.FactsAt != nil || v.JudgedLevel != nil {
		t.Errorf("vda = %+v", v)
	}
	sda := disks["sda"]
	if len(sda.Attributes) != 1 || sda.Attributes[0].State != hardware.StateHealthy || !sda.Attributes[0].PreFail {
		t.Errorf("sda attributes %+v", sda.Attributes)
	}

	// A failing or warning disk stays so through readings that cannot
	// tell, which show as a note; facts keep the last values read.
	asleep := notRead("sda", "A1", agentproto.FactUnknown, agentproto.ReasonAsleep)
	asleep.Model = "Example SSD 500GB"
	f.report(dev, nvme("nvme0n1", "N1", 0), asleep, notRead("sdb", "R1", agentproto.FactUnavailable, agentproto.ReasonRAIDController))
	sda = f.disks(f.super, dev)["sda"]
	if sda.State != hardware.StateWarning || sda.Reason != hardware.RuleReallocated || sda.Since != 1 ||
		sda.Latest.State != agentproto.FactUnknown || sda.Latest.Reason != agentproto.ReasonAsleep || len(sda.Facts) != 17 ||
		sda.FactsAt == nil || sda.FactsAt.After(*sda.JudgedAt) {
		t.Errorf("asleep after a warning: %+v", sda)
	}
	// The report left out vda and sdc: missing, listed after the others.
	list, err := f.svc.Disks(f.ctx, f.super, dev)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 5 || list[3].MissingSince == nil || list[4].MissingSince == nil || list[3].State != hardware.StateUnknown ||
		list[3].Reason != agentproto.ReasonMissing || list[0].MissingSince != nil {
		t.Errorf("missing disks: %+v %+v", list[3], list[4])
	}

	// A newer judged reading changes the level; then age never does.
	f.report(dev, nvme("nvme0n1", "N1", 1<<3), ata("sda", "A1", agentproto.SMARTThresholdExceeded, 3),
		notRead("vda", "", agentproto.FactUnsupported, agentproto.ReasonVirtualDisk))
	f.exec(`UPDATE device_disk_health SET judged_at = now() - interval '30 days' WHERE device_id = $1 AND judged_at IS NOT NULL`, dev)
	got := f.disks(f.super, dev)
	if got["nvme0n1"].State != hardware.StateFailing || got["nvme0n1"].Detail != "NVMe critical warning: media read-only" ||
		got["sda"].State != hardware.StateFailing || got["sda"].Reason != hardware.RuleSMARTStatus {
		t.Errorf("failing: %+v %+v", got["nvme0n1"], got["sda"])
	}
	// A report that lists a missing disk again ends that.
	if got["vda"].MissingSince != nil || got["sdc"].MissingSince == nil {
		t.Errorf("vda %+v sdc %+v", got["vda"], got["sdc"])
	}

	// A healthy reading counts for 2 hours.
	f.report(dev, nvme("nvme0n1", "N1", 0))
	f.exec(`UPDATE device_disk_health SET judged_at = now() - interval '119 minutes' WHERE device_id = $1 AND name = 'nvme0n1'`, dev)
	if d := f.disks(f.super, dev)["nvme0n1"]; d.State != hardware.StateHealthy {
		t.Errorf("healthy for 119 minutes: %+v", d)
	}
	f.exec(`UPDATE device_disk_health SET judged_at = now() - interval '121 minutes' WHERE device_id = $1 AND name = 'nvme0n1'`, dev)
	if d := f.disks(f.super, dev)["nvme0n1"]; d.State != hardware.StateUnknown || d.Reason != agentproto.ReasonStale {
		t.Errorf("stale: %+v", d)
	}

	// A disk never judged shows its latest reading's reason; one whose
	// verdict could not be read is unknown, never healthy.
	noVerdict := nvme("nvme1n1", "N2", 0)
	noVerdict.CriticalWarning = agentproto.NotRead(agentproto.FactUnknown, agentproto.ReasonIOError)
	f.report(dev, noVerdict)
	if d := f.disks(f.super, dev)["nvme1n1"]; d.State != hardware.StateUnknown || d.Reason != agentproto.ReasonNoVerdict || d.JudgedLevel != nil {
		t.Errorf("no verdict: %+v", d)
	}

	// Not valid JSON.
	if err := f.svc.Record(f.ctx, dev, []byte(`{"disks":`)); !errors.Is(err, hardware.ErrBadReport) {
		t.Errorf("bad report: %v", err)
	}
	// Nothing is audited: the agent reads on its own.
	if n := f.count(`SELECT count(*) FROM audit_log`); n != 0 {
		t.Errorf("%d audit records", n)
	}
}

func TestAccess(t *testing.T) {
	f := newFixture(t)
	dev := f.device(f.acme, f.hq, "srv-01")
	theirs := f.device(f.other, f.plant, "plc-01")
	f.report(dev, nvme("nvme0n1", "N1", 0))
	f.report(theirs, nvme("nvme0n1", "N9", 0))
	k := key("nvme0n1", "Example NVMe 1TB", "N1")
	viewer := f.user("viewer@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})

	if d := f.disks(viewer, dev); len(d) != 1 || d["nvme0n1"].Key != k {
		t.Fatalf("read-only %+v", d)
	}
	if _, err := f.svc.Disks(f.ctx, viewer, theirs); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("another organization's device: %v", err)
	}
	if _, err := f.svc.Disk(f.ctx, viewer, theirs, key("nvme0n1", "Example NVMe 1TB", "N9")); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("another organization's disk: %v", err)
	}
	if _, err := f.svc.Disk(f.ctx, viewer, dev, "nope"); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("unknown disk: %v", err)
	}
	// Row-level security: the runtime role in the viewer's scope reads no
	// other organization's disks even without the service's check.
	var n int
	if err := f.db.ReadTx(f.ctx, viewer.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM device_disk_health) + (SELECT count(*) FROM device_disk_health_samples)`).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("the viewer's scope reads %d rows, want its own disk and sample", n)
	}
	// Nor write them: only the system scope does.
	_ = f.db.InTx(f.ctx, viewer.Scope, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `UPDATE device_disk_health SET state = 'failing' WHERE device_id = $1`, dev)
		return err
	})
	if n := f.count(`SELECT count(*) FROM device_disk_health WHERE state = 'failing'`); n != 0 {
		t.Errorf("the viewer's scope changed %d disks", n)
	}

	// The panel: the disk, its days, its open alerts.
	policy := f.id(`SELECT id FROM alert_policies WHERE kind = 'disk_health' AND check_name = 'failing'`)
	f.exec(`INSERT INTO alerts (policy_id, device_id, name, kind, check_name, minutes, severity, value, last_value, subject, subject_label, detail)
		VALUES ($1, $2, 'Disk failing', 'disk_health', 'failing', 30, 'critical', 1, 1, $3, 'nvme0n1 · Example NVMe 1TB', 'x')`, policy, dev, k)
	p, err := f.svc.Disk(f.ctx, viewer, dev, k)
	if err != nil {
		t.Fatal(err)
	}
	if p.Disk == nil || p.Name != "nvme0n1" || len(p.History) != 1 || p.History[0].State != hardware.StateHealthy ||
		p.History[0].Temperature == nil || *p.History[0].Temperature != 40 || len(p.Alerts) != 1 || p.Alerts[0].CheckName != "failing" {
		t.Errorf("panel %+v", p)
	}
}

func TestDevicesList(t *testing.T) {
	f := newFixture(t)
	failing := f.device(f.acme, f.hq, "a-failing")
	healthy := f.device(f.acme, f.hq, "b-healthy")
	f.device(f.acme, f.hq, "c-quiet")
	virtual := f.device(f.acme, f.hq, "d-virtual")
	raid := f.device(f.acme, f.hq, "e-raid")
	f.report(failing, nvme("nvme0n1", "N1", 1), notRead("sdb", "R1", agentproto.FactUnavailable, agentproto.ReasonRAIDController),
		notRead("sdc", "R2", agentproto.FactUnavailable, agentproto.ReasonRAIDController))
	f.report(healthy, nvme("nvme0n1", "N2", 0), notRead("vdb", "", agentproto.FactUnsupported, agentproto.ReasonVirtualDisk))
	f.report(virtual, notRead("vda", "", agentproto.FactUnsupported, agentproto.ReasonVirtualDisk))
	f.report(raid, notRead("sdb", "R3", agentproto.FactUnavailable, agentproto.ReasonRAIDController),
		notRead("vda", "", agentproto.FactUnsupported, agentproto.ReasonVirtualDisk))
	svc := devices.New(f.db, false)

	list, err := svc.List(f.ctx, f.super, devices.Query{})
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]*devices.DiskHealthSummary{}
	for _, d := range list {
		labels[d.Name] = d.DiskHealth
	}
	for name, want := range map[string]*devices.DiskHealthSummary{
		"a-failing": {Label: "failing", States: map[string]int{"failing": 1, "unavailable": 2}},
		"b-healthy": {Label: "healthy", States: map[string]int{"healthy": 1, "unsupported": 1}},
		"c-quiet":   nil,
		"d-virtual": {Label: "unsupported", States: map[string]int{"unsupported": 1}},
		"e-raid":    {Label: "unavailable", States: map[string]int{"unavailable": 1, "unsupported": 1}},
	} {
		got := labels[name]
		if (got == nil) != (want == nil) || got != nil && (got.Label != want.Label || len(got.States) != len(want.States)) {
			t.Errorf("%s = %+v, want %+v", name, got, want)
			continue
		}
		if want == nil {
			continue
		}
		for s, n := range want.States {
			if got.States[s] != n {
				t.Errorf("%s: %d %s, want %d", name, got.States[s], s, n)
			}
		}
	}
	for filter, want := range map[string][]string{
		devices.DiskFailing:     {"a-failing"},
		devices.DiskWarning:     {},
		devices.DiskUnknown:     {},
		devices.DiskHealthy:     {"b-healthy"},
		devices.DiskUnavailable: {"a-failing", "e-raid"},
		devices.DiskUnsupported: {"b-healthy", "d-virtual", "e-raid"},
		devices.DiskNotReported: {"c-quiet"},
	} {
		list, err := svc.List(f.ctx, f.super, devices.Query{DiskHealth: filter})
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, d := range list {
			got = append(got, d.Name)
		}
		if len(got) != len(want) || len(want) > 0 && !equal(got, want) {
			t.Errorf("filter %s = %v, want %v", filter, got, want)
		}
	}
	if _, err := svc.List(f.ctx, f.super, devices.Query{DiskHealth: "bad"}); !invalid(err, "diskHealth") {
		t.Errorf("bad filter: %v", err)
	}
	// One device: the same summary.
	d, err := svc.Get(f.ctx, f.super, failing)
	if err != nil || d.DiskHealth == nil || d.DiskHealth.Label != "failing" {
		t.Errorf("get %+v %v", d, err)
	}
}

func invalid(err error, field string) bool {
	e, ok := apperr.As(err)
	return ok && e.Kind == apperr.KindInvalid && e.Fields[field] != ""
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestPurge(t *testing.T) {
	f := newFixture(t)
	dev := f.device(f.acme, f.hq, "srv-01")
	f.report(dev, nvme("nvme0n1", "N1", 0))
	k := key("nvme0n1", "Example NVMe 1TB", "N1")
	sample := func(at string, state string, judged bool, temp, realloc, wear *int) {
		t.Helper()
		f.exec(`INSERT INTO device_disk_health_samples (device_id, disk_key, at, state, judged, temperature, reallocated, wear)
			VALUES ($1, $2, `+at+`, $3, $4, $5, $6, $7)`, dev, k, state, judged, temp, realloc, wear)
	}
	v := func(n int) *int { return &n }
	day := `date_trunc('day', now() - interval '10 days', 'UTC')`
	sample(day+` + interval '1 hour'`, "healthy", true, v(30), v(1), v(10))
	sample(day+` + interval '2 hours'`, "failing", true, v(45), v(2), nil)
	sample(day+` + interval '3 hours'`, "unknown", false, nil, nil, nil)
	sample(day+` + interval '4 hours'`, "healthy", true, v(35), v(3), v(11))
	sample(`date_trunc('day', now() - interval '9 days', 'UTC') + interval '5 hours'`, "unknown", false, nil, nil, nil)
	// A day thinned long ago, past EASYRMM_HARDWARE_RETENTION.
	f.exec(`INSERT INTO device_disk_health_samples (device_id, disk_key, at, daily, state, judged)
		VALUES ($1, $2, date_trunc('day', now() - interval '800 days', 'UTC'), true, 'healthy', true)`, dev, k)
	// The day that crosses EASYRMM_METRICS_RETENTION is not thinned until
	// it is whole.
	sample(`date_trunc('day', now() - interval '7 days', 'UTC') + interval '1 second'`, "healthy", true, v(31), v(0), v(1))

	if err := f.svc.Purge(f.ctx); err != nil {
		t.Fatal(err)
	}
	var (
		state             string
		judged            bool
		temp, realloc, wr *int
	)
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT state, judged, temperature, reallocated, wear FROM device_disk_health_samples
			WHERE daily AND at = `+day).Scan(&state, &judged, &temp, &realloc, &wr)
	}); err != nil {
		t.Fatal(err)
	}
	if state != "failing" || !judged || *temp != 45 || *realloc != 3 || *wr != 11 {
		t.Errorf("the day: %s %v %d %d %d", state, judged, *temp, *realloc, *wr)
	}
	if n := f.count(`SELECT count(*) FROM device_disk_health_samples WHERE daily`); n != 2 {
		t.Errorf("%d daily rows, want the two thinned days", n)
	}
	if n := f.count(`SELECT count(*) FROM device_disk_health_samples WHERE NOT daily`); n != 2 {
		t.Errorf("%d full rows, want today's reading and the crossing day's", n)
	}
	if n := f.count(`SELECT count(*) FROM device_disk_health_samples WHERE at < now() - interval '799 days'`); n != 0 {
		t.Errorf("a day past retention is kept")
	}
	// Again: nothing more to do.
	if err := f.svc.Purge(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM device_disk_health_samples`); n != 4 {
		t.Errorf("%d rows after a second purge", n)
	}
	// Removing the device removes its disks and their history.
	f.exec(`DELETE FROM devices WHERE id = $1`, dev)
	if n := f.count(`SELECT (SELECT count(*) FROM device_disk_health) + (SELECT count(*) FROM device_disk_health_samples)`); n != 0 {
		t.Errorf("%d rows left after the device's removal", n)
	}
}
