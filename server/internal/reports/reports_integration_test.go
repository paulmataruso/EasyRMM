//go:build integration

package reports

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"slices"
	"strings"
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
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

type fixture struct {
	t                *testing.T
	ctx              context.Context
	db               *database.DB
	svc              *Service
	acme, hq, branch uuid.UUID
	globex, plant    uuid.UUID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	inst := testdb.New(t)
	f := &fixture{t: t, ctx: context.Background(), db: inst.DB}
	f.svc = New(inst.DB, audit.New(inst.DB, nil))
	f.acme = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.hq = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.acme)
	f.branch = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Branch') RETURNING id`, f.acme)
	f.globex = f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	f.plant = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Plant') RETURNING id`, f.globex)
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
	p, err := rbac.NewPrincipal(id, as)
	if err != nil {
		f.t.Fatal(err)
	}
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: id, Label: email})
}

// device adds a device with an agent that last checked in seen ago, or a
// remote-only device when platform is empty.
func (f *fixture) device(org, site uuid.UUID, name, platform string, seen time.Duration) uuid.UUID {
	f.t.Helper()
	if platform == "" {
		return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, last_seen_at) VALUES ($1, $2, $3, lower($3), 'other', now() - $4::interval) RETURNING id`,
			org, site, name, seen.String())
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, os_description, agent_public_key, agent_version, enrolled_at, agent_last_seen_at)
		VALUES ($1, $2, $3, lower($3), $4, $5, $6, '1.4.0', now() - interval '30 days', now() - $7::interval) RETURNING id`,
		org, site, name, platform, map[string]string{"linux": "Debian GNU/Linux 13 (trixie)", "windows": "Windows Server 2025 Standard"}[platform], key, seen.String())
}

func (f *fixture) inventory(device uuid.UUID, inv agentproto.Inventory) {
	f.t.Helper()
	b, _ := json.Marshal(inv)
	f.exec(`INSERT INTO device_inventory (device_id, hash, data) VALUES ($1, repeat('a', 64), $2)`, device, b)
}

func (f *fixture) software(device uuid.UUID, pkgs ...string) {
	f.t.Helper()
	for _, p := range pkgs {
		name, version, _ := strings.Cut(p, "=")
		f.exec(`INSERT INTO device_software (device_id, name, version, arch, publisher) VALUES ($1, $2, $3, 'amd64', '')`, device, name, version)
	}
}

func (f *fixture) metrics(device uuid.UUID, cpu float64, memUsed int64, fss ...agentproto.Filesystem) {
	f.t.Helper()
	b, _ := json.Marshal(fss)
	f.exec(`INSERT INTO device_metrics (device_id, at, cpu_percent, memory_total, memory_used, swap_total, swap_used, load1, load5, load15, uptime_seconds, processes, filesystems)
		VALUES ($1, now(), $2, 1000, $3, 0, 0, 0, 0, 0, 172800, 100, $4)`, device, cpu, memUsed, b)
}

func (f *fixture) alert(device uuid.UUID, name, kind, severity string, value float64, opened time.Duration, resolved bool) {
	f.t.Helper()
	if resolved {
		f.exec(`INSERT INTO alerts (device_id, name, kind, minutes, severity, status, value, last_value, opened_at, resolved_at, resolved_by_label, resolution)
			VALUES ($1, $2, $3, 5, $4, 'resolved', $5, $5, now() - $6::interval, now() - $6::interval + interval '90 minutes', 'tess@example.com', 'manual')`,
			device, name, kind, severity, value, opened.String())
		return
	}
	f.exec(`INSERT INTO alerts (device_id, name, kind, minutes, severity, value, last_value, opened_at) VALUES ($1, $2, $3, 5, $4, $5, $5, now() - $6::interval)`,
		device, name, kind, severity, value, opened.String())
}

func column(rep *Report, key string) []any {
	i := slices.IndexFunc(rep.Columns, func(c Column) bool { return c.Key == key })
	out := []any{}
	for _, r := range rep.Rows {
		out = append(out, r[i])
	}
	return out
}

func TestReports(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	acmeAdmin := f.user("acme@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	hqTech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})

	web := f.device(f.acme, f.hq, "WEB-01", "linux", time.Minute)
	db := f.device(f.acme, f.hq, "DB-01", "linux", 10*24*time.Hour)
	desk := f.device(f.acme, f.branch, "=DESK-01", "windows", time.Minute)
	f.device(f.acme, f.branch, "PRINTER", "", 40*24*time.Hour)
	plant := f.device(f.globex, f.plant, "PLANT-01", "linux", time.Minute)

	f.inventory(web, agentproto.Inventory{
		System: agentproto.SystemInfo{Manufacturer: "Dell Inc.", Model: "PowerEdge R650", Serial: "ABC123"},
		CPU:    agentproto.CPUInfo{Model: "Xeon Silver 4314", Cores: 16, Threads: 32},
		Memory: 64 << 30,
		Disks:  []agentproto.Disk{{Name: "sda", SizeBytes: 480 << 30}, {Name: "sdb", SizeBytes: 32 << 30, Removable: true}},
		Interfaces: []agentproto.Interface{
			{Name: "lo", Addresses: []string{"127.0.0.1/8"}},
			{Name: "eth0", Addresses: []string{"192.0.2.10/24", "fe80::1/64"}},
		},
	})
	f.software(web, "openssl=3.5.1-1", "nginx=1.26.3-3", "jq=1.7.1-6")
	f.software(db, "openssl=3.0.15-1", "postgresql-18=18.1-1")
	f.software(desk, "7-Zip 24.08 (x64)=24.08")
	f.software(plant, "openssl=3.5.1-1")
	f.metrics(web, 12.34, 250, agentproto.Filesystem{Mount: "/", TotalBytes: 100 << 30, UsedBytes: 40 << 30}, agentproto.Filesystem{Mount: "/var", TotalBytes: 200 << 30, UsedBytes: 190 << 30})
	f.metrics(db, 80, 900, agentproto.Filesystem{Mount: "/", TotalBytes: 100 << 30, UsedBytes: 50 << 30})
	f.alert(web, "Disk nearly full", "disk", "critical", 95.4, 2*time.Hour, false)
	f.alert(db, "Offline", "offline", "warning", 12, 3*24*time.Hour, true)
	f.alert(db, "Old", "cpu", "warning", 99, 60*24*time.Hour, true)
	f.alert(plant, "Globex disk", "disk", "critical", 91, time.Hour, false)

	// Device inventory: everything the caller can see, in name order.
	rep, err := f.svc.Run(f.ctx, admin, "devices", Query{}, PreviewRows)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Title != "Device inventory" || rep.Total != 5 || len(rep.Rows) != 5 || rep.Truncated {
		t.Fatalf("devices: %+v", rep)
	}
	if got := column(rep, "device"); !slices.Equal(got, []any{"=DESK-01", "PRINTER", "DB-01", "WEB-01", "PLANT-01"}) {
		t.Errorf("order %v", got)
	}
	w := rep.Rows[3]
	if want := []any{"Acme", "HQ", "WEB-01", "web-01", "Linux", "Debian GNU/Linux 13 (trixie)", true}; !slices.Equal(w[:7], want) {
		t.Errorf("web row %v", w[:7])
	}
	if want := []any{"1.4.0", "Dell Inc.", "PowerEdge R650", "ABC123", "Xeon Silver 4314", 16, 64.0, 480.0, "192.0.2.10"}; !slices.Equal(w[8:17], want) {
		t.Errorf("web inventory %v", w[8:17])
	}
	if p := rep.Rows[1]; p[4] != "Other" || p[6] != false || p[8] != "" || p[13] != nil || p[17] != nil {
		t.Errorf("printer row %v", p)
	}

	// Scope: an organization's administrator sees its devices only; a site's
	// technician, the site's.
	rep, _ = f.svc.Run(f.ctx, acmeAdmin, "devices", Query{}, PreviewRows)
	if rep.Total != 4 {
		t.Errorf("Acme admin sees %d devices", rep.Total)
	}
	rep, _ = f.svc.Run(f.ctx, hqTech, "devices", Query{}, PreviewRows)
	if got := column(rep, "device"); !slices.Equal(got, []any{"DB-01", "WEB-01"}) {
		t.Errorf("HQ technician sees %v", got)
	}
	rep, _ = f.svc.Run(f.ctx, admin, "devices", Query{OrganizationID: f.acme, Platform: "windows"}, PreviewRows)
	if got := column(rep, "device"); !slices.Equal(got, []any{"=DESK-01"}) {
		t.Errorf("Acme's Windows devices %v", got)
	}
	rep, _ = f.svc.Run(f.ctx, admin, "devices", Query{Search: "web"}, 0)
	if rep.Total != 1 || len(rep.Rows) != 0 {
		t.Errorf("kept nothing yet counted %d", rep.Total)
	}

	// Installed software, by package name.
	rep, err = f.svc.Run(f.ctx, admin, "software", Query{Search: "OPENSSL"}, PreviewRows)
	if err != nil {
		t.Fatal(err)
	}
	if got := column(rep, "device"); !slices.Equal(got, []any{"DB-01", "WEB-01", "PLANT-01"}) {
		t.Errorf("openssl on %v", got)
	}
	if got := column(rep, "version"); !slices.Equal(got, []any{"3.0.15-1", "3.5.1-1", "3.5.1-1"}) {
		t.Errorf("openssl versions %v", got)
	}
	rep, _ = f.svc.Run(f.ctx, admin, "software", Query{SiteID: f.hq}, PreviewRows)
	if rep.Total != 5 {
		t.Errorf("HQ has %d packages", rep.Total)
	}
	rep, _ = f.svc.Run(f.ctx, admin, "software", Query{Search: "%"}, PreviewRows)
	if rep.Total != 0 {
		t.Errorf("a literal %% matched %d", rep.Total)
	}

	// Device health: the fullest filesystem, and the filters.
	rep, err = f.svc.Run(f.ctx, admin, "health", Query{OrganizationID: f.acme}, PreviewRows)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Total != 4 {
		t.Fatalf("health rows %d", rep.Total)
	}
	w = rep.Rows[3]
	if want := []any{"WEB-01", "Linux", true}; !slices.Equal(w[2:5], want) {
		t.Errorf("web health %v", w[2:5])
	}
	if want := []any{12.3, 25.0, "/var", 95.0, 10.0, 2.0}; !slices.Equal(w[6:12], want) {
		t.Errorf("web measurements %v", w[6:12])
	}
	rep, _ = f.svc.Run(f.ctx, admin, "health", Query{OrganizationID: f.acme, DiskPercent: 90}, PreviewRows)
	if got := column(rep, "device"); !slices.Equal(got, []any{"WEB-01"}) {
		t.Errorf("disks at least 90%% full: %v", got)
	}
	rep, _ = f.svc.Run(f.ctx, admin, "health", Query{OfflineDays: 7}, PreviewRows)
	if got := column(rep, "device"); !slices.Equal(got, []any{"PRINTER", "DB-01"}) {
		t.Errorf("offline a week: %v", got)
	}

	// Alert history: the period, newest first; severity.
	rep, err = f.svc.Run(f.ctx, admin, "alerts", Query{}, PreviewRows)
	if err != nil {
		t.Fatal(err)
	}
	if got := column(rep, "alert"); !slices.Equal(got, []any{"Globex disk", "Disk nearly full", "Offline"}) {
		t.Errorf("alerts %v", got)
	}
	a := rep.Rows[2]
	if want := []any{"Offline", "Warning", "Resolved", "offline 12 min", 1.5}; !slices.Equal(a[5:10], want) {
		t.Errorf("resolved alert %v", a[5:10])
	}
	if a[12] != "Resolved by tess@example.com" || a[11] == nil {
		t.Errorf("resolution %v %v", a[11], a[12])
	}
	if open := rep.Rows[1]; open[7] != "Open" || open[8] != "95%" || open[11] != nil || open[12] != "" {
		t.Errorf("open alert %v", open)
	}
	rep, _ = f.svc.Run(f.ctx, admin, "alerts", Query{Days: 90, Severity: "warning"}, PreviewRows)
	if got := column(rep, "alert"); !slices.Equal(got, []any{"Offline", "Old"}) {
		t.Errorf("warnings in 90 days: %v", got)
	}
	rep, _ = f.svc.Run(f.ctx, acmeAdmin, "alerts", Query{}, PreviewRows)
	if rep.Total != 2 {
		t.Errorf("Acme admin sees %d alerts", rep.Total)
	}

	// Refusals.
	if _, err := f.svc.Run(f.ctx, admin, "payroll", Query{}, PreviewRows); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("unknown report: %v", err)
	}
	nobody := f.user("nobody@example.com")
	if _, err := f.svc.Run(f.ctx, nobody, "devices", Query{}, PreviewRows); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("no role: %v", err)
	}
	if _, err := f.svc.Run(f.ctx, admin, "devices", Query{Platform: "beos"}, PreviewRows); err == nil {
		t.Error("an odd platform was accepted")
	}

	// An export is audited with its filters and size.
	rep, err = f.svc.Export(f.ctx, acmeAdmin, "software", Query{OrganizationID: f.acme, Search: "openssl"})
	if err != nil || rep.Total != 2 {
		t.Fatalf("export %v %+v", err, rep)
	}
	details := f.str(`SELECT details::text FROM audit_log WHERE action = 'report.export' AND organization_id = $1`, f.acme)
	for _, s := range []string{`"report": "software"`, `"rows": 2`, `"q": "openssl"`, `"truncated": false`} {
		if !strings.Contains(details, s) {
			t.Errorf("audit %s lacks %s", details, s)
		}
	}
	// An export across organizations is recorded under each of them, with
	// its own rows; the site only where all its rows share one.
	if _, err := f.svc.Export(f.ctx, admin, "alerts", Query{Days: 7}); err != nil {
		t.Fatal(err)
	}
	if n := f.str(`SELECT count(*)::text FROM audit_log WHERE action = 'report.export'`); n != "3" {
		t.Errorf("%s export entries", n)
	}
	got := f.str(`SELECT string_agg(o.name || ':' || coalesce(s.name, '-') || ':' || (a.details->>'rows') || '/' || (a.details->>'totalRows'), ',' ORDER BY o.name)
		FROM audit_log a JOIN organizations o ON o.id = a.organization_id LEFT JOIN sites s ON s.id = a.site_id
		WHERE a.action = 'report.export' AND a.target_id = 'alerts'`)
	if got != "Acme:HQ:2/3,Globex:Plant:1/3" {
		t.Errorf("alert export entries %s", got)
	}

	// The organization in the request is a filter, not where the entry is
	// filed: asking for another organization's data takes none of it, and
	// is recorded at platform level, not in that organization's log.
	rep, err = f.svc.Export(f.ctx, acmeAdmin, "devices", Query{OrganizationID: f.globex, Search: "a note for Globex"})
	if err != nil || rep.Total != 0 {
		t.Fatalf("export of another organization %v %+v", err, rep)
	}
	if n := f.str(`SELECT count(*)::text FROM audit_log WHERE action = 'report.export' AND organization_id = $1`, f.globex); n != "1" {
		t.Errorf("%s entries in Globex's log", n)
	}
	if d := f.str(`SELECT details::text FROM audit_log WHERE action = 'report.export' AND target_id = 'devices' AND organization_id IS NULL`); !strings.Contains(d, `"organizationId": "`+f.globex.String()+`"`) || !strings.Contains(d, `"rows": 0`) {
		t.Errorf("empty export entry %s", d)
	}
	if _, err := f.svc.Export(f.ctx, admin, "nope", Query{}); err == nil {
		t.Error("exported an unknown report")
	}
}

// TestReportLimitsAndChecks covers what built-in roles and small fleets do
// not reach: the permission check behind the data scope, the row limit, and
// measurements without filesystems.
func TestReportLimitsAndChecks(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	a := f.device(f.acme, f.hq, "A-01", "linux", time.Minute)
	b := f.device(f.acme, f.hq, "B-01", "linux", time.Minute)
	g := f.device(f.globex, f.plant, "G-01", "windows", time.Minute)
	f.metrics(a, 5, 100)
	for _, d := range []uuid.UUID{a, b, g} {
		f.software(d, "curl=8.14", "zlib=1.3")
		f.alert(d, "Busy", "cpu", "warning", 97, time.Hour, false)
	}

	// Rows are checked against the caller's permissions even when the data
	// scope would let them through.
	acme := f.user("acme@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	wide := access.User(acme.Principal, database.System, acme.Actor)
	for _, name := range Names() {
		rep, err := f.svc.Run(f.ctx, wide, name, Query{}, PreviewRows)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rep.Rows {
			if slices.Contains(r, any("G-01")) || slices.Contains(r, any("Globex")) {
				t.Errorf("%s: a Globex row reached an Acme administrator: %v", name, r)
			}
		}
	}

	// A device measured without filesystems has no fullest one.
	rep, _ := f.svc.Run(f.ctx, admin, "health", Query{SiteID: f.hq}, PreviewRows)
	if r := rep.Rows[0]; r[2] != "A-01" || r[6] != 5.0 || r[7] != 10.0 || r[8] != "" || r[9] != nil || r[10] != nil {
		t.Errorf("health without filesystems %v", r)
	}
	if rep, _ := f.svc.Run(f.ctx, admin, "health", Query{SiteID: f.hq, DiskPercent: 1}, PreviewRows); rep.Total != 0 {
		t.Errorf("%d devices with a disk at least 1%% full", rep.Total)
	}

	// Past the limit a report stops and says so.
	maxRows = 2
	t.Cleanup(func() { maxRows = MaxRows })
	for _, name := range Names() {
		rep, err := f.svc.Run(f.ctx, admin, name, Query{}, PreviewRows)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Total != 2 || len(rep.Rows) != 2 || !rep.Truncated {
			t.Errorf("%s past the limit: total %d, %d rows, truncated %v", name, rep.Total, len(rep.Rows), rep.Truncated)
		}
	}
	rep, err := f.svc.Export(f.ctx, admin, "software", Query{OrganizationID: f.acme, SiteID: f.hq, Platform: "linux"})
	if err != nil || !rep.Truncated {
		t.Fatalf("export %v %+v", err, rep)
	}
	details := f.str(`SELECT details::text FROM audit_log WHERE action = 'report.export'`)
	for _, s := range []string{`"truncated": true`, `"siteId": "` + f.hq.String() + `"`, `"platform": "linux"`} {
		if !strings.Contains(details, s) {
			t.Errorf("audit %s lacks %s", details, s)
		}
	}
	if _, err := f.svc.Export(f.ctx, admin, "health", Query{OfflineDays: 3}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.str(`SELECT details::text FROM audit_log WHERE action = 'report.export' AND target_id = 'health'`), `"offlineDays": 3`) {
		t.Error("the health export's filters are not audited")
	}
}
