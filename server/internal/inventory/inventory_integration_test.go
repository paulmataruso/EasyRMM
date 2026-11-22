//go:build integration

package inventory

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	f.svc = New(inst.DB, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
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

func (f *fixture) device(org, site uuid.UUID, name string) uuid.UUID {
	f.t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at)
		VALUES ($1, $2, $3, $3, 'linux', $4, now(), now()) RETURNING id`, org, site, name, key)
}

func (f *fixture) record(device uuid.UUID, inv any) string {
	f.t.Helper()
	b, _ := json.Marshal(inv)
	h, err := f.svc.Record(f.ctx, device, b)
	if err != nil {
		f.t.Fatal(err)
	}
	return h
}

// invalid reports whether err is a validation error on field.
func invalid(err error, field string) bool {
	e, ok := apperr.As(err)
	return ok && e.Kind == apperr.KindInvalid && e.Fields[field] != ""
}

func pkgs(list ...string) []agentproto.Package {
	out := []agentproto.Package{}
	for _, p := range list {
		name, version, _ := strings.Cut(p, "=")
		out = append(out, agentproto.Package{Name: name, Version: version, Arch: "amd64"})
	}
	return out
}

func TestRecordCleansAndReplaces(t *testing.T) {
	f := newFixture(t)
	pc := f.device(f.acme, f.hq, "HQ-PC")
	super := f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})

	if h, err := f.svc.Hash(f.ctx, pc); err != nil || h != "" {
		t.Fatalf("hash before any upload: %q %v", h, err)
	}
	dns := make([]string, 20)
	for i := range dns {
		dns[i] = fmt.Sprintf("192.0.2.%d", i+1)
	}
	body, _ := json.Marshal(map[string]any{
		"system": map[string]any{"manufacturer": "Dell\x00 Inc.\n", "model": strings.Repeat("m", 300), "virtualization": "kvm"},
		"cpu":    map[string]any{"model": "Xeon", "sockets": -3, "cores": 8, "threads": 16},
		"os":     map[string]any{"name": "Debian GNU/Linux 13 (trixie)", "kernel": "6.12.0"},
		"disks": []any{
			map[string]any{"name": "sda", "sizeBytes": 1000, "kind": "floppy"},
			map[string]any{"name": "  ", "sizeBytes": 5},
			map[string]any{"name": "nvme0n1", "kind": "nvme"},
		},
		"interfaces": []any{
			map[string]any{"name": "eth0", "mac": "00:1A:2B:3C:4D:5E", "addresses": []string{"10.0.0.5/24", "nonsense", "fe80::1/64"}, "up": true, "speedMbps": -5},
			map[string]any{"name": "wg0", "mac": "not-a-mac"},
		},
		"gateways":       []string{"10.0.0.1", "gateway.example"},
		"dnsServers":     dns,
		"packageManager": "snap",
		"packages":       []any{map[string]any{"name": "openssl", "version": "3.0.13", "arch": "amd64"}, map[string]any{"name": ""}, map[string]any{"name": "Bash", "version": "5.2"}},
		"futureField":    true,
	})
	hash, err := f.svc.Record(f.ctx, pc, body)
	sum := sha256.Sum256(body)
	if err != nil || hash != hex.EncodeToString(sum[:]) {
		t.Fatalf("record = %q, %v", hash, err)
	}
	if h, _ := f.svc.Hash(f.ctx, pc); h != hash {
		t.Errorf("stored hash %q", h)
	}

	got, err := f.svc.Get(f.ctx, super, pc)
	if err != nil || got.Inventory == nil || got.Metrics != nil {
		t.Fatalf("get = %+v, %v", got, err)
	}
	inv := got.Inventory
	if inv.System.Manufacturer != "Dell Inc." || len([]rune(inv.System.Model)) != 200 || inv.CPU.Sockets != 0 || inv.CPU.Threads != 16 {
		t.Errorf("system %+v cpu %+v", inv.System, inv.CPU)
	}
	if len(inv.Disks) != 2 || inv.Disks[0].Kind != "" || inv.Disks[1].Kind != "nvme" {
		t.Errorf("disks %+v", inv.Disks)
	}
	if len(inv.Interfaces) != 2 || inv.Interfaces[0].MAC != "00:1a:2b:3c:4d:5e" || strings.Join(inv.Interfaces[0].Addresses, ",") != "10.0.0.5/24,fe80::1/64" ||
		inv.Interfaces[0].SpeedMbps != 0 || inv.Interfaces[1].MAC != "" || inv.Interfaces[1].Addresses == nil {
		t.Errorf("interfaces %+v", inv.Interfaces)
	}
	if strings.Join(inv.Gateways, ",") != "10.0.0.1" || len(inv.DNS) != 16 {
		t.Errorf("gateways %v dns %d", inv.Gateways, len(inv.DNS))
	}
	if inv.PackageManager != "" || inv.PackageCount != 2 || time.Since(inv.ReceivedAt) > time.Minute {
		t.Errorf("packages %q %d %s", inv.PackageManager, inv.PackageCount, inv.ReceivedAt)
	}
	sw, err := f.svc.Software(f.ctx, super, pc)
	if err != nil || len(sw) != 2 || sw[0].Name != "Bash" || sw[1].Name != "openssl" {
		t.Errorf("software %+v %v", sw, err)
	}

	// A new upload replaces the packages.
	f.record(pc, agentproto.Inventory{PackageManager: "dpkg", Packages: pkgs("curl=8.5")})
	if sw, _ := f.svc.Software(f.ctx, super, pc); len(sw) != 1 || sw[0].Name != "curl" {
		t.Errorf("replaced software %+v", sw)
	}
	// Windows programs carry their publisher.
	f.record(pc, agentproto.Inventory{PackageManager: "windows", Packages: []agentproto.Package{{Name: "7-Zip 24.08 (x64)", Version: "24.08", Arch: "x64", Publisher: "Igor Pavlov"}}})
	if sw, _ := f.svc.Software(f.ctx, super, pc); len(sw) != 1 || sw[0].Publisher != "Igor Pavlov" || sw[0].Arch != "x64" {
		t.Errorf("Windows software = %+v", sw)
	}
	if got, _ := f.svc.Get(f.ctx, super, pc); got == nil || got.Inventory == nil || got.Inventory.PackageManager != "windows" || got.Inventory.PackageCount != 1 {
		t.Errorf("Windows inventory = %+v", got)
	}
	f.record(pc, agentproto.Inventory{PackageManager: "dpkg"})
	if n := f.str(`SELECT count(*)::text FROM device_software WHERE device_id = $1`, pc); n != "0" {
		t.Errorf("packages left %s", n)
	}
	if _, err := f.svc.Record(f.ctx, pc, []byte("{not json")); !errors.Is(err, ErrBadInventory) {
		t.Errorf("junk: %v", err)
	}
	// Deleting the device deletes what it reported.
	f.exec(`DELETE FROM devices WHERE id = $1`, pc)
	if n := f.str(`SELECT count(*)::text FROM device_inventory`); n != "0" {
		t.Errorf("inventory left %s", n)
	}
}

// TestPowerShellInstalls: the inventory's powerShell (ADR-0064) is kept,
// cleaned and bounded; without it, it reads as not reported.
func TestPowerShellInstalls(t *testing.T) {
	f := newFixture(t)
	pc := f.device(f.acme, f.hq, "HQ-WIN")
	super := f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})

	f.record(pc, agentproto.Inventory{PackageManager: "windows"})
	if got, _ := f.svc.Get(f.ctx, super, pc); got == nil || got.Inventory == nil || got.Inventory.PowerShell != nil {
		t.Fatalf("an inventory without powerShell = %+v", got)
	}

	list := []agentproto.PowerShellInstall{
		{Edition: "Desktop", Version: "5.1.26100.1", Arch: "x64", Path: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Usable: true},
		{Edition: "Core", Version: "7.6.10", Arch: "x64", Path: `C:\Program Files\PowerShell\7\pwsh.exe`, Usable: true},
		{Edition: "Core", Version: "7.6.10\x00", Arch: "mips", Path: `C:\Program Files (x86)\PowerShell\7\pwsh.exe`, Reason: "An x86 build.\n" + strings.Repeat("r", 600)},
		{Edition: "Core", Version: "7.6.0", Arch: "x64", Path: `C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.0.0_x64__8wekyb3d8bbwe\pwsh.exe`, Store: true, Reason: "A Store install."},
		{Edition: "Other", Version: "1", Path: `C:\x.exe`},
		{Edition: "Core", Version: "7", Path: "  "},
	}
	for i := range 20 {
		list = append(list, agentproto.PowerShellInstall{Edition: "Core", Version: fmt.Sprintf("8.%d", i), Path: fmt.Sprintf(`C:\Program Files\PowerShell\8-%d\pwsh.exe`, i)})
	}
	f.record(pc, agentproto.Inventory{PackageManager: "windows", PowerShell: list})
	got, err := f.svc.Get(f.ctx, super, pc)
	if err != nil {
		t.Fatal(err)
	}
	ps := got.Inventory.PowerShell
	if len(ps) != agentproto.MaxPowerShell {
		t.Fatalf("%d installs kept, want %d: %+v", len(ps), agentproto.MaxPowerShell, ps)
	}
	if ps[0].Edition != "Desktop" || ps[0].Version != "5.1.26100.1" || !ps[0].Usable || ps[1].Path != `C:\Program Files\PowerShell\7\pwsh.exe` {
		t.Errorf("kept as sent: %+v %+v", ps[0], ps[1])
	}
	if x := ps[2]; x.Arch != "" || x.Version != "7.6.10" || x.Usable || len([]rune(x.Reason)) != 500 || strings.ContainsRune(x.Reason, '\n') {
		t.Errorf("cleaned: %+v", x)
	}
	if !ps[3].Store || ps[3].Usable || ps[4].Version != "8.0" {
		t.Errorf("a Store install, then the unknown edition and the empty path dropped: %+v %+v", ps[3], ps[4])
	}

	// An empty list is kept as reported: none found.
	f.record(pc, agentproto.Inventory{PackageManager: "windows", PowerShell: []agentproto.PowerShellInstall{}})
	if got, _ := f.svc.Get(f.ctx, super, pc); got.Inventory.PowerShell == nil || len(got.Inventory.PowerShell) != 0 {
		t.Errorf("an empty list = %#v", got.Inventory.PowerShell)
	}
}

func TestMetricsAndHistory(t *testing.T) {
	f := newFixture(t)
	pc := f.device(f.acme, f.hq, "HQ-PC")
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})

	fs := make([]agentproto.Filesystem, 70)
	for i := range fs {
		fs[i] = agentproto.Filesystem{Mount: fmt.Sprintf("/mnt/%02d", 69-i), Device: "/dev/x", Type: "ext4", TotalBytes: 100, UsedBytes: uint64(i)}
	}
	fs[69].UsedBytes = 500 // /mnt/00, more than its total
	fs[1].Mount = ""
	err := f.svc.RecordMetrics(f.ctx, pc, agentproto.Metrics{
		CPUPercent: 150, MemoryTotal: 1000, MemoryUsed: 2000, SwapTotal: 0, SwapUsed: 10,
		Load1: -1, Load5: 0.5, Load15: 0.25, UptimeSeconds: -9, Processes: 120, Filesystems: fs,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.Get(f.ctx, tech, pc)
	if err != nil || got.Metrics == nil || got.Inventory != nil {
		t.Fatalf("get = %+v, %v", got, err)
	}
	m := got.Metrics
	if m.CPUPercent != 100 || m.MemoryUsed != 1000 || m.SwapUsed != 0 || m.Load1 != 0 || m.UptimeSeconds != 0 || m.Processes != 120 {
		t.Errorf("metrics %+v", m)
	}
	if len(m.Filesystems) != agentproto.MaxListed || m.Filesystems[0].Mount != "/mnt/00" || m.Filesystems[0].UsedBytes != 100 ||
		m.Filesystems[len(m.Filesystems)-1].Mount != "/mnt/63" {
		t.Errorf("filesystems %d %+v", len(m.Filesystems), m.Filesystems[0])
	}
	if s := f.str(`SELECT concat_ws(',', cpu_percent, memory_percent, swap_percent, disk_percent) FROM device_metric_samples WHERE device_id = $1`, pc); s != "100,100,0,100" {
		t.Errorf("sample %s", s)
	}

	// Older samples, then each range's buckets.
	for _, ago := range []string{"40 minutes", "2 hours", "3 days", "9 days"} {
		f.exec(`INSERT INTO device_metric_samples (device_id, at, cpu_percent, memory_percent, swap_percent, disk_percent, load1)
			VALUES ($1, now() - $2::interval, 10, 20, 0, 30, 1)`, pc, ago)
	}
	for rng, want := range map[string]int{"1h": 2, "24h": 3, "7d": 4} {
		h, err := f.svc.History(f.ctx, tech, pc, rng)
		if err != nil || len(h.Samples) != want || h.Range != rng || h.BucketSeconds != int(Ranges[rng].Bucket.Seconds()) {
			t.Errorf("%s: %d samples, %+v %v", rng, len(h.Samples), h, err)
		}
	}
	if _, err := f.svc.History(f.ctx, tech, pc, "1y"); !invalid(err, "range") {
		t.Errorf("bad range: %v", err)
	}

	// Retention: the service keeps at least a day.
	if err := f.svc.Purge(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.str(`SELECT count(*)::text FROM device_metric_samples WHERE device_id = $1`, pc); n != "3" {
		t.Errorf("after purge %s samples", n)
	}
}

func TestVisibilityAndWrites(t *testing.T) {
	f := newFixture(t)
	hqPC := f.device(f.acme, f.hq, "HQ-PC")
	branchPC := f.device(f.acme, f.branch, "BRANCH-PC")
	plantPC := f.device(f.globex, f.plant, "PLANT-PC")
	hqTech := f.user("hq@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	globex := f.user("globex@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.globex})
	for _, d := range []uuid.UUID{hqPC, branchPC, plantPC} {
		f.record(d, agentproto.Inventory{Packages: pkgs("openssl=3.0.13")})
		if err := f.svc.RecordMetrics(f.ctx, d, agentproto.Metrics{CPUPercent: 1}); err != nil {
			t.Fatal(err)
		}
	}
	for name, try := range map[string]func() error{
		"get":      func() error { _, err := f.svc.Get(f.ctx, hqTech, branchPC); return err },
		"software": func() error { _, err := f.svc.Software(f.ctx, globex, hqPC); return err },
		"history":  func() error { _, err := f.svc.History(f.ctx, globex, hqPC, "1h"); return err },
	} {
		if err := try(); !errors.Is(err, apperr.ErrNotFound) {
			t.Errorf("%s across tenants: %v", name, err)
		}
	}
	// Only the system scope writes: a user's transaction cannot, even for a
	// device it sees.
	err := f.db.InTx(f.ctx, hqTech.Scope, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `UPDATE device_metrics SET cpu_percent = 99 WHERE device_id = $1`, hqPC)
		if err != nil {
			return err
		}
		_, err = tx.Exec(f.ctx, `INSERT INTO device_metric_samples (device_id, at, cpu_percent, memory_percent, swap_percent, disk_percent, load1)
			VALUES ($1, now() - interval '1 hour', 99, 0, 0, 0, 0)`, hqPC)
		return err
	})
	if !database.IsRLSViolation(err) {
		t.Errorf("a user wrote metrics: %v", err)
	}
	if v := f.str(`SELECT cpu_percent::text FROM device_metrics WHERE device_id = $1`, hqPC); v != "1" {
		t.Errorf("a user changed metrics: %s", v)
	}
	err = f.db.InTx(f.ctx, hqTech.Scope, func(tx pgx.Tx) error {
		tag, err := tx.Exec(f.ctx, `DELETE FROM device_software WHERE device_id = $1`, hqPC)
		if err == nil && tag.RowsAffected() != 0 {
			return errors.New("deleted")
		}
		return err
	})
	if err != nil {
		t.Errorf("a user deleted software: %v", err)
	}
}

func TestSoftwareSearch(t *testing.T) {
	f := newFixture(t)
	super := f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	acme := f.user("acme@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	globex := f.user("globex@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.globex})
	hq := f.device(f.acme, f.hq, "hq-01")
	branch := f.device(f.acme, f.branch, "branch-01")
	plant := f.device(f.globex, f.plant, "plant-01")
	f.record(hq, agentproto.Inventory{Packages: pkgs("openssl=3.0.13", "bash=5.2", "libssl3=3.0.13")})
	f.record(branch, agentproto.Inventory{Packages: pkgs("openssl=3.0.13", "openssl=1.1.1w", "50%_off=1")})
	f.record(plant, agentproto.Inventory{Packages: pkgs("openssl=3.0.13")})

	summary := func(c access.Caller, q SoftwareQuery) string {
		t.Helper()
		res, err := f.svc.SearchSoftware(f.ctx, c, q)
		if err != nil {
			t.Fatal(err)
		}
		var parts []string
		for _, s := range res.Items {
			parts = append(parts, fmt.Sprintf("%s %s:%d", s.Name, s.Version, s.Devices))
		}
		return strings.Join(parts, ", ")
	}
	if got := summary(super, SoftwareQuery{Search: "OpenSSL"}); got != "openssl 1.1.1w:1, openssl 3.0.13:3" {
		t.Errorf("super %s", got)
	}
	if got := summary(acme, SoftwareQuery{Search: "ssl"}); got != "libssl3 3.0.13:1, openssl 1.1.1w:1, openssl 3.0.13:2" {
		t.Errorf("acme %s", got)
	}
	if got := summary(super, SoftwareQuery{Search: "openssl", SiteID: f.branch}); got != "openssl 1.1.1w:1, openssl 3.0.13:1" {
		t.Errorf("branch %s", got)
	}
	if got := summary(super, SoftwareQuery{OrganizationID: f.globex}); got != "openssl 3.0.13:1" {
		t.Errorf("globex filter %s", got)
	}
	// LIKE wildcards in the search match themselves.
	if got := summary(super, SoftwareQuery{Search: "%"}); got != "50%_off 1:1" {
		t.Errorf("wildcard %s", got)
	}
	if _, err := f.svc.SearchSoftware(f.ctx, super, SoftwareQuery{Search: strings.Repeat("x", 201)}); !invalid(err, "q") {
		t.Errorf("long search: %v", err)
	}

	devices := func(c access.Caller, q SoftwareDevicesQuery) string {
		t.Helper()
		list, err := f.svc.SoftwareDevices(f.ctx, c, q)
		if err != nil {
			t.Fatal(err)
		}
		var parts []string
		for _, d := range list {
			parts = append(parts, d.DeviceName+"@"+d.Version+"/"+d.OrganizationName+"/"+d.SiteName)
		}
		return strings.Join(parts, ", ")
	}
	if got := devices(super, SoftwareDevicesQuery{Name: "openssl"}); got != "branch-01@1.1.1w/Acme/Branch, branch-01@3.0.13/Acme/Branch, hq-01@3.0.13/Acme/HQ, plant-01@3.0.13/Globex/Plant" {
		t.Errorf("devices %s", got)
	}
	v := "1.1.1w"
	if got := devices(super, SoftwareDevicesQuery{Name: "openssl", Version: &v}); got != "branch-01@1.1.1w/Acme/Branch" {
		t.Errorf("one version %s", got)
	}
	if got := devices(globex, SoftwareDevicesQuery{Name: "openssl"}); got != "plant-01@3.0.13/Globex/Plant" {
		t.Errorf("globex %s", got)
	}
	if got := devices(super, SoftwareDevicesQuery{Name: "openssl", OrganizationID: f.acme}); got != "branch-01@1.1.1w/Acme/Branch, branch-01@3.0.13/Acme/Branch, hq-01@3.0.13/Acme/HQ" {
		t.Errorf("acme %s", got)
	}
	if got := devices(super, SoftwareDevicesQuery{Name: "openssl", SiteID: f.hq}); got != "hq-01@3.0.13/Acme/HQ" {
		t.Errorf("hq %s", got)
	}
	if _, err := f.svc.SoftwareDevices(f.ctx, super, SoftwareDevicesQuery{}); !invalid(err, "name") {
		t.Errorf("no name: %v", err)
	}
}
