// Package inventory stores what devices' agents report about themselves
// (ADR-0018): the inventory (hardware, operating system, network, installed
// packages), uploaded when it changes, and the metrics sent with every
// heartbeat, kept as samples for charts and alerts.
package inventory

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// MinRetention is the shortest EASYRMM_METRICS_RETENTION accepted.
const MinRetention = 24 * time.Hour

// ErrBadInventory is an upload the server cannot read.
var ErrBadInventory = errors.New("inventory: not a valid inventory")

// Service stores and reads inventory and metrics.
type Service struct {
	db        *database.DB
	retention time.Duration
	log       *slog.Logger
}

// New builds the service. retention is how long metric samples are kept.
func New(db *database.DB, retention time.Duration, log *slog.Logger) *Service {
	return &Service{db: db, retention: max(retention, MinRetention), log: log}
}

// Hash returns the hash of the inventory held for a device, or "" when
// there is none.
func (s *Service) Hash(ctx context.Context, deviceID uuid.UUID) (string, error) {
	var hash string
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT hash FROM device_inventory WHERE device_id = $1`, deviceID).Scan(&hash)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return hash, err
}

// Record stores an inventory upload. body is the request body as sent: its
// hash is what the agent compares with its own, whatever either side's
// version adds to the document.
func (s *Service) Record(ctx context.Context, deviceID uuid.UUID, body []byte) (string, error) {
	var inv agentproto.Inventory
	if err := json.Unmarshal(body, &inv); err != nil {
		return "", ErrBadInventory
	}
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	inv = cleanInventory(inv)
	pkgs := inv.Packages
	inv.Packages = nil
	data, err := json.Marshal(inv)
	if err != nil {
		return "", err
	}
	names, versions, arches, publishers := make([]string, len(pkgs)), make([]string, len(pkgs)), make([]string, len(pkgs)), make([]string, len(pkgs))
	for i, p := range pkgs {
		names[i], versions[i], arches[i], publishers[i] = p.Name, p.Version, p.Arch, p.Publisher
	}
	ps7, blocked := powerShell7(inv.PowerShell)
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO device_inventory (device_id, hash, data, package_manager, package_count, received_at)
			VALUES ($1, $2, $3, $4, $5, now())
			ON CONFLICT (device_id) DO UPDATE SET hash = $2, data = $3, package_manager = $4, package_count = $5, received_at = now()`,
			deviceID, hash, data, inv.PackageManager, len(pkgs)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET powershell7 = $2, powershell7_blocked = $3
			WHERE id = $1 AND (powershell7 IS DISTINCT FROM $2 OR powershell7_blocked IS DISTINCT FROM $3)`,
			deviceID, ps7, blocked); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM device_software WHERE device_id = $1`, deviceID); err != nil {
			return err
		}
		if len(pkgs) == 0 {
			return nil
		}
		_, err := tx.Exec(ctx, `INSERT INTO device_software (device_id, name, version, arch, publisher)
			SELECT $1, n, v, a, pub FROM unnest($2::text[], $3::text[], $4::text[], $5::text[]) AS p (n, v, a, pub)`,
			deviceID, names, versions, arches, publishers)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("inventory: storing: %w", err)
	}
	return hash, nil
}

// powerShell7 is what the device list says of PowerShell 7 from an
// inventory's PowerShell list (ADR-0064): whether it lists a usable
// install, nil when it lists no PowerShell; and where none is usable but
// one is blocked, why a run fails, the first blocked install's reason, or
// nil.
func powerShell7(list []agentproto.PowerShellInstall) (usable *bool, blocked *string) {
	if list == nil {
		return nil, nil
	}
	found := false
	for _, p := range list {
		if p.Edition == agentproto.EditionCore && p.Usable {
			found = true
			return &found, nil
		}
	}
	for _, p := range list {
		if p.Edition == agentproto.EditionCore && p.Blocked {
			return &found, &p.Reason
		}
	}
	return &found, nil
}

// RecordMetrics stores a heartbeat's metrics as the device's latest and as
// a sample.
func (s *Service) RecordMetrics(ctx context.Context, deviceID uuid.UUID, m agentproto.Metrics) error {
	m = cleanMetrics(m)
	fs, err := json.Marshal(m.Filesystems)
	if err != nil {
		return err
	}
	disk := 0.0
	for _, f := range m.Filesystems {
		disk = max(disk, percent(f.UsedBytes, f.TotalBytes))
	}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO device_metrics (device_id, at, cpu_percent, memory_total, memory_used, swap_total, swap_used,
				load1, load5, load15, uptime_seconds, processes, filesystems)
			VALUES ($1, now(), $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT (device_id) DO UPDATE SET at = now(), cpu_percent = $2, memory_total = $3, memory_used = $4, swap_total = $5,
				swap_used = $6, load1 = $7, load5 = $8, load15 = $9, uptime_seconds = $10, processes = $11, filesystems = $12`,
			deviceID, m.CPUPercent, int64(m.MemoryTotal), int64(m.MemoryUsed), int64(m.SwapTotal), int64(m.SwapUsed), //nolint:gosec // capped by cleanMetrics
			m.Load1, m.Load5, m.Load15, m.UptimeSeconds, m.Processes, fs); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO device_metric_samples (device_id, at, cpu_percent, memory_percent, swap_percent, disk_percent, load1)
			VALUES ($1, date_trunc('second', now()), $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING`,
			deviceID, m.CPUPercent, percent(m.MemoryUsed, m.MemoryTotal), percent(m.SwapUsed, m.SwapTotal), disk, m.Load1)
		return err
	})
	if err != nil {
		return fmt.Errorf("inventory: storing metrics: %w", err)
	}
	return nil
}

// Purge removes metric samples past retention.
func (s *Service) Purge(ctx context.Context) error {
	var n int64
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM device_metric_samples WHERE at < now() - $1::interval`, fmt.Sprintf("%d seconds", int64(s.retention.Seconds())))
		n = tag.RowsAffected()
		return err
	})
	if err == nil && n > 0 {
		s.log.Info("inventory: removed metric samples past retention", "count", n, "retention", s.retention.String())
	}
	return err
}

// Limits of what is stored.
const (
	maxText    = 200
	maxLong    = 500
	maxServers = 16
	maxBytes   = uint64(1) << 62
	maxCount   = 1 << 20
)

// cleanInventory cuts free text to size, drops entries that make no sense
// and caps every list, rather than refusing a whole upload over one odd
// value.
func cleanInventory(in agentproto.Inventory) agentproto.Inventory {
	out := agentproto.Inventory{
		System: agentproto.SystemInfo{
			Manufacturer: text(in.System.Manufacturer, maxText), Model: text(in.System.Model, maxText),
			Serial: text(in.System.Serial, maxText), BIOSVendor: text(in.System.BIOSVendor, maxText),
			BIOSVersion: text(in.System.BIOSVersion, maxText), BIOSDate: text(in.System.BIOSDate, 64),
			Virtualization: text(in.System.Virtualization, 64),
		},
		CPU: agentproto.CPUInfo{
			Model: text(in.CPU.Model, maxText), Sockets: count(in.CPU.Sockets), Cores: count(in.CPU.Cores), Threads: count(in.CPU.Threads),
		},
		Memory: min(in.Memory, maxBytes),
		OS: agentproto.OSInfo{
			Name: text(in.OS.Name, maxLong), ID: text(in.OS.ID, 64), Version: text(in.OS.Version, 64),
			Kernel: text(in.OS.Kernel, maxText), Timezone: text(in.OS.Timezone, 64),
		},
		Disks: []agentproto.Disk{}, Interfaces: []agentproto.Interface{}, Gateways: []string{}, DNS: []string{},
		Packages: []agentproto.Package{},
	}
	for _, d := range in.Disks {
		if name := text(d.Name, 64); name != "" && len(out.Disks) < agentproto.MaxListed {
			kind := d.Kind
			if kind != "ssd" && kind != "hdd" && kind != "nvme" {
				kind = ""
			}
			out.Disks = append(out.Disks, agentproto.Disk{
				Name: name, Model: text(d.Model, maxText), Serial: text(d.Serial, maxText),
				SizeBytes: min(d.SizeBytes, maxBytes), Kind: kind, Removable: d.Removable,
			})
		}
	}
	for _, i := range in.Interfaces {
		name := text(i.Name, 64)
		if name == "" || len(out.Interfaces) >= agentproto.MaxListed {
			continue
		}
		addrs := []string{}
		for _, a := range i.Addresses {
			if p, err := netip.ParsePrefix(a); err == nil && len(addrs) < agentproto.MaxAddresses {
				addrs = append(addrs, p.String())
			}
		}
		mac := ""
		if m := strings.ToLower(text(i.MAC, 64)); validMAC(m) {
			mac = m
		}
		out.Interfaces = append(out.Interfaces, agentproto.Interface{
			Name: name, MAC: mac, Addresses: addrs, Up: i.Up, SpeedMbps: min(max(i.SpeedMbps, 0), 10_000_000),
		})
	}
	out.Gateways = addresses(in.Gateways)
	out.DNS = addresses(in.DNS)
	switch in.PackageManager {
	case "windows", "dpkg", "rpm", "apk", "pacman":
		out.PackageManager = in.PackageManager
	}
	for _, p := range in.Packages {
		if len(out.Packages) >= agentproto.MaxPackages {
			break
		}
		if name := text(p.Name, maxText); name != "" {
			out.Packages = append(out.Packages, agentproto.Package{
				Name: name, Version: text(p.Version, maxText), Arch: text(p.Arch, 40), Publisher: text(p.Publisher, maxText),
			})
		}
	}
	if e := in.EasyPatch; e != nil {
		out.EasyPatch = &agentproto.EasyPatchAgent{
			Version: text(e.Version, 64), Status: text(e.Status, 64), ServerURL: text(e.ServerURL, maxLong),
			EndpointID: text(e.EndpointID, 64), KeyFingerprint: text(e.KeyFingerprint, 128), Error: text(e.Error, maxLong),
		}
	}
	out.PowerShell = cleanPowerShell(in.PowerShell)
	return out
}

// cleanPowerShell keeps the PowerShell installs an agent found (ADR-0064):
// those with a path and a known edition, at most agentproto.MaxPowerShell.
// nil, from an agent too old to look, stays nil: not reported.
func cleanPowerShell(in []agentproto.PowerShellInstall) []agentproto.PowerShellInstall {
	if in == nil {
		return nil
	}
	out := []agentproto.PowerShellInstall{}
	for _, p := range in {
		path := text(p.Path, agentproto.MaxInterpreterPath)
		if path == "" || (p.Edition != agentproto.EditionDesktop && p.Edition != agentproto.EditionCore) {
			continue
		}
		if len(out) == agentproto.MaxPowerShell {
			break
		}
		arch := p.Arch
		if arch != agentproto.ArchX64 && arch != agentproto.ArchARM64 && arch != agentproto.ArchX86 {
			arch = ""
		}
		// Only a PowerShell 7 install is blocked, and a blocked one is not
		// usable.
		blocked := p.Blocked && p.Edition == agentproto.EditionCore
		out = append(out, agentproto.PowerShellInstall{
			Edition: p.Edition, Version: text(p.Version, agentproto.MaxInterpreterVersion), Arch: arch, Path: path,
			Preview: p.Preview, Store: p.Store, Usable: p.Usable && !blocked, Reason: text(p.Reason, maxLong), Blocked: blocked,
		})
	}
	return out
}

// cleanMetrics keeps measurements within physical bounds.
func cleanMetrics(m agentproto.Metrics) agentproto.Metrics {
	out := agentproto.Metrics{
		CPUPercent:  bounded(m.CPUPercent, 100),
		MemoryTotal: min(m.MemoryTotal, maxBytes), SwapTotal: min(m.SwapTotal, maxBytes),
		Load1: bounded(m.Load1, 1e6), Load5: bounded(m.Load5, 1e6), Load15: bounded(m.Load15, 1e6),
		UptimeSeconds: min(max(m.UptimeSeconds, 0), 1<<40), Processes: count(m.Processes),
		Filesystems: []agentproto.Filesystem{},
	}
	out.MemoryUsed = min(m.MemoryUsed, out.MemoryTotal)
	out.SwapUsed = min(m.SwapUsed, out.SwapTotal)
	for _, f := range m.Filesystems[:min(len(m.Filesystems), 4*agentproto.MaxListed)] {
		mount := text(f.Mount, maxLong)
		if mount == "" {
			continue
		}
		total := min(f.TotalBytes, maxBytes)
		out.Filesystems = append(out.Filesystems, agentproto.Filesystem{
			Mount: mount, Device: text(f.Device, 256), Type: text(f.Type, 32), TotalBytes: total, UsedBytes: min(f.UsedBytes, total),
		})
	}
	// Sorted before capping, so the same filesystems are kept whatever
	// order they came in.
	slices.SortFunc(out.Filesystems, func(a, b agentproto.Filesystem) int { return cmp.Compare(a.Mount, b.Mount) })
	out.Filesystems = out.Filesystems[:min(len(out.Filesystems), agentproto.MaxListed)]
	return out
}

func addresses(in []string) []string {
	out := []string{}
	for _, a := range in {
		if ip, err := netip.ParseAddr(strings.TrimSpace(a)); err == nil && len(out) < maxServers {
			out = append(out, ip.String())
		}
	}
	return out
}

func validMAC(s string) bool {
	if len(s) != 17 {
		return false
	}
	for i, r := range s {
		if i%3 == 2 {
			if r != ':' {
				return false
			}
		} else if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

func count(n int) int { return min(max(n, 0), maxCount) }

func bounded(v, limit float64) float64 {
	if math.IsNaN(v) || v < 0 {
		return 0
	}
	return min(v, limit)
}

func percent(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return min(float64(used)/float64(total)*100, 100)
}

// text strips control characters and invalid UTF-8, trims and cuts to
// maxRunes.
func text(s string, maxRunes int) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > maxRunes {
		s = strings.TrimSpace(string([]rune(s)[:maxRunes]))
	}
	return s
}
