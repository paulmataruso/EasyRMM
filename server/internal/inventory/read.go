package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Inventory is a device's inventory as the console shows it: everything but
// the packages, which are read on their own.
type Inventory struct {
	System         agentproto.SystemInfo  `json:"system"`
	CPU            agentproto.CPUInfo     `json:"cpu"`
	MemoryBytes    uint64                 `json:"memoryBytes"`
	OS             agentproto.OSInfo      `json:"os"`
	Disks          []agentproto.Disk      `json:"disks"`
	Interfaces     []agentproto.Interface `json:"interfaces"`
	Gateways       []string               `json:"gateways"`
	DNS            []string               `json:"dnsServers"`
	PackageManager string                 `json:"packageManager"`
	PackageCount   int                    `json:"packageCount"`
	ReceivedAt     time.Time              `json:"receivedAt"`
	// PowerShell lists the PowerShell installs the agent found on Windows
	// (ADR-0064); null when its agent does not report them.
	PowerShell []agentproto.PowerShellInstall `json:"powerShell"`
}

// Metrics are a device's latest measurements.
type Metrics struct {
	At            time.Time               `json:"at"`
	CPUPercent    float64                 `json:"cpuPercent"`
	MemoryTotal   int64                   `json:"memoryTotal"`
	MemoryUsed    int64                   `json:"memoryUsed"`
	SwapTotal     int64                   `json:"swapTotal"`
	SwapUsed      int64                   `json:"swapUsed"`
	Load1         float64                 `json:"load1"`
	Load5         float64                 `json:"load5"`
	Load15        float64                 `json:"load15"`
	UptimeSeconds int64                   `json:"uptimeSeconds"`
	Processes     int                     `json:"processes"`
	Filesystems   []agentproto.Filesystem `json:"filesystems"`
}

// Device is what the console reads for a device's page. Either part is nil
// until the agent first reports it.
type Device struct {
	Inventory *Inventory `json:"inventory"`
	Metrics   *Metrics   `json:"metrics"`
}

// Get returns a device's inventory and latest metrics.
func (s *Service) Get(ctx context.Context, c access.Caller, deviceID uuid.UUID) (*Device, error) {
	if _, err := devices.Lookup(ctx, s.db, c, deviceID); err != nil {
		return nil, err
	}
	out := &Device{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var data []byte
		inv := &Inventory{}
		err := tx.QueryRow(ctx, `SELECT data, package_manager, package_count, received_at FROM device_inventory WHERE device_id = $1`, deviceID).
			Scan(&data, &inv.PackageManager, &inv.PackageCount, &inv.ReceivedAt)
		switch {
		case err == nil:
			var doc agentproto.Inventory
			if err := json.Unmarshal(data, &doc); err != nil {
				return fmt.Errorf("reading stored inventory: %w", err)
			}
			inv.System, inv.CPU, inv.MemoryBytes, inv.OS = doc.System, doc.CPU, doc.Memory, doc.OS
			inv.Disks, inv.Interfaces, inv.Gateways, inv.DNS = nonNil(doc.Disks), nonNil(doc.Interfaces), nonNil(doc.Gateways), nonNil(doc.DNS)
			inv.PowerShell = doc.PowerShell
			out.Inventory = inv
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		m := &Metrics{}
		var fs []byte
		err = tx.QueryRow(ctx, `SELECT at, cpu_percent, memory_total, memory_used, swap_total, swap_used, load1, load5, load15,
				uptime_seconds, processes, filesystems FROM device_metrics WHERE device_id = $1`, deviceID).
			Scan(&m.At, &m.CPUPercent, &m.MemoryTotal, &m.MemoryUsed, &m.SwapTotal, &m.SwapUsed, &m.Load1, &m.Load5, &m.Load15,
				&m.UptimeSeconds, &m.Processes, &fs)
		switch {
		case err == nil:
			if err := json.Unmarshal(fs, &m.Filesystems); err != nil {
				return fmt.Errorf("reading stored filesystems: %w", err)
			}
			m.Filesystems = nonNil(m.Filesystems)
			out.Metrics = m
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		return nil
	})
	return out, err
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// Software lists a device's installed packages by name.
func (s *Service) Software(ctx context.Context, c access.Caller, deviceID uuid.UUID) ([]agentproto.Package, error) {
	d, err := devices.Lookup(ctx, s.db, c, deviceID)
	if err != nil {
		return nil, err
	}
	if !c.Can(rbac.PermSoftwareView, rbac.Site(d.OrganizationID, d.SiteID)) {
		return nil, apperr.Forbidden()
	}
	out := []agentproto.Package{}
	err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT name, version, arch, publisher FROM device_software WHERE device_id = $1
			ORDER BY lower(name), name, version, arch`, deviceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p agentproto.Package
			if err := rows.Scan(&p.Name, &p.Version, &p.Arch, &p.Publisher); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

// Ranges a history can cover, with the width of each averaged point.
var Ranges = map[string]struct{ Span, Bucket time.Duration }{
	"1h":  {time.Hour, time.Minute},
	"24h": {24 * time.Hour, 5 * time.Minute},
	"7d":  {7 * 24 * time.Hour, 30 * time.Minute},
}

// Sample is one point of a device's history: averages over its bucket.
type Sample struct {
	At            time.Time `json:"at"`
	CPUPercent    float64   `json:"cpuPercent"`
	MemoryPercent float64   `json:"memoryPercent"`
	SwapPercent   float64   `json:"swapPercent"`
	DiskPercent   float64   `json:"diskPercent"`
	Load1         float64   `json:"load1"`
}

// History is a device's samples over a range.
type History struct {
	Range         string    `json:"range"`
	BucketSeconds int       `json:"bucketSeconds"`
	From          time.Time `json:"from"`
	To            time.Time `json:"to"`
	Samples       []Sample  `json:"samples"`
}

// History returns a device's samples over rng (1h, 24h or 7d).
func (s *Service) History(ctx context.Context, c access.Caller, deviceID uuid.UUID, rng string) (*History, error) {
	r, ok := Ranges[rng]
	if !ok {
		return nil, apperr.Invalid("range", "Choose 1h, 24h or 7d.")
	}
	if _, err := devices.Lookup(ctx, s.db, c, deviceID); err != nil {
		return nil, err
	}
	out := &History{Range: rng, BucketSeconds: int(r.Bucket.Seconds()), Samples: []Sample{}}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT now() - $1::interval, now()`, seconds(r.Span)).Scan(&out.From, &out.To); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT date_bin($2::interval, at, 'epoch'::timestamptz) AS b,
				avg(cpu_percent), avg(memory_percent), avg(swap_percent), avg(disk_percent), avg(load1)
			FROM device_metric_samples WHERE device_id = $1 AND at >= $3
			GROUP BY b ORDER BY b`, deviceID, seconds(r.Bucket), out.From)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p Sample
			if err := rows.Scan(&p.At, &p.CPUPercent, &p.MemoryPercent, &p.SwapPercent, &p.DiskPercent, &p.Load1); err != nil {
				return err
			}
			out.Samples = append(out.Samples, p)
		}
		return rows.Err()
	})
	return out, err
}

func seconds(d time.Duration) string { return fmt.Sprintf("%d seconds", int64(d.Seconds())) }

// MaxSoftwareResults bounds a fleet software search.
const MaxSoftwareResults = 500

// SoftwareQuery filters a fleet software search.
type SoftwareQuery struct {
	// Search matches package names containing it, case-insensitively.
	Search         string
	OrganizationID uuid.UUID
	SiteID         uuid.UUID
	GroupID        uuid.UUID
}

// SoftwareSummary is one package version and how many devices have it.
type SoftwareSummary struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Devices int    `json:"devices"`
}

// SoftwareResult is a fleet software search's answer.
type SoftwareResult struct {
	Items []SoftwareSummary `json:"items"`
	// Truncated is true when more versions matched than are listed.
	Truncated bool `json:"truncated"`
}

// SearchSoftware finds package versions across the devices the caller may
// see, with how many devices have each.
func (s *Service) SearchSoftware(ctx context.Context, c access.Caller, q SoftwareQuery) (*SoftwareResult, error) {
	search := strings.ToLower(strings.TrimSpace(q.Search))
	if len(search) > maxText {
		return nil, apperr.Invalid("q", "Search for at most 200 characters.")
	}
	type key struct{ name, version string }
	counts := map[key]int{}
	var order []key
	truncated := false
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT s.name, s.version, d.organization_id, d.site_id, count(DISTINCT s.device_id)
			FROM device_software s JOIN devices d ON d.id = s.device_id
			WHERE ($1 = '' OR lower(s.name) LIKE '%' || $1 || '%' ESCAPE '\')
				AND ($2::uuid IS NULL OR d.organization_id = $2) AND ($3::uuid IS NULL OR d.site_id = $3)
				AND ($4::uuid IS NULL OR d.device_group_id = $4)
			GROUP BY s.name, s.version, d.organization_id, d.site_id
			ORDER BY lower(s.name), s.name, s.version LIMIT 20000`, likeEscape(search), nullID(q.OrganizationID), nullID(q.SiteID), nullID(q.GroupID))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k key
			var org, site uuid.UUID
			var n int
			if err := rows.Scan(&k.name, &k.version, &org, &site, &n); err != nil {
				return err
			}
			if !c.Can(rbac.PermSoftwareView, rbac.Site(org, site)) {
				continue
			}
			if _, seen := counts[k]; !seen {
				if len(order) == MaxSoftwareResults {
					truncated = true
					continue
				}
				order = append(order, k)
			}
			counts[k] += n
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	out := &SoftwareResult{Items: make([]SoftwareSummary, 0, len(order)), Truncated: truncated}
	for _, k := range order {
		out.Items = append(out.Items, SoftwareSummary{Name: k.name, Version: k.version, Devices: counts[k]})
	}
	return out, nil
}

// SoftwareDevice is a device that has a package.
type SoftwareDevice struct {
	DeviceID         uuid.UUID `json:"deviceId"`
	DeviceName       string    `json:"deviceName"`
	OrganizationID   uuid.UUID `json:"organizationId"`
	OrganizationName string    `json:"organizationName"`
	SiteID           uuid.UUID `json:"siteId"`
	SiteName         string    `json:"siteName"`
	Version          string    `json:"version"`
	Arch             string    `json:"arch"`
}

// MaxSoftwareDevices bounds the devices listed for one package.
const MaxSoftwareDevices = 1000

// SoftwareDevicesQuery selects the devices with a package.
type SoftwareDevicesQuery struct {
	Name string
	// Version, when not nil, limits the list to that version.
	Version *string
	// OrganizationID and SiteID, when set, limit it as SoftwareQuery does.
	OrganizationID uuid.UUID
	SiteID         uuid.UUID
	GroupID        uuid.UUID
}

// SoftwareDevices lists the devices with a package.
func (s *Service) SoftwareDevices(ctx context.Context, c access.Caller, q SoftwareDevicesQuery) ([]SoftwareDevice, error) {
	if q.Name == "" || len(q.Name) > maxText {
		return nil, apperr.Invalid("name", "Name a package.")
	}
	out := []SoftwareDevice{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT d.id, d.name, d.organization_id, o.name, d.site_id, st.name, s.version, s.arch
			FROM device_software s JOIN devices d ON d.id = s.device_id
				JOIN organizations o ON o.id = d.organization_id JOIN sites st ON st.id = d.site_id
			WHERE s.name = $1 AND ($2::text IS NULL OR s.version = $2)
				AND ($3::uuid IS NULL OR d.organization_id = $3) AND ($4::uuid IS NULL OR d.site_id = $4)
				AND ($6::uuid IS NULL OR d.device_group_id = $6)
			ORDER BY lower(d.name), d.id, s.version LIMIT $5`, q.Name, q.Version, nullID(q.OrganizationID), nullID(q.SiteID), MaxSoftwareDevices,
			nullID(q.GroupID))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d SoftwareDevice
			if err := rows.Scan(&d.DeviceID, &d.DeviceName, &d.OrganizationID, &d.OrganizationName, &d.SiteID, &d.SiteName, &d.Version, &d.Arch); err != nil {
				return err
			}
			if c.Can(rbac.PermSoftwareView, rbac.Site(d.OrganizationID, d.SiteID)) {
				out = append(out, d)
			}
		}
		return rows.Err()
	})
	return out, err
}

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func nullID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}
