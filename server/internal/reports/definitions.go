package reports

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

func likePattern(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	return "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s) + "%"
}

// --- Device inventory --------------------------------------------------------

var devicesReport = definition{
	title: "Device inventory",
	perm:  rbac.PermDeviceView,
	columns: []Column{
		{"organization", "Organization", TypeText},
		{"site", "Site", TypeText},
		{"device", "Device", TypeText},
		{"hostname", "Host name", TypeText},
		{"platform", "Platform", TypeText},
		{"os", "Operating system", TypeText},
		{"online", "Online", TypeBool},
		{"lastSeen", "Last seen", TypeTime},
		{"agentVersion", "Agent version", TypeText},
		{"manufacturer", "Manufacturer", TypeText},
		{"model", "Model", TypeText},
		{"serial", "Serial number", TypeText},
		{"processor", "Processor", TypeText},
		{"cores", "Cores", TypeNumber},
		{"memory", "Memory (GiB)", TypeNumber},
		{"disk", "Disk (GiB)", TypeNumber},
		{"addresses", "IP addresses", TypeText},
		{"inventoryAt", "Inventory reported", TypeTime},
	},
	run: func(ctx context.Context, tx pgx.Tx, q Query, out emit) error {
		rows, err := tx.Query(ctx, `SELECT d.organization_id, d.site_id, o.name, st.name, d.name, d.hostname, d.platform, d.os_description,
				`+onlineSQL+`, `+lastSeenSQL+`, coalesce(d.agent_version, ''), i.data, i.received_at
			FROM devices d`+fromSQL+` LEFT JOIN device_inventory i ON i.device_id = d.id
			WHERE `+scopeSQL+` AND ($4 = '' OR lower(d.name) LIKE $4 ESCAPE '\' OR lower(d.hostname) LIKE $4 ESCAPE '\')
			ORDER BY lower(o.name), o.id, lower(st.name), st.id, lower(d.name), d.id`,
			nullID(q.OrganizationID), nullID(q.SiteID), q.Platform, likePattern(q.Search))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var org, site uuid.UUID
			var orgName, siteName, name, host, platform, osDesc, agentVersion string
			var online bool
			var lastSeen, invAt *time.Time
			var data []byte
			if err := rows.Scan(&org, &site, &orgName, &siteName, &name, &host, &platform, &osDesc, &online, &lastSeen, &agentVersion, &data, &invAt); err != nil {
				return err
			}
			row := []any{orgName, siteName, name, host, platformName(platform), osDesc, online, timeOrNil(lastSeen), agentVersion}
			if data == nil {
				row = append(row, "", "", "", "", nil, nil, nil, "", nil)
			} else {
				var inv agentproto.Inventory
				if err := json.Unmarshal(data, &inv); err != nil {
					return fmt.Errorf("reports: inventory of %s: %w", name, err)
				}
				row = append(row, inv.System.Manufacturer, inv.System.Model, inv.System.Serial, inv.CPU.Model,
					inv.CPU.Cores, round1(float64(inv.Memory)/gib), round1(float64(diskBytes(inv.Disks))/gib),
					strings.Join(addresses(inv.Interfaces), "; "), timeOrNil(invAt))
			}
			if !out(org, site, row) {
				return nil
			}
		}
		return rows.Err()
	},
}

// diskBytes adds up the fixed disks.
func diskBytes(disks []agentproto.Disk) uint64 {
	var n uint64
	for _, d := range disks {
		if !d.Removable {
			n += d.SizeBytes
		}
	}
	return n
}

// addresses lists the addresses other computers can reach: no loopback or
// link-local ones, without their prefix length.
func addresses(ifs []agentproto.Interface) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, i := range ifs {
		for _, a := range i.Addresses {
			p, err := netip.ParsePrefix(a)
			if err != nil {
				continue
			}
			ip := p.Addr()
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || seen[ip.String()] {
				continue
			}
			seen[ip.String()] = true
			out = append(out, ip.String())
		}
	}
	return out
}

// --- Installed software ------------------------------------------------------

var softwareReport = definition{
	title: "Installed software",
	perm:  rbac.PermSoftwareView,
	columns: []Column{
		{"organization", "Organization", TypeText},
		{"site", "Site", TypeText},
		{"device", "Device", TypeText},
		{"platform", "Platform", TypeText},
		{"package", "Package", TypeText},
		{"version", "Version", TypeText},
		{"publisher", "Publisher", TypeText},
		{"arch", "Architecture", TypeText},
	},
	run: func(ctx context.Context, tx pgx.Tx, q Query, out emit) error {
		rows, err := tx.Query(ctx, `SELECT d.organization_id, d.site_id, o.name, st.name, d.name, d.platform, s.name, s.version, s.publisher, s.arch
			FROM device_software s JOIN devices d ON d.id = s.device_id`+fromSQL+`
			WHERE `+scopeSQL+` AND ($4 = '' OR lower(s.name) LIKE $4 ESCAPE '\')
			ORDER BY lower(o.name), o.id, lower(st.name), st.id, lower(d.name), d.id, lower(s.name), s.name, s.version
			LIMIT $5`,
			nullID(q.OrganizationID), nullID(q.SiteID), q.Platform, likePattern(q.Search), maxRows+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var org, site uuid.UUID
			var orgName, siteName, device, platform, pkg, version, publisher, arch string
			if err := rows.Scan(&org, &site, &orgName, &siteName, &device, &platform, &pkg, &version, &publisher, &arch); err != nil {
				return err
			}
			if !out(org, site, []any{orgName, siteName, device, platformName(platform), pkg, version, publisher, arch}) {
				return nil
			}
		}
		return rows.Err()
	},
}

// --- Device health -----------------------------------------------------------

var healthReport = definition{
	title: "Device health",
	perm:  rbac.PermDeviceView,
	columns: []Column{
		{"organization", "Organization", TypeText},
		{"site", "Site", TypeText},
		{"device", "Device", TypeText},
		{"platform", "Platform", TypeText},
		{"online", "Online", TypeBool},
		{"lastSeen", "Last seen", TypeTime},
		{"cpu", "Processor", TypePercent},
		{"memory", "Memory", TypePercent},
		{"filesystem", "Fullest filesystem", TypeText},
		{"disk", "Disk used", TypePercent},
		{"diskFree", "Disk free (GiB)", TypeNumber},
		{"uptime", "Up for (days)", TypeNumber},
		{"measuredAt", "Measured", TypeTime},
	},
	run: func(ctx context.Context, tx pgx.Tx, q Query, out emit) error {
		rows, err := tx.Query(ctx, `SELECT d.organization_id, d.site_id, o.name, st.name, d.name, d.platform, `+onlineSQL+`, `+lastSeenSQL+`,
				m.at, m.cpu_percent, m.memory_total, m.memory_used, m.uptime_seconds, m.filesystems
			FROM devices d`+fromSQL+` LEFT JOIN device_metrics m ON m.device_id = d.id
			WHERE `+scopeSQL+`
				AND ($4 = 0 OR coalesce(`+lastSeenSQL+` < now() - make_interval(days => $4), true))
			ORDER BY lower(o.name), o.id, lower(st.name), st.id, lower(d.name), d.id`,
			nullID(q.OrganizationID), nullID(q.SiteID), q.Platform, q.OfflineDays)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var org, site uuid.UUID
			var orgName, siteName, name, platform string
			var online bool
			var lastSeen, at *time.Time
			var cpu *float64
			var memTotal, memUsed, uptime *int64
			var fsJSON []byte
			if err := rows.Scan(&org, &site, &orgName, &siteName, &name, &platform, &online, &lastSeen, &at, &cpu, &memTotal, &memUsed, &uptime, &fsJSON); err != nil {
				return err
			}
			row := []any{orgName, siteName, name, platformName(platform), online, timeOrNil(lastSeen)}
			if at == nil {
				if q.DiskPercent > 0 {
					continue
				}
				row = append(row, nil, nil, "", nil, nil, nil, nil)
			} else {
				var fss []agentproto.Filesystem
				if len(fsJSON) > 0 {
					if err := json.Unmarshal(fsJSON, &fss); err != nil {
						return fmt.Errorf("reports: filesystems of %s: %w", name, err)
					}
				}
				mount, used, free, ok := fullest(fss)
				if q.DiskPercent > 0 && (!ok || used < float64(q.DiskPercent)) {
					continue
				}
				var mem any
				if *memTotal > 0 {
					mem = round1(float64(*memUsed) * 100 / float64(*memTotal))
				}
				row = append(row, round1(*cpu), mem)
				if ok {
					row = append(row, mount, round1(used), round1(free/gib))
				} else {
					row = append(row, "", nil, nil)
				}
				row = append(row, round1(float64(*uptime)/86400), at.UTC())
			}
			if !out(org, site, row) {
				return nil
			}
		}
		return rows.Err()
	},
}

// fullest finds the fullest filesystem: its mount point, percent used and
// bytes free.
func fullest(fss []agentproto.Filesystem) (mount string, used, free float64, ok bool) {
	for _, f := range fss {
		if f.TotalBytes == 0 {
			continue
		}
		p := float64(f.UsedBytes) * 100 / float64(f.TotalBytes)
		if !ok || p > used {
			mount, used, free, ok = f.Mount, p, float64(f.TotalBytes-min(f.UsedBytes, f.TotalBytes)), true
		}
	}
	return mount, used, free, ok
}

// --- Alert history -----------------------------------------------------------

var alertKinds = map[string]string{"offline": "Offline", "cpu": "Processor", "memory": "Memory", "disk": "Disk"}

var alertStatuses = map[string]string{"open": "Open", "acknowledged": "Acknowledged", "resolved": "Resolved"}

var resolutions = map[string]string{
	"cleared":        "Condition cleared",
	"manual":         "Resolved",
	"not_covered":    "Device left the policy's scope",
	"policy_off":     "Policy turned off",
	"policy_changed": "Policy changed",
	"policy_deleted": "Policy deleted",
}

var alertsReport = definition{
	title: "Alert history",
	perm:  rbac.PermAlertView,
	columns: []Column{
		{"opened", "Opened", TypeTime},
		{"organization", "Organization", TypeText},
		{"site", "Site", TypeText},
		{"device", "Device", TypeText},
		{"alert", "Alert", TypeText},
		{"kind", "Kind", TypeText},
		{"severity", "Severity", TypeText},
		{"status", "Status", TypeText},
		{"value", "Raised at", TypeText},
		{"hours", "Open for (hours)", TypeNumber},
		{"acknowledgedBy", "Acknowledged by", TypeText},
		{"resolved", "Resolved", TypeTime},
		{"resolution", "Resolution", TypeText},
	},
	run: func(ctx context.Context, tx pgx.Tx, q Query, out emit) error {
		rows, err := tx.Query(ctx, `SELECT d.organization_id, d.site_id, a.opened_at, o.name, st.name, d.name, a.name, a.kind, a.severity, a.status,
				a.value, a.acknowledged_by_label, a.resolved_at, coalesce(a.resolution, ''), a.resolved_by_label, now()
			FROM alerts a JOIN devices d ON d.id = a.device_id`+fromSQL+`
			WHERE `+scopeSQL+` AND a.opened_at > now() - make_interval(days => $4) AND ($5 = '' OR a.severity = $5)
			ORDER BY a.opened_at DESC, a.seq DESC
			LIMIT $6`,
			nullID(q.OrganizationID), nullID(q.SiteID), q.Platform, q.Days, q.Severity, maxRows+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var org, site uuid.UUID
			var opened, now time.Time
			var resolved *time.Time
			var orgName, siteName, device, name, kind, severity, status, ackBy, resolution, resolvedBy string
			var value float64
			if err := rows.Scan(&org, &site, &opened, &orgName, &siteName, &device, &name, &kind, &severity, &status,
				&value, &ackBy, &resolved, &resolution, &resolvedBy, &now); err != nil {
				return err
			}
			end := now
			if resolved != nil {
				end = *resolved
			}
			raised := fmt.Sprintf("%d%%", int(value+0.5))
			if kind == "offline" {
				raised = fmt.Sprintf("offline %d min", int(value+0.5))
			}
			res := resolutions[resolution]
			if resolution == "manual" && resolvedBy != "" {
				res = "Resolved by " + resolvedBy
			}
			row := []any{opened.UTC(), orgName, siteName, device, name, alertKinds[kind], strings.ToUpper(severity[:1]) + severity[1:],
				alertStatuses[status], raised, round1(end.Sub(opened).Hours()), ackBy, timeOrNil(resolved), res}
			if !out(org, site, row) {
				return nil
			}
		}
		return rows.Err()
	},
}

// --- Contacts ----------------------------------------------------------------

// contactPriorities are contacts' priorities as the report shows them.
var contactPriorities = map[string]string{"primary": "Primary", "secondary": "Secondary", "none": ""}

// contactsReport lists the customer record's contacts (ADR-0066): each
// organization's own, with no site, then each site's. They are personal
// data, and exporting them is recorded like every export.
var contactsReport = definition{
	title: "Contacts",
	perm:  rbac.PermDocView,
	columns: []Column{
		{"organization", "Organization", TypeText},
		{"site", "Site", TypeText},
		{"name", "Name", TypeText},
		{"jobTitle", "Job title", TypeText},
		{"email", "Email", TypeText},
		{"officePhone", "Office phone", TypeText},
		{"mobilePhone", "Mobile phone", TypeText},
		{"priority", "Priority", TypeText},
		{"emergency", "Emergency", TypeBool},
		{"note", "Note", TypeText},
	},
	run: func(ctx context.Context, tx pgx.Tx, q Query, out emit) error {
		rows, err := tx.Query(ctx, `SELECT c.organization_id, c.site_id, o.name, coalesce(st.name, ''), c.name, c.job_title, c.email,
				c.office_phone, c.mobile_phone, c.priority, c.emergency, c.note
			FROM contacts c JOIN organizations o ON o.id = c.organization_id LEFT JOIN sites st ON st.id = c.site_id
			WHERE ($1::uuid IS NULL OR c.organization_id = $1) AND ($2::uuid IS NULL OR c.site_id = $2)
			  AND ($3 = '' OR lower(c.name) LIKE $3 ESCAPE '\' OR lower(c.email) LIKE $3 ESCAPE '\')
			ORDER BY lower(o.name), o.id, c.site_id IS NOT NULL, lower(st.name), st.id,
				CASE c.priority WHEN 'primary' THEN 0 WHEN 'secondary' THEN 1 ELSE 2 END, lower(c.name), c.id`,
			nullID(q.OrganizationID), nullID(q.SiteID), likePattern(q.Search))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var org uuid.UUID
			var site *uuid.UUID
			var orgName, siteName, name, title, email, office, mobile, priority, note string
			var emergency bool
			if err := rows.Scan(&org, &site, &orgName, &siteName, &name, &title, &email, &office, &mobile, &priority, &emergency, &note); err != nil {
				return err
			}
			// An organization's own contact belongs to no site: the
			// permissions it needs are the organization's.
			var at uuid.UUID
			if site != nil {
				at = *site
			}
			if !out(org, at, []any{orgName, siteName, name, title, email, office, mobile, contactPriorities[priority], emergency, note}) {
				return nil
			}
		}
		return rows.Err()
	},
}
