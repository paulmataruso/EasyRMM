// Package reports turns what EasyRMM knows about devices into tables to read
// in the console and take away as CSV (ADR-0029). Reports only read: each
// runs in the caller's data scope and keeps the rows of sites where the
// caller holds report.view and the permission for what the report shows.
package reports

import (
	"bytes"
	"context"
	"maps"
	"math"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

const (
	// MaxRows is the most rows a report has; past it the report says it was
	// cut short.
	MaxRows = 100_000
	// PreviewRows is how many rows the console is sent; the CSV has them all.
	PreviewRows = 1_000
	// maxSearch is the longest search text accepted.
	maxSearch = 200
)

// maxRows is MaxRows, lowered by tests.
var maxRows = MaxRows

// Column types tell the console how to show a value. The value itself is
// already in the unit the label names.
const (
	TypeText    = "text"
	TypeNumber  = "number"
	TypePercent = "percent"
	TypeTime    = "time"
	TypeBool    = "bool"
)

// Column describes one column of a report.
type Column struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Type  string `json:"type"`
}

// Report is a report's result. Each row has one value per column: a string,
// a number, a bool, a time, or nil when there is nothing to show.
type Report struct {
	Name    string   `json:"name"`
	Title   string   `json:"title"`
	Columns []Column `json:"columns"`
	Rows    [][]any  `json:"rows"`
	// Total counts every row of the report, up to MaxRows; Rows may hold
	// fewer.
	Total int `json:"total"`
	// Truncated says the report has more than MaxRows rows.
	Truncated   bool      `json:"truncated"`
	GeneratedAt time.Time `json:"generatedAt"`

	// from counts the rows by the organization they came from, for the
	// export's audit entries.
	from map[uuid.UUID]*orgRows
}

// orgRows is the part of a report that came from one organization.
type orgRows struct {
	rows  int
	sites map[uuid.UUID]bool
}

// Query narrows a report. Each report reads the fields it has use for.
type Query struct {
	OrganizationID uuid.UUID
	SiteID         uuid.UUID
	// Platform is windows, linux, or empty for every platform.
	Platform string
	// Search matches device names and host names (devices), package
	// names (software) or contacts' names and email addresses (contacts),
	// ignoring case.
	Search string
	// Days is how far back alerts go (alerts).
	Days int
	// OfflineDays keeps devices not seen for at least this many days
	// (health); 0 keeps every device.
	OfflineDays int
	// DiskPercent keeps devices whose fullest filesystem is at least this
	// full (health); 0 keeps every device.
	DiskPercent int
	// Severity is warning, critical, or empty for both (alerts).
	Severity string
	// Compliance is an EasyPatch compliance status, or unlinked for devices
	// EasyPatch does not patch (patch-compliance).
	Compliance string
	// Category and Result are EasyPatch's update category and an update's
	// result (patch-installations).
	Category, Result string
}

// Defaults for the query fields that have them.
const (
	DefaultDays = 30
	MaxDays     = 365
)

func (q *Query) check() error {
	f := apperr.Fields{}
	f.Check(q.Platform == "" || q.Platform == "windows" || q.Platform == "linux", "platform", "Choose Windows or Linux.")
	f.Check(len(q.Search) <= maxSearch, "q", "Search for at most 200 characters.")
	if q.Days == 0 {
		q.Days = DefaultDays
	}
	f.Check(q.Days >= 1 && q.Days <= MaxDays, "days", "Choose from 1 to 365 days.")
	f.Check(q.OfflineDays >= 0 && q.OfflineDays <= 3650, "offlineDays", "Choose from 0 to 3650 days.")
	f.Check(q.DiskPercent >= 0 && q.DiskPercent <= 100, "diskPercent", "Choose a percentage from 0 to 100.")
	f.Check(q.Severity == "" || q.Severity == "warning" || q.Severity == "critical", "severity", "Choose warning or critical.")
	return f.Err()
}

// emit hands one row to the report, with the site it belongs to. It returns
// false once the report has all the rows it can hold.
type emit func(org, site uuid.UUID, row []any) bool

type definition struct {
	title string
	// perm is what the rows show, needed at their site besides report.view.
	perm    rbac.Permission
	columns []Column
	run     func(ctx context.Context, tx pgx.Tx, q Query, out emit) error
	// patch, instead of run, reads the report from the patching engine
	// and says whether it had more rows than it gave.
	patch func(ctx context.Context, src PatchSource, c access.Caller, q Query, out emit) (bool, error)
}

var definitions = map[string]definition{
	"devices":  devicesReport,
	"software": softwareReport,
	"health":   healthReport,
	"alerts":   alertsReport,

	"patch-compliance":    patchComplianceReport,
	"patch-installations": patchInstallationsReport,

	"contacts": contactsReport,
}

// Names lists the reports there are.
func Names() []string {
	return []string{"devices", "software", "health", "alerts", "patch-compliance", "patch-installations", "contacts"}
}

// Service runs reports.
type Service struct {
	db    *database.DB
	audit *audit.Logger
	now   func() time.Time
	// patch is where the patch reports come from (UsePatching).
	patch PatchSource
}

// New builds the service.
func New(db *database.DB, auditLog *audit.Logger) *Service {
	return &Service{db: db, audit: auditLog, now: time.Now}
}

// Run produces a report, keeping at most keep rows (Total still counts them
// all).
func (s *Service) Run(ctx context.Context, c access.Caller, name string, q Query, keep int) (*Report, error) {
	def, ok := definitions[name]
	if !ok || (def.patch != nil && s.patch == nil) {
		return nil, apperr.NotFound()
	}
	if !c.CanAnywhere(rbac.PermReportView) || !c.CanAnywhere(def.perm) {
		return nil, apperr.Forbidden()
	}
	if err := q.check(); err != nil {
		return nil, err
	}
	rep := &Report{Name: name, Title: def.title, Columns: def.columns, Rows: [][]any{}, GeneratedAt: s.now().UTC(), from: map[uuid.UUID]*orgRows{}}
	out := func(org, site uuid.UUID, row []any) bool {
		if !c.Can(rbac.PermReportView, rbac.Site(org, site)) || !c.Can(def.perm, rbac.Site(org, site)) {
			return true
		}
		if rep.Total == maxRows {
			rep.Truncated = true
			return false
		}
		rep.Total++
		o := rep.from[org]
		if o == nil {
			o = &orgRows{sites: map[uuid.UUID]bool{}}
			rep.from[org] = o
		}
		o.rows++
		o.sites[site] = true
		if len(rep.Rows) < keep {
			rep.Rows = append(rep.Rows, row)
		}
		return true
	}
	if def.patch != nil {
		truncated, err := def.patch(ctx, s.patch, c, q, out)
		if err != nil {
			return nil, err
		}
		rep.Truncated = rep.Truncated || truncated
		return rep, nil
	}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error { return def.run(ctx, tx, q, out) })
	if err != nil {
		return nil, err
	}
	return rep, nil
}

// Export produces a whole report for download and records that it left
// EasyRMM: one audit entry for each organization whose rows it holds, under
// that organization (and its site, when the rows share one), so that the
// organization's administrators see it. The organization and site the
// request asked for are only recorded as filters: the entry is never filed
// under an organization the export took nothing from. An export with no
// rows is recorded at platform level.
func (s *Service) Export(ctx context.Context, c access.Caller, name string, q Query) (*Report, error) {
	if q.Days == 0 {
		// As Run reads it, so that the audit entry says the same.
		q.Days = DefaultDays
	}
	rep, err := s.Run(ctx, c, name, q, MaxRows)
	if err != nil {
		return nil, err
	}
	details := map[string]any{"report": name, "rows": rep.Total, "truncated": rep.Truncated}
	for k, v := range map[string]string{"platform": q.Platform, "q": q.Search, "severity": q.Severity, "compliance": q.Compliance,
		"category": q.Category, "result": q.Result} {
		if v != "" {
			details[k] = v
		}
	}
	if q.OrganizationID != uuid.Nil {
		details["organizationId"] = q.OrganizationID.String()
	}
	if q.SiteID != uuid.Nil {
		details["siteId"] = q.SiteID.String()
	}
	switch name {
	case "alerts", "patch-installations":
		details["days"] = q.Days
	case "health":
		details["offlineDays"], details["diskPercent"] = q.OfflineDays, q.DiskPercent
	}
	event := func(org, site uuid.UUID, d map[string]any) audit.Event {
		return audit.Event{Actor: c.Actor, Action: "report.export", OrganizationID: org, SiteID: site,
			TargetType: "report", TargetID: name, Outcome: audit.Success, Details: d}
	}
	var events []audit.Event
	if len(rep.from) == 0 {
		events = append(events, event(uuid.Nil, uuid.Nil, details))
	}
	orgs := slices.SortedFunc(maps.Keys(rep.from), func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	for _, org := range orgs {
		o := rep.from[org]
		d := maps.Clone(details)
		d["rows"] = o.rows
		if len(orgs) > 1 {
			d["totalRows"], d["organizations"] = rep.Total, len(orgs)
		}
		var site uuid.UUID
		if len(o.sites) == 1 {
			for site = range o.sites {
			}
		}
		events = append(events, event(org, site, d))
	}
	// Recorded even if the client has gone: the data was produced.
	ctx = context.WithoutCancel(ctx)
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		for _, e := range events {
			if err := s.audit.Write(ctx, tx, e); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rep, nil
}

// Shared SQL: the scope columns every report filters on.
const (
	// online is a device's state as the device list shows it (ADR-0014,
	// ADR-0018): either agent checked in recently.
	onlineSQL   = `(d.remote_online OR coalesce(d.agent_last_seen_at > now() - interval '3 minutes', false))`
	lastSeenSQL = `greatest(d.last_seen_at, d.agent_last_seen_at)`
	scopeSQL    = `($1::uuid IS NULL OR d.organization_id = $1) AND ($2::uuid IS NULL OR d.site_id = $2) AND ($3 = '' OR d.platform = $3)`
	fromSQL     = ` JOIN organizations o ON o.id = d.organization_id JOIN sites st ON st.id = d.site_id`
)

func nullID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

var platformNames = map[string]string{"windows": "Windows", "linux": "Linux", "macos": "macOS", "other": "Other"}

func platformName(p string) string {
	if n, ok := platformNames[p]; ok {
		return n
	}
	return p
}

const gib = 1 << 30

// round1 rounds to one decimal place.
func round1(v float64) float64 { return math.Round(v*10) / 10 }

// timeOrNil gives nil for a missing time, so that it shows as empty.
func timeOrNil(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC()
}
