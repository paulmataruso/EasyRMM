package monitoring

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Policy levels, as for scripts.
const (
	LevelShared       = "shared"
	LevelOrganization = "organization"
	LevelSite         = "site"
)

// Conditions a policy watches.
const (
	KindOffline = "offline"
	KindCPU     = "cpu"
	KindMemory  = "memory"
	KindDisk    = "disk"
	// KindDiskHealth watches each disk's health with one of the checks
	// below (ADR-0065).
	KindDiskHealth = "disk_health"
)

// Disk health checks (Policy.CheckName).
const (
	// CheckFailing: the disk's reading is failing. No threshold.
	CheckFailing = "failing"
	// CheckErrors: reallocated sectors plus NVMe media errors at or above a
	// count.
	CheckErrors = "errors"
	// CheckPending: pending plus offline-uncorrectable sectors at or above
	// a count.
	CheckPending = "pending"
	// CheckWear: rated endurance used at or above a percentage.
	CheckWear = "wear"
	// CheckTemperature: every reading of the policy's minutes at or above
	// a temperature in °C, or the drive's own limit without one.
	CheckTemperature = "temperature"
)

// DiskMinutes is the reading interval: a temperature check watches at
// least this long, and the other disk checks take it as their minutes.
const DiskMinutes = 30

// Severities.
const (
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Limits on policies.
const (
	MaxName           = 200
	MaxDescription    = 2000
	MaxMinutes        = 1440
	MinOfflineMinutes = 3
	MaxPolicies       = 1000
)

// Policy is an alert policy.
type Policy struct {
	ID               uuid.UUID  `json:"id"`
	Level            string     `json:"level"`
	OrganizationID   *uuid.UUID `json:"organizationId"`
	OrganizationName string     `json:"organizationName,omitempty"`
	SiteID           *uuid.UUID `json:"siteId"`
	SiteName         string     `json:"siteName,omitempty"`
	Name             string     `json:"name"`
	Description      string     `json:"description"`
	Kind             string     `json:"kind"`
	// CheckName is the disk health check, nil for the other kinds.
	CheckName *string `json:"checkName"`
	// Threshold is the percentage for processor, memory and disk; nil for
	// offline. For disk health, the count, percentage or °C the check
	// takes: nil for failing, and for a temperature check that uses each
	// drive's own limit.
	Threshold *int   `json:"threshold"`
	Minutes   int    `json:"minutes"`
	Severity  string `json:"severity"`
	Enabled   bool   `json:"enabled"`
	// ActiveAlerts counts the policy's unresolved alerts on devices the
	// caller can see.
	ActiveAlerts int       `json:"activeAlerts"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	CanEdit      bool      `json:"canEdit"`
}

func (p *Policy) level() (org, site uuid.UUID) {
	if p.OrganizationID != nil {
		org = *p.OrganizationID
	}
	if p.SiteID != nil {
		site = *p.SiteID
	}
	return org, site
}

// canAt reports whether the caller holds perm at a policy's level or, for
// reading, anywhere below it.
func canAt(c access.Caller, perm rbac.Permission, org, site uuid.UUID, below bool) bool {
	switch {
	case org == uuid.Nil && below:
		return c.CanAnywhere(perm)
	case org == uuid.Nil:
		return c.CanGlobal(perm)
	case site != uuid.Nil:
		return c.Can(perm, rbac.Site(org, site))
	case below:
		return c.CanInOrg(perm, org)
	default:
		return c.Can(perm, rbac.Org(org))
	}
}

const policyColumns = `p.id, p.organization_id, coalesce(o.name, ''), p.site_id, coalesce(si.name, ''),
	p.name, p.description, p.kind, p.check_name, p.threshold, p.minutes, p.severity, p.enabled,
	(SELECT count(*) FROM alerts a WHERE a.policy_id = p.id AND a.status <> 'resolved'),
	p.created_at, p.updated_at`

const policyFrom = ` FROM alert_policies p
	LEFT JOIN organizations o ON o.id = p.organization_id
	LEFT JOIN sites si ON si.id = p.site_id`

func scanPolicy(row pgx.Row) (*Policy, error) {
	var p Policy
	if err := row.Scan(&p.ID, &p.OrganizationID, &p.OrganizationName, &p.SiteID, &p.SiteName,
		&p.Name, &p.Description, &p.Kind, &p.CheckName, &p.Threshold, &p.Minutes, &p.Severity, &p.Enabled,
		&p.ActiveAlerts, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	switch {
	case p.SiteID != nil:
		p.Level = LevelSite
	case p.OrganizationID != nil:
		p.Level = LevelOrganization
	default:
		p.Level = LevelShared
	}
	return &p, nil
}

// PolicyQuery filters the policy list.
type PolicyQuery struct {
	// OrganizationID lists the policies that apply in an organization: the
	// shared ones, its own and its sites'.
	OrganizationID uuid.UUID
}

// ListPolicies returns the policies the caller can read, by name.
func (s *Service) ListPolicies(ctx context.Context, c access.Caller, q PolicyQuery) ([]*Policy, error) {
	out := []*Policy{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+policyColumns+policyFrom+`
			WHERE ($1::uuid IS NULL OR p.organization_id IS NULL OR p.organization_id = $1)
			ORDER BY lower(p.name), p.id LIMIT $2`, nullUUID(q.OrganizationID), MaxPolicies)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			p, err := scanPolicy(rows)
			if err != nil {
				return err
			}
			org, site := p.level()
			if !canAt(c, rbac.PermMonitorView, org, site, true) {
				continue
			}
			p.CanEdit = canAt(c, rbac.PermMonitorManage, org, site, false)
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

// GetPolicy returns one policy.
func (s *Service) GetPolicy(ctx context.Context, c access.Caller, id uuid.UUID) (*Policy, error) {
	var p *Policy
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var err error
		p, err = s.getPolicy(ctx, tx, c, id, false)
		return err
	})
	return p, err
}

func (s *Service) getPolicy(ctx context.Context, tx pgx.Tx, c access.Caller, id uuid.UUID, lock bool) (*Policy, error) {
	q := `SELECT ` + policyColumns + policyFrom + ` WHERE p.id = $1`
	if lock {
		q += ` FOR UPDATE OF p`
	}
	p, err := scanPolicy(tx.QueryRow(ctx, q, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	org, site := p.level()
	if !canAt(c, rbac.PermMonitorView, org, site, true) {
		return nil, apperr.NotFound()
	}
	p.CanEdit = canAt(c, rbac.PermMonitorManage, org, site, false)
	return p, nil
}

// editable reads a policy for a change: readable (or not found), writable
// (or forbidden), and locked. Row locks need the update policy too, so the
// check reads before it locks.
func (s *Service) editable(ctx context.Context, tx pgx.Tx, c access.Caller, id uuid.UUID) (*Policy, error) {
	cur, err := s.getPolicy(ctx, tx, c, id, false)
	if err != nil {
		return nil, err
	}
	if !cur.CanEdit {
		return nil, apperr.Forbidden()
	}
	cur, err = s.getPolicy(ctx, tx, c, id, true)
	if errors.Is(err, apperr.ErrNotFound) {
		return nil, apperr.Forbidden()
	}
	return cur, err
}

// PolicyInput creates a policy.
type PolicyInput struct {
	OrganizationID *uuid.UUID `json:"organizationId"`
	SiteID         *uuid.UUID `json:"siteId"`
	Name           string     `json:"name"`
	Description    string     `json:"description"`
	Kind           string     `json:"kind"`
	CheckName      *string    `json:"checkName"`
	Threshold      *int       `json:"threshold"`
	Minutes        int        `json:"minutes"`
	Severity       string     `json:"severity"`
	// Enabled defaults to true.
	Enabled *bool `json:"enabled"`
}

// PolicyPatch changes a policy; nil fields stay as they are. A policy does
// not move between levels. Changing to Offline, or to the failing check,
// drops the threshold; changing away from disk health drops the check.
type PolicyPatch struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Kind        *string `json:"kind"`
	CheckName   *string `json:"checkName"`
	Threshold   *int    `json:"threshold"`
	// DriveLimit, true, has a temperature check use each drive's own limit
	// and drops the threshold.
	DriveLimit *bool   `json:"driveLimit"`
	Minutes    *int    `json:"minutes"`
	Severity   *string `json:"severity"`
	Enabled    *bool   `json:"enabled"`
}

// condition is what a policy watches and how.
type condition struct {
	name, description, kind, severity string
	checkName                         *string
	threshold                         *int
	minutes                           int
	enabled                           bool
}

func validKind(k string) bool {
	return k == KindOffline || k == KindCPU || k == KindMemory || k == KindDisk || k == KindDiskHealth
}

func (cd *condition) validate() error {
	f := apperr.Fields{}
	f.Check(cd.name != "", "name", "Enter a name.")
	f.Check(utf8.RuneCountInString(cd.name) <= MaxName, "name", "Use at most 200 characters.")
	f.Check(utf8.RuneCountInString(cd.description) <= MaxDescription, "description", "Use at most 2,000 characters.")
	f.Check(cd.severity == SeverityWarning || cd.severity == SeverityCritical, "severity", "Choose warning or critical.")
	switch {
	case !validKind(cd.kind):
		f.Add("kind", "Choose offline, processor, memory, disk or disk health.")
	case cd.kind == KindDiskHealth:
		cd.validateDisk(f)
	case cd.kind == KindOffline:
		cd.checkName = nil
		cd.threshold = nil
		f.Check(cd.minutes >= MinOfflineMinutes && cd.minutes <= MaxMinutes, "minutes", "Use 3 to 1,440 minutes.")
	default:
		cd.checkName = nil
		f.Check(cd.threshold != nil && *cd.threshold >= 1 && *cd.threshold <= 100, "threshold", "Use a percentage from 1 to 100.")
		f.Check(cd.minutes >= 1 && cd.minutes <= MaxMinutes, "minutes", "Use 1 to 1,440 minutes.")
	}
	return f.Err()
}

// validateDisk checks a disk health policy (ADR-0065, "Alerts"): a check,
// and the threshold it takes. Minutes apply to temperature only; the other
// checks take the reading interval.
func (cd *condition) validateDisk(f apperr.Fields) {
	check := ""
	if cd.checkName != nil {
		check = *cd.checkName
	}
	inRange := cd.threshold != nil && *cd.threshold >= 1 && *cd.threshold <= 100
	switch check {
	case CheckFailing:
		cd.threshold, cd.minutes = nil, DiskMinutes
	case CheckErrors, CheckPending:
		cd.minutes = DiskMinutes
		f.Check(inRange, "threshold", "Use a count from 1 to 100.")
	case CheckWear:
		cd.minutes = DiskMinutes
		f.Check(inRange, "threshold", "Use a percentage from 1 to 100.")
	case CheckTemperature:
		f.Check(cd.threshold == nil || inRange, "threshold", "Use 1 to 100 °C, or the drive's own limit.")
		f.Check(cd.minutes >= DiskMinutes && cd.minutes <= MaxMinutes, "minutes", "Use 30 to 1,440 minutes.")
	default:
		f.Add("checkName", "Choose failing, errors, pending, wear or temperature.")
	}
}

// CreatePolicy adds a policy at the level the input names.
func (s *Service) CreatePolicy(ctx context.Context, c access.Caller, in PolicyInput) (*Policy, error) {
	var org, site uuid.UUID
	if in.OrganizationID != nil {
		org = *in.OrganizationID
	}
	if in.SiteID != nil {
		site = *in.SiteID
		if org == uuid.Nil {
			return nil, apperr.Invalid("organizationId", "A site's policy needs its organization.")
		}
	}
	if !canAt(c, rbac.PermMonitorManage, org, site, false) {
		return nil, apperr.Forbidden()
	}
	cd := condition{
		name: cleanText(in.Name, false), description: cleanText(in.Description, true),
		kind: in.Kind, checkName: in.CheckName, severity: in.Severity, threshold: in.Threshold, minutes: in.Minutes,
		enabled: in.Enabled == nil || *in.Enabled,
	}
	if err := cd.validate(); err != nil {
		return nil, err
	}
	var id uuid.UUID
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `INSERT INTO alert_policies (organization_id, site_id, name, description, kind, check_name, threshold, minutes, severity, enabled,
				created_by, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11) RETURNING id`,
			nullUUID(org), nullUUID(site), cd.name, cd.description, cd.kind, cd.checkName, cd.threshold, cd.minutes, cd.severity, cd.enabled,
			nullUUID(c.Actor.ID)).Scan(&id)
		if err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "alert_policy.create", Outcome: audit.Success,
			OrganizationID: org, SiteID: site, TargetType: "alert_policy", TargetID: id.String(),
			Details: map[string]any{"name": cd.name, "kind": cd.kind, "checkName": cd.checkName, "threshold": cd.threshold, "minutes": cd.minutes,
				"severity": cd.severity, "enabled": cd.enabled},
		})
	})
	if err != nil {
		return nil, policyWriteError(err)
	}
	return s.GetPolicy(ctx, c, id)
}

// UpdatePolicy changes a policy. Its unresolved alerts follow a new name or
// severity; a changed condition resolves them ("policy_changed") and
// turning it off resolves them ("policy_off"), both at once. The next
// evaluation raises them again under the new condition.
func (s *Service) UpdatePolicy(ctx context.Context, c access.Caller, id uuid.UUID, p PolicyPatch) (*Policy, error) {
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		cur, err := s.editable(ctx, tx, c, id)
		if err != nil {
			return err
		}
		cd := condition{
			name: cur.Name, description: cur.Description, kind: cur.Kind, checkName: cur.CheckName, severity: cur.Severity,
			threshold: cur.Threshold, minutes: cur.Minutes, enabled: cur.Enabled,
		}
		if p.Name != nil {
			cd.name = cleanText(*p.Name, false)
		}
		if p.Description != nil {
			cd.description = cleanText(*p.Description, true)
		}
		if p.Kind != nil {
			cd.kind = *p.Kind
		}
		if p.CheckName != nil {
			cd.checkName = p.CheckName
		}
		if p.Threshold != nil {
			cd.threshold = p.Threshold
		}
		if p.DriveLimit != nil && *p.DriveLimit {
			cd.threshold = nil
		}
		if p.Minutes != nil {
			cd.minutes = *p.Minutes
		}
		if p.Severity != nil {
			cd.severity = *p.Severity
		}
		if p.Enabled != nil {
			cd.enabled = *p.Enabled
		}
		if err := cd.validate(); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE alert_policies SET name = $2, description = $3, kind = $4, check_name = $5, threshold = $6,
				minutes = $7, severity = $8, enabled = $9, updated_by = $10 WHERE id = $1`,
			id, cd.name, cd.description, cd.kind, cd.checkName, cd.threshold, cd.minutes, cd.severity, cd.enabled, nullUUID(c.Actor.ID)); err != nil {
			return err
		}
		changes := policyChanges(cur, &cd)
		if len(changes) == 0 {
			return nil
		}
		if _, err := reconcile(ctx, tx, s.now(), id); err != nil {
			return err
		}
		org, site := cur.level()
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "alert_policy.update", Outcome: audit.Success,
			OrganizationID: org, SiteID: site, TargetType: "alert_policy", TargetID: id.String(),
			Details: map[string]any{"name": cd.name, "changes": changes},
		})
	})
	if err != nil {
		return nil, policyWriteError(err)
	}
	return s.GetPolicy(ctx, c, id)
}

type change[T any] struct {
	From T `json:"from"`
	To   T `json:"to"`
}

func policyChanges(cur *Policy, cd *condition) map[string]any {
	changes := map[string]any{}
	if cd.name != cur.Name {
		changes["name"] = change[string]{cur.Name, cd.name}
	}
	if cd.description != cur.Description {
		changes["description"] = true
	}
	if cd.kind != cur.Kind {
		changes["kind"] = change[string]{cur.Kind, cd.kind}
	}
	if !same(cd.checkName, cur.CheckName) {
		changes["checkName"] = change[*string]{cur.CheckName, cd.checkName}
	}
	if !same(cd.threshold, cur.Threshold) {
		changes["threshold"] = change[*int]{cur.Threshold, cd.threshold}
	}
	if cd.minutes != cur.Minutes {
		changes["minutes"] = change[int]{cur.Minutes, cd.minutes}
	}
	if cd.severity != cur.Severity {
		changes["severity"] = change[string]{cur.Severity, cd.severity}
	}
	if cd.enabled != cur.Enabled {
		changes["enabled"] = change[bool]{cur.Enabled, cd.enabled}
	}
	return changes
}

func same[T comparable](a, b *T) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

// DeletePolicy removes a policy and resolves its alerts ("policy_deleted").
// Resolved alerts keep its name and condition.
func (s *Service) DeletePolicy(ctx context.Context, c access.Caller, id uuid.UUID) error {
	return s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		cur, err := s.editable(ctx, tx, c, id)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE alerts SET status = 'resolved', resolved_at = $2, resolution = 'policy_deleted'
				WHERE policy_id = $1 AND status <> 'resolved'`, id, s.now()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM alert_policies WHERE id = $1`, id); err != nil {
			return err
		}
		org, site := cur.level()
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "alert_policy.delete", Outcome: audit.Success,
			OrganizationID: org, SiteID: site, TargetType: "alert_policy", TargetID: id.String(),
			Details: map[string]any{"name": cur.Name, "kind": cur.Kind},
		})
	})
}

func policyWriteError(err error) error {
	switch {
	case database.IsUniqueViolation(err):
		return apperr.Invalid("name", "A policy with this name already exists here.")
	case database.IsForeignKeyViolation(err):
		return apperr.Invalid("siteId", "That site is not in that organization.")
	case database.IsRLSViolation(err):
		return apperr.Forbidden()
	}
	return err
}
