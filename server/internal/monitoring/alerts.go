package monitoring

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Alert statuses.
const (
	StatusOpen         = "open"
	StatusAcknowledged = "acknowledged"
	StatusResolved     = "resolved"
)

// Alert is one policy's condition on one device, and on one of its disks
// for disk health (Subject).
type Alert struct {
	ID               uuid.UUID  `json:"id"`
	PolicyID         *uuid.UUID `json:"policyId"`
	DeviceID         uuid.UUID  `json:"deviceId"`
	DeviceName       string     `json:"deviceName"`
	OrganizationID   uuid.UUID  `json:"organizationId"`
	OrganizationName string     `json:"organizationName"`
	SiteID           uuid.UUID  `json:"siteId"`
	SiteName         string     `json:"siteName"`
	// The policy's name, condition and severity: as they were when the
	// alert resolved, or as they are while it is not.
	Name      string  `json:"name"`
	Kind      string  `json:"kind"`
	CheckName *string `json:"checkName"`
	Threshold *int    `json:"threshold"`
	Minutes   int     `json:"minutes"`
	Severity  string  `json:"severity"`
	Status    string  `json:"status"`
	// Subject is the disk's identity for disk health, empty for the other
	// kinds; SubjectLabel names it ("PhysicalDrive1 · Samsung SSD 870 EVO
	// 1TB") and Detail says what holds ("Pending sectors 8,
	// uncorrectable 0").
	Subject      string `json:"subject"`
	SubjectLabel string `json:"subjectLabel"`
	Detail       string `json:"detail"`
	// Value raised the alert; LastValue is the latest. Percent, or minutes
	// without a check-in for offline; for disk health the count,
	// percentage or °C the check watches, 1 for failing.
	Value          float64    `json:"value"`
	LastValue      float64    `json:"lastValue"`
	OpenedAt       time.Time  `json:"openedAt"`
	AcknowledgedAt *time.Time `json:"acknowledgedAt"`
	AcknowledgedBy string     `json:"acknowledgedBy,omitempty"`
	ResolvedAt     *time.Time `json:"resolvedAt"`
	ResolvedBy     string     `json:"resolvedBy,omitempty"`
	// Resolution says why it resolved: cleared, manual, not_covered,
	// policy_off, policy_changed, policy_deleted or subject_gone (a disk
	// missing from the device's hardware reports for 14 days).
	Resolution string `json:"resolution,omitempty"`
	CanManage  bool   `json:"canManage"`
	// Repairs are the repairs started on the device since the alert opened,
	// set when one alert is read, for the remote access kinds (ADR-0069).
	Repairs []AlertRepair `json:"repairs,omitempty"`

	seq int64
}

const alertColumns = `a.id, a.seq, a.policy_id, a.device_id, d.name, d.organization_id, o.name, d.site_id, si.name,
	a.name, a.kind, a.check_name, a.threshold, a.minutes, a.severity, a.status, a.subject, a.subject_label, a.detail,
	a.value, a.last_value, a.opened_at,
	a.acknowledged_at, a.acknowledged_by_label, a.resolved_at, a.resolved_by_label, coalesce(a.resolution, '')`

const alertFrom = ` FROM alerts a
	JOIN devices d ON d.id = a.device_id
	JOIN organizations o ON o.id = d.organization_id
	JOIN sites si ON si.id = d.site_id`

func scanAlert(row pgx.Row) (*Alert, error) {
	var a Alert
	err := row.Scan(&a.ID, &a.seq, &a.PolicyID, &a.DeviceID, &a.DeviceName, &a.OrganizationID, &a.OrganizationName, &a.SiteID, &a.SiteName,
		&a.Name, &a.Kind, &a.CheckName, &a.Threshold, &a.Minutes, &a.Severity, &a.Status, &a.Subject, &a.SubjectLabel, &a.Detail,
		&a.Value, &a.LastValue, &a.OpenedAt,
		&a.AcknowledgedAt, &a.AcknowledgedBy, &a.ResolvedAt, &a.ResolvedBy, &a.Resolution)
	return &a, err
}

func (a *Alert) site() rbac.Resource { return rbac.Site(a.OrganizationID, a.SiteID) }

// AlertQuery filters the alert list.
type AlertQuery struct {
	// Status is "active" (open or acknowledged; the default), "resolved" or
	// "all".
	Status         string
	DeviceID       uuid.UUID
	OrganizationID uuid.UUID
	SiteID         uuid.UUID
	Severity       string
	// PolicyID and Subject narrow to one policy's alerts, and for disk
	// health to one disk's: an alert's earlier and later openings.
	PolicyID uuid.UUID
	Subject  string
	// Before pages: alerts opened before the one with this cursor.
	Before int64
	Limit  int
}

// Alert list filters.
const (
	FilterActive   = "active"
	FilterResolved = "resolved"
	FilterAll      = "all"
)

// ListAlerts returns the alerts on devices the caller can see, newest
// first, and the cursor of the next page (0 when there is none).
func (s *Service) ListAlerts(ctx context.Context, c access.Caller, q AlertQuery) ([]*Alert, int64, error) {
	if q.Status == "" {
		q.Status = FilterActive
	}
	f := apperr.Fields{}
	f.Check(q.Status == FilterActive || q.Status == FilterResolved || q.Status == FilterAll, "status", "Use active, resolved or all.")
	f.Check(q.Severity == "" || q.Severity == SeverityWarning || q.Severity == SeverityCritical, "severity", "Use warning or critical.")
	f.Check(len(q.Subject) <= maxSubject, "subject", "A subject is at most 64 characters.")
	if err := f.Err(); err != nil {
		return nil, 0, err
	}
	out := []*Alert{}
	var next int64
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+alertColumns+alertFrom+`
			WHERE ($1 = 'all' OR ($1 = 'active') = (a.status <> 'resolved'))
			  AND ($2::uuid IS NULL OR a.device_id = $2)
			  AND ($3::uuid IS NULL OR d.organization_id = $3)
			  AND ($4::uuid IS NULL OR d.site_id = $4)
			  AND ($5 = '' OR a.severity = $5)
			  AND ($6 = 0 OR a.seq < $6)
			  AND ($8::uuid IS NULL OR a.policy_id = $8)
			  AND ($9 = '' OR a.subject = $9)
			ORDER BY a.seq DESC LIMIT $7`,
			q.Status, nullUUID(q.DeviceID), nullUUID(q.OrganizationID), nullUUID(q.SiteID), q.Severity, q.Before, q.Limit+1,
			nullUUID(q.PolicyID), q.Subject)
		if err != nil {
			return err
		}
		defer rows.Close()
		scanned := 0
		for rows.Next() {
			a, err := scanAlert(rows)
			if err != nil {
				return err
			}
			scanned++
			if scanned > q.Limit {
				break
			}
			next = a.seq
			if !c.Can(rbac.PermAlertView, a.site()) {
				continue
			}
			a.CanManage = c.Can(rbac.PermAlertManage, a.site())
			out = append(out, a)
		}
		if scanned <= q.Limit {
			next = 0
		}
		return rows.Err()
	})
	return out, next, err
}

// Summary counts the active alerts on devices the caller can see.
type Summary struct {
	Active       int `json:"active"`
	Critical     int `json:"critical"`
	Warning      int `json:"warning"`
	Acknowledged int `json:"acknowledged"`
	// Devices counts the devices with at least one active alert.
	Devices int `json:"devices"`
}

// Summarize counts the caller's active alerts.
func (s *Service) Summarize(ctx context.Context, c access.Caller) (Summary, error) {
	var out Summary
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		out = Summary{}
		rows, err := tx.Query(ctx, `SELECT d.organization_id, d.site_id, a.device_id, a.severity, a.status, count(*)
			FROM alerts a JOIN devices d ON d.id = a.device_id
			WHERE a.status <> 'resolved'
			GROUP BY 1, 2, 3, 4, 5`)
		if err != nil {
			return err
		}
		defer rows.Close()
		seen := map[uuid.UUID]bool{}
		for rows.Next() {
			var (
				org, site, device uuid.UUID
				severity, status  string
				n                 int
			)
			if err := rows.Scan(&org, &site, &device, &severity, &status, &n); err != nil {
				return err
			}
			if !c.Can(rbac.PermAlertView, rbac.Site(org, site)) {
				continue
			}
			out.Active += n
			if severity == SeverityCritical {
				out.Critical += n
			} else {
				out.Warning += n
			}
			if status == StatusAcknowledged {
				out.Acknowledged += n
			}
			if !seen[device] {
				seen[device] = true
				out.Devices++
			}
		}
		return rows.Err()
	})
	return out, err
}

// DeviceAlerts counts the active alerts on one device.
type DeviceAlerts struct {
	DeviceID       uuid.UUID `json:"deviceId"`
	OrganizationID uuid.UUID `json:"organizationId"`
	SiteID         uuid.UUID `json:"siteId"`
	Active         int       `json:"active"`
	Critical       int       `json:"critical"`
}

// ActiveByDevice counts the active alerts on every device the caller can see
// that has any, for the console's alerts tree.
func (s *Service) ActiveByDevice(ctx context.Context, c access.Caller) ([]DeviceAlerts, error) {
	var out []DeviceAlerts
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		out = []DeviceAlerts{}
		rows, err := tx.Query(ctx, `SELECT a.device_id, d.organization_id, d.site_id, count(*), count(*) FILTER (WHERE a.severity = $1)
			FROM alerts a JOIN devices d ON d.id = a.device_id
			WHERE a.status <> 'resolved'
			GROUP BY 1, 2, 3
			ORDER BY 1`, SeverityCritical)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d DeviceAlerts
			if err := rows.Scan(&d.DeviceID, &d.OrganizationID, &d.SiteID, &d.Active, &d.Critical); err != nil {
				return err
			}
			if c.Can(rbac.PermAlertView, rbac.Site(d.OrganizationID, d.SiteID)) {
				out = append(out, d)
			}
		}
		return rows.Err()
	})
	return out, err
}

// AlertRepair is a repair tried on the device since an alert opened.
type AlertRepair struct {
	Target    string     `json:"target"`
	Trigger   string     `json:"trigger"`
	State     string     `json:"state"`
	StartedAt time.Time  `json:"startedAt"`
	EndedAt   *time.Time `json:"endedAt"`
	Error     string     `json:"error"`
	// Steps are the step names tried, in order, with their outcomes.
	Steps []AlertRepairStep `json:"steps"`
}

// AlertRepairStep is one step of an AlertRepair.
type AlertRepairStep struct {
	Step  string `json:"step"`
	State string `json:"state"`
	Error string `json:"error,omitempty"`
}

// GetAlert returns one alert.
func (s *Service) GetAlert(ctx context.Context, c access.Caller, id uuid.UUID) (*Alert, error) {
	var a *Alert
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var err error
		if a, err = getAlert(ctx, tx, c, id, false); err != nil {
			return err
		}
		if a.Kind == KindRemoteDown || a.Kind == KindAgentSilent {
			a.Repairs, err = alertRepairs(ctx, tx, a)
		}
		return err
	})
	return a, err
}

// alertRepairs reads the repairs started on an alert's device while it was
// open, oldest first.
func alertRepairs(ctx context.Context, tx pgx.Tx, a *Alert) ([]AlertRepair, error) {
	rows, err := tx.Query(ctx, `SELECT target, trigger, state, started_at, ended_at, error, steps
		FROM agent_repairs
		WHERE device_id = $1 AND started_at >= $2 AND ($3::timestamptz IS NULL OR started_at <= $3)
		ORDER BY started_at LIMIT 20`, a.DeviceID, a.OpenedAt, a.ResolvedAt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertRepair
	for rows.Next() {
		var (
			r     AlertRepair
			steps []AlertRepairStep
		)
		if err := rows.Scan(&r.Target, &r.Trigger, &r.State, &r.StartedAt, &r.EndedAt, &r.Error, &steps); err != nil {
			return nil, err
		}
		r.Steps = steps
		out = append(out, r)
	}
	return out, rows.Err()
}

func getAlert(ctx context.Context, tx pgx.Tx, c access.Caller, id uuid.UUID, lock bool) (*Alert, error) {
	q := `SELECT ` + alertColumns + alertFrom + ` WHERE a.id = $1`
	if lock {
		q += ` FOR UPDATE OF a`
	}
	a, err := scanAlert(tx.QueryRow(ctx, q, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	if !c.Can(rbac.PermAlertView, a.site()) {
		return nil, apperr.NotFound()
	}
	a.CanManage = c.Can(rbac.PermAlertManage, a.site())
	return a, nil
}

// Acknowledge marks an open alert as being dealt with. It stays active and
// resolves when its condition clears. Acknowledging twice is not an error.
func (s *Service) Acknowledge(ctx context.Context, c access.Caller, id uuid.UUID) (*Alert, error) {
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		a, err := s.manageable(ctx, tx, c, id)
		if err != nil || a.Status == StatusAcknowledged {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE alerts SET status = 'acknowledged', acknowledged_at = $2, acknowledged_by = $3,
				acknowledged_by_label = $4 WHERE id = $1`, id, s.now(), nullUUID(c.Actor.ID), c.Actor.Label); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "alert.acknowledge", Outcome: audit.Success,
			OrganizationID: a.OrganizationID, SiteID: a.SiteID, DeviceID: a.DeviceID, TargetType: "alert", TargetID: id.String(),
			Details: map[string]any{"name": a.Name, "device": a.DeviceName, "severity": a.Severity},
		})
	})
	if err != nil {
		return nil, err
	}
	return s.GetAlert(ctx, c, id)
}

// Resolve closes an alert by hand. If its condition still holds, the next
// evaluation opens a new one.
func (s *Service) Resolve(ctx context.Context, c access.Caller, id uuid.UUID) (*Alert, error) {
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		a, err := s.manageable(ctx, tx, c, id)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE alerts SET status = 'resolved', resolved_at = $2, resolved_by = $3,
				resolved_by_label = $4, resolution = 'manual' WHERE id = $1`, id, s.now(), nullUUID(c.Actor.ID), c.Actor.Label); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "alert.resolve", Outcome: audit.Success,
			OrganizationID: a.OrganizationID, SiteID: a.SiteID, DeviceID: a.DeviceID, TargetType: "alert", TargetID: id.String(),
			Details: map[string]any{"name": a.Name, "device": a.DeviceName, "severity": a.Severity},
		})
	})
	if err != nil {
		return nil, err
	}
	return s.GetAlert(ctx, c, id)
}

// manageable reads and locks an active alert the caller may change.
func (s *Service) manageable(ctx context.Context, tx pgx.Tx, c access.Caller, id uuid.UUID) (*Alert, error) {
	a, err := getAlert(ctx, tx, c, id, true)
	if err != nil {
		return nil, err
	}
	if !a.CanManage {
		return nil, apperr.Forbidden()
	}
	if a.Status == StatusResolved {
		return nil, apperr.Conflict("alert_resolved", "This alert is already resolved.")
	}
	return a, nil
}
