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

// Suppression is a device–kind pair the monitoring system skips (ADR-0085).
type Suppression struct {
	ID             uuid.UUID  `json:"id"`
	DeviceID       uuid.UUID  `json:"deviceId"`
	DeviceName     string     `json:"deviceName"`
	OrganizationID uuid.UUID  `json:"organizationId"`
	SiteID         uuid.UUID  `json:"siteId"`
	Kind           string     `json:"kind"`
	Subject        string     `json:"subject"`
	SubjectLabel   string     `json:"subjectLabel,omitempty"`
	Reason         string     `json:"reason"`
	CreatedBy      string     `json:"createdBy"`
	CreatedAt      time.Time  `json:"createdAt"`
	CanManage      bool       `json:"canManage"`
}

// SuppressInput is what the caller sends to suppress an alert.
type SuppressInput struct {
	Reason string `json:"reason"`
}

// Suppress creates a suppression for the alert's device–kind–subject and
// resolves the alert (ADR-0085). The next evaluation skips the pair.
func (s *Service) Suppress(ctx context.Context, c access.Caller, alertID uuid.UUID, in SuppressInput) (*Alert, error) {
	f := apperr.Fields{}
	f.Check(len(in.Reason) <= 500, "reason", "A reason is at most 500 characters.")
	if err := f.Err(); err != nil {
		return nil, err
	}
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		a, err := s.manageable(ctx, tx, c, alertID)
		if err != nil {
			return err
		}
		now := s.now()
		if _, err := tx.Exec(ctx, `INSERT INTO alert_suppressions (device_id, kind, subject, reason, created_by, created_by_label, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (device_id, kind, subject) DO UPDATE SET reason = EXCLUDED.reason,
			created_by = EXCLUDED.created_by, created_by_label = EXCLUDED.created_by_label, created_at = EXCLUDED.created_at`,
			a.DeviceID, a.Kind, a.Subject, in.Reason, nullUUID(c.Actor.ID), c.Actor.Label, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE alerts SET status = 'resolved', resolved_at = $2, resolved_by = $3,
			resolved_by_label = $4, resolution = 'suppressed' WHERE id = $1`,
			alertID, now, nullUUID(c.Actor.ID), c.Actor.Label); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "alert.suppress", Outcome: audit.Success,
			OrganizationID: a.OrganizationID, SiteID: a.SiteID, DeviceID: a.DeviceID,
			TargetType: "alert", TargetID: alertID.String(),
			Details: map[string]any{"name": a.Name, "kind": a.Kind, "device": a.DeviceName, "reason": in.Reason},
		})
	})
	if err != nil {
		return nil, err
	}
	return s.GetAlert(ctx, c, alertID)
}

// Unsuppress removes a suppression. The next evaluation may open a new alert.
func (s *Service) Unsuppress(ctx context.Context, c access.Caller, id uuid.UUID) error {
	return s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var (
			deviceID, orgID, siteID uuid.UUID
			kind, deviceName        string
		)
		err := tx.QueryRow(ctx, `SELECT s.device_id, d.organization_id, d.site_id, d.name, s.kind
			FROM alert_suppressions s JOIN devices d ON d.id = s.device_id WHERE s.id = $1`, id).
			Scan(&deviceID, &orgID, &siteID, &deviceName, &kind)
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound()
		}
		if err != nil {
			return err
		}
		if !c.Can(rbac.PermAlertManage, rbac.Site(orgID, siteID)) {
			return apperr.Forbidden()
		}
		if _, err := tx.Exec(ctx, `DELETE FROM alert_suppressions WHERE id = $1`, id); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "alert.unsuppress", Outcome: audit.Success,
			OrganizationID: orgID, SiteID: siteID, DeviceID: deviceID,
			TargetType: "suppression", TargetID: id.String(),
			Details: map[string]any{"kind": kind, "device": deviceName},
		})
	})
}

// ListSuppressions returns the suppressions on a device, or all if deviceID
// is nil.
func (s *Service) ListSuppressions(ctx context.Context, c access.Caller, deviceID uuid.UUID) ([]Suppression, error) {
	var out []Suppression
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		out = []Suppression{}
		rows, err := tx.Query(ctx, `SELECT s.id, s.device_id, d.name, d.organization_id, d.site_id,
				s.kind, s.subject, coalesce(a.subject_label, ''), s.reason, s.created_by_label, s.created_at
			FROM alert_suppressions s
			JOIN devices d ON d.id = s.device_id
			LEFT JOIN LATERAL (SELECT a.subject_label FROM alerts a
				WHERE a.device_id = s.device_id AND a.kind = s.kind AND a.subject = s.subject
				ORDER BY a.seq DESC LIMIT 1) a ON true
			WHERE $1::uuid IS NULL OR s.device_id = $1
			ORDER BY d.name, s.kind, s.subject`, nullUUID(deviceID))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sup Suppression
			if err := rows.Scan(&sup.ID, &sup.DeviceID, &sup.DeviceName, &sup.OrganizationID, &sup.SiteID,
				&sup.Kind, &sup.Subject, &sup.SubjectLabel, &sup.Reason, &sup.CreatedBy, &sup.CreatedAt); err != nil {
				return err
			}
			if !c.Can(rbac.PermAlertView, rbac.Site(sup.OrganizationID, sup.SiteID)) {
				continue
			}
			sup.CanManage = c.Can(rbac.PermAlertManage, rbac.Site(sup.OrganizationID, sup.SiteID))
			out = append(out, sup)
		}
		return rows.Err()
	})
	return out, err
}
