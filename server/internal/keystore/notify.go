package keystore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/mailer"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Notifier is ADR-0053's sender, as far as the keystore needs it.
type Notifier interface {
	Available(ctx context.Context) bool
	SendAccountMail(ctx context.Context, to string, msg mailer.Message, by mailer.AccountMail) error
}

// SetNotifier gives the service the mail sender. Without one, notices are
// still recorded and shown in the console.
func (s *Service) SetNotifier(n Notifier) { s.notifier = n }

type recipient struct {
	id    uuid.UUID
	email string
}

// admins are the people who get a notice for an organization: every super
// administrator and every administrator of it.
func (s *Service) admins(ctx context.Context, org uuid.UUID) ([]recipient, error) {
	var out []recipient
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT u.id, u.email FROM users u JOIN role_assignments a ON a.user_id = u.id
			WHERE u.status = 'active' AND (a.role = 'super_admin' OR (a.role = 'org_admin' AND a.organization_id = $1))`, org)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r recipient
			if err := rows.Scan(&r.id, &r.email); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// notifyRead mails the organization's administrators that a key was read: who,
// which device, why, never the key. The console's notice row was written with
// the read; a mail that cannot be sent is logged and does not undo it.
func (s *Service) notifyRead(ctx context.Context, e *escrowRef, who, approver, reason string) {
	if !devscope.Allowed(e.org) || s.notifier == nil || !s.notifier.Available(ctx) {
		return
	}
	to, err := s.admins(ctx, e.org)
	if err != nil {
		s.warn("listing the administrators to notify", err)
		return
	}
	lines := []string{
		fmt.Sprintf("%s read the disk recovery key of the device %s.", who, e.hostname),
		"Reason given: " + oneLine(reason),
	}
	if approver != "" {
		lines = append(lines, "Approved by: "+approver)
	}
	msg, err := mailer.Letter{
		Subject: "A disk recovery key was read",
		Before:  lines,
		After:   []string{"The key itself is never sent by email. If you do not expect this, review the audit log."},
	}.Message()
	if err != nil {
		s.warn("composing the notice", err)
		return
	}
	for _, r := range to {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		s.warn("mailing a read notice", s.notifier.SendAccountMail(cctx, r.email, msg, mailer.AccountMail{Account: r.id, Organization: e.org}))
		cancel()
	}
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// Notice is what the console shows of a read.
type Notice struct {
	ID       uuid.UUID `json:"id"`
	Device   string    `json:"device"`
	DeviceID uuid.UUID `json:"deviceId"`
	Org      uuid.UUID `json:"organizationId"`
	By       string    `json:"by"`
	Approver string    `json:"approver,omitempty"`
	Reason   string    `json:"reason"`
	At       time.Time `json:"at"`
}

// Notices lists the reads of the organizations the caller administers (a
// super administrator: all), newest first.
func (s *Service) Notices(ctx context.Context, c access.Caller) ([]Notice, error) {
	if c.IsSystem() || c.Principal == nil {
		return nil, apperr.Forbidden()
	}
	out := []Notice{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, device_name, device_id, organization_id, actor_label, approver_label, reason, created_at
			FROM keystore_notices ORDER BY created_at DESC LIMIT 100`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var n Notice
			if err := rows.Scan(&n.ID, &n.Device, &n.DeviceID, &n.Org, &n.By, &n.Approver, &n.Reason, &n.At); err != nil {
				return err
			}
			if c.Can(rbac.PermUserManage, rbac.Org(n.Org)) {
				out = append(out, n)
			}
		}
		return rows.Err()
	})
	return out, err
}

// Alert is one of the keystore's alerts.
type Alert struct {
	ID       uuid.UUID  `json:"id"`
	Org      *uuid.UUID `json:"organizationId,omitempty"`
	Kind     string     `json:"kind"`
	Subject  string     `json:"subject,omitempty"`
	Severity string     `json:"severity"`
	Detail   string     `json:"detail"`
	OpenedAt time.Time  `json:"openedAt"`
}

// Alerts lists the open alerts the caller may see: the keystore-wide ones for
// whoever manages platform settings, an organization's for its administrators.
func (s *Service) Alerts(ctx context.Context, c access.Caller) ([]Alert, error) {
	if c.IsSystem() || c.Principal == nil {
		return nil, apperr.Forbidden()
	}
	out := []Alert{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, organization_id, kind, subject, severity, detail, opened_at FROM keystore_alerts
			WHERE resolved_at IS NULL ORDER BY opened_at DESC LIMIT 100`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a Alert
			if err := rows.Scan(&a.ID, &a.Org, &a.Kind, &a.Subject, &a.Severity, &a.Detail, &a.OpenedAt); err != nil {
				return err
			}
			if (a.Org == nil && c.CanGlobal(rbac.PermSettingsManage)) || (a.Org != nil && c.Can(rbac.PermUserManage, rbac.Org(*a.Org))) {
				out = append(out, a)
			}
		}
		return rows.Err()
	})
	return out, err
}

// raiseAlert opens an alert of a kind and subject, or refreshes the open one
// (the alert system's dedupe), and writes an audit record when it is new.
func (s *Service) raiseAlert(ctx context.Context, org *uuid.UUID, kind, severity, subject, detail string) (bool, error) {
	var created bool
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE keystore_alerts SET last_seen_at = now(), detail = left($3, 1000) WHERE kind = $1 AND subject = $2 AND resolved_at IS NULL`, kind, subject, detail)
		if err != nil {
			return err
		}
		if tag.RowsAffected() > 0 {
			return nil
		}
		created = true
		_, err = tx.Exec(ctx, `INSERT INTO keystore_alerts (organization_id, kind, severity, subject, detail) VALUES ($1, $2, $3, $4, left($5, 1000))`, org, kind, severity, subject, detail)
		return err
	})
	return created, err
}
