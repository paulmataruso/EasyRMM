package notify

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
)

// Notice is something the console raises that is not a policy's condition on
// a device: a failing channel, messages not sent, a quota reached.
type Notice struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID *uuid.UUID `json:"organizationId"`
	Kind           string     `json:"kind"`
	Subject        string     `json:"subject"`
	Title          string     `json:"title"`
	Detail         string     `json:"detail"`
	OpenedAt       time.Time  `json:"openedAt"`
	AcknowledgedAt *time.Time `json:"acknowledgedAt,omitempty"`
	ResolvedAt     *time.Time `json:"resolvedAt,omitempty"`
}

// openNotice opens a notice, or updates the detail of the one already open
// for the same thing. Only the server opens notices, at platform scope, in
// the transaction of the change that caused them; the journal records it.
// No notice is raised for an organization outside the dev scope.
func openNotice(ctx context.Context, tx pgx.Tx, org *uuid.UUID, kind, subject, title, detail string) error {
	if org != nil && !devscope.Allowed(*org) {
		return nil
	}
	_, err := tx.Exec(ctx, `INSERT INTO notices (organization_id, kind, subject, title, detail) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (coalesce(organization_id, '00000000-0000-0000-0000-000000000000'::uuid), kind, subject) WHERE resolved_at IS NULL
		DO UPDATE SET detail = EXCLUDED.detail`, org, kind, subject, clip(title, 200), clip(detail, 1000))
	return err
}

// resolveNotice resolves the notice open for a thing, if any.
func resolveNotice(ctx context.Context, tx pgx.Tx, org *uuid.UUID, kind, subject string) error {
	_, err := tx.Exec(ctx, `UPDATE notices SET resolved_at = now()
		WHERE coalesce(organization_id, '00000000-0000-0000-0000-000000000000'::uuid) = coalesce($1, '00000000-0000-0000-0000-000000000000'::uuid)
		  AND kind = $2 AND subject = $3 AND resolved_at IS NULL`, org, kind, subject)
	return err
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// Notices lists the open notices (and, if asked, those resolved) the caller
// manages: with an organization, its own; with none, a super administrator's
// see everything, the platform's included.
func (s *Service) Notices(ctx context.Context, c access.Caller, org *uuid.UUID, resolved bool) ([]Notice, error) {
	scope := database.System
	if org == nil {
		if err := authorize(c, uuid.Nil); err != nil {
			return nil, err
		}
	} else {
		if err := authorize(c, *org); err != nil {
			return nil, err
		}
		scope = ownerScope(*org)
	}
	out := []Notice{}
	err := s.db.ReadTx(ctx, scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, organization_id, kind, subject, title, detail, opened_at, acknowledged_at, resolved_at FROM notices
			WHERE ($1 OR resolved_at IS NULL) AND ($2::uuid IS NULL OR organization_id = $2) ORDER BY opened_at DESC LIMIT 500`, resolved, org)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var n Notice
			if err := rows.Scan(&n.ID, &n.OrganizationID, &n.Kind, &n.Subject, &n.Title, &n.Detail, &n.OpenedAt, &n.AcknowledgedAt, &n.ResolvedAt); err != nil {
				return err
			}
			out = append(out, n)
		}
		return rows.Err()
	})
	return out, err
}

// Acknowledge acknowledges a notice, in the caller's own scope.
func (s *Service) Acknowledge(ctx context.Context, c access.Caller, id uuid.UUID) error {
	var org *uuid.UUID
	if err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT organization_id FROM notices WHERE id = $1`, id).Scan(&org)
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound()
		}
		return err
	}
	owner := uuid.Nil
	if org != nil {
		owner = *org
	}
	if err := authorize(c, owner); err != nil {
		return err
	}
	return s.db.InTx(ctx, ownerScope(owner), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE notices SET acknowledged_at = now(), acknowledged_by = $2 WHERE id = $1 AND acknowledged_at IS NULL AND resolved_at IS NULL`, id, actorID(c.Actor))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return apperr.Conflict("notice_closed", "That notice is already acknowledged or resolved.")
		}
		return nil
	})
}

// RaisePlatformNotice opens, or updates the detail of, a notice about the
// platform itself (no organization): a certificate that is failing or about
// to expire (ADR-0055). Super administrators see it; the journal records it.
func (s *Service) RaisePlatformNotice(ctx context.Context, kind, subject, title, detail string) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		return openNotice(ctx, tx, nil, kind, subject, title, detail)
	})
}

// ResolvePlatformNotice resolves the platform notice open for a thing, if any.
func (s *Service) ResolvePlatformNotice(ctx context.Context, kind, subject string) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		return resolveNotice(ctx, tx, nil, kind, subject)
	})
}
