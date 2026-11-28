package posture

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
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// NoticeNoncompliant is the kind of the notice "this computer no longer meets
// its security policy" (ADR-0082, slice P4); its subject is the device's ID. It
// is opened when a posture goes from meets to does not meet, and resolved when
// the computer meets again.
const NoticeNoncompliant = "posture_noncompliant"

// History reads of a device.
const (
	DefaultHistoryDays = 30
	MaxHistoryDays     = 90
)

// HistoryEntry is one change in a computer's posture.
type HistoryEntry struct {
	Word       string     `json:"word"`
	Percent    *int       `json:"percent"`
	Failing    int        `json:"failing"`
	CannotTell int        `json:"cannotTell"`
	CheckedAt  *time.Time `json:"checkedAt"`
	RecordedAt time.Time  `json:"recordedAt"`
}

// RecordHistory notes a computer's posture when its word or score differs from
// the last one noted (or none was), so an unchanged posture adds nothing however
// often it is read, and a posture that flaps is noted each time it moves. It
// also opens the noncompliant notice when the computer went from meeting its
// policy to not meeting it, and resolves it when it meets again. It writes with
// the system scope; the caller has read the posture.
func (s *Service) RecordHistory(ctx context.Context, device uuid.UUID, p *Posture) error {
	if p == nil {
		return nil
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		// Two readers of one device at once note it once.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "posture_history:"+device.String()); err != nil {
			return err
		}
		var prevWord *string
		var same bool
		err := tx.QueryRow(ctx, `SELECT word, word = $2 AND percent IS NOT DISTINCT FROM $3::integer FROM posture_history
			WHERE device_id = $1 ORDER BY recorded_at DESC, id DESC LIMIT 1`, device, p.Word, p.Percent).Scan(&prevWord, &same)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if prevWord != nil && same {
			return nil
		}
		if _, err := tx.Exec(ctx, `INSERT INTO posture_history (device_id, word, percent, failing, cannot_tell, checked_at, recorded_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, device, p.Word, p.Percent, p.Failing, p.CannotTell, p.CheckedAt, s.now()); err != nil {
			return err
		}
		return s.syncNotice(ctx, tx, device, prevWord, p)
	})
}

// syncNotice opens the notice on the move from meets to does not meet and
// resolves it on a return to meets. Other moves leave it as it is: a computer
// that cannot be told is not known to have recovered.
func (s *Service) syncNotice(ctx context.Context, tx pgx.Tx, device uuid.UUID, prev *string, p *Posture) error {
	switch {
	case p.Word == WordMeets:
		_, err := tx.Exec(ctx, `UPDATE notices SET resolved_at = now() WHERE kind = $1 AND subject = $2 AND resolved_at IS NULL`,
			NoticeNoncompliant, device.String())
		return err
	case p.Word == WordDoesNotMeet && prev != nil && *prev == WordMeets:
		var org, site uuid.UUID
		var name string
		if err := tx.QueryRow(ctx, `SELECT organization_id, site_id, name FROM devices WHERE id = $1`, device).Scan(&org, &site, &name); err != nil {
			return err
		}
		title := "Computer no longer meets its security policy: " + name
		if len(title) > 200 {
			title = title[:200]
		}
		detail := name + " met its security policy and now does not. Open its Security tab for the controls that fail."
		if len(detail) > 1000 {
			detail = detail[:1000]
		}
		_, err := tx.Exec(ctx, `INSERT INTO notices (organization_id, kind, subject, site_id, device_id, title, detail) VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (coalesce(organization_id, '00000000-0000-0000-0000-000000000000'::uuid), kind, subject) WHERE resolved_at IS NULL
			DO UPDATE SET detail = EXCLUDED.detail`, org, NoticeNoncompliant, device.String(), site, device, title, detail)
		return err
	}
	return nil
}

// History lists a computer's posture changes of the last days (30 when days is
// 0 or below, at most 90), newest first. It needs device.view on the computer.
func (s *Service) History(ctx context.Context, c access.Caller, device uuid.UUID, days int) ([]HistoryEntry, error) {
	if days <= 0 {
		days = DefaultHistoryDays
	}
	if days > MaxHistoryDays {
		days = MaxHistoryDays
	}
	out := []HistoryEntry{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var org, site uuid.UUID
		err := tx.QueryRow(ctx, `SELECT organization_id, site_id FROM devices WHERE id = $1 AND NOT quick_assist`, device).Scan(&org, &site)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && !c.Can(rbac.PermDeviceView, rbac.Site(org, site))) {
			return apperr.NotFound()
		}
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT word, percent, failing, cannot_tell, checked_at, recorded_at FROM posture_history
			WHERE device_id = $1 AND recorded_at >= $2 ORDER BY recorded_at DESC, id DESC`, device, s.now().Add(-time.Duration(days)*24*time.Hour))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e HistoryEntry
			if err := rows.Scan(&e.Word, &e.Percent, &e.Failing, &e.CannotTell, &e.CheckedAt, &e.RecordedAt); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

// evaluateBatch is how many computers Evaluate loads at once.
const evaluateBatch = 200

// Evaluate reads the posture of every computer posture covers and records the
// changes, so history and the notice follow the fleet and not only the
// computers somebody opens. It returns how many it read.
func (s *Service) Evaluate(ctx context.Context) (int, error) {
	var refs []Ref
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, organization_id, platform FROM devices WHERE NOT quick_assist AND enrolled_at IS NOT NULL
			AND platform IN ('linux', 'windows')`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r := Ref{Enrolled: true}
			if err := rows.Scan(&r.ID, &r.Org, &r.Platform); err != nil {
				return err
			}
			if devscope.Allowed(r.Org) {
				refs = append(refs, r)
			}
		}
		return rows.Err()
	})
	if err != nil {
		return 0, err
	}
	n := 0
	for len(refs) > 0 {
		batch := refs[:min(evaluateBatch, len(refs))]
		refs = refs[len(batch):]
		var m map[uuid.UUID]*Posture
		if err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
			var err error
			m, err = Load(ctx, tx, batch, s.now())
			return err
		}); err != nil {
			return n, err
		}
		for _, r := range batch {
			if p := m[r.ID]; p != nil {
				if err := s.RecordHistory(ctx, r.ID, p); err != nil {
					return n, err
				}
				n++
			}
		}
	}
	return n, nil
}
