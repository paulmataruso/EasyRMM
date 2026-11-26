package notify

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Audit actions of the platform's own controls.
const (
	ActionSilenceEnd     = "fleet_silence.end"
	ActionJournalRetry   = "notification_journal.retry"
	ActionJournalDiscard = "notification_journal.discard"
	ActionDeviceKind     = "device.kind_set"
)

// Silence is the fleet-wide hold in force.
type Silence struct {
	ID        uuid.UUID `json:"id"`
	StartedAt time.Time `json:"startedAt"`
	Counted   int       `json:"counted"`
}

// CurrentSilence reports the fleet-wide hold in force, or nil. Super
// administrators only.
func (s *Service) CurrentSilence(ctx context.Context, c access.Caller) (*Silence, error) {
	if err := authorize(c, uuid.Nil); err != nil {
		return nil, err
	}
	var out *Silence
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		var x Silence
		err := tx.QueryRow(ctx, `SELECT id, started_at, counted_n FROM fleet_silences WHERE ended_at IS NULL`).Scan(&x.ID, &x.StartedAt, &x.Counted)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		out = &x
		return err
	})
	return out, err
}

// EndSilence ends the fleet-wide hold now. Organizations' openings that
// waited and whose alerts are still open are then planned as usual.
func (s *Service) EndSilence(ctx context.Context, c access.Caller) error {
	if err := authorize(c, uuid.Nil); err != nil {
		return err
	}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		ended, err := s.endSilence(ctx, tx, actorID(c.Actor))
		if err != nil {
			return err
		}
		if !ended {
			return apperr.Conflict("no_silence", "There is no fleet-wide hold to end.")
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: ActionSilenceEnd, TargetType: "fleet_silence", Outcome: audit.Success})
	})
	if err == nil {
		s.Kick()
	}
	return err
}

// Quarantined is a journal row set aside after failing three times.
type Quarantined struct {
	ID          int64     `json:"id"`
	SubjectType string    `json:"subjectType"`
	SubjectID   uuid.UUID `json:"subjectId"`
	Event       string    `json:"event"`
	Error       string    `json:"error"`
	FailedRuns  int       `json:"failedRuns"`
	CreatedAt   time.Time `json:"createdAt"`
	// Held counts the later rows about the same subject waiting behind it.
	Held int `json:"held"`
}

// QuarantinedRows lists the rows set aside. Super administrators only.
func (s *Service) QuarantinedRows(ctx context.Context, c access.Caller) ([]Quarantined, error) {
	if err := authorize(c, uuid.Nil); err != nil {
		return nil, err
	}
	out := []Quarantined{}
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rs, err := tx.Query(ctx, `SELECT e.id, e.subject_type, e.subject_id, e.event, coalesce(e.error, ''), e.failed_runs, e.created_at,
				(SELECT count(*) FROM notification_events l WHERE l.status = 'new' AND l.subject_type = e.subject_type AND l.subject_id = e.subject_id AND l.id > e.id)
			FROM notification_events e WHERE e.status = 'quarantined' ORDER BY e.id LIMIT 200`)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var q Quarantined
			if err := rs.Scan(&q.ID, &q.SubjectType, &q.SubjectID, &q.Event, &q.Error, &q.FailedRuns, &q.CreatedAt, &q.Held); err != nil {
				return err
			}
			out = append(out, q)
		}
		return rs.Err()
	})
	return out, err
}

// RetryJournal replays a quarantined row, and those behind it, in order.
func (s *Service) RetryJournal(ctx context.Context, c access.Caller, id int64) error {
	if err := authorize(c, uuid.Nil); err != nil {
		return err
	}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE notification_events SET status = 'new', failed_runs = 0, error = NULL WHERE id = $1 AND status = 'quarantined'`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return apperr.NotFound()
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: ActionJournalRetry, TargetType: "notification_event", TargetID: itoa(id), Outcome: audit.Success})
	})
	if err == nil {
		s.Kick()
	}
	return err
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

// DiscardJournal marks a quarantined row and every other unplanned row about
// its subject planned, and plans the subject's current state as one row:
// channels told of it get that state (a resolution, say), others nothing.
func (s *Service) DiscardJournal(ctx context.Context, c access.Caller, id int64) error {
	if err := authorize(c, uuid.Nil); err != nil {
		return err
	}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var typ string
		var subject uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT subject_type, subject_id FROM notification_events WHERE id = $1 AND status = 'quarantined'`, id).Scan(&typ, &subject); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apperr.NotFound()
			}
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE notification_events SET status = 'planned', planned_at = now() WHERE subject_type = $1 AND subject_id = $2 AND status <> 'planned'`, typ, subject); err != nil {
			return err
		}
		rules, err := loadRules(ctx, tx, `WHERE r.enabled`)
		if err != nil {
			return err
		}
		if err := s.planCurrent(ctx, tx, rules, typ, subject); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: ActionJournalDiscard, TargetType: "notification_event", TargetID: itoa(id), Outcome: audit.Success})
	})
	if err == nil {
		s.Kick()
	}
	return err
}

// planCurrent plans a subject's current state as if it were a single row.
func (s *Service) planCurrent(ctx context.Context, tx pgx.Tx, rules []Rule, typ string, id uuid.UUID) error {
	var cur []byte
	table := map[string]string{"alert": "alerts", "notice": "notices"}[typ]
	if table == "" {
		return nil
	}
	err := tx.QueryRow(ctx, `SELECT to_jsonb(t) FROM `+table+` t WHERE id = $1`, id).Scan(&cur)
	if errors.Is(err, pgx.ErrNoRows) {
		if typ == "alert" {
			return s.incidentResolved(ctx, tx, id, "device_removed", s.now(), "")
		}
		return nil
	}
	if err != nil {
		return err
	}
	var st struct {
		Status         string     `json:"status"`
		AcknowledgedAt *time.Time `json:"acknowledged_at"`
		ResolvedAt     *time.Time `json:"resolved_at"`
	}
	if err := json.Unmarshal(cur, &st); err != nil {
		return err
	}
	seen := false
	if typ == "alert" {
		inc, err := incidentOf(ctx, tx, id, false)
		if err != nil {
			return err
		}
		seen = inc != nil
	} else {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM alert_notifications WHERE subject_type = 'notice' AND subject_id = $1`, id).Scan(&n); err != nil {
			return err
		}
		seen = n > 0
	}
	apply := func(event string) error {
		return s.applyRow(ctx, tx, rules, journalRow{subjectType: typ, subjectID: id, event: event, newRow: cur, createdAt: s.now()})
	}
	if !seen {
		if err := apply("opened"); err != nil {
			return err
		}
	}
	resolved := st.Status == "resolved" || st.ResolvedAt != nil
	if st.AcknowledgedAt != nil && !resolved {
		if err := apply("acknowledged"); err != nil {
			return err
		}
	}
	if resolved {
		return apply("resolved")
	}
	return nil
}

// SetDeviceKind sets a device's kind, which wins over what the agent
// reports and what its operating system's description says; nil clears it.
// `monitoring.manage` at the device's site.
func (s *Service) SetDeviceKind(ctx context.Context, c access.Caller, device uuid.UUID, kind *string) (string, error) {
	if kind != nil && *kind != "server" && *kind != "workstation" {
		return "", apperr.Invalid("kind", "A device is a server or a workstation.")
	}
	var org, site uuid.UUID
	var reported *string
	var osd, platform string
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT organization_id, site_id, agent_role, os_description, platform FROM devices WHERE id = $1`, device).Scan(&org, &site, &reported, &osd, &platform)
	})
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !c.Can(rbac.PermMonitorManage, rbac.Site(org, site))) {
		return "", apperr.NotFound()
	}
	if err != nil {
		return "", err
	}
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE devices SET role = $2, role_set_by = CASE WHEN $2::text IS NULL THEN NULL ELSE $3::uuid END WHERE id = $1`, device, kind, actorID(c.Actor)); err != nil {
			return err
		}
		set := ""
		if kind != nil {
			set = *kind
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: ActionDeviceKind, OrganizationID: org, SiteID: site, DeviceID: device, TargetType: "device",
			TargetID: device.String(), Outcome: audit.Success, Details: map[string]any{"kind": set}})
	})
	if err != nil {
		return "", err
	}
	return DeviceKind(kind, reported, osd, platform), nil
}
