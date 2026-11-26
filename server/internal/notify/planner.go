package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
)

// The planner (ADR-0053, "Nothing lost or queued twice"): it reads the
// journal the database wrote, in order, matches each row against the rules,
// records per subject and channel what was told and what is due, and queues
// the deliveries due now, all in one commit, so that each row is planned
// exactly once.

// Planner limits.
const (
	PlanBatch        = 1000
	PlanTransient    = 3 // transient failures of one batch in a row before going row by row
	PlanQuarantine   = 3 // failures of one row before it is quarantined
	PlanStoppedAfter = 10 * time.Minute
	// PolicyHold is how long a policy change's resolution waits for a successor.
	PolicyHold = 5 * time.Minute
)

type journalRow struct {
	id          int64
	subjectType string
	subjectID   uuid.UUID
	event       string
	oldRow      []byte
	newRow      []byte
	failedRuns  int
	createdAt   time.Time
}

func (r journalRow) subject() string { return r.subjectType + ":" + r.subjectID.String() }

// planState is what the planner remembers between runs, on this server.
type planState struct {
	transient int       // transient failures of a batch in a row
	rowByRow  bool      // plan one row per transaction until a run succeeds
	batch     int       // the batch it starts with
	progress  time.Time // the last time a row was planned, or none waited
}

// isTransient is a failure the next run may not meet again: a serialization
// failure, a deadlock, a lock or statement timeout, or a lost connection.
func isTransient(err error) bool {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		case "40001", "40P01", "55P03", "57014", "57P01", "08000", "08003", "08006":
			return true
		}
		return false
	}
	return errors.Is(err, context.DeadlineExceeded) || pgconn.Timeout(err) || pgconn.SafeToRetry(err)
}

// Plan plans the journal's rows, then what is due. It is safe to call from
// two servers: the planner's advisory lock lets one in.
func (s *Service) Plan(ctx context.Context) error {
	s.pmu.Lock()
	defer s.pmu.Unlock()
	if s.ps.batch == 0 {
		s.ps.batch = PlanBatch
	}
	if s.ps.progress.IsZero() {
		s.ps.progress = s.now()
	}
	err := s.planRows(ctx)
	if err != nil {
		return err
	}
	if err := s.duePass(ctx); err != nil {
		return fmt.Errorf("planning what is due: %w", err)
	}
	return s.planWatch(ctx)
}

func (s *Service) planRows(ctx context.Context) error {
	if s.ps.rowByRow {
		done, err := s.planOneByOne(ctx)
		if err != nil {
			return err
		}
		if done {
			s.ps.rowByRow, s.ps.transient, s.ps.batch = false, 0, PlanBatch
		}
		return nil
	}
	n, err := s.planBatch(ctx, s.ps.batch)
	if err == nil {
		s.ps.transient, s.ps.batch = 0, PlanBatch
		if n > 0 {
			s.ps.progress = s.now()
		}
		return nil
	}
	if isTransient(err) {
		s.ps.transient++
		if s.ps.transient < PlanTransient {
			return err
		}
	}
	// Three transient failures in a row, or any other error: find the bad
	// row, one per transaction, with a smaller batch each later failure.
	s.ps.rowByRow = true
	s.ps.batch = max(1, s.ps.batch/2)
	s.log.Warn("notifications: planning a batch failed; planning row by row", "error", err)
	return err
}

// loadRows reads the rows to plan: up to n of them, in order, leaving out a
// subject's rows behind one that is quarantined.
func loadRows(ctx context.Context, tx pgx.Tx, n int) ([]journalRow, error) {
	rs, err := tx.Query(ctx, `SELECT e.id, e.subject_type, e.subject_id, e.event, e.old_row, e.new_row, e.failed_runs, e.created_at
		FROM notification_events e
		WHERE e.status = 'new' AND NOT EXISTS (SELECT 1 FROM notification_events q
			WHERE q.status = 'quarantined' AND q.subject_type = e.subject_type AND q.subject_id = e.subject_id AND q.id < e.id)
		ORDER BY e.id LIMIT $1`, n)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []journalRow
	for rs.Next() {
		var r journalRow
		if err := rs.Scan(&r.id, &r.subjectType, &r.subjectID, &r.event, &r.oldRow, &r.newRow, &r.failedRuns, &r.createdAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rs.Err()
}

// planBatch plans up to n rows in one transaction.
func (s *Service) planBatch(ctx context.Context, n int) (int, error) {
	planned := 0
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		planned = 0
		var got bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, lockPlanner).Scan(&got); err != nil || !got {
			return err
		}
		rows, err := loadRows(ctx, tx, n)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		rules, err := loadRules(ctx, tx, `WHERE r.enabled`)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if err := s.applyRow(ctx, tx, rules, r); err != nil {
				return err
			}
		}
		ids := make([]int64, len(rows))
		for i, r := range rows {
			ids[i] = r.id
		}
		planned = len(rows)
		_, err = tx.Exec(ctx, `UPDATE notification_events SET status = 'planned', planned_at = now() WHERE id = ANY ($1)`, ids)
		return err
	})
	return planned, err
}

// planOneByOne plans each waiting row in a transaction of its own. A row
// that fails is counted (transient failures too), and quarantined at the
// third; the later rows about its subject wait behind it, the others go on.
// It reports whether every row was planned.
func (s *Service) planOneByOne(ctx context.Context) (bool, error) {
	var rows []journalRow
	if err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		var err error
		rows, err = loadRows(ctx, tx, s.ps.batch)
		return err
	}); err != nil {
		return false, err
	}
	blocked := map[string]bool{}
	clean := true
	for _, r := range rows {
		if blocked[r.subject()] {
			clean = false
			continue
		}
		err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			var got bool
			if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, lockPlanner).Scan(&got); err != nil || !got {
				return err
			}
			rules, err := loadRules(ctx, tx, `WHERE r.enabled`)
			if err != nil {
				return err
			}
			if err := s.applyRow(ctx, tx, rules, r); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `UPDATE notification_events SET status = 'planned', planned_at = now() WHERE id = $1`, r.id)
			return err
		})
		if err == nil {
			s.ps.progress = s.now()
			continue
		}
		clean = false
		blocked[r.subject()] = true
		s.failRow(ctx, r, err)
	}
	return clean && len(rows) < s.ps.batch, nil
}

// failRow counts a failure of one row; at the third it is quarantined, by a
// minimal update nothing can refuse, and super administrators are told.
func (s *Service) failRow(ctx context.Context, r journalRow, cause error) {
	msg := clip(cause.Error(), 400)
	quarantined := false
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var runs int
		if err := tx.QueryRow(ctx, `UPDATE notification_events SET failed_runs = failed_runs + 1, error = $2 WHERE id = $1 RETURNING failed_runs`, r.id, msg).Scan(&runs); err != nil {
			return err
		}
		if runs < PlanQuarantine {
			return nil
		}
		quarantined = true
		if _, err := tx.Exec(ctx, `UPDATE notification_events SET status = 'quarantined' WHERE id = $1`, r.id); err != nil {
			return err
		}
		return openNotice(ctx, tx, nil, NoticeQuarantined, fmt.Sprint(r.id), "A change could not be planned for notification",
			"The journal row "+fmt.Sprint(r.id)+" failed "+fmt.Sprint(runs)+" times and is set aside; later changes about the same alert wait behind it. A super administrator can retry or discard it under Settings > Notifications.")
	})
	if err != nil {
		s.log.Warn("notifications: recording a failed row failed", "error", err, "row", r.id)
		return
	}
	if quarantined {
		s.log.Error("notifications: a journal row was quarantined", "row", r.id, "error", msg)
	}
}

// planWatch raises *planning has stopped* when rows wait and none has been
// planned for 10 minutes, and resolves it when one is.
func (s *Service) planWatch(ctx context.Context) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var waiting int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM notification_events WHERE status = 'new'`).Scan(&waiting); err != nil {
			return err
		}
		if waiting == 0 {
			s.ps.progress = s.now()
		}
		if waiting > 0 && s.now().Sub(s.ps.progress) >= PlanStoppedAfter {
			return openNotice(ctx, tx, nil, NoticePlanningStopped, "planner", "Notification planning has stopped",
				fmt.Sprintf("%d changes wait to be planned and none has been for %d minutes. Notifications about them are delayed.", waiting, int(PlanStoppedAfter.Minutes())))
		}
		if waiting == 0 || s.now().Sub(s.ps.progress) < PlanStoppedAfter {
			return resolveNotice(ctx, tx, nil, NoticePlanningStopped, "planner")
		}
		return nil
	})
}

// applyRow plans one journal row.
func (s *Service) applyRow(ctx context.Context, tx pgx.Tx, rules []Rule, r journalRow) error {
	switch r.subjectType {
	case "alert":
		return s.applyAlert(ctx, tx, rules, r)
	case "notice":
		return s.applyNotice(ctx, tx, rules, r)
	}
	return nil
}

// alertRow is an alert as the journal copied it.
type alertRow struct {
	ID                 uuid.UUID  `json:"id"`
	DeviceID           uuid.UUID  `json:"device_id"`
	PolicyID           *uuid.UUID `json:"policy_id"`
	Name               string     `json:"name"`
	Kind               string     `json:"kind"`
	Severity           string     `json:"severity"`
	Status             string     `json:"status"`
	Value              float64    `json:"value"`
	LastValue          float64    `json:"last_value"`
	Detail             string     `json:"detail"`
	Subject            string     `json:"subject"`
	SubjectLabel       string     `json:"subject_label"`
	CheckName          *string    `json:"check_name"`
	OpenedAt           time.Time  `json:"opened_at"`
	AcknowledgedAt     *time.Time `json:"acknowledged_at"`
	AcknowledgedByName string     `json:"acknowledged_by_label"`
	ResolvedAt         *time.Time `json:"resolved_at"`
	Resolution         *string    `json:"resolution"`
	Reason             string     `json:"reason"` // a deletion's reason, in the journal's new_row
}

// incident is a row of alert_incidents.
type incident struct {
	ID             uuid.UUID
	Org            uuid.UUID
	OrgName        string
	Site           uuid.UUID
	SiteName       string
	Group          *uuid.UUID
	Device         uuid.UUID
	DeviceName     string
	Kind           *string
	PolicyID       *uuid.UUID
	AlertID        uuid.UUID
	AlertKind      string
	AlertName      string
	Check          *string
	Subject        string
	SubjectLabel   string
	Key            string
	Severity       string
	Detail         string
	Value          float64
	Status         string
	OpenedAt       time.Time
	AcknowledgedAt *time.Time
	AcknowledgedBy string
	ResolvedAt     *time.Time
	Resolution     *string
}

const incidentCols = `id, organization_id, organization_name, site_id, site_name, device_group_id, device_id, device_name, device_kind, policy_id, alert_id,
	alert_kind, alert_name, check_name, subject, subject_label, key, severity, detail, value, status, opened_at, acknowledged_at, acknowledged_by, resolved_at, resolution`

func scanIncident(row pgx.Row) (incident, error) {
	var i incident
	err := row.Scan(&i.ID, &i.Org, &i.OrgName, &i.Site, &i.SiteName, &i.Group, &i.Device, &i.DeviceName, &i.Kind, &i.PolicyID, &i.AlertID, &i.AlertKind,
		&i.AlertName, &i.Check, &i.Subject, &i.SubjectLabel, &i.Key, &i.Severity, &i.Detail, &i.Value, &i.Status, &i.OpenedAt, &i.AcknowledgedAt,
		&i.AcknowledgedBy, &i.ResolvedAt, &i.Resolution)
	return i, err
}

func (i incident) item() AlertItem {
	a := AlertItem{ID: i.ID, AlertID: i.AlertID, Key: i.Key, Kind: i.AlertKind, Name: i.AlertName, Severity: i.Severity, Status: i.Status, Value: i.Value,
		Detail: i.Detail, Subject: i.SubjectLabel, DeviceID: i.Device, Device: i.DeviceName, SiteID: i.Site, Site: i.SiteName, OrganizationID: i.Org,
		Organization: i.OrgName, OpenedAt: i.OpenedAt, AcknowledgedAt: i.AcknowledgedAt, AcknowledgedBy: i.AcknowledgedBy, ResolvedAt: i.ResolvedAt}
	if i.Check != nil {
		a.Check = *i.Check
	}
	if i.Resolution != nil {
		a.Resolution = *i.Resolution
	}
	return a
}

func incidentOf(ctx context.Context, tx pgx.Tx, alert uuid.UUID, lock bool) (*incident, error) {
	q := `SELECT ` + incidentCols + ` FROM alert_incidents WHERE id = (SELECT incident_id FROM alert_incident_alerts WHERE alert_id = $1)`
	if lock {
		q += ` FOR UPDATE`
	}
	i, err := scanIncident(tx.QueryRow(ctx, q, alert))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &i, err
}

func (s *Service) applyAlert(ctx context.Context, tx pgx.Tx, rules []Rule, r journalRow) error {
	var a alertRow
	src := r.newRow
	if r.event == "deleted" {
		src = r.oldRow
	}
	if err := json.Unmarshal(src, &a); err != nil {
		return fmt.Errorf("reading the journal row: %w", err)
	}
	switch r.event {
	case "opened":
		return s.incidentOpened(ctx, tx, rules, a)
	case "acknowledged":
		return s.incidentAcknowledged(ctx, tx, a)
	case "resolved":
		res := ""
		if a.Resolution != nil {
			res = *a.Resolution
		}
		at := s.now()
		if a.ResolvedAt != nil {
			at = *a.ResolvedAt
		}
		return s.incidentResolved(ctx, tx, a.ID, res, at, "")
	case "deleted":
		var d struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(r.newRow, &d)
		if d.Reason == "" {
			d.Reason = "device_removed"
		}
		return s.incidentResolved(ctx, tx, a.ID, d.Reason, r.createdAt, "")
	}
	return nil
}

// incidentOpened records an alert that opened: a new incident, or the
// successor of one held after a policy change, which carries it on.
func (s *Service) incidentOpened(ctx context.Context, tx pgx.Tx, rules []Rule, a alertRow) error {
	if cur, err := incidentOf(ctx, tx, a.ID, false); err != nil || cur != nil {
		return err
	}
	var (
		org, site         uuid.UUID
		group             *uuid.UUID
		name, siteN, orgN string
		set, reported     *string
		osDesc, platform  string
		check             = ""
	)
	err := tx.QueryRow(ctx, `SELECT d.organization_id, d.site_id, d.device_group_id, d.name, d.role, d.agent_role, d.os_description, d.platform, s.name, o.name
		FROM devices d JOIN sites s ON s.id = d.site_id JOIN organizations o ON o.id = d.organization_id WHERE d.id = $1`, a.DeviceID).
		Scan(&org, &site, &group, &name, &set, &reported, &osDesc, &platform, &siteN, &orgN)
	if errors.Is(err, pgx.ErrNoRows) {
		// The device is gone: nothing was told about the alert and nothing will be.
		return nil
	}
	if err != nil {
		return err
	}
	if !devscope.Allowed(org) {
		return nil
	}
	if a.CheckName != nil {
		check = *a.CheckName
	}
	kind := DeviceKind(set, reported, osDesc, platform)
	// A held predecessor on the same policy, device, kind, check and subject
	// carries on.
	if a.PolicyID != nil {
		var held uuid.UUID
		err := tx.QueryRow(ctx, `SELECT id FROM alert_incidents WHERE status = 'held' AND policy_id = $1 AND device_id = $2 AND alert_kind = $3
				AND coalesce(check_name, '') = $4 AND subject = $5 ORDER BY hold_until DESC LIMIT 1 FOR UPDATE`,
			*a.PolicyID, a.DeviceID, a.Kind, check, a.Subject).Scan(&held)
		if err == nil {
			if _, err := tx.Exec(ctx, `UPDATE alert_incidents SET status = CASE WHEN acknowledged_at IS NULL THEN 'open' ELSE 'acknowledged' END,
					alert_id = $2, alert_name = $3, severity = $4, detail = $5, value = $6, hold_until = NULL, resolved_at = NULL, resolution = NULL, updated_at = now()
				WHERE id = $1`, held, a.ID, Clean(a.Name, OtherNameClip), a.Severity, Clean(a.Detail, 500), a.Value); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `INSERT INTO alert_incident_alerts (alert_id, incident_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, a.ID, held)
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
	}
	key := ""
	if a.Subject != "" {
		key = a.DeviceID.String()[:8] + ":" + a.Kind + ":" + check + ":" + a.Subject
	}
	if _, err := tx.Exec(ctx, `INSERT INTO alert_incidents (id, organization_id, organization_name, site_id, site_name, device_group_id, device_id, device_name, device_kind,
			policy_id, alert_id, alert_kind, alert_name, check_name, subject, subject_label, key, severity, detail, value, status, opened_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), $10, $1, $11, $12, $13, $14, $15, $16, $17, $18, $19, 'open', $20)`,
		a.ID, org, Clean(orgN, OtherNameClip), site, Clean(siteN, OtherNameClip), group, a.DeviceID, Clean(name, DeviceNameClip), kind, a.PolicyID, a.Kind,
		Clean(a.Name, OtherNameClip), a.CheckName, a.Subject, Clean(a.SubjectLabel, OtherNameClip), key, a.Severity, Clean(a.Detail, 500), a.Value, a.OpenedAt); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO alert_incident_alerts (alert_id, incident_id) VALUES ($1, $1)`, a.ID); err != nil {
		return err
	}
	subj := Subject{Source: SourceAlerts, Org: org, Site: site, Group: group, Kind: kind, Severity: a.Severity, Condition: a.Kind, Check: check}
	return matchRules(ctx, tx, rules, subj, "incident", a.ID, a.OpenedAt)
}

// matchRules records what each matching rule's channels are to be told.
func matchRules(ctx context.Context, tx pgx.Tx, rules []Rule, subj Subject, kind string, id uuid.UUID, from time.Time) error {
	for i := range rules {
		r := &rules[i]
		if !r.Matches(subj) {
			continue
		}
		for _, ch := range r.ChannelIDs {
			if _, err := tx.Exec(ctx, `INSERT INTO alert_notifications (subject_type, subject_id, channel_id, rule_id, charged_org, wait_minutes, send_resolved, send_ack,
					reminder_hours, ignore_windows, group_outages, due_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
				ON CONFLICT (subject_type, subject_id, channel_id) DO UPDATE SET
					wait_minutes = LEAST(alert_notifications.wait_minutes, EXCLUDED.wait_minutes),
					due_at = LEAST(alert_notifications.due_at, EXCLUDED.due_at),
					send_resolved = alert_notifications.send_resolved OR EXCLUDED.send_resolved,
					send_ack = alert_notifications.send_ack OR EXCLUDED.send_ack,
					reminder_hours = CASE WHEN alert_notifications.reminder_hours = 0 THEN EXCLUDED.reminder_hours
						WHEN EXCLUDED.reminder_hours = 0 THEN alert_notifications.reminder_hours ELSE LEAST(alert_notifications.reminder_hours, EXCLUDED.reminder_hours) END,
					ignore_windows = alert_notifications.ignore_windows AND EXCLUDED.ignore_windows,
					group_outages = alert_notifications.group_outages AND EXCLUDED.group_outages`,
				kind, id, ch, r.ID, r.owner(), r.WaitMinutes, r.OnResolve, r.OnAcknowledge, r.ReminderHours, r.IgnoreWindows, r.GroupOutages,
				from.Add(time.Duration(r.WaitMinutes)*time.Minute)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) incidentAcknowledged(ctx context.Context, tx pgx.Tx, a alertRow) error {
	inc, err := incidentOf(ctx, tx, a.ID, true)
	if err != nil || inc == nil || inc.Status == "resolved" {
		return err
	}
	if a.AcknowledgedAt == nil {
		_, err := tx.Exec(ctx, `UPDATE alert_incidents SET acknowledged_at = NULL, acknowledged_by = '', updated_at = now(),
			status = CASE WHEN status = 'acknowledged' THEN 'open' ELSE status END WHERE id = $1`, inc.ID)
		return err
	}
	by := Clean(a.AcknowledgedByName, OtherNameClip)
	if _, err := tx.Exec(ctx, `UPDATE alert_incidents SET acknowledged_at = $2, acknowledged_by = $3, updated_at = now(),
		status = CASE WHEN status = 'open' THEN 'acknowledged' ELSE status END WHERE id = $1`, inc.ID, a.AcknowledgedAt, by); err != nil {
		return err
	}
	if inc.Status == "held" {
		return nil
	}
	inc.AcknowledgedAt, inc.AcknowledgedBy, inc.Status = a.AcknowledgedAt, by, "acknowledged"
	rows, err := notificationsOf(ctx, tx, "incident", inc.ID)
	if err != nil {
		return err
	}
	for _, n := range rows {
		if n.done || n.toldOpened == nil || !n.sendAck || n.ch.kind != KindWebhook || n.folded != nil {
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE alert_notifications SET told_ack_at = now() WHERE subject_type = 'incident' AND subject_id = $1 AND channel_id = $2`, inc.ID, n.ch.id); err != nil {
			return err
		}
		if err := s.enqueue(ctx, tx, n.ch, n.charged, inc.Org, []string{inc.ID.String()}, outEvent{name: EventAlertAcknowledged, op: opAck, alert: ref(inc.item())}); err != nil {
			return err
		}
	}
	return nil
}

func ref[T any](v T) *T { return &v }

// incidentResolved records a resolution. A policy change's resolution is
// held for a successor; any other is told at once to every channel that was
// told the alert opened.
func (s *Service) incidentResolved(ctx context.Context, tx pgx.Tx, alert uuid.UUID, resolution string, at time.Time, by string) error {
	inc, err := incidentOf(ctx, tx, alert, true)
	if err != nil || inc == nil || inc.Status == "resolved" {
		// A second resolution of a subject already resolved sends nothing.
		return err
	}
	if inc.Status == "held" {
		return nil
	}
	if resolution == "policy_changed" {
		_, err := tx.Exec(ctx, `UPDATE alert_incidents SET status = 'held', hold_until = $2, resolved_at = $3, resolution = $4, updated_at = now() WHERE id = $1`,
			inc.ID, s.now().Add(PolicyHold), at, resolution)
		return err
	}
	return s.finalizeResolved(ctx, tx, inc, resolution, at)
}

// finalizeResolved resolves an incident and tells the channels told of it.
func (s *Service) finalizeResolved(ctx context.Context, tx pgx.Tx, inc *incident, resolution string, at time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE alert_incidents SET status = 'resolved', hold_until = NULL, resolved_at = $2, resolution = $3, updated_at = now() WHERE id = $1`,
		inc.ID, at, resolution); err != nil {
		return err
	}
	inc.Status, inc.ResolvedAt, inc.Resolution = "resolved", &at, &resolution
	rows, err := notificationsOf(ctx, tx, "incident", inc.ID)
	if err != nil {
		return err
	}
	for _, n := range rows {
		if n.done {
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE alert_notifications SET done = true WHERE subject_type = 'incident' AND subject_id = $1 AND channel_id = $2`, inc.ID, n.ch.id); err != nil {
			return err
		}
		// Folded into a site outage, or never told: nothing to say. Once told,
		// told to the end, if the channel's people hear of resolutions.
		if n.folded != nil || n.toldOpened == nil || (n.ch.kind != KindWebhook && !n.sendResolved) {
			continue
		}
		if err := s.enqueue(ctx, tx, n.ch, n.charged, inc.Org, []string{inc.ID.String()}, outEvent{name: EventAlertResolved, op: opResolved, alert: ref(inc.item())}); err != nil {
			return err
		}
	}
	return nil
}

// notification is a row of alert_notifications with its channel.
type notification struct {
	ch           chInfo
	rule         *uuid.UUID
	charged      uuid.UUID
	waitMinutes  int
	sendResolved bool
	sendAck      bool
	reminder     int
	ignoreWin    bool
	groupOutages bool
	due          time.Time
	toldOpened   *time.Time
	lastTold     *time.Time
	folded       *uuid.UUID
	done         bool
	subject      uuid.UUID
}

// chInfo is the channel a delivery is queued to.
type chInfo struct {
	id         uuid.UUID
	owner      uuid.UUID
	kind       string
	enabled    bool
	recipients []string
}

const notificationCols = `n.subject_id, n.channel_id, n.rule_id, n.charged_org, n.wait_minutes, n.send_resolved, n.send_ack, n.reminder_hours, n.ignore_windows,
	n.group_outages, n.due_at, n.told_opened_at, n.last_told_at, n.folded_outage, n.done, c.owner, c.kind, c.enabled, d.recipients`

func scanNotification(row pgx.Row) (notification, error) {
	var n notification
	err := row.Scan(&n.subject, &n.ch.id, &n.rule, &n.charged, &n.waitMinutes, &n.sendResolved, &n.sendAck, &n.reminder, &n.ignoreWin, &n.groupOutages, &n.due,
		&n.toldOpened, &n.lastTold, &n.folded, &n.done, &n.ch.owner, &n.ch.kind, &n.ch.enabled, &n.ch.recipients)
	return n, err
}

func notificationsOf(ctx context.Context, tx pgx.Tx, typ string, id uuid.UUID) ([]notification, error) {
	rs, err := tx.Query(ctx, `SELECT `+notificationCols+` FROM alert_notifications n JOIN notification_channels c ON c.id = n.channel_id
		JOIN notification_channel_details d ON d.channel_id = c.id WHERE n.subject_type = $1 AND n.subject_id = $2 ORDER BY n.channel_id`, typ, id)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []notification
	for rs.Next() {
		n, err := scanNotification(rs)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rs.Err()
}

// applyNotice plans a notice's journal row.
func (s *Service) applyNotice(ctx context.Context, tx pgx.Tx, rules []Rule, r journalRow) error {
	var n struct {
		ID             uuid.UUID  `json:"id"`
		OrganizationID *uuid.UUID `json:"organization_id"`
		Kind           string     `json:"kind"`
		Title          string     `json:"title"`
		Detail         string     `json:"detail"`
		SiteID         *uuid.UUID `json:"site_id"`
		OpenedAt       time.Time  `json:"opened_at"`
	}
	if err := json.Unmarshal(r.newRow, &n); err != nil {
		return fmt.Errorf("reading the journal row: %w", err)
	}
	org := uuid.Nil
	if n.OrganizationID != nil {
		org = *n.OrganizationID
		if !devscope.Allowed(org) {
			return nil
		}
	}
	body := NoticeBody{ID: n.ID, Kind: n.Kind, Title: Clean(n.Title, 200), Detail: Clean(n.Detail, 1000), OrganizationID: n.OrganizationID, OpenedAt: n.OpenedAt}
	switch r.event {
	case "opened":
		subj := Subject{Source: SourceNotices, Org: org, Condition: n.Kind}
		if n.SiteID != nil {
			subj.Site = *n.SiteID
		}
		return matchRules(ctx, tx, rules, subj, "notice", n.ID, n.OpenedAt)
	case "resolved":
		rows, err := notificationsOf(ctx, tx, "notice", n.ID)
		if err != nil {
			return err
		}
		for _, x := range rows {
			if x.done {
				continue
			}
			if _, err := tx.Exec(ctx, `UPDATE alert_notifications SET done = true WHERE subject_type = 'notice' AND subject_id = $1 AND channel_id = $2`, n.ID, x.ch.id); err != nil {
				return err
			}
			if x.toldOpened == nil || (x.ch.kind != KindWebhook && !x.sendResolved) {
				continue
			}
			if err := s.enqueue(ctx, tx, x.ch, x.charged, org, []string{n.ID.String()}, outEvent{name: EventNoticeResolved, op: opNoticeResolved, notice: &body}); err != nil {
				return err
			}
		}
	case "acknowledged":
		var ack struct {
			At *time.Time `json:"acknowledged_at"`
		}
		_ = json.Unmarshal(r.newRow, &ack)
		rows, err := notificationsOf(ctx, tx, "notice", n.ID)
		if err != nil {
			return err
		}
		for _, x := range rows {
			if x.done || x.toldOpened == nil || !x.sendAck || x.ch.kind != KindWebhook || ack.At == nil {
				continue
			}
			if err := s.enqueue(ctx, tx, x.ch, x.charged, org, []string{n.ID.String()}, outEvent{name: "notices.acknowledged", op: opAck, notice: &body}); err != nil {
				return err
			}
		}
	}
	return nil
}
