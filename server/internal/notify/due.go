package notify

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
)

// What is due (ADR-0053, "Device alert rules"): waits that ended, reminders,
// maintenance windows, site outages, the fleet-wide hold. The planner does
// all of it, after the journal's rows, in one transaction, under its lock.

// The fleet-wide hold's thresholds (ADR-0053, "Restarts, and EasyRMM itself
// unreachable").
const (
	// A device is silent after three of its own heartbeat intervals (ADR-0058), which is what it takes to stop counting
	// as online.
	FleetSilentIntervals = 3
	FleetWindow          = 5 * time.Minute // the window in which devices go silent
	FleetMinDevices      = 20
)

// Notice kinds raised by slice 4.
const (
	NoticePlanningStopped = "planning_stopped"
	NoticeQuarantined     = "journal_quarantined"
	NoticeQueueFull       = "queue_full"
	NoticeFleetSilent     = "fleet_silent"
	NoticeMaintenance     = "maintenance_window"
	NoticeRuleEmpty       = "rule_matches_nothing"
)

func (s *Service) duePass(ctx context.Context) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var got bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, lockPlanner).Scan(&got); err != nil || !got {
			return err
		}
		now := s.now()
		windows, err := s.windowsTick(ctx, tx, now)
		if err != nil {
			return fmt.Errorf("maintenance windows: %w", err)
		}
		if err := s.releaseHeld(ctx, tx, now); err != nil {
			return fmt.Errorf("policy changes: %w", err)
		}
		silent, err := s.silenceTick(ctx, tx, now)
		if err != nil {
			return fmt.Errorf("the fleet-wide hold: %w", err)
		}
		outages, err := s.outageTick(ctx, tx, now)
		if err != nil {
			return fmt.Errorf("site outages: %w", err)
		}
		if err := s.sendDue(ctx, tx, now, windows, silent, outages); err != nil {
			return fmt.Errorf("what is due: %w", err)
		}
		if err := s.sendNotices(ctx, tx, now); err != nil {
			return fmt.Errorf("notices: %w", err)
		}
		return s.emptyRules(ctx, tx)
	})
}

// windowsTick finds the sites held by a maintenance window now, and raises a
// notice at each window's start and resolves it at its end.
func (s *Service) windowsTick(ctx context.Context, tx pgx.Tx, now time.Time) (map[uuid.UUID]bool, error) {
	rs, err := tx.Query(ctx, `SELECT `+windowCols+` FROM site_maintenance_windows w JOIN sites s ON s.id = w.site_id`)
	if err != nil {
		return nil, err
	}
	type w struct {
		Window
		tz string
	}
	var all []w
	for rs.Next() {
		x, tz, err := scanWindow(rs)
		if err != nil {
			rs.Close()
			return nil, err
		}
		all = append(all, w{x, tz})
	}
	rs.Close()
	if err := rs.Err(); err != nil {
		return nil, err
	}
	held := map[uuid.UUID]bool{}
	for _, x := range all {
		active := x.HoldsNotifications() && x.ActiveAt(siteLocation(x.tz), now)
		if active {
			held[x.SiteID] = true
		}
		if active == x.Active {
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE site_maintenance_windows SET active = $2 WHERE id = $1`, x.ID, active); err != nil {
			return nil, err
		}
		org := x.OrganizationID
		if active {
			if !devscope.Allowed(org) {
				continue
			}
			if _, err := tx.Exec(ctx, `INSERT INTO notices (organization_id, kind, subject, site_id, title, detail) VALUES ($1, $2, $3, $4, $5, $6)
				ON CONFLICT (coalesce(organization_id, '00000000-0000-0000-0000-000000000000'::uuid), kind, subject) WHERE resolved_at IS NULL DO NOTHING`,
				org, NoticeMaintenance, x.ID.String(), x.SiteID, clip("Maintenance window started at "+Clean(x.SiteName, OtherNameClip), 200),
				clip(fmt.Sprintf("The window %q holds notifications about this site's devices until it ends.", Clean(x.Name, OtherNameClip)), 1000)); err != nil {
				return nil, err
			}
		} else if err := resolveNotice(ctx, tx, &org, NoticeMaintenance, x.ID.String()); err != nil {
			return nil, err
		}
	}
	return held, nil
}

// releaseHeld finishes the resolutions of policy changes whose successor
// never opened: they are told now, as resolutions.
func (s *Service) releaseHeld(ctx context.Context, tx pgx.Tx, now time.Time) error {
	rs, err := tx.Query(ctx, `SELECT `+incidentCols+` FROM alert_incidents WHERE status = 'held' AND hold_until <= $1 ORDER BY hold_until FOR UPDATE`, now)
	if err != nil {
		return err
	}
	var held []incident
	for rs.Next() {
		i, err := scanIncident(rs)
		if err != nil {
			rs.Close()
			return err
		}
		held = append(held, i)
	}
	rs.Close()
	if err := rs.Err(); err != nil {
		return err
	}
	for i := range held {
		at := now
		if held[i].ResolvedAt != nil {
			at = *held[i].ResolvedAt
		}
		if err := s.finalizeResolved(ctx, tx, &held[i], "policy_changed", at); err != nil {
			return err
		}
	}
	return nil
}

// silenceTick starts and ends the fleet-wide hold, and reports whether it
// is on: of the devices with an EasyRMM agent that had checked in lately, at
// least half and at least 20 have gone silent at once. While the server is
// within its serving floor it neither starts nor ends one.
func (s *Service) silenceTick(ctx context.Context, tx pgx.Tx, now time.Time) (bool, error) {
	floor := s.floor(now)
	var id uuid.UUID
	var started time.Time
	var counted []uuid.UUID
	var countedN int
	open := true
	err := tx.QueryRow(ctx, `SELECT id, started_at, counted, counted_n FROM fleet_silences WHERE ended_at IS NULL`).Scan(&id, &started, &counted, &countedN)
	if errors.Is(err, pgx.ErrNoRows) {
		open = false
	} else if err != nil {
		return false, err
	}
	if now.Before(floor) {
		return open, nil
	}
	if open {
		var back int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM devices WHERE id = ANY ($1) AND agent_last_seen_at > $2`, counted, started).Scan(&back); err != nil {
			return false, err
		}
		if back*2 <= countedN {
			return true, nil
		}
		if _, err := tx.Exec(ctx, `UPDATE fleet_silences SET ended_at = $2, back_n = $3 WHERE id = $1`, id, now, back); err != nil {
			return false, err
		}
		return false, resolveNotice(ctx, tx, nil, NoticeFleetSilent, id.String())
	}
	rs, err := tx.Query(ctx, `SELECT id, organization_id, agent_last_seen_at, agent_heartbeat_seconds FROM devices
		WHERE agent_public_key IS NOT NULL AND agent_uninstalled_at IS NULL AND NOT quick_assist AND agent_online_until >= $1`,
		now.Add(-FleetWindow))
	if err != nil {
		return false, err
	}
	var base []uuid.UUID
	silent := 0
	for rs.Next() {
		var d, o uuid.UUID
		var seen time.Time
		var interval int
		if err := rs.Scan(&d, &o, &seen, &interval); err != nil {
			rs.Close()
			return false, err
		}
		if !devscope.Allowed(o) {
			continue
		}
		base = append(base, d)
		if seen.Before(floor) {
			seen = floor
		}
		if now.Sub(seen) >= FleetSilentIntervals*time.Duration(interval)*time.Second {
			silent++
		}
	}
	rs.Close()
	if err := rs.Err(); err != nil {
		return false, err
	}
	if len(base) < FleetMinDevices || silent*2 < len(base) {
		return false, nil
	}
	if err := tx.QueryRow(ctx, `INSERT INTO fleet_silences (started_at, counted, counted_n) VALUES ($1, $2, $3) RETURNING id`, now, base, len(base)).Scan(&id); err != nil {
		return false, err
	}
	return true, openNotice(ctx, tx, nil, NoticeFleetSilent, id.String(), "Most devices stopped checking in",
		fmt.Sprintf("%d of %d devices that had been checking in went silent within %d minutes. EasyRMM may be unreachable from them. Organizations' offline alerts wait until devices are back, or a super administrator ends the hold.", silent, len(base), int(FleetWindow.Minutes())))
}

// EndSilence ends the fleet-wide hold now, as a super administrator asks;
// the openings that waited and whose alerts are still open are then planned.
func (s *Service) endSilence(ctx context.Context, tx pgx.Tx, by *uuid.UUID) (bool, error) {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `UPDATE fleet_silences SET ended_at = now(), ended_by = $1 WHERE ended_at IS NULL RETURNING id`, by).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, resolveNotice(ctx, tx, nil, NoticeFleetSilent, id.String())
}

// outageOpen is a site outage in force.
type outageOpen struct {
	id       uuid.UUID
	org      uuid.UUID
	site     uuid.UUID
	siteName string
	started  time.Time
	total    int
}

// outageTick opens and ends site outages. A site is down when at least two
// of its devices have an EasyRMM agent, are not uninstalled, are watched by
// an enabled offline policy, and all of them have an offline alert open.
func (s *Service) outageTick(ctx context.Context, tx pgx.Tx, now time.Time) (map[uuid.UUID]outageOpen, error) {
	rs, err := tx.Query(ctx, `SELECT d.site_id, d.organization_id, st.name, count(*),
			count(*) FILTER (WHERE EXISTS (SELECT 1 FROM alerts a WHERE a.device_id = d.id AND a.kind = 'offline' AND a.status <> 'resolved'))
		FROM devices d JOIN sites st ON st.id = d.site_id
		WHERE d.agent_public_key IS NOT NULL AND d.agent_uninstalled_at IS NULL AND NOT d.quick_assist
		  AND EXISTS (SELECT 1 FROM alert_policies p WHERE p.enabled AND p.kind = 'offline'
			AND (p.organization_id IS NULL OR (p.organization_id = d.organization_id AND (p.site_id IS NULL OR p.site_id = d.site_id))))
		GROUP BY d.site_id, d.organization_id, st.name`)
	if err != nil {
		return nil, err
	}
	type siteState struct {
		org         uuid.UUID
		name        string
		total, down int
	}
	states := map[uuid.UUID]siteState{}
	for rs.Next() {
		var site uuid.UUID
		var st siteState
		if err := rs.Scan(&site, &st.org, &st.name, &st.total, &st.down); err != nil {
			rs.Close()
			return nil, err
		}
		states[site] = st
	}
	rs.Close()
	if err := rs.Err(); err != nil {
		return nil, err
	}
	os, err := tx.Query(ctx, `SELECT id, organization_id, site_id, site_name, started_at, devices_total FROM site_outages WHERE ended_at IS NULL`)
	if err != nil {
		return nil, err
	}
	open := map[uuid.UUID]outageOpen{}
	for os.Next() {
		var o outageOpen
		if err := os.Scan(&o.id, &o.org, &o.site, &o.siteName, &o.started, &o.total); err != nil {
			os.Close()
			return nil, err
		}
		open[o.site] = o
	}
	os.Close()
	if err := os.Err(); err != nil {
		return nil, err
	}
	for site, o := range open {
		st := states[site]
		if st.total >= 2 && st.down == st.total {
			continue
		}
		if err := s.endOutage(ctx, tx, o, st.total-st.down, now); err != nil {
			return nil, err
		}
		delete(open, site)
	}
	for site, st := range states {
		if _, ok := open[site]; ok || st.total < 2 || st.down != st.total || !devscope.Allowed(st.org) {
			continue
		}
		o := outageOpen{org: st.org, site: site, siteName: Clean(st.name, OtherNameClip), started: now, total: st.total}
		if err := tx.QueryRow(ctx, `INSERT INTO site_outages (organization_id, site_id, site_name, started_at, devices_total) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
			o.org, o.site, o.siteName, now, o.total).Scan(&o.id); err != nil {
			return nil, err
		}
		open[site] = o
	}
	return open, nil
}

// endOutage ends an outage: channels told it began are told the site is
// back, and alerts folded in that are still open are told as their own.
func (s *Service) endOutage(ctx context.Context, tx pgx.Tx, o outageOpen, back int, now time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE site_outages SET ended_at = $2, devices_back = $3 WHERE id = $1`, o.id, now, back); err != nil {
		return err
	}
	rows, err := notificationsOf(ctx, tx, "outage", o.id)
	if err != nil {
		return err
	}
	for _, n := range rows {
		if n.done {
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE alert_notifications SET done = true WHERE subject_type = 'outage' AND subject_id = $1 AND channel_id = $2`, o.id, n.ch.id); err != nil {
			return err
		}
		ids, err := foldedIDs(ctx, tx, o.id, n.ch.id, false)
		if err != nil {
			return err
		}
		item := OutageItem{ID: o.id, SiteID: o.site, Site: o.siteName, OrganizationID: o.org, Devices: o.total, Back: back, StartedAt: o.started, EndedAt: &now, AlertIDs: ids}
		subjects := append([]string{o.id.String()}, idStrings(ids)...)
		if err := s.enqueue(ctx, tx, n.ch, n.charged, o.org, subjects, outEvent{name: EventSiteOnline, op: opUp, outage: &item}); err != nil {
			return err
		}
	}
	// Folded and still open: they go as their own opened alerts.
	_, err = tx.Exec(ctx, `UPDATE alert_notifications SET folded_outage = NULL, told_opened_at = NULL, due_at = $2
		WHERE folded_outage = $1 AND NOT done`, o.id, now)
	return err
}

func idStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

// foldedIDs lists the incidents folded into an outage for a channel.
func foldedIDs(ctx context.Context, tx pgx.Tx, outage, channel uuid.UUID, openOnly bool) ([]uuid.UUID, error) {
	q := `SELECT subject_id FROM alert_notifications WHERE subject_type = 'incident' AND folded_outage = $1 AND channel_id = $2`
	if openOnly {
		q += ` AND NOT done`
	}
	rs, err := tx.Query(ctx, q+` ORDER BY subject_id`, outage, channel)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var ids []uuid.UUID
	for rs.Next() {
		var id uuid.UUID
		if err := rs.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rs.Err()
}

type foldKey struct {
	outage, channel, charged uuid.UUID
}

// sendDue tells the channels what is due: openings whose wait ended and
// that nothing holds, reminders, and the alerts folded into outages.
func (s *Service) sendDue(ctx context.Context, tx pgx.Tx, now time.Time, windows map[uuid.UUID]bool, silent bool, outages map[uuid.UUID]outageOpen) error {
	rs, err := tx.Query(ctx, `SELECT `+notificationCols+` FROM alert_notifications n JOIN notification_channels c ON c.id = n.channel_id
		JOIN notification_channel_details d ON d.channel_id = c.id
		WHERE n.subject_type = 'incident' AND NOT n.done AND c.enabled ORDER BY n.due_at, n.subject_id, n.channel_id LIMIT 5000`)
	if err != nil {
		return err
	}
	var rows []notification
	for rs.Next() {
		n, err := scanNotification(rs)
		if err != nil {
			rs.Close()
			return err
		}
		rows = append(rows, n)
	}
	rs.Close()
	if err := rs.Err(); err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, 0, len(rows))
	for _, n := range rows {
		if !slices.Contains(ids, n.subject) {
			ids = append(ids, n.subject)
		}
	}
	ir, err := tx.Query(ctx, `SELECT `+incidentCols+` FROM alert_incidents WHERE id = ANY ($1)`, ids)
	if err != nil {
		return err
	}
	incs := map[uuid.UUID]incident{}
	for ir.Next() {
		i, err := scanIncident(ir)
		if err != nil {
			ir.Close()
			return err
		}
		incs[i.ID] = i
	}
	ir.Close()
	if err := ir.Err(); err != nil {
		return err
	}
	folds := map[foldKey][]incident{}
	foldRows := map[foldKey][]notification{}
	for _, n := range rows {
		inc, ok := incs[n.subject]
		if !ok || !devscope.Allowed(inc.Org) {
			continue
		}
		if inc.Status == "resolved" {
			if err := s.setDone(ctx, tx, n); err != nil {
				return err
			}
			continue
		}
		if inc.Status == "held" {
			continue
		}
		windowHeld := windows[inc.Site] && (n.charged != uuid.Nil || !n.ignoreWin) && inc.AlertKind != ConditionAgentRemoved
		if n.toldOpened == nil {
			switch {
			case inc.Status == "acknowledged" && inc.AcknowledgedAt != nil && inc.AcknowledgedAt.Before(n.due):
				// Acknowledged before the wait ended: nothing is sent.
				if err := s.setDone(ctx, tx, n); err != nil {
					return err
				}
			case now.Before(n.due):
			case windowHeld:
				if err := s.setHeld(ctx, tx, n, true); err != nil {
					return err
				}
			case silent && n.charged != uuid.Nil && inc.AlertKind == "offline":
				// Most devices went silent at once: organizations wait.
			default:
				o, down := outages[inc.Site]
				if down && inc.AlertKind == "offline" && n.groupOutages {
					k := foldKey{o.id, n.ch.id, n.charged}
					folds[k] = append(folds[k], inc)
					foldRows[k] = append(foldRows[k], n)
					continue
				}
				if err := s.tellOpened(ctx, tx, n, inc, now); err != nil {
					return err
				}
			}
			continue
		}
		if n.folded != nil || inc.Status != "open" || n.reminder <= 0 || windowHeld {
			continue
		}
		last := n.lastTold
		if last == nil {
			last = n.toldOpened
		}
		if now.Before(last.Add(time.Duration(n.reminder) * time.Hour)) {
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE alert_notifications SET last_told_at = $3 WHERE subject_type = 'incident' AND subject_id = $1 AND channel_id = $2`, n.subject, n.ch.id, now); err != nil {
			return err
		}
		if err := s.enqueue(ctx, tx, n.ch, n.charged, inc.Org, []string{inc.ID.String()}, outEvent{name: EventAlertReminder, op: opReminder, alert: ref(inc.item())}); err != nil {
			return err
		}
	}
	keys := make([]foldKey, 0, len(folds))
	for k := range folds {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b foldKey) int {
		return strings.Compare(a.outage.String()+a.channel.String(), b.outage.String()+b.channel.String())
	})
	for _, k := range keys {
		if err := s.fold(ctx, tx, k, folds[k], foldRows[k], outages, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) setDone(ctx context.Context, tx pgx.Tx, n notification) error {
	_, err := tx.Exec(ctx, `UPDATE alert_notifications SET done = true WHERE subject_type = 'incident' AND subject_id = $1 AND channel_id = $2`, n.subject, n.ch.id)
	return err
}

func (s *Service) setHeld(ctx context.Context, tx pgx.Tx, n notification, held bool) error {
	_, err := tx.Exec(ctx, `UPDATE alert_notifications SET held_by_window = $3 WHERE subject_type = 'incident' AND subject_id = $1 AND channel_id = $2 AND held_by_window <> $3`,
		n.subject, n.ch.id, held)
	return err
}

func (s *Service) tellOpened(ctx context.Context, tx pgx.Tx, n notification, inc incident, now time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE alert_notifications SET told_opened_at = $3, last_told_at = $3, held_by_window = false WHERE subject_type = 'incident' AND subject_id = $1 AND channel_id = $2`,
		n.subject, n.ch.id, now); err != nil {
		return err
	}
	return s.enqueue(ctx, tx, n.ch, n.charged, inc.Org, []string{inc.ID.String()}, outEvent{name: EventAlertOpened, op: opOpened, alert: ref(inc.item())})
}

// fold tells a channel one item for the outage in place of the alerts of
// the site's devices that its rules match. A folded alert counts as told.
func (s *Service) fold(ctx context.Context, tx pgx.Tx, k foldKey, incs []incident, rows []notification, outages map[uuid.UUID]outageOpen, now time.Time) error {
	o := outages[incs[0].Site]
	for _, n := range rows {
		if _, err := tx.Exec(ctx, `UPDATE alert_notifications SET told_opened_at = $3, last_told_at = $3, folded_outage = $4, held_by_window = false
			WHERE subject_type = 'incident' AND subject_id = $1 AND channel_id = $2`, n.subject, n.ch.id, now, k.outage); err != nil {
			return err
		}
	}
	first := rows[0]
	tag, err := tx.Exec(ctx, `INSERT INTO alert_notifications (subject_type, subject_id, channel_id, rule_id, charged_org, send_resolved, told_opened_at, last_told_at)
		VALUES ('outage', $1, $2, $3, $4, $5, $6, $6) ON CONFLICT DO NOTHING`, k.outage, k.channel, first.rule, k.charged, first.sendResolved, now)
	if err != nil || tag.RowsAffected() == 0 {
		// The channel already heard of the outage; stragglers are folded in.
		return err
	}
	ids, err := foldedIDs(ctx, tx, k.outage, k.channel, true)
	if err != nil {
		return err
	}
	item := OutageItem{ID: o.id, SiteID: o.site, Site: o.siteName, OrganizationID: o.org, Devices: o.total, StartedAt: o.started, AlertIDs: ids}
	subjects := append([]string{o.id.String()}, idStrings(ids)...)
	return s.enqueue(ctx, tx, first.ch, k.charged, o.org, subjects, outEvent{name: EventSiteOffline, op: opDown, outage: &item})
}

// emptyRules raises a notice, to the managers of its owner, for each rule
// whose list was emptied by deletions: it matches nothing; and resolves it
// when it does again.
func (s *Service) emptyRules(ctx context.Context, tx pgx.Tx) error {
	rs, err := tx.Query(ctx, `SELECT r.id, r.organization_id, r.name FROM notification_rules r WHERE r.enabled AND (
			(r.orgs_mode = 'list' AND NOT EXISTS (SELECT 1 FROM notification_rule_orgs x WHERE x.rule_id = r.id))
		 OR (r.sites_mode = 'list' AND NOT EXISTS (SELECT 1 FROM notification_rule_sites x WHERE x.rule_id = r.id))
		 OR (r.groups_mode = 'list' AND NOT EXISTS (SELECT 1 FROM notification_rule_groups x WHERE x.rule_id = r.id)))`)
	if err != nil {
		return err
	}
	type e struct {
		id   uuid.UUID
		org  *uuid.UUID
		name string
	}
	var empty []e
	for rs.Next() {
		var x e
		if err := rs.Scan(&x.id, &x.org, &x.name); err != nil {
			rs.Close()
			return err
		}
		empty = append(empty, x)
	}
	rs.Close()
	if err := rs.Err(); err != nil {
		return err
	}
	keep := make([]string, 0, len(empty))
	for _, x := range empty {
		keep = append(keep, x.id.String())
		if err := openNotice(ctx, tx, x.org, NoticeRuleEmpty, x.id.String(), "A notification rule matches nothing",
			fmt.Sprintf("The rule %q lists sites, device groups or organizations that were all deleted, so it notifies about nothing. Choose new ones or delete the rule.", Clean(x.name, OtherNameClip))); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `UPDATE notices SET resolved_at = now() WHERE kind = $1 AND resolved_at IS NULL AND NOT (subject = ANY ($2))`, NoticeRuleEmpty, keep)
	return err
}

// sendNotices tells the channels of rules about notices that a notice opened.
// A notice resolved before its wait ended sends nothing. Maintenance windows
// do not hold notices.
func (s *Service) sendNotices(ctx context.Context, tx pgx.Tx, now time.Time) error {
	rs, err := tx.Query(ctx, `SELECT `+notificationCols+`, x.organization_id, x.kind, x.title, x.detail, x.opened_at, x.resolved_at
		FROM alert_notifications n JOIN notification_channels c ON c.id = n.channel_id
		JOIN notification_channel_details d ON d.channel_id = c.id JOIN notices x ON x.id = n.subject_id
		WHERE n.subject_type = 'notice' AND NOT n.done AND n.told_opened_at IS NULL AND n.due_at <= $1 AND c.enabled
		ORDER BY n.due_at, n.subject_id, n.channel_id LIMIT 1000`, now)
	if err != nil {
		return err
	}
	type due struct {
		n        notification
		org      *uuid.UUID
		body     NoticeBody
		resolved *time.Time
	}
	var list []due
	for rs.Next() {
		var d due
		var kind, title, detail string
		var opened time.Time
		if err := rs.Scan(&d.n.subject, &d.n.ch.id, &d.n.rule, &d.n.charged, &d.n.waitMinutes, &d.n.sendResolved, &d.n.sendAck, &d.n.reminder, &d.n.ignoreWin,
			&d.n.groupOutages, &d.n.due, &d.n.toldOpened, &d.n.lastTold, &d.n.folded, &d.n.done, &d.n.ch.owner, &d.n.ch.kind, &d.n.ch.enabled, &d.n.ch.recipients,
			&d.org, &kind, &title, &detail, &opened, &d.resolved); err != nil {
			rs.Close()
			return err
		}
		d.body = NoticeBody{ID: d.n.subject, Kind: kind, Title: Clean(title, 200), Detail: Clean(detail, 1000), OrganizationID: d.org, OpenedAt: opened}
		list = append(list, d)
	}
	rs.Close()
	if err := rs.Err(); err != nil {
		return err
	}
	for _, d := range list {
		org := uuid.Nil
		if d.org != nil {
			org = *d.org
			if !devscope.Allowed(org) {
				continue
			}
		}
		if d.resolved != nil {
			if err := s.setNoticeDone(ctx, tx, d.n, nil, now); err != nil {
				return err
			}
			continue
		}
		if err := s.setNoticeDone(ctx, tx, d.n, &now, now); err != nil {
			return err
		}
		if err := s.enqueue(ctx, tx, d.n.ch, d.n.charged, org, []string{d.n.subject.String()}, outEvent{name: EventNoticeOpened, op: opNoticeOpened, notice: ref(d.body)}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) setNoticeDone(ctx context.Context, tx pgx.Tx, n notification, told *time.Time, now time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE alert_notifications SET told_opened_at = $3::timestamptz, last_told_at = $3::timestamptz, done = ($3::timestamptz IS NULL)
		WHERE subject_type = 'notice' AND subject_id = $1 AND channel_id = $2`, n.subject, n.ch.id, told)
	return err
}
