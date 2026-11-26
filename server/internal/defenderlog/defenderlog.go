// Package defenderlog stores the Microsoft Defender events the agents read
// from the Operational log and judges them (ADR-0074 section 7): it
// deduplicates and acknowledges batches, keeps what names a path or a user
// apart from what anyone with defender.view may see, marks EasyRMM's own
// changes, and derives the snapshot the event-driven alert kinds read.
package defenderlog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/defender"
)

// Gate says whether the Defender module may work for a site (the toggle and
// the development scope): modules.Service.Allowed.
type Gate interface {
	Allowed(ctx context.Context, org, site uuid.UUID, m modules.Module) bool
}

// Retention (ADR-0074): paths, users and changed values for 30 days, the
// row for 90.
const (
	SensitiveFor = 30 * 24 * time.Hour
	KeepFor      = 90 * 24 * time.Hour
	// RecentBackfill is how old a backfilled event may be and still raise an
	// alert, so enabling the module does not raise a day of stale ones.
	RecentBackfill = 60 * time.Minute
	// the window around a change EasyRMM made, in which Defender's own
	// event for it is ours.
	oursBefore = 5 * time.Second
	oursAfter  = 60 * time.Second
)

// Store keeps and judges Defender events.
type Store struct {
	db   *database.DB
	gate Gate
	log  *slog.Logger
	now  func() time.Time
}

// New builds the store.
func New(db *database.DB, gate Gate, log *slog.Logger) *Store {
	return &Store{db: db, gate: gate, log: log, now: time.Now}
}

// Enabled says whether the agent of d should read its Defender log: the
// module is on for the site and the organization is in scope, and the device
// reported the Defender role as present.
func (s *Store) Enabled(ctx context.Context, tx pgx.Tx, device, org, site uuid.UUID) bool {
	if s.gate == nil || !s.gate.Allowed(ctx, org, site, modules.Defender) {
		return false
	}
	def, ok := modules.Lookup(modules.Defender)
	if !ok {
		return false
	}
	var present bool
	err := tx.QueryRow(ctx, `SELECT jsonb_path_exists(coalesce(roles, '[]'::jsonb),
		'$[*] ? (@.name == $role && @.state == "present")', jsonb_build_object('role', $2::text)) FROM devices WHERE id = $1`,
		device, def.Role).Scan(&present)
	return err == nil && present
}

// class says what a configuration change event touched, from the setting's
// key in its old or new value: "exclusion", "setting" (a security-relevant
// one) or "other" (Defender writes many on its own). The list is data, to
// confirm against real events (ADR-0074 R5).
func class(eventID int, sensitive map[string]string) string {
	if eventID == 5004 {
		return "setting"
	}
	v := strings.ToLower(sensitive["oldValue"] + " " + sensitive["newValue"])
	switch {
	case strings.Contains(v, `\exclusions\`):
		return "exclusion"
	}
	for _, k := range securityKeys {
		if strings.Contains(v, k) {
			return "setting"
		}
	}
	return "other"
}

var securityKeys = []string{
	`\real-time protection`, `disableantispyware`, `disableantivirus`, `disablerealtimemonitoring`, `disablebehaviormonitoring`,
	`disableioavprotection`, `disableonaccessprotection`, `\spynet`, `threatseveritydefaultaction`, `\windows defender exploit guard\`,
	`puaprotection`, `enablenetworkprotection`, `\controlled folder access`, `\attack surface reduction`,
}

func nullIf(m map[string]string) any {
	if len(m) == 0 {
		return nil
	}
	return m
}

// row is an event ready to store.
type row struct {
	e       agentproto.DefenderLogEvent
	rank    int
	summary map[string]any
	sens    map[string]string
	ours    bool
}

func rank(name string) int {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "low":
		return 1
	case "moderate", "medium":
		return 2
	case "high":
		return 4
	case "severe", "critical":
		return 5
	}
	return 0
}

// normalise splits an event into what defender.view may see (summary) and
// what needs defender.view_sensitive. A path, a user, a process name and the
// old and new value of a change are never in the summary; a configuration
// change shows only its class.
func normalise(e agentproto.DefenderLogEvent) row {
	sum := map[string]any{"eventId": e.EventID}
	put := func(k, v string) {
		if v != "" {
			sum[k] = v
		}
	}
	put("severity", e.Severity)
	put("origin", e.Origin)
	put("source", e.Source)
	put("errorCode", e.ErrorCode)
	put("engineVersion", e.EngineVer)
	put("signatureVersion", e.SigVer)
	if e.EventID == 5004 || e.EventID == 5007 {
		sum["class"] = class(e.EventID, e.Sensitive)
	}
	if e.Count > 1 {
		sum["count"] = e.Count
		sum["firstAt"] = e.FirstAt
		sum["firstRecord"] = e.FirstRecord
		if len(e.ThreatIDs) > 0 {
			sum["threatIds"] = e.ThreatIDs
		}
	}
	if e.Truncated {
		sum["truncated"] = true
	}
	return row{e: e, rank: rank(e.Severity), summary: sum, sens: e.Sensitive}
}

// configEvents are the events a change of EasyRMM's own can cause.
var configEvents = []int{5000, 5001, 5004, 5007, 5009, 5010, 5011, 5012, 5013}

type window struct{ from, to time.Time }

// ownWindows are the periods of this device's Defender change jobs
// (ADR-0074: from 5 seconds before the job started to 60 after it ended).
func (s *Store) ownWindows(ctx context.Context, tx pgx.Tx, device uuid.UUID, from, to time.Time) ([]window, error) {
	var actions []string
	for _, a := range defender.Actions() {
		if a.Changes {
			actions = append(actions, a.Name)
		}
	}
	rows, err := tx.Query(ctx, `SELECT coalesce(r.started_at, r.created_at), coalesce(r.finished_at, $5)
		FROM job_runs r JOIN jobs j ON j.id = r.job_id
		WHERE r.device_id = $1 AND j.kind = 'winmod' AND j.winmod->>'module' = 'defender' AND j.winmod->>'action' = ANY ($2)
		  AND coalesce(r.finished_at, $5) >= $3 AND coalesce(r.started_at, r.created_at) <= $4`,
		device, actions, from.Add(-oursAfter), to.Add(oursBefore), s.now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []window
	for rows.Next() {
		var w window
		if err := rows.Scan(&w.from, &w.to); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// Ingest stores a batch (nil for none), tags EasyRMM's own changes, refreshes
// the derived snapshot when something arrived or it is stale, and returns the
// acknowledgement for the agent. It runs in the heartbeat's transaction and
// is not called for a device the module is not enabled for.
func (s *Store) Ingest(ctx context.Context, tx pgx.Tx, device, org, site uuid.UUID, b *agentproto.DefenderLogBatch) (*agentproto.DefenderLogAck, error) {
	d := struct{ ID, Org, Site uuid.UUID }{device, org, site}
	var ack *agentproto.DefenderLogAck
	refresh, gap := false, false
	if b != nil {
		gap = b.Gap
		if err := b.Check(); err != nil {
			return nil, err
		}
		rows := make([]row, 0, len(b.Events))
		for _, e := range b.Events {
			rows = append(rows, normalise(e))
		}
		if len(rows) > 0 {
			from, to := rows[0].e.At, rows[0].e.At
			for _, r := range rows {
				if r.e.At.Before(from) {
					from = r.e.At
				}
				if r.e.At.After(to) {
					to = r.e.At
				}
			}
			wins, err := s.ownWindows(ctx, tx, d.ID, from, to)
			if err != nil {
				return nil, err
			}
			for i := range rows {
				if !slices.Contains(configEvents, rows[i].e.EventID) {
					continue
				}
				for _, w := range wins {
					if !rows[i].e.At.Before(w.from.Add(-oursBefore)) && !rows[i].e.At.After(w.to.Add(oursAfter)) {
						rows[i].ours = true
					}
				}
			}
		}
		for _, r := range rows {
			sum, _ := json.Marshal(r.summary)
			var sens []byte
			if len(r.sens) > 0 {
				sens, _ = json.Marshal(r.sens)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO defender_events (organization_id, site_id, device_id, epoch, record_id, event_id, occurred_at,
					severity, threat_id, threat_name, category, action, summary, sensitive, ours, backfill)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
				ON CONFLICT (device_id, epoch, record_id) DO NOTHING`,
				d.Org, d.Site, d.ID, b.Epoch, r.e.RecordID, r.e.EventID, r.e.At, r.rank, r.e.ThreatID, r.e.ThreatName, r.e.Category, r.e.Action,
				sum, sens, r.ours, b.Backfill); err != nil {
				return nil, fmt.Errorf("defenderlog: storing an event: %w", err)
			}
		}
		ack = &agentproto.DefenderLogAck{Epoch: b.Epoch, RecordID: b.Through}
		refresh = len(rows) > 0 || b.Gap || b.Backfill
	}
	if !refresh {
		var taken time.Time
		err := tx.QueryRow(ctx, `SELECT taken_at FROM windows_module_snapshots WHERE device_id = $1 AND action = $2 AND params_hash = ''`,
			d.ID, defender.EventsAction).Scan(&taken)
		refresh = errors.Is(err, pgx.ErrNoRows) || (err == nil && s.now().Sub(taken) >= defender.EventsRefreshEach)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return ack, err
		}
	}
	if refresh {
		if err := s.Refresh(ctx, tx, d.ID, gap); err != nil {
			return ack, err
		}
	}
	return ack, nil
}

type ev struct {
	eventID    int
	at         time.Time
	severity   int
	threatID   string
	threatName string
	class      string
	ours       bool
}

// Refresh recomputes the derived snapshot of a device from its events of the
// last seven days and stores it; gap says events may have been missed now.
func (s *Store) Refresh(ctx context.Context, tx pgx.Tx, device uuid.UUID, gap bool) error {
	now := s.now().UTC()
	rows, err := tx.Query(ctx, `SELECT event_id, occurred_at, severity, threat_id, threat_name, coalesce(summary->>'class', ''), ours
		FROM defender_events WHERE device_id = $1 AND occurred_at > $2 AND (NOT backfill OR occurred_at > received_at - $3::interval)
		ORDER BY occurred_at, id`, device, now.Add(-defender.ChangeAlertFor), fmt.Sprintf("%d seconds", int(RecentBackfill.Seconds())))
	if err != nil {
		return err
	}
	var events []ev
	for rows.Next() {
		var e ev
		if err := rows.Scan(&e.eventID, &e.at, &e.severity, &e.threatID, &e.threatName, &e.class, &e.ours); err != nil {
			rows.Close()
			return err
		}
		events = append(events, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var prev []byte
	_ = tx.QueryRow(ctx, `SELECT data FROM windows_module_snapshots WHERE device_id = $1 AND action = $2 AND params_hash = ''`,
		device, defender.EventsAction).Scan(&prev)
	st := derive(events, now)
	var old struct {
		Gap *json.RawMessage `json:"gap"`
	}
	if len(prev) > 0 && json.Unmarshal(prev, &old) == nil && old.Gap != nil {
		var s string
		if json.Unmarshal(*old.Gap, &s) == nil {
			if t, err := time.Parse(time.RFC3339, s); err == nil && now.Sub(t) < defender.ChangeAlertFor {
				st.Gap = &t
			}
		}
	}
	if gap {
		st.Gap = tp(now)
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO windows_module_snapshots (device_id, module, action, params_hash, taken_at, sensitive, data)
		VALUES ($1, 'defender', $2, '', $3, false, $4)
		ON CONFLICT (device_id, action, params_hash) DO UPDATE SET taken_at = excluded.taken_at, data = excluded.data`,
		device, defender.EventsAction, now, data)
	return err
}

func tp(t time.Time) *time.Time { return &t }

// derive derives the unresolved facts from events in time order. A detection
// is open until a later action event (1117 or 1007) names the same threat; a
// failed remediation likewise; an update failure until a later success;
// health, support and the change kinds by their age. EasyRMM's own changes
// are never counted.
func derive(events []ev, now time.Time) defender.EventsState {
	st := defender.EventsState{AsOf: now, OpenThreats: []defender.OpenThreat{}, FailedRemediations: []defender.OpenThreat{}}
	open := map[string]defender.OpenThreat{}
	failed := map[string]defender.OpenThreat{}
	var order, forder []string
	var lastUpdateOK time.Time
	for _, e := range events {
		switch e.eventID {
		case 1006, 1116, 1015:
			t := defender.OpenThreat{ID: e.threatID, Name: e.threatName, Severity: e.severity, At: e.at}
			if t.Name == "" {
				t.Name = "a threat"
			}
			if _, ok := open[e.threatID]; !ok {
				order = append(order, e.threatID)
			}
			open[e.threatID] = t
		case 1117, 1007:
			delete(open, e.threatID)
			delete(failed, e.threatID)
		case 1008, 1118, 1119:
			t := defender.OpenThreat{ID: e.threatID, Name: e.threatName, Severity: e.severity, At: e.at}
			if t.Name == "" {
				t.Name = "a threat"
			}
			if _, ok := failed[e.threatID]; !ok {
				forder = append(forder, e.threatID)
			}
			failed[e.threatID] = t
		case 2000, 2002:
			lastUpdateOK = e.at
			st.UpdateFailingSince = nil
		case 2001, 2003, 2006:
			if st.UpdateFailingSince == nil && e.at.After(lastUpdateOK) {
				st.UpdateFailingSince = tp(e.at)
			}
		case 3002, 5008:
			st.UnhealthyAt = tp(e.at)
		case 3007:
			st.UnhealthyAt = nil
		case 5100, 5101:
			st.OutOfSupportAt = tp(e.at)
		case 5013:
			if !e.ours {
				st.TamperBlockedAt = tp(e.at)
			}
		case 5004, 5007:
			if e.ours {
				continue
			}
			switch e.class {
			case "exclusion":
				st.ExclusionChangedAt = tp(e.at)
			case "setting":
				st.ConfigChangedAt = tp(e.at)
			}
		}
	}
	for _, id := range order {
		if t, ok := open[id]; ok {
			st.OpenThreats = append(st.OpenThreats, t)
		}
	}
	for _, id := range forder {
		if t, ok := failed[id]; ok {
			st.FailedRemediations = append(st.FailedRemediations, t)
		}
	}
	if len(st.OpenThreats) > 20 {
		st.OpenThreats = st.OpenThreats[len(st.OpenThreats)-20:]
	}
	if len(st.FailedRemediations) > 20 {
		st.FailedRemediations = st.FailedRemediations[len(st.FailedRemediations)-20:]
	}
	return st
}

// Cleanup applies the retention: changed values, paths and users are cleared
// after 30 days, the rows deleted after 90.
func (s *Store) Cleanup(ctx context.Context) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		now := s.now()
		if _, err := tx.Exec(ctx, `UPDATE defender_events SET sensitive = NULL WHERE sensitive IS NOT NULL AND received_at < $1`, now.Add(-SensitiveFor)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM defender_events WHERE received_at < $1`, now.Add(-KeepFor))
		return err
	})
}
