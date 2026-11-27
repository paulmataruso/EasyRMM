package notify

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Maintenance windows (ADR-0053): during one, a site's devices still raise
// alerts in the console, but organizations' rules send nothing new about
// them; what is still open and not acknowledged when it ends is sent, in one
// message.

// Window limits.
const (
	MaxWeeklyLength = 24 * 60
	MaxOnceLength   = 7 * 24 * 60
	MaxOnceAhead    = 90 * 24 * time.Hour
)

// Audit actions of windows.
const (
	ActionWindowCreate = "maintenance_window.create"
	ActionWindowUpdate = "maintenance_window.update"
	ActionWindowDelete = "maintenance_window.delete"
)

// Window is a maintenance window as the console shows it and sends it.
type Window struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organizationId"`
	SiteID         uuid.UUID `json:"siteId"`
	SiteName       string    `json:"siteName,omitempty"`
	Name           string    `json:"name"`
	Kind           string    `json:"kind"` // weekly or once
	// Days are the days of the week of a weekly window, 0 Sunday to 6
	// Saturday; the window belongs to the day it starts.
	Days []int `json:"days"`
	// Start is a weekly window's start, "15:04", in the site's time zone.
	Start string `json:"start,omitempty"`
	// StartsAt is a one-off window's start, "2006-01-02T15:04", as the
	// site's clock reads it.
	StartsAt      string    `json:"startsAt,omitempty"`
	LengthMinutes int       `json:"lengthMinutes"`
	Enabled       bool      `json:"enabled"`
	Active        bool      `json:"active"`
	CreatedAt     time.Time `json:"createdAt"`
	CanEdit       bool      `json:"canEdit"`
}

const (
	hhmm   = "15:04"
	local  = "2006-01-02T15:04"
	maxWin = 200
)

// wallInstant is the instant a wall clock reads in loc, made exact across
// daylight saving: a time in an hour that is skipped is the moment the gap
// ends; one in an hour that repeats is its first occurrence.
func wallInstant(loc *time.Location, y int, mo time.Month, d, h, mi int) time.Time {
	wall := time.Date(y, mo, d, h, mi, 0, 0, time.UTC)
	reads := func(t time.Time) bool {
		l := t.In(loc)
		return l.Year() == y && l.Month() == mo && l.Day() == d && l.Hour() == h && l.Minute() == mi
	}
	_, before := wall.Add(-36 * time.Hour).In(loc).Zone()
	_, after := wall.Add(36 * time.Hour).In(loc).Zone()
	var best time.Time
	for _, off := range []int{before, after} {
		t := wall.Add(-time.Duration(off) * time.Second)
		if reads(t) && (best.IsZero() || t.Before(best)) {
			best = t
		}
	}
	if !best.IsZero() {
		return best
	}
	// In a gap: the first instant after it.
	lo, hi := wall.Add(-time.Duration(max(before, after))*time.Second), wall.Add(-time.Duration(min(before, after))*time.Second)
	_, offLo := lo.In(loc).Zone()
	for hi.Sub(lo) > time.Second {
		mid := lo.Add(hi.Sub(lo) / 2)
		if _, o := mid.In(loc).Zone(); o == offLo {
			lo = mid
		} else {
			hi = mid
		}
	}
	return hi.Truncate(time.Second)
}

func parseHM(s string) (h, m int, ok bool) {
	t, err := time.Parse(hhmm, s)
	if err != nil {
		return 0, 0, false
	}
	return t.Hour(), t.Minute(), true
}

// span is when one occurrence of a window lies.
type span struct{ start, end time.Time }

// spans lists the occurrences of w that can contain at (those starting
// yesterday or today, as lengths are at most a day), in the site's zone.
func (w *Window) spans(loc *time.Location, at time.Time) []span {
	length := time.Duration(w.LengthMinutes) * time.Minute
	switch w.Kind {
	case "once":
		t, err := time.Parse(local, w.StartsAt)
		if err != nil {
			return nil
		}
		st := wallInstant(loc, t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute())
		return []span{{st, st.Add(length)}}
	case "weekly":
		h, m, ok := parseHM(w.Start)
		if !ok {
			return nil
		}
		var out []span
		today := at.In(loc)
		for back := 0; back <= 1; back++ {
			d := time.Date(today.Year(), today.Month(), today.Day()-back, 12, 0, 0, 0, loc)
			if !slices.Contains(w.Days, int(d.Weekday())) {
				continue
			}
			st := wallInstant(loc, d.Year(), d.Month(), d.Day(), h, m)
			out = append(out, span{st, st.Add(length)})
		}
		return out
	}
	return nil
}

// ActiveAt reports whether the window holds notifications at that moment.
func (w *Window) ActiveAt(loc *time.Location, at time.Time) bool {
	if !w.Enabled {
		return false
	}
	for _, sp := range w.spans(loc, at) {
		if !at.Before(sp.start) && at.Before(sp.end) {
			return true
		}
	}
	return false
}

func siteLocation(name string) *time.Location {
	loc, err := time.LoadLocation(name)
	if err != nil {
		return time.UTC
	}
	return loc
}

func (s *Service) cleanWindow(in Window, loc *time.Location) (Window, error) {
	var err error
	if in.Name, err = cleanName(in.Name); err != nil {
		return in, err
	}
	switch in.Kind {
	case "weekly":
		in.StartsAt = ""
		if _, _, ok := parseHM(in.Start); !ok {
			return in, apperr.Invalid("start", "Enter the start as hours and minutes, such as 22:00.")
		}
		days := []int{}
		for _, d := range in.Days {
			if d < 0 || d > 6 {
				return in, apperr.Invalid("days", "Days are 0 (Sunday) to 6 (Saturday).")
			}
			if !slices.Contains(days, d) {
				days = append(days, d)
			}
		}
		slices.Sort(days)
		if len(days) == 0 {
			return in, apperr.Invalid("days", "Choose at least one day.")
		}
		in.Days = days
		if in.LengthMinutes < 1 || in.LengthMinutes > MaxWeeklyLength {
			return in, apperr.Invalid("lengthMinutes", "A weekly window lasts from 1 minute to 24 hours.")
		}
	case "once":
		in.Start, in.Days = "", []int{}
		t, err := time.Parse(local, in.StartsAt)
		if err != nil {
			return in, apperr.Invalid("startsAt", "Enter the start as a date and time.")
		}
		if in.LengthMinutes < 1 || in.LengthMinutes > MaxOnceLength {
			return in, apperr.Invalid("lengthMinutes", "A one-off window lasts from 1 minute to 7 days.")
		}
		st := wallInstant(loc, t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute())
		now := s.now()
		if st.After(now.Add(MaxOnceAhead)) {
			return in, apperr.Invalid("startsAt", "A one-off window must start within 90 days.")
		}
		if !st.Add(time.Duration(in.LengthMinutes) * time.Minute).After(now) {
			return in, apperr.Invalid("startsAt", "That window has already ended.")
		}
	default:
		return in, apperr.Invalid("kind", "A window is weekly or once.")
	}
	return in, nil
}

const windowCols = `w.id, w.organization_id, w.site_id, s.name, s.timezone, w.name, w.kind, w.days, coalesce(to_char(w.start_local, 'HH24:MI'), ''),
	coalesce(to_char(w.starts_local, 'YYYY-MM-DD"T"HH24:MI'), ''), w.length_minutes, w.enabled, w.active, w.created_at`

func scanWindow(row pgx.Row) (Window, string, error) {
	var w Window
	var days []int16
	var tz string
	err := row.Scan(&w.ID, &w.OrganizationID, &w.SiteID, &w.SiteName, &tz, &w.Name, &w.Kind, &days, &w.Start, &w.StartsAt, &w.LengthMinutes, &w.Enabled, &w.Active, &w.CreatedAt)
	w.Days = make([]int, 0, len(days))
	for _, d := range days {
		w.Days = append(w.Days, int(d))
	}
	return w, tz, err
}

// WindowQuery narrows the windows listed.
type WindowQuery struct {
	OrganizationID *uuid.UUID
	SiteID         *uuid.UUID
}

// Windows lists the maintenance windows the caller may see
// (`monitoring.view` at the site).
func (s *Service) Windows(ctx context.Context, c access.Caller, q WindowQuery) ([]Window, error) {
	out := []Window{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+windowCols+` FROM site_maintenance_windows w JOIN sites s ON s.id = w.site_id
			WHERE ($1::uuid IS NULL OR w.organization_id = $1) AND ($2::uuid IS NULL OR w.site_id = $2)
			ORDER BY lower(s.name), lower(w.name), w.id LIMIT $3`, q.OrganizationID, q.SiteID, maxWin)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			w, _, err := scanWindow(rows)
			if err != nil {
				return err
			}
			if !c.Can(rbac.PermMonitorView, rbac.Site(w.OrganizationID, w.SiteID)) {
				continue
			}
			w.CanEdit = c.Can(rbac.PermMonitorManage, rbac.Site(w.OrganizationID, w.SiteID))
			out = append(out, w)
		}
		return rows.Err()
	})
	return out, err
}

func (s *Service) siteOf(ctx context.Context, c access.Caller, site uuid.UUID) (org uuid.UUID, tz string, err error) {
	err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT organization_id, timezone FROM sites WHERE id = $1`, site).Scan(&org, &tz)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", apperr.NotFound()
	}
	return org, tz, err
}

// CreateWindow makes a window at a site (`monitoring.manage` there).
func (s *Service) CreateWindow(ctx context.Context, c access.Caller, site uuid.UUID, in Window) (Window, error) {
	org, tz, err := s.siteOf(ctx, c, site)
	if err != nil {
		return Window{}, err
	}
	if !c.Can(rbac.PermMonitorManage, rbac.Site(org, site)) {
		return Window{}, apperr.NotFound()
	}
	in, err = s.cleanWindow(in, siteLocation(tz))
	if err != nil {
		return Window{}, err
	}
	id := uuid.New()
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM site_maintenance_windows WHERE site_id = $1`, site).Scan(&n); err != nil {
			return err
		}
		if n >= 50 {
			return apperr.Conflict("window_limit", "A site can have at most 50 maintenance windows.")
		}
		if _, err := tx.Exec(ctx, `INSERT INTO site_maintenance_windows (id, organization_id, site_id, name, kind, days, start_local, starts_local, length_minutes, enabled, created_by)
			VALUES ($1, $2, $3, $4, $5, $6::smallint[], NULLIF($7, '')::time, NULLIF($8, '')::timestamp, $9, $10, $11)`,
			id, org, site, in.Name, in.Kind, in.Days, in.Start, in.StartsAt, in.LengthMinutes, in.Enabled, actorID(c.Actor)); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: ActionWindowCreate, OrganizationID: org, SiteID: site, TargetType: "maintenance_window",
			TargetID: id.String(), Outcome: audit.Success, Details: map[string]any{"name": in.Name, "kind": in.Kind, "lengthMinutes": in.LengthMinutes}})
	})
	if err != nil {
		return Window{}, err
	}
	return s.window(ctx, c, id)
}

func (s *Service) window(ctx context.Context, c access.Caller, id uuid.UUID) (Window, error) {
	var w Window
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var err error
		w, _, err = scanWindow(tx.QueryRow(ctx, `SELECT `+windowCols+` FROM site_maintenance_windows w JOIN sites s ON s.id = w.site_id WHERE w.id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Window{}, apperr.NotFound()
	}
	w.CanEdit = c.Can(rbac.PermMonitorManage, rbac.Site(w.OrganizationID, w.SiteID))
	return w, err
}

// UpdateWindow replaces a window's settings.
func (s *Service) UpdateWindow(ctx context.Context, c access.Caller, id uuid.UUID, in Window) (Window, error) {
	cur, err := s.window(ctx, c, id)
	if err != nil {
		return Window{}, err
	}
	if !cur.CanEdit {
		return Window{}, apperr.NotFound()
	}
	_, tz, err := s.siteOf(ctx, c, cur.SiteID)
	if err != nil {
		return Window{}, err
	}
	in, err = s.cleanWindow(in, siteLocation(tz))
	if err != nil {
		return Window{}, err
	}
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE site_maintenance_windows SET name = $2, kind = $3, days = $4::smallint[], start_local = NULLIF($5, '')::time,
				starts_local = NULLIF($6, '')::timestamp, length_minutes = $7, enabled = $8 WHERE id = $1`,
			id, in.Name, in.Kind, in.Days, in.Start, in.StartsAt, in.LengthMinutes, in.Enabled); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: ActionWindowUpdate, OrganizationID: cur.OrganizationID, SiteID: cur.SiteID,
			TargetType: "maintenance_window", TargetID: id.String(), Outcome: audit.Success,
			Details: map[string]any{"name": in.Name, "kind": in.Kind, "lengthMinutes": in.LengthMinutes, "enabled": in.Enabled}})
	})
	if err != nil {
		return Window{}, err
	}
	return s.window(ctx, c, id)
}

// DeleteWindow deletes a window.
func (s *Service) DeleteWindow(ctx context.Context, c access.Caller, id uuid.UUID) error {
	cur, err := s.window(ctx, c, id)
	if err != nil {
		return err
	}
	if !cur.CanEdit {
		return apperr.NotFound()
	}
	return s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM site_maintenance_windows WHERE id = $1`, id); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: ActionWindowDelete, OrganizationID: cur.OrganizationID, SiteID: cur.SiteID,
			TargetType: "maintenance_window", TargetID: id.String(), Outcome: audit.Success, Details: map[string]any{"name": cur.Name}})
	})
}

// WallInstant is the instant a wall clock reads in loc, with ADR-0053's
// daylight-saving rules: a time in a skipped hour is the moment the gap ends,
// one in a repeated hour is its first occurrence. Scheduled tasks use it.
func WallInstant(loc *time.Location, y int, mo time.Month, d, h, mi int) time.Time {
	return wallInstant(loc, y, mo, d, h, mi)
}
