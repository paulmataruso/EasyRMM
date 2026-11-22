package hardware

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Reading is a disk's latest reading, whatever it found.
type Reading struct {
	// State is the reading's own: its level, or the disk as a whole when it
	// was not read.
	State      string    `json:"state"`
	Reason     string    `json:"reason"`
	Detail     string    `json:"detail"`
	ReadAt     time.Time `json:"readAt"`
	ReceivedAt time.Time `json:"receivedAt"`
}

// Disk is one disk as the console shows it (ADR-0065, "The five states").
type Disk struct {
	// Key is the disk's identity; Unstable when it comes from the disk's
	// name, for want of a serial.
	Key      string `json:"key"`
	Unstable bool   `json:"unstable"`
	Name     string `json:"name"`
	Model    string `json:"model"`
	Serial   string `json:"serial"`
	// State is what the console shows: healthy, warning, failing,
	// unknown, unsupported or unavailable; Reason says why.
	State  string `json:"state"`
	Reason string `json:"reason"`
	// Detail is in words what made the disk warning or failing.
	Detail string `json:"detail"`
	// Latest is the latest reading. For a failing or warning disk it may
	// be newer than JudgedAt and say why it could not tell.
	Latest Reading `json:"latest"`
	// JudgedLevel and JudgedAt are the last reading that read the drive's
	// verdict, nil before one did.
	JudgedLevel *string    `json:"judgedLevel"`
	JudgedAt    *time.Time `json:"judgedAt"`
	// Since counts the readings since JudgedAt that could not tell.
	Since int `json:"since"`
	// MissingSince is when a report first left the disk out.
	MissingSince *time.Time `json:"missingSince"`
	// Protocol, Route, Facts and Attributes are from the latest reading that
	// read the disk, at FactsAt.
	Protocol   string          `json:"protocol"`
	Route      string          `json:"route"`
	FactsAt    *time.Time      `json:"factsAt"`
	Facts      []FactView      `json:"facts"`
	Attributes []AttributeView `json:"attributes"`
}

// show derives the shown reason from the shown state.
func (d *Disk) show(state, judgedReason, judgedDetail string) {
	d.State = state
	switch {
	case d.MissingSince != nil:
		d.Reason = agentproto.ReasonMissing
	case state == StateUnsupported || state == StateUnavailable:
		d.Reason, d.Detail = d.Latest.Reason, d.Latest.Detail
	case state == StateFailing || state == StateWarning:
		d.Reason, d.Detail = judgedReason, judgedDetail
	case state == StateHealthy:
	case d.JudgedLevel != nil && *d.JudgedLevel == StateHealthy:
		d.Reason = agentproto.ReasonStale
	default:
		d.Reason, d.Detail = d.Latest.Reason, d.Latest.Detail
	}
}

const diskColumns = `h.disk_key, h.unstable, h.name, h.model, h.serial,
	easyrmm_disk_state(h.missing_since, h.state, h.judged_level, h.judged_at),
	h.state, h.reason, h.detail, h.read_at, h.received_at, h.judged_level, h.judged_reason, h.judged_detail, h.judged_at,
	(SELECT count(*) FROM device_disk_health_samples s WHERE s.device_id = h.device_id AND s.disk_key = h.disk_key
		AND NOT s.daily AND NOT s.judged AND s.at > h.judged_at),
	h.missing_since, h.protocol, h.route, h.facts_at, h.facts, h.attributes`

func scanDisk(row pgx.Row) (*Disk, error) {
	var (
		d                       Disk
		state, jReason, jDetail string
	)
	err := row.Scan(&d.Key, &d.Unstable, &d.Name, &d.Model, &d.Serial, &state,
		&d.Latest.State, &d.Latest.Reason, &d.Latest.Detail, &d.Latest.ReadAt, &d.Latest.ReceivedAt,
		&d.JudgedLevel, &jReason, &jDetail, &d.JudgedAt, &d.Since,
		&d.MissingSince, &d.Protocol, &d.Route, &d.FactsAt, &d.Facts, &d.Attributes)
	if err != nil {
		return nil, err
	}
	d.show(state, jReason, jDetail)
	return &d, nil
}

// Disks lists a device's disks for a caller who may view the device:
// present ones first, then missing ones, each by name. An empty list means
// the device's agent has reported none.
func (s *Service) Disks(ctx context.Context, c access.Caller, deviceID uuid.UUID) ([]*Disk, error) {
	if _, err := devices.Lookup(ctx, s.db, c, deviceID); err != nil {
		return nil, err
	}
	out := []*Disk{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+diskColumns+` FROM device_disk_health h WHERE h.device_id = $1
			ORDER BY h.missing_since IS NOT NULL, h.name, h.disk_key`, deviceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			d, err := scanDisk(rows)
			if err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}

// Day is a disk's history on one UTC day.
type Day struct {
	Day time.Time `json:"day"`
	// State is the day's worst.
	State string `json:"state"`
	// Temperature is the day's highest; the others are the day's last.
	Temperature   *int64 `json:"temperature"`
	Wear          *int64 `json:"wear"`
	Reallocated   *int64 `json:"reallocatedSectors"`
	MediaErrors   *int64 `json:"mediaErrors"`
	Pending       *int64 `json:"pendingSectors"`
	Uncorrectable *int64 `json:"uncorrectableSectors"`
	DriveErrors   *int64 `json:"driveErrors"`
	PowerOnHours  *int64 `json:"powerOnHours"`
}

// HistoryDays is how far back a disk's panel looks.
const HistoryDays = 30

// DiskAlert is an open alert on a disk.
type DiskAlert struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	CheckName string    `json:"checkName"`
	Severity  string    `json:"severity"`
	Status    string    `json:"status"`
	Detail    string    `json:"detail"`
	OpenedAt  time.Time `json:"openedAt"`
}

// DiskDetail is a disk's panel: the disk, its last 30 days and its open
// alerts (nil when the caller may not view alerts there).
type DiskDetail struct {
	*Disk
	History []Day       `json:"history"`
	Alerts  []DiskAlert `json:"alerts"`
}

// Disk returns one disk's panel for a caller who may view the device.
func (s *Service) Disk(ctx context.Context, c access.Caller, deviceID uuid.UUID, key string) (*DiskDetail, error) {
	dev, err := devices.Lookup(ctx, s.db, c, deviceID)
	if err != nil {
		return nil, err
	}
	out := &DiskDetail{History: []Day{}}
	err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		d, err := scanDisk(tx.QueryRow(ctx, `SELECT `+diskColumns+` FROM device_disk_health h WHERE h.device_id = $1 AND h.disk_key = $2`, deviceID, key))
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound()
		}
		if err != nil {
			return err
		}
		out.Disk = d
		rows, err := tx.Query(ctx, `SELECT date_trunc('day', at, 'UTC') AS day,
				(array_agg(state ORDER BY array_position($3::text[], state)))[1], max(temperature),
				(array_agg(wear ORDER BY at DESC) FILTER (WHERE wear IS NOT NULL))[1],
				(array_agg(reallocated ORDER BY at DESC) FILTER (WHERE reallocated IS NOT NULL))[1],
				(array_agg(media_errors ORDER BY at DESC) FILTER (WHERE media_errors IS NOT NULL))[1],
				(array_agg(pending ORDER BY at DESC) FILTER (WHERE pending IS NOT NULL))[1],
				(array_agg(uncorrectable ORDER BY at DESC) FILTER (WHERE uncorrectable IS NOT NULL))[1],
				(array_agg(drive_errors ORDER BY at DESC) FILTER (WHERE drive_errors IS NOT NULL))[1],
				(array_agg(power_on_hours ORDER BY at DESC) FILTER (WHERE power_on_hours IS NOT NULL))[1]
			FROM device_disk_health_samples
			WHERE device_id = $1 AND disk_key = $2 AND at >= date_trunc('day', now(), 'UTC') - make_interval(days => $4)
			GROUP BY 1 ORDER BY 1 DESC`, deviceID, key, worstFirst, HistoryDays-1)
		if err != nil {
			return err
		}
		if out.History, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Day, error) {
			var x Day
			err := row.Scan(&x.Day, &x.State, &x.Temperature, &x.Wear, &x.Reallocated, &x.MediaErrors, &x.Pending, &x.Uncorrectable,
				&x.DriveErrors, &x.PowerOnHours)
			return x, err
		}); err != nil {
			return err
		}
		if !c.Can(rbac.PermAlertView, rbac.Site(dev.OrganizationID, dev.SiteID)) {
			return nil
		}
		rows, err = tx.Query(ctx, `SELECT id, name, coalesce(check_name, ''), severity, status, detail, opened_at FROM alerts
			WHERE device_id = $1 AND subject = $2 AND status <> 'resolved' ORDER BY seq DESC`, deviceID, key)
		if err != nil {
			return err
		}
		out.Alerts, err = pgx.CollectRows(rows, pgx.RowToStructByPos[DiskAlert])
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
