package easypatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// Link states of a device.
const (
	LinkLinked   = "linked"
	LinkUnlinked = "unlinked"
	LinkPending  = "pending"
	// LinkNone: the device has no EasyPatch agent (no row).
	LinkNone = "none"
)

const (
	// recheckLinked is how long a link holds before it is checked again.
	recheckLinked = 6 * time.Hour
	// recheckUnlinked is how soon a refused device is tried again: an
	// administrator may have fixed the reason.
	recheckUnlinked = 15 * time.Minute
	// maxChecks bounds the EasyPatch calls of one pass.
	maxChecks = 200
)

// ---------------------------------------------------------------- organizations

// OrganizationLink is an EasyRMM organization patched with an EasyPatch one.
type OrganizationLink struct {
	OrganizationID   uuid.UUID    `json:"organizationId"`
	OrganizationName string       `json:"organizationName"`
	EasyPatchID      uuid.UUID    `json:"easyPatchId"`
	EasyPatchName    string       `json:"easyPatchName"`
	LinkedAt         time.Time    `json:"linkedAt"`
	LinkedBy         string       `json:"linkedBy,omitempty"`
	Devices          DeviceCounts `json:"devices"`
}

// DeviceCounts counts devices by link state.
type DeviceCounts struct {
	Linked   int `json:"linked"`
	Unlinked int `json:"unlinked"`
	Pending  int `json:"pending"`
}

// Organizations is what Settings shows: EasyPatch's organizations and the
// links.
type Organizations struct {
	EasyPatch []Organization     `json:"easyPatch"`
	Links     []OrganizationLink `json:"links"`
	// Error says why EasyPatch's organizations could not be read; the links
	// still show.
	Error string `json:"error,omitempty"`
}

var errNotConfigured = apperr.Conflict("easypatch_not_configured", "EasyPatch is not set up. A super administrator sets it up in Settings → EasyPatch.")

// Organizations lists EasyPatch's organizations and the links.
func (s *Service) Organizations(ctx context.Context) (Organizations, error) {
	r, c, err := s.conn(ctx)
	if err != nil {
		return Organizations{}, err
	}
	if r == nil {
		return Organizations{}, errNotConfigured
	}
	out := Organizations{EasyPatch: []Organization{}, Links: []OrganizationLink{}}
	if list, err := c.Organizations(ctx); err != nil {
		out.Error = err.Error()
		s.noteError(ctx, err)
	} else {
		out.EasyPatch = list
	}
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT l.organization_id, o.name, l.easypatch_id, l.easypatch_name, l.linked_at, u.email,
				count(*) FILTER (WHERE e.state = 'linked'), count(*) FILTER (WHERE e.state = 'unlinked'),
				count(*) FILTER (WHERE e.state = 'pending')
			FROM easypatch_organizations l JOIN organizations o ON o.id = l.organization_id
			LEFT JOIN users u ON u.id = l.linked_by
			LEFT JOIN devices d ON d.organization_id = l.organization_id
			LEFT JOIN easypatch_devices e ON e.device_id = d.id
			GROUP BY l.organization_id, o.name, l.easypatch_id, l.easypatch_name, l.linked_at, u.email
			ORDER BY o.name`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var l OrganizationLink
			var by *string
			if err := rows.Scan(&l.OrganizationID, &l.OrganizationName, &l.EasyPatchID, &l.EasyPatchName, &l.LinkedAt, &by,
				&l.Devices.Linked, &l.Devices.Unlinked, &l.Devices.Pending); err != nil {
				return err
			}
			if by != nil {
				l.LinkedBy = *by
			}
			out.Links = append(out.Links, l)
		}
		return rows.Err()
	})
	return out, err
}

// LinkOrganization patches an EasyRMM organization with an EasyPatch
// organization, replacing any earlier link. Its devices are checked again.
func (s *Service) LinkOrganization(ctx context.Context, actor audit.Actor, organizationID, easyPatchID uuid.UUID) error {
	r, c, err := s.conn(ctx)
	if err != nil {
		return err
	}
	if r == nil {
		return errNotConfigured
	}
	list, err := c.Organizations(ctx)
	if err != nil {
		return epError(err)
	}
	var ep *Organization
	for i := range list {
		if list[i].ID == easyPatchID {
			ep = &list[i]
		}
	}
	if ep == nil {
		return apperr.Invalid("easyPatchId", "EasyPatch has no such organization, or EasyRMM's token cannot see it")
	}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var name string
		if err := tx.QueryRow(ctx, `SELECT name FROM organizations WHERE id = $1`, organizationID).Scan(&name); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apperr.NotFound()
			}
			return err
		}
		var other string
		err := tx.QueryRow(ctx, `SELECT o.name FROM easypatch_organizations l JOIN organizations o ON o.id = l.organization_id
			WHERE l.easypatch_id = $1 AND l.organization_id <> $2`, easyPatchID, organizationID).Scan(&other)
		if err == nil {
			return apperr.Conflict("easypatch_organization_linked", fmt.Sprintf("%s in EasyPatch is already linked to %s.", ep.Name, other))
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var by *uuid.UUID
		if actor.ID != uuid.Nil {
			by = &actor.ID
		}
		if _, err := tx.Exec(ctx, `INSERT INTO easypatch_organizations (organization_id, easypatch_id, easypatch_name, linked_by)
			VALUES ($1, $2, $3, $4) ON CONFLICT (organization_id) DO UPDATE SET easypatch_id = $2, easypatch_name = $3, linked_at = now(),
			linked_by = $4`, organizationID, easyPatchID, cut(ep.Name, 200), by); err != nil {
			return err
		}
		if err := recheckOrganization(ctx, tx, organizationID); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: actor, Action: "easypatch.organization_link", OrganizationID: organizationID,
			TargetType: "organization", TargetID: organizationID.String(), Outcome: audit.Success,
			Details: map[string]any{"organization": name, "easyPatchId": easyPatchID.String(), "easyPatchName": ep.Name}})
	})
	if err == nil {
		s.fleet.clear()
	}
	return err
}

// UnlinkOrganization stops patching an organization from EasyRMM.
func (s *Service) UnlinkOrganization(ctx context.Context, actor audit.Actor, organizationID uuid.UUID) error {
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var epName, name string
		err := tx.QueryRow(ctx, `DELETE FROM easypatch_organizations l USING organizations o
			WHERE l.organization_id = $1 AND o.id = l.organization_id RETURNING l.easypatch_name, o.name`,
			organizationID).Scan(&epName, &name)
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound()
		} else if err != nil {
			return err
		}
		if err := recheckOrganization(ctx, tx, organizationID); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: actor, Action: "easypatch.organization_unlink", OrganizationID: organizationID,
			TargetType: "organization", TargetID: organizationID.String(), Outcome: audit.Success,
			Details: map[string]any{"organization": name, "easyPatchName": epName}})
	})
	if err == nil {
		s.fleet.clear()
	}
	return err
}

// recheckOrganization has the next pass check an organization's devices.
func recheckOrganization(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID) error {
	_, err := tx.Exec(ctx, `UPDATE easypatch_devices SET state = 'pending', reason = '', checked_at = NULL
		WHERE device_id IN (SELECT id FROM devices WHERE organization_id = $1)`, organizationID)
	return err
}

// DeviceLink is a device's link as Settings lists it.
type DeviceLink struct {
	DeviceID         uuid.UUID  `json:"deviceId"`
	DeviceName       string     `json:"deviceName"`
	OrganizationName string     `json:"organizationName"`
	State            string     `json:"state"`
	Reason           string     `json:"reason,omitempty"`
	EndpointID       *uuid.UUID `json:"endpointId,omitempty"`
	CheckedAt        *time.Time `json:"checkedAt,omitempty"`
}

// DeviceLinks lists the devices that are not linked, for Settings.
func (s *Service) DeviceLinks(ctx context.Context) ([]DeviceLink, error) {
	out := []DeviceLink{}
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT d.id, d.name, o.name, e.state, e.reason, e.endpoint_id, e.checked_at
			FROM easypatch_devices e JOIN devices d ON d.id = e.device_id JOIN organizations o ON o.id = d.organization_id
			WHERE e.state <> 'linked' ORDER BY e.state, o.name, d.name LIMIT 500`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var l DeviceLink
			if err := rows.Scan(&l.DeviceID, &l.DeviceName, &l.OrganizationName, &l.State, &l.Reason, &l.EndpointID, &l.CheckedAt); err != nil {
				return err
			}
			out = append(out, l)
		}
		return rows.Err()
	})
	return out, err
}

// ---------------------------------------------------------------- device links

type candidate struct {
	deviceID, organizationID uuid.UUID
	name, hostname, serial   string
	report                   *agentproto.EasyPatchAgent
	hasRow                   bool
	state, fingerprint       string
	endpointID               *uuid.UUID
	checkedAt, linkedAt      *time.Time
	easyPatchOrg             *uuid.UUID
	easyPatchOrgName         string
}

// due reports whether a candidate should be checked now.
func (c *candidate) due(now time.Time, reported *uuid.UUID) bool {
	switch {
	case !c.hasRow, c.state == LinkPending, c.checkedAt == nil:
		return true
	case !sameID(c.endpointID, reported), !strings.EqualFold(c.fingerprint, c.report.KeyFingerprint):
		return true
	case c.state == LinkLinked:
		return now.Sub(*c.checkedAt) >= recheckLinked
	default:
		return now.Sub(*c.checkedAt) >= recheckUnlinked
	}
}

func sameID(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// SyncLinks checks the devices whose EasyPatch report is new, changed or
// due, and forgets links of devices that no longer report an EasyPatch
// agent. It returns how many devices it checked.
func (s *Service) SyncLinks(ctx context.Context) (int, error) {
	r, c, err := s.conn(ctx)
	if err != nil || r == nil {
		return 0, err
	}
	var list []candidate
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT d.id, d.organization_id, d.name, d.hostname, coalesce(i.data->'system'->>'serial', ''),
				i.data->'easyPatch', e.device_id IS NOT NULL, coalesce(e.state, ''), coalesce(e.key_fingerprint, ''), e.endpoint_id,
				e.checked_at, e.linked_at, l.easypatch_id, coalesce(l.easypatch_name, '')
			FROM devices d
			LEFT JOIN device_inventory i ON i.device_id = d.id
			LEFT JOIN easypatch_devices e ON e.device_id = d.id
			LEFT JOIN easypatch_organizations l ON l.organization_id = d.organization_id
			WHERE i.data ? 'easyPatch' OR e.device_id IS NOT NULL`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var cd candidate
			var report []byte
			if err := rows.Scan(&cd.deviceID, &cd.organizationID, &cd.name, &cd.hostname, &cd.serial, &report, &cd.hasRow, &cd.state,
				&cd.fingerprint, &cd.endpointID, &cd.checkedAt, &cd.linkedAt, &cd.easyPatchOrg, &cd.easyPatchOrgName); err != nil {
				return err
			}
			if len(report) > 0 && string(report) != "null" {
				var rep agentproto.EasyPatchAgent
				if json.Unmarshal(report, &rep) == nil {
					cd.report = &rep
				}
			}
			list = append(list, cd)
		}
		return rows.Err()
	})
	if err != nil {
		return 0, err
	}
	now := s.now()
	checked := 0
	for i := range list {
		cd := &list[i]
		if cd.report == nil {
			if err := s.forget(ctx, cd.deviceID); err != nil {
				return checked, err
			}
			continue
		}
		reported := parseID(cd.report.EndpointID)
		if !cd.due(now, reported) {
			continue
		}
		if checked >= maxChecks {
			break
		}
		checked++
		state, reason, err := s.verify(ctx, c, r, cd, reported)
		if err != nil {
			// EasyPatch could not answer: keep what was known.
			s.noteError(ctx, err)
			continue
		}
		if err := s.saveLink(ctx, cd, reported, state, reason); err != nil {
			return checked, err
		}
	}
	if checked > 0 {
		s.fleet.clear()
	}
	return checked, nil
}

func parseID(s string) *uuid.UUID {
	id, err := uuid.Parse(s)
	if err != nil || id == uuid.Nil {
		return nil
	}
	return &id
}

// shortHost is the first label of a host name, lower case.
func shortHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.IndexByte(h, '.'); i > 0 {
		h = h[:i]
	}
	return h
}

// verify decides whether a device is the endpoint it reports. An error means
// EasyPatch could not answer.
func (s *Service) verify(ctx context.Context, c *Client, conn *connRow, cd *candidate, endpointID *uuid.UUID) (string, string, error) {
	rep := cd.report
	switch {
	case !strings.EqualFold(rep.Status, "Active"):
		status := rep.Status
		if status == "" {
			status = "Unknown"
		}
		if rep.Error != "" {
			return LinkUnlinked, cut(fmt.Sprintf("The EasyPatch agent could not report its status (%s): %s", status, rep.Error), 500), nil
		}
		return LinkUnlinked, fmt.Sprintf("The EasyPatch agent is not enrolled and active (its status is %s).", status), nil
	case endpointID == nil:
		return LinkUnlinked, "The EasyPatch agent did not report its endpoint id.", nil
	case !SameServer(rep.ServerURL, conn.url) && !SameServer(rep.ServerURL, conn.publicURL):
		return LinkUnlinked, cut(fmt.Sprintf("The EasyPatch agent is enrolled with %s, not with the EasyPatch server EasyRMM uses.", rep.ServerURL), 500), nil
	case cd.easyPatchOrg == nil:
		return LinkUnlinked, "The device's organization is not linked to an EasyPatch organization (Settings → EasyPatch).", nil
	}
	ep, err := c.Endpoint(ctx, *endpointID)
	switch {
	case IsStatus(err, http.StatusNotFound):
		return LinkUnlinked, fmt.Sprintf("EasyPatch has no endpoint %s, or EasyRMM's token cannot see it.", endpointID), nil
	case err != nil:
		return "", "", err
	case ep.Summary.OrganizationID != *cd.easyPatchOrg:
		return LinkUnlinked, cut(fmt.Sprintf("In EasyPatch the endpoint belongs to %s, not to %s, the organization linked to this device's.",
			ep.Summary.OrganizationName, cd.easyPatchOrgName), 500), nil
	case ep.Summary.Status != "Active":
		return LinkUnlinked, fmt.Sprintf("In EasyPatch the endpoint is %s.", strings.ToLower(ep.Summary.Status)), nil
	}
	if !holdsKey(ep.Credentials, rep.KeyFingerprint) {
		return LinkUnlinked, "The key fingerprint the device reported is not one of the EasyPatch endpoint's active credentials.", nil
	}
	host := cd.hostname
	if host == "" {
		host = cd.name
	}
	if shortHost(ep.Summary.Hostname) != shortHost(host) {
		return LinkUnlinked, cut(fmt.Sprintf("Host names differ: EasyPatch has %q, EasyRMM has %q.", ep.Summary.Hostname, host), 500), nil
	}
	a, b := strings.TrimSpace(ep.SerialNumber), strings.TrimSpace(cd.serial)
	if a != "" && b != "" && !strings.EqualFold(a, b) {
		return LinkUnlinked, cut(fmt.Sprintf("Serial numbers differ: EasyPatch has %q, EasyRMM has %q.", a, b), 500), nil
	}
	return LinkLinked, "", nil
}

func holdsKey(creds []Credential, fingerprint string) bool {
	if strings.TrimSpace(fingerprint) == "" {
		return false
	}
	for _, c := range creds {
		if c.RevokedAt == nil && strings.EqualFold(c.KeyFingerprint, fingerprint) {
			return true
		}
	}
	return false
}

// saveLink records a check. A second device claiming a linked endpoint is
// refused.
func (s *Service) saveLink(ctx context.Context, cd *candidate, endpointID *uuid.UUID, state, reason string) error {
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if state == LinkLinked {
			var other string
			err := tx.QueryRow(ctx, `SELECT d.name FROM easypatch_devices e JOIN devices d ON d.id = e.device_id
				WHERE e.endpoint_id = $1 AND e.state = 'linked' AND e.device_id <> $2`, endpointID, cd.deviceID).Scan(&other)
			if err == nil {
				state, reason = LinkUnlinked, cut(fmt.Sprintf("%s is already linked to this EasyPatch endpoint.", other), 500)
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		_, err := tx.Exec(ctx, `INSERT INTO easypatch_devices (device_id, endpoint_id, key_fingerprint, state, reason, checked_at, linked_at)
			VALUES ($1, $2, $3, $4, $5, now(), CASE WHEN $4 = 'linked' THEN now() END)
			ON CONFLICT (device_id) DO UPDATE SET endpoint_id = $2, key_fingerprint = $3, state = $4, reason = $5, checked_at = now(),
				linked_at = CASE WHEN $4 <> 'linked' THEN NULL
					WHEN easypatch_devices.state = 'linked' AND easypatch_devices.endpoint_id = $2 THEN easypatch_devices.linked_at
					ELSE now() END`,
			cd.deviceID, endpointID, cut(cd.report.KeyFingerprint, 128), state, reason)
		return err
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		// Another device was linked to the endpoint meanwhile; the next
		// check of this one says so.
		return nil
	}
	return err
}

func (s *Service) forget(ctx context.Context, deviceID uuid.UUID) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM easypatch_devices WHERE device_id = $1`, deviceID)
		return err
	})
}

// Run checks device links every minute, and the server every ten minutes,
// until ctx ends.
func (s *Service) Run(ctx context.Context) {
	links := time.NewTicker(time.Minute)
	defer links.Stop()
	server := time.NewTicker(10 * time.Minute)
	defer server.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-links.C:
			if _, err := s.SyncLinks(ctx); err != nil && ctx.Err() == nil {
				s.log.Warn("easypatch: device links", "err", err)
			}
		case <-server.C:
			if _, err := s.CheckConnection(ctx); err != nil && !errors.Is(err, apperr.ErrNotFound) && ctx.Err() == nil {
				s.log.Warn("easypatch: server check", "err", err)
			}
		}
	}
}
