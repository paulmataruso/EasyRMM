package easypatch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

const (
	// fleetTTL is how long an organization's endpoint list is reused.
	fleetTTL = 30 * time.Second
	// maxFleetPages bounds the endpoint pages read per organization.
	maxFleetPages = 50
	// maxFleetDevices bounds the devices of one fleet view.
	maxFleetDevices = 5000
	// maxScheduleAhead is how far ahead EasyPatch accepts a scheduled job.
	maxScheduleAhead = 31 * 24 * time.Hour
)

// epError turns a failed call to the engine into what the console shows.
// The engine refusing EasyRMM's statement is EasyRMM's problem, never the
// user's: it is shown as the engine being unavailable,
// not as a 401 or 403 the console would take for a lost session.
func epError(err error) error {
	var e *Error
	if !errors.As(err, &e) {
		return err
	}
	if e.Status == http.StatusBadRequest && len(e.Fields) > 0 {
		f := apperr.Fields{}
		for name, msg := range e.Fields {
			f.Add(name, msg)
		}
		return f.Err()
	}
	switch {
	case e.Status == 0 || e.Status >= 500:
		return apperr.Unavailable("patching_unavailable", e.Detail)
	case e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden:
		return apperr.Unavailable("patching_unavailable", "The patching engine refused EasyRMM's call: "+e.Detail)
	case e.Status == http.StatusNotFound:
		return apperr.NotFound()
	}
	code := e.Code
	if code == "" {
		code = "easypatch_refused"
	}
	return apperr.Conflict(cut(code, 64), "The patching engine refused: "+e.Detail)
}

// message is what a user reads of an error.
func message(err error) string {
	var ae *apperr.Error
	if errors.As(err, &ae) {
		return ae.Message
	}
	return err.Error()
}

// ---------------------------------------------------------------- fleet cache

type fleetEntry struct {
	at        time.Time
	endpoints map[uuid.UUID]Endpoint
}

// fleetCache keeps each EasyPatch organization's endpoints for fleetTTL.
type fleetCache struct {
	mu      sync.Mutex
	entries map[uuid.UUID]fleetEntry
}

func (f *fleetCache) clear() {
	f.mu.Lock()
	clear(f.entries)
	f.mu.Unlock()
}

func (s *Service) endpoints(ctx context.Context, c *Client, organizationID uuid.UUID) (map[uuid.UUID]Endpoint, error) {
	s.fleet.mu.Lock()
	defer s.fleet.mu.Unlock()
	if e, ok := s.fleet.entries[organizationID]; ok && s.now().Sub(e.at) < fleetTTL {
		return e.endpoints, nil
	}
	out := map[uuid.UUID]Endpoint{}
	for page := 1; page <= maxFleetPages; page++ {
		p, err := c.Endpoints(ctx, organizationID, page)
		if err != nil {
			return nil, err
		}
		for _, e := range p.Items {
			out[e.ID] = e
		}
		if len(p.Items) == 0 || page*PageSize >= p.TotalCount {
			break
		}
	}
	s.fleet.entries[organizationID] = fleetEntry{at: s.now(), endpoints: out}
	return out, nil
}

// ---------------------------------------------------------------- status

// Status is what the console needs before showing patching.
type Status struct {
	Configured bool `json:"configured"`
}

// Status says whether patching is available, to anyone who may see it
// somewhere.
func (s *Service) Status(ctx context.Context, c access.Caller) (Status, error) {
	if !c.CanAnywhere(rbac.PermPatchView) {
		return Status{}, apperr.Forbidden()
	}
	conn, err := s.Connection(ctx)
	if err != nil {
		return Status{}, err
	}
	return Status{Configured: conn.Configured}, nil
}

// ---------------------------------------------------------------- devices

type deviceRow struct {
	id, organizationID, siteID uuid.UUID
	groupID                    *uuid.UUID
	name, organizationName     string
	siteName, platform         string
	state, reason              string
	endpointID                 *uuid.UUID
	checkedAt                  *time.Time
	easyPatchOrg               *uuid.UUID
	install                    *AgentInstall
	stopped                    *PatchingStop
	removal                    *AgentRemoval
}

func (d *deviceRow) resource() rbac.Resource { return rbac.Site(d.organizationID, d.siteID) }

const deviceSelect = `SELECT d.id, d.organization_id, d.site_id, d.device_group_id, d.name, o.name, s.name, d.platform,
		coalesce(e.state, 'none'), coalesce(e.reason, ''), e.endpoint_id, e.checked_at, l.easypatch_id, ` + installColumns + `,
		po.opted_out_at, pu.email, rm.reason, rm.state, rm.requested_at, rm.last_error
	FROM devices d JOIN organizations o ON o.id = d.organization_id JOIN sites s ON s.id = d.site_id
	LEFT JOIN easypatch_devices e ON e.device_id = d.id
	LEFT JOIN easypatch_organizations l ON l.organization_id = d.organization_id
	LEFT JOIN easypatch_opt_outs po ON po.device_id = d.id LEFT JOIN users pu ON pu.id = po.opted_out_by
	LEFT JOIN LATERAL (SELECT r.reason, r.state, r.requested_at, r.last_error FROM easypatch_removals r WHERE r.device_id = d.id
		ORDER BY r.requested_at DESC LIMIT 1) rm ON true` + installJoin

// PatchingStop says patching is stopped for a device: EasyRMM removed its
// EasyPatch agent, or is removing it, and installs none (ADR-0040).
type PatchingStop struct {
	At time.Time `json:"at"`
	By string    `json:"by,omitempty"`
}

// AgentRemoval is EasyRMM removing a device's EasyPatch agent.
type AgentRemoval struct {
	// Reason is deleted (its device, or the endpoint, was removed),
	// opted_out (patching stopped) or moved (to another organization).
	Reason string `json:"reason"`
	// State is pending (not sent yet) or uninstalling.
	State       string    `json:"state"`
	RequestedAt time.Time `json:"requestedAt"`
	Error       string    `json:"error,omitempty"`
}

func scanDevice(row pgx.Row) (deviceRow, error) {
	var d deviceRow
	var x installScan
	var stopAt, rmAt *time.Time
	var stopBy, rmReason, rmState, rmError *string
	err := row.Scan(append(append([]any{&d.id, &d.organizationID, &d.siteID, &d.groupID, &d.name, &d.organizationName, &d.siteName, &d.platform,
		&d.state, &d.reason, &d.endpointID, &d.checkedAt, &d.easyPatchOrg}, x.dest()...),
		&stopAt, &stopBy, &rmReason, &rmState, &rmAt, &rmError)...)
	d.install = x.view()
	if stopAt != nil {
		d.stopped = &PatchingStop{At: *stopAt}
		if stopBy != nil {
			d.stopped.By = *stopBy
		}
	}
	if rmReason != nil {
		d.removal = &AgentRemoval{Reason: *rmReason, State: *rmState, RequestedAt: *rmAt, Error: *rmError}
	}
	return d, err
}

// device reads a device the caller may see patching of.
func (s *Service) device(ctx context.Context, c access.Caller, id uuid.UUID, perm rbac.Permission) (deviceRow, error) {
	var d deviceRow
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) (err error) {
		d, err = scanDevice(tx.QueryRow(ctx, deviceSelect+` WHERE d.id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return d, apperr.NotFound()
	}
	if err != nil {
		return d, err
	}
	if !c.Can(rbac.PermDeviceView, d.resource()) || !c.Can(rbac.PermPatchView, d.resource()) {
		return d, apperr.NotFound()
	}
	if perm != rbac.PermPatchView && !c.Can(perm, d.resource()) {
		return d, apperr.Forbidden()
	}
	return d, nil
}

func notLinked(d deviceRow) error {
	switch d.state {
	case LinkLinked:
		return nil
	case LinkPending:
		return apperr.Conflict("easypatch_link_pending", "EasyRMM is checking this device's EasyPatch agent; try again in a minute.")
	case LinkUnlinked:
		return apperr.Conflict("easypatch_not_linked", d.reason)
	}
	return apperr.Conflict("easypatch_no_agent", "This device has no EasyPatch agent, or its EasyRMM agent has not reported it yet.")
}

// FleetQuery narrows the patching list.
type FleetQuery struct {
	OrganizationID, SiteID, GroupID uuid.UUID
	// Compliance is an EasyPatch compliance status, or "unlinked" for
	// devices that are not linked.
	Compliance string
	Search     string
}

// Compliance statuses EasyPatch reports.
var complianceStatuses = []string{"Compliant", "MissingUpdates", "FailedUpdates", "RebootRequired", "ScanStale", "NeverScanned"}

// FleetDevice is one row of the patching list.
type FleetDevice struct {
	DeviceID         uuid.UUID  `json:"deviceId"`
	Name             string     `json:"name"`
	OrganizationID   uuid.UUID  `json:"organizationId"`
	OrganizationName string     `json:"organizationName"`
	SiteID           uuid.UUID  `json:"siteId"`
	SiteName         string     `json:"siteName"`
	Platform         string     `json:"platform"`
	Link             string     `json:"link"`
	Reason           string     `json:"reason,omitempty"`
	CanManage        bool       `json:"canManage"`
	Endpoint         *Endpoint  `json:"endpoint,omitempty"`
	CheckedAt        *time.Time `json:"checkedAt,omitempty"`
	// Install is the device's EasyPatch agent install (ADR-0031), when one
	// was asked for.
	Install *AgentInstall `json:"install,omitempty"`
	// Stopped says patching is stopped for the device; Removal, that
	// EasyRMM is removing its EasyPatch agent.
	Stopped *PatchingStop `json:"stopped,omitempty"`
	Removal *AgentRemoval `json:"removal,omitempty"`
}

// UnmatchedEndpoint is an EasyPatch endpoint in a linked organization that
// no EasyRMM device is linked to, such as one enrolled before EasyRMM's agent
// was on its machine.
type UnmatchedEndpoint struct {
	Endpoint
	// OrganizationID and OrganizationName are EasyRMM's.
	OrganizationID   uuid.UUID `json:"organizationId"`
	OrganizationName string    `json:"organizationName"`
	// CanRemove says the caller may remove the endpoint (ADR-0050).
	CanRemove bool `json:"canRemove"`
	// Removal is its removal under way.
	Removal *AgentRemoval `json:"removal,omitempty"`
}

// maxUnmatched is how many unmatched endpoints the patching list holds.
const maxUnmatched = 500

// Fleet is the patching list.
type Fleet struct {
	Devices []FleetDevice `json:"devices"`
	// Unmatched lists, for organizations the caller sees whole, endpoints
	// with no EasyRMM device; only without site, group, status or name
	// filters.
	Unmatched []UnmatchedEndpoint `json:"unmatched"`
	// Truncated says there were more devices than the list holds.
	Truncated bool `json:"truncated"`
	// Errors says which EasyPatch organizations could not be read.
	Errors []string `json:"errors"`
}

// Fleet lists the devices of linked organizations, and every device with an
// EasyPatch agent, with what EasyPatch says about them.
func (s *Service) Fleet(ctx context.Context, c access.Caller, q FleetQuery) (Fleet, error) {
	if !c.CanAnywhere(rbac.PermPatchView) {
		return Fleet{}, apperr.Forbidden()
	}
	if q.Compliance != "" && q.Compliance != LinkUnlinked && !slices.Contains(complianceStatuses, q.Compliance) {
		return Fleet{}, apperr.Invalid("compliance", "Choose a compliance status.")
	}
	if len(q.Search) > 200 {
		return Fleet{}, apperr.Invalid("q", "Search for at most 200 characters.")
	}
	r, cl, err := s.conn(ctx)
	if err != nil {
		return Fleet{}, err
	}
	if r == nil {
		return Fleet{}, errNotConfigured
	}
	out := Fleet{Devices: []FleetDevice{}, Unmatched: []UnmatchedEndpoint{}, Errors: []string{}}
	var rows []deviceRow
	err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		list, err := tx.Query(ctx, deviceSelect+`
			WHERE (l.organization_id IS NOT NULL OR e.device_id IS NOT NULL)
			  AND ($1::uuid IS NULL OR d.organization_id = $1) AND ($2::uuid IS NULL OR d.site_id = $2)
			  AND ($3::uuid IS NULL OR d.device_group_id = $3)
			  AND ($4 = '' OR d.name ILIKE $4 OR d.hostname ILIKE $4)
			ORDER BY o.name, s.name, d.name, d.id`,
			nullID(q.OrganizationID), nullID(q.SiteID), nullID(q.GroupID), likePattern(q.Search))
		if err != nil {
			return err
		}
		for list.Next() {
			d, err := scanDevice(list)
			if err != nil {
				return err
			}
			if c.Can(rbac.PermDeviceView, d.resource()) && c.Can(rbac.PermPatchView, d.resource()) {
				rows = append(rows, d)
			}
		}
		return list.Err()
	})
	if err != nil {
		return Fleet{}, err
	}
	fetched := map[uuid.UUID]map[uuid.UUID]Endpoint{}
	for _, d := range rows {
		if d.state != LinkLinked || d.easyPatchOrg == nil {
			continue
		}
		if _, ok := fetched[*d.easyPatchOrg]; ok {
			continue
		}
		eps, err := s.endpoints(s.as(ctx, c, RoleReadOnly, *d.easyPatchOrg), cl, *d.easyPatchOrg)
		if err != nil {
			s.noteError(err)
			out.Errors = append(out.Errors, fmt.Sprintf("%s: %s", d.organizationName, message(epError(err))))
		}
		fetched[*d.easyPatchOrg] = eps
	}
	for _, d := range rows {
		f := FleetDevice{DeviceID: d.id, Name: d.name, OrganizationID: d.organizationID, OrganizationName: d.organizationName,
			SiteID: d.siteID, SiteName: d.siteName, Platform: d.platform, Link: d.state, Reason: d.reason, CheckedAt: d.checkedAt,
			CanManage: c.Can(rbac.PermPatchManage, d.resource()), Install: d.install, Stopped: d.stopped, Removal: d.removal}
		if d.state == LinkLinked && d.easyPatchOrg != nil && d.endpointID != nil {
			if e, ok := fetched[*d.easyPatchOrg][*d.endpointID]; ok {
				f.Endpoint = &e
			} else if fetched[*d.easyPatchOrg] != nil {
				f.Link, f.Reason = LinkUnlinked, "The patching engine no longer lists this endpoint as active."
			}
		}
		switch {
		case q.Compliance == LinkUnlinked && f.Link == LinkLinked:
			continue
		case q.Compliance != "" && q.Compliance != LinkUnlinked && (f.Endpoint == nil || f.Endpoint.ComplianceStatus != q.Compliance):
			continue
		}
		if len(out.Devices) == maxFleetDevices {
			out.Truncated = true
			break
		}
		out.Devices = append(out.Devices, f)
	}
	if q.SiteID != uuid.Nil || q.GroupID != uuid.Nil || q.Compliance != "" || q.Search != "" {
		return out, nil
	}
	return out, s.unmatched(ctx, c, cl, q.OrganizationID, fetched, &out)
}

// unmatched adds the endpoints of organizations the caller sees whole that no
// device is linked to.
func (s *Service) unmatched(ctx context.Context, c access.Caller, cl *Client, organizationID uuid.UUID, fetched map[uuid.UUID]map[uuid.UUID]Endpoint,
	out *Fleet) error {
	linked, err := s.linkedOrgs(ctx, c)
	if err != nil {
		return err
	}
	var candidates []uuid.UUID
	for ep, o := range linked {
		if (organizationID == uuid.Nil || o.id == organizationID) && c.Can(rbac.PermPatchView, rbac.Org(o.id)) {
			candidates = append(candidates, ep)
		}
	}
	slices.SortFunc(candidates, func(a, b uuid.UUID) int { return strings.Compare(linked[a].name, linked[b].name) })
	var ids []uuid.UUID
	for _, ep := range candidates {
		if _, ok := fetched[ep]; !ok {
			eps, err := s.endpoints(s.as(ctx, c, RoleReadOnly, ep), cl, ep)
			if err != nil {
				s.noteError(err)
				out.Errors = append(out.Errors, fmt.Sprintf("%s: %s", linked[ep].name, message(epError(err))))
			}
			fetched[ep] = eps
		}
		for id := range fetched[ep] {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	matched := map[uuid.UUID]bool{}
	var removals map[uuid.UUID]*AgentRemoval
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT endpoint_id FROM easypatch_devices WHERE endpoint_id = ANY($1)`, ids)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			matched[id] = true
		}
		if err := rows.Err(); err != nil {
			return err
		}
		removals, err = endpointRemovals(ctx, tx, ids)
		return err
	})
	if err != nil {
		return err
	}
	for _, ep := range candidates {
		var list []UnmatchedEndpoint
		for id, e := range fetched[ep] {
			if !matched[id] {
				list = append(list, UnmatchedEndpoint{Endpoint: e, OrganizationID: linked[ep].id, OrganizationName: linked[ep].name,
					CanRemove: c.Can(rbac.PermDeviceRetire, rbac.Org(linked[ep].id)), Removal: removals[id]})
			}
		}
		slices.SortFunc(list, func(a, b UnmatchedEndpoint) int { return strings.Compare(a.Hostname, b.Hostname) })
		for _, u := range list {
			if len(out.Unmatched) == maxUnmatched {
				out.Truncated = true
				return nil
			}
			out.Unmatched = append(out.Unmatched, u)
		}
	}
	return nil
}

// orgOf is the EasyPatch organization of a linked device, for a statement.
func orgOf(d deviceRow) []uuid.UUID {
	if d.easyPatchOrg == nil {
		return nil
	}
	return []uuid.UUID{*d.easyPatchOrg}
}

// orgsOf is the EasyPatch organizations of linked devices.
func orgsOf(devices []deviceRow) []uuid.UUID {
	var out []uuid.UUID
	for _, d := range devices {
		out = append(out, orgOf(d)...)
	}
	return out
}

// patchOrganizations is the EasyPatch organizations linked to the
// organizations where c may see patching (only organizationID's, when it is
// set), by EasyPatch name.
func (s *Service) patchOrganizations(ctx context.Context, c access.Caller, organizationID uuid.UUID) ([]uuid.UUID, error) {
	var orgs []uuid.UUID
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT l.easypatch_id, l.organization_id FROM easypatch_organizations l
			WHERE $1::uuid IS NULL OR l.organization_id = $1 ORDER BY l.easypatch_name`, nullID(organizationID))
		if err != nil {
			return err
		}
		for rows.Next() {
			var ep, org uuid.UUID
			if err := rows.Scan(&ep, &org); err != nil {
				return err
			}
			if c.CanInOrg(rbac.PermPatchView, org) {
				orgs = append(orgs, ep)
			}
		}
		return rows.Err()
	})
	return orgs, err
}

func nullID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

func likePattern(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s) + "%"
}

// DevicePatching is a device's Patches tab.
type DevicePatching struct {
	DeviceID  uuid.UUID       `json:"deviceId"`
	Link      string          `json:"link"`
	Reason    string          `json:"reason,omitempty"`
	CheckedAt *time.Time      `json:"checkedAt,omitempty"`
	CanManage bool            `json:"canManage"`
	Endpoint  *EndpointDetail `json:"endpoint,omitempty"`
	Policy    *Policy         `json:"policy,omitempty"`
	// Install is the device's EasyPatch agent install (ADR-0031), when one
	// was asked for.
	Install *AgentInstall `json:"install,omitempty"`
	// Stopped says patching is stopped for the device; Removal, that
	// EasyRMM is removing its EasyPatch agent.
	Stopped *PatchingStop `json:"stopped,omitempty"`
	Removal *AgentRemoval `json:"removal,omitempty"`
	// Error says why EasyPatch could not be read; the link still shows.
	Error string `json:"error,omitempty"`
}

// Device reads a device's patch summary and effective policy.
func (s *Service) Device(ctx context.Context, c access.Caller, id uuid.UUID) (DevicePatching, error) {
	d, err := s.device(ctx, c, id, rbac.PermPatchView)
	if err != nil {
		return DevicePatching{}, err
	}
	r, cl, err := s.conn(ctx)
	if err != nil {
		return DevicePatching{}, err
	}
	if r == nil {
		return DevicePatching{}, errNotConfigured
	}
	out := DevicePatching{DeviceID: d.id, Link: d.state, Reason: d.reason, CheckedAt: d.checkedAt,
		CanManage: c.Can(rbac.PermPatchManage, d.resource()), Install: d.install, Stopped: d.stopped, Removal: d.removal}
	if d.state != LinkLinked {
		return out, nil
	}
	rctx := s.as(ctx, c, RoleReadOnly, orgOf(d)...)
	ep, err := cl.Endpoint(rctx, *d.endpointID)
	if err != nil {
		s.noteError(err)
		out.Error = message(epError(err))
		if IsStatus(err, http.StatusNotFound) {
			out.Error = "The patching engine no longer has this endpoint; EasyRMM checks the link again shortly."
		}
		return out, nil
	}
	ep.Credentials = nil
	out.Endpoint = &ep
	if p, err := cl.EffectivePolicy(rctx, *d.endpointID); err == nil {
		out.Policy = &p
	}
	return out, nil
}

// linked reads a linked device and a client.
func (s *Service) linked(ctx context.Context, c access.Caller, id uuid.UUID, perm rbac.Permission) (deviceRow, *connRow, *Client, error) {
	d, err := s.device(ctx, c, id, perm)
	if err != nil {
		return d, nil, nil, err
	}
	r, cl, err := s.conn(ctx)
	switch {
	case err != nil:
		return d, nil, nil, err
	case r == nil:
		return d, nil, nil, errNotConfigured
	}
	return d, r, cl, notLinked(d)
}

// Updates lists a device's updates that are not installed; state narrows
// them to one EasyPatch state.
func (s *Service) Updates(ctx context.Context, c access.Caller, id uuid.UUID, state string) ([]Update, error) {
	if state != "" && !slices.Contains([]string{"Missing", "Failed", "PendingVerification", "PendingReboot", "Superseded",
		"NotApplicable", "Excluded", "Reoffered"}, state) {
		return nil, apperr.Invalid("state", "Choose an update state.")
	}
	d, _, cl, err := s.linked(ctx, c, id, rbac.PermPatchView)
	if err != nil {
		return nil, err
	}
	list, err := cl.Updates(s.as(ctx, c, RoleReadOnly, orgOf(d)...), *d.endpointID, state)
	if err != nil {
		return nil, epError(err)
	}
	return orEmpty(list), nil
}

// InstalledUpdates lists the updates installed on a device.
func (s *Service) InstalledUpdates(ctx context.Context, c access.Caller, id uuid.UUID) ([]Update, error) {
	d, _, cl, err := s.linked(ctx, c, id, rbac.PermPatchView)
	if err != nil {
		return nil, err
	}
	list, err := cl.InstalledUpdates(s.as(ctx, c, RoleReadOnly, orgOf(d)...), *d.endpointID)
	if err != nil {
		return nil, epError(err)
	}
	return orEmpty(list), nil
}

// History lists one page of a device's update history.
func (s *Service) History(ctx context.Context, c access.Caller, id uuid.UUID, page int) (Page[HistoryEntry], error) {
	d, _, cl, err := s.linked(ctx, c, id, rbac.PermPatchView)
	if err != nil {
		return Page[HistoryEntry]{}, err
	}
	p, err := cl.History(s.as(ctx, c, RoleReadOnly, orgOf(d)...), *d.endpointID, max(page, 1))
	if err != nil {
		return p, epError(err)
	}
	p.Items = orEmpty(p.Items)
	return p, nil
}

// DeviceJobs lists one page of a device's EasyPatch jobs.
func (s *Service) DeviceJobs(ctx context.Context, c access.Caller, id uuid.UUID, page int) (Page[Job], error) {
	d, _, cl, err := s.linked(ctx, c, id, rbac.PermPatchView)
	if err != nil {
		return Page[Job]{}, err
	}
	p, err := cl.EndpointJobs(s.as(ctx, c, RoleReadOnly, orgOf(d)...), *d.endpointID, max(page, 1))
	if err != nil {
		return p, epError(err)
	}
	p.Items = orEmpty(p.Items)
	return p, nil
}

func orEmpty[T any](list []T) []T {
	if list == nil {
		return []T{}
	}
	return list
}

// ---------------------------------------------------------------- jobs

// JobView is an EasyPatch job with the EasyRMM device it ran on.
type JobView struct {
	Job
	DeviceID   uuid.UUID `json:"deviceId"`
	DeviceName string    `json:"deviceName"`
	CanManage  bool      `json:"canManage"`
}

// JobDetailView is one job in full, with its device.
type JobDetailView struct {
	JobDetail
	DeviceID   uuid.UUID `json:"deviceId"`
	DeviceName string    `json:"deviceName"`
	CanManage  bool      `json:"canManage"`
	// RestartAfter is an install's restart of its device afterwards, as
	// asked for with the install; RestartFor, on a restart EasyRMM asked for
	// after an install, is that install's job.
	RestartAfter *RestartAfterView `json:"restartAfter"`
	RestartFor   *uuid.UUID        `json:"restartFor"`
}

// linkedDevices reads the linked devices of the given endpoints that the
// caller may see patching of.
func (s *Service) linkedDevices(ctx context.Context, c access.Caller, endpoints []uuid.UUID) (map[uuid.UUID]deviceRow, error) {
	out := map[uuid.UUID]deviceRow{}
	if len(endpoints) == 0 {
		return out, nil
	}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, deviceSelect+` WHERE e.state = 'linked' AND e.endpoint_id = ANY($1)`, endpoints)
		if err != nil {
			return err
		}
		for rows.Next() {
			d, err := scanDevice(rows)
			if err != nil {
				return err
			}
			if c.Can(rbac.PermDeviceView, d.resource()) && c.Can(rbac.PermPatchView, d.resource()) {
				out[*d.endpointID] = d
			}
		}
		return rows.Err()
	})
	return out, err
}

// JobsQuery narrows the patching job list: to an organization or one
// device, jobs still to finish (Active), and EasyPatch's status, type and
// trigger, and when the job was created ([From, To)).
type JobsQuery struct {
	OrganizationID uuid.UUID
	DeviceID       uuid.UUID
	Active         bool
	Status         string
	Type           string
	Trigger        string
	From, To       *time.Time
}

// JobList is the newest jobs that match, at most PageSize; Capped says
// there may be older ones.
type JobList struct {
	Items  []JobView `json:"items"`
	Capped bool      `json:"capped"`
}

func (q JobsQuery) validate() error {
	switch {
	case q.Status != "" && !slices.Contains(JobStatuses, q.Status):
		return apperr.Invalid("status", "Choose a status.")
	case q.Type != "" && !slices.Contains(JobTypes, q.Type):
		return apperr.Invalid("type", "Choose a type.")
	case q.Trigger != "" && !slices.Contains(JobTriggers, q.Trigger):
		return apperr.Invalid("trigger", "Choose how it was started.")
	case q.From != nil && q.To != nil && !q.From.Before(*q.To):
		return apperr.Invalid("to", "Choose an end after the start.")
	}
	return nil
}

// Jobs lists the newest EasyPatch jobs of devices the caller may see that
// match, at most PageSize.
func (s *Service) Jobs(ctx context.Context, c access.Caller, q JobsQuery) (JobList, error) {
	if !c.CanAnywhere(rbac.PermPatchView) {
		return JobList{}, apperr.Forbidden()
	}
	if err := q.validate(); err != nil {
		return JobList{}, err
	}
	r, cl, err := s.conn(ctx)
	if err != nil {
		return JobList{}, err
	}
	if r == nil {
		return JobList{}, errNotConfigured
	}
	filter := JobFilter{Active: q.Active, Status: q.Status, Type: q.Type, Trigger: q.Trigger, From: q.From, To: q.To}
	var orgs []uuid.UUID
	if q.DeviceID != uuid.Nil {
		d, err := s.device(ctx, c, q.DeviceID, rbac.PermPatchView)
		if err != nil {
			return JobList{}, err
		}
		if d.endpointID == nil || d.easyPatchOrg == nil {
			return JobList{Items: []JobView{}}, nil
		}
		filter.EndpointID, orgs = d.endpointID, []uuid.UUID{*d.easyPatchOrg}
	} else if orgs, err = s.patchOrganizations(ctx, c, q.OrganizationID); err != nil {
		return JobList{}, err
	}
	var jobs []Job
	capped := false
	for _, org := range orgs {
		filter.OrganizationID = org
		p, err := cl.Jobs(s.as(ctx, c, RoleReadOnly, org), filter, 1)
		if err != nil {
			s.noteError(err)
			return JobList{}, epError(err)
		}
		jobs = append(jobs, p.Items...)
		capped = capped || p.TotalCount > len(p.Items)
	}
	ids := make([]uuid.UUID, 0, len(jobs))
	for _, j := range jobs {
		ids = append(ids, j.EndpointID)
	}
	devices, err := s.linkedDevices(ctx, c, ids)
	if err != nil {
		return JobList{}, err
	}
	out := []JobView{}
	for _, j := range jobs {
		if d, ok := devices[j.EndpointID]; ok {
			out = append(out, JobView{Job: j, DeviceID: d.id, DeviceName: d.name,
				CanManage: c.Can(rbac.PermPatchManage, d.resource())})
		}
	}
	slices.SortFunc(out, func(a, b JobView) int { return b.CreatedAt.Compare(a.CreatedAt) })
	if len(out) > PageSize {
		out, capped = out[:PageSize], true
	}
	return JobList{Items: out, Capped: capped}, nil
}

// job reads a job and the device it ran on, if the caller may see it.
func (s *Service) job(ctx context.Context, c access.Caller, id uuid.UUID) (JobDetail, deviceRow, *connRow, *Client, error) {
	r, cl, err := s.conn(ctx)
	if err != nil {
		return JobDetail{}, deviceRow{}, nil, nil, err
	}
	if r == nil {
		return JobDetail{}, deviceRow{}, nil, nil, errNotConfigured
	}
	orgs, err := s.patchOrganizations(ctx, c, uuid.Nil)
	if err != nil {
		return JobDetail{}, deviceRow{}, nil, nil, err
	}
	j, err := cl.Job(s.as(ctx, c, RoleReadOnly, orgs...), id)
	if err != nil {
		return j, deviceRow{}, nil, nil, epError(err)
	}
	devices, err := s.linkedDevices(ctx, c, []uuid.UUID{j.Summary.EndpointID})
	if err != nil {
		return j, deviceRow{}, nil, nil, err
	}
	d, ok := devices[j.Summary.EndpointID]
	if !ok {
		return j, d, nil, nil, apperr.NotFound()
	}
	return j, d, r, cl, nil
}

// Job reads one job of a device the caller may see.
func (s *Service) Job(ctx context.Context, c access.Caller, id uuid.UUID) (JobDetailView, error) {
	j, d, _, _, err := s.job(ctx, c, id)
	if err != nil {
		return JobDetailView{}, err
	}
	j.Items, j.Events = orEmpty(j.Items), orEmpty(j.Events)
	after, install, err := s.restartAfter(ctx, c, id)
	if err != nil {
		return JobDetailView{}, err
	}
	return JobDetailView{JobDetail: j, DeviceID: d.id, DeviceName: d.name, CanManage: c.Can(rbac.PermPatchManage, d.resource()),
		RestartAfter: after, RestartFor: install}, nil
}

// CancelJob cancels a job of a device the caller may manage patching of.
func (s *Service) CancelJob(ctx context.Context, c access.Caller, id uuid.UUID) (JobDetailView, error) {
	_, d, _, cl, err := s.job(ctx, c, id)
	if err != nil {
		return JobDetailView{}, err
	}
	if !c.Can(rbac.PermPatchManage, d.resource()) {
		return JobDetailView{}, apperr.Forbidden()
	}
	j, err := cl.CancelJob(s.as(ctx, c, RoleAdmin, orgOf(d)...), id, c.Actor.Label)
	if err != nil {
		return JobDetailView{}, epError(err)
	}
	if err := s.audit.Record(ctx, audit.Event{Actor: c.Actor, Action: "patch.cancel", OrganizationID: d.organizationID, SiteID: d.siteID,
		DeviceID: d.id, TargetType: "device", TargetID: d.id.String(), Outcome: audit.Success,
		Details: map[string]any{"device": d.name, "jobId": id.String(), "jobType": j.Summary.Type}}); err != nil {
		return JobDetailView{}, err
	}
	j.Items, j.Events = orEmpty(j.Items), orEmpty(j.Events)
	after, install, err := s.restartAfter(ctx, c, id)
	if err != nil {
		return JobDetailView{}, err
	}
	return JobDetailView{JobDetail: j, DeviceID: d.id, DeviceName: d.name, CanManage: true, RestartAfter: after, RestartFor: install}, nil
}

// ---------------------------------------------------------------- actions

// ActionInput chooses the devices of a scan or an install.
type ActionInput struct {
	DeviceIDs []uuid.UUID `json:"deviceIds"`
	// UpdateIDs installs these updates (EasyPatch update GUIDs) rather
	// than every eligible one; one device only.
	UpdateIDs []uuid.UUID `json:"updateIds"`
	// ScheduledAt installs later: the jobs wait until then.
	ScheduledAt *time.Time `json:"scheduledAt"`
}

// ActionItem is one device's outcome.
type ActionItem struct {
	DeviceID   uuid.UUID  `json:"deviceId"`
	DeviceName string     `json:"deviceName"`
	OK         bool       `json:"ok"`
	JobID      *uuid.UUID `json:"jobId,omitempty"`
	// JobIDs are the device's jobs when there are several (an install of
	// more updates than one job takes), JobID the last of them.
	JobIDs []uuid.UUID `json:"jobIds,omitempty"`
	// UpToDate is a device with nothing to install: no job, and no failure.
	UpToDate bool   `json:"upToDate,omitempty"`
	Message  string `json:"message,omitempty"`
}

// ActionResult is the outcome of a scan or an install.
type ActionResult struct {
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	// UpToDate counts the devices that had nothing to install.
	UpToDate int          `json:"upToDate,omitempty"`
	Results  []ActionItem `json:"results"`
	// Scope is a Patch all's organization or site, as resolved when the
	// request ran; Batches, each request it made to the engine.
	Scope   *ScopeView `json:"scope,omitempty"`
	Batches []Batch    `json:"batches,omitempty"`
	// RestartAfter, on an install asked to restart its devices afterwards,
	// counts those that will once their install ends.
	RestartAfter *int `json:"restartAfter,omitempty"`
}

func (r *ActionResult) add(it ActionItem) {
	switch {
	case it.UpToDate:
		r.UpToDate++
	case it.OK:
		r.Succeeded++
	default:
		r.Failed++
	}
	r.Results = append(r.Results, it)
}

// targets reads the devices of an action: each must be visible and
// manageable; those that are not linked are reported, not sent.
func (s *Service) targets(ctx context.Context, c access.Caller, ids []uuid.UUID, res *ActionResult) ([]deviceRow, error) {
	if len(ids) == 0 || len(ids) > MaxBulk {
		return nil, apperr.Invalid("deviceIds", fmt.Sprintf("Choose from 1 to %d devices.", MaxBulk))
	}
	seen := map[uuid.UUID]bool{}
	var out []deviceRow
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		d, err := s.device(ctx, c, id, rbac.PermPatchManage)
		if err != nil {
			return nil, err
		}
		if err := notLinked(d); err != nil {
			res.add(ActionItem{DeviceID: d.id, DeviceName: d.name, Message: message(err)})
			continue
		}
		out = append(out, d)
	}
	return out, nil
}

// bulk sends a bulk request for devices and records each device's outcome.
func (s *Service) bulk(ctx context.Context, c access.Caller, devices []deviceRow, res *ActionResult, action string, details map[string]any,
	send func([]uuid.UUID) (BulkResult, error)) error {
	if len(devices) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, 0, len(devices))
	for _, d := range devices {
		ids = append(ids, *d.endpointID)
	}
	br, err := send(ids)
	if err != nil {
		return epError(err)
	}
	return s.settle(ctx, c, devices, br, res, action, details)
}

// settle records each device's outcome of a bulk request, and audits those
// the engine started a job for.
func (s *Service) settle(ctx context.Context, c access.Caller, devices []deviceRow, br BulkResult, res *ActionResult, action string,
	details map[string]any) error {
	byEndpoint := map[uuid.UUID]deviceRow{}
	for _, d := range devices {
		byEndpoint[*d.endpointID] = d
	}
	answered := map[uuid.UUID]bool{}
	var events []audit.Event
	for _, it := range br.Results {
		d, ok := byEndpoint[it.EndpointID]
		if !ok || answered[it.EndpointID] {
			continue
		}
		answered[it.EndpointID] = true
		item := ActionItem{DeviceID: d.id, DeviceName: d.name, OK: it.Success, JobID: it.JobID, Message: cut(it.Message, 500)}
		res.add(item)
		if it.Success {
			det := map[string]any{"device": d.name, "endpointId": it.EndpointID.String()}
			if it.JobID != nil {
				det["jobId"] = it.JobID.String()
			}
			for k, v := range details {
				det[k] = v
			}
			events = append(events, audit.Event{Actor: c.Actor, Action: action, OrganizationID: d.organizationID, SiteID: d.siteID,
				DeviceID: d.id, TargetType: "device", TargetID: d.id.String(), Outcome: audit.Success, Details: det})
		}
	}
	for _, d := range devices {
		if !answered[*d.endpointID] {
			res.add(ActionItem{DeviceID: d.id, DeviceName: d.name, Message: unansweredMessage})
		}
	}
	return s.record(ctx, events)
}

func (s *Service) record(ctx context.Context, events []audit.Event) error {
	if len(events) == 0 {
		return nil
	}
	ctx = context.WithoutCancel(ctx)
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		for _, e := range events {
			if err := s.audit.Write(ctx, tx, e); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Service) operable(ctx context.Context) (*connRow, *Client, error) {
	r, cl, err := s.conn(ctx)
	switch {
	case err != nil:
		return nil, nil, err
	case r == nil:
		return nil, nil, errNotConfigured
	}
	return r, cl, nil
}

// Scan has devices look for updates.
func (s *Service) Scan(ctx context.Context, c access.Caller, in ActionInput) (ActionResult, error) {
	if len(in.UpdateIDs) > 0 || in.ScheduledAt != nil {
		return ActionResult{}, apperr.Invalid("deviceIds", "A scan takes devices only.")
	}
	_, cl, err := s.operable(ctx)
	if err != nil {
		return ActionResult{}, err
	}
	res := ActionResult{Results: []ActionItem{}}
	devices, err := s.targets(ctx, c, in.DeviceIDs, &res)
	if err != nil {
		return ActionResult{}, err
	}
	actx := s.as(ctx, c, RoleAdmin, orgsOf(devices)...)
	err = s.bulk(ctx, c, devices, &res, "patch.scan", nil, func(ids []uuid.UUID) (BulkResult, error) {
		return cl.BulkScan(actx, ids, c.Actor.Label)
	})
	s.fleet.clear()
	return res, err
}

// What an install installs.
const (
	// UpdatesPolicy is every update each device's patch policy allows.
	UpdatesPolicy = "policy"
	// UpdatesAvailable is every update the engine reports missing or failed
	// on each device, but those excluded, held or not approved, and feature
	// upgrades unless asked for.
	UpdatesAvailable = "available"
)

// InstallInput chooses the devices of an install, what it installs and when,
// and whether each device restarts once its install has finished.
type InstallInput struct {
	DeviceIDs []uuid.UUID `json:"deviceIds"`
	// All, with OrganizationID (and SiteID), installs on every device of
	// the organization (or the site) that the caller may patch, on
	// Platforms (every platform when empty): Patch all.
	All            bool      `json:"all"`
	OrganizationID uuid.UUID `json:"organizationId"`
	SiteID         uuid.UUID `json:"siteId"`
	Platforms      []string  `json:"platforms"`
	// UpdateIDs installs these updates (EasyPatch update GUIDs); one device
	// only.
	UpdateIDs []uuid.UUID `json:"updateIds"`
	// Updates is UpdatesPolicy (the default) or UpdatesAvailable; Features
	// adds feature upgrades to every available update, and SkipDelayed
	// leaves out those still in the policy's rollout delay.
	Updates     string `json:"updates"`
	Features    bool   `json:"features"`
	SkipDelayed bool   `json:"skipDelayed"`
	// ScheduledAt installs later: the jobs wait until then.
	ScheduledAt *time.Time `json:"scheduledAt"`
	// Restart restarts each device once its install has finished.
	Restart *AfterInstall `json:"restart"`
	// ConfirmServers are the servers the person ticked: only they restart
	// after the install. Other servers install, and do not restart.
	ConfirmServers []uuid.UUID `json:"confirmServers"`
}

func (in InstallInput) targets() Targets {
	return Targets{DeviceIDs: in.DeviceIDs, All: in.All, OrganizationID: in.OrganizationID, SiteID: in.SiteID, Platforms: in.Platforms}
}

// check checks the request on its own, and returns the restart options.
func (in *InstallInput) check(now time.Time) (*RestartOptions, error) {
	if err := in.targets().checkTargets(); err != nil {
		return nil, err
	}
	if in.Updates == "" {
		in.Updates = UpdatesPolicy
	}
	f := apperr.Fields{}
	f.Check(in.Updates == UpdatesPolicy || in.Updates == UpdatesAvailable, "updates", "Choose the updates the policy allows, or every available update.")
	f.Check(!in.Features || in.Updates == UpdatesAvailable, "features", "Feature upgrades go with every available update.")
	f.Check(!in.SkipDelayed || in.Updates == UpdatesAvailable, "skipDelayed", "Leaving out updates in the rollout delay goes with every available update.")
	if len(in.UpdateIDs) > 0 {
		f.Check(len(in.DeviceIDs) == 1 && !in.All, "updateIds", "Choose updates on one device at a time.")
		f.Check(in.Updates == UpdatesPolicy, "updateIds", "Choose updates, or every available update, not both.")
		f.Check(len(in.UpdateIDs) <= MaxSelected, "updateIds", fmt.Sprintf("Choose at most %d updates: the patching engine takes no more in one install.",
			MaxSelected))
	}
	if in.ScheduledAt != nil {
		switch {
		case in.ScheduledAt.Before(now.Add(time.Minute)):
			f.Add("scheduledAt", "Choose a time in the future.")
		case in.ScheduledAt.After(now.Add(maxScheduleAhead)):
			f.Add("scheduledAt", "Choose a time within 31 days.")
		}
	}
	if err := f.Err(); err != nil {
		return nil, err
	}
	if in.ScheduledAt != nil {
		at := in.ScheduledAt.UTC()
		in.ScheduledAt = &at
	}
	if in.Restart == nil {
		return nil, nil
	}
	o, err := in.Restart.options(now)
	return &o, err
}

// checkCount refuses an install that reaches more devices than what it asks
// for allows.
func (in InstallInput) checkCount(n int) error {
	switch {
	case in.Restart != nil && in.Restart.Condition == conditionAlways && n > maxAlwaysRestart:
		return apperr.Invalid("restart", fmt.Sprintf("Restarting when done reaches at most %d devices at once: restart only if the updates need it, "+
			"or choose fewer devices.", maxAlwaysRestart))
	case in.Restart != nil && n > MaxBulk:
		return apperr.Invalid("restart", fmt.Sprintf("Restarting after the install reaches at most %s devices at once: choose a site, "+
			"or install without restarting and use Schedule restart all.", thousands(MaxBulk)))
	case in.Updates == UpdatesAvailable && n > MaxBulk:
		return availableLimit()
	}
	return nil
}

// thousands writes n as people read it: 1,000.
func thousands(n int) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// Install has devices install updates: every update their policy allows,
// every available update, or chosen updates on one device; on chosen
// devices or every device of an organization or site (Patch all); now or at
// a scheduled time; and, when asked, restart each device once its install
// has finished.
func (s *Service) Install(ctx context.Context, c access.Caller, in InstallInput) (ActionResult, error) {
	_, cl, err := s.operable(ctx)
	if err != nil {
		return ActionResult{}, err
	}
	restart, err := in.check(s.now())
	if err != nil {
		return ActionResult{}, err
	}
	res := ActionResult{Results: []ActionItem{}}
	var devices []deviceRow
	var sc *scope
	if in.All {
		if sc, err = s.resolveAll(ctx, c, in.targets()); err != nil {
			return ActionResult{}, err
		}
		if len(sc.devices) == 0 {
			return ActionResult{}, apperr.Conflict("easypatch_no_devices", fmt.Sprintf("No device of %s can be patched from EasyRMM.", sc.view.where()))
		}
		devices, res.Scope = sc.devices, &sc.view
	} else if devices, err = s.targets(ctx, c, in.DeviceIDs, &res); err != nil {
		return ActionResult{}, err
	}
	if err := in.checkCount(len(devices)); err != nil {
		return ActionResult{}, err
	}
	details := map[string]any{"updates": "all eligible"}
	if in.Updates == UpdatesAvailable {
		details["updates"], details["featureUpgrades"], details["rolloutDelayed"] = "all available", in.Features, !in.SkipDelayed
	}
	if len(in.UpdateIDs) > 0 {
		details["updates"] = len(in.UpdateIDs)
	}
	if in.ScheduledAt != nil {
		details["scheduledAt"] = in.ScheduledAt.Format(time.RFC3339)
	}
	if restart != nil {
		details["restartAfter"], details["restartMode"] = afterText(restart.Condition), restartModeText(*restart)
	}
	request := uuid.New()
	if sc != nil {
		details["patchAll"], details["requestId"] = sc.view.where(), request.String()
	}
	// Each restart choice is saved as soon as the engine has started its
	// install, whatever becomes of the request.
	var keep *restartKeeper
	if restart != nil {
		keep = &restartKeeper{s: s, c: c, o: *restart, confirm: in.ConfirmServers, scheduledAt: in.ScheduledAt}
	}
	switch {
	case len(in.UpdateIDs) > 0:
		err = s.installChosen(ctx, c, cl, devices, in, &res, details, keep)
	case in.Updates == UpdatesAvailable:
		err = s.installAvailable(ctx, c, cl, devices, in, &res, details, keep)
	case sc != nil:
		res.Batches, err = s.batches(ctx, c, devices, &res, "patch.install", details, func(actx context.Context, ids []uuid.UUID) (BulkResult, error) {
			return cl.BulkInstall(actx, ids, in.ScheduledAt, c.Actor.Label)
		}, keep.keep)
	default:
		sctx, cancel := detached(ctx)
		defer cancel()
		actx := s.as(sctx, c, RoleAdmin, orgsOf(devices)...)
		start := len(res.Results)
		err = s.bulk(sctx, c, devices, &res, "patch.install", details, func(ids []uuid.UUID) (BulkResult, error) {
			return cl.BulkInstall(actx, ids, in.ScheduledAt, c.Actor.Label)
		})
		err = errors.Join(err, keep.keep(sctx, devices, res.Results[start:]))
	}
	s.fleet.clear()
	res.RestartAfter = keep.count()
	if sc != nil {
		// What was sent is audited, whatever became of the request.
		rctx, cancel := detached(ctx)
		defer cancel()
		err = errors.Join(err, s.recordAll(rctx, c, "patch.install_all", sc, request, &res, details, map[string]any{"platforms": platformText(in.Platforms)}))
	}
	if err != nil && len(res.Results) == 0 {
		return ActionResult{}, err
	}
	return res, err
}

// installChosen installs chosen updates on one device.
func (s *Service) installChosen(ctx context.Context, c access.Caller, cl *Client, devices []deviceRow, in InstallInput, res *ActionResult,
	details map[string]any, keep *restartKeeper) error {
	if len(devices) != 1 {
		return nil
	}
	d := devices[0]
	ctx, cancel := detached(ctx)
	defer cancel()
	j, err := cl.Install(s.as(ctx, c, RoleAdmin, orgOf(d)...), *d.endpointID, in.UpdateIDs, in.ScheduledAt, c.Actor.Label)
	if err != nil {
		if !IsStatus(err, http.StatusConflict) && !IsStatus(err, http.StatusBadRequest) {
			return epError(err)
		}
		res.add(ActionItem{DeviceID: d.id, DeviceName: d.name, Message: message(epError(err))})
		return nil
	}
	it := ActionItem{DeviceID: d.id, DeviceName: d.name, OK: true, JobID: &j.ID}
	res.add(it)
	det := map[string]any{"device": d.name, "endpointId": d.endpointID.String(), "jobId": j.ID.String()}
	for k, v := range details {
		det[k] = v
	}
	return errors.Join(keep.keep(ctx, devices, []ActionItem{it}),
		s.record(ctx, []audit.Event{{Actor: c.Actor, Action: "patch.install", OrganizationID: d.organizationID, SiteID: d.siteID,
			DeviceID: d.id, TargetType: "device", TargetID: d.id.String(), Outcome: audit.Success, Details: det}}))
}

// recordAll audits a Patch all once, for its organization or site: what it
// reached, what it left out and why, and each batch.
func (s *Service) recordAll(ctx context.Context, c access.Caller, action string, sc *scope, request uuid.UUID, res *ActionResult,
	details, extra map[string]any) error {
	det := map[string]any{"requestId": request.String(), "organization": sc.view.OrganizationName, "devices": len(sc.devices),
		"succeeded": res.Succeeded, "failed": res.Failed, "skipped": sc.view.skippedDetails()}
	if res.UpToDate > 0 {
		det["upToDate"] = res.UpToDate
	}
	for k, v := range details {
		if k != "patchAll" && k != "requestId" {
			det[k] = v
		}
	}
	for k, v := range extra {
		det[k] = v
	}
	if len(res.Batches) > 0 {
		det["batches"] = batchDetails(res.Batches)
	}
	if res.RestartAfter != nil {
		det["restartAfterDevices"] = *res.RestartAfter
	}
	ev := audit.Event{Actor: c.Actor, Action: action, OrganizationID: sc.view.OrganizationID, TargetType: "organization",
		TargetID: sc.view.OrganizationID.String(), Outcome: audit.Success, Details: det}
	if sc.view.SiteID != nil {
		ev.SiteID, ev.TargetType, ev.TargetID, det["site"] = *sc.view.SiteID, "site", sc.view.SiteID.String(), sc.view.SiteName
	}
	if res.Succeeded == 0 && res.UpToDate == 0 && len(sc.devices) > 0 {
		ev.Outcome = audit.Failure
	}
	return s.record(ctx, []audit.Event{ev})
}
