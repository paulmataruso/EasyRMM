package easypatch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Patching → Updates: EasyPatch's update catalog, counted over the devices a
// person may see; one update's page with the devices that report it;
// installing or removing it on many devices; and holds.
//
// EasyPatch counts per organization or site, not per device, so the
// catalog covers whole organizations where the caller sees patching across
// the organization, or one site they may see.

// UpdateScope is where the catalog counts: every organization the caller
// sees whole, one organization, or one site.
type UpdateScope struct {
	OrganizationID uuid.UUID
	SiteID         uuid.UUID
}

// updateScope is an UpdateScope resolved to EasyPatch's ids.
type updateScope struct {
	// orgs are the EasyPatch organizations a statement names; none means
	// there is nothing to show.
	orgs  []uuid.UUID
	fleet FleetScope
	// byEngine maps EasyPatch organizations to EasyRMM's, for every linked
	// organization the caller may see patching in.
	byEngine map[uuid.UUID]linkedOrg
}

type linkedOrg struct {
	id   uuid.UUID
	name string
}

var errChooseSite = apperr.Invalid("siteId", "Your role covers single sites in this organization: choose one of them.")

// linkedOrgs reads the organizations linked to EasyPatch that the caller may
// see patching in, by EasyPatch id.
func (s *Service) linkedOrgs(ctx context.Context, c access.Caller) (map[uuid.UUID]linkedOrg, error) {
	out := map[uuid.UUID]linkedOrg{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT l.easypatch_id, o.id, o.name FROM easypatch_organizations l
			JOIN organizations o ON o.id = l.organization_id ORDER BY o.name`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var ep uuid.UUID
			var o linkedOrg
			if err := rows.Scan(&ep, &o.id, &o.name); err != nil {
				return err
			}
			if c.CanInOrg(rbac.PermPatchView, o.id) {
				out[ep] = o
			}
		}
		return rows.Err()
	})
	return out, err
}

// resolveScope checks that the caller may see patching across the scope and
// resolves it to EasyPatch's ids.
func (s *Service) resolveScope(ctx context.Context, c access.Caller, cl *Client, in UpdateScope) (updateScope, error) {
	if !c.CanAnywhere(rbac.PermPatchView) {
		return updateScope{}, apperr.Forbidden()
	}
	linked, err := s.linkedOrgs(ctx, c)
	if err != nil {
		return updateScope{}, err
	}
	out := updateScope{byEngine: linked}
	engineOf := func(org uuid.UUID) *uuid.UUID {
		for ep, o := range linked {
			if o.id == org {
				return &ep
			}
		}
		return nil
	}
	if in.SiteID != uuid.Nil {
		var org uuid.UUID
		var name string
		var epSite *uuid.UUID
		err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT s.organization_id, s.name, ls.easypatch_id FROM sites s
				LEFT JOIN easypatch_sites ls ON ls.site_id = s.id WHERE s.id = $1`, in.SiteID).Scan(&org, &name, &epSite)
		})
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return out, apperr.NotFound()
		case err != nil:
			return out, err
		case in.OrganizationID != uuid.Nil && in.OrganizationID != org:
			return out, apperr.Invalid("siteId", "Choose a site of the organization.")
		case !c.Can(rbac.PermPatchView, rbac.Site(org, in.SiteID)):
			return out, apperr.NotFound()
		}
		ep := engineOf(org)
		if ep == nil {
			return out, errOrgNotLinked
		}
		if epSite == nil {
			// A site the reconciler has not recorded yet is found by name,
			// as installs do.
			sites, err := cl.Sites(s.as(ctx, c, RoleReadOnly, *ep), *ep)
			if err != nil {
				s.noteError(err)
				return out, epError(err)
			}
			for _, x := range sites {
				if strings.EqualFold(strings.TrimSpace(x.Name), strings.TrimSpace(name)) {
					epSite = &x.ID
					break
				}
			}
			if epSite == nil {
				return out, apperr.Conflict("easypatch_site_not_found", fmt.Sprintf("The patching engine has no site named %q in this organization.", name))
			}
		}
		out.orgs, out.fleet = []uuid.UUID{*ep}, FleetScope{OrganizationID: ep, SiteID: epSite}
		return out, nil
	}
	if in.OrganizationID != uuid.Nil {
		ep := engineOf(in.OrganizationID)
		switch {
		case ep == nil && c.CanInOrg(rbac.PermPatchView, in.OrganizationID):
			return out, errOrgNotLinked
		case ep == nil:
			return out, apperr.NotFound()
		case !c.Can(rbac.PermPatchView, rbac.Org(in.OrganizationID)):
			return out, errChooseSite
		}
		out.orgs, out.fleet = []uuid.UUID{*ep}, FleetScope{OrganizationID: ep}
		return out, nil
	}
	partial := false
	for ep, o := range linked {
		if c.Can(rbac.PermPatchView, rbac.Org(o.id)) {
			out.orgs = append(out.orgs, ep)
		} else {
			partial = true
		}
	}
	slices.SortFunc(out.orgs, func(a, b uuid.UUID) int { return strings.Compare(linked[a].name, linked[b].name) })
	switch {
	case len(out.orgs) == 0 && partial:
		return out, errChooseSite
	case len(out.orgs) == 1:
		out.fleet = FleetScope{OrganizationID: &out.orgs[0]}
	}
	return out, nil
}

var errOrgNotLinked = apperr.Conflict("easypatch_not_linked", "This organization is not in the patching engine yet.")

// Catalog lists updates across the devices in scope, 50 at a time.
func (s *Service) Catalog(ctx context.Context, c access.Caller, scope UpdateScope, q CatalogQuery) (Page[FleetUpdate], error) {
	f := apperr.Fields{}
	f.Check(q.Category == "" || slices.Contains(UpdateCategories, q.Category), "category", "Choose a category.")
	f.Check(q.State == "" || slices.Contains(UpdateStates, q.State), "state", "Choose a state.")
	f.Check(q.Sort == "" || slices.Contains([]string{"missing", "failed", "installed"}, q.Sort), "sort", "Sort by missing, failed or installed.")
	f.Check(len(q.Search) <= 200, "q", "Search for at most 200 characters.")
	f.Check(q.Page >= 0 && q.Page <= 10_000, "page", "Choose a page from 1 to 10,000.")
	if err := f.Err(); err != nil {
		return Page[FleetUpdate]{}, err
	}
	r, cl, err := s.conn(ctx)
	if err != nil {
		return Page[FleetUpdate]{}, err
	}
	if r == nil {
		return Page[FleetUpdate]{}, errNotConfigured
	}
	sc, err := s.resolveScope(ctx, c, cl, scope)
	if err != nil {
		return Page[FleetUpdate]{}, err
	}
	empty := Page[FleetUpdate]{Items: []FleetUpdate{}, Page: max(q.Page, 1), PageSize: CatalogPageSize}
	if len(sc.orgs) == 0 {
		return empty, nil
	}
	q.FleetScope = sc.fleet
	p, err := cl.Catalog(s.as(ctx, c, RoleReadOnly, sc.orgs...), q)
	if err != nil {
		s.noteError(err)
		return p, epError(err)
	}
	p.Items = orEmpty(p.Items)
	return p, nil
}

// HoldView is a hold, with the EasyRMM organization it applies to.
type HoldView struct {
	Hold
	// OrganizationID is EasyRMM's; nil for a hold in every organization.
	OrganizationID   *uuid.UUID `json:"organizationId"`
	OrganizationName string     `json:"organizationName"`
	// CanRelease says the caller may release it: patch.configure in its
	// organization, or a super administrator's for one everywhere.
	CanRelease bool `json:"canRelease"`
}

// holdViews maps holds to EasyRMM's organizations, leaving out holds of
// organizations the caller may not see.
func (s *Service) holdViews(c access.Caller, holds []Hold, linked map[uuid.UUID]linkedOrg) []HoldView {
	out := []HoldView{}
	for _, h := range holds {
		if h.ReleasedAt != nil {
			continue
		}
		v := HoldView{Hold: h}
		if h.OrganizationID == nil {
			v.CanRelease = c.CanGlobal(rbac.PermPatchConfigure)
		} else {
			o, ok := linked[*h.OrganizationID]
			if !ok {
				continue
			}
			v.OrganizationID, v.OrganizationName = &o.id, o.name
			v.CanRelease = c.Can(rbac.PermPatchConfigure, rbac.Org(o.id))
		}
		out = append(out, v)
	}
	return out
}

// UpdateView is one update's page.
type UpdateView struct {
	FleetUpdateDetail
	Holds []HoldView `json:"holds"`
	// CanManage says the caller may install or remove updates somewhere;
	// each device says whether on it.
	CanManage bool `json:"canManage"`
	// CanHold says the caller may hold it somewhere: patch.configure in a
	// linked organization, or everywhere as a super administrator.
	CanHold bool `json:"canHold"`
	// HoldIn lists the linked organizations the caller may hold it in, by
	// name; holding it everywhere also needs CanHoldEverywhere.
	HoldIn            []HoldOrganization `json:"holdIn"`
	CanHoldEverywhere bool               `json:"canHoldEverywhere"`
}

// HoldOrganization is an EasyRMM organization an update can be held in.
type HoldOrganization struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// Update reads one update, counted over the devices in scope.
func (s *Service) Update(ctx context.Context, c access.Caller, guid uuid.UUID, scope UpdateScope) (UpdateView, error) {
	r, cl, err := s.conn(ctx)
	if err != nil {
		return UpdateView{}, err
	}
	if r == nil {
		return UpdateView{}, errNotConfigured
	}
	sc, err := s.resolveScope(ctx, c, cl, scope)
	if err != nil {
		return UpdateView{}, err
	}
	if len(sc.orgs) == 0 {
		return UpdateView{}, apperr.NotFound()
	}
	d, err := cl.FleetUpdate(s.as(ctx, c, RoleReadOnly, sc.orgs...), guid, sc.fleet)
	if err != nil {
		if IsStatus(err, http.StatusNotFound) {
			return UpdateView{}, apperr.NotFound()
		}
		s.noteError(err)
		return UpdateView{}, epError(err)
	}
	d.KbNumbers, d.Products, d.SupersededUpdateGUIDs = orEmpty(d.KbNumbers), orEmpty(d.Products), orEmpty(d.SupersededUpdateGUIDs)
	d.Vulnerabilities = orEmpty(d.Vulnerabilities)
	v := UpdateView{FleetUpdateDetail: d, Holds: s.holdViews(c, d.Holds, sc.byEngine), CanManage: c.CanAnywhere(rbac.PermPatchManage),
		CanHoldEverywhere: c.CanGlobal(rbac.PermPatchConfigure), HoldIn: []HoldOrganization{}}
	for _, o := range sc.byEngine {
		if c.Can(rbac.PermPatchConfigure, rbac.Org(o.id)) {
			v.HoldIn = append(v.HoldIn, HoldOrganization{ID: o.id, Name: o.name})
		}
	}
	slices.SortFunc(v.HoldIn, func(a, b HoldOrganization) int { return strings.Compare(a.Name, b.Name) })
	v.CanHold = v.CanHoldEverywhere || len(v.HoldIn) > 0
	return v, nil
}

// UpdateDevice is a device, or an EasyPatch endpoint with no EasyRMM device,
// that reports an update.
type UpdateDevice struct {
	FleetUpdateEndpoint
	// DeviceID is nil for an endpoint no EasyRMM device is linked to.
	DeviceID   *uuid.UUID `json:"deviceId"`
	DeviceName string     `json:"deviceName"`
	// OrganizationName and SiteName are EasyRMM's for a device.
	OrganizationName string `json:"organizationName"`
	SiteName         string `json:"siteName"`
	Platform         string `json:"platform"`
	CanManage        bool   `json:"canManage"`
}

// UpdateDevices lists the devices in scope that report an update, by host
// name, 200 at a time; state narrows them.
func (s *Service) UpdateDevices(ctx context.Context, c access.Caller, guid uuid.UUID, scope UpdateScope, state string, page int) (Page[UpdateDevice], error) {
	if state != "" && !slices.Contains(UpdateStates, state) {
		return Page[UpdateDevice]{}, apperr.Invalid("state", "Choose a state.")
	}
	if page < 0 || page > 10_000 {
		return Page[UpdateDevice]{}, apperr.Invalid("page", "Choose a page from 1 to 10,000.")
	}
	r, cl, err := s.conn(ctx)
	if err != nil {
		return Page[UpdateDevice]{}, err
	}
	if r == nil {
		return Page[UpdateDevice]{}, errNotConfigured
	}
	sc, err := s.resolveScope(ctx, c, cl, scope)
	if err != nil {
		return Page[UpdateDevice]{}, err
	}
	out := Page[UpdateDevice]{Items: []UpdateDevice{}, Page: max(page, 1), PageSize: PageSize}
	if len(sc.orgs) == 0 {
		return out, nil
	}
	p, err := cl.FleetUpdateEndpoints(s.as(ctx, c, RoleReadOnly, sc.orgs...), guid, sc.fleet, state, page)
	if err != nil {
		s.noteError(err)
		return out, epError(err)
	}
	devices, linked, err := s.endpointDevices(ctx, c, p.Items)
	if err != nil {
		return out, err
	}
	out.Page, out.PageSize, out.TotalCount = p.Page, p.PageSize, p.TotalCount
	for _, e := range p.Items {
		row := UpdateDevice{FleetUpdateEndpoint: e, OrganizationName: e.OrganizationName, SiteName: e.SiteName}
		if d, ok := devices[e.EndpointID]; ok {
			id := d.id
			row.DeviceID, row.DeviceName, row.OrganizationName, row.SiteName, row.Platform = &id, d.name, d.organizationName, d.siteName, d.platform
			row.CanManage = c.Can(rbac.PermPatchManage, d.resource())
		} else if linked[e.EndpointID] {
			// A device the caller may not see.
			continue
		}
		out.Items = append(out.Items, row)
	}
	return out, nil
}

// endpointDevices reads the devices the caller may see that endpoints are
// linked to, and which of the endpoints any device is linked to.
func (s *Service) endpointDevices(ctx context.Context, c access.Caller, endpoints []FleetUpdateEndpoint) (map[uuid.UUID]deviceRow, map[uuid.UUID]bool, error) {
	ids := make([]uuid.UUID, 0, len(endpoints))
	for _, e := range endpoints {
		ids = append(ids, e.EndpointID)
	}
	devices, err := s.linkedDevices(ctx, c, ids)
	if err != nil {
		return nil, nil, err
	}
	linked := map[uuid.UUID]bool{}
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT endpoint_id FROM easypatch_devices WHERE state = 'linked' AND endpoint_id = ANY($1)`, ids)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			linked[id] = true
		}
		return rows.Err()
	})
	return devices, linked, err
}

// FleetActionInput chooses the devices to install an update on, or remove
// it from: DeviceIDs, or with All every device in Scope where it is missing
// or failed (an install) or installed (a removal).
type FleetActionInput struct {
	DeviceIDs      []uuid.UUID `json:"deviceIds"`
	All            bool        `json:"all"`
	OrganizationID uuid.UUID   `json:"organizationId"`
	SiteID         uuid.UUID   `json:"siteId"`
	// Block, for a removal, also excludes the update on each device, with
	// Reason.
	Block  bool   `json:"block"`
	Reason string `json:"reason"`
}

// fleetTargets resolves a fleet action's devices. With All, it reads the
// endpoints in scope in the given states from EasyPatch; devices the caller
// may not manage are reported, not sent.
func (s *Service) fleetTargets(ctx context.Context, c access.Caller, cl *Client, guid uuid.UUID, in FleetActionInput, states []string,
	res *ActionResult) ([]deviceRow, error) {
	if !in.All {
		return s.targets(ctx, c, in.DeviceIDs, res)
	}
	if len(in.DeviceIDs) > 0 {
		return nil, apperr.Invalid("deviceIds", "Choose devices, or every device in the scope, not both.")
	}
	if !c.CanAnywhere(rbac.PermPatchManage) {
		return nil, apperr.Forbidden()
	}
	sc, err := s.resolveScope(ctx, c, cl, UpdateScope{OrganizationID: in.OrganizationID, SiteID: in.SiteID})
	if err != nil {
		return nil, err
	}
	if len(sc.orgs) == 0 {
		return nil, nil
	}
	actx := s.as(ctx, c, RoleReadOnly, sc.orgs...)
	var endpoints []FleetUpdateEndpoint
	for _, st := range states {
		for page := 1; len(endpoints) <= MaxBulk; page++ {
			p, err := cl.FleetUpdateEndpoints(actx, guid, sc.fleet, st, page)
			if err != nil {
				s.noteError(err)
				return nil, epError(err)
			}
			for _, e := range p.Items {
				if !e.IsExcluded || (st != "Missing" && st != "Failed") {
					endpoints = append(endpoints, e)
				}
			}
			if len(p.Items) == 0 || page*PageSize >= p.TotalCount {
				break
			}
		}
	}
	devices, _, err := s.endpointDevices(ctx, c, endpoints)
	if err != nil {
		return nil, err
	}
	var out []deviceRow
	seen := map[uuid.UUID]bool{}
	for _, e := range endpoints {
		d, ok := devices[e.EndpointID]
		if !ok || seen[d.id] {
			continue
		}
		seen[d.id] = true
		if !c.Can(rbac.PermPatchManage, d.resource()) {
			res.add(ActionItem{DeviceID: d.id, DeviceName: d.name, Message: "You may not install or remove updates on this device."})
			continue
		}
		out = append(out, d)
	}
	if len(out) > MaxBulk {
		return nil, apperr.Invalid("all", fmt.Sprintf("More than %d devices: narrow the scope to an organization or a site.", MaxBulk))
	}
	return out, nil
}

// unanswered relabels devices EasyPatch left out of a fleet action, with why
// it does.
func unanswered(res *ActionResult, why string) {
	for i := range res.Results {
		if res.Results[i].Message == unansweredMessage {
			res.Results[i].Message = why
		}
	}
}

const unansweredMessage = "The patching engine did not say what became of this device."

// InstallUpdate installs one update on devices where it is missing or
// failed. It installs whatever the update's category, but not where it is
// excluded.
func (s *Service) InstallUpdate(ctx context.Context, c access.Caller, guid uuid.UUID, in FleetActionInput) (ActionResult, error) {
	_, cl, err := s.operable(ctx)
	if err != nil {
		return ActionResult{}, err
	}
	res := ActionResult{Results: []ActionItem{}}
	devices, err := s.fleetTargets(ctx, c, cl, guid, in, []string{"Missing", "Failed"}, &res)
	if err != nil {
		return ActionResult{}, err
	}
	actx := s.as(ctx, c, RoleAdmin, orgsOf(devices)...)
	err = s.bulk(ctx, c, devices, &res, "patch.install", map[string]any{"updates": 1, "updateId": guid.String()},
		func(ids []uuid.UUID) (BulkResult, error) { return cl.FleetInstall(actx, guid, ids, c.Actor.Label) })
	unanswered(&res, "The update is not missing on this device, or is excluded there.")
	s.fleet.clear()
	return res, err
}

// RemoveUpdateFromDevices has devices where an update is installed, or waits
// for its restart, uninstall it. EasyPatch refuses devices other than Windows.
func (s *Service) RemoveUpdateFromDevices(ctx context.Context, c access.Caller, guid uuid.UUID, in FleetActionInput) (ActionResult, error) {
	in.Reason = strings.TrimSpace(in.Reason)
	if len([]rune(in.Reason)) > maxReason {
		return ActionResult{}, apperr.Invalid("reason", "Keep the reason under 500 characters.")
	}
	if !in.Block {
		in.Reason = ""
	}
	_, cl, err := s.operable(ctx)
	if err != nil {
		return ActionResult{}, err
	}
	res := ActionResult{Results: []ActionItem{}}
	devices, err := s.fleetTargets(ctx, c, cl, guid, in, []string{"Installed", "PendingReboot"}, &res)
	if err != nil {
		return ActionResult{}, err
	}
	details := map[string]any{"updateId": guid.String(), "block": in.Block}
	if in.Reason != "" {
		details["reason"] = in.Reason
	}
	actx := s.as(ctx, c, RoleAdmin, orgsOf(devices)...)
	err = s.bulk(ctx, c, devices, &res, "patch.remove_update", details,
		func(ids []uuid.UUID) (BulkResult, error) {
			return cl.FleetRemove(actx, guid, ids, in.Block, in.Reason, c.Actor.Label)
		})
	unanswered(&res, "The update is not installed on this device.")
	s.fleet.clear()
	return res, err
}

// HoldInput holds an update in one organization, or in every organization
// when OrganizationID is empty (super administrators).
type HoldInput struct {
	OrganizationID uuid.UUID `json:"organizationId"`
	Reason         string    `json:"reason"`
}

// HoldUpdate keeps an update from installing automatically. People can still
// install it by choosing it.
func (s *Service) HoldUpdate(ctx context.Context, c access.Caller, guid uuid.UUID, in HoldInput) (HoldView, error) {
	in.Reason = strings.TrimSpace(in.Reason)
	f := apperr.Fields{}
	f.Check(in.Reason != "", "reason", "Say why it is held.")
	f.Check(len([]rune(in.Reason)) <= maxReason, "reason", "Keep the reason under 500 characters.")
	if err := f.Err(); err != nil {
		return HoldView{}, err
	}
	_, cl, err := s.operable(ctx)
	if err != nil {
		return HoldView{}, err
	}
	linked, err := s.linkedOrgs(ctx, c)
	if err != nil {
		return HoldView{}, err
	}
	var org *linkedOrg
	var ep *uuid.UUID
	var actx context.Context
	if in.OrganizationID == uuid.Nil {
		if !c.CanGlobal(rbac.PermPatchConfigure) {
			return HoldView{}, apperr.Forbidden()
		}
		st := s.statement(c, RoleSuperAdmin)
		st.AllOrganizations = true
		actx = WithStatement(ctx, st)
	} else {
		for id, o := range linked {
			if o.id == in.OrganizationID {
				org, ep = &o, &id
			}
		}
		switch {
		case org == nil && c.CanInOrg(rbac.PermPatchView, in.OrganizationID):
			return HoldView{}, errOrgNotLinked
		case org == nil:
			return HoldView{}, apperr.NotFound()
		case !c.Can(rbac.PermPatchConfigure, rbac.Org(org.id)):
			return HoldView{}, apperr.Forbidden()
		}
		actx = s.as(ctx, c, RoleAdmin, *ep)
	}
	h, err := cl.HoldUpdate(actx, guid, ep, in.Reason, c.Actor.Label)
	if err != nil {
		if IsStatus(err, http.StatusNotFound) {
			return HoldView{}, apperr.NotFound()
		}
		s.noteError(err)
		return HoldView{}, epError(err)
	}
	ev := audit.Event{Actor: c.Actor, Action: "patch.hold", TargetType: "update", TargetID: guid.String(), Outcome: audit.Success,
		Details: map[string]any{"update": h.Title, "reason": in.Reason, "scope": "every organization"}}
	if org != nil {
		ev.OrganizationID, ev.Details["scope"] = org.id, org.name
	}
	if err := s.record(ctx, []audit.Event{ev}); err != nil {
		return HoldView{}, err
	}
	views := s.holdViews(c, []Hold{h}, linked)
	if len(views) == 0 {
		return HoldView{Hold: h}, nil
	}
	return views[0], nil
}

// ReleaseHold lets a held update install automatically again.
func (s *Service) ReleaseHold(ctx context.Context, c access.Caller, guid, id uuid.UUID) (HoldView, error) {
	_, cl, err := s.operable(ctx)
	if err != nil {
		return HoldView{}, err
	}
	linked, err := s.linkedOrgs(ctx, c)
	if err != nil {
		return HoldView{}, err
	}
	orgs := make([]uuid.UUID, 0, len(linked))
	for ep := range linked {
		orgs = append(orgs, ep)
	}
	holds, err := cl.Holds(s.as(ctx, c, RoleReadOnly, orgs...), guid)
	if err != nil {
		s.noteError(err)
		return HoldView{}, epError(err)
	}
	var hold *HoldView
	for _, v := range s.holdViews(c, holds, linked) {
		if v.ID == id {
			hold = &v
		}
	}
	switch {
	case hold == nil:
		return HoldView{}, apperr.NotFound()
	case !hold.CanRelease:
		return HoldView{}, apperr.Forbidden()
	}
	var actx context.Context
	if hold.Hold.OrganizationID == nil {
		st := s.statement(c, RoleSuperAdmin)
		st.AllOrganizations = true
		actx = WithStatement(ctx, st)
	} else {
		actx = s.as(ctx, c, RoleAdmin, *hold.Hold.OrganizationID)
	}
	h, err := cl.ReleaseHold(actx, id, c.Actor.Label)
	if err != nil {
		s.noteError(err)
		return HoldView{}, epError(err)
	}
	ev := audit.Event{Actor: c.Actor, Action: "patch.release_hold", TargetType: "update", TargetID: guid.String(), Outcome: audit.Success,
		Details: map[string]any{"update": h.Title, "reason": hold.Reason, "scope": "every organization"}}
	if hold.OrganizationID != nil {
		ev.OrganizationID, ev.Details["scope"] = *hold.OrganizationID, hold.OrganizationName
	}
	if err := s.record(ctx, []audit.Event{ev}); err != nil {
		return HoldView{}, err
	}
	out := *hold
	out.Hold, out.CanRelease = h, false
	return out, nil
}
