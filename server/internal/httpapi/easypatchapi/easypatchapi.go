// Package easypatchapi serves the EasyPatch connector (ADR-0030): its
// settings, for super administrators, and the patch views and actions of
// the console.
package easypatchapi

import (
	"net/http"
	"net/url"
	"slices"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// API serves the connector.
type API struct{ svc *easypatch.Service }

// New builds the API.
func New(svc *easypatch.Service) *API { return &API{svc: svc} }

// Register adds the routes.
func (a *API) Register(mux *http.ServeMux) {
	settings := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(func(w http.ResponseWriter, r *http.Request) error {
			if !httpapi.Can(r, rbac.PermSettingsManage, rbac.Resource{}) {
				return apperr.Forbidden()
			}
			return h(w, r)
		})))
	}
	settings("GET /api/v1/settings/easypatch", a.connection)
	settings("PUT /api/v1/settings/easypatch", a.updateConnection)
	settings("DELETE /api/v1/settings/easypatch", a.deleteConnection)
	settings("POST /api/v1/settings/easypatch/check", a.checkConnection)
	settings("GET /api/v1/settings/easypatch/organizations", a.organizations)
	settings("PUT /api/v1/settings/easypatch/organizations/{id}", a.linkOrganization)
	settings("PATCH /api/v1/settings/easypatch/organizations/{id}", a.updateOrganization)
	settings("DELETE /api/v1/settings/easypatch/organizations/{id}", a.unlinkOrganization)
	settings("GET /api/v1/settings/easypatch/devices", a.deviceLinks)
	settings("GET /api/v1/settings/easypatch/sync", a.sync)

	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/patching", a.status)
	r("GET /api/v1/patching/devices", a.fleet)
	r("GET /api/v1/patching/devices/{id}", a.device)
	r("GET /api/v1/patching/devices/{id}/updates", a.updates)
	r("GET /api/v1/patching/devices/{id}/installed", a.installed)
	r("GET /api/v1/patching/devices/{id}/history", a.history)
	r("GET /api/v1/patching/devices/{id}/jobs", a.deviceJobs)
	r("GET /api/v1/patching/jobs", a.jobs)
	r("GET /api/v1/patching/jobs/{id}", a.job)
	r("POST /api/v1/patching/jobs/{id}/cancel", a.cancelJob)
	r("POST /api/v1/patching/jobs/{id}/retry", a.retryJob)
	r("POST /api/v1/patching/scan", a.scan)
	r("POST /api/v1/patching/install", a.install)
	r("POST /api/v1/patching/restart/plan", a.planRestart)
	r("POST /api/v1/patching/restart", a.restart)
	r("POST /api/v1/patching/agent-install", a.installAgent)
	r("POST /api/v1/patching/stop", a.stopPatching)
	r("POST /api/v1/patching/allow", a.allowPatching)
	// A device's Patches tab (one-product plan, C1).
	r("GET /api/v1/patching/devices/{id}/install-preview", a.installPreview)
	r("POST /api/v1/patching/devices/{id}/exclusions", a.exclude)
	r("DELETE /api/v1/patching/devices/{id}/exclusions/{update}", a.include)
	r("POST /api/v1/patching/devices/{id}/updates/{update}/remove", a.removeUpdate)
	r("GET /api/v1/patching/messages", a.messagePresets)
	r("POST /api/v1/patching/notify", a.notify)
	r("POST /api/v1/patching/agent-update", a.updateAgent)
	// The product switch: for anyone signed in, it says whether to show it.
	r("GET /api/v1/patching/switch", a.productSwitch)
	// Where a link from EasyPatch opens the console.
	r("GET /api/v1/patching/from-easypatch/{kind}/{id}", a.fromEasyPatch)

	// A browser link, not an API call: it answers with a redirect.
	mux.Handle("GET /go/to-easypatch", httpapi.Handle(a.goToEasyPatch))
}

func ok(w http.ResponseWriter, v any, err error) error {
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, v)
	return nil
}

func (a *API) connection(w http.ResponseWriter, r *http.Request) error {
	c, err := a.svc.Connection(r.Context())
	return ok(w, c, err)
}

func (a *API) updateConnection(w http.ResponseWriter, r *http.Request) error {
	var in easypatch.ConnectionInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	c, err := a.svc.UpdateConnection(r.Context(), httpapi.Actor(r), in)
	return ok(w, c, err)
}

func (a *API) deleteConnection(w http.ResponseWriter, r *http.Request) error {
	if err := a.svc.DeleteConnection(r.Context(), httpapi.Actor(r)); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) checkConnection(w http.ResponseWriter, r *http.Request) error {
	c, err := a.svc.CheckConnection(r.Context())
	return ok(w, c, err)
}

func (a *API) organizations(w http.ResponseWriter, r *http.Request) error {
	o, err := a.svc.Organizations(r.Context())
	return ok(w, o, err)
}

func (a *API) linkOrganization(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in struct {
		EasyPatchID string `json:"easyPatchId"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	ep, err := parseID(in.EasyPatchID, "easyPatchId")
	if err != nil {
		return err
	}
	if err := a.svc.LinkOrganization(r.Context(), httpapi.Actor(r), id, ep); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) updateOrganization(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in struct {
		AutoInstall *bool `json:"autoInstall"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	if in.AutoInstall == nil {
		return apperr.Invalid("autoInstall", "must be true or false")
	}
	if err := a.svc.SetAutoInstall(r.Context(), httpapi.Actor(r), id, *in.AutoInstall); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) unlinkOrganization(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.UnlinkOrganization(r.Context(), httpapi.Actor(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) deviceLinks(w http.ResponseWriter, r *http.Request) error {
	l, err := a.svc.DeviceLinks(r.Context())
	return ok(w, map[string]any{"items": l}, err)
}

func (a *API) status(w http.ResponseWriter, r *http.Request) error {
	s, err := a.svc.Status(r.Context(), httpapi.Caller(r))
	return ok(w, s, err)
}

func (a *API) fleet(w http.ResponseWriter, r *http.Request) error {
	var q easypatch.FleetQuery
	var err error
	if q.OrganizationID, err = httpapi.QueryID(r, "organizationId"); err != nil {
		return err
	}
	if q.SiteID, err = httpapi.QueryID(r, "siteId"); err != nil {
		return err
	}
	if q.GroupID, err = httpapi.QueryID(r, "groupId"); err != nil {
		return err
	}
	q.Compliance, q.Search = r.URL.Query().Get("compliance"), r.URL.Query().Get("q")
	f, err := a.svc.Fleet(r.Context(), httpapi.Caller(r), q)
	return ok(w, f, err)
}

func (a *API) device(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	d, err := a.svc.Device(r.Context(), httpapi.Caller(r), id)
	return ok(w, d, err)
}

func (a *API) updates(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	list, err := a.svc.Updates(r.Context(), httpapi.Caller(r), id, r.URL.Query().Get("state"))
	return ok(w, map[string]any{"items": list}, err)
}

func (a *API) installed(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	list, err := a.svc.InstalledUpdates(r.Context(), httpapi.Caller(r), id)
	return ok(w, map[string]any{"items": list}, err)
}

func page(r *http.Request) (int, error) {
	return httpapi.QueryCount(r, "page", 1, 1, 10000)
}

func (a *API) history(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	p, err := page(r)
	if err != nil {
		return err
	}
	h, err := a.svc.History(r.Context(), httpapi.Caller(r), id, p)
	return ok(w, h, err)
}

func (a *API) deviceJobs(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	p, err := page(r)
	if err != nil {
		return err
	}
	j, err := a.svc.DeviceJobs(r.Context(), httpapi.Caller(r), id, p)
	return ok(w, j, err)
}

func (a *API) jobs(w http.ResponseWriter, r *http.Request) error {
	var q easypatch.JobsQuery
	var err error
	if q.OrganizationID, err = httpapi.QueryID(r, "organizationId"); err != nil {
		return err
	}
	switch r.URL.Query().Get("active") {
	case "", "false":
	case "true":
		q.Active = true
	default:
		return apperr.Invalid("active", "must be true or false")
	}
	list, err := a.svc.Jobs(r.Context(), httpapi.Caller(r), q)
	return ok(w, map[string]any{"items": list}, err)
}

func (a *API) job(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	j, err := a.svc.Job(r.Context(), httpapi.Caller(r), id)
	return ok(w, j, err)
}

func (a *API) cancelJob(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	j, err := a.svc.CancelJob(r.Context(), httpapi.Caller(r), id)
	return ok(w, j, err)
}

func (a *API) retryJob(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	j, err := a.svc.RetryJob(r.Context(), httpapi.Caller(r), id)
	return ok(w, j, err)
}

func (a *API) planRestart(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		DeviceIDs []uuid.UUID `json:"deviceIds"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	p, err := a.svc.PlanRestart(r.Context(), httpapi.Caller(r), in.DeviceIDs)
	return ok(w, p, err)
}

func (a *API) restart(w http.ResponseWriter, r *http.Request) error {
	var in easypatch.RestartInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	res, err := a.svc.Restart(r.Context(), httpapi.Caller(r), in)
	return ok(w, res, err)
}

// goToEasyPatch redirects to the page of EasyPatch's console for an object
// of EasyRMM's (easypatch.GoTarget): ?device=<id>[&tab=…], ?organization=,
// ?job= (an EasyPatch job) or ?update= (an EasyPatch update), or none for
// its home page. Someone not signed in signs in first and comes back.
func (a *API) goToEasyPatch(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Cache-Control", "no-store")
	if id := httpapi.IdentityFrom(r.Context()); id == nil || id.Session.State != auth.StateActive {
		http.Redirect(w, r, "/login?returnTo="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return nil
	}
	var t easypatch.GoTarget
	var err error
	named := 0
	for _, p := range []struct {
		name string
		to   *uuid.UUID
	}{{"device", &t.DeviceID}, {"organization", &t.OrganizationID}, {"site", &t.SiteID}, {"job", &t.JobID}, {"update", &t.UpdateID}} {
		if *p.to, err = httpapi.QueryID(r, p.name); err != nil {
			return err
		}
		if *p.to != uuid.Nil {
			named++
		}
	}
	if t.List = r.URL.Query().Get("list"); t.List != "" {
		if !slices.Contains(easypatch.GoLists, t.List) {
			return apperr.Invalid("list", "Choose endpoints or jobs.")
		}
		named++
	}
	if named > 1 {
		return apperr.Invalid("device", "Name one of device, organization, site, job, update or list.")
	}
	t.Tab = r.URL.Query().Get("tab")
	dest, err := a.svc.EasyPatchURL(r.Context(), httpapi.Caller(r), t)
	if err != nil {
		return err
	}
	if dest == "" { // EasyPatch is not set up
		dest = "/patching"
	}
	http.Redirect(w, r, dest, http.StatusFound)
	return nil
}

func (a *API) productSwitch(w http.ResponseWriter, r *http.Request) error {
	sw, err := a.svc.Switch(r.Context(), httpapi.Caller(r))
	return ok(w, sw, err)
}

func (a *API) scan(w http.ResponseWriter, r *http.Request) error {
	var in easypatch.ActionInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	res, err := a.svc.Scan(r.Context(), httpapi.Caller(r), in)
	return ok(w, res, err)
}

func (a *API) install(w http.ResponseWriter, r *http.Request) error {
	var in easypatch.ActionInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	res, err := a.svc.Install(r.Context(), httpapi.Caller(r), in)
	return ok(w, res, err)
}

func (a *API) installAgent(w http.ResponseWriter, r *http.Request) error {
	var in easypatch.ActionInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	res, err := a.svc.InstallAgent(r.Context(), httpapi.Caller(r), in)
	return ok(w, res, err)
}

func (a *API) stopPatching(w http.ResponseWriter, r *http.Request) error {
	var in easypatch.ActionInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	res, err := a.svc.StopPatching(r.Context(), httpapi.Caller(r), in)
	return ok(w, res, err)
}

func (a *API) allowPatching(w http.ResponseWriter, r *http.Request) error {
	var in easypatch.ActionInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	res, err := a.svc.AllowPatching(r.Context(), httpapi.Caller(r), in)
	return ok(w, res, err)
}

func (a *API) sync(w http.ResponseWriter, r *http.Request) error {
	st, err := a.svc.Sync(r.Context())
	return ok(w, st, err)
}

func parseID(s, field string) (uuid.UUID, error) {
	id, err := uuid.Parse(s)
	if err != nil || id == uuid.Nil {
		return uuid.Nil, apperr.Invalid(field, "must be an id")
	}
	return id, nil
}

func (a *API) fromEasyPatch(w http.ResponseWriter, r *http.Request) error {
	kind := r.PathValue("kind")
	if !slices.Contains(easypatch.FromKinds, kind) {
		return apperr.NotFound()
	}
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	l, err := a.svc.FromEasyPatch(r.Context(), httpapi.Caller(r), kind, id)
	return ok(w, l, err)
}

func (a *API) installPreview(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var updates []uuid.UUID
	for _, v := range r.URL.Query()["updateId"] {
		u, err := parseID(v, "updateId")
		if err != nil {
			return err
		}
		updates = append(updates, u)
	}
	p, err := a.svc.InstallPreview(r.Context(), httpapi.Caller(r), id, updates)
	return ok(w, p, err)
}

func (a *API) exclude(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in easypatch.ExclusionInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	if err := a.svc.Exclude(r.Context(), httpapi.Caller(r), id, in); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) include(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	update, err := httpapi.PathUUID(r, "update")
	if err != nil {
		return err
	}
	if err := a.svc.Include(r.Context(), httpapi.Caller(r), id, update); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) removeUpdate(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	update, err := httpapi.PathUUID(r, "update")
	if err != nil {
		return err
	}
	var in easypatch.RemoveInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	res, err := a.svc.RemoveUpdate(r.Context(), httpapi.Caller(r), id, update, in)
	return ok(w, res, err)
}

func (a *API) messagePresets(w http.ResponseWriter, r *http.Request) error {
	list, err := a.svc.MessagePresets(r.Context(), httpapi.Caller(r))
	return ok(w, map[string]any{"items": list}, err)
}

func (a *API) notify(w http.ResponseWriter, r *http.Request) error {
	var in easypatch.NotifyInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	res, err := a.svc.Notify(r.Context(), httpapi.Caller(r), in)
	return ok(w, res, err)
}

func (a *API) updateAgent(w http.ResponseWriter, r *http.Request) error {
	var in easypatch.ActionInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	res, err := a.svc.UpdateAgent(r.Context(), httpapi.Caller(r), in)
	return ok(w, res, err)
}
