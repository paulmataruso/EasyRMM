// Package easypatchapi serves patching: the patching engine's state and
// EasyRMM's links to it, for super administrators, and the patch views and
// actions of the console.
package easypatchapi

import (
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// API serves patching.
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
	settings("POST /api/v1/settings/easypatch/check", a.checkConnection)
	settings("GET /api/v1/settings/easypatch/organizations", a.organizations)
	settings("PATCH /api/v1/settings/easypatch/organizations/{id}", a.updateOrganization)
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
	r("GET /api/v1/patching/scope", a.scope)
	r("POST /api/v1/patching/install/plan", a.planInstall)
	r("POST /api/v1/patching/install", a.install)
	r("POST /api/v1/patching/restart/plan", a.planRestart)
	r("POST /api/v1/patching/restart", a.restart)
	r("POST /api/v1/patching/agent-install", a.installAgent)
	r("POST /api/v1/patching/stop", a.stopPatching)
	r("POST /api/v1/patching/allow", a.allowPatching)
	r("POST /api/v1/patching/endpoints/{id}/remove", a.removeEndpoint)
	// A device's Patches tab.
	r("GET /api/v1/patching/devices/{id}/install-preview", a.installPreview)
	r("POST /api/v1/patching/devices/{id}/exclusions", a.exclude)
	r("DELETE /api/v1/patching/devices/{id}/exclusions/{update}", a.include)
	r("POST /api/v1/patching/devices/{id}/updates/{update}/remove", a.removeUpdate)
	r("GET /api/v1/patching/messages", a.messagePresets)
	r("POST /api/v1/patching/notify", a.notify)
	r("POST /api/v1/patching/agent-update", a.updateAgent)
	// Patching → Updates.
	r("GET /api/v1/patching/updates", a.catalog)
	r("GET /api/v1/patching/updates/{update}", a.update)
	r("GET /api/v1/patching/updates/{update}/devices", a.updateDevices)
	r("POST /api/v1/patching/updates/{update}/install", a.installUpdate)
	r("POST /api/v1/patching/updates/{update}/remove", a.removeFromDevices)
	r("POST /api/v1/patching/updates/{update}/holds", a.holdUpdate)
	r("POST /api/v1/patching/updates/{update}/holds/{id}/release", a.releaseHold)
	a.registerPolicies(r)
	a.registerReports(r)
	a.registerSettings(r)
	a.registerAlerts(r)
	// Where a link in one of the engine's messages opens the console.
	r("GET /api/v1/patching/from-easypatch/{kind}/{id}", a.fromEasyPatch)
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

func (a *API) checkConnection(w http.ResponseWriter, r *http.Request) error {
	c, err := a.svc.CheckConnection(r.Context())
	return ok(w, c, err)
}

func (a *API) organizations(w http.ResponseWriter, r *http.Request) error {
	o, err := a.svc.Organizations(r.Context())
	return ok(w, o, err)
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
	if q.DeviceID, err = httpapi.QueryID(r, "deviceId"); err != nil {
		return err
	}
	v := r.URL.Query()
	switch v.Get("active") {
	case "", "false":
	case "true":
		q.Active = true
	default:
		return apperr.Invalid("active", "must be true or false")
	}
	q.Status, q.Type, q.Trigger = v.Get("status"), v.Get("type"), v.Get("trigger")
	for name, t := range map[string]**time.Time{"from": &q.From, "to": &q.To} {
		if raw := v.Get(name); raw != "" {
			at, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				return apperr.Invalid(name, "Give a time as in 2026-11-18T09:00:00Z.")
			}
			*t = &at
		}
	}
	list, err := a.svc.Jobs(r.Context(), httpapi.Caller(r), q)
	return ok(w, list, err)
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
	var in easypatch.RestartPlanInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	p, err := a.svc.PlanRestart(r.Context(), httpapi.Caller(r), in)
	return ok(w, p, err)
}

func (a *API) scope(w http.ResponseWriter, r *http.Request) error {
	var q easypatch.ScopeQuery
	var err error
	if q.OrganizationID, err = httpapi.QueryID(r, "organizationId"); err != nil {
		return err
	}
	if q.SiteID, err = httpapi.QueryID(r, "siteId"); err != nil {
		return err
	}
	v, err := a.svc.Scope(r.Context(), httpapi.Caller(r), q)
	return ok(w, v, err)
}

func (a *API) planInstall(w http.ResponseWriter, r *http.Request) error {
	var in easypatch.AvailableInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	p, err := a.svc.PlanAvailable(r.Context(), httpapi.Caller(r), in)
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

func (a *API) scan(w http.ResponseWriter, r *http.Request) error {
	var in easypatch.ActionInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	res, err := a.svc.Scan(r.Context(), httpapi.Caller(r), in)
	return ok(w, res, err)
}

func (a *API) install(w http.ResponseWriter, r *http.Request) error {
	var in easypatch.InstallInput
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

func (a *API) removeEndpoint(w http.ResponseWriter, r *http.Request) error {
	id, err := parseID(r.PathValue("id"), "id")
	if err != nil {
		return err
	}
	e, err := a.svc.RemoveEndpoint(r.Context(), httpapi.Caller(r), id)
	return ok(w, e, err)
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

// updateScope reads the organizationId and siteId a catalog view counts in.
func updateScope(r *http.Request) (easypatch.UpdateScope, error) {
	var sc easypatch.UpdateScope
	var err error
	if sc.OrganizationID, err = httpapi.QueryID(r, "organizationId"); err != nil {
		return sc, err
	}
	sc.SiteID, err = httpapi.QueryID(r, "siteId")
	return sc, err
}

func (a *API) catalog(w http.ResponseWriter, r *http.Request) error {
	sc, err := updateScope(r)
	if err != nil {
		return err
	}
	q := r.URL.Query()
	in := easypatch.CatalogQuery{Category: q.Get("category"), State: q.Get("state"), Search: q.Get("q"), Sort: q.Get("sort"), Desc: q.Get("dir") != "asc"}
	switch q.Get("knownExploited") {
	case "true", "false":
		v := q.Get("knownExploited") == "true"
		in.KnownExploited = &v
	case "":
	default:
		return apperr.Invalid("knownExploited", "must be true or false")
	}
	if in.Page, err = page(r); err != nil {
		return err
	}
	p, err := a.svc.Catalog(r.Context(), httpapi.Caller(r), sc, in)
	return ok(w, p, err)
}

func (a *API) update(w http.ResponseWriter, r *http.Request) error {
	guid, err := httpapi.PathUUID(r, "update")
	if err != nil {
		return err
	}
	sc, err := updateScope(r)
	if err != nil {
		return err
	}
	v, err := a.svc.Update(r.Context(), httpapi.Caller(r), guid, sc)
	return ok(w, v, err)
}

func (a *API) updateDevices(w http.ResponseWriter, r *http.Request) error {
	guid, err := httpapi.PathUUID(r, "update")
	if err != nil {
		return err
	}
	sc, err := updateScope(r)
	if err != nil {
		return err
	}
	p, err := page(r)
	if err != nil {
		return err
	}
	list, err := a.svc.UpdateDevices(r.Context(), httpapi.Caller(r), guid, sc, r.URL.Query().Get("state"), p)
	return ok(w, list, err)
}

func (a *API) installUpdate(w http.ResponseWriter, r *http.Request) error {
	guid, err := httpapi.PathUUID(r, "update")
	if err != nil {
		return err
	}
	var in easypatch.FleetActionInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	res, err := a.svc.InstallUpdate(r.Context(), httpapi.Caller(r), guid, in)
	return ok(w, res, err)
}

func (a *API) removeFromDevices(w http.ResponseWriter, r *http.Request) error {
	guid, err := httpapi.PathUUID(r, "update")
	if err != nil {
		return err
	}
	var in easypatch.FleetActionInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	res, err := a.svc.RemoveUpdateFromDevices(r.Context(), httpapi.Caller(r), guid, in)
	return ok(w, res, err)
}

func (a *API) holdUpdate(w http.ResponseWriter, r *http.Request) error {
	guid, err := httpapi.PathUUID(r, "update")
	if err != nil {
		return err
	}
	var in easypatch.HoldInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	h, err := a.svc.HoldUpdate(r.Context(), httpapi.Caller(r), guid, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, h)
	return nil
}

func (a *API) releaseHold(w http.ResponseWriter, r *http.Request) error {
	guid, err := httpapi.PathUUID(r, "update")
	if err != nil {
		return err
	}
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	h, err := a.svc.ReleaseHold(r.Context(), httpapi.Caller(r), guid, id)
	return ok(w, h, err)
}
