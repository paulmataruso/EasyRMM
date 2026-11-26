// Package modulesapi exposes the Windows management framework to the
// console (ADR-0073): a device's roles, and the per-organization and
// per-site module toggles.
package modulesapi

import (
	"net/http"

	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
)

// API serves the routes.
type API struct {
	svc *modules.Service
}

// New builds the API.
func New(svc *modules.Service) *API { return &API{svc: svc} }

// Register mounts the routes. Every route requires a fully signed-in
// session; the service checks each permission.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/devices/{id}/roles", a.roles)
	r("POST /api/v1/devices/{id}/roles/rescan", a.rescan)
	r("GET /api/v1/organizations/{id}/windows-modules", a.list(modules.AtOrganization))
	r("PUT /api/v1/organizations/{id}/windows-modules/{module}", a.set(modules.AtOrganization))
	r("GET /api/v1/sites/{id}/windows-modules", a.list(modules.AtSite))
	r("PUT /api/v1/sites/{id}/windows-modules/{module}", a.set(modules.AtSite))
	r("DELETE /api/v1/sites/{id}/windows-modules/{module}", a.clear)
}

func (a *API) roles(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	out, err := a.svc.Roles(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) rescan(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.RequestRescan(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusAccepted)
	return nil
}

func (a *API) list(l modules.Level) httpapi.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		id, err := httpapi.PathID(r)
		if err != nil {
			return err
		}
		out, err := a.svc.Settings(r.Context(), httpapi.Caller(r), l, id)
		if err != nil {
			return err
		}
		httpapi.WriteJSON(w, http.StatusOK, out)
		return nil
	}
}

// enabledBody is what turning a module on or off takes.
type enabledBody struct {
	Enabled *bool `json:"enabled"`
}

func (a *API) set(l modules.Level) httpapi.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		id, err := httpapi.PathID(r)
		if err != nil {
			return err
		}
		var in enabledBody
		if err := httpapi.DecodeJSON(w, r, &in); err != nil {
			return err
		}
		if in.Enabled == nil {
			return httpapi.Validation(map[string]string{"enabled": "is required"})
		}
		if err := a.svc.SetEnabled(r.Context(), httpapi.Caller(r), l, id, modules.Module(r.PathValue("module")), *in.Enabled); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}

func (a *API) clear(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.ClearOverride(r.Context(), httpapi.Caller(r), id, modules.Module(r.PathValue("module"))); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
