// Package complianceapi exposes the compliance engine's read side and the
// scan to the console (ADR-0078, slice C1): the control library, the
// packs and profiles, starting a scan and reading its results. The fix
// queue and the results screens are slice C2.
package complianceapi

import (
	"net/http"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/engine"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/fix"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/packs"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// API serves the compliance routes.
type API struct {
	svc *engine.Service
	fix *fix.Service
}

// New builds the API.
func New(svc *engine.Service, fixes *fix.Service) *API { return &API{svc: svc, fix: fixes} }

// Register mounts the routes. Every route requires a fully signed-in
// session; the service checks each permission in the organization.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/compliance/controls", a.controls)
	r("GET /api/v1/compliance/profiles", a.profiles)
	r("GET /api/v1/compliance/content", a.content)
	r("GET /api/v1/organizations/{id}/compliance/packs", a.packs)
	r("GET /api/v1/organizations/{id}/compliance/settings", a.getSettings)
	r("PUT /api/v1/organizations/{id}/compliance/settings", a.putSettings)
	r("GET /api/v1/organizations/{id}/compliance/scans", a.scans)
	r("POST /api/v1/organizations/{id}/compliance/scans", a.startScan)
	r("GET /api/v1/organizations/{id}/compliance/scans/{scanId}", a.scan)
	r("GET /api/v1/organizations/{id}/compliance/frameworks/{key}", a.framework)
	r("GET /api/v1/devices/{id}/compliance", a.deviceResults)
	a.registerFix(r)
}

func (a *API) controls(w http.ResponseWriter, r *http.Request) error {
	p := r.URL.Query().Get("platform")
	if p != "" && p != "windows" && p != "linux" {
		return apperr.Invalid("platform", "Choose windows or linux.")
	}
	items, err := a.svc.Controls(r.Context(), httpapi.Caller(r), p)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[engine.ControlInfo]{Items: items})
	return nil
}

func (a *API) profiles(w http.ResponseWriter, r *http.Request) error {
	items, err := a.svc.Profiles(r.Context(), httpapi.Caller(r))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[engine.ProfileInfo]{Items: items})
	return nil
}

// content says what the loader did with each content file; it is for
// whoever administers packs.
func (a *API) content(w http.ResponseWriter, r *http.Request) error {
	if err := httpapi.Caller(r).RequireGlobal(rbac.PermComplianceAdmin); err != nil {
		return err
	}
	items := a.svc.LoadReport()
	if items == nil {
		items = []packs.Status{}
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[packs.Status]{Items: items})
	return nil
}

func (a *API) packs(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	items, err := a.svc.Packs(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[engine.PackInfo]{Items: items})
	return nil
}

func (a *API) getSettings(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	out, err := a.svc.GetSettings(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) putSettings(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in engine.Settings
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	out, err := a.svc.PutSettings(r.Context(), httpapi.Caller(r), id, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) scans(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	limit, err := httpapi.QueryInt(r, "limit", 20, 1, 100)
	if err != nil {
		return err
	}
	items, err := a.svc.Scans(r.Context(), httpapi.Caller(r), id, int(limit))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[engine.Scan]{Items: items})
	return nil
}

func (a *API) startScan(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in engine.ScanInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	out, err := a.svc.StartScan(r.Context(), httpapi.Caller(r), id, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, out)
	return nil
}

func (a *API) scan(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	sid, err := httpapi.PathUUID(r, "scanId")
	if err != nil {
		return err
	}
	out, err := a.svc.Scan(r.Context(), httpapi.Caller(r), id, sid)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) framework(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	out, err := a.svc.Framework(r.Context(), httpapi.Caller(r), id, r.PathValue("key"))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) deviceResults(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	items, err := a.svc.DeviceResults(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[engine.DeviceResult]{Items: items})
	return nil
}
