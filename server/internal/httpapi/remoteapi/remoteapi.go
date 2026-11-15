// Package remoteapi exposes devices and remote sessions.
package remoteapi

import (
	"net/http"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/remote"
)

// API serves the device and remote-session routes.
type API struct {
	svc *remote.Service
}

// New builds the API.
func New(svc *remote.Service) *API { return &API{svc: svc} }

// Register mounts the routes. Every route requires a fully signed-in session.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/devices", a.list)
	r("GET /api/v1/devices/{id}", a.get)
	r("POST /api/v1/devices/{id}/remote-sessions", a.startSession)
	r("GET /api/v1/remote-access/status", a.status)
}

func (a *API) list(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.QueryID(r, "organizationId")
	if err != nil {
		return err
	}
	site, err := httpapi.QueryID(r, "siteId")
	if err != nil {
		return err
	}
	q := r.URL.Query()
	items, err := a.svc.ListDevices(r.Context(), httpapi.Caller(r), remote.DeviceQuery{
		OrganizationID: org, SiteID: site, Search: q.Get("q"), Status: q.Get("status"),
	})
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[*remote.Device]{Items: items})
	return nil
}

func (a *API) get(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	d, err := a.svc.GetDevice(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, d)
	return nil
}

type sessionRequest struct {
	Kind remote.Kind `json:"kind"`
}

func (a *API) startSession(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in sessionRequest
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	ident := httpapi.IdentityFrom(r.Context())
	l, err := a.svc.StartSession(r.Context(), httpapi.Caller(r), ident.Session.ID, id, in.Kind)
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusCreated, l)
	return nil
}

func (a *API) status(w http.ResponseWriter, r *http.Request) error {
	if !httpapi.Can(r, rbac.PermSettingsManage, rbac.Resource{}) {
		return apperr.Forbidden()
	}
	httpapi.WriteJSON(w, http.StatusOK, a.svc.Status(r.Context()))
	return nil
}
