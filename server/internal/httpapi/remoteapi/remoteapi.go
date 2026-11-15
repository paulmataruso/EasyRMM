// Package remoteapi exposes remote sessions and the remote-access status.
package remoteapi

import (
	"net/http"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/remote"
)

// API serves the remote-session routes.
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
	r("POST /api/v1/devices/{id}/remote-sessions", a.startSession)
	r("GET /api/v1/remote-access/status", a.status)
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
