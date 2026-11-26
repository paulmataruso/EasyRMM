// Package agentfilesapi exposes the hash list of everything the server hands
// out or the agents install (Settings, "Agent files"), and a device's
// Defender exclusion state with its installed-file hashes (ADR-0070).
package agentfilesapi

import (
	"net/http"

	"github.com/paulmataruso/easyrmm/server/internal/agentfiles"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// API serves the routes.
type API struct{ files *agentfiles.Service }

// New builds the API.
func New(f *agentfiles.Service) *API { return &API{files: f} }

// Register mounts the routes. Each requires a fully signed-in session; the
// service checks permissions.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/settings/agent-files", a.list)
	r("POST /api/v1/settings/agent-files/refresh", a.refresh)
	r("GET /api/v1/devices/{id}/defender", a.device)
}

type listing struct {
	Entries []agentfiles.Entry `json:"entries"`
	// CanRefresh: the caller holds settings.manage, which Refresh needs.
	CanRefresh bool `json:"canRefresh"`
}

func (a *API) list(w http.ResponseWriter, r *http.Request) error {
	c := httpapi.Caller(r)
	e, err := a.files.List(r.Context(), c)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, listing{Entries: e, CanRefresh: c.CanGlobal(rbac.PermSettingsManage)})
	return nil
}

func (a *API) refresh(w http.ResponseWriter, r *http.Request) error {
	c := httpapi.Caller(r)
	e, err := a.files.RefreshNow(r.Context(), c)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, listing{Entries: e, CanRefresh: true})
	return nil
}

func (a *API) device(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	v, err := a.files.ForDevice(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, v)
	return nil
}
