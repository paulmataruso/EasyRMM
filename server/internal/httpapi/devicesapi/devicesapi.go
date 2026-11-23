// Package devicesapi exposes the device inventory.
package devicesapi

import (
	"net/http"

	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

// API serves the device routes.
type API struct {
	svc *devices.Service
}

// New builds the API.
func New(svc *devices.Service) *API { return &API{svc: svc} }

// Register mounts the routes. Every route requires a fully signed-in session.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/devices", a.list)
	r("GET /api/v1/devices/recent-connections", a.recent)
	r("GET /api/v1/device-tree", a.tree)
	r("GET /api/v1/devices/{id}", a.get)
}

func (a *API) tree(w http.ResponseWriter, r *http.Request) error {
	t, err := a.svc.Tree(r.Context(), httpapi.Caller(r))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, t)
	return nil
}

func (a *API) recent(w http.ResponseWriter, r *http.Request) error {
	items, err := a.svc.RecentConnections(r.Context(), httpapi.Caller(r))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[devices.RecentConnection]{Items: items})
	return nil
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
	group, err := httpapi.QueryID(r, "groupId")
	if err != nil {
		return err
	}
	q := r.URL.Query()
	items, err := a.svc.List(r.Context(), httpapi.Caller(r), devices.Query{
		OrganizationID: org, SiteID: site, GroupID: group, Ungrouped: q.Get("ungrouped") == "true", Search: q.Get("q"), Status: q.Get("status"), Hardening: q.Get("hardening"),
		DiskHealth: q.Get("diskHealth"),
	})
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[*devices.Device]{Items: items})
	return nil
}

func (a *API) get(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	d, err := a.svc.Get(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, d)
	return nil
}
