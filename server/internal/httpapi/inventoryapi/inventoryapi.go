// Package inventoryapi exposes device inventory, metrics and the fleet
// software search to the console (ADR-0018).
package inventoryapi

import (
	"net/http"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/inventory"
)

// API serves the inventory routes.
type API struct {
	svc *inventory.Service
}

// New builds the API.
func New(svc *inventory.Service) *API { return &API{svc: svc} }

// Register mounts the routes. Every route requires a fully signed-in session.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/devices/{id}/inventory", a.device)
	r("GET /api/v1/devices/{id}/software", a.deviceSoftware)
	r("GET /api/v1/devices/{id}/metrics", a.history)
	r("GET /api/v1/software", a.search)
	r("GET /api/v1/software/devices", a.softwareDevices)
}

func (a *API) device(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	out, err := a.svc.Get(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) deviceSoftware(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	items, err := a.svc.Software(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[agentproto.Package]{Items: items})
	return nil
}

func (a *API) history(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	rng := r.URL.Query().Get("range")
	if rng == "" {
		rng = "24h"
	}
	out, err := a.svc.History(r.Context(), httpapi.Caller(r), id, rng)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) search(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.QueryID(r, "organizationId")
	if err != nil {
		return err
	}
	site, err := httpapi.QueryID(r, "siteId")
	if err != nil {
		return err
	}
	out, err := a.svc.SearchSoftware(r.Context(), httpapi.Caller(r), inventory.SoftwareQuery{
		Search: r.URL.Query().Get("q"), OrganizationID: org, SiteID: site,
	})
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) softwareDevices(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.QueryID(r, "organizationId")
	if err != nil {
		return err
	}
	site, err := httpapi.QueryID(r, "siteId")
	if err != nil {
		return err
	}
	q := r.URL.Query()
	query := inventory.SoftwareDevicesQuery{Name: q.Get("name"), OrganizationID: org, SiteID: site}
	if q.Has("version") {
		v := q.Get("version")
		query.Version = &v
	}
	items, err := a.svc.SoftwareDevices(r.Context(), httpapi.Caller(r), query)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[inventory.SoftwareDevice]{Items: items})
	return nil
}
