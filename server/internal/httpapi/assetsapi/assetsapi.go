// Package assetsapi exposes the asset record (ADR-0066, slice 2): assets at
// an organization, a site or a device group, a device's asset, and an
// organization's age policy.
package assetsapi

import (
	"net/http"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/assets"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

// API serves the asset routes.
type API struct{ svc *assets.Service }

// New builds the API.
func New(svc *assets.Service) *API { return &API{svc: svc} }

// Register mounts the routes. Every route requires a fully signed-in session.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/organizations/{id}/assets", a.list)
	r("POST /api/v1/organizations/{id}/assets", a.create)
	r("GET /api/v1/organizations/{id}/asset-policy", a.getPolicy)
	r("PUT /api/v1/organizations/{id}/asset-policy", a.setPolicy)
	r("GET /api/v1/assets/{id}", a.get)
	r("PATCH /api/v1/assets/{id}", a.update)
	r("DELETE /api/v1/assets/{id}", a.delete)
	r("GET /api/v1/devices/{id}/asset", a.forDevice)
	r("POST /api/v1/devices/{id}/asset", a.createForDevice)
}

// listResponse is a page of assets and how many match in all.
type listResponse struct {
	Items []assets.Asset `json:"items"`
	Total int            `json:"total"`
}

func (a *API) list(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var q assets.Query
	if q.SiteID, err = httpapi.QueryID(r, "siteId"); err != nil {
		return err
	}
	if q.GroupID, err = httpapi.QueryID(r, "groupId"); err != nil {
		return err
	}
	if q.Limit, err = httpapi.QueryCount(r, "limit", 50, 1, assets.MaxLimit); err != nil {
		return err
	}
	if q.Offset, err = httpapi.QueryCount(r, "offset", 0, 0, 1_000_000); err != nil {
		return err
	}
	v := r.URL.Query()
	q.Kind, q.Status, q.Search, q.Warranty, q.Age, q.Sort = v.Get("kind"), v.Get("status"), v.Get("q"), v.Get("warranty"), v.Get("age"), v.Get("sort")
	switch v.Get("dir") {
	case "", "asc":
	case "desc":
		q.Desc = true
	default:
		return apperr.Invalid("dir", "Use asc or desc.")
	}
	items, total, err := a.svc.List(r.Context(), httpapi.Caller(r), org, q)
	if err != nil {
		return err
	}
	if items == nil {
		items = []assets.Asset{}
	}
	httpapi.WriteJSON(w, http.StatusOK, listResponse{Items: items, Total: total})
	return nil
}

func (a *API) create(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in assets.Input
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	x, err := a.svc.Create(r.Context(), httpapi.Caller(r), org, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, x)
	return nil
}

func (a *API) get(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	x, err := a.svc.Get(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, x)
	return nil
}

func (a *API) update(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in assets.Patch
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	x, err := a.svc.Update(r.Context(), httpapi.Caller(r), id, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, x)
	return nil
}

func (a *API) delete(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.Delete(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) forDevice(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	x, err := a.svc.ForDevice(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, x)
	return nil
}

func (a *API) createForDevice(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	x, err := a.svc.CreateForDevice(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, x)
	return nil
}

func (a *API) getPolicy(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	p, err := a.svc.GetPolicy(r.Context(), httpapi.Caller(r), org)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, p)
	return nil
}

func (a *API) setPolicy(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in assets.AgePolicy
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	p, err := a.svc.SetPolicy(r.Context(), httpapi.Caller(r), org, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, p)
	return nil
}
