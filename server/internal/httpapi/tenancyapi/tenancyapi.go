// Package tenancyapi exposes organizations, sites and device groups.
package tenancyapi

import (
	"net/http"

	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/tenancy"
)

// API serves the tenancy routes.
type API struct{ svc *tenancy.Service }

// New builds the API.
func New(svc *tenancy.Service) *API { return &API{svc: svc} }

// Register mounts the routes. Every route requires a fully signed-in session.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/organizations", a.listOrgs)
	r("POST /api/v1/organizations", a.createOrg)
	r("GET /api/v1/organizations/{id}", a.getOrg)
	r("PUT /api/v1/organizations/{id}", a.updateOrg)
	r("DELETE /api/v1/organizations/{id}", a.deleteOrg)
	r("GET /api/v1/organizations/{id}/sites", a.listOrgSites)
	r("POST /api/v1/organizations/{id}/sites", a.createSite)

	r("GET /api/v1/sites", a.listSites)
	r("GET /api/v1/sites/{id}", a.getSite)
	r("PUT /api/v1/sites/{id}", a.updateSite)
	r("DELETE /api/v1/sites/{id}", a.deleteSite)
	r("GET /api/v1/sites/{id}/device-groups", a.listGroups)
	r("POST /api/v1/sites/{id}/device-groups", a.createGroup)

	r("PUT /api/v1/device-groups/{id}", a.updateGroup)
	r("DELETE /api/v1/device-groups/{id}", a.deleteGroup)
}

func (a *API) listOrgs(w http.ResponseWriter, r *http.Request) error {
	items, err := a.svc.ListOrganizations(r.Context(), httpapi.Caller(r), r.URL.Query().Get("q"))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[tenancy.Organization]{Items: items})
	return nil
}

func (a *API) getOrg(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	o, err := a.svc.GetOrganization(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, o)
	return nil
}

func (a *API) createOrg(w http.ResponseWriter, r *http.Request) error {
	var in tenancy.OrganizationInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	o, err := a.svc.CreateOrganization(r.Context(), httpapi.Caller(r), in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, o)
	return nil
}

func (a *API) updateOrg(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in tenancy.OrganizationInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	o, err := a.svc.UpdateOrganization(r.Context(), httpapi.Caller(r), id, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, o)
	return nil
}

func (a *API) deleteOrg(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.DeleteOrganization(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) listOrgSites(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	c := httpapi.Caller(r)
	if _, err := a.svc.GetOrganization(r.Context(), c, id); err != nil {
		return err
	}
	items, err := a.svc.ListSites(r.Context(), c, id, r.URL.Query().Get("q"))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[tenancy.Site]{Items: items})
	return nil
}

func (a *API) listSites(w http.ResponseWriter, r *http.Request) error {
	orgID, err := httpapi.QueryID(r, "organizationId")
	if err != nil {
		return err
	}
	items, err := a.svc.ListSites(r.Context(), httpapi.Caller(r), orgID, r.URL.Query().Get("q"))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[tenancy.Site]{Items: items})
	return nil
}

func (a *API) createSite(w http.ResponseWriter, r *http.Request) error {
	orgID, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in tenancy.SiteInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	s, err := a.svc.CreateSite(r.Context(), httpapi.Caller(r), orgID, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, s)
	return nil
}

func (a *API) getSite(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	s, err := a.svc.GetSite(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, s)
	return nil
}

func (a *API) updateSite(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in tenancy.SiteInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	s, err := a.svc.UpdateSite(r.Context(), httpapi.Caller(r), id, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, s)
	return nil
}

func (a *API) deleteSite(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.DeleteSite(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) listGroups(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	items, err := a.svc.ListDeviceGroups(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[tenancy.DeviceGroup]{Items: items})
	return nil
}

func (a *API) createGroup(w http.ResponseWriter, r *http.Request) error {
	siteID, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in tenancy.DeviceGroupInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	g, err := a.svc.CreateDeviceGroup(r.Context(), httpapi.Caller(r), siteID, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, g)
	return nil
}

func (a *API) updateGroup(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in tenancy.DeviceGroupInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	g, err := a.svc.UpdateDeviceGroup(r.Context(), httpapi.Caller(r), id, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, g)
	return nil
}

func (a *API) deleteGroup(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.DeleteDeviceGroup(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
