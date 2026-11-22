// Package docsapi exposes the customer record's contacts and places
// (ADR-0066). An organization's and a site's own details are tenancyapi's.
package docsapi

import (
	"net/http"

	"github.com/paulmataruso/easyrmm/server/internal/docs"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

// API serves the documentation routes.
type API struct{ svc *docs.Service }

// New builds the API.
func New(svc *docs.Service) *API { return &API{svc: svc} }

// Register mounts the routes. Every route requires a fully signed-in session.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/organizations/{id}/contacts", a.listContacts)
	r("POST /api/v1/organizations/{id}/contacts", a.createContact)
	r("PATCH /api/v1/contacts/{id}", a.updateContact)
	r("DELETE /api/v1/contacts/{id}", a.deleteContact)

	r("GET /api/v1/sites/{id}/places", a.listPlaces)
	r("POST /api/v1/sites/{id}/places", a.createPlace)
	r("PATCH /api/v1/places/{id}", a.updatePlace)
	r("DELETE /api/v1/places/{id}", a.deletePlace)
}

func (a *API) listContacts(w http.ResponseWriter, r *http.Request) error {
	orgID, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	siteID, err := httpapi.QueryID(r, "siteId")
	if err != nil {
		return err
	}
	limit, err := httpapi.QueryCount(r, "limit", 200, 1, docs.MaxContactsAtLevel)
	if err != nil {
		return err
	}
	items, next, err := a.svc.ListContacts(r.Context(), httpapi.Caller(r), orgID,
		docs.ContactQuery{SiteID: siteID, After: r.URL.Query().Get("after"), Limit: limit})
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[docs.Contact]{Items: items, Next: next})
	return nil
}

func (a *API) createContact(w http.ResponseWriter, r *http.Request) error {
	orgID, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in docs.ContactInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	x, err := a.svc.CreateContact(r.Context(), httpapi.Caller(r), orgID, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, x)
	return nil
}

func (a *API) updateContact(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in docs.ContactPatch
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	x, err := a.svc.UpdateContact(r.Context(), httpapi.Caller(r), id, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, x)
	return nil
}

func (a *API) deleteContact(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.DeleteContact(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) listPlaces(w http.ResponseWriter, r *http.Request) error {
	siteID, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	items, err := a.svc.ListPlaces(r.Context(), httpapi.Caller(r), siteID)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[docs.Place]{Items: items})
	return nil
}

func (a *API) createPlace(w http.ResponseWriter, r *http.Request) error {
	siteID, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in docs.PlaceInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	p, err := a.svc.CreatePlace(r.Context(), httpapi.Caller(r), siteID, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, p)
	return nil
}

func (a *API) updatePlace(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in docs.PlacePatch
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	p, err := a.svc.UpdatePlace(r.Context(), httpapi.Caller(r), id, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, p)
	return nil
}

func (a *API) deletePlace(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.DeletePlace(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
