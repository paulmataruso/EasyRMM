// Package postureapi exposes a computer's security posture and the reasons
// behind its score (ADR-0082).
package postureapi

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/posture"
)

// API serves the posture routes.
type API struct{ svc *posture.Service }

// New builds the API.
func New(svc *posture.Service) *API { return &API{svc: svc} }

// Register mounts the routes. The service checks device.view on the computer,
// and org.manage in the organization for its policies.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/devices/{id}/posture", a.device)
	r("GET /api/v1/devices/{id}/posture/history", a.history)
	r("GET /api/v1/organizations/{id}/posture/policies", a.listPolicies)
	r("GET /api/v1/organizations/{id}/posture/policies/{control}", a.getPolicy)
	r("PUT /api/v1/organizations/{id}/posture/policies/{control}", a.setPolicy)
	r("DELETE /api/v1/organizations/{id}/posture/policies/{control}", a.deletePolicy)
}

func (a *API) device(w http.ResponseWriter, r *http.Request) error {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return apperr.NotFound()
	}
	d, err := a.svc.Device(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, d)
	return nil
}

func (a *API) history(w http.ResponseWriter, r *http.Request) error {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return apperr.NotFound()
	}
	days, err := httpapi.QueryInt(r, "days", posture.DefaultHistoryDays, 1, posture.MaxHistoryDays)
	if err != nil {
		return err
	}
	list, err := a.svc.History(r.Context(), httpapi.Caller(r), id, int(days))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"items": list})
	return nil
}

func (a *API) listPolicies(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	list, err := a.svc.ListPolicies(r.Context(), httpapi.Caller(r), org)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"items": list})
	return nil
}

func (a *API) getPolicy(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	p, err := a.svc.GetPolicy(r.Context(), httpapi.Caller(r), org, r.PathValue("control"))
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
	var in struct {
		Weight int `json:"weight"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	p, err := a.svc.SetPolicy(r.Context(), httpapi.Caller(r), org, r.PathValue("control"), in.Weight)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, p)
	return nil
}

func (a *API) deletePolicy(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.DeletePolicy(r.Context(), httpapi.Caller(r), org, r.PathValue("control")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
