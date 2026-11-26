// Package repairsapi exposes repairing a device's agents (ADR-0069): what a
// device's repairs are, what the one Repair button would do, and pressing it.
package repairsapi

import (
	"net/http"

	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/recovery"
)

// API serves the repair routes.
type API struct{ svc *recovery.Service }

// New builds the API.
func New(svc *recovery.Service) *API { return &API{svc: svc} }

// Register mounts the routes. Every route requires a fully signed-in
// session; the service checks permissions.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/devices/{id}/repairs", a.list)
	r("GET /api/v1/devices/{id}/repair-plan", a.plan)
	r("POST /api/v1/devices/{id}/repairs", a.request)
}

func (a *API) list(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	items, err := a.svc.List(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[*recovery.Repair]{Items: items})
	return nil
}

func (a *API) plan(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	p, err := a.svc.Plan(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, p)
	return nil
}

// request is the console's one Repair button: the body is empty (an object
// with no fields); the server decides what to repair (ADR-0069).
type request struct{}

func (a *API) request(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in request
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	out, err := a.svc.RepairDevice(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, out)
	return nil
}
