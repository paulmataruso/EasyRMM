// Package repairsapi exposes repairing a device's agents (ADR-0069): what a
// device's repairs are and asking for one, as the console's "Reconnect
// remote access" does.
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

// request is what the console sends to ask for a repair.
type request struct {
	// Target is meshagent: "Reconnect remote access".
	Target string `json:"target"`
}

func (a *API) request(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in request
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	rep, err := a.svc.Request(r.Context(), httpapi.Caller(r), id, in.Target)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, rep)
	return nil
}
