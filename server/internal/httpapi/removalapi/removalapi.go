// Package removalapi exposes removing a device (ADR-0050): asking its
// agent to uninstall itself, withdrawing that, and removing it by force.
package removalapi

import (
	"net/http"

	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

// API serves the removal routes.
type API struct {
	agents  *agents.Service
	devices *devices.Service
}

// New builds the API.
func New(a *agents.Service, d *devices.Service) *API { return &API{agents: a, devices: d} }

// Register mounts the routes. Every route requires a fully signed-in
// session; the service checks permissions.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("POST /api/v1/devices/{id}/removal", a.request)
	r("DELETE /api/v1/devices/{id}/removal", a.cancel)
	r("DELETE /api/v1/devices/{id}", a.force)
}

// Result answers a removal request: the device while it waits for its
// agent, none once it is removed.
type Result struct {
	// Status is agents.RemovalAsked or agents.RemovalDone.
	Status string          `json:"status"`
	Device *devices.Device `json:"device,omitempty"`
}

func (a *API) request(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	c := httpapi.Caller(r)
	status, err := a.agents.RequestRemoval(r.Context(), c, id)
	if err != nil {
		return err
	}
	out := Result{Status: status}
	if status == agents.RemovalAsked {
		if out.Device, err = a.devices.Get(r.Context(), c, id); err != nil {
			return err
		}
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) cancel(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	c := httpapi.Caller(r)
	if err := a.agents.CancelRemoval(r.Context(), c, id); err != nil {
		return err
	}
	d, err := a.devices.Get(r.Context(), c, id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, d)
	return nil
}

func (a *API) force(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.agents.ForceRemove(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
