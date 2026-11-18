// Package agentupdatesapi exposes the agent update rollout (ADR-0027): its
// setting, the fleet's state, and asking for updates.
package agentupdatesapi

import (
	"net/http"

	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

// API serves the agent update routes.
type API struct {
	agents  *agents.Service
	devices *devices.Service
}

// New builds the API.
func New(a *agents.Service, d *devices.Service) *API { return &API{agents: a, devices: d} }

// Register mounts the routes. Every route requires a fully signed-in
// session; the services check permissions.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/settings/agent-updates", a.get)
	r("PUT /api/v1/settings/agent-updates", a.put)
	r("POST /api/v1/settings/agent-updates/request-all", a.requestAll)
	r("POST /api/v1/devices/{id}/agent-update", a.requestOne)
}

func (a *API) get(w http.ResponseWriter, r *http.Request) error {
	s, err := a.agents.UpdateSettings(r.Context(), httpapi.Caller(r))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, s)
	return nil
}

func (a *API) put(w http.ResponseWriter, r *http.Request) error {
	var in agents.UpdatePolicy
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	s, err := a.agents.SetUpdatePolicy(r.Context(), httpapi.Caller(r), in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, s)
	return nil
}

func (a *API) requestAll(w http.ResponseWriter, r *http.Request) error {
	n, err := a.agents.RequestAll(r.Context(), httpapi.Caller(r))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]int{"requested": n})
	return nil
}

// requestOne asks for one device's update and answers with the device.
func (a *API) requestOne(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	c := httpapi.Caller(r)
	if err := a.agents.RequestUpdate(r.Context(), c, id); err != nil {
		return err
	}
	d, err := a.devices.Get(r.Context(), c, id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, d)
	return nil
}
