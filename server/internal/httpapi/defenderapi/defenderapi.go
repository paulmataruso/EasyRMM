// Package defenderapi serves the Defender module's stored data to the
// console (ADR-0074): the Events panel. Actions and the other panels go
// through the winmod routes.
package defenderapi

import (
	"net/http"
	"strconv"

	"github.com/paulmataruso/easyrmm/server/internal/defenderlog"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

// API serves the routes.
type API struct {
	store   *defenderlog.Store
	offered defenderlog.Offerer
}

// New builds the API.
func New(store *defenderlog.Store, offered defenderlog.Offerer) *API {
	return &API{store: store, offered: offered}
}

// Register mounts the routes. Every route requires a fully signed-in session;
// the store checks the permission and that the module is offered.
func (a *API) Register(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/devices/{id}/defender/events", httpapi.RequireActive(httpapi.Handle(a.events)))
}

func (a *API) events(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	limit := 50
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil {
		limit = v
	}
	out, err := a.store.List(r.Context(), a.offered, httpapi.Caller(r), id, limit)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}
