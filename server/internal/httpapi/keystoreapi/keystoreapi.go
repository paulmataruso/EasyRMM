// Package keystoreapi exposes the keystore's state and the per-volume escrow
// state of a device (ADR-0081). No route returns a key: slice 1 has no reads.
package keystoreapi

import (
	"net/http"

	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/keystore"
)

// API serves the routes.
type API struct{ svc *keystore.Service }

// New builds the API.
func New(svc *keystore.Service) *API { return &API{svc: svc} }

// Register mounts the routes. Every route requires a fully signed-in session.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/devices/{id}/escrow", a.device)
	r("GET /api/v1/keystore", a.status)
}

func (a *API) device(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	out, err := a.svc.DeviceState(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) status(w http.ResponseWriter, r *http.Request) error {
	st, err := a.svc.Platform(r.Context(), httpapi.Caller(r))
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusOK, st)
	return nil
}
