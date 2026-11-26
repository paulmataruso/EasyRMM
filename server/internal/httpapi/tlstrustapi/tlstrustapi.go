// Package tlstrustapi exposes what a device's agent trusts to the console
// (ADR-0055, slice 5b1).
package tlstrustapi

import (
	"net/http"

	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/tlstrust"
)

// API serves the route.
type API struct{ svc *tlstrust.Service }

// New builds the API.
func New(svc *tlstrust.Service) *API { return &API{svc: svc} }

// Register mounts the route. It requires a fully signed-in session; whoever
// may view a device may see what its agent trusts.
func (a *API) Register(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/devices/{id}/tls-trust", httpapi.RequireActive(httpapi.Handle(a.device)))
}

func (a *API) device(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	out, err := a.svc.Device(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}
