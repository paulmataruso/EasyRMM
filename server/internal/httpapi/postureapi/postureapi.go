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

// Register mounts the routes. The service checks device.view on the computer.
func (a *API) Register(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/devices/{id}/posture", httpapi.RequireActive(httpapi.Handle(a.device)))
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
