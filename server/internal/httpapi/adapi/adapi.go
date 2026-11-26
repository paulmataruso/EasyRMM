// Package adapi serves the Active Directory card of the organization page
// and the pin of a domain's controller (ADR-0075, section 3). The card
// reads stored snapshots and sends no job.
package adapi

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/activedirectory"
)

// API serves the routes.
type API struct{ svc *activedirectory.Service }

// New builds the API.
func New(s *activedirectory.Service) *API { return &API{svc: s} }

// Register mounts the routes; the service checks ad.view and ad.manage.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/organizations/{id}/ad/domains", a.list)
	r("PUT /api/v1/organizations/{id}/ad/domains/{sid}/preferred", a.pin)
}

func (a *API) list(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	out, err := a.svc.Read(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

// pinRequest names the controller to prefer; a null device clears the pin.
type pinRequest struct {
	DeviceID *uuid.UUID `json:"deviceId"`
}

func (a *API) pin(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in pinRequest
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	if err := a.svc.Pin(r.Context(), httpapi.Caller(r), id, r.PathValue("sid"), in.DeviceID); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
