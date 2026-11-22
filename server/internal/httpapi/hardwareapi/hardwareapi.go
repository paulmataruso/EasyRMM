// Package hardwareapi exposes devices' disk health to the console
// (ADR-0065).
package hardwareapi

import (
	"net/http"

	"github.com/paulmataruso/easyrmm/server/internal/hardware"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

// API serves the hardware routes.
type API struct {
	svc *hardware.Service
}

// New builds the API.
func New(svc *hardware.Service) *API { return &API{svc: svc} }

// Register mounts the routes. Every route requires a fully signed-in
// session; whoever may view a device may view its disks.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/devices/{id}/disks", a.disks)
	r("GET /api/v1/devices/{id}/disks/{key}", a.disk)
}

func (a *API) disks(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	items, err := a.svc.Disks(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[*hardware.Disk]{Items: items})
	return nil
}

func (a *API) disk(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	out, err := a.svc.Disk(r.Context(), httpapi.Caller(r), id, r.PathValue("key"))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}
