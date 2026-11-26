// Package backupapi serves the Windows Backup cards of the organization and
// site pages (ADR-0077, section 4). A card reads stored snapshots and sends
// no job.
package backupapi

import (
	"net/http"

	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/backup"
)

// API serves the routes.
type API struct{ cards *backup.Cards }

// New builds the API.
func New(c *backup.Cards) *API { return &API{cards: c} }

// Register mounts the routes; the service checks backup.view at the level.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/organizations/{id}/backup", a.read(backup.AtOrganization))
	r("GET /api/v1/sites/{id}/backup", a.read(backup.AtSite))
}

func (a *API) read(l backup.Level) httpapi.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		id, err := httpapi.PathID(r)
		if err != nil {
			return err
		}
		out, err := a.cards.Read(r.Context(), httpapi.Caller(r), l, id)
		if err != nil {
			return err
		}
		httpapi.WriteJSON(w, http.StatusOK, out)
		return nil
	}
}
