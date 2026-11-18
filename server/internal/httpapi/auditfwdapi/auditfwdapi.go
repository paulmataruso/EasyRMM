// Package auditfwdapi exposes the audit forwarding settings (ADR-0023).
package auditfwdapi

import (
	"net/http"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/auditfwd"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// API serves the audit forwarding routes.
type API struct{ svc *auditfwd.Service }

// New builds the API.
func New(svc *auditfwd.Service) *API { return &API{svc: svc} }

// Register mounts the routes. All of them need settings.manage everywhere:
// forwarding sends every tenant's records.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(func(w http.ResponseWriter, r *http.Request) error {
			if !httpapi.Can(r, rbac.PermSettingsManage, rbac.Resource{}) {
				return apperr.Forbidden()
			}
			return h(w, r)
		})))
	}
	r("GET /api/v1/settings/audit-forwarding", a.get)
	r("PUT /api/v1/settings/audit-forwarding", a.put)
	r("POST /api/v1/settings/audit-forwarding/test", a.test)
}

func (a *API) get(w http.ResponseWriter, r *http.Request) error {
	s, err := a.svc.Get(r.Context())
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, s)
	return nil
}

func (a *API) put(w http.ResponseWriter, r *http.Request) error {
	var in auditfwd.Input
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	s, err := a.svc.Update(r.Context(), httpapi.Actor(r), in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, s)
	return nil
}

func (a *API) test(w http.ResponseWriter, r *http.Request) error {
	var in auditfwd.Input
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	res, err := a.svc.Test(r.Context(), httpapi.Actor(r), in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, res)
	return nil
}
