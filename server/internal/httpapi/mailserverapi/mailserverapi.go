// Package mailserverapi exposes the mail server settings (ADR-0053):
// Settings → Notifications → Mail server.
package mailserverapi

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/mailserver"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// API serves the mail server routes.
type API struct{ svc *mailserver.Service }

// New builds the API.
func New(svc *mailserver.Service) *API { return &API{svc: svc} }

// Register mounts the routes. All of them need settings.manage everywhere:
// the mail server sends every organization's invitations and notifications.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(func(w http.ResponseWriter, r *http.Request) error {
			if !httpapi.Can(r, rbac.PermSettingsManage, rbac.Resource{}) {
				return apperr.Forbidden()
			}
			return h(w, r)
		})))
	}
	r("GET /api/v1/settings/mail-server", a.get)
	r("PUT /api/v1/settings/mail-server", a.put)
	r("DELETE /api/v1/settings/mail-server", a.del)
	r("PUT /api/v1/settings/mail-server/limits", a.limits)
	r("POST /api/v1/settings/mail-server/test", a.test)
}

func (a *API) get(w http.ResponseWriter, r *http.Request) error {
	v, err := a.svc.Get(r.Context())
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, v)
	return nil
}

func (a *API) put(w http.ResponseWriter, r *http.Request) error {
	var in mailserver.Input
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	v, err := a.svc.Update(r.Context(), httpapi.Actor(r), in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, v)
	return nil
}

func (a *API) del(w http.ResponseWriter, r *http.Request) error {
	v, err := a.svc.Delete(r.Context(), httpapi.Actor(r))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, v)
	return nil
}

func (a *API) limits(w http.ResponseWriter, r *http.Request) error {
	var in mailserver.LimitsInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	v, err := a.svc.SetLimits(r.Context(), httpapi.Actor(r), in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, v)
	return nil
}

func (a *API) test(w http.ResponseWriter, r *http.Request) error {
	var in mailserver.TestInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	res, err := a.svc.Test(r.Context(), httpapi.Actor(r), in)
	var soon *mailserver.TooSoonError
	if errors.As(err, &soon) {
		w.Header().Set("Retry-After", strconv.Itoa(soon.Seconds()))
		return &httpapi.Error{Status: http.StatusTooManyRequests, Code: "test_rate_limited", Message: soon.Error()}
	}
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, res)
	return nil
}
