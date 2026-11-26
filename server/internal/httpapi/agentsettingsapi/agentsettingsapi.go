// Package agentsettingsapi serves agent settings at the platform, an
// organization, a site and a device (ADR-0058).
package agentsettingsapi

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/agentsettings"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

// API serves the routes.
type API struct{ svc *agentsettings.Service }

// New builds the API.
func New(svc *agentsettings.Service) *API { return &API{svc: svc} }

// Register mounts the routes. Every route requires a fully signed-in session.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/agent-settings/keys", a.keys)
	r("GET /api/v1/settings/agent-settings/limits", a.limits)
	r("PUT /api/v1/settings/agent-settings/limits", a.setLimits)
	for _, s := range []struct {
		scope agentsettings.Scope
		base  string
	}{
		{agentsettings.ScopePlatform, "/api/v1/settings/agent-settings"},
		{agentsettings.ScopeOrganization, "/api/v1/organizations/{id}/agent-settings"},
		{agentsettings.ScopeSite, "/api/v1/sites/{id}/agent-settings"},
		{agentsettings.ScopeDevice, "/api/v1/devices/{id}/agent-settings"},
	} {
		r("GET "+s.base, a.list(s.scope))
		r("PUT "+s.base+"/{key}", a.put(s.scope))
		r("DELETE "+s.base+"/{key}", a.clear(s.scope))
	}
}

func (a *API) keys(w http.ResponseWriter, _ *http.Request) error {
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"items": agentsettings.Keys()})
	return nil
}

func (a *API) limits(w http.ResponseWriter, r *http.Request) error {
	l, err := a.svc.Limits(r.Context())
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, l)
	return nil
}

func (a *API) setLimits(w http.ResponseWriter, r *http.Request) error {
	var in agentsettings.Limits
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	l, err := a.svc.SetLimits(r.Context(), httpapi.Caller(r), in)
	if err != nil {
		return fail(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, l)
	return nil
}

// fail gives the errors this API names in ADR-0058 the status the ADR gives
// them: a value or scope the catalog refuses is 400, where the rest of the
// API answers a field that needs attention with 422.
func fail(err error) error {
	if ae, ok := apperr.As(err); ok && (ae.Code == "setting_invalid" || ae.Code == "setting_scope") {
		return &httpapi.Error{Status: http.StatusBadRequest, Code: ae.Code, Message: ae.Message, Fields: ae.Fields}
	}
	return err
}

// target finds what the request is about; the platform has no ID.
func (a *API) target(r *http.Request, scope agentsettings.Scope) (agentsettings.Target, error) {
	id := uuid.Nil
	if scope != agentsettings.ScopePlatform {
		var err error
		if id, err = httpapi.PathID(r); err != nil {
			return agentsettings.Target{}, err
		}
	}
	t, err := a.svc.Resolve(r.Context(), httpapi.Caller(r), scope, id)
	return t, fail(err)
}

func (a *API) list(scope agentsettings.Scope) httpapi.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		t, err := a.target(r, scope)
		if err != nil {
			return err
		}
		out, err := a.svc.List(r.Context(), httpapi.Caller(r), t)
		if err != nil {
			return err
		}
		httpapi.WriteJSON(w, http.StatusOK, out)
		return nil
	}
}

func (a *API) put(scope agentsettings.Scope) httpapi.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		t, err := a.target(r, scope)
		if err != nil {
			return err
		}
		var in agentsettings.PutInput
		if err := httpapi.DecodeJSON(w, r, &in); err != nil {
			return err
		}
		out, err := a.svc.Put(r.Context(), httpapi.Caller(r), t, r.PathValue("key"), in)
		if err != nil {
			return fail(err)
		}
		httpapi.WriteJSON(w, http.StatusOK, out)
		return nil
	}
}

func (a *API) clear(scope agentsettings.Scope) httpapi.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		t, err := a.target(r, scope)
		if err != nil {
			return err
		}
		if err := a.svc.Delete(r.Context(), httpapi.Caller(r), t, r.PathValue("key")); err != nil {
			return fail(err)
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}
