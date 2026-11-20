package easypatchapi

// Settings → Patching's server-wide views (one-product plan, C6): EasyPatch's
// server settings and vulnerability feeds, OS lifecycle, agent packages and
// audit log.

import (
	"net/http"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

func (a *API) registerSettings(r func(string, httpapi.HandlerFunc)) {
	r("GET /api/v1/patching/settings", a.serverSettings)
	r("PUT /api/v1/patching/settings", a.setServerSettings)
	r("GET /api/v1/patching/lifecycle", a.lifecycle)
	r("POST /api/v1/patching/lifecycle", a.createLifecycle)
	r("PUT /api/v1/patching/lifecycle/{id}", a.updateLifecycle)
	r("DELETE /api/v1/patching/lifecycle/{id}", a.deleteLifecycle)
	r("GET /api/v1/patching/agent-packages", a.agentPackages)
	r("GET /api/v1/patching/audit", a.engineAudit)
}

func (a *API) serverSettings(w http.ResponseWriter, r *http.Request) error {
	v, err := a.svc.ServerSettings(r.Context(), httpapi.Caller(r))
	return ok(w, v, err)
}

func (a *API) setServerSettings(w http.ResponseWriter, r *http.Request) error {
	var in easypatch.ServerSettings
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	v, err := a.svc.SetServerSettings(r.Context(), httpapi.Caller(r), in)
	return ok(w, v, err)
}

func (a *API) lifecycle(w http.ResponseWriter, r *http.Request) error {
	l, err := a.svc.Lifecycle(r.Context(), httpapi.Caller(r))
	return ok(w, l, err)
}

func (a *API) createLifecycle(w http.ResponseWriter, r *http.Request) error {
	var in easypatch.LifecycleInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	e, err := a.svc.CreateLifecycle(r.Context(), httpapi.Caller(r), in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, e)
	return nil
}

func (a *API) updateLifecycle(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in easypatch.LifecycleInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	e, err := a.svc.UpdateLifecycle(r.Context(), httpapi.Caller(r), id, in)
	return ok(w, e, err)
}

func (a *API) deleteLifecycle(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.DeleteLifecycle(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) agentPackages(w http.ResponseWriter, r *http.Request) error {
	list, err := a.svc.AgentPackageList(r.Context(), httpapi.Caller(r))
	return ok(w, map[string]any{"items": list}, err)
}

// engineAudit reads EasyPatch's audit log. from and to are instants (the
// console sends the start of the first day and of the day after the last,
// in the browser's time zone); to is not included.
func (a *API) engineAudit(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.QueryID(r, "organizationId")
	if err != nil {
		return err
	}
	page, err := httpapi.QueryCount(r, "page", 1, 1, 10_000)
	if err != nil {
		return err
	}
	v := r.URL.Query()
	q := easypatch.AuditQuery{OrganizationID: org, Area: strings.TrimSpace(v.Get("area")), Page: page}
	for name, t := range map[string]**time.Time{"from": &q.From, "to": &q.To} {
		if raw := v.Get(name); raw != "" {
			at, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				return apperr.Invalid(name, "Give a time as in 2026-11-18T09:00:00Z.")
			}
			*t = &at
		}
	}
	p, err := a.svc.AuditLog(r.Context(), httpapi.Caller(r), q)
	return ok(w, p, err)
}
