package notifyapi

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/notify"
)

// registerRules mounts device alert rules, maintenance windows, the
// fleet-wide hold, the journal's quarantine and a device's kind (ADR-0053,
// slice 4).
func (a *API) registerRules(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/notifications/rules", a.rules)
	r("POST /api/v1/notifications/rules", a.createRule)
	r("GET /api/v1/notifications/rules/{id}", a.rule)
	r("PUT /api/v1/notifications/rules/{id}", a.updateRule)
	r("DELETE /api/v1/notifications/rules/{id}", a.deleteRule)
	r("GET /api/v1/maintenance-windows", a.windows)
	r("POST /api/v1/sites/{id}/maintenance-windows", a.createWindow)
	r("PUT /api/v1/maintenance-windows/{id}", a.updateWindow)
	r("DELETE /api/v1/maintenance-windows/{id}", a.deleteWindow)
	r("GET /api/v1/notifications/silence", a.silence)
	r("POST /api/v1/notifications/silence/end", a.endSilence)
	r("GET /api/v1/notifications/quarantined", a.quarantined)
	r("POST /api/v1/notifications/quarantined/{row}/retry", a.retry)
	r("POST /api/v1/notifications/quarantined/{row}/discard", a.discard)
	r("PUT /api/v1/devices/{id}/kind", a.deviceKind)
}

func (a *API) rules(w http.ResponseWriter, r *http.Request) error {
	org, err := orgParam(r)
	if err != nil {
		return err
	}
	out, err := a.svc.Rules(r.Context(), httpapi.Caller(r), org)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"rules": out})
	return nil
}

func (a *API) createRule(w http.ResponseWriter, r *http.Request) error {
	var in notify.Rule
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	out, err := a.svc.CreateRule(r.Context(), httpapi.Caller(r), in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, out)
	return nil
}

func (a *API) rule(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	out, err := a.svc.Rule(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) updateRule(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in notify.Rule
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	out, err := a.svc.UpdateRule(r.Context(), httpapi.Caller(r), id, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) deleteRule(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.DeleteRule(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) windows(w http.ResponseWriter, r *http.Request) error {
	org, err := orgParam(r)
	if err != nil {
		return err
	}
	site, err := httpapi.QueryID(r, "siteId")
	if err != nil {
		return err
	}
	q := notify.WindowQuery{OrganizationID: org}
	if site != uuid.Nil {
		q.SiteID = &site
	}
	out, err := a.svc.Windows(r.Context(), httpapi.Caller(r), q)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"windows": out})
	return nil
}

func (a *API) createWindow(w http.ResponseWriter, r *http.Request) error {
	site, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in notify.Window
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	out, err := a.svc.CreateWindow(r.Context(), httpapi.Caller(r), site, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, out)
	return nil
}

func (a *API) updateWindow(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in notify.Window
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	out, err := a.svc.UpdateWindow(r.Context(), httpapi.Caller(r), id, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) deleteWindow(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.DeleteWindow(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) silence(w http.ResponseWriter, r *http.Request) error {
	s, err := a.svc.CurrentSilence(r.Context(), httpapi.Caller(r))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"silence": s})
	return nil
}

func (a *API) endSilence(w http.ResponseWriter, r *http.Request) error {
	if err := a.svc.EndSilence(r.Context(), httpapi.Caller(r)); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) quarantined(w http.ResponseWriter, r *http.Request) error {
	out, err := a.svc.QuarantinedRows(r.Context(), httpapi.Caller(r))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"rows": out})
	return nil
}

func rowParam(r *http.Request) (int64, error) {
	n, err := strconv.ParseInt(r.PathValue("row"), 10, 64)
	if err != nil || n < 1 {
		return 0, apperr.NotFound()
	}
	return n, nil
}

func (a *API) retry(w http.ResponseWriter, r *http.Request) error {
	n, err := rowParam(r)
	if err != nil {
		return err
	}
	if err := a.svc.RetryJournal(r.Context(), httpapi.Caller(r), n); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) discard(w http.ResponseWriter, r *http.Request) error {
	n, err := rowParam(r)
	if err != nil {
		return err
	}
	if err := a.svc.DiscardJournal(r.Context(), httpapi.Caller(r), n); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// deviceKind sets, or with a null kind clears, a device's kind.
func (a *API) deviceKind(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in struct {
		Kind *string `json:"kind"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	kind, err := a.svc.SetDeviceKind(r.Context(), httpapi.Caller(r), id, in.Kind)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"kind": kind})
	return nil
}
