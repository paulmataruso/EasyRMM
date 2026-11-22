// Package alertsapi exposes alert policies and alerts to the console
// (ADR-0019).
package alertsapi

import (
	"net/http"
	"strconv"

	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/monitoring"
)

// API serves the alert routes.
type API struct {
	svc *monitoring.Service
}

// New builds the API.
func New(svc *monitoring.Service) *API { return &API{svc: svc} }

// Register mounts the routes. Every route requires a fully signed-in session.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/alerts", a.listAlerts)
	r("GET /api/v1/alerts/summary", a.summary)
	r("GET /api/v1/alerts/devices", a.deviceCounts)
	r("GET /api/v1/alerts/{id}", a.getAlert)
	r("GET /api/v1/alerts/{id}/metrics", a.alertMetrics)
	r("POST /api/v1/alerts/{id}/acknowledge", a.acknowledge)
	r("POST /api/v1/alerts/{id}/resolve", a.resolve)
	r("GET /api/v1/alert-policies", a.listPolicies)
	r("POST /api/v1/alert-policies", a.createPolicy)
	r("GET /api/v1/alert-policies/{id}", a.getPolicy)
	r("PATCH /api/v1/alert-policies/{id}", a.updatePolicy)
	r("DELETE /api/v1/alert-policies/{id}", a.deletePolicy)
}

func (a *API) listAlerts(w http.ResponseWriter, r *http.Request) error {
	device, err := httpapi.QueryID(r, "deviceId")
	if err != nil {
		return err
	}
	org, err := httpapi.QueryID(r, "organizationId")
	if err != nil {
		return err
	}
	site, err := httpapi.QueryID(r, "siteId")
	if err != nil {
		return err
	}
	policy, err := httpapi.QueryID(r, "policyId")
	if err != nil {
		return err
	}
	before, err := httpapi.QueryInt(r, "before", 0, 0, 1<<62)
	if err != nil {
		return err
	}
	limit, err := httpapi.QueryCount(r, "limit", 100, 1, 500)
	if err != nil {
		return err
	}
	q := r.URL.Query()
	items, next, err := a.svc.ListAlerts(r.Context(), httpapi.Caller(r), monitoring.AlertQuery{
		Status: q.Get("status"), DeviceID: device, OrganizationID: org, SiteID: site, Severity: q.Get("severity"),
		PolicyID: policy, Subject: q.Get("subject"), Before: before, Limit: limit,
	})
	if err != nil {
		return err
	}
	out := httpapi.List[*monitoring.Alert]{Items: items}
	if next > 0 {
		out.Next = strconv.FormatInt(next, 10)
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) summary(w http.ResponseWriter, r *http.Request) error {
	s, err := a.svc.Summarize(r.Context(), httpapi.Caller(r))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, s)
	return nil
}

func (a *API) deviceCounts(w http.ResponseWriter, r *http.Request) error {
	items, err := a.svc.ActiveByDevice(r.Context(), httpapi.Caller(r))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[monitoring.DeviceAlerts]{Items: items})
	return nil
}

func (a *API) getAlert(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	al, err := a.svc.GetAlert(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, al)
	return nil
}

func (a *API) alertMetrics(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	m, err := a.svc.AlertMetrics(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, m)
	return nil
}

func (a *API) acknowledge(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	al, err := a.svc.Acknowledge(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, al)
	return nil
}

func (a *API) resolve(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	al, err := a.svc.Resolve(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, al)
	return nil
}

func (a *API) listPolicies(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.QueryID(r, "organizationId")
	if err != nil {
		return err
	}
	items, err := a.svc.ListPolicies(r.Context(), httpapi.Caller(r), monitoring.PolicyQuery{OrganizationID: org})
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[*monitoring.Policy]{Items: items})
	return nil
}

func (a *API) createPolicy(w http.ResponseWriter, r *http.Request) error {
	var in monitoring.PolicyInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	p, err := a.svc.CreatePolicy(r.Context(), httpapi.Caller(r), in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, p)
	return nil
}

func (a *API) getPolicy(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	p, err := a.svc.GetPolicy(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, p)
	return nil
}

func (a *API) updatePolicy(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var p monitoring.PolicyPatch
	if err := httpapi.DecodeJSON(w, r, &p); err != nil {
		return err
	}
	out, err := a.svc.UpdatePolicy(r.Context(), httpapi.Caller(r), id, p)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) deletePolicy(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.DeletePolicy(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
