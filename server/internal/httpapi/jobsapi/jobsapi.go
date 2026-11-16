// Package jobsapi exposes the script library and jobs to the console
// (ADR-0017).
package jobsapi

import (
	"net/http"

	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
)

// API serves the script and job routes.
type API struct {
	svc *jobs.Service
}

// New builds the API.
func New(svc *jobs.Service) *API { return &API{svc: svc} }

// Register mounts the routes. Every route requires a fully signed-in session.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/scripts", a.listScripts)
	r("POST /api/v1/scripts", a.createScript)
	r("GET /api/v1/scripts/{id}", a.getScript)
	r("PATCH /api/v1/scripts/{id}", a.updateScript)
	r("DELETE /api/v1/scripts/{id}", a.deleteScript)
	r("GET /api/v1/jobs", a.listJobs)
	r("POST /api/v1/jobs", a.createJob)
	r("GET /api/v1/jobs/{id}", a.getJob)
	r("POST /api/v1/jobs/{id}/cancel", a.cancelJob)
	r("GET /api/v1/job-runs", a.listRuns)
	r("GET /api/v1/job-runs/{id}", a.getRun)
	r("POST /api/v1/job-runs/{id}/cancel", a.cancelRun)
}

func (a *API) listScripts(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.QueryID(r, "organizationId")
	if err != nil {
		return err
	}
	site, err := httpapi.QueryID(r, "siteId")
	if err != nil {
		return err
	}
	device, err := httpapi.QueryID(r, "deviceId")
	if err != nil {
		return err
	}
	q := r.URL.Query()
	items, err := a.svc.ListScripts(r.Context(), httpapi.Caller(r), jobs.ScriptQuery{
		OrganizationID: org, SiteID: site, DeviceID: device, Shared: q.Get("level") == jobs.LevelShared, Search: q.Get("q"),
	})
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[*jobs.Script]{Items: items})
	return nil
}

func (a *API) createScript(w http.ResponseWriter, r *http.Request) error {
	var in jobs.ScriptInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	sc, err := a.svc.CreateScript(r.Context(), httpapi.Caller(r), in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, sc)
	return nil
}

func (a *API) getScript(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	sc, err := a.svc.GetScript(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, sc)
	return nil
}

func (a *API) updateScript(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in jobs.ScriptPatch
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	sc, err := a.svc.UpdateScript(r.Context(), httpapi.Caller(r), id, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, sc)
	return nil
}

func (a *API) deleteScript(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.DeleteScript(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) listJobs(w http.ResponseWriter, r *http.Request) error {
	device, err := httpapi.QueryID(r, "deviceId")
	if err != nil {
		return err
	}
	script, err := httpapi.QueryID(r, "scriptId")
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
	items, err := a.svc.ListJobs(r.Context(), httpapi.Caller(r), jobs.JobQuery{
		OrganizationID: org, SiteID: site, DeviceID: device, ScriptID: script, Status: r.URL.Query().Get("status"),
	})
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[*jobs.Job]{Items: items})
	return nil
}

func (a *API) createJob(w http.ResponseWriter, r *http.Request) error {
	var in jobs.JobInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	j, err := a.svc.CreateJob(r.Context(), httpapi.Caller(r), in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, j)
	return nil
}

func (a *API) getJob(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	j, err := a.svc.GetJob(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, j)
	return nil
}

func (a *API) cancelJob(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	j, err := a.svc.CancelJob(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, j)
	return nil
}

func (a *API) listRuns(w http.ResponseWriter, r *http.Request) error {
	device, err := httpapi.QueryID(r, "deviceId")
	if err != nil {
		return err
	}
	items, err := a.svc.ListRuns(r.Context(), httpapi.Caller(r), jobs.RunQuery{DeviceID: device})
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[*jobs.Run]{Items: items})
	return nil
}

func (a *API) getRun(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	run, err := a.svc.GetRun(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, run)
	return nil
}

func (a *API) cancelRun(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	run, err := a.svc.CancelRun(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, run)
	return nil
}
