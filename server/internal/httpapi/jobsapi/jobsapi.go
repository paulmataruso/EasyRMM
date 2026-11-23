// Package jobsapi exposes the script library and jobs to the console
// (ADR-0017).
package jobsapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
)

// How often one person may download a job's output archive (ADR-0064): six
// at once, then one every 10 seconds, so up to 11 in the first minute and
// six a minute after that. Each archive appends up to 500 audit records
// under the audit chain's lock. The limit is kept by each server process,
// in memory: a restart starts it again, and each of several servers keeps
// its own.
const (
	zipBurst = 6
	zipEvery = 10 * time.Second
	// zipCallers bounds the people the limit remembers.
	zipCallers = 10000
)

// errTooManyZips answers an archive beyond the limit, with Retry-After.
var errTooManyZips = &httpapi.Error{Status: http.StatusTooManyRequests, Code: "rate_limited",
	Message: "You have downloaded several jobs' output in the last minute. Wait a few seconds and try again.", RetryAfter: zipEvery}

// API serves the script and job routes.
type API struct {
	svc  *jobs.Service
	zips *auth.KeyedLimiter
}

// New builds the API.
func New(svc *jobs.Service) *API {
	return &API{svc: svc, zips: auth.NewKeyedLimiter(zipEvery, zipBurst, zipCallers)}
}

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
	r("POST /api/v1/jobs/software", a.createSoftwareJob)
	r("POST /api/v1/jobs/hardening", a.createHardeningJob)
	r("GET /api/v1/devices/{id}/hardening", a.deviceHardening)
	r("GET /api/v1/jobs/{id}", a.getJob)
	r("GET /api/v1/jobs/{id}/arguments", a.jobArguments)
	r("GET /api/v1/jobs/{id}/output.zip", a.jobOutputZip)
	r("GET /api/v1/jobs/{id}/runs.csv", a.jobResultsCSV)
	r("POST /api/v1/jobs/{id}/cancel", a.cancelJob)
	r("GET /api/v1/job-runs", a.listRuns)
	r("GET /api/v1/job-runs/{id}", a.getRun)
	r("GET /api/v1/job-runs/{id}/output", a.runOutput)
	r("DELETE /api/v1/job-runs/{id}/output", a.removeRunOutput)
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
	group, err := httpapi.QueryID(r, "groupId")
	if err != nil {
		return err
	}
	q := r.URL.Query()
	items, err := a.svc.ListScripts(r.Context(), httpapi.Caller(r), jobs.ScriptQuery{
		OrganizationID: org, SiteID: site, DeviceID: device, GroupID: group, Shared: q.Get("level") == jobs.LevelShared, Search: q.Get("q"),
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
	group, err := httpapi.QueryID(r, "groupId")
	if err != nil {
		return err
	}
	items, err := a.svc.ListJobs(r.Context(), httpapi.Caller(r), jobs.JobQuery{
		OrganizationID: org, SiteID: site, GroupID: group, DeviceID: device, ScriptID: script, Status: r.URL.Query().Get("status"),
		Kind: r.URL.Query().Get("kind"),
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

// createSoftwareJob installs, updates or removes a package (ADR-0028).
func (a *API) createSoftwareJob(w http.ResponseWriter, r *http.Request) error {
	var in jobs.SoftwareInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	j, err := a.svc.CreateSoftwareJob(r.Context(), httpapi.Caller(r), in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, j)
	return nil
}

func (a *API) createHardeningJob(w http.ResponseWriter, r *http.Request) error {
	var in jobs.HardeningInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	j, err := a.svc.CreateHardeningJob(r.Context(), httpapi.Caller(r), in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, j)
	return nil
}

func (a *API) deviceHardening(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	h, err := a.svc.DeviceHardening(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, h)
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

// jobArguments returns a job's argument values, each read audited
// (ADR-0063).
func (a *API) jobArguments(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	args, err := a.svc.ReadArguments(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, args)
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
	group, err := httpapi.QueryID(r, "groupId")
	if err != nil {
		return err
	}
	items, err := a.svc.ListRuns(r.Context(), httpapi.Caller(r), jobs.RunQuery{DeviceID: device, GroupID: group, Kind: r.URL.Query().Get("kind")})
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

// runOutput returns what a run printed, each read audited (ADR-0063), or,
// with ?download=stdout, stderr or json, a file of it (ADR-0064).
func (a *API) runOutput(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if q := r.URL.Query(); q.Has("download") {
		f, err := a.svc.DownloadOutput(r.Context(), httpapi.Caller(r), id, q.Get("download"))
		if err != nil {
			return err
		}
		contentType := "text/plain; charset=utf-8"
		if q.Get("download") == jobs.DownloadJSON {
			contentType = "application/json; charset=utf-8"
		}
		writeFile(w, f, contentType)
		return nil
	}
	out, err := a.svc.ReadOutput(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

// writeFile sends a download. Its name is letters, digits, '.', '_', '-'
// (jobs.fileName) and its body what a script printed, never rendered: an
// attachment, of a text or JSON type, under nosniff and the console's CSP.
func writeFile(w http.ResponseWriter, f *jobs.File, contentType string) {
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Content-Disposition", `attachment; filename="`+f.Name+`"`)
	h.Set("Content-Length", strconv.Itoa(len(f.Body)))
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(f.Body) //nolint:gosec // an attachment of a text, CSV or JSON type, sent with nosniff: never rendered as a page
}

// jobOutputZip sends a job's output as a ZIP archive. Every run's read is
// recorded, and committed, before the first byte is sent (ADR-0064). Each
// person may ask for six at once, then one every 10 seconds (zipBurst,
// zipEvery); a request beyond that is answered 429 before anything is read
// or recorded.
func (a *API) jobOutputZip(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	c := httpapi.Caller(r)
	if !a.zips.Allow(c.Actor.ID.String()) {
		return errTooManyZips
	}
	arc, err := a.svc.OutputArchive(r.Context(), c, id)
	if err != nil {
		return err
	}
	h := w.Header()
	h.Set("Content-Type", "application/zip")
	h.Set("Content-Disposition", `attachment; filename="`+arc.Name+`"`)
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if err := arc.Write(r.Context(), w); err != nil {
		// The answer has begun: break it off, so the client sees a failed
		// download rather than a short archive.
		httpapi.LoggerFrom(r.Context()).Warn("sending a job's output archive failed", "error", err, "job_id", id)
		panic(http.ErrAbortHandler)
	}
	return nil
}

// jobResultsCSV sends a job's results without output, recorded as an
// export (ADR-0064).
func (a *API) jobResultsCSV(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	f, err := a.svc.ResultsCSV(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	writeFile(w, f, "text/csv; charset=utf-8")
	return nil
}

// removeRunOutput empties a finished run's output at once and returns the
// run.
func (a *API) removeRunOutput(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	run, err := a.svc.RemoveOutput(r.Context(), httpapi.Caller(r), id)
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
