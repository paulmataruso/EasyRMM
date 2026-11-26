// Package reportsapi serves reports to the console, as tables and as CSV
// downloads (ADR-0029).
package reportsapi

import (
	"bytes"
	"net/http"
	"strconv"

	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/reports"
)

// API serves the report routes.
type API struct {
	svc *reports.Service
}

// New builds the API.
func New(svc *reports.Service) *API { return &API{svc: svc} }

// Register mounts the routes. Every route requires a fully signed-in session.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/reports/{name}", a.show)
	r("GET /api/v1/reports/{name}/csv", a.csv)
}

func query(r *http.Request) (reports.Query, error) {
	var q reports.Query
	var err error
	if q.OrganizationID, err = httpapi.QueryID(r, "organizationId"); err != nil {
		return q, err
	}
	if q.SiteID, err = httpapi.QueryID(r, "siteId"); err != nil {
		return q, err
	}
	v := r.URL.Query()
	q.Platform, q.Search, q.Severity = v.Get("platform"), v.Get("q"), v.Get("severity")
	q.Compliance, q.Category, q.Result = v.Get("compliance"), v.Get("category"), v.Get("result")
	q.Posture = v.Get("posture")
	ints := []struct {
		name    string
		def, hi int
		dst     *int
	}{
		{"days", reports.DefaultDays, reports.MaxDays, &q.Days},
		{"offlineDays", 0, 3650, &q.OfflineDays},
		{"diskPercent", 0, 100, &q.DiskPercent},
	}
	for _, p := range ints {
		lo := 0
		if p.name == "days" {
			lo = 1
		}
		n, err := httpapi.QueryCount(r, p.name, p.def, lo, p.hi)
		if err != nil {
			return q, err
		}
		*p.dst = n
	}
	return q, nil
}

func (a *API) show(w http.ResponseWriter, r *http.Request) error {
	q, err := query(r)
	if err != nil {
		return err
	}
	rep, err := a.svc.Run(r.Context(), httpapi.Caller(r), r.PathValue("name"), q, reports.PreviewRows)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, rep)
	return nil
}

// csv sends the whole report as a file. The export is audited before any of
// it is sent.
func (a *API) csv(w http.ResponseWriter, r *http.Request) error {
	q, err := query(r)
	if err != nil {
		return err
	}
	rep, err := a.svc.Export(r.Context(), httpapi.Caller(r), r.PathValue("name"), q)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := reports.WriteCSV(&buf, rep); err != nil {
		return err
	}
	h := w.Header()
	h.Set("Content-Type", "text/csv; charset=utf-8")
	h.Set("Content-Disposition", `attachment; filename="`+reports.FileName(rep)+`"`)
	h.Set("Content-Length", strconv.Itoa(buf.Len()))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Report-Rows", strconv.Itoa(rep.Total))
	if rep.Truncated {
		h.Set("X-Report-Truncated", "true")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = buf.WriteTo(w)
	return nil
}
