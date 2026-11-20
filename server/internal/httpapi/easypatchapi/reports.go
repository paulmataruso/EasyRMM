package easypatchapi

// Patch reports: the compliance trend, monthly PDF reports and their
// schedules. The compliance and installations reports are EasyRMM reports,
// under /api/v1/reports.

import (
	"net/http"
	"regexp"
	"strconv"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/easypatch"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

func (a *API) registerReports(r func(string, httpapi.HandlerFunc)) {
	r("GET /api/v1/patching/reports/trend", a.trend)
	r("GET /api/v1/patching/reports/monthly", a.monthlyReports)
	r("POST /api/v1/patching/reports/monthly", a.generateReport)
	r("GET /api/v1/patching/reports/monthly/{id}/pdf", a.reportPDF)
	r("POST /api/v1/patching/reports/monthly/{id}/send", a.sendReport)
	r("DELETE /api/v1/patching/reports/monthly/{id}", a.deleteReport)
	r("GET /api/v1/patching/report-schedules", a.reportSchedules)
	r("PUT /api/v1/patching/report-schedules/{id}", a.setReportSchedule)
}

func (a *API) trend(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.QueryID(r, "organizationId")
	if err != nil {
		return err
	}
	days, err := httpapi.QueryCount(r, "days", easypatch.DefaultReportDays, 7, easypatch.MaxReportDays)
	if err != nil {
		return err
	}
	t, err := a.svc.ComplianceTrend(r.Context(), httpapi.Caller(r), org, days)
	return ok(w, t, err)
}

func (a *API) monthlyReports(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.QueryID(r, "organizationId")
	if err != nil {
		return err
	}
	list, err := a.svc.MonthlyReports(r.Context(), httpapi.Caller(r), org)
	return ok(w, list, err)
}

type generateInput struct {
	OrganizationID      uuid.UUID `json:"organizationId"`
	Year                int       `json:"year"`
	Month               int       `json:"month"`
	IncludeEndpointList bool      `json:"includeEndpointList"`
}

func (a *API) generateReport(w http.ResponseWriter, r *http.Request) error {
	var in generateInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	rep, err := a.svc.GenerateMonthlyReport(r.Context(), httpapi.Caller(r), in.OrganizationID, in.Year, in.Month, in.IncludeEndpointList)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, rep)
	return nil
}

// unsafeFileName is what may not appear in a download's file name.
var unsafeFileName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// reportPDF sends a monthly report's PDF as a download. It is recorded
// before any of it is sent.
func (a *API) reportPDF(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	rep, pdf, err := a.svc.MonthlyReportPDF(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	name := unsafeFileName.ReplaceAllString(rep.FileName, "-")
	if name == "" || name == "-" {
		name = "patch-report.pdf"
	}
	h := w.Header()
	h.Set("Content-Type", "application/pdf")
	h.Set("Content-Disposition", `attachment; filename="`+name+`"`)
	h.Set("Content-Length", strconv.Itoa(len(pdf)))
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pdf)
	return nil
}

type sendInput struct {
	Recipients []string `json:"recipients"`
}

func (a *API) sendReport(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in sendInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	rep, err := a.svc.SendMonthlyReport(r.Context(), httpapi.Caller(r), id, in.Recipients)
	return ok(w, rep, err)
}

func (a *API) deleteReport(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.DeleteMonthlyReport(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) reportSchedules(w http.ResponseWriter, r *http.Request) error {
	list, err := a.svc.ReportSchedules(r.Context(), httpapi.Caller(r))
	return ok(w, list, err)
}

func (a *API) setReportSchedule(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in easypatch.ReportScheduleInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	s, err := a.svc.SetReportSchedule(r.Context(), httpapi.Caller(r), org, in)
	return ok(w, s, err)
}
