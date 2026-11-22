package eptest

import (
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// EasyPatch's reports: the compliance trend, the installations report,
// monthly reports and their schedules, and the mail settings reports are sent
// with. The contract test holds these to the real server's rules.

// TrendDay is one day of an organization's compliance.
type TrendDay struct {
	Date                                                    string
	Total, Compliant, Missing, Failed, Reboot, Stale, Never int
	Offline, MissingUpdates                                 int
}

// InstallationInfo is one update a job finished with.
type InstallationInfo struct {
	JobID, EndpointID, Org  uuid.UUID
	Title, KB, Category     string
	Status, SkipReason      string
	ErrorCode, ErrorMessage string
	RebootRequired          bool
	RequestedBy             string
	CompletedAt             time.Time
}

// ReportInfo is a generated monthly report.
type ReportInfo struct {
	ID, Org                uuid.UUID
	PeriodStart, PeriodEnd string
	MonthToDate            bool
	GeneratedAt            time.Time
	GeneratedBy            string
	IncludeEndpointList    bool
	PDF                    []byte
	DeliveryStatus         string
	Recipients             []string
	QueuedAt               *time.Time
	// LastError is why emailing it last failed.
	LastError string
}

// ScheduleInfo is an organization's monthly report schedule.
type ScheduleInfo struct {
	Enabled             bool
	Recipients          []string
	DayOfMonth          int
	IncludeEndpointList bool
	EnabledAt           *time.Time
	UpdatedAt           *time.Time
}

// SetTrend sets an organization's daily compliance.
func (s *Server) SetTrend(org uuid.UUID, days ...TrendDay) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.trend == nil {
		s.trend = map[uuid.UUID][]TrendDay{}
	}
	s.trend[org] = days
}

// AddInstallation records that a job finished with an update on an
// endpoint, and returns the job's id.
func (s *Server) AddInstallation(e *Endpoint, i InstallationInfo) uuid.UUID {
	s.mu.Lock()
	defer s.mu.Unlock()
	i.EndpointID, i.Org = e.ID, e.Org
	if i.JobID == uuid.Nil {
		i.JobID = uuid.New()
	}
	if i.Category == "" {
		i.Category = "Security"
	}
	if i.Status == "" {
		i.Status = "Succeeded"
	}
	if i.RequestedBy == "" {
		i.RequestedBy = "EasyRMM"
	}
	s.installations = append(s.installations, &i)
	return i.JobID
}

// MonthlyReports lists the generated reports, oldest first.
func (s *Server) MonthlyReports() []ReportInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ReportInfo, 0, len(s.reports))
	for _, r := range s.reports {
		out = append(out, *r)
	}
	return out
}

// FailDelivery has emailing report id fail for good, with lastError, as
// the engine records a delivery it gives up on.
func (s *Server) FailDelivery(id uuid.UUID, lastError string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.reports {
		if r.ID == id {
			r.DeliveryStatus, r.LastError = "Failed", lastError
		}
	}
}

// Schedule is an organization's monthly report schedule, if it has one.
func (s *Server) Schedule(org uuid.UUID) *ScheduleInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sc := s.schedules[org]; sc != nil {
		c := *sc
		return &c
	}
	return nil
}

// Mail is the mail settings, with the password as it was given.
func (s *Server) Mail() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]any{}
	for k, v := range s.mail {
		out[k] = v
	}
	return out
}

func (s *Server) serveReports(w http.ResponseWriter, r *http.Request, parts []string, q url.Values, page, size int) {
	org, _ := uuid.Parse(q.Get("organizationId"))
	switch {
	case r.Method == http.MethodGet && len(parts) == 3 && parts[1] == "compliance" && parts[2] == "trend":
		from, to := q.Get("from"), q.Get("to")
		out := []map[string]any{}
		for o, days := range s.trend {
			if (org != uuid.Nil && o != org) || !s.canAccess(o) {
				continue
			}
			for _, d := range days {
				if d.Date < from || d.Date > to {
					continue
				}
				pct := 0.0
				if d.Total > 0 {
					pct = float64(int(float64(d.Compliant)*1000/float64(d.Total)+0.5)) / 10
				}
				out = append(out, map[string]any{"date": d.Date, "totalEndpoints": d.Total, "compliant": d.Compliant, "missingUpdates": d.Missing,
					"failedUpdates": d.Failed, "rebootRequired": d.Reboot, "scanStale": d.Stale, "neverScanned": d.Never, "offline": d.Offline,
					"missingRequiredUpdates": d.MissingUpdates, "compliancePercent": pct})
			}
		}
		slices.SortFunc(out, func(a, b map[string]any) int { return strings.Compare(a["date"].(string), b["date"].(string)) })
		reply(w, 200, out)
	case r.Method == http.MethodGet && len(parts) == 2 && parts[1] == "installations":
		from, _ := time.Parse(time.RFC3339, q.Get("from"))
		to, err := time.Parse(time.RFC3339, q.Get("to"))
		if err != nil {
			to = time.Now().Add(time.Hour)
		}
		var rows []map[string]any
		for _, i := range slices.Backward(s.installations) {
			e := s.endpoints[i.EndpointID]
			if (org != uuid.Nil && i.Org != org) || !s.canAccess(i.Org) || i.CompletedAt.Before(from) || !i.CompletedAt.Before(to) ||
				(q.Get("category") != "" && q.Get("category") != i.Category) || (q.Get("result") != "" && q.Get("result") != i.Status) {
				continue
			}
			rows = append(rows, map[string]any{"jobId": i.JobID, "endpointId": i.EndpointID, "hostname": e.Hostname, "organizationName": e.OrgName,
				"siteName": nullable(e.SiteName), "updateGuid": uuid.New(), "title": i.Title, "kbNumber": nullable(i.KB), "category": i.Category,
				"status": i.Status, "skipReason": nullable(i.SkipReason), "errorCode": nullable(i.ErrorCode), "errorMessage": nullable(i.ErrorMessage),
				"rebootRequired": i.RebootRequired, "requestedBy": i.RequestedBy, "completedAt": i.CompletedAt})
		}
		reply(w, 200, paged(rows, page, min(size, 200)))
	default:
		problem(w, 404, "not_found", "Not found.")
	}
}

func (s *Server) reportDTO(rep *ReportInfo) map[string]any {
	o := s.org(rep.Org)
	var status any
	if rep.DeliveryStatus != "" {
		status = rep.DeliveryStatus
	}
	return map[string]any{"id": rep.ID, "organizationId": rep.Org, "organizationName": o.Name, "periodStart": rep.PeriodStart,
		"periodEnd": rep.PeriodEnd, "monthToDate": rep.MonthToDate, "scheduled": false, "generatedAt": rep.GeneratedAt,
		"generatedBy": nullable(rep.GeneratedBy), "fileName": fmt.Sprintf("patch-report-%s.pdf", rep.PeriodStart[:7]),
		"sizeBytes": len(rep.PDF), "sha256": strings.Repeat("0", 64), "deliveryStatus": status, "recipients": orEmpty(rep.Recipients),
		"attempts": 0, "queuedAt": rep.QueuedAt, "sentAt": nil, "lastError": nullable(rep.LastError)}
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (s *Server) serveMonthlyReports(w http.ResponseWriter, r *http.Request, parts []string, body map[string]any, q url.Values, page, size int) {
	if r.Method != http.MethodGet && s.readOnlyCall {
		problem(w, 403, "forbidden", "You do not have permission.")
		return
	}
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			org, _ := uuid.Parse(q.Get("organizationId"))
			var rows []map[string]any
			for _, rep := range slices.Backward(s.reports) {
				if (org == uuid.Nil || rep.Org == org) && s.canAccess(rep.Org) {
					rows = append(rows, s.reportDTO(rep))
				}
			}
			reply(w, 200, paged(rows, page, min(size, 200)))
		case http.MethodPost:
			s.generateReport(w, r, body)
		default:
			problem(w, 405, "", "")
		}
		return
	}
	id, _ := uuid.Parse(parts[1])
	i := slices.IndexFunc(s.reports, func(x *ReportInfo) bool { return x.ID == id })
	if i < 0 {
		problem(w, 404, "not_found", "The report was not found.")
		return
	}
	rep := s.reports[i]
	if !s.canAccess(rep.Org) {
		problem(w, 403, "forbidden", "You do not have access to this organization.")
		return
	}
	switch {
	case len(parts) == 2 && r.Method == http.MethodGet:
		reply(w, 200, s.reportDTO(rep))
	case len(parts) == 2 && r.Method == http.MethodDelete:
		s.reports = slices.Delete(s.reports, i, i+1)
		w.WriteHeader(http.StatusNoContent)
	case len(parts) == 3 && parts[2] == "pdf" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/pdf")
		_, _ = w.Write(rep.PDF)
	case len(parts) == 3 && parts[2] == "send" && r.Method == http.MethodPost:
		s.sendReport(w, rep, body)
	default:
		problem(w, 405, "", "")
	}
}

func (s *Server) generateReport(w http.ResponseWriter, r *http.Request, body map[string]any) {
	org, _ := uuid.Parse(fmt.Sprint(body["organizationId"]))
	if !s.canAccess(org) {
		problem(w, 403, "forbidden", "You do not have access to this organization.")
		return
	}
	if s.org(org) == nil {
		problem(w, 404, "not_found", "Organization was not found.")
		return
	}
	year, _ := body["year"].(float64)
	month, _ := body["month"].(float64)
	now := time.Now().UTC()
	start := time.Date(int(year), time.Month(month), 1, 0, 0, 0, 0, time.UTC)
	if month < 1 || month > 12 || start.After(now) || !start.After(now.AddDate(-10, 0, 0)) {
		problem(w, 400, "invalid_period", "Choose a month that has started and is at most 10 years old.")
		return
	}
	end := start.AddDate(0, 1, -1)
	toDate := end.After(now)
	if toDate {
		end = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	}
	include, ok := body["includeEndpointList"].(bool)
	if !ok {
		include = true
		if sc := s.schedules[org]; sc != nil {
			include = sc.IncludeEndpointList
		}
	}
	// serve answered 401 to a request without a valid statement.
	by := s.requests[len(s.requests)-1].Statement.Name
	rep := &ReportInfo{ID: uuid.New(), Org: org, PeriodStart: start.Format(time.DateOnly), PeriodEnd: end.Format(time.DateOnly), MonthToDate: toDate,
		GeneratedAt: now, GeneratedBy: by, IncludeEndpointList: include, PDF: []byte("%PDF-1.7\n% EasyPatch monthly report\n%%EOF\n")}
	s.reports = append(s.reports, rep)
	reply(w, 201, s.reportDTO(rep))
}

func validEmails(raw any) ([]string, bool) {
	list, _ := raw.([]any)
	var out []string
	for _, x := range list {
		e := strings.TrimSpace(fmt.Sprint(x))
		if e == "" || slices.ContainsFunc(out, func(y string) bool { return strings.EqualFold(y, e) }) {
			continue
		}
		a, err := mail.ParseAddress(e)
		if err != nil || !strings.EqualFold(a.Address, e) || len(e) > 254 {
			return nil, false
		}
		out = append(out, e)
	}
	return out, true
}

func (s *Server) sendReport(w http.ResponseWriter, rep *ReportInfo, body map[string]any) {
	to, ok := validEmails(body["recipients"])
	switch {
	case !ok:
		problem(w, 400, "validation_failed", "One of the email addresses is not valid.")
		return
	case len(to) > 20:
		problem(w, 400, "validation_failed", "Enter at most 20 email addresses.")
		return
	case len(to) == 0 && s.schedules[rep.Org] != nil:
		to = s.schedules[rep.Org].Recipients
	}
	if len(to) == 0 {
		problem(w, 400, "no_recipients", "Enter recipients, or add them to the organization's report schedule.")
		return
	}
	if host, _ := s.mail["smtpHost"].(string); host == "" || s.mail["fromAddress"] == nil || s.mail["fromAddress"] == "" {
		problem(w, 409, "smtp_not_configured", "Configure SMTP first (Settings → Notifications).")
		return
	}
	if s.mail["smtpSecurity"] == "None" {
		problem(w, 409, "smtp_not_encrypted", "Reports are emailed only over STARTTLS or TLS; change the SMTP security setting.")
		return
	}
	now := time.Now().UTC()
	rep.DeliveryStatus, rep.Recipients, rep.QueuedAt, rep.LastError = "Pending", to, &now, ""
	reply(w, 200, s.reportDTO(rep))
}

func (s *Server) scheduleDTO(o *OrgInfo) map[string]any {
	sc := s.schedules[o.ID]
	if sc == nil {
		sc = &ScheduleInfo{DayOfMonth: 1, IncludeEndpointList: true}
	}
	var next, period any
	if sc.Enabled {
		now := time.Now().UTC()
		due := time.Date(now.Year(), now.Month(), sc.DayOfMonth, 0, 0, 0, 0, time.UTC)
		if !due.After(now) {
			due = due.AddDate(0, 1, 0)
		}
		next, period = due.Format(time.DateOnly), due.AddDate(0, -1, 1-due.Day()).Format(time.DateOnly)
	}
	return map[string]any{"organizationId": o.ID, "enabled": sc.Enabled, "recipients": orEmpty(sc.Recipients), "dayOfMonth": sc.DayOfMonth,
		"includeEndpointList": sc.IncludeEndpointList, "enabledAt": sc.EnabledAt, "lastScheduledPeriod": nil, "nextReportDate": next,
		"nextReportPeriod": period, "timeZone": o.TimeZone, "updatedAt": sc.UpdatedAt}
}

func (s *Server) serveSchedule(w http.ResponseWriter, r *http.Request, o *OrgInfo, body map[string]any) {
	if !s.canAccess(o.ID) {
		problem(w, 403, "forbidden", "You do not have access to this organization.")
		return
	}
	switch r.Method {
	case http.MethodGet:
		reply(w, 200, s.scheduleDTO(o))
	case http.MethodPut:
		if s.readOnlyCall {
			problem(w, 403, "forbidden", "You do not have permission.")
			return
		}
		to, ok := validEmails(body["recipients"])
		enabled, _ := body["enabled"].(bool)
		day, _ := body["dayOfMonth"].(float64)
		include, _ := body["includeEndpointList"].(bool)
		fields := map[string][]string{}
		switch {
		case !ok:
			fields["recipients"] = []string{"One of the email addresses is not valid."}
		case len(to) > 20:
			fields["recipients"] = []string{"Enter at most 20 email addresses."}
		case enabled && len(to) == 0:
			fields["recipients"] = []string{"Enter at least one email address."}
		}
		if day < 1 || day > 28 {
			fields["dayOfMonth"] = []string{"Choose a day from 1 to 28."}
		}
		if len(fields) > 0 {
			reply(w, 400, map[string]any{"title": "Validation failed", "status": 400, "code": "validation_failed", "errors": fields})
			return
		}
		if s.schedules == nil {
			s.schedules = map[uuid.UUID]*ScheduleInfo{}
		}
		sc := s.schedules[o.ID]
		if sc == nil {
			sc = &ScheduleInfo{}
			s.schedules[o.ID] = sc
		}
		now := time.Now().UTC()
		if enabled && !sc.Enabled {
			sc.EnabledAt = &now
		}
		sc.Enabled, sc.Recipients, sc.DayOfMonth, sc.IncludeEndpointList, sc.UpdatedAt = enabled, to, int(day), include, &now
		reply(w, 200, s.scheduleDTO(o))
	default:
		problem(w, 405, "", "")
	}
}

func (s *Server) serveMail(w http.ResponseWriter, r *http.Request, body map[string]any) {
	if !s.superAdmin() {
		problem(w, 403, "forbidden", "You do not have permission.")
		return
	}
	if s.mail == nil {
		s.mail = map[string]any{"smtpHost": nil, "smtpPort": 587.0, "smtpSecurity": "StartTls", "smtpUsername": nil, "fromAddress": nil,
			"fromName": nil, "allowPrivateNetworkWebhooks": false}
	}
	switch r.Method {
	case http.MethodGet:
		out := map[string]any{}
		for k, v := range s.mail {
			if k != "smtpPassword" {
				out[k] = v
			}
		}
		pw, _ := s.mail["smtpPassword"].(string)
		out["smtpPasswordConfigured"] = pw != ""
		reply(w, 200, out)
	case http.MethodPut:
		for _, k := range []string{"smtpHost", "smtpPort", "smtpSecurity", "smtpUsername", "fromAddress", "fromName", "allowPrivateNetworkWebhooks",
			"smtpSkipCertificateValidation"} {
			s.mail[k] = body[k]
			// EasyPatch keeps blank text as none.
			if v, ok := body[k].(string); ok && strings.TrimSpace(v) == "" {
				s.mail[k] = nil
			}
		}
		if pw, ok := body["smtpPassword"].(string); ok {
			s.mail["smtpPassword"] = pw
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		problem(w, 405, "", "")
	}
}
