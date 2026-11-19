package easypatch

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/mail"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/reports"
)

// Patch reports (one-product plan, C5): the compliance trend, the
// installations report, and monthly PDF reports with their schedules.
// Reports need report.view besides patch.view. The trend and monthly reports
// describe whole organizations, so they need both over the organization; the
// installations report lists devices, so it needs them at each device's site.

const (
	// MaxInstallations is the most rows the installations report reads.
	MaxInstallations = 5000
	// DefaultReportDays and MaxReportDays bound how far back the trend and
	// the installations report go.
	DefaultReportDays = 30
	MaxReportDays     = 365
	// maxRecipients is EasyPatch's limit on a report's recipients.
	maxRecipients = 20
)

// InstallationCategories and InstallationResults are what the installations
// report filters on, as EasyPatch names them.
var (
	InstallationCategories = []string{"Security", "Critical", "Cumulative", "Definition", "ServicingStack", "DotNet", "Feature", "Driver",
		"Other", "Application"}
	InstallationResults = []string{"Succeeded", "Failed", "Skipped", statusCanceled}
)

// reportOrg is a linked organization a report covers.
type reportOrg struct {
	id, ep uuid.UUID
	name   string
}

// reportOrganizations lists the linked organizations (or the one asked for)
// where the caller holds report.view and perm over the whole organization.
func (s *Service) reportOrganizations(ctx context.Context, c access.Caller, org uuid.UUID, perm rbac.Permission) ([]reportOrg, error) {
	return s.wholeOrganizations(ctx, c, org, rbac.PermReportView, perm)
}

// linkedOrganizations lists the linked organizations, or the one asked for,
// by name.
func (s *Service) linkedOrganizations(ctx context.Context, c access.Caller, org uuid.UUID) ([]reportOrg, error) {
	var out []reportOrg
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT l.organization_id, l.easypatch_id, o.name FROM easypatch_organizations l
			JOIN organizations o ON o.id = l.organization_id WHERE $1::uuid IS NULL OR l.organization_id = $1 ORDER BY o.name`, nullID(org))
		if err != nil {
			return err
		}
		for rows.Next() {
			var o reportOrg
			if err := rows.Scan(&o.id, &o.ep, &o.name); err != nil {
				return err
			}
			out = append(out, o)
		}
		return rows.Err()
	})
	return out, err
}

// reportConn is the engine's client for a report, or errNotConfigured.
func (s *Service) reportConn(ctx context.Context) (*Client, error) {
	r, cl, err := s.conn(ctx)
	if err == nil && r == nil {
		err = errNotConfigured
	}
	return cl, err
}

// Trend is the daily compliance of the organizations a caller sees as a
// whole, added up.
type Trend struct {
	Points []TrendPoint `json:"points"`
	// Organizations counts the organizations in it.
	Organizations int `json:"organizations"`
}

// ComplianceTrend adds up, day by day, the compliance EasyPatch recorded for
// the organizations (or the one asked for) the caller sees patching of as a
// whole, over the days ending today.
func (s *Service) ComplianceTrend(ctx context.Context, c access.Caller, org uuid.UUID, days int) (Trend, error) {
	if !c.CanAnywhere(rbac.PermReportView) || !c.CanAnywhere(rbac.PermPatchView) {
		return Trend{}, apperr.Forbidden()
	}
	if days == 0 {
		days = DefaultReportDays
	}
	if days < 7 || days > MaxReportDays {
		return Trend{}, apperr.Invalid("days", "Choose from 7 to 365 days.")
	}
	cl, err := s.reportConn(ctx)
	if err != nil {
		return Trend{}, err
	}
	orgs, err := s.reportOrganizations(ctx, c, org, rbac.PermPatchView)
	if err != nil {
		return Trend{}, err
	}
	today := s.now().UTC()
	from, to := today.AddDate(0, 0, -(days-1)).Format(time.DateOnly), today.Format(time.DateOnly)
	byDate := map[string]*TrendPoint{}
	for _, o := range orgs {
		points, err := cl.ComplianceTrend(s.as(ctx, c, RoleReadOnly, o.ep), o.ep, from, to)
		if err != nil {
			s.noteError(err)
			return Trend{}, epError(err)
		}
		for _, p := range points {
			t := byDate[p.Date]
			if t == nil {
				t = &TrendPoint{Date: p.Date}
				byDate[p.Date] = t
			}
			t.TotalEndpoints += p.TotalEndpoints
			t.Compliant += p.Compliant
			t.MissingUpdates += p.MissingUpdates
			t.FailedUpdates += p.FailedUpdates
			t.RebootRequired += p.RebootRequired
			t.ScanStale += p.ScanStale
			t.NeverScanned += p.NeverScanned
			t.Offline += p.Offline
			t.MissingRequiredUpdates += p.MissingRequiredUpdates
		}
	}
	out := Trend{Points: []TrendPoint{}, Organizations: len(orgs)}
	for _, p := range byDate {
		p.CompliancePercent = percent(p.Compliant, p.TotalEndpoints)
		out.Points = append(out.Points, *p)
	}
	slices.SortFunc(out.Points, func(a, b TrendPoint) int { return strings.Compare(a.Date, b.Date) })
	return out, nil
}

// percent is part of whole as a percentage with one decimal, as EasyPatch
// rounds it; 0 of nothing is 0.
func percent(part, whole int) float64 {
	if whole == 0 {
		return 0
	}
	return math.Round(float64(part)*1000/float64(whole)) / 10
}

// InstallationQuery narrows the installations report.
type InstallationQuery struct {
	OrganizationID, SiteID uuid.UUID
	// Days is how far back it goes, from 1 to 365; 0 is 30.
	Days int
	// Category and Result are among InstallationCategories and
	// InstallationResults, or empty for any.
	Category, Result string
}

// Installation is one update a job finished with on a device: installed,
// failed, skipped or canceled.
type Installation struct {
	CompletedAt      time.Time
	DeviceID         uuid.UUID
	DeviceName       string
	OrganizationID   uuid.UUID
	OrganizationName string
	SiteID           uuid.UUID
	SiteName         string
	Title            string
	KB               string
	Category         string
	Result           string
	// Detail is why it was skipped, or EasyPatch's error and its code.
	Detail         string
	RebootRequired bool
	RequestedBy    string
	JobID          uuid.UUID
}

// Installations is the report's rows, newest first; Truncated says
// EasyPatch had more than MaxInstallations.
type Installations struct {
	Items     []Installation
	Truncated bool
}

// Installations lists what EasyPatch's jobs installed, failed to install or
// skipped on the devices the caller sees patching of, newest first.
// Endpoints with no EasyRMM device are left out.
func (s *Service) Installations(ctx context.Context, c access.Caller, q InstallationQuery) (Installations, error) {
	if !c.CanAnywhere(rbac.PermReportView) || !c.CanAnywhere(rbac.PermPatchView) {
		return Installations{}, apperr.Forbidden()
	}
	if q.Days == 0 {
		q.Days = DefaultReportDays
	}
	f := apperr.Fields{}
	f.Check(q.Days >= 1 && q.Days <= MaxReportDays, "days", "Choose from 1 to 365 days.")
	f.Check(q.Category == "" || slices.Contains(InstallationCategories, q.Category), "category", "Choose a category.")
	f.Check(q.Result == "" || slices.Contains(InstallationResults, q.Result), "result", "Choose a result.")
	if err := f.Err(); err != nil {
		return Installations{}, err
	}
	cl, err := s.reportConn(ctx)
	if err != nil {
		return Installations{}, err
	}
	orgs, err := s.patchOrganizations(ctx, c, q.OrganizationID)
	if err != nil {
		return Installations{}, err
	}
	now := s.now().UTC()
	filter := InstallationFilter{From: now.AddDate(0, 0, -q.Days), To: now.Add(time.Minute), Category: q.Category, Result: q.Result}
	var rows []InstallationRow
	out := Installations{Items: []Installation{}}
	for _, org := range orgs {
		filter.OrganizationID = org
		for page := 1; ; page++ {
			p, err := cl.Installations(s.as(ctx, c, RoleReadOnly, org), filter, page)
			if err != nil {
				s.noteError(err)
				return Installations{}, epError(err)
			}
			rows = append(rows, p.Items...)
			if len(rows) >= MaxInstallations {
				out.Truncated = len(rows) > MaxInstallations || p.TotalCount > page*PageSize
				rows = rows[:MaxInstallations]
				break
			}
			if len(p.Items) < PageSize || page*PageSize >= p.TotalCount {
				break
			}
		}
		if len(rows) >= MaxInstallations {
			out.Truncated = out.Truncated || org != orgs[len(orgs)-1]
			break
		}
	}
	ids := make([]uuid.UUID, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.EndpointID)
	}
	devices, err := s.linkedDevices(ctx, c, dedupe(ids))
	if err != nil {
		return Installations{}, err
	}
	for _, r := range rows {
		d, ok := devices[r.EndpointID]
		if !ok || r.CompletedAt == nil || (q.SiteID != uuid.Nil && d.siteID != q.SiteID) {
			continue
		}
		detail := r.SkipReason
		if r.ErrorMessage != "" || r.ErrorCode != "" {
			detail = strings.TrimSpace(strings.TrimSpace(r.ErrorMessage) + " " + parenthesized(r.ErrorCode))
		}
		out.Items = append(out.Items, Installation{CompletedAt: *r.CompletedAt, DeviceID: d.id, DeviceName: d.name,
			OrganizationID: d.organizationID, OrganizationName: d.organizationName, SiteID: d.siteID, SiteName: d.siteName,
			Title: r.Title, KB: r.KbNumber, Category: r.Category, Result: r.Status, Detail: detail, RebootRequired: r.RebootRequired,
			RequestedBy: r.RequestedBy, JobID: r.JobID})
	}
	slices.SortStableFunc(out.Items, func(a, b Installation) int { return b.CompletedAt.Compare(a.CompletedAt) })
	return out, nil
}

func parenthesized(s string) string {
	if s == "" {
		return ""
	}
	return "(" + s + ")"
}

// MonthlyReportView is a monthly report as EasyRMM shows it, under the
// EasyRMM organization it is about.
type MonthlyReportView struct {
	MonthlyReport
	OrganizationID   uuid.UUID `json:"organizationId"`
	OrganizationName string    `json:"organizationName"`
	// CanManage says the caller may email and delete it.
	CanManage bool `json:"canManage"`
}

// MonthlyReportList is the newest monthly reports of the organizations
// asked for; Capped says there are older ones.
type MonthlyReportList struct {
	Items  []MonthlyReportView `json:"items"`
	Capped bool                `json:"capped"`
	// CanGenerate lists the organizations the caller may make reports of.
	CanGenerate []uuid.UUID `json:"canGenerate"`
}

// MonthlyReports lists the newest monthly reports of the organizations (or
// the one asked for) the caller sees patching of as a whole.
func (s *Service) MonthlyReports(ctx context.Context, c access.Caller, org uuid.UUID) (MonthlyReportList, error) {
	if !c.CanAnywhere(rbac.PermReportView) || !c.CanAnywhere(rbac.PermPatchView) {
		return MonthlyReportList{}, apperr.Forbidden()
	}
	cl, err := s.reportConn(ctx)
	if err != nil {
		return MonthlyReportList{}, err
	}
	orgs, err := s.reportOrganizations(ctx, c, org, rbac.PermPatchView)
	if err != nil {
		return MonthlyReportList{}, err
	}
	out := MonthlyReportList{Items: []MonthlyReportView{}, CanGenerate: []uuid.UUID{}}
	for _, o := range orgs {
		p, err := cl.MonthlyReports(s.as(ctx, c, RoleReadOnly, o.ep), o.ep, 1)
		if err != nil {
			s.noteError(err)
			return MonthlyReportList{}, epError(err)
		}
		manage := c.Can(rbac.PermPatchManage, rbac.Org(o.id))
		for _, m := range p.Items {
			out.Items = append(out.Items, MonthlyReportView{MonthlyReport: m, OrganizationID: o.id, OrganizationName: o.name, CanManage: manage})
		}
		out.Capped = out.Capped || p.TotalCount > len(p.Items)
		if manage {
			out.CanGenerate = append(out.CanGenerate, o.id)
		}
	}
	slices.SortStableFunc(out.Items, func(a, b MonthlyReportView) int { return b.GeneratedAt.Compare(a.GeneratedAt) })
	if len(out.Items) > PageSize {
		out.Items, out.Capped = out.Items[:PageSize], true
	}
	return out, nil
}

// monthlyReport reads a report and the organization it belongs to, when
// the caller holds report.view and perm over that organization.
func (s *Service) monthlyReport(ctx context.Context, c access.Caller, id uuid.UUID, perm rbac.Permission) (MonthlyReport, reportOrg, *Client, error) {
	cl, err := s.reportConn(ctx)
	if err != nil {
		return MonthlyReport{}, reportOrg{}, nil, err
	}
	orgs, err := s.reportOrganizations(ctx, c, uuid.Nil, rbac.PermPatchView)
	if err != nil {
		return MonthlyReport{}, reportOrg{}, nil, err
	}
	if len(orgs) == 0 {
		return MonthlyReport{}, reportOrg{}, nil, apperr.NotFound()
	}
	eps := make([]uuid.UUID, 0, len(orgs))
	for _, o := range orgs {
		eps = append(eps, o.ep)
	}
	m, err := cl.MonthlyReport(s.as(ctx, c, RoleReadOnly, eps...), id)
	if err != nil {
		if IsStatus(err, http.StatusNotFound) || IsStatus(err, http.StatusForbidden) {
			return MonthlyReport{}, reportOrg{}, nil, apperr.NotFound()
		}
		s.noteError(err)
		return MonthlyReport{}, reportOrg{}, nil, epError(err)
	}
	i := slices.IndexFunc(orgs, func(o reportOrg) bool { return o.ep == m.OrganizationID })
	if i < 0 {
		return MonthlyReport{}, reportOrg{}, nil, apperr.NotFound()
	}
	if !c.Can(perm, rbac.Org(orgs[i].id)) {
		return MonthlyReport{}, reportOrg{}, nil, apperr.Forbidden()
	}
	return m, orgs[i], cl, nil
}

// GenerateMonthlyReport makes an organization's report of a month: a past
// one, or the current one so far.
func (s *Service) GenerateMonthlyReport(ctx context.Context, c access.Caller, org uuid.UUID, year, month int, endpointList bool) (MonthlyReportView, error) {
	_, cl, err := s.operable(ctx)
	if err != nil {
		return MonthlyReportView{}, err
	}
	if !c.Can(rbac.PermReportView, rbac.Org(org)) || !c.Can(rbac.PermPatchManage, rbac.Org(org)) {
		return MonthlyReportView{}, apperr.Forbidden()
	}
	now := s.now().UTC()
	f := apperr.Fields{}
	f.Check(month >= 1 && month <= 12, "month", "Choose a month.")
	start := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)
	f.Check(!start.After(now) && start.After(now.AddDate(-10, 0, 0)), "month", "Choose a month that has started and is at most 10 years old.")
	if err := f.Err(); err != nil {
		return MonthlyReportView{}, err
	}
	orgs, err := s.reportOrganizations(ctx, c, org, rbac.PermPatchManage)
	if err != nil {
		return MonthlyReportView{}, err
	}
	if len(orgs) == 0 {
		return MonthlyReportView{}, errOrgNotLinked
	}
	o := orgs[0]
	m, err := cl.GenerateMonthlyReport(s.as(ctx, c, RoleAdmin, o.ep), o.ep, year, month, endpointList, c.Actor.Label)
	if err != nil {
		s.noteError(err)
		return MonthlyReportView{}, epError(err)
	}
	if err := s.recordReport(ctx, c, "patch.report_generate", o, m, map[string]any{"includeEndpointList": endpointList}); err != nil {
		return MonthlyReportView{}, err
	}
	return MonthlyReportView{MonthlyReport: m, OrganizationID: o.id, OrganizationName: o.name, CanManage: true}, nil
}

// MonthlyReportPDF reads a monthly report's PDF, and records that it left
// EasyRMM.
func (s *Service) MonthlyReportPDF(ctx context.Context, c access.Caller, id uuid.UUID) (MonthlyReport, []byte, error) {
	m, o, cl, err := s.monthlyReport(ctx, c, id, rbac.PermPatchView)
	if err != nil {
		return MonthlyReport{}, nil, err
	}
	pdf, err := cl.MonthlyReportPDF(s.as(ctx, c, RoleReadOnly, o.ep), id)
	if err != nil {
		s.noteError(err)
		return MonthlyReport{}, nil, epError(err)
	}
	if err := s.recordReport(ctx, c, "patch.report_download", o, m, nil); err != nil {
		return MonthlyReport{}, nil, err
	}
	return m, pdf, nil
}

// SendMonthlyReport emails a monthly report to recipients, or to its
// organization's schedule's recipients when none are given.
func (s *Service) SendMonthlyReport(ctx context.Context, c access.Caller, id uuid.UUID, recipients []string) (MonthlyReportView, error) {
	if _, _, err := s.operable(ctx); err != nil {
		return MonthlyReportView{}, err
	}
	to, err := validRecipients(recipients, false)
	if err != nil {
		return MonthlyReportView{}, err
	}
	m, o, cl, err := s.monthlyReport(ctx, c, id, rbac.PermPatchManage)
	if err != nil {
		return MonthlyReportView{}, err
	}
	sent, err := cl.SendMonthlyReport(s.as(ctx, c, RoleAdmin, o.ep), id, to, c.Actor.Label)
	if err != nil {
		return MonthlyReportView{}, s.mailError(ctx, err)
	}
	if err := s.recordReport(ctx, c, "patch.report_send", o, m, map[string]any{"recipients": len(sent.Recipients)}); err != nil {
		return MonthlyReportView{}, err
	}
	return MonthlyReportView{MonthlyReport: sent, OrganizationID: o.id, OrganizationName: o.name, CanManage: true}, nil
}

// DeleteMonthlyReport deletes a monthly report.
func (s *Service) DeleteMonthlyReport(ctx context.Context, c access.Caller, id uuid.UUID) error {
	if _, _, err := s.operable(ctx); err != nil {
		return err
	}
	m, o, cl, err := s.monthlyReport(ctx, c, id, rbac.PermPatchManage)
	if err != nil {
		return err
	}
	if err := cl.DeleteMonthlyReport(s.as(ctx, c, RoleAdmin, o.ep), id, c.Actor.Label); err != nil {
		s.noteError(err)
		return epError(err)
	}
	return s.recordReport(ctx, c, "patch.report_delete", o, m, nil)
}

// recordReport audits an action on a monthly report.
func (s *Service) recordReport(ctx context.Context, c access.Caller, action string, o reportOrg, m MonthlyReport, extra map[string]any) error {
	details := map[string]any{"period": monthOf(m.PeriodStart), "file": m.FileName, "monthToDate": m.MonthToDate}
	for k, v := range extra {
		details[k] = v
	}
	return s.record(ctx, []audit.Event{{Actor: c.Actor, Action: action, TargetType: "patch_report", TargetID: m.ID.String(),
		OrganizationID: o.id, Outcome: audit.Success, Details: details}})
}

// monthOf is a date's month, as 2006-01.
func monthOf(date string) string {
	if len(date) >= 7 {
		return date[:7]
	}
	return date
}

// validRecipients trims and checks email addresses as EasyPatch does.
func validRecipients(in []string, required bool) ([]string, error) {
	out := []string{}
	for _, r := range in {
		r = strings.TrimSpace(r)
		if r != "" && !slices.ContainsFunc(out, func(x string) bool { return strings.EqualFold(x, r) }) {
			out = append(out, r)
		}
	}
	switch {
	case len(out) > maxRecipients:
		return nil, apperr.Invalid("recipients", fmt.Sprintf("Enter at most %d email addresses.", maxRecipients))
	case required && len(out) == 0:
		return nil, apperr.Invalid("recipients", "Enter at least one email address.")
	}
	for _, r := range out {
		a, err := mail.ParseAddress(r)
		if err != nil || len(r) > 254 || !strings.EqualFold(a.Address, r) {
			return nil, apperr.Invalid("recipients", fmt.Sprintf("%q is not an email address.", r))
		}
	}
	return out, nil
}

// mailError explains the engine refusing to email a report, in EasyRMM's
// terms: EasyRMM's own mail server sends it.
func (s *Service) mailError(ctx context.Context, err error) error {
	var e *Error
	if !errors.As(err, &e) {
		s.noteError(err)
		return epError(err)
	}
	switch e.Code {
	case "smtp_not_configured":
		return apperr.Conflict("mail_not_configured", "EasyRMM has no mail server to send reports with. Set EASYRMM_SMTP_HOST and the other EASYRMM_SMTP_ settings, then restart EasyRMM.")
	case "smtp_not_encrypted":
		return apperr.Conflict("mail_not_encrypted", "Reports are emailed only over STARTTLS or TLS, and EASYRMM_SMTP_TLS is none.")
	case "report_too_large":
		return apperr.Conflict("report_too_large", "The report is larger than 15 MB, too large to email: download it instead.")
	case "no_recipients":
		return apperr.Invalid("recipients", "Enter recipients, or add them to the organization's report schedule.")
	}
	s.noteError(err)
	return epError(err)
}

// ScheduleView is an organization's monthly report schedule.
type ScheduleView struct {
	ReportSchedule
	OrganizationID   uuid.UUID `json:"organizationId"`
	OrganizationName string    `json:"organizationName"`
	CanEdit          bool      `json:"canEdit"`
}

// ReportSchedules lists the monthly report schedules of the organizations
// the caller sees patching of as a whole.
func (s *Service) ReportSchedules(ctx context.Context, c access.Caller) ([]ScheduleView, error) {
	if !c.CanAnywhere(rbac.PermReportView) || !c.CanAnywhere(rbac.PermPatchView) {
		return nil, apperr.Forbidden()
	}
	cl, err := s.reportConn(ctx)
	if err != nil {
		return nil, err
	}
	orgs, err := s.reportOrganizations(ctx, c, uuid.Nil, rbac.PermPatchView)
	if err != nil {
		return nil, err
	}
	out := []ScheduleView{}
	for _, o := range orgs {
		sc, err := cl.ReportSchedule(s.as(ctx, c, RoleReadOnly, o.ep), o.ep)
		if err != nil {
			s.noteError(err)
			return nil, epError(err)
		}
		out = append(out, ScheduleView{ReportSchedule: orEmptySchedule(sc), OrganizationID: o.id, OrganizationName: o.name,
			CanEdit: c.Can(rbac.PermPatchConfigure, rbac.Org(o.id))})
	}
	return out, nil
}

func orEmptySchedule(s ReportSchedule) ReportSchedule {
	s.Recipients = orEmpty(s.Recipients)
	return s
}

// SetReportSchedule changes an organization's monthly report schedule: on
// a day from 1 to 28, the report of the month before is made and emailed.
func (s *Service) SetReportSchedule(ctx context.Context, c access.Caller, org uuid.UUID, in ReportScheduleInput) (ScheduleView, error) {
	if _, _, err := s.operable(ctx); err != nil {
		return ScheduleView{}, err
	}
	if !c.Can(rbac.PermReportView, rbac.Org(org)) || !c.Can(rbac.PermPatchConfigure, rbac.Org(org)) {
		return ScheduleView{}, apperr.Forbidden()
	}
	if in.DayOfMonth < 1 || in.DayOfMonth > 28 {
		return ScheduleView{}, apperr.Invalid("dayOfMonth", "Choose a day from 1 to 28.")
	}
	to, err := validRecipients(in.Recipients, in.Enabled)
	if err != nil {
		return ScheduleView{}, err
	}
	in.Recipients = to
	cl, err := s.reportConn(ctx)
	if err != nil {
		return ScheduleView{}, err
	}
	orgs, err := s.reportOrganizations(ctx, c, org, rbac.PermPatchConfigure)
	if err != nil {
		return ScheduleView{}, err
	}
	if len(orgs) == 0 {
		return ScheduleView{}, errOrgNotLinked
	}
	o := orgs[0]
	sc, err := cl.SetReportSchedule(s.as(ctx, c, RoleAdmin, o.ep), o.ep, in, c.Actor.Label)
	if err != nil {
		s.noteError(err)
		return ScheduleView{}, epError(err)
	}
	ev := audit.Event{Actor: c.Actor, Action: "patch.report_schedule", TargetType: "organization", TargetID: o.id.String(), OrganizationID: o.id,
		Outcome: audit.Success, Details: map[string]any{"enabled": in.Enabled, "dayOfMonth": in.DayOfMonth, "recipients": len(in.Recipients),
			"includeEndpointList": in.IncludeEndpointList}}
	if err := s.record(ctx, []audit.Event{ev}); err != nil {
		return ScheduleView{}, err
	}
	return ScheduleView{ReportSchedule: orEmptySchedule(sc), OrganizationID: o.id, OrganizationName: o.name, CanEdit: true}, nil
}

// The patch reports (reports.PatchSource): EasyRMM's reports read patching
// through these.

var _ reports.PatchSource = (*Service)(nil)

// PatchDevices lists, for the patch compliance report, the devices whose
// patching the caller sees and what EasyPatch says about them. An
// organization EasyPatch could not be read for fails the report rather
// than leave its devices out.
func (s *Service) PatchDevices(ctx context.Context, c access.Caller, q reports.Query) ([]reports.PatchDevice, bool, error) {
	fleet, err := s.Fleet(ctx, c, FleetQuery{OrganizationID: q.OrganizationID, SiteID: q.SiteID, Compliance: q.Compliance, Search: q.Search})
	if err != nil {
		return nil, false, err
	}
	if len(fleet.Errors) > 0 {
		return nil, false, apperr.Unavailable("easypatch_unavailable", "EasyPatch could not be read for the report. "+strings.Join(fleet.Errors, " "))
	}
	out := make([]reports.PatchDevice, 0, len(fleet.Devices))
	for _, d := range fleet.Devices {
		p := reports.PatchDevice{OrganizationID: d.OrganizationID, SiteID: d.SiteID, Organization: d.OrganizationName, Site: d.SiteName,
			Device: d.Name, Platform: d.Platform}
		switch e := d.Endpoint; {
		case e != nil:
			p.Linked, p.OS, p.OSBuild, p.OSSupport, p.Compliance = true, e.OperatingSystem, e.OSBuild, e.OSSupportStatus, e.ComplianceStatus
			p.MissingRequired, p.MissingTotal, p.Failed, p.KnownExploited = e.MissingRequiredCount, e.MissingTotalCount, e.FailedCount, e.KnownExploitedCount
			p.RestartPending, p.Online, p.LastScan, p.LastCheckIn = e.RebootPending, e.IsOnline, e.LastScanAt, e.LastCheckInAt
		case d.Removal != nil:
			p.NotPatched = "EasyRMM is removing EasyPatch's agent from the device."
		case d.Stopped != nil:
			p.NotPatched = "Patching was stopped for the device."
		case d.Reason != "":
			p.NotPatched = d.Reason
		case d.Install != nil && d.Install.State == InstallFailed:
			p.NotPatched = "Installing EasyPatch's agent failed: " + d.Install.Error
		case d.Install != nil && d.Install.State != InstallSucceeded:
			p.NotPatched = "EasyPatch's agent is being installed."
		default:
			p.NotPatched = "EasyPatch's agent is not on the device."
		}
		out = append(out, p)
	}
	return out, fleet.Truncated, nil
}

// PatchInstallations lists, for the patch installations report, the updates
// EasyPatch's jobs finished with on the devices the caller sees patching
// of.
func (s *Service) PatchInstallations(ctx context.Context, c access.Caller, q reports.Query) ([]reports.PatchInstallation, bool, error) {
	list, err := s.Installations(ctx, c, InstallationQuery{OrganizationID: q.OrganizationID, SiteID: q.SiteID, Days: q.Days,
		Category: q.Category, Result: q.Result})
	if err != nil {
		return nil, false, err
	}
	out := make([]reports.PatchInstallation, 0, len(list.Items))
	for _, i := range list.Items {
		if q.Search != "" && !strings.Contains(strings.ToLower(i.DeviceName+" "+i.Title+" "+i.KB), strings.ToLower(strings.TrimSpace(q.Search))) {
			continue
		}
		out = append(out, reports.PatchInstallation{OrganizationID: i.OrganizationID, SiteID: i.SiteID, Organization: i.OrganizationName,
			Site: i.SiteName, Device: i.DeviceName, CompletedAt: i.CompletedAt, KB: i.KB, Title: i.Title, Category: i.Category, Result: i.Result,
			Detail: i.Detail, RestartRequired: i.RebootRequired, RequestedBy: i.RequestedBy, JobID: i.JobID})
	}
	return out, list.Truncated, nil
}
