package easypatch

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// EasyPatch's reports: the compliance trend, the installations report,
// monthly PDF reports and their schedules, and the mail server they are sent
// with.

// TrendPoint is one day of an organization's compliance, as EasyPatch
// recorded it that night.
type TrendPoint struct {
	// Date is the day, as 2006-01-02.
	Date                   string  `json:"date"`
	TotalEndpoints         int     `json:"totalEndpoints"`
	Compliant              int     `json:"compliant"`
	MissingUpdates         int     `json:"missingUpdates"`
	FailedUpdates          int     `json:"failedUpdates"`
	RebootRequired         int     `json:"rebootRequired"`
	ScanStale              int     `json:"scanStale"`
	NeverScanned           int     `json:"neverScanned"`
	Offline                int     `json:"offline"`
	MissingRequiredUpdates int     `json:"missingRequiredUpdates"`
	CompliancePercent      float64 `json:"compliancePercent"`
}

// ComplianceTrend reads an organization's daily compliance from one day to
// another (both 2006-01-02, both included).
func (c *Client) ComplianceTrend(ctx context.Context, org uuid.UUID, from, to string) ([]TrendPoint, error) {
	var out []TrendPoint
	q := url.Values{"organizationId": {org.String()}, "from": {from}, "to": {to}}
	err := c.do(ctx, http.MethodGet, "/api/v1/reports/compliance/trend", q, nil, "", &out)
	return out, err
}

// InstallationRow is one update a job finished with, installed or not.
type InstallationRow struct {
	JobID            uuid.UUID  `json:"jobId"`
	EndpointID       uuid.UUID  `json:"endpointId"`
	Hostname         string     `json:"hostname"`
	OrganizationName string     `json:"organizationName"`
	SiteName         string     `json:"siteName"`
	UpdateGUID       uuid.UUID  `json:"updateGuid"`
	Title            string     `json:"title"`
	KbNumber         string     `json:"kbNumber"`
	Category         string     `json:"category"`
	Status           string     `json:"status"`
	SkipReason       string     `json:"skipReason"`
	ErrorCode        string     `json:"errorCode"`
	ErrorMessage     string     `json:"errorMessage"`
	RebootRequired   bool       `json:"rebootRequired"`
	RequestedBy      string     `json:"requestedBy"`
	CompletedAt      *time.Time `json:"completedAt"`
}

// InstallationFilter narrows the installations report to one organization
// and the updates finished from one time to another.
type InstallationFilter struct {
	OrganizationID uuid.UUID
	SiteID         *uuid.UUID
	From, To       time.Time
	// Category and Result are EasyPatch's names (Security, Failed...), or
	// empty for any.
	Category, Result string
}

// Installations reads a page of the installations report, newest first.
func (c *Client) Installations(ctx context.Context, f InstallationFilter, page int) (Page[InstallationRow], error) {
	q := url.Values{"organizationId": {f.OrganizationID.String()}, "from": {f.From.UTC().Format(time.RFC3339)},
		"to": {f.To.UTC().Format(time.RFC3339)}, "page": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(PageSize)}}
	if f.SiteID != nil {
		q.Set("siteId", f.SiteID.String())
	}
	if f.Category != "" {
		q.Set("category", f.Category)
	}
	if f.Result != "" {
		q.Set("result", f.Result)
	}
	var p Page[InstallationRow]
	err := c.do(ctx, http.MethodGet, "/api/v1/reports/installations", q, nil, "", &p)
	return p, err
}

// ReportSchedule is when an organization's monthly report is made and who
// it is emailed to. Dates are in the organization's time zone.
type ReportSchedule struct {
	OrganizationID      uuid.UUID  `json:"organizationId"`
	Enabled             bool       `json:"enabled"`
	Recipients          []string   `json:"recipients"`
	DayOfMonth          int        `json:"dayOfMonth"`
	IncludeEndpointList bool       `json:"includeEndpointList"`
	EnabledAt           *time.Time `json:"enabledAt"`
	LastScheduledPeriod *string    `json:"lastScheduledPeriod"`
	NextReportDate      *string    `json:"nextReportDate"`
	NextReportPeriod    *string    `json:"nextReportPeriod"`
	TimeZone            string     `json:"timeZone"`
	UpdatedAt           *time.Time `json:"updatedAt"`
}

// ReportScheduleInput is what changes in a schedule.
type ReportScheduleInput struct {
	Enabled             bool     `json:"enabled"`
	Recipients          []string `json:"recipients"`
	DayOfMonth          int      `json:"dayOfMonth"`
	IncludeEndpointList bool     `json:"includeEndpointList"`
}

func reportSchedulePath(org uuid.UUID) string {
	return "/api/v1/organizations/" + org.String() + "/report-schedule"
}

// ReportSchedule reads an organization's monthly report schedule.
func (c *Client) ReportSchedule(ctx context.Context, org uuid.UUID) (ReportSchedule, error) {
	var s ReportSchedule
	err := c.do(ctx, http.MethodGet, reportSchedulePath(org), nil, nil, "", &s)
	return s, err
}

// SetReportSchedule replaces an organization's monthly report schedule.
func (c *Client) SetReportSchedule(ctx context.Context, org uuid.UUID, in ReportScheduleInput, onBehalfOf string) (ReportSchedule, error) {
	var s ReportSchedule
	err := c.do(ctx, http.MethodPut, reportSchedulePath(org), nil, in, onBehalfOf, &s)
	return s, err
}

// MonthlyReport is a generated monthly report: the PDF, and its delivery
// when it was emailed.
type MonthlyReport struct {
	ID               uuid.UUID `json:"id"`
	OrganizationID   uuid.UUID `json:"organizationId"`
	OrganizationName string    `json:"organizationName"`
	// PeriodStart and PeriodEnd are the month's first and last days, as
	// 2006-01-02; a report of the month so far ends today.
	PeriodStart string    `json:"periodStart"`
	PeriodEnd   string    `json:"periodEnd"`
	MonthToDate bool      `json:"monthToDate"`
	Scheduled   bool      `json:"scheduled"`
	GeneratedAt time.Time `json:"generatedAt"`
	GeneratedBy string    `json:"generatedBy"`
	FileName    string    `json:"fileName"`
	SizeBytes   int64     `json:"sizeBytes"`
	Sha256      string    `json:"sha256"`
	// DeliveryStatus is Pending, Sending, Sent or Failed once the report
	// was emailed, and empty before.
	DeliveryStatus string     `json:"deliveryStatus"`
	Recipients     []string   `json:"recipients"`
	Attempts       int        `json:"attempts"`
	QueuedAt       *time.Time `json:"queuedAt"`
	SentAt         *time.Time `json:"sentAt"`
	LastError      string     `json:"lastError"`
}

// MonthlyReports reads a page of an organization's monthly reports, newest
// first.
func (c *Client) MonthlyReports(ctx context.Context, org uuid.UUID, page int) (Page[MonthlyReport], error) {
	q := url.Values{"organizationId": {org.String()}, "page": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(PageSize)}}
	var p Page[MonthlyReport]
	err := c.do(ctx, http.MethodGet, "/api/v1/monthly-reports", q, nil, "", &p)
	return p, err
}

// GenerateMonthlyReport makes an organization's report of a month; the
// current month makes a report of the month so far.
func (c *Client) GenerateMonthlyReport(ctx context.Context, org uuid.UUID, year, month int, includeEndpointList bool, onBehalfOf string) (MonthlyReport, error) {
	body := map[string]any{"organizationId": org, "year": year, "month": month, "includeEndpointList": includeEndpointList}
	var r MonthlyReport
	err := c.do(ctx, http.MethodPost, "/api/v1/monthly-reports", nil, body, onBehalfOf, &r)
	return r, err
}

func monthlyReportPath(id uuid.UUID) string { return "/api/v1/monthly-reports/" + id.String() }

// MonthlyReport reads one monthly report.
func (c *Client) MonthlyReport(ctx context.Context, id uuid.UUID) (MonthlyReport, error) {
	var r MonthlyReport
	err := c.do(ctx, http.MethodGet, monthlyReportPath(id), nil, nil, "", &r)
	return r, err
}

// MonthlyReportPDF reads a monthly report's PDF.
func (c *Client) MonthlyReportPDF(ctx context.Context, id uuid.UUID) ([]byte, error) {
	var pdf []byte
	err := c.do(ctx, http.MethodGet, monthlyReportPath(id)+"/pdf", nil, nil, "", &pdf)
	return pdf, err
}

// SendMonthlyReport emails a monthly report to recipients, or to its
// organization's schedule's recipients when there are none.
func (c *Client) SendMonthlyReport(ctx context.Context, id uuid.UUID, recipients []string, onBehalfOf string) (MonthlyReport, error) {
	var r MonthlyReport
	err := c.do(ctx, http.MethodPost, monthlyReportPath(id)+"/send", nil, map[string]any{"recipients": recipients}, onBehalfOf, &r)
	return r, err
}

// DeleteMonthlyReport deletes a monthly report.
func (c *Client) DeleteMonthlyReport(ctx context.Context, id uuid.UUID, onBehalfOf string) error {
	return c.do(ctx, http.MethodDelete, monthlyReportPath(id), nil, nil, onBehalfOf, nil)
}

// MailSettings is the mail server EasyPatch emails reports and alerts with.
type MailSettings struct {
	SMTPHost                    string `json:"smtpHost"`
	SMTPPort                    int    `json:"smtpPort"`
	SMTPSecurity                string `json:"smtpSecurity"`
	SMTPUsername                string `json:"smtpUsername"`
	SMTPPasswordConfigured      bool   `json:"smtpPasswordConfigured"`
	FromAddress                 string `json:"fromAddress"`
	FromName                    string `json:"fromName"`
	AllowPrivateNetworkWebhooks bool   `json:"allowPrivateNetworkWebhooks"`
	SMTPSkipCertificateCheck    bool   `json:"smtpSkipCertificateValidation"`
}

// MailSettingsInput replaces the mail settings. A nil SMTPPassword keeps
// the stored one; an empty one removes it.
type MailSettingsInput struct {
	SMTPHost                    string  `json:"smtpHost"`
	SMTPPort                    int     `json:"smtpPort"`
	SMTPSecurity                string  `json:"smtpSecurity"`
	SMTPUsername                string  `json:"smtpUsername"`
	SMTPPassword                *string `json:"smtpPassword"`
	FromAddress                 string  `json:"fromAddress"`
	FromName                    string  `json:"fromName"`
	AllowPrivateNetworkWebhooks bool    `json:"allowPrivateNetworkWebhooks"`
	SMTPSkipCertificateCheck    bool    `json:"smtpSkipCertificateValidation"`
}

const mailSettingsPath = "/api/v1/notifications/settings"

// MailSettings reads EasyPatch's mail settings.
func (c *Client) MailSettings(ctx context.Context) (MailSettings, error) {
	var m MailSettings
	err := c.do(ctx, http.MethodGet, mailSettingsPath, nil, nil, "", &m)
	return m, err
}

// SetMailSettings replaces EasyPatch's mail settings.
func (c *Client) SetMailSettings(ctx context.Context, in MailSettingsInput) error {
	return c.do(ctx, http.MethodPut, mailSettingsPath, nil, in, "", nil)
}
