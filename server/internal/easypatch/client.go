// Package easypatch connects EasyRMM to an EasyPatch server (ADR-0030):
// the connection settings, which EasyPatch organization and endpoint each
// EasyRMM organization and device is, and the patch views and actions of
// the console. EasyPatch stays the source of truth for patch data; this
// package reads it through EasyPatch's API when it is asked for, with an
// EasyPatch API token, after EasyRMM's own permission checks.
package easypatch

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/netguard"
)

const (
	// requestTimeout bounds one call to EasyPatch.
	requestTimeout = 30 * time.Second
	// maxResponse bounds what EasyPatch may send back.
	maxResponse = 32 << 20
	// PageSize is the largest page EasyPatch's lists return.
	PageSize = 200
	// onBehalfOfHeader names the EasyRMM user an action is for. EasyPatch
	// records it when it supports it (CapabilityOnBehalfOf) and ignores it
	// otherwise.
	onBehalfOfHeader = "X-EasyPatch-On-Behalf-Of"
)

// Capabilities a server may list in /api/v1/server-info.
const (
	// CapabilityScheduledInstalls: install requests accept scheduledAt.
	CapabilityScheduledInstalls = "scheduled-installs"
	// CapabilityOnBehalfOf: API token requests may name the user they are
	// for.
	CapabilityOnBehalfOf = "on-behalf-of"
)

// Error is a failed call: EasyPatch's answer, or Status 0 when it could not
// be reached.
type Error struct {
	Status int
	// Code is EasyPatch's machine-readable code (duplicate_job,
	// validation_failed…), when it sent one.
	Code   string
	Detail string
}

func (e *Error) Error() string {
	if e.Status == 0 {
		return e.Detail
	}
	return fmt.Sprintf("EasyPatch answered %d: %s", e.Status, e.Detail)
}

// IsStatus reports whether err is EasyPatch answering with status.
func IsStatus(err error, status int) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == status
}

// Client calls one EasyPatch server's API with an API token.
type Client struct {
	base      *url.URL
	token     string
	userAgent string
	http      *http.Client
}

// ParseURL checks an EasyPatch server address: https, a host, no query,
// fragment or credentials. It returns it without a trailing slash.
func ParseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	switch {
	case err != nil || u.Host == "" || u.Hostname() == "":
		return nil, errors.New("must be an address such as https://patch.example.com")
	case u.Scheme != "https":
		return nil, errors.New("must start with https://")
	case u.User != nil:
		return nil, errors.New("must not contain a user name or password")
	case u.RawQuery != "" || u.Fragment != "" || u.Opaque != "":
		return nil, errors.New("must not contain a query or a fragment")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, errors.New("has an invalid port")
		}
	}
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

// SameServer reports whether two addresses name the same EasyPatch server,
// ignoring case, a default port and a trailing slash.
func SameServer(a, b string) bool {
	ua, errA := ParseURL(a)
	ub, errB := ParseURL(b)
	if errA != nil || errB != nil {
		return false
	}
	return hostPort(ua) == hostPort(ub) && ua.Path == ub.Path
}

func hostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// NewClient builds a client for the server at rawURL. caPEM, when set, is
// trusted besides the system's certificate authorities.
func NewClient(rawURL, token, caPEM, version string) (*Client, error) {
	base, err := ParseURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("url %w", err)
	}
	if token == "" {
		return nil, errors.New("an API token is required")
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if strings.TrimSpace(caPEM) != "" && !roots.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, errors.New("the CA certificate is not PEM")
	}
	// No link-local or cloud metadata addresses (netguard).
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: netguard.Control}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: requestTimeout,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &Client{
		base: base, token: token, userAgent: "EasyRMM/" + version,
		http: &http.Client{
			Transport: transport,
			Timeout:   requestTimeout,
			// A token is never sent anywhere but the configured server.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// do sends a request and decodes a JSON answer into out (nil for none).
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any, onBehalfOf string, out any) error {
	u := *c.base
	u.Path += path
	u.RawQuery = query.Encode()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if onBehalfOf != "" {
		req.Header.Set(onBehalfOfHeader, onBehalfOf)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return &Error{Detail: "Cannot reach EasyPatch: " + reachError(err)}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return &Error{Detail: "EasyPatch's answer was cut short: " + err.Error()}
	}
	if len(data) > maxResponse {
		return &Error{Status: resp.StatusCode, Detail: "EasyPatch's answer is larger than 32 MiB"}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return problem(resp.StatusCode, data)
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return &Error{Status: resp.StatusCode, Detail: "EasyPatch's answer is not what EasyRMM expects: " + err.Error()}
	}
	return nil
}

// reachError explains a transport failure without Go's request dump.
func reachError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var cert *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	switch {
	case errors.As(err, &unknown) || errors.As(err, &cert):
		return "its certificate is not trusted (" + err.Error() + "); add the CA certificate that signed it"
	case errors.Is(err, context.DeadlineExceeded):
		return "it did not answer within 30 seconds"
	}
	return err.Error()
}

// problem reads EasyPatch's problem details.
func problem(status int, data []byte) *Error {
	var p struct {
		Title  string `json:"title"`
		Detail string `json:"detail"`
		Code   string `json:"code"`
	}
	_ = json.Unmarshal(data, &p)
	detail := strings.TrimSpace(p.Detail)
	if detail == "" {
		detail = strings.TrimSpace(p.Title)
	}
	if detail == "" {
		switch status {
		case http.StatusUnauthorized:
			detail = "the API token is not valid: it may have expired or been revoked"
		case http.StatusForbidden:
			detail = "the API token may not do this"
		case http.StatusNotFound:
			detail = "not found"
		default:
			detail = http.StatusText(status)
		}
	}
	return &Error{Status: status, Code: cut(p.Code, 64), Detail: cut(detail, 500)}
}

// ServerInfo is what /api/v1/server-info says.
type ServerInfo struct {
	Version    string    `json:"version"`
	PublicURL  string    `json:"publicUrl"`
	ServerTime time.Time `json:"serverTime"`
	// Capabilities lists optional features (Capability*). Servers without
	// the EasyRMM integration changes send none.
	Capabilities []string `json:"capabilities"`
}

// ServerInfo asks the server what it is.
func (c *Client) ServerInfo(ctx context.Context) (ServerInfo, error) {
	var s ServerInfo
	err := c.do(ctx, http.MethodGet, "/api/v1/server-info", nil, nil, "", &s)
	return s, err
}

// CanOperate reports whether the token may act (an Admin token) rather than
// only read: listing enrollment tokens needs the operator role.
func (c *Client) CanOperate(ctx context.Context) (bool, error) {
	err := c.do(ctx, http.MethodGet, "/api/v1/enrollment-tokens", nil, nil, "", nil)
	if IsStatus(err, http.StatusForbidden) {
		return false, nil
	}
	return err == nil, err
}

// Organization is an EasyPatch organization.
type Organization struct {
	ID            uuid.UUID `json:"id"`
	Name          string    `json:"name"`
	IsActive      bool      `json:"isActive"`
	SiteCount     int       `json:"siteCount"`
	EndpointCount int       `json:"endpointCount"`
}

// Organizations lists the organizations the token can see.
func (c *Client) Organizations(ctx context.Context) ([]Organization, error) {
	var list []Organization
	err := c.do(ctx, http.MethodGet, "/api/v1/organizations", nil, nil, "", &list)
	return list, err
}

// Page is one page of an EasyPatch list.
type Page[T any] struct {
	Items      []T `json:"items"`
	Page       int `json:"page"`
	PageSize   int `json:"pageSize"`
	TotalCount int `json:"totalCount"`
}

// Endpoint is an EasyPatch endpoint as its lists show it.
type Endpoint struct {
	ID                   uuid.UUID  `json:"id"`
	Hostname             string     `json:"hostname"`
	OrganizationID       uuid.UUID  `json:"organizationId"`
	OrganizationName     string     `json:"organizationName"`
	SiteName             string     `json:"siteName"`
	Status               string     `json:"status"`
	OperatingSystem      string     `json:"operatingSystem"`
	Platform             string     `json:"platform"`
	AgentVersion         string     `json:"agentVersion"`
	AgentOutdated        bool       `json:"agentOutdated"`
	IsOnline             bool       `json:"isOnline"`
	LastCheckInAt        *time.Time `json:"lastCheckInAt"`
	LastScanAt           *time.Time `json:"lastScanAt"`
	ComplianceStatus     string     `json:"complianceStatus"`
	MissingRequiredCount int        `json:"missingRequiredCount"`
	MissingTotalCount    int        `json:"missingTotalCount"`
	MissingDeferredCount int        `json:"missingDeferredCount"`
	FailedCount          int        `json:"failedCount"`
	RebootPending        bool       `json:"rebootPending"`
	KnownExploitedCount  int        `json:"knownExploitedMissingCount"`
	CurrentActivity      string     `json:"currentActivity"`
}

// Endpoints lists one page of an organization's active endpoints.
func (c *Client) Endpoints(ctx context.Context, organizationID uuid.UUID, page int) (Page[Endpoint], error) {
	var p Page[Endpoint]
	q := url.Values{"organizationId": {organizationID.String()}, "pageSize": {strconv.Itoa(PageSize)}, "page": {strconv.Itoa(page)},
		"sort": {"hostname"}}
	err := c.do(ctx, http.MethodGet, "/api/v1/endpoints", q, nil, "", &p)
	return p, err
}

// Credential is one of an endpoint's agent credentials.
type Credential struct {
	CredentialID   string     `json:"credentialId"`
	KeyFingerprint string     `json:"keyFingerprint"`
	ExpiresAt      time.Time  `json:"expiresAt"`
	RevokedAt      *time.Time `json:"revokedAt"`
}

// EndpointDetail is one endpoint in full.
type EndpointDetail struct {
	Summary                  Endpoint     `json:"summary"`
	SerialNumber             string       `json:"serialNumber"`
	LastScanAttemptAt        *time.Time   `json:"lastScanAttemptAt"`
	LastScanError            string       `json:"lastScanError"`
	RebootReasons            []string     `json:"rebootReasons"`
	RebootPendingSince       *time.Time   `json:"rebootPendingSince"`
	InstalledCount           int          `json:"installedCount"`
	PendingRebootUpdateCount int          `json:"pendingRebootUpdateCount"`
	ComplianceEvaluatedAt    *time.Time   `json:"complianceEvaluatedAt"`
	Credentials              []Credential `json:"credentials"`
}

// Endpoint reads one endpoint.
func (c *Client) Endpoint(ctx context.Context, id uuid.UUID) (EndpointDetail, error) {
	var e EndpointDetail
	err := c.do(ctx, http.MethodGet, "/api/v1/endpoints/"+id.String(), nil, nil, "", &e)
	return e, err
}

// Package is the Linux package behind an update.
type Package struct {
	Name             string   `json:"name"`
	Version          string   `json:"version"`
	InstalledVersion string   `json:"installedVersion"`
	Repository       string   `json:"repository"`
	Advisories       []string `json:"advisories"`
}

// UpdateJob is the job working on an update right now.
type UpdateJob struct {
	JobID           uuid.UUID `json:"jobId"`
	JobStatus       string    `json:"jobStatus"`
	ItemStatus      string    `json:"itemStatus"`
	DownloadPercent *int      `json:"downloadPercent"`
	InstallPercent  *int      `json:"installPercent"`
	JobType         string    `json:"jobType"`
}

// Update is an update as it stands on one endpoint.
type Update struct {
	UpdateGUID      uuid.UUID  `json:"updateGuid"`
	Title           string     `json:"title"`
	KbNumber        string     `json:"kbNumber"`
	Category        string     `json:"category"`
	MsrcSeverity    string     `json:"msrcSeverity"`
	ReleaseDate     *time.Time `json:"releaseDate"`
	SizeBytes       *int64     `json:"sizeBytes"`
	RebootLikely    bool       `json:"rebootLikely"`
	SupportURL      string     `json:"supportUrl"`
	State           string     `json:"state"`
	IsRequired      bool       `json:"isRequired"`
	IsExcluded      bool       `json:"isExcluded"`
	FirstDetectedAt time.Time  `json:"firstDetectedAt"`
	StateChangedAt  time.Time  `json:"stateChangedAt"`
	InstalledAt     *time.Time `json:"installedAt"`
	FailedAttempts  int        `json:"failedAttempts"`
	ErrorCode       string     `json:"errorCode"`
	ErrorMessage    string     `json:"errorMessage"`
	ActiveJob       *UpdateJob `json:"activeJob"`
	Package         *Package   `json:"package"`
	DeferredUntil   *time.Time `json:"deferredUntil"`
	CveIDs          []string   `json:"cveIds"`
	KnownExploited  bool       `json:"knownExploited"`
	HoldReason      string     `json:"holdReason"`
}

// Updates lists an endpoint's updates that are not installed, optionally in
// one state.
func (c *Client) Updates(ctx context.Context, endpointID uuid.UUID, state string) ([]Update, error) {
	var q url.Values
	if state != "" {
		q = url.Values{"state": {state}}
	}
	var list []Update
	err := c.do(ctx, http.MethodGet, "/api/v1/endpoints/"+endpointID.String()+"/updates", q, nil, "", &list)
	return list, err
}

// InstalledUpdates lists the updates installed on an endpoint, newest first.
func (c *Client) InstalledUpdates(ctx context.Context, endpointID uuid.UUID) ([]Update, error) {
	var list []Update
	err := c.do(ctx, http.MethodGet, "/api/v1/endpoints/"+endpointID.String()+"/installed-updates", nil, nil, "", &list)
	return list, err
}

// HistoryEntry is one line of an endpoint's update history.
type HistoryEntry struct {
	ID               int64      `json:"id"`
	UpdateGUID       *uuid.UUID `json:"updateGuid"`
	Title            string     `json:"title"`
	KbNumber         string     `json:"kbNumber"`
	Operation        string     `json:"operation"`
	ResultCode       int        `json:"resultCode"`
	Result           string     `json:"result"`
	HResult          string     `json:"hResult"`
	ErrorDescription string     `json:"errorDescription"`
	Date             time.Time  `json:"date"`
}

// History lists one page of an endpoint's update history, newest first.
func (c *Client) History(ctx context.Context, endpointID uuid.UUID, page int) (Page[HistoryEntry], error) {
	var p Page[HistoryEntry]
	q := url.Values{"page": {strconv.Itoa(page)}, "pageSize": {"50"}}
	err := c.do(ctx, http.MethodGet, "/api/v1/endpoints/"+endpointID.String()+"/update-history", q, nil, "", &p)
	return p, err
}

// Job is an EasyPatch job as its lists show it.
type Job struct {
	ID              uuid.UUID  `json:"id"`
	EndpointID      uuid.UUID  `json:"endpointId"`
	Hostname        string     `json:"hostname"`
	OrganizationID  uuid.UUID  `json:"organizationId"`
	Type            string     `json:"type"`
	Status          string     `json:"status"`
	Trigger         string     `json:"trigger"`
	RequestedBy     string     `json:"requestedBy"`
	CreatedAt       time.Time  `json:"createdAt"`
	StartedAt       *time.Time `json:"startedAt"`
	CompletedAt     *time.Time `json:"completedAt"`
	ExpiresAt       time.Time  `json:"expiresAt"`
	ProgressPercent *int       `json:"progressPercent"`
	Phase           string     `json:"phase"`
	ProgressMessage string     `json:"progressMessage"`
	ErrorCode       string     `json:"errorCode"`
	ErrorMessage    string     `json:"errorMessage"`
	RebootRequired  bool       `json:"rebootRequired"`
	TimedOut        bool       `json:"timedOut"`
	CancelRequested bool       `json:"cancelRequested"`
	ItemCount       int        `json:"itemCount"`
	SucceededCount  int        `json:"succeededCount"`
	FailedCount     int        `json:"failedCount"`
}

// JobItem is one update of an install job.
type JobItem struct {
	UpdateGUID      uuid.UUID  `json:"updateGuid"`
	Title           string     `json:"title"`
	KbNumber        string     `json:"kbNumber"`
	Category        string     `json:"category"`
	Status          string     `json:"status"`
	SkipReason      string     `json:"skipReason"`
	ResultCode      *int       `json:"resultCode"`
	ErrorCode       string     `json:"errorCode"`
	ErrorMessage    string     `json:"errorMessage"`
	RebootRequired  bool       `json:"rebootRequired"`
	DownloadPercent *int       `json:"downloadPercent"`
	InstallPercent  *int       `json:"installPercent"`
	StartedAt       *time.Time `json:"startedAt"`
	CompletedAt     *time.Time `json:"completedAt"`
}

// JobEvent is something that happened to a job's endpoint during the job.
type JobEvent struct {
	ID        int64     `json:"id"`
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"createdAt"`
}

// JobDetail is one job in full.
type JobDetail struct {
	Summary      Job        `json:"summary"`
	InstallMode  string     `json:"installMode"`
	NotBefore    *time.Time `json:"notBefore"`
	DeliveredAt  *time.Time `json:"deliveredAt"`
	LastProgress *time.Time `json:"lastProgressAt"`
	Items        []JobItem  `json:"items"`
	Events       []JobEvent `json:"events"`
}

// EndpointJobs lists one page of an endpoint's jobs, newest first.
func (c *Client) EndpointJobs(ctx context.Context, endpointID uuid.UUID, page int) (Page[Job], error) {
	var p Page[Job]
	q := url.Values{"page": {strconv.Itoa(page)}, "pageSize": {"50"}}
	err := c.do(ctx, http.MethodGet, "/api/v1/endpoints/"+endpointID.String()+"/jobs", q, nil, "", &p)
	return p, err
}

// Jobs lists one page of an organization's jobs, newest first; active keeps
// those still to finish.
func (c *Client) Jobs(ctx context.Context, organizationID uuid.UUID, active bool, page int) (Page[Job], error) {
	var p Page[Job]
	q := url.Values{"organizationId": {organizationID.String()}, "page": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(PageSize)}}
	if active {
		q.Set("active", "true")
	}
	err := c.do(ctx, http.MethodGet, "/api/v1/jobs", q, nil, "", &p)
	return p, err
}

// Job reads one job.
func (c *Client) Job(ctx context.Context, id uuid.UUID) (JobDetail, error) {
	var j JobDetail
	err := c.do(ctx, http.MethodGet, "/api/v1/jobs/"+id.String(), nil, nil, "", &j)
	return j, err
}

// CancelJob cancels a job, or asks its agent to stop it.
func (c *Client) CancelJob(ctx context.Context, id uuid.UUID, onBehalfOf string) (JobDetail, error) {
	var j JobDetail
	err := c.do(ctx, http.MethodPost, "/api/v1/jobs/"+id.String()+"/cancel", nil, nil, onBehalfOf, &j)
	return j, err
}

// Policy is what an endpoint's effective policy says about when updates
// install.
type Policy struct {
	AutoInstallEnabled         bool     `json:"autoInstallEnabled"`
	MaintenanceDays            []int    `json:"maintenanceDays"`
	MaintenanceStart           string   `json:"maintenanceStart"`
	MaintenanceDurationMinutes *int     `json:"maintenanceDurationMinutes"`
	TimeZone                   string   `json:"timeZone"`
	ScanIntervalMinutes        int      `json:"scanIntervalMinutes"`
	AllowedCategories          []string `json:"allowedCategories"`
	IncludeOptional            bool     `json:"includeOptional"`
	InstallDelayDays           int      `json:"installDelayDays"`
	SecurityInstallDelayDays   int      `json:"securityInstallDelayDays"`
}

// EffectivePolicy reads the policy that applies to an endpoint.
func (c *Client) EffectivePolicy(ctx context.Context, endpointID uuid.UUID) (Policy, error) {
	var p Policy
	err := c.do(ctx, http.MethodGet, "/api/v1/endpoints/"+endpointID.String()+"/effective-policy", nil, nil, "", &p)
	return p, err
}

type installRequest struct {
	Mode        string      `json:"mode"`
	UpdateGUIDs []uuid.UUID `json:"updateGuids,omitempty"`
	Force       bool        `json:"force"`
	ScheduledAt *time.Time  `json:"scheduledAt,omitempty"`
}

// Install has an endpoint install updates: every eligible one when guids is
// empty, those otherwise. scheduledAt must only be set when the server
// lists CapabilityScheduledInstalls: a server without it installs at once.
func (c *Client) Install(ctx context.Context, endpointID uuid.UUID, guids []uuid.UUID, scheduledAt *time.Time, onBehalfOf string) (Job, error) {
	req := installRequest{Mode: "AllEligible", ScheduledAt: scheduledAt}
	if len(guids) > 0 {
		req.Mode, req.UpdateGUIDs = "Selected", guids
	}
	var j Job
	err := c.do(ctx, http.MethodPost, "/api/v1/endpoints/"+endpointID.String()+"/install-updates", nil, req, onBehalfOf, &j)
	return j, err
}

// BulkItem is one endpoint's outcome in a bulk request.
type BulkItem struct {
	EndpointID uuid.UUID  `json:"endpointId"`
	Hostname   string     `json:"hostname"`
	Success    bool       `json:"success"`
	JobID      *uuid.UUID `json:"jobId"`
	ErrorCode  string     `json:"errorCode"`
	Message    string     `json:"message"`
}

// BulkResult is the outcome of a bulk request.
type BulkResult struct {
	Succeeded int        `json:"succeeded"`
	Failed    int        `json:"failed"`
	Results   []BulkItem `json:"results"`
}

type bulkRequest struct {
	EndpointIDs []uuid.UUID `json:"endpointIds"`
	Force       bool        `json:"force"`
	ScheduledAt *time.Time  `json:"scheduledAt,omitempty"`
}

// MaxBulk is the most endpoints one bulk request takes.
const MaxBulk = 1000

// BulkScan has endpoints scan for updates.
func (c *Client) BulkScan(ctx context.Context, ids []uuid.UUID, onBehalfOf string) (BulkResult, error) {
	var r BulkResult
	err := c.do(ctx, http.MethodPost, "/api/v1/endpoints/bulk/scan", nil, bulkRequest{EndpointIDs: ids}, onBehalfOf, &r)
	return r, err
}

// BulkInstall has endpoints install every eligible update; see Install about
// scheduledAt.
func (c *Client) BulkInstall(ctx context.Context, ids []uuid.UUID, scheduledAt *time.Time, onBehalfOf string) (BulkResult, error) {
	var r BulkResult
	err := c.do(ctx, http.MethodPost, "/api/v1/endpoints/bulk/install-updates", nil,
		bulkRequest{EndpointIDs: ids, ScheduledAt: scheduledAt}, onBehalfOf, &r)
	return r, err
}

// AgentPackage is an EasyPatch agent package the server hosts.
type AgentPackage struct {
	FileName string `json:"fileName"`
	Version  string `json:"version"`
	// Architecture is x64 or arm64.
	Architecture string `json:"architecture"`
	SizeBytes    int64  `json:"sizeBytes"`
	// SHA256 is in hex; EasyPatch writes it in capitals.
	SHA256 string `json:"sha256"`
	// DownloadURL is relative to EasyPatch's address.
	DownloadURL string `json:"downloadUrl"`
	// IsLatest marks the newest package of its format and architecture.
	IsLatest bool `json:"isLatest"`
	// Format is msi, deb, rpm or pkg.
	Format string `json:"format"`
}

// AgentPackages lists the agent packages EasyPatch hosts.
func (c *Client) AgentPackages(ctx context.Context) ([]AgentPackage, error) {
	var list []AgentPackage
	err := c.do(ctx, http.MethodGet, "/api/v1/agent-packages", nil, nil, "", &list)
	return list, err
}

// Site is an EasyPatch site.
type Site struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// Sites lists an EasyPatch organization's sites.
func (c *Client) Sites(ctx context.Context, organizationID uuid.UUID) ([]Site, error) {
	var list []Site
	err := c.do(ctx, http.MethodGet, "/api/v1/organizations/"+organizationID.String()+"/sites", nil, nil, "", &list)
	return list, err
}

// EnrollmentToken is a newly created EasyPatch enrollment token.
type EnrollmentToken struct {
	ID uuid.UUID
	// Secret is shown by EasyPatch once.
	Secret string
}

// CreateEnrollmentToken creates a single-use enrollment token for an
// organization (and site), valid for an hour.
func (c *Client) CreateEnrollmentToken(ctx context.Context, organizationID uuid.UUID, siteID *uuid.UUID, description, onBehalfOf string) (EnrollmentToken, error) {
	body := struct {
		OrganizationID uuid.UUID  `json:"organizationId"`
		SiteID         *uuid.UUID `json:"siteId,omitempty"`
		Description    string     `json:"description"`
		ExpiresInHours int        `json:"expiresInHours"`
		MaxUses        int        `json:"maxUses"`
		Count          int        `json:"count"`
	}{organizationID, siteID, description, 1, 1, 1}
	var out []struct {
		Token struct {
			ID uuid.UUID `json:"id"`
		} `json:"token"`
		PlaintextToken string `json:"plaintextToken"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/enrollment-tokens", nil, body, onBehalfOf, &out); err != nil {
		return EnrollmentToken{}, err
	}
	if len(out) != 1 || out[0].Token.ID == uuid.Nil || out[0].PlaintextToken == "" {
		return EnrollmentToken{}, &Error{Status: http.StatusBadGateway, Code: "bad_response", Detail: "EasyPatch did not return one enrollment token."}
	}
	return EnrollmentToken{ID: out[0].Token.ID, Secret: out[0].PlaintextToken}, nil
}

// RevokeEnrollmentToken revokes an enrollment token; revoking twice is
// harmless.
func (c *Client) RevokeEnrollmentToken(ctx context.Context, id uuid.UUID, onBehalfOf string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/enrollment-tokens/"+id.String()+"/revoke", nil, nil, onBehalfOf, nil)
}
