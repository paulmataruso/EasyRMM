// Package easypatch is EasyRMM's side of the patching engine in this
// deployment, EasyPatch's server (ADR-0038, ADR-0046): which engine
// organization and endpoint each EasyRMM organization and device is, and
// the patch views and actions of the console. The engine stays the source
// of truth for patch data; this package reads it through the engine's API
// when it is asked for, with a statement for each call, after EasyRMM's own
// permission checks.
package easypatch

import (
	"bytes"
	"context"
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
)

const (
	// requestTimeout bounds one call to EasyPatch.
	requestTimeout = 30 * time.Second
	// maxResponse bounds what EasyPatch may send back.
	maxResponse = 32 << 20
	// PageSize is the largest page EasyPatch's lists return.
	PageSize = 200
)

// Capabilities a server may list in /api/v1/server-info.
const (
	// CapabilityScheduledInstalls: install requests accept scheduledAt.
	CapabilityScheduledInstalls = "scheduled-installs"
)

// Error is a failed call: the engine's answer, or Status 0 when it could
// not be reached.
type Error struct {
	Status int
	// Code is EasyPatch's machine-readable code (duplicate_job,
	// validation_failed…), when it sent one.
	Code   string
	Detail string
	// Fields are EasyPatch's field errors (validation_failed), the first
	// message of each.
	Fields map[string]string
}

func (e *Error) Error() string {
	if e.Status == 0 {
		return e.Detail
	}
	return fmt.Sprintf("The patching engine answered %d: %s", e.Status, e.Detail)
}

// IsStatus reports whether err is EasyPatch answering with status.
func IsStatus(err error, status int) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == status
}

// Client calls the patching engine in this deployment with statements
// (NewEngineClient).
type Client struct {
	base      *url.URL
	signer    *Signer
	userAgent string
	http      *http.Client
}

// NewEngineClient builds a client for the patching engine in this
// deployment: plain HTTP on loopback, each request with a statement from
// signer (ADR-0038) rather than a token. The configuration checked rawURL is
// http:// on a loopback address.
func NewEngineClient(rawURL string, signer *Signer, version string) (*Client, error) {
	base, err := url.Parse(rawURL)
	if err != nil || base.Scheme != "http" || base.Host == "" {
		return nil, errors.New("easypatch: the engine's address must be http://<loopback address>:<port>")
	}
	if ip := net.ParseIP(base.Hostname()); ip == nil || !ip.IsLoopback() {
		return nil, errors.New("easypatch: the engine is reached on loopback only")
	}
	if signer == nil {
		return nil, errors.New("easypatch: the engine needs a statement signer")
	}
	base.Path = strings.TrimSuffix(base.Path, "/")
	transport := &http.Transport{
		// Never a proxy: statements stay on this host.
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ResponseHeaderTimeout: requestTimeout,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
	}
	return &Client{
		base: base, signer: signer, userAgent: "EasyRMM/" + version,
		http: &http.Client{
			Transport: transport,
			Timeout:   requestTimeout,
			// A statement is made for one request: never follow it elsewhere.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
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
	// The statement names this request exactly as it is sent.
	signed, err := c.signer.Sign(statementFor(ctx, onBehalfOf), method, req.URL.RequestURI())
	if err != nil {
		return err
	}
	req.Header.Set(StatementHeader, signed)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return &Error{Detail: "Cannot reach the patching engine: " + reachError(err)}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return &Error{Detail: "The patching engine's answer was cut short: " + err.Error()}
	}
	if len(data) > maxResponse {
		return &Error{Status: resp.StatusCode, Detail: "The patching engine's answer is larger than 32 MiB"}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return problem(resp.StatusCode, data)
	}
	if raw, ok := out.(*[]byte); ok {
		// A file, such as a monthly report's PDF, as EasyPatch sent it.
		*raw = data
		return nil
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return &Error{Status: resp.StatusCode, Detail: "The patching engine's answer is not what EasyRMM expects: " + err.Error()}
	}
	return nil
}

// reachError explains a transport failure without Go's request dump.
func reachError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "it did not answer within 30 seconds"
	}
	return err.Error()
}

// problem reads EasyPatch's problem details.
func problem(status int, data []byte) *Error {
	var p struct {
		Title  string              `json:"title"`
		Detail string              `json:"detail"`
		Code   string              `json:"code"`
		Errors map[string][]string `json:"errors"`
	}
	_ = json.Unmarshal(data, &p)
	var fields map[string]string
	for name, msgs := range p.Errors {
		if len(msgs) > 0 && len(fields) < 50 {
			if fields == nil {
				fields = map[string]string{}
			}
			fields[cut(name, 100)] = cut(msgs[0], 500)
		}
	}
	detail := strings.TrimSpace(p.Detail)
	if detail == "" {
		detail = strings.TrimSpace(p.Title)
	}
	if detail == "" {
		switch status {
		case http.StatusUnauthorized:
			detail = "EasyRMM's statement is not valid: EASYRMM_PATCHING_KEY may differ from the engine's gateway key"
		case http.StatusForbidden:
			detail = "the statement's role may not do this"
		case http.StatusNotFound:
			detail = "not found"
		default:
			detail = http.StatusText(status)
		}
	}
	return &Error{Status: status, Code: cut(p.Code, 64), Detail: cut(detail, 500), Fields: fields}
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

// CanOperate reports whether the engine lets EasyRMM act as an
// administrator: listing enrollment tokens needs that role.
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
	TimeZone      string    `json:"timeZone"`
	IsActive      bool      `json:"isActive"`
	SiteCount     int       `json:"siteCount"`
	EndpointCount int       `json:"endpointCount"`
}

// Organizations lists the engine's organizations.
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
	ID               uuid.UUID  `json:"id"`
	Hostname         string     `json:"hostname"`
	OrganizationID   uuid.UUID  `json:"organizationId"`
	OrganizationName string     `json:"organizationName"`
	SiteID           *uuid.UUID `json:"siteId"`
	SiteName         string     `json:"siteName"`
	// Tags are the endpoint's tags, with those it has through its site or
	// organization (InheritedFrom says which).
	Tags            []TagRef `json:"tags"`
	Status          string   `json:"status"`
	OperatingSystem string   `json:"operatingSystem"`
	OSBuild         string   `json:"osBuild"`
	// OSSupportStatus is Supported, ExtendedSecurityUpdates, Unsupported
	// (the operating system gets no more security updates) or Unknown.
	OSSupportStatus      string     `json:"osSupportStatus"`
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
	Summary Endpoint `json:"summary"`
	// OsProductType is Workstation, Server or DomainController (Windows).
	OsProductType            string       `json:"osProductType"`
	SerialNumber             string       `json:"serialNumber"`
	LastScanAttemptAt        *time.Time   `json:"lastScanAttemptAt"`
	LastScanError            string       `json:"lastScanError"`
	RebootReasons            []string     `json:"rebootReasons"`
	RebootPendingSince       *time.Time   `json:"rebootPendingSince"`
	InstalledCount           int          `json:"installedCount"`
	PendingRebootUpdateCount int          `json:"pendingRebootUpdateCount"`
	ComplianceEvaluatedAt    *time.Time   `json:"complianceEvaluatedAt"`
	Credentials              []Credential `json:"credentials"`
	Notes                    *string      `json:"notes"`
	EsuOverride              string       `json:"esuOverride"`
	// ActiveJob is the job the endpoint is working on, if any.
	ActiveJob *Job `json:"activeJob"`
	// AgentCapabilities are what the agent can do (AgentCan*).
	AgentCapabilities []string `json:"agentCapabilities"`
	// SignedInUsers and TrayConnectedSessions count sessions at the
	// latest check-in; nil until the agent reports them.
	SignedInUsers         *int `json:"signedInUsers"`
	TrayConnectedSessions *int `json:"trayConnectedSessions"`
	// HasOwnPolicy says the endpoint has its own policy layer.
	HasOwnPolicy bool              `json:"hasOwnPolicy"`
	AgentUpdate  *AgentUpdateState `json:"agentUpdate"`
	// Restart says what a pending restart is for; nil when none is.
	Restart *RestartDetails `json:"restart"`
	// WindowsUpdatePolicy is how the agent applied the Windows Update
	// settings of its policy (Windows only).
	WindowsUpdatePolicy           *WindowsUpdateReport `json:"windowsUpdatePolicy"`
	WindowsUpdatePolicyReportedAt *time.Time           `json:"windowsUpdatePolicyReportedAt"`
}

// What EasyPatch agents can do, as they report it (agentCapabilities).
const (
	AgentCanRestart          = "restart"
	AgentCanNotifyUser       = "notify-user"
	AgentCanUninstallUpdates = "uninstall-updates"
	AgentCanTray             = "tray"
)

// AgentUpdateState says whether an endpoint's agent can update itself, and
// to what.
type AgentUpdateState struct {
	// Supported: the agent is 1.2.0 or newer, built with a release key.
	Supported bool `json:"supported"`
	// AutomaticUpdates: the effective policy updates agents by itself.
	AutomaticUpdates bool `json:"automaticUpdates"`
	// AvailableVersion is what an update would install now; empty when
	// nothing would, and then Code and Message say why.
	AvailableVersion string `json:"availableVersion"`
	Code             string `json:"code"`
	Message          string `json:"message"`
	// PackageFormat is msi, deb, rpm or pkg.
	PackageFormat string `json:"packageFormat"`
}

// RestartDetails is what a pending restart is for.
type RestartDetails struct {
	Updates           []RestartUpdate `json:"updates"`
	ServicingPackages []string        `json:"servicingPackages"`
	// FileOperations are the first 25 of FileOperationCount.
	FileOperations     []FileOperation `json:"fileOperations"`
	FileOperationCount int             `json:"fileOperationCount"`
	// DetailsSupported: the agent reports what Windows has queued
	// (Windows agent 1.5.3 and later).
	DetailsSupported bool `json:"detailsSupported"`
}

// RestartUpdate is an update waiting for the restart.
type RestartUpdate struct {
	UpdateGUID *uuid.UUID `json:"updateGuid"`
	Title      string     `json:"title"`
	KbNumbers  []string   `json:"kbNumbers"`
	// Source is Installed, WindowsUpdate or Servicing.
	Source      string     `json:"source"`
	InstalledAt *time.Time `json:"installedAt"`
}

// FileOperation is a file Windows deletes or replaces at the restart.
type FileOperation struct {
	Action string `json:"action"`
	Path   string `json:"path"`
}

// WindowsUpdateReport is how the agent applied its Windows Update settings.
type WindowsUpdateReport struct {
	Groups                   []WindowsUpdateGroupStatus `json:"groups"`
	MdmUpdatePoliciesPresent bool                       `json:"mdmUpdatePoliciesPresent"`
}

// WindowsUpdateGroupStatus is one group of settings on the endpoint.
type WindowsUpdateGroupStatus struct {
	Group string `json:"group"`
	// State is NotManaged, Applied, Conflict or Error.
	State             string     `json:"state"`
	Message           string     `json:"message"`
	AppliedAt         *time.Time `json:"appliedAt"`
	ConflictingValues []string   `json:"conflictingValues"`
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
	KbNumbers       []string   `json:"kbNumbers"`
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
	// KevDueDate is CISA's date for fixing an exploited vulnerability
	// (YYYY-MM-DD).
	KevDueDate string `json:"kevDueDate"`
	HoldReason string `json:"holdReason"`
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
	Summary        Job        `json:"summary"`
	InstallMode    string     `json:"installMode"`
	NotBefore      *time.Time `json:"notBefore"`
	DeliveredAt    *time.Time `json:"deliveredAt"`
	AcknowledgedAt *time.Time `json:"acknowledgedAt"`
	LastProgress   *time.Time `json:"lastProgressAt"`
	// DeliveryCount is how many times the job was handed to the agent.
	DeliveryCount int `json:"deliveryCount"`
	// RetryOfJobID is the job this one runs again.
	RetryOfJobID      *uuid.UUID `json:"retryOfJobId"`
	CancelRequestedAt *time.Time `json:"cancelRequestedAt"`
	Items             []JobItem  `json:"items"`
	Events            []JobEvent `json:"events"`
}

// EndpointJobs lists one page of an endpoint's jobs, newest first.
func (c *Client) EndpointJobs(ctx context.Context, endpointID uuid.UUID, page int) (Page[Job], error) {
	var p Page[Job]
	q := url.Values{"page": {strconv.Itoa(page)}, "pageSize": {"50"}}
	err := c.do(ctx, http.MethodGet, "/api/v1/endpoints/"+endpointID.String()+"/jobs", q, nil, "", &p)
	return p, err
}

// statusCanceled is EasyPatch's status of a canceled job, spelled as its
// API spells it.
const statusCanceled = "Cancelled" //nolint:misspell // EasyPatch's enum value

// JobStatuses, JobTypes and JobTriggers are EasyPatch's.
var (
	JobStatuses = []string{"Queued", "Delivered", "Acknowledged", "Running", "Completed", "Failed", statusCanceled, "Expired", "WaitingForReboot"}
	JobTypes    = []string{"UpdateScan", "InstallUpdates", "InventoryRefresh", "Restart", "NotifyUser", "AgentUpdate", "UninstallAgent",
		"UninstallUpdate", "DownloadUpdates"}
	JobTriggers = []string{"Manual", "Scheduled", "System"}
)

// JobFilter narrows an organization's jobs. Active keeps those still to
// finish; the others are EasyPatch's (JobStatuses, JobTypes, JobTriggers);
// From and To bound when the job was created ([From, To)).
type JobFilter struct {
	OrganizationID uuid.UUID
	EndpointID     *uuid.UUID
	Active         bool
	Status         string
	Type           string
	Trigger        string
	From, To       *time.Time
}

// Jobs lists one page of an organization's jobs, newest first.
func (c *Client) Jobs(ctx context.Context, f JobFilter, page int) (Page[Job], error) {
	var p Page[Job]
	q := url.Values{"organizationId": {f.OrganizationID.String()}, "page": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(PageSize)}}
	if f.EndpointID != nil {
		q.Set("endpointId", f.EndpointID.String())
	}
	if f.Active {
		q.Set("active", "true")
	}
	for k, v := range map[string]string{"status": f.Status, "type": f.Type, "trigger": f.Trigger} {
		if v != "" {
			q.Set(k, v)
		}
	}
	if f.From != nil {
		q.Set("from", f.From.UTC().Format(time.RFC3339))
	}
	if f.To != nil {
		q.Set("to", f.To.UTC().Format(time.RFC3339))
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

// Policy is an endpoint's effective policy: every value, and which layer of
// EasyPatch's policies set it.
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

	CheckInIntervalSeconds       int      `json:"checkInIntervalSeconds"`
	InventoryIntervalMinutes     int      `json:"inventoryIntervalMinutes"`
	JitterPercent                int      `json:"jitterPercent"`
	ExcludedKbs                  []string `json:"excludedKbs"`
	AcceptEulas                  bool     `json:"acceptEulas"`
	ScanStaleAfterHours          int      `json:"scanStaleAfterHours"`
	MaxConcurrentInstallsPerSite int      `json:"maxConcurrentInstallsPerSite"`
	TrayIconEnabled              bool     `json:"trayIconEnabled"`
	InstallNotificationsEnabled  bool     `json:"installNotificationsEnabled"`
	AgentAutoUpdateEnabled       bool     `json:"agentAutoUpdateEnabled"`
	KnownExploitedSkipsDelay     bool     `json:"knownExploitedSkipsDelay"`
	PreDownloadHours             int      `json:"preDownloadHours"`

	RestartSchedule     *RestartSchedule    `json:"restartSchedule"`
	WindowsUpdate       *WindowsUpdate      `json:"windowsUpdate"`
	WindowsUpdateValues []RegistryValue     `json:"windowsUpdateValues"`
	ApplicationUpdates  *ApplicationUpdates `json:"applicationUpdates"`

	// Sources names, for each value, the layer that set it: Global,
	// Organization, Site, Tag or Endpoint. EasyPatch keys it by the value's
	// name in PascalCase (WindowsUpdate.<Group> for those settings).
	Sources map[string]string `json:"sources"`
	// SourceTags names the tag of the values a tag's policy set.
	SourceTags map[string]string `json:"sourceTags"`
}

// RestartSchedule is a recurring restart. Time is HH:mm in the policy's time
// zone; days are 0 (Sunday) to 6.
type RestartSchedule struct {
	Enabled bool   `json:"enabled"`
	Days    []int  `json:"days"`
	Time    string `json:"time"`
	// Condition is OnlyIfPending or Always.
	Condition string `json:"condition"`
	// Mode is Immediate, Countdown, PromptWithDeadline or
	// PromptNoDeadline.
	Mode             string `json:"mode"`
	CountdownMinutes int    `json:"countdownMinutes"`
	DeadlineMinutes  int    `json:"deadlineMinutes"`
	ExpiryMinutes    int    `json:"expiryMinutes"`
}

// WindowsUpdate is the Windows Update settings EasyPatch applies; a nil
// group is left as it is on the endpoint.
type WindowsUpdate struct {
	AutomaticUpdates *AutomaticUpdates `json:"automaticUpdates"`
	FeatureUpdates   *FeatureUpdates   `json:"featureUpdates"`
	QualityUpdates   *QualityUpdates   `json:"qualityUpdates"`
	RestartBehavior  *RestartBehavior  `json:"restartBehavior"`
}

// AutomaticUpdates is Windows' own automatic updating.
type AutomaticUpdates struct {
	// Mode is Disabled, NotifyDownload, AutoDownloadNotifyInstall or
	// AutoDownloadScheduleInstall.
	Mode string `json:"mode"`
	// ScheduledInstallDay is 0 for every day, 1 (Sunday) to 7.
	ScheduledInstallDay  int `json:"scheduledInstallDay"`
	ScheduledInstallHour int `json:"scheduledInstallHour"`
}

// FeatureUpdates defers new Windows releases, or keeps a version.
type FeatureUpdates struct {
	DeferDays            *int   `json:"deferDays"`
	TargetProductVersion string `json:"targetProductVersion"`
	TargetReleaseVersion string `json:"targetReleaseVersion"`
}

// QualityUpdates defers monthly updates.
type QualityUpdates struct {
	DeferDays    *int `json:"deferDays"`
	DisablePause bool `json:"disablePause"`
}

// RestartBehavior is when Windows may restart by itself.
type RestartBehavior struct {
	NoAutoRestartWithSignedInUsers bool `json:"noAutoRestartWithSignedInUsers"`
	ActiveHoursStart               *int `json:"activeHoursStart"`
	ActiveHoursEnd                 *int `json:"activeHoursEnd"`
}

// RegistryValue is a Windows Update policy value EasyPatch sets.
type RegistryValue struct {
	Group string `json:"group"`
	Path  string `json:"path"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ApplicationUpdates is the policy's winget application updates.
type ApplicationUpdates struct {
	Enabled      bool     `json:"enabled"`
	ApprovedApps []string `json:"approvedApps"`
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

// PendingRestart is an endpoint whose operating system reports a pending
// restart, as EasyPatch lists them for "Restart all that need it".
type PendingRestart struct {
	ID       uuid.UUID `json:"id"`
	Hostname string    `json:"hostname"`
	Platform string    `json:"platform"`
	// IsServer marks Windows Server and domain controllers.
	IsServer bool `json:"isServer"`
	IsOnline bool `json:"isOnline"`
	// CanRestart says the endpoint's agent runs restart jobs.
	CanRestart         bool       `json:"canRestart"`
	RebootPendingSince *time.Time `json:"rebootPendingSince"`
}

// PendingRestarts is an organization's endpoints that need a restart:
// Endpoints holds at most 1,000 of Total.
type PendingRestarts struct {
	Total     int              `json:"total"`
	Endpoints []PendingRestart `json:"endpoints"`
}

// RestartPending lists an organization's endpoints whose operating system
// reports a pending restart.
func (c *Client) RestartPending(ctx context.Context, organizationID uuid.UUID) (PendingRestarts, error) {
	var p PendingRestarts
	err := c.do(ctx, http.MethodGet, "/api/v1/organizations/"+organizationID.String()+"/restart-pending", nil, nil, "", &p)
	return p, err
}

// RestartOptions say how a restart treats the people signed in, when it
// starts and how long it waits for an offline computer (EasyPatch's
// RestartRequest). Nil minutes take EasyPatch's defaults.
type RestartOptions struct {
	// Mode is Countdown, PromptWithDeadline, PromptNoDeadline or Immediate.
	Mode string `json:"mode"`
	// Condition is OnlyIfPending or Always.
	Condition string `json:"condition"`
	// CountdownMinutes is the Countdown mode's (1–60).
	CountdownMinutes *int `json:"countdownMinutes,omitempty"`
	// DeadlineMinutes is the PromptWithDeadline mode's (15 minutes–7 days).
	DeadlineMinutes *int `json:"deadlineMinutes,omitempty"`
	// ScheduledAt starts it then rather than now.
	ScheduledAt *time.Time `json:"scheduledAt,omitempty"`
	// ExpiresAfterMinutes is how long it waits for an offline computer
	// (15 minutes–24 hours).
	ExpiresAfterMinutes *int `json:"expiresAfterMinutes,omitempty"`
	Force               bool `json:"force"`
}

// BulkRestart restarts endpoints.
func (c *Client) BulkRestart(ctx context.Context, ids []uuid.UUID, opts RestartOptions, onBehalfOf string) (BulkResult, error) {
	var r BulkResult
	body := struct {
		EndpointIDs []uuid.UUID    `json:"endpointIds"`
		Restart     RestartOptions `json:"restart"`
	}{ids, opts}
	err := c.do(ctx, http.MethodPost, "/api/v1/endpoints/bulk/restart", nil, body, onBehalfOf, &r)
	return r, err
}

// RetryJob runs a finished job again as a new job, which it returns.
func (c *Client) RetryJob(ctx context.Context, id uuid.UUID, onBehalfOf string) (Job, error) {
	var j Job
	err := c.do(ctx, http.MethodPost, "/api/v1/jobs/"+id.String()+"/retry", nil, nil, onBehalfOf, &j)
	return j, err
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
	// ReleaseKeyID names the release key of the package's valid .sig;
	// empty without one. SignatureProblem says why a .sig was ignored.
	ReleaseKeyID     string `json:"releaseKeyId"`
	SignatureProblem string `json:"signatureProblem"`
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
		return EnrollmentToken{}, &Error{Status: http.StatusBadGateway, Code: "bad_response", Detail: "The patching engine did not return one enrollment token."}
	}
	return EnrollmentToken{ID: out[0].Token.ID, Secret: out[0].PlaintextToken}, nil
}

// RevokeEnrollmentToken revokes an enrollment token; revoking twice is
// harmless.
func (c *Client) RevokeEnrollmentToken(ctx context.Context, id uuid.UUID, onBehalfOf string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/enrollment-tokens/"+id.String()+"/revoke", nil, nil, onBehalfOf, nil)
}
