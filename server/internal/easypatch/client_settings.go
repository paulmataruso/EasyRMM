package easypatch

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// EasyPatch's server-wide settings: its server settings, the vulnerability
// feeds it downloads, the operating systems' end-of-servicing dates and its
// audit log.

const settingsPath = "/api/v1/settings"

// ServerSettings are EasyPatch's server settings, all of which EasyRMM
// shows (the contract test checks that EasyPatch has no others).
type ServerSettings struct {
	GlobalMaxConcurrentInstalls int `json:"globalMaxConcurrentInstalls"`
	JobDefaultExpiryHours       int `json:"jobDefaultExpiryHours"`
	RunningJobTimeoutHours      int `json:"runningJobTimeoutHours"`
	WaitingForRebootExpiryDays  int `json:"waitingForRebootExpiryDays"`
	DeliveryLeaseMinutes        int `json:"deliveryLeaseMinutes"`
	MaxDeliveryAttempts         int `json:"maxDeliveryAttempts"`
	OfflineThresholdMinutes     int `json:"offlineThresholdMinutes"`
	CredentialLifetimeDays      int `json:"credentialLifetimeDays"`
	CredentialRotateBeforeDays  int `json:"credentialRotateBeforeDays"`
	RetentionEventsDays         int `json:"retentionEventsDays"`
	RetentionAuditDays          int `json:"retentionAuditDays"`
	RetentionJobsDays           int `json:"retentionJobsDays"`
	RetentionScansDays          int `json:"retentionScansDays"`
	RetentionHistoryDays        int `json:"retentionHistoryDays"`
	RetentionReportsMonths      int `json:"retentionReportsMonths"`
	// VulnerabilityFeedsEnabled has EasyPatch's worker download CISA's,
	// Microsoft's and Debian's vulnerability data.
	VulnerabilityFeedsEnabled bool `json:"vulnerabilityFeedsEnabled"`
	// ReportBrandName is the "Prepared by" line of monthly reports.
	ReportBrandName *string `json:"reportBrandName"`
	// The rollout guard holds a Windows update everywhere once it failed on
	// at least RolloutGuardMinFailedEndpoints endpoints and
	// RolloutGuardFailurePercent percent of those that tried it, over
	// RolloutGuardWindowDays days.
	RolloutGuardEnabled            bool `json:"rolloutGuardEnabled"`
	RolloutGuardMinFailedEndpoints int  `json:"rolloutGuardMinFailedEndpoints"`
	RolloutGuardFailurePercent     int  `json:"rolloutGuardFailurePercent"`
	RolloutGuardWindowDays         int  `json:"rolloutGuardWindowDays"`
}

// ServerSettings reads EasyPatch's server settings.
func (c *Client) ServerSettings(ctx context.Context) (ServerSettings, error) {
	var s ServerSettings
	err := c.do(ctx, http.MethodGet, settingsPath, nil, nil, "", &s)
	return s, err
}

// SetServerSettings replaces EasyPatch's server settings.
func (c *Client) SetServerSettings(ctx context.Context, in ServerSettings) (ServerSettings, error) {
	var out ServerSettings
	err := c.do(ctx, http.MethodPut, settingsPath, nil, in, "", &out)
	return out, err
}

// VulnerabilityFeed is the state of one feed EasyPatch's worker downloads:
// kev (CISA's Known Exploited Vulnerabilities), msrc (Microsoft) or debian.
type VulnerabilityFeed struct {
	Name          string     `json:"name"`
	LastAttemptAt *time.Time `json:"lastAttemptAt"`
	LastSuccessAt *time.Time `json:"lastSuccessAt"`
	LastError     string     `json:"lastError"`
	Version       string     `json:"version"`
	ItemCount     int        `json:"itemCount"`
}

// VulnerabilityFeeds reads the feeds' state.
func (c *Client) VulnerabilityFeeds(ctx context.Context) ([]VulnerabilityFeed, error) {
	var out []VulnerabilityFeed
	err := c.do(ctx, http.MethodGet, "/api/v1/vulnerability-feeds", nil, nil, "", &out)
	return out, err
}

// LifecycleEntry is an operating system build's end of servicing, which
// EasyPatch matches by product, edition group and build number to say
// whether an endpoint's operating system is still supported.
type LifecycleEntry struct {
	ID uuid.UUID `json:"id"`
	LifecycleInput
}

// LifecycleInput is a lifecycle entry to add or change. Dates are
// 2006-01-02.
type LifecycleInput struct {
	Product        string  `json:"product"`
	EditionGroup   string  `json:"editionGroup"`
	BuildNumber    int     `json:"buildNumber"`
	VersionLabel   string  `json:"versionLabel"`
	EndOfServicing string  `json:"endOfServicing"`
	EsuEndDate     *string `json:"esuEndDate"`
	Notes          *string `json:"notes"`
}

const lifecyclePath = "/api/v1/lifecycle"

// Lifecycle lists the lifecycle entries.
func (c *Client) Lifecycle(ctx context.Context) ([]LifecycleEntry, error) {
	var out []LifecycleEntry
	err := c.do(ctx, http.MethodGet, lifecyclePath, nil, nil, "", &out)
	return out, err
}

// CreateLifecycle adds a lifecycle entry.
func (c *Client) CreateLifecycle(ctx context.Context, in LifecycleInput) (LifecycleEntry, error) {
	var out LifecycleEntry
	err := c.do(ctx, http.MethodPost, lifecyclePath, nil, in, "", &out)
	return out, err
}

// UpdateLifecycle changes a lifecycle entry.
func (c *Client) UpdateLifecycle(ctx context.Context, id uuid.UUID, in LifecycleInput) (LifecycleEntry, error) {
	var out LifecycleEntry
	err := c.do(ctx, http.MethodPut, lifecyclePath+"/"+id.String(), nil, in, "", &out)
	return out, err
}

// DeleteLifecycle deletes a lifecycle entry.
func (c *Client) DeleteLifecycle(ctx context.Context, id uuid.UUID) error {
	return c.do(ctx, http.MethodDelete, lifecyclePath+"/"+id.String(), nil, nil, "", nil)
}

// AuditLog is an entry of EasyPatch's audit log.
type AuditLog struct {
	ID             int64      `json:"id"`
	UserID         *uuid.UUID `json:"userId"`
	Username       string     `json:"username"`
	OrganizationID *uuid.UUID `json:"organizationId"`
	EndpointID     *uuid.UUID `json:"endpointId"`
	Action         string     `json:"action"`
	TargetType     string     `json:"targetType"`
	TargetID       string     `json:"targetId"`
	// Details is JSON, as EasyPatch recorded it.
	Details       string    `json:"details"`
	IPAddress     string    `json:"ipAddress"`
	CorrelationID string    `json:"correlationId"`
	CreatedAt     time.Time `json:"createdAt"`
}

// AuditFilter narrows EasyPatch's audit log: Action is a prefix of the
// action's name; From is included and To is not.
type AuditFilter struct {
	OrganizationID *uuid.UUID
	Action         string
	From, To       *time.Time
}

// AuditLogs reads a page of EasyPatch's audit log, newest first.
func (c *Client) AuditLogs(ctx context.Context, f AuditFilter, page, pageSize int) (Page[AuditLog], error) {
	q := url.Values{"page": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(pageSize)}}
	if f.OrganizationID != nil {
		q.Set("organizationId", f.OrganizationID.String())
	}
	if f.Action != "" {
		q.Set("action", f.Action)
	}
	if f.From != nil {
		q.Set("from", f.From.UTC().Format(time.RFC3339))
	}
	if f.To != nil {
		q.Set("to", f.To.UTC().Format(time.RFC3339))
	}
	var p Page[AuditLog]
	err := c.do(ctx, http.MethodGet, "/api/v1/audit-logs", q, nil, "", &p)
	return p, err
}
