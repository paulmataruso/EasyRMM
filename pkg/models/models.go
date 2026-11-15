package models

import (
	"time"

	"github.com/google/uuid"
)

type Organization struct {
	ID        uuid.UUID         `json:"id"`
	Name      string            `json:"name"`
	Slug      string            `json:"slug"`
	Settings  map[string]any    `json:"settings"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

type Site struct {
	ID             uuid.UUID      `json:"id"`
	OrganizationID uuid.UUID     `json:"organization_id"`
	Name           string         `json:"name"`
	Slug           string         `json:"slug"`
	Settings       map[string]any `json:"settings"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

type DeviceGroup struct {
	ID          uuid.UUID  `json:"id"`
	SiteID      uuid.UUID  `json:"site_id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	MeshGroupID string     `json:"mesh_group_id,omitempty"`
	Settings    map[string]any `json:"settings"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type Device struct {
	ID              uuid.UUID      `json:"id"`
	OrganizationID  uuid.UUID      `json:"organization_id"`
	SiteID          uuid.UUID      `json:"site_id"`
	DeviceGroupID   *uuid.UUID     `json:"device_group_id,omitempty"`
	Hostname        string         `json:"hostname"`
	DisplayName     string         `json:"display_name,omitempty"`
	OSType          string         `json:"os_type"`
	OSName          string         `json:"os_name,omitempty"`
	OSVersion       string         `json:"os_version,omitempty"`
	OSBuild         string         `json:"os_build,omitempty"`
	Arch            string         `json:"arch,omitempty"`
	MeshNodeID      string         `json:"mesh_node_id,omitempty"`
	MeshGroupID     string         `json:"mesh_group_id,omitempty"`
	CPUModel        string         `json:"cpu_model,omitempty"`
	CPUCores        int            `json:"cpu_cores,omitempty"`
	TotalMemoryMB   int64          `json:"total_memory_mb,omitempty"`
	SerialNumber    string         `json:"serial_number,omitempty"`
	Manufacturer    string         `json:"manufacturer,omitempty"`
	Model           string         `json:"model,omitempty"`
	AgentID         string         `json:"agent_id"`
	AgentVersion    string         `json:"agent_version,omitempty"`
	MeshAgentVersion string        `json:"mesh_agent_version,omitempty"`
	Status          string         `json:"status"`
	LastSeenAt      *time.Time     `json:"last_seen_at,omitempty"`
	EnrolledAt      *time.Time     `json:"enrolled_at,omitempty"`
	Tags            []string       `json:"tags"`
	CustomProperties map[string]any `json:"custom_properties"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

type User struct {
	ID           uuid.UUID  `json:"id"`
	Email        string     `json:"email"`
	Username     string     `json:"username"`
	PasswordHash string     `json:"-"`
	DisplayName  string     `json:"display_name"`
	Role         string     `json:"role"`
	IsActive     bool       `json:"is_active"`
	MFAEnabled   bool       `json:"mfa_enabled"`
	MFASecret    string     `json:"-"`
	FailedLogins int        `json:"-"`
	LockedUntil  *time.Time `json:"-"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type UserOrganizationAccess struct {
	ID             uuid.UUID `json:"id"`
	UserID         uuid.UUID `json:"user_id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	Role           string    `json:"role"`
	CreatedAt      time.Time `json:"created_at"`
}

type Session struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	TokenHash string    `json:"-"`
	IPAddress string    `json:"ip_address,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type EnrollmentToken struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	SiteID         *uuid.UUID `json:"site_id,omitempty"`
	DeviceGroupID  *uuid.UUID `json:"device_group_id,omitempty"`
	TokenHash      string     `json:"-"`
	Name           string     `json:"name,omitempty"`
	MaxUses        *int       `json:"max_uses,omitempty"`
	UseCount       int        `json:"use_count"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	Revoked        bool       `json:"revoked"`
	CreatedBy      uuid.UUID  `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
}

type Script struct {
	ID             uuid.UUID      `json:"id"`
	OrganizationID *uuid.UUID     `json:"organization_id,omitempty"`
	Name           string         `json:"name"`
	Description    string         `json:"description,omitempty"`
	Shell          string         `json:"shell"`
	OSType         string         `json:"os_type"`
	Content        string         `json:"content"`
	Parameters     []ScriptParam  `json:"parameters"`
	TimeoutSeconds int            `json:"timeout_seconds"`
	Category       string         `json:"category,omitempty"`
	IsBuiltin      bool           `json:"is_builtin"`
	CreatedBy      *uuid.UUID     `json:"created_by,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

type ScriptParam struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Default     string `json:"default,omitempty"`
}

type Job struct {
	ID             uuid.UUID      `json:"id"`
	OrganizationID uuid.UUID      `json:"organization_id"`
	Name           string         `json:"name"`
	JobType        string         `json:"job_type"`
	Status         string         `json:"status"`
	TargetType     string         `json:"target_type"`
	TargetID       uuid.UUID      `json:"target_id"`
	ScriptID       *uuid.UUID     `json:"script_id,omitempty"`
	Payload        map[string]any `json:"payload"`
	ScheduledAt    *time.Time     `json:"scheduled_at,omitempty"`
	StartedAt      *time.Time     `json:"started_at,omitempty"`
	CompletedAt    *time.Time     `json:"completed_at,omitempty"`
	CreatedBy      uuid.UUID      `json:"created_by"`
	CreatedAt      time.Time      `json:"created_at"`
}

type JobResult struct {
	ID           uuid.UUID  `json:"id"`
	JobID        uuid.UUID  `json:"job_id"`
	DeviceID     uuid.UUID  `json:"device_id"`
	Status       string     `json:"status"`
	ExitCode     *int       `json:"exit_code,omitempty"`
	Stdout       string     `json:"stdout,omitempty"`
	Stderr       string     `json:"stderr,omitempty"`
	DispatchedAt *time.Time `json:"dispatched_at,omitempty"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

type AlertRule struct {
	ID             uuid.UUID      `json:"id"`
	OrganizationID *uuid.UUID     `json:"organization_id,omitempty"`
	Name           string         `json:"name"`
	Description    string         `json:"description,omitempty"`
	Metric         string         `json:"metric"`
	Condition      map[string]any `json:"condition"`
	Severity       string         `json:"severity"`
	IsActive       bool           `json:"is_active"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

type Alert struct {
	ID             uuid.UUID  `json:"id"`
	AlertRuleID    *uuid.UUID `json:"alert_rule_id,omitempty"`
	DeviceID       uuid.UUID  `json:"device_id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	Severity       string     `json:"severity"`
	Message        string     `json:"message"`
	Metric         string     `json:"metric"`
	MetricValue    *float64   `json:"metric_value,omitempty"`
	Status         string     `json:"status"`
	AcknowledgedBy *uuid.UUID `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

type AuditLog struct {
	ID             uuid.UUID      `json:"id"`
	UserID         *uuid.UUID     `json:"user_id,omitempty"`
	OrganizationID *uuid.UUID     `json:"organization_id,omitempty"`
	DeviceID       *uuid.UUID     `json:"device_id,omitempty"`
	Action         string         `json:"action"`
	ResourceType   string         `json:"resource_type"`
	ResourceID     string         `json:"resource_id,omitempty"`
	Details        map[string]any `json:"details,omitempty"`
	IPAddress      string         `json:"ip_address,omitempty"`
	UserAgent      string         `json:"user_agent,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
}

// Telemetry collected from agents
type DeviceTelemetry struct {
	ID            uuid.UUID      `json:"id"`
	DeviceID      uuid.UUID      `json:"device_id"`
	CPUPercent    *float64       `json:"cpu_percent,omitempty"`
	MemoryPercent *float64       `json:"memory_percent,omitempty"`
	DiskUsage     []DiskInfo     `json:"disk_usage,omitempty"`
	Network       []NetworkInfo  `json:"network,omitempty"`
	CollectedAt   time.Time      `json:"collected_at"`
}

type DiskInfo struct {
	Mount   string  `json:"mount"`
	Total   int64   `json:"total"`
	Used    int64   `json:"used"`
	Percent float64 `json:"percent"`
}

type NetworkInfo struct {
	Interface string `json:"interface"`
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
}

// Statuses
const (
	DeviceStatusPending  = "pending"
	DeviceStatusOnline   = "online"
	DeviceStatusOffline  = "offline"
	DeviceStatusAlert    = "alert"

	JobStatusPending     = "pending"
	JobStatusQueued      = "queued"
	JobStatusDispatched  = "dispatched"
	JobStatusRunning     = "running"
	JobStatusCompleted   = "completed"
	JobStatusFailed      = "failed"
	JobStatusTimedOut    = "timed_out"
	JobStatusCancelled   = "cancelled"

	AlertStatusActive       = "active"
	AlertStatusAcknowledged = "acknowledged"
	AlertStatusResolved     = "resolved"

	RoleSuperAdmin = "super_admin"
	RoleOrgAdmin   = "org_admin"
	RoleSiteAdmin  = "site_admin"
	RoleTechnician = "technician"
	RoleReadOnly   = "read_only"
)
