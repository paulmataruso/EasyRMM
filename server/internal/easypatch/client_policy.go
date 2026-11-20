package easypatch

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// PolicyLayer is one level's own EasyPatch policy: the default policy, an
// organization's, a site's, a tag's or an endpoint's. A nil value inherits
// from the level above. EasyPatch replaces a level's policy whole when it is
// saved, so a value left out is inherited.
//
// Some values override as a unit: the maintenance window (set when
// MaintenanceDays is not nil; an empty list is no window, and its start and
// length come from the same level), the restart schedule, application
// updates and each group of Windows Update settings. Excluded KBs add up
// across levels: a level cannot lift an exclusion it inherits.
type PolicyLayer struct {
	CheckInIntervalSeconds   *int `json:"checkInIntervalSeconds"`
	ScanIntervalMinutes      *int `json:"scanIntervalMinutes"`
	InventoryIntervalMinutes *int `json:"inventoryIntervalMinutes"`
	JitterPercent            *int `json:"jitterPercent"`

	AllowedCategories []string `json:"allowedCategories"`
	IncludeOptional   *bool    `json:"includeOptional"`
	ExcludedKbs       []string `json:"excludedKbs"`
	AcceptEulas       *bool    `json:"acceptEulas"`

	AutoInstallEnabled         *bool   `json:"autoInstallEnabled"`
	MaintenanceDays            []int   `json:"maintenanceDays"`
	MaintenanceStart           *string `json:"maintenanceStart"`
	MaintenanceDurationMinutes *int    `json:"maintenanceDurationMinutes"`
	PreDownloadHours           *int    `json:"preDownloadHours"`

	InstallDelayDays         *int  `json:"installDelayDays"`
	SecurityInstallDelayDays *int  `json:"securityInstallDelayDays"`
	KnownExploitedSkipsDelay *bool `json:"knownExploitedSkipsDelay"`

	ScanStaleAfterHours          *int `json:"scanStaleAfterHours"`
	MaxConcurrentInstallsPerSite *int `json:"maxConcurrentInstallsPerSite"`

	TrayIconEnabled             *bool `json:"trayIconEnabled"`
	InstallNotificationsEnabled *bool `json:"installNotificationsEnabled"`
	AgentAutoUpdateEnabled      *bool `json:"agentAutoUpdateEnabled"`

	RestartSchedule    *RestartSchedule    `json:"restartSchedule"`
	WindowsUpdate      *LayerWindowsUpdate `json:"windowsUpdate"`
	ApplicationUpdates *ApplicationUpdates `json:"applicationUpdates"`
}

// GroupSetting is one group of Windows Update settings at one level: not
// managed leaves Windows alone even when a level above manages the group.
type GroupSetting[T any] struct {
	Managed bool `json:"managed"`
	Value   *T   `json:"value"`
}

// LayerWindowsUpdate is a level's Windows Update settings; a nil group
// inherits.
type LayerWindowsUpdate struct {
	AutomaticUpdates *GroupSetting[AutomaticUpdates] `json:"automaticUpdates"`
	FeatureUpdates   *GroupSetting[FeatureUpdates]   `json:"featureUpdates"`
	QualityUpdates   *GroupSetting[QualityUpdates]   `json:"qualityUpdates"`
	RestartBehavior  *GroupSetting[RestartBehavior]  `json:"restartBehavior"`
}

// LevelPolicy is a level's policy as EasyPatch returns it; ID is nil when
// the level has no policy of its own.
type LevelPolicy struct {
	ID        *uuid.UUID `json:"id"`
	UpdatedAt *time.Time `json:"updatedAt"`
	PolicyLayer
}

// TagPolicyLayer is a tag's policy as it applies to an endpoint.
type TagPolicyLayer struct {
	Tag      TagRef      `json:"tag"`
	Priority int         `json:"priority"`
	Policy   LevelPolicy `json:"policy"`
}

// TagRef names a tag; InheritedFrom says where an object got it (its
// organization or site), empty when it was given the tag itself.
type TagRef struct {
	ID            uuid.UUID `json:"id"`
	Name          string    `json:"name"`
	Color         string    `json:"color"`
	InheritedFrom string    `json:"inheritedFrom,omitempty"`
}

// The paths of each level's policy.
const globalPolicyPath = "/api/v1/policies/global"

func organizationPolicyPath(id uuid.UUID) string {
	return "/api/v1/organizations/" + id.String() + "/policy"
}
func sitePolicyPath(id uuid.UUID) string     { return "/api/v1/sites/" + id.String() + "/policy" }
func endpointPolicyPath(id uuid.UUID) string { return "/api/v1/endpoints/" + id.String() + "/policy" }

// LevelPolicy reads a level's own policy from its path (one of the
// *PolicyPath functions, or the global policy's).
func (c *Client) LevelPolicy(ctx context.Context, path string) (LevelPolicy, error) {
	var p LevelPolicy
	err := c.do(ctx, http.MethodGet, path, nil, nil, "", &p)
	return p, err
}

// SetLevelPolicy replaces a level's own policy.
func (c *Client) SetLevelPolicy(ctx context.Context, path string, p PolicyLayer, onBehalfOf string) (LevelPolicy, error) {
	if p.ExcludedKbs == nil {
		p.ExcludedKbs = []string{}
	}
	var out LevelPolicy
	err := c.do(ctx, http.MethodPut, path, nil, p, onBehalfOf, &out)
	return out, err
}

// DeleteLevelPolicy removes a level's own policy, so it inherits everything.
// EasyPatch has no such call for the global policy.
func (c *Client) DeleteLevelPolicy(ctx context.Context, path, onBehalfOf string) error {
	return c.do(ctx, http.MethodDelete, path, nil, nil, onBehalfOf, nil)
}

// TagPolicies lists the tag policies that apply to an endpoint, in the order
// EasyPatch applies them: the last one wins.
func (c *Client) TagPolicies(ctx context.Context, endpointID uuid.UUID) ([]TagPolicyLayer, error) {
	var out []TagPolicyLayer
	err := c.do(ctx, http.MethodGet, "/api/v1/endpoints/"+endpointID.String()+"/tag-policies", nil, nil, "", &out)
	return out, err
}

// Tag is one of EasyPatch's tags. Tags are shared by every organization: a
// tag's policy applies to the devices that have it, directly or through
// their site or organization, over their site's policy.
type Tag struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Color       string    `json:"color"`
	Description *string   `json:"description"`
	// Priority orders tag policies: the highest applies last and wins.
	Priority int `json:"priority"`
	// The counts are 0 for someone restricted to some organizations.
	EndpointCount     int       `json:"endpointCount"`
	SiteCount         int       `json:"siteCount"`
	OrganizationCount int       `json:"organizationCount"`
	HasPolicy         bool      `json:"hasPolicy"`
	CreatedAt         time.Time `json:"createdAt"`
}

// TagInput is a tag's name, color, description and priority.
type TagInput struct {
	Name        string  `json:"name"`
	Color       string  `json:"color"`
	Description *string `json:"description"`
	Priority    int     `json:"priority"`
}

type tagIDs struct {
	TagIDs []uuid.UUID `json:"tagIds"`
}

// Tags lists the tags, by name.
func (c *Client) Tags(ctx context.Context) ([]Tag, error) {
	var out []Tag
	err := c.do(ctx, http.MethodGet, "/api/v1/tags", nil, nil, "", &out)
	return out, err
}

// CreateTag adds a tag.
func (c *Client) CreateTag(ctx context.Context, in TagInput, onBehalfOf string) (Tag, error) {
	var t Tag
	err := c.do(ctx, http.MethodPost, "/api/v1/tags", nil, in, onBehalfOf, &t)
	return t, err
}

// UpdateTag changes a tag.
func (c *Client) UpdateTag(ctx context.Context, id uuid.UUID, in TagInput, onBehalfOf string) (Tag, error) {
	var t Tag
	err := c.do(ctx, http.MethodPut, "/api/v1/tags/"+id.String(), nil, in, onBehalfOf, &t)
	return t, err
}

// DeleteTag removes a tag, its policy and every assignment of it.
func (c *Client) DeleteTag(ctx context.Context, id uuid.UUID, onBehalfOf string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/tags/"+id.String(), nil, nil, onBehalfOf, nil)
}

func tagPolicyPath(id uuid.UUID) string { return "/api/v1/tags/" + id.String() + "/policy" }

// SetTags replaces the tags of an organization ("organizations"), a site
// ("sites") or an endpoint ("endpoints").
func (c *Client) SetTags(ctx context.Context, kind string, id uuid.UUID, tags []uuid.UUID, onBehalfOf string) error {
	if tags == nil {
		tags = []uuid.UUID{}
	}
	return c.do(ctx, http.MethodPut, "/api/v1/"+kind+"/"+id.String()+"/tags", nil, tagIDs{tags}, onBehalfOf, nil)
}
