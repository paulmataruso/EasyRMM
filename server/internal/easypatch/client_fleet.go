package easypatch

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// The calls behind Patching → Updates (one-product plan, C2): EasyPatch's
// update catalog across endpoints, one update's page with the endpoints
// that report it, installing or removing it on many endpoints, and holds.

// UpdateCategories are EasyPatch's update categories.
var UpdateCategories = []string{"Security", "Critical", "Cumulative", "Definition", "ServicingStack", "DotNet", "Feature", "Driver", "Other", "Application"}

// UpdateStates are the states an update can have on an endpoint.
var UpdateStates = []string{"Missing", "Failed", "PendingVerification", "PendingReboot", "Installed", "Superseded", "NotApplicable", "Excluded", "Reoffered"}

// FleetUpdate is one update across the endpoints in a scope.
type FleetUpdate struct {
	UpdateGUID   uuid.UUID  `json:"updateGuid"`
	Title        string     `json:"title"`
	KbNumber     string     `json:"kbNumber"`
	Category     string     `json:"category"`
	MsrcSeverity string     `json:"msrcSeverity"`
	ReleaseDate  *time.Time `json:"releaseDate"`
	SizeBytes    *int64     `json:"sizeBytes"`
	MissingCount int        `json:"missingCount"`
	FailedCount  int        `json:"failedCount"`
	// InstalledCount counts endpoints that have it; PendingRebootCount, those
	// where it waits for a restart.
	InstalledCount     int      `json:"installedCount"`
	PendingRebootCount int      `json:"pendingRebootCount"`
	ExcludedCount      int      `json:"excludedCount"`
	Package            *Package `json:"package"`
	CveCount           int      `json:"cveCount"`
	KnownExploited     bool     `json:"knownExploited"`
	ReofferedCount     int      `json:"reofferedCount"`
	OnHold             bool     `json:"onHold"`
}

// Vulnerability is a CVE an update fixes.
type Vulnerability struct {
	CveID         string   `json:"cveId"`
	Title         string   `json:"title"`
	Severity      string   `json:"severity"`
	CvssBase      *float64 `json:"cvssBase"`
	MsrcExploited bool     `json:"msrcExploited"`
	// Kev says CISA lists it as known exploited.
	Kev           bool    `json:"kev"`
	KevDateAdded  *string `json:"kevDateAdded"`
	KevDueDate    *string `json:"kevDueDate"`
	KevRansomware bool    `json:"kevRansomware"`
	KevName       string  `json:"kevName"`
}

// Hold keeps an update from installing automatically: in one organization,
// or everywhere when OrganizationID is nil. Source is Automatic (EasyPatch's
// rollout guard, after failures) or Manual.
type Hold struct {
	ID                 uuid.UUID  `json:"id"`
	UpdateGUID         uuid.UUID  `json:"updateGuid"`
	Title              string     `json:"title"`
	KbNumber           string     `json:"kbNumber"`
	OrganizationID     *uuid.UUID `json:"organizationId"`
	OrganizationName   string     `json:"organizationName"`
	Source             string     `json:"source"`
	Reason             string     `json:"reason"`
	FailedEndpoints    *int       `json:"failedEndpoints"`
	AttemptedEndpoints *int       `json:"attemptedEndpoints"`
	CreatedAt          time.Time  `json:"createdAt"`
	CreatedBy          string     `json:"createdBy"`
	ReleasedAt         *time.Time `json:"releasedAt"`
	ReleasedBy         string     `json:"releasedBy"`
	CanRelease         bool       `json:"canRelease"`
}

// FleetUpdateDetail is one update's page: its counts in a scope, what
// Microsoft or the repository says about it, the CVEs it fixes there, and its
// active holds.
type FleetUpdateDetail struct {
	Summary               FleetUpdate     `json:"summary"`
	Description           string          `json:"description"`
	SupportURL            string          `json:"supportUrl"`
	KbNumbers             []string        `json:"kbNumbers"`
	Products              []string        `json:"products"`
	MsClassification      string          `json:"msClassification"`
	RebootLikely          bool            `json:"rebootLikely"`
	SupersededUpdateGUIDs []uuid.UUID     `json:"supersededUpdateGuids"`
	Vulnerabilities       []Vulnerability `json:"vulnerabilities"`
	Holds                 []Hold          `json:"holds"`
}

// FleetUpdateEndpoint is an endpoint that reports an update, with its state
// there.
type FleetUpdateEndpoint struct {
	EndpointID       uuid.UUID `json:"endpointId"`
	Hostname         string    `json:"hostname"`
	OrganizationName string    `json:"organizationName"`
	SiteName         string    `json:"siteName"`
	IsOnline         bool      `json:"isOnline"`
	State            string    `json:"state"`
	IsRequired       bool      `json:"isRequired"`
	IsExcluded       bool      `json:"isExcluded"`
	FailedAttempts   int       `json:"failedAttempts"`
	ErrorCode        string    `json:"errorCode"`
	ErrorMessage     string    `json:"errorMessage"`
	StateChangedAt   time.Time `json:"stateChangedAt"`
}

// FleetScope narrows the catalog to one EasyPatch organization, or one of
// its sites; the statement's organizations bound it in any case.
type FleetScope struct {
	OrganizationID, SiteID *uuid.UUID
}

func (s FleetScope) query(q url.Values) url.Values {
	if q == nil {
		q = url.Values{}
	}
	if s.OrganizationID != nil {
		q.Set("organizationId", s.OrganizationID.String())
	}
	if s.SiteID != nil {
		q.Set("siteId", s.SiteID.String())
	}
	return q
}

// CatalogQuery filters and orders the catalog. Without a State, it lists
// updates some endpoint still needs (missing, failed, waiting for a restart
// or offered again), those fixing known-exploited vulnerabilities first.
type CatalogQuery struct {
	FleetScope
	Category, State, Search string
	KnownExploited          *bool
	// Sort is missing (missing or failed), failed or installed, by the
	// number of endpoints; Desc orders from the most.
	Sort string
	Desc bool
	Page int
}

// Catalog lists updates across the endpoints in scope, 50 at a time.
func (c *Client) Catalog(ctx context.Context, q CatalogQuery) (Page[FleetUpdate], error) {
	v := q.query(url.Values{"pageSize": {strconv.Itoa(CatalogPageSize)}})
	if q.Page > 1 {
		v.Set("page", strconv.Itoa(q.Page))
	}
	for k, s := range map[string]string{"category": q.Category, "state": q.State, "search": q.Search, "sort": q.Sort} {
		if s != "" {
			v.Set(k, s)
		}
	}
	if q.Sort != "" {
		v.Set("dir", map[bool]string{true: "desc", false: "asc"}[q.Desc])
	}
	if q.KnownExploited != nil {
		v.Set("knownExploited", strconv.FormatBool(*q.KnownExploited))
	}
	var p Page[FleetUpdate]
	err := c.do(ctx, http.MethodGet, "/api/v1/updates", v, nil, "", &p)
	return p, err
}

// CatalogPageSize is how many updates a catalog page holds.
const CatalogPageSize = 50

// FleetUpdate reads one update, counted over the endpoints in scope.
func (c *Client) FleetUpdate(ctx context.Context, guid uuid.UUID, scope FleetScope) (FleetUpdateDetail, error) {
	var d FleetUpdateDetail
	err := c.do(ctx, http.MethodGet, "/api/v1/updates/"+guid.String(), scope.query(nil), nil, "", &d)
	return d, err
}

// FleetUpdateEndpoints lists the endpoints in scope that report an update,
// by host name, PageSize at a time; state narrows them.
func (c *Client) FleetUpdateEndpoints(ctx context.Context, guid uuid.UUID, scope FleetScope, state string, page int) (Page[FleetUpdateEndpoint], error) {
	v := scope.query(url.Values{"pageSize": {strconv.Itoa(PageSize)}, "page": {strconv.Itoa(max(page, 1))}})
	if state != "" {
		v.Set("state", state)
	}
	var p Page[FleetUpdateEndpoint]
	err := c.do(ctx, http.MethodGet, "/api/v1/updates/"+guid.String()+"/endpoints", v, nil, "", &p)
	return p, err
}

// FleetInstall installs one update on endpoints where it is missing or
// failed and not excluded; the others are left out. Unlike a policy
// install, it installs whatever the update's category.
func (c *Client) FleetInstall(ctx context.Context, guid uuid.UUID, ids []uuid.UUID, onBehalfOf string) (BulkResult, error) {
	body := struct {
		EndpointIDs []uuid.UUID `json:"endpointIds"`
	}{ids}
	var r BulkResult
	err := c.do(ctx, http.MethodPost, "/api/v1/updates/"+guid.String()+"/install", nil, body, onBehalfOf, &r)
	return r, err
}

// FleetRemove has endpoints that report an update installed, or waiting for
// its restart, uninstall it; block also excludes it on each.
func (c *Client) FleetRemove(ctx context.Context, guid uuid.UUID, ids []uuid.UUID, block bool, reason, onBehalfOf string) (BulkResult, error) {
	body := struct {
		EndpointIDs []uuid.UUID `json:"endpointIds"`
		Block       bool        `json:"block"`
		Reason      *string     `json:"reason"`
	}{EndpointIDs: ids, Block: block}
	if reason != "" {
		body.Reason = &reason
	}
	var r BulkResult
	err := c.do(ctx, http.MethodPost, "/api/v1/updates/"+guid.String()+"/uninstall", nil, body, onBehalfOf, &r)
	return r, err
}

// HoldUpdate holds an update in one organization, or everywhere when
// organizationID is nil (super administrators only). EasyPatch refuses to
// hold it again where it is held (409, already_held).
func (c *Client) HoldUpdate(ctx context.Context, guid uuid.UUID, organizationID *uuid.UUID, reason, onBehalfOf string) (Hold, error) {
	body := struct {
		OrganizationID *uuid.UUID `json:"organizationId"`
		Reason         string     `json:"reason"`
	}{organizationID, reason}
	var h Hold
	err := c.do(ctx, http.MethodPost, "/api/v1/updates/"+guid.String()+"/holds", nil, body, onBehalfOf, &h)
	return h, err
}

// Holds lists an update's active holds.
func (c *Client) Holds(ctx context.Context, guid uuid.UUID) ([]Hold, error) {
	var list []Hold
	err := c.do(ctx, http.MethodGet, "/api/v1/update-holds", url.Values{"updateGuid": {guid.String()}}, nil, "", &list)
	return list, err
}

// ReleaseHold lets a held update install automatically again.
func (c *Client) ReleaseHold(ctx context.Context, id uuid.UUID, onBehalfOf string) (Hold, error) {
	var h Hold
	err := c.do(ctx, http.MethodPost, "/api/v1/update-holds/"+id.String()+"/release", nil, struct{}{}, onBehalfOf, &h)
	return h, err
}
