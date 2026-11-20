package easypatch

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
)

// What the reconciler (ADR-0040) changes in the patching engine: its
// organizations and sites, and its endpoints' sites.
//
// EasyPatch's updates replace every field they carry, so each update here
// sends back what EasyRMM does not own (descriptions, contacts, notes,
// addresses) as it read it.

// OrganizationDetail is one EasyPatch organization in full.
type OrganizationDetail struct {
	ID           uuid.UUID  `json:"id"`
	Name         string     `json:"name"`
	Description  *string    `json:"description"`
	ContactName  *string    `json:"contactName"`
	ContactEmail *string    `json:"contactEmail"`
	Notes        *string    `json:"notes"`
	TimeZone     string     `json:"timeZone"`
	IsActive     bool       `json:"isActive"`
	ArchivedAt   *time.Time `json:"archivedAt"`
	// Tags are the organization's own tags.
	Tags []TagRef `json:"tags"`
}

type organizationRequest struct {
	Name         string  `json:"name"`
	Description  *string `json:"description"`
	ContactName  *string `json:"contactName"`
	ContactEmail *string `json:"contactEmail"`
	Notes        *string `json:"notes"`
	// TimeZone null keeps the current one, or takes the default; EasyPatch
	// refuses "".
	TimeZone *string `json:"timeZone"`
}

// AllOrganizations lists every organization, archived ones too.
func (c *Client) AllOrganizations(ctx context.Context) ([]Organization, error) {
	var list []Organization
	err := c.do(ctx, http.MethodGet, "/api/v1/organizations", url.Values{"includeArchived": {"true"}}, nil, "", &list)
	return list, err
}

// CreateOrganization creates an organization. A name in use, archived
// organizations' included, is a 409.
func (c *Client) CreateOrganization(ctx context.Context, name, timeZone string) (OrganizationDetail, error) {
	var o OrganizationDetail
	err := c.do(ctx, http.MethodPost, "/api/v1/organizations", nil, organizationRequest{Name: name, TimeZone: zone(timeZone)}, "", &o)
	return o, err
}

// GetOrganization reads one organization.
func (c *Client) GetOrganization(ctx context.Context, id uuid.UUID) (OrganizationDetail, error) {
	var o OrganizationDetail
	err := c.do(ctx, http.MethodGet, "/api/v1/organizations/"+id.String(), nil, nil, "", &o)
	return o, err
}

// UpdateOrganization writes o's name and time zone, and the rest of o as
// read.
func (c *Client) UpdateOrganization(ctx context.Context, o OrganizationDetail) (OrganizationDetail, error) {
	var out OrganizationDetail
	err := c.do(ctx, http.MethodPut, "/api/v1/organizations/"+o.ID.String(), nil, organizationRequest{Name: o.Name,
		Description: o.Description, ContactName: o.ContactName, ContactEmail: o.ContactEmail, Notes: o.Notes, TimeZone: zone(o.TimeZone)}, "", &out)
	return out, err
}

// ArchiveOrganization archives an organization; archiving twice is
// harmless. Its agents keep checking in, but it takes no new ones.
func (c *Client) ArchiveOrganization(ctx context.Context, id uuid.UUID) error {
	return c.do(ctx, http.MethodPost, "/api/v1/organizations/"+id.String()+"/archive", nil, nil, "", nil)
}

// RestoreOrganization undoes archiving; restoring an active one is harmless.
func (c *Client) RestoreOrganization(ctx context.Context, id uuid.UUID) error {
	return c.do(ctx, http.MethodPost, "/api/v1/organizations/"+id.String()+"/restore", nil, nil, "", nil)
}

// SiteDetail is one EasyPatch site in full.
type SiteDetail struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organizationId"`
	Name           string     `json:"name"`
	Description    *string    `json:"description"`
	Address        *string    `json:"address"`
	TimeZone       string     `json:"timeZone"`
	IsActive       bool       `json:"isActive"`
	ArchivedAt     *time.Time `json:"archivedAt"`
	// Tags are the site's own tags.
	Tags []TagRef `json:"tags"`
}

type siteRequest struct {
	Name        string  `json:"name"`
	Description *string `json:"description"`
	Address     *string `json:"address"`
	TimeZone    *string `json:"timeZone"`
}

// AllSites lists an organization's sites, archived ones too.
func (c *Client) AllSites(ctx context.Context, organizationID uuid.UUID) ([]SiteDetail, error) {
	var list []SiteDetail
	err := c.do(ctx, http.MethodGet, "/api/v1/organizations/"+organizationID.String()+"/sites", url.Values{"includeArchived": {"true"}}, nil, "", &list)
	return list, err
}

// CreateSite creates a site. A name in use in the organization, archived
// sites' included, is a 409.
func (c *Client) CreateSite(ctx context.Context, organizationID uuid.UUID, name, timeZone string) (SiteDetail, error) {
	var s SiteDetail
	err := c.do(ctx, http.MethodPost, "/api/v1/organizations/"+organizationID.String()+"/sites", nil, siteRequest{Name: name, TimeZone: zone(timeZone)}, "", &s)
	return s, err
}

// GetSite reads one site.
func (c *Client) GetSite(ctx context.Context, id uuid.UUID) (SiteDetail, error) {
	var s SiteDetail
	err := c.do(ctx, http.MethodGet, "/api/v1/sites/"+id.String(), nil, nil, "", &s)
	return s, err
}

// UpdateSite writes s's name and time zone, and the rest of s as read.
func (c *Client) UpdateSite(ctx context.Context, s SiteDetail) (SiteDetail, error) {
	var out SiteDetail
	err := c.do(ctx, http.MethodPut, "/api/v1/sites/"+s.ID.String(), nil, siteRequest{Name: s.Name, Description: s.Description,
		Address: s.Address, TimeZone: zone(s.TimeZone)}, "", &out)
	return out, err
}

// ArchiveSite archives a site; archiving twice is harmless.
func (c *Client) ArchiveSite(ctx context.Context, id uuid.UUID) error {
	return c.do(ctx, http.MethodPost, "/api/v1/sites/"+id.String()+"/archive", nil, nil, "", nil)
}

// RestoreSite undoes archiving; restoring an active one is harmless.
func (c *Client) RestoreSite(ctx context.Context, id uuid.UUID) error {
	return c.do(ctx, http.MethodPost, "/api/v1/sites/"+id.String()+"/restore", nil, nil, "", nil)
}

// MoveEndpoint puts an endpoint in another site of its organization (nil:
// no site), keeping its notes and ESU setting. EasyPatch cannot move an
// endpoint to another organization.
func (c *Client) MoveEndpoint(ctx context.Context, id uuid.UUID, siteID *uuid.UUID) error {
	e, err := c.Endpoint(ctx, id)
	if err != nil {
		return err
	}
	if sameID(e.Summary.SiteID, siteID) {
		return nil
	}
	body := struct {
		SiteID      *uuid.UUID `json:"siteId"`
		Notes       *string    `json:"notes"`
		EsuOverride string     `json:"esuOverride,omitempty"`
	}{siteID, e.Notes, e.EsuOverride}
	return c.do(ctx, http.MethodPut, "/api/v1/endpoints/"+id.String(), nil, body, "", nil)
}

// UninstallAgent queues a job that has the endpoint's agent remove itself
// and unenroll. The endpoint must be active; 409 duplicate_job when one is
// queued already.
func (c *Client) UninstallAgent(ctx context.Context, id uuid.UUID) (Job, error) {
	var j Job
	err := c.do(ctx, http.MethodPost, "/api/v1/endpoints/"+id.String()+"/uninstall-agent", nil, nil, "", &j)
	return j, err
}

// RevokeEndpoint revokes an endpoint's credentials and cancels its open
// jobs, so its agent suspends itself. Revoking twice is harmless.
func (c *Client) RevokeEndpoint(ctx context.Context, id uuid.UUID, reason string) error {
	body := struct {
		Reason string `json:"reason"`
	}{reason}
	return c.do(ctx, http.MethodPost, "/api/v1/endpoints/"+id.String()+"/revoke", nil, body, "", nil)
}

// errorCode is EasyPatch's machine-readable code of a failed call, if any.
func errorCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// zone is a time zone for EasyPatch: nil for none.
func zone(tz string) *string {
	if tz == "" {
		return nil
	}
	return &tz
}
