package easypatch

import (
	"context"
	"errors"
	"net/url"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Links from EasyRMM's console to the page of EasyPatch's console that edits
// what EasyRMM only shows (integration plan, section 6.2). They point at
// EasyRMM's /go/to-easypatch, which looks the object up in EasyRMM's own link
// tables and redirects, so the console never needs EasyPatch's ids. An object
// that is not linked, or that the person may not see, goes to EasyPatch's
// matching list instead: the redirect never says more than the person may
// know. EasyPatch checks its own access on every page.

// GoTarget is what a /go/to-easypatch link names: at most one object.
type GoTarget struct {
	DeviceID       uuid.UUID
	OrganizationID uuid.UUID
	// SiteID opens the site's organization: EasyPatch's sites have no page.
	SiteID uuid.UUID
	// JobID and UpdateID are EasyPatch's own ids, passed through.
	JobID    uuid.UUID
	UpdateID uuid.UUID
	// Tab is a device's tab: updates, installed, history, jobs or policy.
	Tab string
	// List is one of EasyPatch's lists: "endpoints" or "jobs".
	List string
}

// GoLists are the lists a link may open.
var GoLists = []string{"endpoints", "jobs"}

// goPage is a resolved target: where in EasyPatch's console to go.
type goPage struct {
	endpointID   uuid.UUID // a linked device's endpoint
	search       string    // a device that is not linked: its name
	devices      bool      // a device the person may not see
	organization uuid.UUID // a linked organization
	orgs         bool      // an organization that is not linked or not visible
	jobs         bool      // the job list
	job, update  uuid.UUID
	tab          string
}

// endpointTabs are the endpoint page's tabs a link may open.
var endpointTabs = []string{"updates", "installed", "history", "jobs", "policy"}

// easyPatchPage is the address of the EasyPatch page for p, under base,
// EasyPatch's console. It marks the link as coming from EasyRMM.
func easyPatchPage(base string, p goPage) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := url.Values{}
	switch {
	case p.endpointID != uuid.Nil:
		u.Path += "/endpoints/" + p.endpointID.String()
		if slices.Contains(endpointTabs, p.tab) {
			q.Set("tab", p.tab)
		}
	case p.search != "":
		u.Path += "/endpoints"
		q.Set("search", p.search)
	case p.devices:
		u.Path += "/endpoints"
	case p.organization != uuid.Nil:
		u.Path += "/organizations/" + p.organization.String()
	case p.orgs:
		u.Path += "/organizations"
	case p.job != uuid.Nil:
		u.Path += "/jobs/" + p.job.String()
	case p.update != uuid.Nil:
		u.Path += "/updates/" + p.update.String()
	case p.jobs:
		u.Path += "/jobs"
	default:
		u.Path += "/"
	}
	q.Set("from", "easyrmm")
	u.RawQuery = q.Encode()
	return u.String()
}

// EasyPatchURL is the EasyPatch page for a link, or "" when EasyPatch is not
// set up.
func (s *Service) EasyPatchURL(ctx context.Context, c access.Caller, t GoTarget) (string, error) {
	if !c.CanAnywhere(rbac.PermPatchView) {
		return "", apperr.Forbidden()
	}
	conn, err := s.Connection(ctx)
	if err != nil {
		return "", err
	}
	base := consoleURL(conn)
	if !conn.Configured || base == "" {
		return "", nil
	}
	var p goPage
	switch {
	case t.DeviceID != uuid.Nil:
		p.tab = t.Tab
		d, err := s.device(ctx, c, t.DeviceID, rbac.PermPatchView)
		switch {
		case errors.Is(err, apperr.ErrNotFound):
			p.devices = true
		case err != nil:
			return "", err
		case d.state == LinkLinked && d.endpointID != nil:
			p.endpointID = *d.endpointID
		default:
			p.search = d.name
		}
	case t.OrganizationID != uuid.Nil, t.SiteID != uuid.Nil:
		p.orgs = true
		ep, err := s.linkedOrganization(ctx, c, t.OrganizationID, t.SiteID)
		if err != nil {
			return "", err
		}
		if ep != uuid.Nil {
			p.organization, p.orgs = ep, false
		}
	case t.JobID != uuid.Nil:
		p.job = t.JobID
	case t.UpdateID != uuid.Nil:
		p.update = t.UpdateID
	case t.List == "endpoints":
		p.devices = true
	case t.List == "jobs":
		p.jobs = true
	}
	return easyPatchPage(base, p), nil
}

// linkedOrganization is the EasyPatch organization linked to an
// organization, or to a site's organization, when the caller may see
// patching in it; uuid.Nil otherwise.
func (s *Service) linkedOrganization(ctx context.Context, c access.Caller, orgID, siteID uuid.UUID) (uuid.UUID, error) {
	var ep uuid.UUID
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		if siteID != uuid.Nil {
			if err := tx.QueryRow(ctx, `SELECT organization_id FROM sites WHERE id = $1`, siteID).Scan(&orgID); err != nil {
				return err
			}
		}
		if !c.CanInOrg(rbac.PermPatchView, orgID) {
			return pgx.ErrNoRows
		}
		return tx.QueryRow(ctx, `SELECT easypatch_id FROM easypatch_organizations WHERE organization_id = $1`, orgID).Scan(&ep)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, nil
	}
	return ep, err
}
