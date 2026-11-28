package easypatch

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// AdHocGrant is what a Quick Assist session's EasyPatch agent enrolls with
// (ADR-0080 QA6).
type AdHocGrant struct {
	// Secret is the single-use token; it is shown once and never stored.
	Secret string
	// Server is the address agents enroll with.
	Server string
	// TokenID and SiteID are kept so the session's endpoint can be revoked.
	TokenID, SiteID uuid.UUID
}

// AdHocToken makes the enrollment token for a Quick Assist session's
// EasyPatch agent: single use, one hour, for the engine site named siteName
// (made when it is missing) in the engine organization the EasyRMM
// organization is linked to. It returns nil, nil when there is nothing to
// give: patching is not set up or the organization is not linked.
func (s *Service) AdHocToken(ctx context.Context, org uuid.UUID, siteName, description string) (*AdHocGrant, error) {
	r, cl, err := s.conn(ctx)
	if err != nil || r == nil || cl == nil {
		return nil, nil //nolint:nilerr // an engine that is not set up is "nothing to give"
	}
	server := strings.TrimRight(r.publicURL, "/")
	if server == "" {
		return nil, nil
	}
	var linked uuid.UUID
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT easypatch_id FROM easypatch_organizations WHERE organization_id = $1`, org).Scan(&linked)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	site, err := s.adHocSite(ctx, cl, linked, siteName)
	if err != nil {
		return nil, err
	}
	tok, err := cl.CreateEnrollmentToken(ctx, linked, &site, cut(description, 200), "")
	if err != nil {
		s.noteError(err)
		return nil, err
	}
	return &AdHocGrant{Secret: tok.Secret, Server: server, TokenID: tok.ID, SiteID: site}, nil
}

// adHocSite finds the engine site called name, or makes it.
func (s *Service) adHocSite(ctx context.Context, cl *Client, org uuid.UUID, name string) (uuid.UUID, error) {
	sites, err := cl.AllSites(ctx, org)
	if err != nil {
		s.noteError(err)
		return uuid.Nil, err
	}
	for _, x := range sites {
		if strings.EqualFold(strings.TrimSpace(x.Name), strings.TrimSpace(name)) {
			return x.ID, nil
		}
	}
	x, err := cl.CreateSite(ctx, org, name, "")
	if err != nil {
		s.noteError(err)
		return uuid.Nil, err
	}
	return x.ID, nil
}

// AdHocRemove ends a Quick Assist session's EasyPatch presence: it revokes
// the enrollment token and the endpoint the agent made with it, found as
// the active endpoint called hostname in the grant's site, a site only Quick
// Assist sessions enroll into. Revoking twice, or an endpoint that never
// enrolled, is harmless.
func (s *Service) AdHocRemove(ctx context.Context, org uuid.UUID, tokenID, siteID uuid.UUID, hostname string) error {
	_, cl, err := s.conn(ctx)
	if err != nil || cl == nil {
		return err
	}
	if err := cl.RevokeEnrollmentToken(ctx, tokenID, ""); err != nil && !IsStatus(err, http.StatusNotFound) {
		s.noteError(err)
		return err
	}
	var linked uuid.UUID
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT easypatch_id FROM easypatch_organizations WHERE organization_id = $1`, org).Scan(&linked)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	for page := 1; page <= 20; page++ {
		p, err := cl.Endpoints(ctx, linked, page)
		if err != nil {
			s.noteError(err)
			return err
		}
		for _, e := range p.Items {
			if e.SiteID == nil || *e.SiteID != siteID || e.Status != "Active" || !strings.EqualFold(e.Hostname, hostname) {
				continue
			}
			if err := cl.RevokeEndpoint(ctx, e.ID, "EasyRMM: the Quick Assist session ended"); err != nil && !IsStatus(err, http.StatusNotFound) {
				s.noteError(err)
				return err
			}
		}
		if len(p.Items) < PageSize {
			break
		}
	}
	return nil
}
