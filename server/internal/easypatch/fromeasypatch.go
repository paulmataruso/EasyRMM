package easypatch

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Links from the patching engine into EasyRMM. The engine's alert messages,
// and those an imported EasyPatch sent, name the engine's own ids:
// /go/from-easypatch/endpoints/:id, organizations/:id, jobs/:id, and
// alerts/:id for an organization's alerts. The console asks where each opens;
// EasyRMM resolves the id against its link tables and the caller's
// permissions.

// FromKinds are the engine's objects a link may name.
var FromKinds = []string{"endpoints", "organizations", "jobs", "alerts"}

// Landing is where a link from EasyPatch opens EasyRMM's console. Notice,
// when set, says why it is not the page the link named.
type Landing struct {
	Path   string `json:"path"`
	Notice string `json:"notice,omitempty"`
}

// The notices.
const (
	noticeNotSetUp     = "The patching engine is not set up, so EasyRMM cannot tell which of its pages that was."
	noticeEndpoint     = "That patching engine endpoint is not linked to an EasyRMM device you can see."
	noticeOrganization = "That patching engine organization is not linked to an EasyRMM organization you can see."
)

// landingFor builds the console path for what an EasyPatch id resolved to.
func landingFor(kind string, device, org, job uuid.UUID) Landing {
	switch {
	case kind == "endpoints" && device != uuid.Nil:
		return Landing{Path: "/devices/" + device.String() + "?tab=patches"}
	case kind == "endpoints":
		return Landing{Path: "/patching", Notice: noticeEndpoint}
	case kind == "organizations" && org != uuid.Nil:
		return Landing{Path: "/organizations/" + org.String()}
	case kind == "organizations":
		return Landing{Path: "/patching", Notice: noticeOrganization}
	case kind == "alerts" && org != uuid.Nil:
		return Landing{Path: "/patching?tab=alerts&organizationId=" + org.String()}
	case kind == "alerts":
		return Landing{Path: "/patching?tab=alerts", Notice: noticeOrganization}
	case kind == "jobs" && job != uuid.Nil:
		// The Patching page opens the job; reading it checks access.
		return Landing{Path: "/patching?tab=jobs&job=" + job.String()}
	}
	return Landing{Path: "/patching"}
}

// FromEasyPatch resolves a link from EasyPatch: an endpoint opens its
// device's Patches tab, an organization the organization, an organization's
// alerts Patching's Alerts filtered to it, a job the Patching job dialog.
// What the caller may not see, or EasyRMM does not link, opens Patching with
// a notice.
func (s *Service) FromEasyPatch(ctx context.Context, c access.Caller, kind string, id uuid.UUID) (Landing, error) {
	if !c.CanAnywhere(rbac.PermPatchView) {
		return Landing{}, apperr.Forbidden()
	}
	conn, err := s.Connection(ctx)
	if err != nil {
		return Landing{}, err
	}
	if !conn.Configured {
		return Landing{Path: "/patching", Notice: noticeNotSetUp}, nil
	}
	var device, org, job uuid.UUID
	switch kind {
	case "endpoints":
		err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT device_id FROM easypatch_devices WHERE endpoint_id = $1 AND state = 'linked'`, id).Scan(&device)
		})
		if err == nil {
			// The same check as the device's own patch views.
			_, err = s.device(ctx, c, device, rbac.PermPatchView)
		}
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, apperr.ErrNotFound) {
			device, err = uuid.Nil, nil
		}
	case "organizations", "alerts":
		err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT organization_id FROM easypatch_organizations WHERE easypatch_id = $1`, id).Scan(&org)
		})
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && !c.CanInOrg(rbac.PermPatchView, org)) {
			org, err = uuid.Nil, nil
		}
	case "jobs":
		job = id
	default:
		return Landing{}, apperr.NotFound()
	}
	if err != nil {
		return Landing{}, err
	}
	return landingFor(kind, device, org, job), nil
}
