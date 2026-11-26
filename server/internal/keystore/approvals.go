package keystore

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// The two-person rule (ADR-0081 section 6). ADR-0055's general approvals did
// not exist when this slice was built, so this is the minimum the ADR needs, for
// key reads only (Amended, decided in review): a request by one person, an
// approval by another with their own step-up within ten minutes, single use,
// and the key shown to the requester alone.

// openRequest records the request of a requester who has none open for the
// record yet, and audits it.
func (s *Service) openRequest(ctx context.Context, c access.Caller, e *escrowRef, in ReadInput) (*KeyRequest, error) {
	var id uuid.UUID
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT id FROM recovery_key_requests
			WHERE escrow_id = $1 AND requested_by = $2 AND state IN ('pending', 'approved') AND expires_at > $3`,
			e.id, c.Principal.UserID, s.now()).Scan(&id)
		if err == nil {
			return nil // the same person asking again sees their open request
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO recovery_key_requests (organization_id, site_id, device_id, escrow_id, requested_by, requested_label, reason, ticket, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
			e.org, e.site, e.device, e.id, c.Principal.UserID, c.Actor.Label, in.Reason, in.Ticket, s.now().Add(RequestWait)).Scan(&id); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: ActionRequested, Outcome: audit.Success, OrganizationID: e.org, SiteID: e.site, DeviceID: e.device,
			TargetType: "device", TargetID: e.device.String(),
			Details: map[string]any{"request": id.String(), "volume": e.volume, "protector": e.protector, "reason": in.Reason, "ticket": in.Ticket},
		})
	})
	if err != nil {
		return nil, err
	}
	return s.loadRequest(ctx, c, id)
}

// checkApproved confirms that the request is the caller's, approved by another
// person within ten minutes, for this record, and returns what it recorded.
func (s *Service) checkApproved(ctx context.Context, id, user uuid.UUID, e *escrowRef) (reason, ticket, approver string, err error) {
	var state string
	var requester uuid.UUID
	var escrow uuid.UUID
	var decided *time.Time
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT reason, ticket, approver_label, state, requested_by, escrow_id, decided_at FROM recovery_key_requests WHERE id = $1`, id).
			Scan(&reason, &ticket, &approver, &state, &requester, &escrow, &decided)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", apperr.NotFound()
	}
	if err != nil {
		return "", "", "", err
	}
	switch {
	case requester != user || escrow != e.id:
		// Another person's approval is not usable by this one.
		return "", "", "", apperr.NotFound()
	case state == "pending":
		return "", "", "", apperr.Conflict("approval_pending", "A second person has not approved this yet.")
	case state != "approved" || decided == nil || decided.Add(ApprovalValid).Before(s.now()):
		return "", "", "", apperr.Conflict("approval_expired", "That approval was used, refused or has expired. Ask again.")
	}
	return reason, ticket, approver, nil
}

func (s *Service) loadRequest(ctx context.Context, c access.Caller, id uuid.UUID) (*KeyRequest, error) {
	rs, err := s.listRequests(ctx, c, `AND r.id = $1`, id)
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 {
		return nil, apperr.NotFound()
	}
	return &rs[0], nil
}

func (s *Service) listRequests(ctx context.Context, c access.Caller, where string, args ...any) ([]KeyRequest, error) {
	var out []KeyRequest
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT r.id, r.device_id, d.hostname, e.volume_id, e.protector_id, r.requested_label, r.reason, r.ticket, r.state,
				r.approver_label, r.created_at, r.expires_at, r.decided_at, r.requested_by, r.organization_id, r.site_id
			FROM recovery_key_requests r JOIN devices d ON d.id = r.device_id JOIN recovery_key_escrows e ON e.id = r.escrow_id
			WHERE r.created_at > now() - interval '1 day' `+where+` ORDER BY r.created_at DESC LIMIT 200`, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r KeyRequest
			var by, org, site uuid.UUID
			if err := rows.Scan(&r.ID, &r.DeviceID, &r.Device, &r.Volume, &r.Protector, &r.Requester, &r.Reason, &r.Ticket, &r.State,
				&r.Approver, &r.CreatedAt, &r.ExpiresAt, &r.DecidedAt, &by, &org, &site); err != nil {
				return err
			}
			r.Mine = c.Principal != nil && by == c.Principal.UserID
			open := r.State == "pending" && r.ExpiresAt.After(s.now())
			r.CanDecide = open && !r.Mine && c.Can(rbac.PermRecoveryKeyApprove, rbac.Site(org, site))
			if !r.Mine && !c.Can(rbac.PermRecoveryKeyApprove, rbac.Site(org, site)) {
				continue
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// Requests lists the caller's own requests and, for an approver, the ones
// they may decide, from the last day.
func (s *Service) Requests(ctx context.Context, c access.Caller) ([]KeyRequest, error) {
	if c.IsSystem() || c.Principal == nil {
		return nil, apperr.Forbidden()
	}
	rs, err := s.listRequests(ctx, c, ``)
	if rs == nil {
		rs = []KeyRequest{}
	}
	return rs, err
}

// Decide approves or refuses a pending request. An approval needs the
// permission, the approver's own step-up, and a person other than the
// requester.
func (s *Service) Decide(ctx context.Context, c access.Caller, id uuid.UUID, approve bool) (*KeyRequest, error) {
	if c.IsSystem() || c.Principal == nil {
		return nil, apperr.Forbidden()
	}
	r, err := s.loadRequest(ctx, c, id)
	if err != nil {
		return nil, err
	}
	var org, site uuid.UUID
	if err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT organization_id, site_id FROM recovery_key_requests WHERE id = $1`, id).Scan(&org, &site)
	}); err != nil {
		return nil, err
	}
	if !c.Can(rbac.PermRecoveryKeyApprove, rbac.Site(org, site)) {
		return nil, apperr.Forbidden()
	}
	if r.Mine {
		return nil, apperr.Conflict("own_request", "A second person has to decide your request, not you.")
	}
	if s.stepUp == nil {
		return nil, apperr.Forbidden()
	}
	if err := s.stepUp.VerifyStepUp(ctx); err != nil {
		return nil, err
	}
	state, action := "denied", ActionDenied
	if approve {
		state, action = "approved", ActionApproved
	}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE recovery_key_requests SET state = $2, approver_id = $3, approver_label = $4, decided_at = now()
			WHERE id = $1 AND state = 'pending' AND expires_at > $5 AND requested_by <> $3`, id, state, c.Principal.UserID, c.Actor.Label, s.now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return apperr.Conflict("request_closed", "That request was already decided or has expired.")
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: action, Outcome: audit.Success, OrganizationID: org, SiteID: site, DeviceID: r.DeviceID,
			TargetType: "device", TargetID: r.DeviceID.String(),
			Details: map[string]any{"request": id.String(), "requester": r.Requester, "volume": r.Volume, "protector": r.Protector},
		})
	})
	if err != nil {
		return nil, err
	}
	return s.loadRequest(ctx, c, id)
}

// Settings is an organization's keystore setting.
type Settings struct {
	TwoPerson bool `json:"twoPerson"`
	// LUKSEscrow: the agent adds a key slot to each encrypted Linux volume it can
	// unlock by itself (off by default).
	LUKSEscrow bool `json:"luksEscrow"`
	// Approvers is how many people hold the approve permission here; two are
	// needed to turn the rule on.
	Approvers int `json:"approvers"`
	// Key is the organization's escrow key as rotation sees it; nil before
	// the organization's first escrow makes one.
	Key *OrgKeyInfo `json:"key,omitempty"`
}

// OrgKeyInfo says where an organization's escrow key rotation stands: the
// active key's version and the KEK version wrapping it, how many retired keys
// are kept, and how many records still wait to be moved to the active key.
// No key material.
type OrgKeyInfo struct {
	Version    int       `json:"version"`
	KEKVersion int       `json:"kekVersion"`
	CreatedAt  time.Time `json:"createdAt"`
	Retired    int       `json:"retired"`
	ToMove     int       `json:"toMove"`
}

func (s *Service) approvers(ctx context.Context, org uuid.UUID) (int, error) {
	n := 0
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(DISTINCT a.user_id) FROM role_assignments a JOIN users u ON u.id = a.user_id
			WHERE a.role = 'key_approver' AND a.organization_id = $1 AND u.status = 'active'`, org).Scan(&n)
	})
	return n, err
}

// SettingsOf returns an organization's setting for someone who may manage it.
func (s *Service) SettingsOf(ctx context.Context, c access.Caller, org uuid.UUID) (Settings, error) {
	if err := c.Require(rbac.PermOrgManage, rbac.Org(org)); err != nil {
		return Settings{}, err
	}
	on, err := s.twoPerson(ctx, org)
	if err != nil {
		return Settings{}, err
	}
	n, err := s.approvers(ctx, org)
	if err != nil {
		return Settings{}, err
	}
	l, err := s.luksEscrowOn(ctx, org)
	if err != nil {
		return Settings{}, err
	}
	info, err := s.orgKeyInfo(ctx, org)
	return Settings{TwoPerson: on, LUKSEscrow: l, Approvers: n, Key: info}, err
}

func (s *Service) orgKeyInfo(ctx context.Context, org uuid.UUID) (*OrgKeyInfo, error) {
	var k OrgKeyInfo
	found := false
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT version, kek_version, created_at FROM keystore_org_keys
			WHERE organization_id = $1 AND purpose = 'escrow' AND state = 'active'`, org).Scan(&k.Version, &k.KEKVersion, &k.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		return tx.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM keystore_org_keys WHERE organization_id = $1 AND purpose = 'escrow' AND state = 'retired'),
				(SELECT count(*) FROM recovery_key_escrows e JOIN keystore_org_keys o ON o.id = e.org_key_id
					WHERE e.organization_id = $1 AND o.state = 'retired' AND e.state IN ('verified', 'conflict', 'pending'))`, org).Scan(&k.Retired, &k.ToMove)
	})
	if !found {
		return nil, err
	}
	return &k, err
}

// luksEscrowOn says whether the organization has turned LUKS escrow on.
func (s *Service) luksEscrowOn(ctx context.Context, org uuid.UUID) (bool, error) {
	on := false
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT luks_escrow FROM keystore_org_settings WHERE organization_id = $1`, org).Scan(&on)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	return on, err
}

// SetLUKSEscrow turns LUKS escrow on or off for an organization: it needs
// org.manage and step-up and is audited. Off, volumes are still reported and
// shown as "escrow off", and the agent adds nothing.
func (s *Service) SetLUKSEscrow(ctx context.Context, c access.Caller, org uuid.UUID, on bool) (Settings, error) {
	if err := c.Require(rbac.PermOrgManage, rbac.Org(org)); err != nil {
		return Settings{}, err
	}
	if c.Principal == nil || s.stepUp == nil {
		return Settings{}, apperr.Forbidden()
	}
	if err := s.stepUp.VerifyStepUp(ctx); err != nil {
		return Settings{}, err
	}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO keystore_org_settings (organization_id, luks_escrow, updated_by) VALUES ($1, $2, $3)
			ON CONFLICT (organization_id) DO UPDATE SET luks_escrow = EXCLUDED.luks_escrow, updated_by = EXCLUDED.updated_by, updated_at = now()`,
			org, on, c.Principal.UserID); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: ActionLUKSSetting, Outcome: audit.Success, OrganizationID: org,
			TargetType: "organization", TargetID: org.String(), Details: map[string]any{"luksEscrow": on},
		})
	})
	if err != nil {
		return Settings{}, err
	}
	return s.SettingsOf(ctx, c, org)
}

// SetTwoPerson turns the two-person rule on or off for an organization
// (decided in review: off by default). Turning it on needs at least two
// holders of the approve permission, and step-up either way.
func (s *Service) SetTwoPerson(ctx context.Context, c access.Caller, org uuid.UUID, on bool) (Settings, error) {
	if err := c.Require(rbac.PermOrgManage, rbac.Org(org)); err != nil {
		return Settings{}, err
	}
	if c.Principal == nil {
		return Settings{}, apperr.Forbidden()
	}
	if s.stepUp == nil {
		return Settings{}, apperr.Forbidden()
	}
	if err := s.stepUp.VerifyStepUp(ctx); err != nil {
		return Settings{}, err
	}
	n, err := s.approvers(ctx, org)
	if err != nil {
		return Settings{}, err
	}
	if on && n < 2 {
		return Settings{}, apperr.Conflict("need_approvers", "Give the Recovery Key Approver add-on to at least two people in this organization first.")
	}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO keystore_org_settings (organization_id, two_person, updated_by) VALUES ($1, $2, $3)
			ON CONFLICT (organization_id) DO UPDATE SET two_person = EXCLUDED.two_person, updated_by = EXCLUDED.updated_by, updated_at = now()`,
			org, on, c.Principal.UserID); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: ActionSetting, Outcome: audit.Success, OrganizationID: org,
			TargetType: "organization", TargetID: org.String(), Details: map[string]any{"twoPerson": on},
		})
	})
	if err != nil {
		return Settings{}, err
	}
	return s.SettingsOf(ctx, c, org)
}
