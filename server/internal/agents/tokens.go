package agents

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Token limits.
const (
	MaxTokenDays = 90
	MaxTokenUses = 100_000
	// MaxTokens bounds one list response.
	MaxTokens = 1000
)

// TokenStatus summarizes whether a token can still enroll devices.
type TokenStatus string

// Token statuses.
const (
	TokenActive  TokenStatus = "active"
	TokenExpired TokenStatus = "expired"
	TokenRevoked TokenStatus = "revoked"
	TokenUsedUp  TokenStatus = "used_up"
)

// Token is a deployment token as the console shows it. The secret is
// returned by CreateToken and, while the token is active, by RevealToken.
type Token struct {
	ID               uuid.UUID   `json:"id"`
	OrganizationID   uuid.UUID   `json:"organizationId"`
	OrganizationName string      `json:"organizationName"`
	SiteID           uuid.UUID   `json:"siteId"`
	SiteName         string      `json:"siteName"`
	DeviceGroupID    *uuid.UUID  `json:"deviceGroupId"`
	DeviceGroupName  string      `json:"deviceGroupName,omitempty"`
	Name             string      `json:"name"`
	ExpiresAt        time.Time   `json:"expiresAt"`
	MaxUses          *int        `json:"maxUses"`
	Uses             int         `json:"uses"`
	CreatedByName    string      `json:"createdByName,omitempty"`
	CreatedAt        time.Time   `json:"createdAt"`
	LastUsedAt       *time.Time  `json:"lastUsedAt"`
	RevokedAt        *time.Time  `json:"revokedAt"`
	Status           TokenStatus `json:"status"`
	// Kept says the secret was kept, so the token can be shown again.
	Kept bool `json:"kept"`
}

// TokenInput describes a new token.
type TokenInput struct {
	Name          string     `json:"name"`
	DeviceGroupID *uuid.UUID `json:"deviceGroupId"`
	ExpiresInDays int        `json:"expiresInDays"`
	// MaxUses limits how many devices can enroll; nil means no limit.
	MaxUses *int `json:"maxUses"`
}

func (in *TokenInput) normalize() error {
	f := apperr.Fields{}
	in.Name = clean(in.Name, 1000)
	f.Check(in.Name != "", "name", "Name the token, for example after the deployment it is for.")
	f.Check(len([]rune(in.Name)) <= 200, "name", "Use at most 200 characters.")
	f.Check(in.ExpiresInDays >= 1 && in.ExpiresInDays <= MaxTokenDays, "expiresInDays", "Choose between 1 and 90 days.")
	if in.MaxUses != nil {
		f.Check(*in.MaxUses >= 1 && *in.MaxUses <= MaxTokenUses, "maxUses", "Choose between 1 and 100,000 devices, or no limit.")
	}
	return f.Err()
}

// NewToken is a token with its secret: a new one, or one shown again.
type NewToken struct {
	Token  *Token `json:"token"`
	Secret string `json:"secret"`
}

// TokenQuery filters a token list.
type TokenQuery struct {
	OrganizationID uuid.UUID
	SiteID         uuid.UUID
	// Active limits the list to tokens that can still enroll devices.
	Active bool
}

//nolint:gosec // column names, not credentials
const tokenColumns = `t.id, t.organization_id, o.name, t.site_id, s.name, t.device_group_id, coalesce(g.name, ''),
	t.name, t.expires_at, t.max_uses, t.uses, coalesce(u.display_name, ''), t.created_at, t.last_used_at, t.revoked_at,
	t.token_sealed IS NOT NULL`

const tokenFrom = ` FROM enrollment_tokens t
	JOIN sites s ON s.id = t.site_id
	JOIN organizations o ON o.id = t.organization_id
	LEFT JOIN device_groups g ON g.id = t.device_group_id
	LEFT JOIN users u ON u.id = t.created_by`

func (s *Service) scanToken(row pgx.Row) (*Token, error) {
	var t Token
	err := row.Scan(&t.ID, &t.OrganizationID, &t.OrganizationName, &t.SiteID, &t.SiteName, &t.DeviceGroupID, &t.DeviceGroupName,
		&t.Name, &t.ExpiresAt, &t.MaxUses, &t.Uses, &t.CreatedByName, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt, &t.Kept)
	if err != nil {
		return nil, err
	}
	t.Status = tokenStatus(t.RevokedAt != nil, t.ExpiresAt, t.MaxUses, t.Uses, s.now())
	return &t, nil
}

func tokenStatus(revoked bool, expires time.Time, maxUses *int, uses int, now time.Time) TokenStatus {
	switch {
	case revoked:
		return TokenRevoked
	case !now.Before(expires):
		return TokenExpired
	case maxUses != nil && uses >= *maxUses:
		return TokenUsedUp
	}
	return TokenActive
}

// newTokenSecret returns a deployment token and the hash stored for it.
func newTokenSecret() (string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	secret := agentproto.TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	return secret, hashToken(secret), nil
}

func hashToken(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// The tables holding tokens, and their kinds as audit events name them.
const (
	deploymentTokens = "enrollment_tokens"
	approvalTokens   = "approval_tokens"
)

func tokenKind(table string) string {
	if table == approvalTokens {
		return "approval_token"
	}
	return "enrollment_token"
}

// sealToken seals a new token's secret for the row it goes in, or returns
// nil when the service keeps none.
func (s *Service) sealToken(table string, id uuid.UUID, secret string) (*string, error) {
	if s.tokens == nil {
		return nil, nil
	}
	sealed, err := s.tokens.Seal([]byte(secret), []byte(tokenKind(table)+":"+id.String()))
	if err != nil {
		return nil, err
	}
	return &sealed, nil
}

var errNotKept = errors.New("agents: token secret not kept")

// revealSecret opens an active token's kept secret and records who saw it.
func (s *Service) revealSecret(ctx context.Context, c access.Caller, table string, id uuid.UUID, status TokenStatus, ev audit.Event) (string, error) {
	if status != TokenActive {
		return "", apperr.Conflict("token_inactive", "This token can no longer add devices, so there is nothing to show. Create a new one.")
	}
	var secret string
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var sealed *string
		var hash []byte
		if err := tx.QueryRow(ctx, `SELECT token_sealed, token_hash FROM `+table+` WHERE id = $1`, id).Scan(&sealed, &hash); err != nil {
			return err
		}
		if sealed == nil || s.tokens == nil {
			return errNotKept
		}
		plain, err := s.tokens.Open(*sealed, []byte(tokenKind(table)+":"+id.String()))
		if err != nil {
			return fmt.Errorf("agents: opening %s %s: %w", tokenKind(table), id, err)
		}
		if subtle.ConstantTimeCompare(hashToken(string(plain)), hash) != 1 {
			return fmt.Errorf("agents: %s %s: the kept secret does not match its hash", tokenKind(table), id)
		}
		secret = string(plain)
		ev.Actor, ev.Action, ev.Outcome = c.Actor, tokenKind(table)+".reveal", audit.Success
		ev.TargetType, ev.TargetID = tokenKind(table), id.String()
		return s.audit.Write(ctx, tx, ev)
	})
	if errors.Is(err, errNotKept) {
		return "", apperr.Conflict("token_not_kept",
			"This token was created before EasyRMM kept tokens to show again. Create a new one, or use the command saved when it was created.")
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return "", apperr.NotFound()
	}
	return secret, err
}

// CreateToken creates a deployment token for a site.
func (s *Service) CreateToken(ctx context.Context, c access.Caller, siteID uuid.UUID, in TokenInput) (*NewToken, error) {
	var orgID uuid.UUID
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT organization_id FROM sites WHERE id = $1`, siteID).Scan(&orgID)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	res := rbac.Site(orgID, siteID)
	if !c.Can(rbac.PermSiteView, res) {
		return nil, apperr.NotFound()
	}
	if err := c.Require(rbac.PermEnrollManage, res); err != nil {
		return nil, err
	}
	if err := in.normalize(); err != nil {
		return nil, err
	}
	secret, hash, err := newTokenSecret()
	if err != nil {
		return nil, err
	}
	var createdBy *uuid.UUID
	if c.Principal != nil {
		createdBy = &c.Principal.UserID
	}
	expires := s.now().Add(time.Duration(in.ExpiresInDays) * 24 * time.Hour)
	id := uuid.New()
	sealed, err := s.sealToken(deploymentTokens, id, secret)
	if err != nil {
		return nil, err
	}
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO enrollment_tokens
			(id, organization_id, site_id, device_group_id, name, token_hash, token_sealed, expires_at, max_uses, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			id, orgID, siteID, in.DeviceGroupID, in.Name, hash, sealed, expires, in.MaxUses, createdBy); err != nil {
			return err
		}
		details := map[string]any{"name": in.Name, "expiresAt": expires.UTC().Format(time.RFC3339)}
		if in.MaxUses != nil {
			details["maxUses"] = *in.MaxUses
		}
		if in.DeviceGroupID != nil {
			details["deviceGroupId"] = in.DeviceGroupID.String()
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "enrollment_token.create", Outcome: audit.Success,
			OrganizationID: orgID, SiteID: siteID, TargetType: "enrollment_token", TargetID: id.String(), Details: details})
	})
	if database.IsForeignKeyViolation(err) {
		return nil, apperr.Invalid("deviceGroupId", "Choose a device group of this site.")
	}
	if err != nil {
		return nil, err
	}
	t, err := s.GetToken(ctx, c, id)
	if err != nil {
		return nil, err
	}
	return &NewToken{Token: t, Secret: secret}, nil
}

// GetToken returns one token the caller manages.
func (s *Service) GetToken(ctx context.Context, c access.Caller, id uuid.UUID) (*Token, error) {
	var t *Token
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var err error
		t, err = s.scanToken(tx.QueryRow(ctx, `SELECT `+tokenColumns+tokenFrom+` WHERE t.id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	if !c.Can(rbac.PermEnrollManage, rbac.Site(t.OrganizationID, t.SiteID)) {
		return nil, apperr.NotFound()
	}
	return t, nil
}

// RevealToken returns an active deployment token with its secret again, for
// its install commands (ADR-0047). Every time is audited.
func (s *Service) RevealToken(ctx context.Context, c access.Caller, id uuid.UUID) (*NewToken, error) {
	t, err := s.GetToken(ctx, c, id)
	if err != nil {
		return nil, err
	}
	secret, err := s.revealSecret(ctx, c, deploymentTokens, id, t.Status, audit.Event{
		OrganizationID: t.OrganizationID, SiteID: t.SiteID, Details: map[string]any{"name": t.Name},
	})
	if err != nil {
		return nil, err
	}
	return &NewToken{Token: t, Secret: secret}, nil
}

// ListTokens returns the tokens the caller manages, newest first.
func (s *Service) ListTokens(ctx context.Context, c access.Caller, q TokenQuery) ([]*Token, error) {
	out := []*Token{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+tokenColumns+tokenFrom+`
			WHERE ($1::uuid IS NULL OR t.organization_id = $1)
			  AND ($2::uuid IS NULL OR t.site_id = $2)
			  AND (NOT $3 OR (t.revoked_at IS NULL AND t.expires_at > now() AND (t.max_uses IS NULL OR t.uses < t.max_uses)))
			ORDER BY t.created_at DESC, t.id LIMIT $4`,
			nullUUID(q.OrganizationID), nullUUID(q.SiteID), q.Active, MaxTokens)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			t, err := s.scanToken(rows)
			if err != nil {
				return err
			}
			if c.Can(rbac.PermEnrollManage, rbac.Site(t.OrganizationID, t.SiteID)) {
				out = append(out, t)
			}
		}
		return rows.Err()
	})
	return out, err
}

// RevokeToken stops a token from enrolling more devices. Devices it
// enrolled stay enrolled. Revoking a revoked token changes nothing.
func (s *Service) RevokeToken(ctx context.Context, c access.Caller, id uuid.UUID) (*Token, error) {
	t, err := s.GetToken(ctx, c, id)
	if err != nil {
		return nil, err
	}
	if t.RevokedAt != nil {
		return t, nil
	}
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE enrollment_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "enrollment_token.revoke", Outcome: audit.Success,
			OrganizationID: t.OrganizationID, SiteID: t.SiteID, TargetType: "enrollment_token", TargetID: id.String(),
			Details: map[string]any{"name": t.Name, "uses": t.Uses}})
	})
	if err != nil {
		return nil, err
	}
	return s.GetToken(ctx, c, id)
}

func nullUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

// TokenOrg is the organization a deployment token belongs to, for the
// downloads an installer makes before it enrolls (package devscope). A token
// that is unknown or revoked belongs to none.
func (s *Service) TokenOrg(ctx context.Context, secret string) (uuid.UUID, bool) {
	var org uuid.UUID
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT organization_id FROM enrollment_tokens WHERE token_hash = $1 AND revoked_at IS NULL`,
			hashToken(secret)).Scan(&org)
	})
	return org, err == nil
}
