package quickassist

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// ConversionLife is how long the conversion token works; a failed install
// can retry until it ends (ADR-0080).
const ConversionLife = 30 * time.Minute

// Audit actions for installing permanently.
const (
	ActionInstall   = "quickassist.install"
	ActionConverted = "quickassist.converted"
)

// RequestInstall records the technician's wish to keep the agent on the
// computer. The caller must hold the session; the API has checked step-up.
// Nothing happens on the computer until the user agrees in the runner.
func (s *Service) RequestInstall(ctx context.Context, c access.Caller, id uuid.UUID) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		x, _, err := s.loadSession(ctx, tx, c, id)
		if err != nil {
			return err
		}
		if err := c.Require(rbac.PermQAInstall, rbac.Org(x.Organization)); err != nil {
			return err
		}
		if !devscope.Allowed(x.Organization) {
			return apperr.Forbidden()
		}
		if x.State != SessionActive {
			return apperr.Conflict("not_active", "Only an active session can install the agent.")
		}
		if !holder(c, x) {
			return apperr.Forbidden()
		}
		if !x.Elevated {
			return apperr.Conflict("not_elevated", "The program is not running as administrator. Ask the user to start it again as administrator first.")
		}
		var by *uuid.UUID
		if c.Principal != nil {
			by = &c.Principal.UserID
		}
		tag, err := tx.Exec(ctx, `UPDATE quick_assist_sessions SET install_state = 'requested', install_by = $2
			WHERE id = $1 AND install_state IN ('none', 'declined', 'consented')`, id, by)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return apperr.Conflict("install_started", "The agent is already installed or being installed.")
		}
		return s.audit.Write(ctx, tx, s.sessionEvent(c.Actor, x, ActionInstall, audit.Success, map[string]any{"step": "requested"}))
	})
}

// Conversion is what a runner gets once its user agrees: the server and a
// token for the one enrollment that makes the permanent agent.
type Conversion struct {
	Token string `json:"token"`
}

// InstallConsent records the user's answer in the runner. On yes it makes
// the conversion token: one use, thirty minutes, for the organization's
// Quick Assist site. Only the runner's signed message gets here, and only
// after the technician asked.
func (s *Service) InstallConsent(ctx context.Context, device uuid.UUID, ip netip.Addr, accept bool) (*Conversion, error) {
	var out *Conversion
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var id, org uuid.UUID
		var state, install string
		var name string
		if err := tx.QueryRow(ctx, `SELECT s.id, s.organization_id, s.state, s.install_state, coalesce(d.name, '')
			FROM quick_assist_sessions s LEFT JOIN devices d ON d.id = s.device_id WHERE s.device_id = $1 FOR UPDATE OF s`, device).
			Scan(&id, &org, &state, &install, &name); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apperr.NotFound()
			}
			return err
		}
		if state != SessionActive || install != "requested" || !devscope.Allowed(org) {
			return apperr.Conflict("no_offer", "The technician has not asked to install the agent.")
		}
		actor := audit.Actor{Type: audit.ActorAgent, ID: device, Label: name, SourceIP: ip}
		x := &Session{ID: id, Organization: org, DeviceName: name}
		if !accept {
			if _, err := tx.Exec(ctx, `UPDATE quick_assist_sessions SET install_state = 'declined' WHERE id = $1`, id); err != nil {
				return err
			}
			return s.audit.Write(ctx, tx, s.sessionEvent(actor, x, ActionInstall, audit.Denied, map[string]any{"step": "user_declined"}))
		}
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		secret := agentproto.TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
		var site uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM sites WHERE organization_id = $1 AND kind = 'quick_assist'`, org).Scan(&site); err != nil {
			return err
		}
		var tokenID uuid.UUID
		if err := tx.QueryRow(ctx, `INSERT INTO enrollment_tokens (organization_id, site_id, name, token_hash, expires_at, max_uses)
			VALUES ($1, $2, 'Quick Assist conversion', $3, $4, 1) RETURNING id`, org, site, hashToken(secret), s.now().Add(ConversionLife)).Scan(&tokenID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE quick_assist_sessions SET install_state = 'consented', install_token_id = $2 WHERE id = $1`, id, tokenID); err != nil {
			return err
		}
		out = &Conversion{Token: secret}
		return s.audit.Write(ctx, tx, s.sessionEvent(actor, x, ActionInstall, audit.Success, map[string]any{"step": "user_consented"}))
	})
	return out, err
}

// Converted is the runner's report that the permanent agent is in place. The
// server finds the new device by the token it enrolled with, so a runner
// cannot name another computer, and links it to the session. The temporary
// device goes when the runner reports its clean-up.
func (s *Service) Converted(ctx context.Context, device uuid.UUID, ip netip.Addr) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var id, org uuid.UUID
		var install string
		var token *uuid.UUID
		var name string
		if err := tx.QueryRow(ctx, `SELECT s.id, s.organization_id, s.install_state, s.install_token_id, coalesce(d.name, '')
			FROM quick_assist_sessions s LEFT JOIN devices d ON d.id = s.device_id WHERE s.device_id = $1 AND s.state = 'active' FOR UPDATE OF s`, device).
			Scan(&id, &org, &install, &token, &name); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apperr.NotFound()
			}
			return err
		}
		if install != "consented" || token == nil {
			return apperr.Conflict("no_consent", "The user has not agreed to install the agent.")
		}
		var newDev uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM devices WHERE enrollment_token_id = $1 AND id <> $2 AND organization_id = $3`, *token, device, org).Scan(&newDev); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apperr.Conflict("not_enrolled", "The permanent agent has not enrolled yet.")
			}
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET origin_session_id = $2, quick_assist = true WHERE id = $1`, newDev, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE quick_assist_sessions SET state = 'converted', install_state = 'converted', converted_device_id = $2, end_reason = 'converted', ended_at = now() WHERE id = $1`, id, newDev); err != nil {
			return err
		}
		// The token is spent with the session.
		if _, err := tx.Exec(ctx, `UPDATE enrollment_tokens SET revoked_at = coalesce(revoked_at, now()) WHERE id = $1`, *token); err != nil {
			return err
		}
		x := &Session{ID: id, Organization: org, DeviceName: name}
		e := s.sessionEvent(audit.Actor{Type: audit.ActorAgent, ID: device, Label: name, SourceIP: ip}, x, ActionConverted, audit.Success,
			map[string]any{"fromDevice": device.String(), "toDevice": newDev.String()})
		e.DeviceID = newDev
		return s.audit.Write(ctx, tx, e)
	})
}
