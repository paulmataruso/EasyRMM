package agents

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// Enroll exchanges a deployment token for a device identity. The device is
// created in the token's site, owned by the public key the agent sent.
func (s *Service) Enroll(ctx context.Context, ip netip.Addr, req agentproto.EnrollRequest) (*agentproto.EnrollResponse, error) {
	if !s.enroll.Allow(ip.String()) {
		return nil, ErrRateLimited
	}
	if !strings.HasPrefix(req.Token, agentproto.TokenPrefix) || len(req.Token) > 100 {
		return nil, ErrTokenInvalid
	}
	key, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, apperr.Invalid("publicKey", "Send a base64 Ed25519 public key.")
	}
	f, err := cleanFacts(req.Facts)
	if err != nil {
		return nil, apperr.Invalid("facts", err.Error())
	}

	var (
		id                     uuid.UUID
		tokenID, orgID, siteID uuid.UUID
		groupID                *uuid.UUID
		tokenName              string
		expires                time.Time
		maxUses                *int
		uses                   int
		revoked                bool
	)
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT id, organization_id, site_id, device_group_id, name, expires_at, max_uses, uses, revoked_at IS NOT NULL
			FROM enrollment_tokens WHERE token_hash = $1 FOR UPDATE`, hashToken(req.Token)).
			Scan(&tokenID, &orgID, &siteID, &groupID, &tokenName, &expires, &maxUses, &uses, &revoked)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTokenInvalid
		}
		if err != nil {
			return err
		}
		if st := tokenStatus(revoked, expires, maxUses, uses, s.now()); st != TokenActive {
			s.log.Info("agent enrollment refused", "token_id", tokenID, "token_status", st, "ip", ip.String(), "hostname", f.hostname)
			return ErrTokenInvalid
		}
		err = tx.QueryRow(ctx, `INSERT INTO devices (organization_id, site_id, device_group_id, name, hostname, os_description, platform,
				agent_public_key, agent_version, agent_arch, agent_last_seen_at, enrolled_at, enrollment_token_id)
			VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8, $9, now(), now(), $10) RETURNING id`,
			orgID, siteID, groupID, f.hostname, f.os, f.platform, key, f.version, f.arch, tokenID).Scan(&id)
		if database.IsUniqueViolation(err) {
			return ErrKeyInUse
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE enrollment_tokens SET uses = uses + 1, last_used_at = now() WHERE id = $1`, tokenID); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor:  audit.Actor{Type: audit.ActorAgent, ID: id, Label: f.hostname, SourceIP: ip},
			Action: "device.enroll", Outcome: audit.Success,
			OrganizationID: orgID, SiteID: siteID, DeviceID: id, TargetType: "device", TargetID: id.String(),
			Details: map[string]any{
				"device": f.hostname, "platform": f.platform, "agentVersion": f.version,
				"token": tokenName, "tokenId": tokenID.String(),
			},
		})
	})
	if err != nil {
		if errors.Is(err, ErrTokenInvalid) || errors.Is(err, ErrKeyInUse) {
			return nil, err
		}
		return nil, fmt.Errorf("agents: enrolling: %w", err)
	}
	s.log.Info("agent enrolled", "device_id", id, "hostname", f.hostname, "site_id", siteID, "token_id", tokenID)
	available, err := s.meshAvailable(ctx, siteID)
	if err != nil {
		s.log.Warn("agents: checking remote access for a new device failed", "error", err)
	}
	return &agentproto.EnrollResponse{
		DeviceID:         id.String(),
		HeartbeatSeconds: int(HeartbeatInterval.Seconds()),
		MeshAgent:        agentproto.MeshAgentInfo{Available: available},
	}, nil
}

// meshAvailable says whether MeshAgent can be installed for a site now.
func (s *Service) meshAvailable(ctx context.Context, siteID uuid.UUID) (bool, error) {
	if s.mesh == nil {
		return false, nil
	}
	g, err := s.mesh.Group(ctx, siteID)
	if err != nil {
		return false, err
	}
	return g != "", nil
}
