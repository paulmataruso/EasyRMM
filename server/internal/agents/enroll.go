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

// Enroll exchanges a deployment token for a device identity. With a site's
// token the device is created in that site, owned by the public key the
// agent sent. With an approval token (ADR-0024) the device waits until
// someone approves it in the console: the answer says so (Pending), at once
// the first time, so that the installer can finish, and after holding the
// request open for up to agentproto.ApprovalWait for a decision when the
// agent asks again with the same key.
func (s *Service) Enroll(ctx context.Context, ip netip.Addr, req agentproto.EnrollRequest) (*agentproto.EnrollResponse, error) {
	// Every request reads the database; this only keeps junk from loading
	// it. New devices from one address have a stricter limit below.
	if !s.lookups.Allow(ip.String()) {
		return nil, ErrRateLimited
	}
	if !strings.HasPrefix(req.Token, agentproto.TokenPrefix) || len(req.Token) > 100 {
		return nil, s.refuse(ip)
	}
	key, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, apperr.Invalid("publicKey", "Send a base64 Ed25519 public key.")
	}
	f, err := cleanFacts(req.Facts)
	if err != nil {
		return nil, apperr.Invalid("facts", err.Error())
	}

	// Subscribe before looking, so a decision made in between still wakes us.
	wake := s.waits.subscribe(req.PublicKey)
	defer s.waits.unsubscribe(req.PublicKey, wake)
	resp, fresh, err := s.enrollOnce(ctx, ip, hashToken(req.Token), key, f, false)
	if err != nil || resp.Pending == nil || fresh {
		return resp, err
	}
	timer := time.NewTimer(s.approvalWait)
	defer timer.Stop()
	select {
	case <-wake:
		// Decided while waiting: answer with the decision.
		resp, _, err := s.enrollOnce(ctx, ip, hashToken(req.Token), key, f, true)
		return resp, err
	case <-timer.C:
	case <-ctx.Done():
	case <-s.waits.done:
	}
	return resp, nil
}

// refuse answers a token that is not valid. Unknown tokens count against
// the address's enrollment limit, so it ends in ErrRateLimited.
func (s *Service) refuse(ip netip.Addr) error {
	if !s.enroll.Allow(ip.String()) {
		return ErrRateLimited
	}
	return ErrTokenInvalid
}

// enrollOnce looks the token up and enrolls, or records or reports the
// request for approval; fresh is a request recorded now. again is a second
// look after a wake-up, which does not count against the limits.
func (s *Service) enrollOnce(ctx context.Context, ip netip.Addr, hash, key []byte, f facts, again bool) (out *agentproto.EnrollResponse, fresh bool, err error) {
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var err error
		out, err = s.enrollSite(ctx, tx, ip, hash, key, f)
		if !errors.Is(err, errNoSiteToken) {
			return err
		}
		out, fresh, err = s.askApproval(ctx, tx, ip, hash, key, f, again)
		if errors.Is(err, errNoApprovalToken) {
			return s.refuse(ip)
		}
		return err
	})
	if err != nil {
		if errors.Is(err, ErrTokenInvalid) || errors.Is(err, ErrKeyInUse) || errors.Is(err, ErrRateLimited) ||
			errors.Is(err, ErrRejected) || errors.Is(err, ErrTooManyWaiting) {
			return nil, false, err
		}
		return nil, false, fmt.Errorf("agents: enrolling: %w", err)
	}
	if out.Pending != nil {
		return out, fresh, nil
	}
	out, err = s.enrolled(ctx, out.DeviceID)
	return out, false, err
}

var errNoSiteToken = errors.New("agents: not a site token")

// enrollSite creates the device in the site of a site's deployment token.
// It returns errNoSiteToken when the token is not one.
func (s *Service) enrollSite(ctx context.Context, tx pgx.Tx, ip netip.Addr, hash, key []byte, f facts) (*agentproto.EnrollResponse, error) {
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
	err := tx.QueryRow(ctx, `SELECT id, organization_id, site_id, device_group_id, name, expires_at, max_uses, uses, revoked_at IS NOT NULL
		FROM enrollment_tokens WHERE token_hash = $1 FOR UPDATE`, hash).
		Scan(&tokenID, &orgID, &siteID, &groupID, &tokenName, &expires, &maxUses, &uses, &revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNoSiteToken
	}
	if err != nil {
		return nil, err
	}
	if !s.enroll.Allow(ip.String()) {
		return nil, ErrRateLimited
	}
	if st := tokenStatus(revoked, expires, maxUses, uses, s.now()); st != TokenActive {
		s.log.Info("agent enrollment refused", "token_id", tokenID, "token_status", st, "ip", ip.String(), "hostname", f.hostname)
		return nil, ErrTokenInvalid
	}
	err = tx.QueryRow(ctx, `INSERT INTO devices (organization_id, site_id, device_group_id, name, hostname, os_description, platform,
			agent_public_key, agent_version, agent_arch, agent_last_seen_at, enrolled_at, enrollment_token_id)
		VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8, $9, now(), now(), $10) RETURNING id`,
		orgID, siteID, groupID, f.hostname, f.os, f.platform, key, f.version, f.arch, tokenID).Scan(&id)
	if database.IsUniqueViolation(err) {
		return nil, ErrKeyInUse
	}
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE enrollment_tokens SET uses = uses + 1, last_used_at = now() WHERE id = $1`, tokenID); err != nil {
		return nil, err
	}
	s.log.Info("agent enrolled", "device_id", id, "hostname", f.hostname, "site_id", siteID, "token_id", tokenID)
	return &agentproto.EnrollResponse{DeviceID: id.String()}, s.audit.Write(ctx, tx, audit.Event{
		Actor:  audit.Actor{Type: audit.ActorAgent, ID: id, Label: f.hostname, SourceIP: ip},
		Action: "device.enroll", Outcome: audit.Success,
		OrganizationID: orgID, SiteID: siteID, DeviceID: id, TargetType: "device", TargetID: id.String(),
		Details: map[string]any{
			"device": f.hostname, "platform": f.platform, "agentVersion": f.version,
			"token": tokenName, "tokenId": tokenID.String(),
		},
	})
}

// enrolled is the answer to an enrolled device: its identity and whether
// it should install MeshAgent now.
func (s *Service) enrolled(ctx context.Context, deviceID string) (*agentproto.EnrollResponse, error) {
	var siteID uuid.UUID
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT site_id FROM devices WHERE id = $1`, deviceID).Scan(&siteID)
	})
	if err != nil {
		return nil, fmt.Errorf("agents: reading the new device: %w", err)
	}
	available, err := s.meshAvailable(ctx, siteID)
	if err != nil {
		s.log.Warn("agents: checking remote access for a new device failed", "error", err)
	}
	return &agentproto.EnrollResponse{
		DeviceID:         deviceID,
		HeartbeatSeconds: int(HeartbeatInterval.Seconds()),
		MeshAgent:        agentproto.MeshAgentInfo{Available: available},
		JobKey:           s.jobKey,
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
