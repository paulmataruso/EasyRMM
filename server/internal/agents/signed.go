package agents

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// Device is an authenticated agent's device.
type Device struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	SiteID         uuid.UUID
	Hostname       string
	MeshNodeID     string
}

// nonceGrace keeps a nonce a little past the moment its timestamp stops
// being accepted, covering clock differences between server and database.
const nonceGrace = time.Minute

// Authenticate verifies a signed agent request: the Authorization header,
// the request's method and target (path and query as sent) and its body.
// Each nonce is accepted once.
func (s *Service) Authenticate(ctx context.Context, header, method, target string, body []byte) (*Device, error) {
	p, err := s.BeginSigned(ctx, header)
	if err != nil {
		return nil, err
	}
	return s.FinishSigned(ctx, p, method, target, body)
}

// SignedRequest is a signed agent request whose header names an enrolled
// device, before its body is read and its signature checked.
type SignedRequest struct {
	auth   agentproto.Auth
	device Device
	key    ed25519.PublicKey
}

// DeviceID is the device the request claims to come from. Nothing about it
// is verified yet.
func (p *SignedRequest) DeviceID() uuid.UUID { return p.device.ID }

// BeginSigned checks what a signed request's header says on its own: its
// form, its timestamp and that it names an enrolled device. The server
// does this before reading the body, so a request from no enrolled device
// is refused before it can send one.
func (s *Service) BeginSigned(ctx context.Context, header string) (*SignedRequest, error) {
	a, err := agentproto.Parse(header)
	if err != nil {
		return nil, ErrUnauthorized
	}
	if !a.Fresh(s.now()) {
		return nil, ErrClockSkew
	}
	id, err := uuid.Parse(a.Device)
	if err != nil {
		return nil, ErrUnauthorized
	}
	var (
		d   = Device{ID: id}
		key []byte
	)
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT agent_public_key, organization_id, site_id, hostname, coalesce(mesh_node_id, '')
			FROM devices WHERE id = $1 AND agent_public_key IS NOT NULL`, id).
			Scan(&key, &d.OrganizationID, &d.SiteID, &d.Hostname, &d.MeshNodeID)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUnknownDevice
	}
	if err != nil {
		return nil, err
	}
	return &SignedRequest{auth: a, device: d, key: ed25519.PublicKey(key)}, nil
}

// FinishSigned verifies the request's signature over its method, target
// and body, and accepts its nonce once. The timestamp is checked again: the
// body may have taken a while, and a nonce is only remembered for a little
// longer than its timestamp is accepted.
func (s *Service) FinishSigned(ctx context.Context, p *SignedRequest, method, target string, body []byte) (*Device, error) {
	a, id, d := p.auth, p.device.ID, p.device
	if !a.Verify(p.key, method, target, body) {
		return nil, ErrUnauthorized
	}
	if !a.Fresh(s.now()) {
		return nil, ErrClockSkew
	}
	expires := time.Unix(a.Timestamp, 0).Add(agentproto.MaxSkew + nonceGrace)
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO agent_nonces (device_id, nonce, expires_at) VALUES ($1, $2, $3)
			ON CONFLICT DO NOTHING`, id, a.Nonce, expires)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrReplay
		}
		return err
	})
	if errors.Is(err, ErrReplay) {
		return nil, err
	}
	if database.IsForeignKeyViolation(err) {
		return nil, ErrUnknownDevice // removed while we verified
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}
