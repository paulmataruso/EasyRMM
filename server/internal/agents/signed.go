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
	if !a.Verify(ed25519.PublicKey(key), method, target, body) {
		return nil, ErrUnauthorized
	}
	expires := time.Unix(a.Timestamp, 0).Add(agentproto.MaxSkew + nonceGrace)
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
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
