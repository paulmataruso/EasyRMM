package enrollment

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/paulmataruso/easyrm/pkg/models"
)

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Create(ctx context.Context, et models.EnrollmentToken) (*models.EnrollmentToken, error) {
	var created models.EnrollmentToken
	err := s.pool.QueryRow(ctx,
		`INSERT INTO enrollment_tokens (organization_id, site_id, device_group_id, token_hash, name, max_uses, expires_at, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING id, organization_id, site_id, device_group_id, token_hash, name, max_uses, use_count, expires_at, revoked, created_by, created_at`,
		et.OrganizationID, et.SiteID, et.DeviceGroupID, et.TokenHash, et.Name, et.MaxUses, et.ExpiresAt, et.CreatedBy,
	).Scan(
		&created.ID, &created.OrganizationID, &created.SiteID, &created.DeviceGroupID,
		&created.TokenHash, &created.Name, &created.MaxUses, &created.UseCount,
		&created.ExpiresAt, &created.Revoked, &created.CreatedBy, &created.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting enrollment token: %w", err)
	}
	return &created, nil
}

func (s *Store) ValidateToken(ctx context.Context, tokenHash string) (*models.EnrollmentToken, error) {
	var et models.EnrollmentToken
	err := s.pool.QueryRow(ctx,
		`SELECT id, organization_id, site_id, device_group_id, token_hash, name, max_uses, use_count, expires_at, revoked, created_by, created_at
		 FROM enrollment_tokens
		 WHERE token_hash = $1
		   AND revoked = false
		   AND (expires_at IS NULL OR expires_at > now())
		   AND (max_uses IS NULL OR use_count < max_uses)`,
		tokenHash,
	).Scan(
		&et.ID, &et.OrganizationID, &et.SiteID, &et.DeviceGroupID,
		&et.TokenHash, &et.Name, &et.MaxUses, &et.UseCount,
		&et.ExpiresAt, &et.Revoked, &et.CreatedBy, &et.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("validating enrollment token: %w", err)
	}

	// Ensure the token has a valid site_id (required for device creation)
	if et.SiteID == nil {
		// Get the first site in the organization as default
		var siteID uuid.UUID
		err := s.pool.QueryRow(ctx,
			`SELECT id FROM sites WHERE organization_id = $1 ORDER BY created_at LIMIT 1`,
			et.OrganizationID,
		).Scan(&siteID)
		if err != nil {
			return nil, fmt.Errorf("no sites found for organization: %w", err)
		}
		et.SiteID = &siteID
	}

	return &et, nil
}

func (s *Store) IncrementTokenUse(ctx context.Context, tokenID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE enrollment_tokens SET use_count = use_count + 1 WHERE id = $1`,
		tokenID,
	)
	return err
}

func (s *Store) List(ctx context.Context, orgID uuid.UUID) ([]models.EnrollmentToken, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, organization_id, site_id, device_group_id, name, max_uses, use_count, expires_at, revoked, created_by, created_at
		 FROM enrollment_tokens
		 WHERE organization_id = $1
		 ORDER BY created_at DESC`,
		orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing enrollment tokens: %w", err)
	}
	defer rows.Close()

	var tokens []models.EnrollmentToken
	for rows.Next() {
		var et models.EnrollmentToken
		if err := rows.Scan(
			&et.ID, &et.OrganizationID, &et.SiteID, &et.DeviceGroupID,
			&et.Name, &et.MaxUses, &et.UseCount,
			&et.ExpiresAt, &et.Revoked, &et.CreatedBy, &et.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning enrollment token: %w", err)
		}
		tokens = append(tokens, et)
	}
	return tokens, rows.Err()
}

func (s *Store) Revoke(ctx context.Context, tokenID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE enrollment_tokens SET revoked = true WHERE id = $1 AND revoked = false`,
		tokenID,
	)
	if err != nil {
		return fmt.Errorf("revoking enrollment token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("token not found or already revoked")
	}
	return nil
}

