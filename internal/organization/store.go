package organization

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/paulmataruso/easyrm/pkg/models"
)

var ErrNotFound = errors.New("organization not found")

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Create(ctx context.Context, name, slug string, settings map[string]any) (*models.Organization, error) {
	if settings == nil {
		settings = map[string]any{}
	}

	var org models.Organization
	err := s.pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug, settings)
		 VALUES ($1, $2, $3)
		 RETURNING id, name, slug, settings, created_at, updated_at`,
		name, slug, settings,
	).Scan(&org.ID, &org.Name, &org.Slug, &org.Settings, &org.CreatedAt, &org.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("creating organization: %w", err)
	}
	return &org, nil
}

func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*models.Organization, error) {
	var org models.Organization
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, slug, settings, created_at, updated_at
		 FROM organizations WHERE id = $1`, id,
	).Scan(&org.ID, &org.Name, &org.Slug, &org.Settings, &org.CreatedAt, &org.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting organization by id: %w", err)
	}
	return &org, nil
}

func (s *Store) GetBySlug(ctx context.Context, slug string) (*models.Organization, error) {
	var org models.Organization
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, slug, settings, created_at, updated_at
		 FROM organizations WHERE slug = $1`, slug,
	).Scan(&org.ID, &org.Name, &org.Slug, &org.Settings, &org.CreatedAt, &org.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting organization by slug: %w", err)
	}
	return &org, nil
}

func (s *Store) List(ctx context.Context) ([]models.Organization, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, slug, settings, created_at, updated_at
		 FROM organizations ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("listing organizations: %w", err)
	}
	defer rows.Close()

	var orgs []models.Organization
	for rows.Next() {
		var org models.Organization
		if err := rows.Scan(&org.ID, &org.Name, &org.Slug, &org.Settings, &org.CreatedAt, &org.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning organization: %w", err)
		}
		orgs = append(orgs, org)
	}
	return orgs, rows.Err()
}

func (s *Store) ListForUser(ctx context.Context, userID uuid.UUID) ([]models.Organization, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT o.id, o.name, o.slug, o.settings, o.created_at, o.updated_at
		 FROM organizations o
		 INNER JOIN user_organization_access uoa ON uoa.organization_id = o.id
		 WHERE uoa.user_id = $1
		 ORDER BY o.name`, userID)
	if err != nil {
		return nil, fmt.Errorf("listing organizations for user: %w", err)
	}
	defer rows.Close()

	var orgs []models.Organization
	for rows.Next() {
		var org models.Organization
		if err := rows.Scan(&org.ID, &org.Name, &org.Slug, &org.Settings, &org.CreatedAt, &org.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning organization: %w", err)
		}
		orgs = append(orgs, org)
	}
	return orgs, rows.Err()
}

type UpdateParams struct {
	Name     *string
	Slug     *string
	Settings map[string]any
}

func (s *Store) Update(ctx context.Context, id uuid.UUID, params UpdateParams) (*models.Organization, error) {
	org, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if params.Name != nil {
		org.Name = *params.Name
	}
	if params.Slug != nil {
		org.Slug = *params.Slug
	}
	if params.Settings != nil {
		org.Settings = params.Settings
	}

	err = s.pool.QueryRow(ctx,
		`UPDATE organizations SET name = $1, slug = $2, settings = $3
		 WHERE id = $4
		 RETURNING id, name, slug, settings, created_at, updated_at`,
		org.Name, org.Slug, org.Settings, id,
	).Scan(&org.ID, &org.Name, &org.Slug, &org.Settings, &org.CreatedAt, &org.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("updating organization: %w", err)
	}
	return org, nil
}

func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	result, err := s.pool.Exec(ctx, "DELETE FROM organizations WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("deleting organization: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
