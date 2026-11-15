package site

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/paulmataruso/easyrm/pkg/models"
)

var ErrNotFound = errors.New("site not found")

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Create(ctx context.Context, orgID uuid.UUID, name, slug string, settings map[string]any) (*models.Site, error) {
	if settings == nil {
		settings = map[string]any{}
	}

	var site models.Site
	err := s.pool.QueryRow(ctx,
		`INSERT INTO sites (organization_id, name, slug, settings)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, organization_id, name, slug, settings, created_at, updated_at`,
		orgID, name, slug, settings,
	).Scan(&site.ID, &site.OrganizationID, &site.Name, &site.Slug, &site.Settings, &site.CreatedAt, &site.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("creating site: %w", err)
	}
	return &site, nil
}

func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*models.Site, error) {
	var site models.Site
	err := s.pool.QueryRow(ctx,
		`SELECT id, organization_id, name, slug, settings, created_at, updated_at
		 FROM sites WHERE id = $1`, id,
	).Scan(&site.ID, &site.OrganizationID, &site.Name, &site.Slug, &site.Settings, &site.CreatedAt, &site.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting site by id: %w", err)
	}
	return &site, nil
}

func (s *Store) List(ctx context.Context, orgID uuid.UUID) ([]models.Site, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, organization_id, name, slug, settings, created_at, updated_at
		 FROM sites WHERE organization_id = $1 ORDER BY name`, orgID)
	if err != nil {
		return nil, fmt.Errorf("listing sites: %w", err)
	}
	defer rows.Close()

	var sites []models.Site
	for rows.Next() {
		var site models.Site
		if err := rows.Scan(&site.ID, &site.OrganizationID, &site.Name, &site.Slug, &site.Settings, &site.CreatedAt, &site.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning site: %w", err)
		}
		sites = append(sites, site)
	}
	return sites, rows.Err()
}

type UpdateParams struct {
	Name     *string
	Slug     *string
	Settings map[string]any
}

func (s *Store) Update(ctx context.Context, id uuid.UUID, params UpdateParams) (*models.Site, error) {
	site, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if params.Name != nil {
		site.Name = *params.Name
	}
	if params.Slug != nil {
		site.Slug = *params.Slug
	}
	if params.Settings != nil {
		site.Settings = params.Settings
	}

	err = s.pool.QueryRow(ctx,
		`UPDATE sites SET name = $1, slug = $2, settings = $3
		 WHERE id = $4
		 RETURNING id, organization_id, name, slug, settings, created_at, updated_at`,
		site.Name, site.Slug, site.Settings, id,
	).Scan(&site.ID, &site.OrganizationID, &site.Name, &site.Slug, &site.Settings, &site.CreatedAt, &site.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("updating site: %w", err)
	}
	return site, nil
}

func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	result, err := s.pool.Exec(ctx, "DELETE FROM sites WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("deleting site: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
