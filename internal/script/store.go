package script

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/paulmataruso/easyrm/pkg/models"
)

var ErrNotFound = errors.New("script not found")

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

const scriptColumns = `id, organization_id, name, description, shell, os_type, content, timeout_seconds, category, is_builtin, created_by, created_at, updated_at`

func scanScript(row pgx.Row) (*models.Script, error) {
	var s models.Script
	err := row.Scan(&s.ID, &s.OrganizationID, &s.Name, &s.Description, &s.Shell, &s.OSType, &s.Content, &s.TimeoutSeconds, &s.Category, &s.IsBuiltin, &s.CreatedBy, &s.CreatedAt, &s.UpdatedAt)
	return &s, err
}

type CreateParams struct {
	OrganizationID *uuid.UUID
	Name           string
	Description    string
	Shell          string
	OSType         string
	Content        string
	TimeoutSeconds int
	Category       string
	CreatedBy      *uuid.UUID
}

func (s *Store) Create(ctx context.Context, p CreateParams) (*models.Script, error) {
	timeout := p.TimeoutSeconds
	if timeout <= 0 {
		timeout = 300
	}
	row := s.pool.QueryRow(ctx,
		`INSERT INTO scripts (organization_id, name, description, shell, os_type, content, timeout_seconds, category, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 RETURNING `+scriptColumns,
		p.OrganizationID, p.Name, p.Description, p.Shell, p.OSType, p.Content, timeout, p.Category, p.CreatedBy,
	)
	sc, err := scanScript(row)
	if err != nil {
		return nil, fmt.Errorf("creating script: %w", err)
	}
	return sc, nil
}

func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*models.Script, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+scriptColumns+` FROM scripts WHERE id = $1`, id)
	sc, err := scanScript(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting script: %w", err)
	}
	return sc, nil
}

func (s *Store) List(ctx context.Context, orgID uuid.UUID) ([]models.Script, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+scriptColumns+` FROM scripts WHERE organization_id = $1 OR organization_id IS NULL ORDER BY is_builtin DESC, name`, orgID)
	if err != nil {
		return nil, fmt.Errorf("listing scripts: %w", err)
	}
	defer rows.Close()

	var scripts []models.Script
	for rows.Next() {
		var sc models.Script
		if err := rows.Scan(&sc.ID, &sc.OrganizationID, &sc.Name, &sc.Description, &sc.Shell, &sc.OSType, &sc.Content, &sc.TimeoutSeconds, &sc.Category, &sc.IsBuiltin, &sc.CreatedBy, &sc.CreatedAt, &sc.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning script: %w", err)
		}
		scripts = append(scripts, sc)
	}
	return scripts, rows.Err()
}

type UpdateParams struct {
	Name           *string
	Description    *string
	Content        *string
	Shell          *string
	Category       *string
	TimeoutSeconds *int
}

func (s *Store) Update(ctx context.Context, id uuid.UUID, p UpdateParams) (*models.Script, error) {
	sc, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if p.Name != nil {
		sc.Name = *p.Name
	}
	if p.Description != nil {
		sc.Description = *p.Description
	}
	if p.Content != nil {
		sc.Content = *p.Content
	}
	if p.Shell != nil {
		sc.Shell = *p.Shell
	}
	if p.Category != nil {
		sc.Category = *p.Category
	}
	if p.TimeoutSeconds != nil {
		sc.TimeoutSeconds = *p.TimeoutSeconds
	}

	row := s.pool.QueryRow(ctx,
		`UPDATE scripts SET name=$1, description=$2, content=$3, shell=$4, category=$5, timeout_seconds=$6
		 WHERE id=$7
		 RETURNING `+scriptColumns,
		sc.Name, sc.Description, sc.Content, sc.Shell, sc.Category, sc.TimeoutSeconds, id,
	)
	sc, err = scanScript(row)
	if err != nil {
		return nil, fmt.Errorf("updating script: %w", err)
	}
	return sc, nil
}

func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	result, err := s.pool.Exec(ctx, "DELETE FROM scripts WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("deleting script: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
