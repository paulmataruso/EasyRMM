package job

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/paulmataruso/easyrm/pkg/models"
)

var ErrNotFound = errors.New("job not found")

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

const jobColumns = `id, organization_id, name, job_type, status, target_type, target_id, script_id, payload, scheduled_at, started_at, completed_at, created_by, created_at`

func scanJob(row pgx.Row) (*models.Job, error) {
	var j models.Job
	err := row.Scan(&j.ID, &j.OrganizationID, &j.Name, &j.JobType, &j.Status, &j.TargetType, &j.TargetID, &j.ScriptID, &j.Payload, &j.ScheduledAt, &j.StartedAt, &j.CompletedAt, &j.CreatedBy, &j.CreatedAt)
	return &j, err
}

type CreateParams struct {
	OrganizationID uuid.UUID
	Name           string
	JobType        string
	ScriptID       *uuid.UUID
	TargetType     string
	TargetID       uuid.UUID
	CreatedBy      uuid.UUID
	Payload        map[string]any
}

func (s *Store) Create(ctx context.Context, p CreateParams) (*models.Job, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO jobs (organization_id, name, job_type, status, target_type, target_id, script_id, payload, created_by)
		 VALUES ($1, $2, $3, 'pending', $4, $5, $6, $7, $8)
		 RETURNING `+jobColumns,
		p.OrganizationID, p.Name, p.JobType, p.TargetType, p.TargetID, p.ScriptID, p.Payload, p.CreatedBy,
	)
	j, err := scanJob(row)
	if err != nil {
		return nil, fmt.Errorf("creating job: %w", err)
	}
	return j, nil
}

func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*models.Job, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+jobColumns+` FROM jobs WHERE id = $1`, id)
	j, err := scanJob(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting job: %w", err)
	}
	return j, nil
}

type ListFilters struct {
	Status string
	Limit  int
	Offset int
}

func (s *Store) List(ctx context.Context, orgID uuid.UUID, f ListFilters) ([]models.Job, int, error) {
	var conditions []string
	var args []any
	argIdx := 1

	conditions = append(conditions, fmt.Sprintf("organization_id = $%d", argIdx))
	args = append(args, orgID)
	argIdx++

	if f.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, f.Status)
		argIdx++
	}

	where := "WHERE " + strings.Join(conditions, " AND ")

	var total int
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM jobs "+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting jobs: %w", err)
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}

	query := fmt.Sprintf("SELECT %s FROM jobs %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d",
		jobColumns, where, argIdx, argIdx+1)
	args = append(args, limit, f.Offset)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("listing jobs: %w", err)
	}
	defer rows.Close()

	var jobs []models.Job
	for rows.Next() {
		var j models.Job
		if err := rows.Scan(&j.ID, &j.OrganizationID, &j.Name, &j.JobType, &j.Status, &j.TargetType, &j.TargetID, &j.ScriptID, &j.Payload, &j.ScheduledAt, &j.StartedAt, &j.CompletedAt, &j.CreatedBy, &j.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("scanning job: %w", err)
		}
		jobs = append(jobs, j)
	}
	return jobs, total, rows.Err()
}

func (s *Store) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	var extra string
	switch status {
	case "running":
		extra = ", started_at = NOW()"
	case "completed", "failed", "cancelled":
		extra = ", completed_at = NOW()"
	}
	_, err := s.pool.Exec(ctx, fmt.Sprintf("UPDATE jobs SET status = $1%s WHERE id = $2", extra), status, id)
	if err != nil {
		return fmt.Errorf("updating job status: %w", err)
	}
	return nil
}

const resultColumns = `id, job_id, device_id, status, exit_code, stdout, stderr, dispatched_at, started_at, completed_at, created_at`

func scanResult(row pgx.Row) (*models.JobResult, error) {
	var r models.JobResult
	err := row.Scan(&r.ID, &r.JobID, &r.DeviceID, &r.Status, &r.ExitCode, &r.Stdout, &r.Stderr, &r.DispatchedAt, &r.StartedAt, &r.CompletedAt, &r.CreatedAt)
	return &r, err
}

func (s *Store) CreateResult(ctx context.Context, jobID, deviceID uuid.UUID, status, stdout, stderr string, exitCode *int) (*models.JobResult, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO job_results (job_id, device_id, status, exit_code, stdout, stderr, dispatched_at)
		 VALUES ($1, $2, $3, $4, $5, $6, NOW())
		 RETURNING `+resultColumns,
		jobID, deviceID, status, exitCode, stdout, stderr,
	)
	r, err := scanResult(row)
	if err != nil {
		return nil, fmt.Errorf("creating job result: %w", err)
	}
	return r, nil
}

func (s *Store) ListResults(ctx context.Context, jobID uuid.UUID) ([]models.JobResult, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+resultColumns+` FROM job_results WHERE job_id = $1 ORDER BY created_at`, jobID)
	if err != nil {
		return nil, fmt.Errorf("listing job results: %w", err)
	}
	defer rows.Close()

	var results []models.JobResult
	for rows.Next() {
		var r models.JobResult
		if err := rows.Scan(&r.ID, &r.JobID, &r.DeviceID, &r.Status, &r.ExitCode, &r.Stdout, &r.Stderr, &r.DispatchedAt, &r.StartedAt, &r.CompletedAt, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning job result: %w", err)
		}
		results = append(results, r)
	}
	return results, rows.Err()
}
