package audit

import (
	"context"
	"fmt"
	"strings"

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

func (s *Store) Log(ctx context.Context, entry models.AuditLog) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO audit_logs (user_id, organization_id, device_id, action, resource_type, resource_id, details, ip_address, user_agent)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		entry.UserID, entry.OrganizationID, entry.DeviceID,
		entry.Action, entry.ResourceType, entry.ResourceID,
		entry.Details, entry.IPAddress, entry.UserAgent,
	)
	if err != nil {
		return fmt.Errorf("inserting audit log: %w", err)
	}
	return nil
}

type ListFilters struct {
	Action       string
	ResourceType string
	UserID       *uuid.UUID
	DeviceID     *uuid.UUID
	Limit        int
	Offset       int
}

func (s *Store) List(ctx context.Context, orgID uuid.UUID, f ListFilters) ([]models.AuditLog, int, error) {
	var conditions []string
	var args []any
	argIdx := 1

	conditions = append(conditions, fmt.Sprintf("organization_id = $%d", argIdx))
	args = append(args, orgID)
	argIdx++

	if f.Action != "" {
		conditions = append(conditions, fmt.Sprintf("action = $%d", argIdx))
		args = append(args, f.Action)
		argIdx++
	}
	if f.ResourceType != "" {
		conditions = append(conditions, fmt.Sprintf("resource_type = $%d", argIdx))
		args = append(args, f.ResourceType)
		argIdx++
	}
	if f.UserID != nil {
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", argIdx))
		args = append(args, *f.UserID)
		argIdx++
	}
	if f.DeviceID != nil {
		conditions = append(conditions, fmt.Sprintf("device_id = $%d", argIdx))
		args = append(args, *f.DeviceID)
		argIdx++
	}

	where := "WHERE " + strings.Join(conditions, " AND ")

	var total int
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM audit_logs "+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting audit logs: %w", err)
	}

	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	query := fmt.Sprintf(
		`SELECT id, user_id, organization_id, device_id, action, resource_type, resource_id, details, ip_address, user_agent, created_at
		 FROM audit_logs %s ORDER BY created_at DESC LIMIT %d OFFSET %d`,
		where, limit, offset,
	)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("listing audit logs: %w", err)
	}
	defer rows.Close()

	var logs []models.AuditLog
	for rows.Next() {
		var l models.AuditLog
		if err := rows.Scan(
			&l.ID, &l.UserID, &l.OrganizationID, &l.DeviceID,
			&l.Action, &l.ResourceType, &l.ResourceID,
			&l.Details, &l.IPAddress, &l.UserAgent, &l.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning audit log: %w", err)
		}
		logs = append(logs, l)
	}
	return logs, total, rows.Err()
}
