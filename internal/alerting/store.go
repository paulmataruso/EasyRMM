package alerting

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/paulmataruso/easyrm/pkg/models"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// ── Alert Rules ───────────────────────────────────────────────

const ruleColumns = `id, organization_id, name, description, metric, condition, severity, is_active, created_at, updated_at`

func scanRule(row pgx.Row) (*models.AlertRule, error) {
	var r models.AlertRule
	err := row.Scan(&r.ID, &r.OrganizationID, &r.Name, &r.Description, &r.Metric, &r.Condition, &r.Severity, &r.IsActive, &r.CreatedAt, &r.UpdatedAt)
	return &r, err
}

type CreateRuleParams struct {
	OrganizationID *uuid.UUID
	Name           string
	Description    string
	Metric         string
	Condition      map[string]any
	Severity       string
	Enabled        bool
}

func (s *Store) CreateRule(ctx context.Context, p CreateRuleParams) (*models.AlertRule, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO alert_rules (organization_id, name, description, metric, condition, severity, is_active)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING `+ruleColumns,
		p.OrganizationID, p.Name, p.Description, p.Metric, p.Condition, p.Severity, p.Enabled,
	)
	rule, err := scanRule(row)
	if err != nil {
		return nil, fmt.Errorf("creating alert rule: %w", err)
	}
	return rule, nil
}

func (s *Store) GetRuleByID(ctx context.Context, id uuid.UUID) (*models.AlertRule, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+ruleColumns+` FROM alert_rules WHERE id = $1`, id)
	rule, err := scanRule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting alert rule: %w", err)
	}
	return rule, nil
}

func (s *Store) ListRules(ctx context.Context, orgID uuid.UUID) ([]models.AlertRule, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+ruleColumns+` FROM alert_rules WHERE organization_id = $1 ORDER BY name`, orgID)
	if err != nil {
		return nil, fmt.Errorf("listing alert rules: %w", err)
	}
	defer rows.Close()

	var rules []models.AlertRule
	for rows.Next() {
		var r models.AlertRule
		if err := rows.Scan(&r.ID, &r.OrganizationID, &r.Name, &r.Description, &r.Metric, &r.Condition, &r.Severity, &r.IsActive, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning alert rule: %w", err)
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

type UpdateRuleParams struct {
	Name        *string
	Description *string
	Metric      *string
	Condition   map[string]any
	Severity    *string
	IsActive    *bool
}

func (s *Store) UpdateRule(ctx context.Context, id uuid.UUID, p UpdateRuleParams) (*models.AlertRule, error) {
	rule, err := s.GetRuleByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if p.Name != nil {
		rule.Name = *p.Name
	}
	if p.Description != nil {
		rule.Description = *p.Description
	}
	if p.Metric != nil {
		rule.Metric = *p.Metric
	}
	if p.Condition != nil {
		rule.Condition = p.Condition
	}
	if p.Severity != nil {
		rule.Severity = *p.Severity
	}
	if p.IsActive != nil {
		rule.IsActive = *p.IsActive
	}

	row := s.pool.QueryRow(ctx,
		`UPDATE alert_rules SET name=$1, description=$2, metric=$3, condition=$4, severity=$5, is_active=$6
		 WHERE id=$7
		 RETURNING `+ruleColumns,
		rule.Name, rule.Description, rule.Metric, rule.Condition, rule.Severity, rule.IsActive, id,
	)
	rule, err = scanRule(row)
	if err != nil {
		return nil, fmt.Errorf("updating alert rule: %w", err)
	}
	return rule, nil
}

func (s *Store) DeleteRule(ctx context.Context, id uuid.UUID) error {
	result, err := s.pool.Exec(ctx, `DELETE FROM alert_rules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("deleting alert rule: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Alerts ────────────────────────────────────────────────────

const alertColumns = `id, alert_rule_id, device_id, organization_id, severity, message, metric, metric_value, status, acknowledged_by, acknowledged_at, resolved_at, created_at`

func scanAlert(row pgx.Row) (*models.Alert, error) {
	var a models.Alert
	err := row.Scan(&a.ID, &a.AlertRuleID, &a.DeviceID, &a.OrganizationID, &a.Severity, &a.Message, &a.Metric, &a.MetricValue, &a.Status, &a.AcknowledgedBy, &a.AcknowledgedAt, &a.ResolvedAt, &a.CreatedAt)
	return &a, err
}

func (s *Store) CreateAlert(ctx context.Context, deviceID uuid.UUID, ruleID *uuid.UUID, orgID uuid.UUID, severity, message, metric string, value *float64) (*models.Alert, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO alerts (device_id, alert_rule_id, organization_id, severity, message, metric, metric_value)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING `+alertColumns,
		deviceID, ruleID, orgID, severity, message, metric, value,
	)
	a, err := scanAlert(row)
	if err != nil {
		return nil, fmt.Errorf("creating alert: %w", err)
	}
	return a, nil
}

type AlertListFilters struct {
	Status   string
	Severity string
	DeviceID *uuid.UUID
	Limit    int
	Offset   int
}

func (s *Store) ListAlerts(ctx context.Context, orgID uuid.UUID, f AlertListFilters) ([]models.Alert, int, error) {
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
	if f.Severity != "" {
		conditions = append(conditions, fmt.Sprintf("severity = $%d", argIdx))
		args = append(args, f.Severity)
		argIdx++
	}
	if f.DeviceID != nil {
		conditions = append(conditions, fmt.Sprintf("device_id = $%d", argIdx))
		args = append(args, *f.DeviceID)
		argIdx++
	}

	where := "WHERE " + strings.Join(conditions, " AND ")

	var total int
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM alerts "+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting alerts: %w", err)
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
		`SELECT %s FROM alerts %s ORDER BY created_at DESC LIMIT %d OFFSET %d`,
		alertColumns, where, limit, offset,
	)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("listing alerts: %w", err)
	}
	defer rows.Close()

	var alerts []models.Alert
	for rows.Next() {
		var a models.Alert
		if err := rows.Scan(&a.ID, &a.AlertRuleID, &a.DeviceID, &a.OrganizationID, &a.Severity, &a.Message, &a.Metric, &a.MetricValue, &a.Status, &a.AcknowledgedBy, &a.AcknowledgedAt, &a.ResolvedAt, &a.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("scanning alert: %w", err)
		}
		alerts = append(alerts, a)
	}
	return alerts, total, rows.Err()
}

func (s *Store) AcknowledgeAlert(ctx context.Context, alertID uuid.UUID, userID uuid.UUID) (*models.Alert, error) {
	now := time.Now()
	row := s.pool.QueryRow(ctx,
		`UPDATE alerts SET status = 'acknowledged', acknowledged_by = $1, acknowledged_at = $2
		 WHERE id = $3 AND status = 'active'
		 RETURNING `+alertColumns,
		userID, now, alertID,
	)
	a, err := scanAlert(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("acknowledging alert: %w", err)
	}
	return a, nil
}

func (s *Store) ResolveAlert(ctx context.Context, alertID uuid.UUID) (*models.Alert, error) {
	now := time.Now()
	row := s.pool.QueryRow(ctx,
		`UPDATE alerts SET status = 'resolved', resolved_at = $1
		 WHERE id = $2 AND status != 'resolved'
		 RETURNING `+alertColumns,
		now, alertID,
	)
	a, err := scanAlert(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("resolving alert: %w", err)
	}
	return a, nil
}
