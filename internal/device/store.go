package device

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

var ErrNotFound = errors.New("device not found")

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

const deviceColumns = `id, organization_id, site_id, device_group_id, hostname, display_name,
	os_type, os_name, os_version, os_build, arch,
	mesh_node_id, mesh_group_id,
	cpu_model, cpu_cores, total_memory_mb,
	serial_number, manufacturer, model,
	agent_id, agent_version, mesh_agent_version,
	status, last_seen_at, enrolled_at,
	tags, custom_properties, created_at, updated_at`

func scanDevice(row pgx.Row) (*models.Device, error) {
	var d models.Device
	err := row.Scan(
		&d.ID, &d.OrganizationID, &d.SiteID, &d.DeviceGroupID, &d.Hostname, &d.DisplayName,
		&d.OSType, &d.OSName, &d.OSVersion, &d.OSBuild, &d.Arch,
		&d.MeshNodeID, &d.MeshGroupID,
		&d.CPUModel, &d.CPUCores, &d.TotalMemoryMB,
		&d.SerialNumber, &d.Manufacturer, &d.Model,
		&d.AgentID, &d.AgentVersion, &d.MeshAgentVersion,
		&d.Status, &d.LastSeenAt, &d.EnrolledAt,
		&d.Tags, &d.CustomProperties, &d.CreatedAt, &d.UpdatedAt,
	)
	return &d, err
}

func scanDevices(rows pgx.Rows) ([]models.Device, error) {
	var devices []models.Device
	for rows.Next() {
		var d models.Device
		err := rows.Scan(
			&d.ID, &d.OrganizationID, &d.SiteID, &d.DeviceGroupID, &d.Hostname, &d.DisplayName,
			&d.OSType, &d.OSName, &d.OSVersion, &d.OSBuild, &d.Arch,
			&d.MeshNodeID, &d.MeshGroupID,
			&d.CPUModel, &d.CPUCores, &d.TotalMemoryMB,
			&d.SerialNumber, &d.Manufacturer, &d.Model,
			&d.AgentID, &d.AgentVersion, &d.MeshAgentVersion,
			&d.Status, &d.LastSeenAt, &d.EnrolledAt,
			&d.Tags, &d.CustomProperties, &d.CreatedAt, &d.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning device: %w", err)
		}
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

type CreateParams struct {
	OrganizationID uuid.UUID
	SiteID         uuid.UUID
	DeviceGroupID  *uuid.UUID
	Hostname       string
	DisplayName    string
	OSType         string
	AgentID        string
	MeshNodeID     string
}

func (s *Store) Create(ctx context.Context, p CreateParams) (*models.Device, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO devices (organization_id, site_id, device_group_id, hostname, display_name, os_type, agent_id, mesh_node_id, status, enrolled_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'online', now())
		 RETURNING `+deviceColumns,
		p.OrganizationID, p.SiteID, p.DeviceGroupID, p.Hostname, p.DisplayName, p.OSType, p.AgentID, p.MeshNodeID,
	)
	d, err := scanDevice(row)
	if err != nil {
		return nil, fmt.Errorf("creating device: %w", err)
	}
	return d, nil
}

func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*models.Device, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+deviceColumns+` FROM devices WHERE id = $1`, id)
	d, err := scanDevice(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting device by id: %w", err)
	}
	return d, nil
}

func (s *Store) GetByAgentID(ctx context.Context, agentID string) (*models.Device, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+deviceColumns+` FROM devices WHERE agent_id = $1`, agentID)
	d, err := scanDevice(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting device by agent_id: %w", err)
	}
	return d, nil
}

func (s *Store) GetByMeshNodeID(ctx context.Context, meshNodeID string) (*models.Device, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+deviceColumns+` FROM devices WHERE mesh_node_id = $1`, meshNodeID)
	d, err := scanDevice(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting device by mesh_node_id: %w", err)
	}
	return d, nil
}

type ListFilters struct {
	SiteID        *uuid.UUID
	DeviceGroupID *uuid.UUID
	Status        string
	OSType        string
	Search        string
	SortBy        string
	SortDir       string
	Limit         int
	Offset        int
}

func (s *Store) ListByOrganization(ctx context.Context, orgID uuid.UUID, f ListFilters) ([]models.Device, int, error) {
	var conditions []string
	var args []any
	argIdx := 1

	conditions = append(conditions, fmt.Sprintf("organization_id = $%d", argIdx))
	args = append(args, orgID)
	argIdx++

	if f.SiteID != nil {
		conditions = append(conditions, fmt.Sprintf("site_id = $%d", argIdx))
		args = append(args, *f.SiteID)
		argIdx++
	}
	if f.DeviceGroupID != nil {
		conditions = append(conditions, fmt.Sprintf("device_group_id = $%d", argIdx))
		args = append(args, *f.DeviceGroupID)
		argIdx++
	}
	if f.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, f.Status)
		argIdx++
	}
	if f.OSType != "" {
		conditions = append(conditions, fmt.Sprintf("os_type = $%d", argIdx))
		args = append(args, f.OSType)
		argIdx++
	}
	if f.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(hostname ILIKE $%d OR display_name ILIKE $%d)", argIdx, argIdx))
		args = append(args, "%"+f.Search+"%")
		argIdx++
	}

	where := "WHERE " + strings.Join(conditions, " AND ")

	// Count total
	var total int
	countQuery := "SELECT COUNT(*) FROM devices " + where
	if err := s.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting devices: %w", err)
	}

	// Sort
	sortCol := "hostname"
	switch f.SortBy {
	case "hostname", "status", "os_type", "last_seen_at", "created_at", "os_name":
		sortCol = f.SortBy
	}
	sortDir := "ASC"
	if strings.EqualFold(f.SortDir, "desc") {
		sortDir = "DESC"
	}

	// Pagination
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	query := fmt.Sprintf(
		"SELECT %s FROM devices %s ORDER BY %s %s LIMIT %d OFFSET %d",
		deviceColumns, where, sortCol, sortDir, limit, offset,
	)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("listing devices: %w", err)
	}
	defer rows.Close()

	devices, err := scanDevices(rows)
	if err != nil {
		return nil, 0, err
	}
	return devices, total, nil
}

func (s *Store) UpdateStatus(ctx context.Context, deviceID uuid.UUID, status string) error {
	result, err := s.pool.Exec(ctx,
		"UPDATE devices SET status = $1 WHERE id = $2", status, deviceID)
	if err != nil {
		return fmt.Errorf("updating device status: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) UpdateLastSeen(ctx context.Context, deviceID uuid.UUID) error {
	result, err := s.pool.Exec(ctx,
		"UPDATE devices SET last_seen_at = now(), status = 'online' WHERE id = $1", deviceID)
	if err != nil {
		return fmt.Errorf("updating device last_seen: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

type InventoryUpdate struct {
	OSName           string
	OSVersion        string
	OSBuild          string
	Arch             string
	CPUModel         string
	CPUCores         int
	TotalMemoryMB    int64
	SerialNumber     string
	Manufacturer     string
	Model            string
	AgentVersion     string
	MeshAgentVersion string
}

func (s *Store) UpdateInventory(ctx context.Context, deviceID uuid.UUID, inv InventoryUpdate) error {
	result, err := s.pool.Exec(ctx,
		`UPDATE devices SET
			os_name = $1, os_version = $2, os_build = $3, arch = $4,
			cpu_model = $5, cpu_cores = $6, total_memory_mb = $7,
			serial_number = $8, manufacturer = $9, model = $10,
			agent_version = $11, mesh_agent_version = $12
		 WHERE id = $13`,
		inv.OSName, inv.OSVersion, inv.OSBuild, inv.Arch,
		inv.CPUModel, inv.CPUCores, inv.TotalMemoryMB,
		inv.SerialNumber, inv.Manufacturer, inv.Model,
		inv.AgentVersion, inv.MeshAgentVersion, deviceID,
	)
	if err != nil {
		return fmt.Errorf("updating device inventory: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) CountByStatus(ctx context.Context, orgID *uuid.UUID) (map[string]int, error) {
	var query string
	var args []any
	if orgID != nil {
		query = `SELECT status, COUNT(*) FROM devices WHERE organization_id = $1 GROUP BY status`
		args = []any{*orgID}
	} else {
		query = `SELECT status, COUNT(*) FROM devices GROUP BY status`
	}
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("counting devices by status: %w", err)
	}
	defer rows.Close()

	counts := map[string]int{
		"pending": 0,
		"online":  0,
		"offline": 0,
		"alert":   0,
	}
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("scanning device count: %w", err)
		}
		counts[status] = count
	}
	return counts, rows.Err()
}

type UpdateMetaParams struct {
	DisplayName      *string
	DeviceGroupID    *uuid.UUID
	Tags             []string
	CustomProperties map[string]any
}

func (s *Store) UpdateMeta(ctx context.Context, id uuid.UUID, p UpdateMetaParams) (*models.Device, error) {
	d, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if p.DisplayName != nil {
		d.DisplayName = *p.DisplayName
	}
	if p.DeviceGroupID != nil {
		d.DeviceGroupID = p.DeviceGroupID
	}
	if p.Tags != nil {
		d.Tags = p.Tags
	}
	if p.CustomProperties != nil {
		d.CustomProperties = p.CustomProperties
	}

	row := s.pool.QueryRow(ctx,
		`UPDATE devices SET display_name = $1, device_group_id = $2, tags = $3, custom_properties = $4
		 WHERE id = $5
		 RETURNING `+deviceColumns,
		d.DisplayName, d.DeviceGroupID, d.Tags, d.CustomProperties, id,
	)
	return scanDevice(row)
}

func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	result, err := s.pool.Exec(ctx, "DELETE FROM devices WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("deleting device: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
