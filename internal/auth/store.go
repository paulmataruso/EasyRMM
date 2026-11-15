package auth

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/paulmataruso/easyrm/internal/config"
	"github.com/paulmataruso/easyrm/pkg/models"
)

type Store struct {
	pool *pgxpool.Pool
	cfg  config.AuthConfig
}

func NewStore(pool *pgxpool.Pool, cfg config.AuthConfig) *Store {
	return &Store{pool: pool, cfg: cfg}
}

func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

// --- Users ---

func (s *Store) CreateUser(ctx context.Context, email, username, password, displayName, role string) (*models.User, error) {
	hash, err := HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	var u models.User
	err = s.pool.QueryRow(ctx,
		`INSERT INTO users (email, username, password_hash, display_name, role)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, email, username, password_hash, display_name, role,
		           is_active, mfa_enabled, mfa_secret, failed_logins, locked_until,
		           last_login_at, created_at, updated_at`,
		email, username, hash, displayName, role,
	).Scan(
		&u.ID, &u.Email, &u.Username, &u.PasswordHash, &u.DisplayName, &u.Role,
		&u.IsActive, &u.MFAEnabled, &u.MFASecret, &u.FailedLogins, &u.LockedUntil,
		&u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting user: %w", err)
	}
	return &u, nil
}

func (s *Store) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	return s.scanUser(s.pool.QueryRow(ctx,
		`SELECT id, email, username, password_hash, display_name, role,
		        is_active, mfa_enabled, mfa_secret, failed_logins, locked_until,
		        last_login_at, created_at, updated_at
		 FROM users WHERE id = $1`, id))
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	return s.scanUser(s.pool.QueryRow(ctx,
		`SELECT id, email, username, password_hash, display_name, role,
		        is_active, mfa_enabled, mfa_secret, failed_logins, locked_until,
		        last_login_at, created_at, updated_at
		 FROM users WHERE username = $1`, username))
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	return s.scanUser(s.pool.QueryRow(ctx,
		`SELECT id, email, username, password_hash, display_name, role,
		        is_active, mfa_enabled, mfa_secret, failed_logins, locked_until,
		        last_login_at, created_at, updated_at
		 FROM users WHERE email = $1`, email))
}

func (s *Store) scanUser(row pgx.Row) (*models.User, error) {
	var u models.User
	err := row.Scan(
		&u.ID, &u.Email, &u.Username, &u.PasswordHash, &u.DisplayName, &u.Role,
		&u.IsActive, &u.MFAEnabled, &u.MFASecret, &u.FailedLogins, &u.LockedUntil,
		&u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) ListUsers(ctx context.Context) ([]models.User, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, email, username, password_hash, display_name, role,
		        is_active, mfa_enabled, mfa_secret, failed_logins, locked_until,
		        last_login_at, created_at, updated_at
		 FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(
			&u.ID, &u.Email, &u.Username, &u.PasswordHash, &u.DisplayName, &u.Role,
			&u.IsActive, &u.MFAEnabled, &u.MFASecret, &u.FailedLogins, &u.LockedUntil,
			&u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

type UserUpdate struct {
	Email       *string `json:"email,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
	Role        *string `json:"role,omitempty"`
	IsActive    *bool   `json:"is_active,omitempty"`
}

func (s *Store) UpdateUser(ctx context.Context, id uuid.UUID, u UserUpdate) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET
			email        = COALESCE($2, email),
			display_name = COALESCE($3, display_name),
			role         = COALESCE($4, role),
			is_active    = COALESCE($5, is_active)
		 WHERE id = $1`,
		id, u.Email, u.DisplayName, u.Role, u.IsActive,
	)
	return err
}

func (s *Store) DeleteUser(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	return err
}

func (s *Store) IncrementFailedLogins(ctx context.Context, id uuid.UUID) error {
	var failedLogins int
	err := s.pool.QueryRow(ctx,
		`UPDATE users SET failed_logins = failed_logins + 1
		 WHERE id = $1
		 RETURNING failed_logins`, id,
	).Scan(&failedLogins)
	if err != nil {
		return err
	}

	if failedLogins >= s.cfg.MaxFailedLogins {
		idx := failedLogins - s.cfg.MaxFailedLogins
		if idx >= len(s.cfg.LockoutDurations) {
			idx = len(s.cfg.LockoutDurations) - 1
		}
		lockUntil := time.Now().Add(s.cfg.LockoutDurations[idx])
		_, err = s.pool.Exec(ctx,
			`UPDATE users SET locked_until = $2 WHERE id = $1`, id, lockUntil)
		if err != nil {
			return err
		}
		slog.Warn("account locked", "user_id", id, "locked_until", lockUntil)
	}
	return nil
}

func (s *Store) ResetFailedLogins(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1`, id)
	return err
}

func (s *Store) SetMFASecret(ctx context.Context, id uuid.UUID, secret string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET mfa_secret = $2, mfa_enabled = true WHERE id = $1`, id, secret)
	return err
}

func (s *Store) DisableMFA(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET mfa_secret = NULL, mfa_enabled = false WHERE id = $1`, id)
	return err
}

func (s *Store) UpdatePassword(ctx context.Context, id uuid.UUID, newHash string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET password_hash = $2 WHERE id = $1`, id, newHash)
	return err
}

func (s *Store) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET last_login_at = now() WHERE id = $1`, id)
	return err
}

// --- Sessions ---

func (s *Store) CreateSession(ctx context.Context, userID uuid.UUID, tokenHash, ip, userAgent string, duration time.Duration) (*models.Session, error) {
	var sess models.Session
	err := s.pool.QueryRow(ctx,
		`INSERT INTO sessions (user_id, token_hash, ip_address, user_agent, expires_at)
		 VALUES ($1, $2, $3::inet, $4, $5)
		 RETURNING id, user_id, token_hash, ip_address, user_agent, expires_at, created_at`,
		userID, tokenHash, ip, userAgent, time.Now().Add(duration),
	).Scan(&sess.ID, &sess.UserID, &sess.TokenHash, &sess.IPAddress, &sess.UserAgent, &sess.ExpiresAt, &sess.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *Store) GetSessionByToken(ctx context.Context, tokenHash string) (*models.Session, error) {
	var sess models.Session
	err := s.pool.QueryRow(ctx,
		`SELECT id, user_id, token_hash, ip_address, user_agent, expires_at, created_at
		 FROM sessions WHERE token_hash = $1 AND expires_at > now()`, tokenHash,
	).Scan(&sess.ID, &sess.UserID, &sess.TokenHash, &sess.IPAddress, &sess.UserAgent, &sess.ExpiresAt, &sess.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *Store) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, sessionID)
	return err
}

func (s *Store) DeleteUserSessions(ctx context.Context, userID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	return err
}

func (s *Store) CleanExpiredSessions(ctx context.Context) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= now()`)
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		slog.Info("cleaned expired sessions", "count", tag.RowsAffected())
	}
	return nil
}

// --- User Organization Access ---

func (s *Store) GrantOrganizationAccess(ctx context.Context, userID, orgID uuid.UUID, role string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO user_organization_access (user_id, organization_id, role)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (user_id, organization_id) DO UPDATE SET role = $3`,
		userID, orgID, role,
	)
	return err
}

func (s *Store) RevokeOrganizationAccess(ctx context.Context, userID, orgID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM user_organization_access WHERE user_id = $1 AND organization_id = $2`,
		userID, orgID)
	return err
}

func (s *Store) GetUserOrganizations(ctx context.Context, userID uuid.UUID) ([]models.UserOrganizationAccess, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, organization_id, role, created_at
		 FROM user_organization_access WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var access []models.UserOrganizationAccess
	for rows.Next() {
		var a models.UserOrganizationAccess
		if err := rows.Scan(&a.ID, &a.UserID, &a.OrganizationID, &a.Role, &a.CreatedAt); err != nil {
			return nil, err
		}
		access = append(access, a)
	}
	return access, rows.Err()
}

func (s *Store) HasOrganizationAccess(ctx context.Context, userID, orgID uuid.UUID) (bool, string, error) {
	var role string
	err := s.pool.QueryRow(ctx,
		`SELECT role FROM user_organization_access
		 WHERE user_id = $1 AND organization_id = $2`, userID, orgID,
	).Scan(&role)
	if err == pgx.ErrNoRows {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	return true, role, nil
}

// --- Audit ---

func (s *Store) CreateAuditLog(ctx context.Context, log models.AuditLog) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO audit_logs (user_id, organization_id, device_id, action, resource_type, resource_id, details, ip_address, user_agent)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::inet, $9)`,
		log.UserID, log.OrganizationID, log.DeviceID, log.Action, log.ResourceType,
		log.ResourceID, log.Details, nilIfEmpty(log.IPAddress), log.UserAgent,
	)
	return err
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
