// Package auth implements interactive authentication: password login,
// TOTP multi-factor authentication, recovery codes, sessions, password
// changes and password resets.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
)

// SessionState tracks how far a session has progressed through sign-in.
type SessionState string

const (
	// StateMFARequired: password accepted, second factor not yet verified.
	StateMFARequired SessionState = "mfa_required"
	// StateMFAEnrollment: password accepted, the user must set up MFA
	// before doing anything else.
	StateMFAEnrollment SessionState = "mfa_enrollment"
	// StateActive: fully signed in.
	StateActive SessionState = "active"
)

// Errors returned to handlers. Messages are deliberately generic so they do
// not reveal whether an account exists or why exactly sign-in failed.
var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrRateLimited        = errors.New("too many attempts, try again later")
	ErrInvalidSession     = errors.New("session is invalid or expired")
	ErrInvalidCode        = errors.New("invalid verification code")
	ErrWrongState         = errors.New("session is not in the required state")
	ErrInvalidResetToken  = errors.New("password reset link is invalid or expired")
	ErrResetUnavailable   = errors.New("self-service password reset is not configured")
)

// Config holds authentication policy.
type Config struct {
	IdleTimeout      time.Duration
	MaxSessionAge    time.Duration
	RequireMFA       bool
	Issuer           string // shown in authenticator apps
	PasswordResetTTL time.Duration
	PublicURL        string // used to build password reset links
	// Lockout policy: after LockoutThreshold consecutive failures the
	// account is locked for LockoutBase, doubling per further failure up to
	// LockoutMax.
	LockoutThreshold int
	LockoutBase      time.Duration
	LockoutMax       time.Duration
	MaxMFAFailures   int
}

// DefaultConfig is the secure default policy.
func DefaultConfig() Config {
	return Config{
		IdleTimeout:      2 * time.Hour,
		MaxSessionAge:    12 * time.Hour,
		RequireMFA:       true,
		Issuer:           "EasyRMM",
		PasswordResetTTL: 30 * time.Minute,
		LockoutThreshold: 5,
		LockoutBase:      time.Minute,
		LockoutMax:       30 * time.Minute,
		MaxMFAFailures:   5,
	}
}

// Mailer sends plain-text e-mail. When nil, self-service password reset is
// disabled and administrators issue reset links instead.
type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}

// RequestMeta describes the client making a request.
type RequestMeta struct {
	IP        netip.Addr
	UserAgent string
}

// User is the authenticated user's account summary.
type User struct {
	ID          uuid.UUID `json:"id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"displayName"`
	Status      string    `json:"status"`
	MFAEnabled  bool      `json:"mfaEnabled"`
}

// Session is a sign-in session.
type Session struct {
	ID            uuid.UUID    `json:"id"`
	UserID        uuid.UUID    `json:"-"`
	State         SessionState `json:"state"`
	CreatedAt     time.Time    `json:"createdAt"`
	LastSeenAt    time.Time    `json:"lastSeenAt"`
	ExpiresAt     time.Time    `json:"expiresAt"`
	IdleExpiresAt time.Time    `json:"idleExpiresAt"`
	SourceIP      *netip.Addr  `json:"sourceIp,omitempty"`
	UserAgent     string       `json:"userAgent"`
}

// Service is the authentication service.
type Service struct {
	db       *database.DB
	audit    *audit.Logger
	hasher   *Hasher
	sealer   *secrets.Sealer
	mailer   Mailer
	cfg      Config
	now      func() time.Time
	ipLimit  *KeyedLimiter
	mfaLimit *KeyedLimiter
}

// NewService builds the service.
func NewService(db *database.DB, auditLog *audit.Logger, hasher *Hasher, sealer *secrets.Sealer, mailer Mailer, cfg Config) *Service {
	return &Service{
		db: db, audit: auditLog, hasher: hasher, sealer: sealer, mailer: mailer, cfg: cfg, now: time.Now,
		// 10 attempts at once, then one every 6 seconds, per client address.
		ipLimit:  NewKeyedLimiter(6*time.Second, 10, 100_000),
		mfaLimit: NewKeyedLimiter(6*time.Second, 10, 100_000),
	}
}

// SetClock replaces the time source (tests only).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Config returns the active policy.
func (s *Service) Config() Config { return s.cfg }

// ResetAvailable reports whether self-service password reset can send mail.
func (s *Service) ResetAvailable() bool { return s.mailer != nil }

// NewToken returns 256 bits of randomness encoded for use in a cookie or
// URL, and its SHA-256 hash for storage.
func NewToken() (token string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("auth: generating token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, HashToken(token), nil
}

// HashToken hashes a bearer token for storage and lookup. Tokens have full
// entropy, so a single SHA-256 is appropriate.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func normaliseEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

func userActor(id uuid.UUID, label string, meta RequestMeta) audit.Actor {
	return audit.Actor{Type: audit.ActorUser, ID: id, Label: label, SourceIP: meta.IP, UserAgent: meta.UserAgent}
}

func anonymousActor(label string, meta RequestMeta) audit.Actor {
	return audit.Actor{Type: audit.ActorUser, Label: label, SourceIP: meta.IP, UserAgent: meta.UserAgent}
}

// Login verifies an e-mail address and password and opens a session. The
// session is fully active only when no second factor is required.
func (s *Service) Login(ctx context.Context, email, password string, meta RequestMeta) (string, *Session, error) {
	email = normaliseEmail(email)
	if meta.IP.IsValid() && !s.ipLimit.Allow("login:"+meta.IP.String()) {
		_ = s.audit.Record(ctx, audit.Event{Actor: anonymousActor(email, meta), Action: "auth.login", Outcome: audit.Denied, Details: map[string]any{"reason": "rate_limited"}})
		return "", nil, ErrRateLimited
	}
	if len(password) > MaxPasswordLength*4 || len(email) > 254 {
		return "", nil, ErrInvalidCredentials
	}

	var token string
	var sess *Session
	var failure string
	var userID uuid.UUID
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var (
			hash, status string
			pwHash       *string
			totpEnabled  *time.Time
			failed       int
			lockedUntil  *time.Time
		)
		err := tx.QueryRow(ctx, `SELECT id, password_hash, status, totp_enabled_at, failed_logins, locked_until
			FROM users WHERE email = $1 FOR UPDATE`, email).
			Scan(&userID, &pwHash, &status, &totpEnabled, &failed, &lockedUntil)
		if errors.Is(err, pgx.ErrNoRows) {
			s.hasher.DummyVerify(ctx, password)
			failure = "unknown_account"
			return nil
		}
		if err != nil {
			return err
		}
		now := s.now()
		if lockedUntil != nil && now.Before(*lockedUntil) {
			s.hasher.DummyVerify(ctx, password)
			failure = "locked"
			return nil
		}
		if pwHash == nil {
			s.hasher.DummyVerify(ctx, password)
			failure = "no_password"
			return nil
		}
		hash = *pwHash
		ok, rehash, err := s.hasher.Verify(ctx, password, hash)
		if err != nil {
			return err
		}
		if !ok {
			failure = "bad_password"
			failed++
			var lock *time.Time
			if failed >= s.cfg.LockoutThreshold {
				d := s.cfg.LockoutBase << min(failed-s.cfg.LockoutThreshold, 16)
				if d > s.cfg.LockoutMax || d <= 0 {
					d = s.cfg.LockoutMax
				}
				until := now.Add(d)
				lock = &until
			}
			_, err := tx.Exec(ctx, `UPDATE users SET failed_logins = $2, locked_until = $3 WHERE id = $1`, userID, failed, lock)
			return err
		}
		if status != "active" {
			failure = "disabled"
			return nil
		}
		if rehash {
			if newHash, err := s.hasher.Hash(ctx, password); err == nil {
				if _, err := tx.Exec(ctx, `UPDATE users SET password_hash = $2 WHERE id = $1`, userID, newHash); err != nil {
					return err
				}
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1`, userID); err != nil {
			return err
		}
		state := StateActive
		switch {
		case totpEnabled != nil:
			state = StateMFARequired
		case s.cfg.RequireMFA:
			state = StateMFAEnrollment
		}
		token, sess, err = s.createSession(ctx, tx, userID, state, meta)
		if err != nil {
			return err
		}
		if state == StateActive {
			if _, err := tx.Exec(ctx, `UPDATE users SET last_login_at = now() WHERE id = $1`, userID); err != nil {
				return err
			}
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: userActor(userID, email, meta), Action: "auth.login", Outcome: audit.Success,
			TargetType: "session", TargetID: sess.ID.String(), Details: map[string]any{"state": string(state)},
		})
	})
	if err != nil {
		return "", nil, fmt.Errorf("auth: login: %w", err)
	}
	if failure != "" {
		actor := anonymousActor(email, meta)
		if userID != uuid.Nil {
			actor = userActor(userID, email, meta)
		}
		_ = s.audit.Record(ctx, audit.Event{Actor: actor, Action: "auth.login", Outcome: audit.Failure, Details: map[string]any{"reason": failure}})
		return "", nil, ErrInvalidCredentials
	}
	return token, sess, nil
}

func (s *Service) createSession(ctx context.Context, tx pgx.Tx, userID uuid.UUID, state SessionState, meta RequestMeta) (string, *Session, error) {
	token, hash, err := NewToken()
	if err != nil {
		return "", nil, err
	}
	now := s.now()
	sess := &Session{
		UserID: userID, State: state, CreatedAt: now, LastSeenAt: now,
		ExpiresAt: now.Add(s.cfg.MaxSessionAge), IdleExpiresAt: minTime(now.Add(s.cfg.IdleTimeout), now.Add(s.cfg.MaxSessionAge)),
		UserAgent: truncateString(meta.UserAgent, 512),
	}
	if state != StateActive {
		// Half-finished sign-ins expire quickly.
		sess.IdleExpiresAt = now.Add(10 * time.Minute)
		sess.ExpiresAt = sess.IdleExpiresAt
	}
	if meta.IP.IsValid() {
		ip := meta.IP.Unmap()
		sess.SourceIP = &ip
	}
	err = tx.QueryRow(ctx, `INSERT INTO sessions (token_hash, user_id, state, created_at, last_seen_at, idle_expires_at, expires_at, source_ip, user_agent)
		VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8) RETURNING id`,
		hash, userID, string(state), now, sess.IdleExpiresAt, sess.ExpiresAt, sess.SourceIP, sess.UserAgent).Scan(&sess.ID)
	if err != nil {
		return "", nil, fmt.Errorf("auth: creating session: %w", err)
	}
	return token, sess, nil
}

// Authenticate resolves a session token. Active sessions have their idle
// deadline extended (at most once a minute, to limit write load).
func (s *Service) Authenticate(ctx context.Context, token string) (*Session, *User, error) {
	if token == "" || len(token) > 128 {
		return nil, nil, ErrInvalidSession
	}
	hash := HashToken(token)
	var sess Session
	var user User
	var state string
	var totpEnabled *time.Time
	var revokedAt *time.Time
	now := s.now()
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			SELECT s.id, s.user_id, s.state, s.created_at, s.last_seen_at, s.expires_at, s.idle_expires_at,
			       s.revoked_at, s.source_ip, s.user_agent,
			       u.email, u.display_name, u.status, u.totp_enabled_at
			FROM sessions s JOIN users u ON u.id = s.user_id
			WHERE s.token_hash = $1`, hash).
			Scan(&sess.ID, &sess.UserID, &state, &sess.CreatedAt, &sess.LastSeenAt, &sess.ExpiresAt, &sess.IdleExpiresAt,
				&revokedAt, &sess.SourceIP, &sess.UserAgent, &user.Email, &user.DisplayName, &user.Status, &totpEnabled)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidSession
		}
		if err != nil {
			return err
		}
		if revokedAt != nil || !now.Before(sess.ExpiresAt) || !now.Before(sess.IdleExpiresAt) || user.Status != "active" {
			return ErrInvalidSession
		}
		if state == string(StateActive) && now.Sub(sess.LastSeenAt) >= time.Minute {
			sess.LastSeenAt = now
			sess.IdleExpiresAt = minTime(now.Add(s.cfg.IdleTimeout), sess.ExpiresAt)
			_, err = tx.Exec(ctx, `UPDATE sessions SET last_seen_at = $2, idle_expires_at = $3 WHERE id = $1`, sess.ID, now, sess.IdleExpiresAt)
			return err
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrInvalidSession) {
			return nil, nil, ErrInvalidSession
		}
		return nil, nil, fmt.Errorf("auth: authenticating: %w", err)
	}
	sess.State = SessionState(state)
	user.ID = sess.UserID
	user.MFAEnabled = totpEnabled != nil
	return &sess, &user, nil
}

// rotate replaces a session's token (after a privilege change, to defeat
// session fixation) and optionally changes its state.
func (s *Service) rotate(ctx context.Context, tx pgx.Tx, sessionID uuid.UUID, state SessionState) (string, error) {
	token, hash, err := NewToken()
	if err != nil {
		return "", err
	}
	now := s.now()
	idle := minTime(now.Add(s.cfg.IdleTimeout), now.Add(s.cfg.MaxSessionAge))
	_, err = tx.Exec(ctx, `UPDATE sessions SET token_hash = $2, state = $3, mfa_failures = 0,
		last_seen_at = $4, idle_expires_at = $5, expires_at = $6 WHERE id = $1`,
		sessionID, hash, string(state), now, idle, now.Add(s.cfg.MaxSessionAge))
	if err != nil {
		return "", fmt.Errorf("auth: rotating session: %w", err)
	}
	return token, nil
}

// VerifyMFA completes sign-in with a TOTP code or a recovery code. It returns
// a new session token; the old one stops working.
func (s *Service) VerifyMFA(ctx context.Context, sess *Session, user *User, code string, meta RequestMeta) (string, error) {
	if sess.State != StateMFARequired {
		return "", ErrWrongState
	}
	if !s.mfaLimit.Allow("mfa:" + sess.UserID.String()) {
		return "", ErrRateLimited
	}
	var token string
	var verifyErr error
	method := "totp"
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var sealed *string
		var lastStep *int64
		if err := tx.QueryRow(ctx, `SELECT totp_secret_sealed, totp_last_step FROM users WHERE id = $1 FOR UPDATE`, sess.UserID).Scan(&sealed, &lastStep); err != nil {
			return err
		}
		ok := false
		if LooksLikeRecoveryCode(code) {
			method = "recovery_code"
			tag, err := tx.Exec(ctx, `UPDATE user_recovery_codes SET used_at = now()
				WHERE id = (SELECT id FROM user_recovery_codes WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL LIMIT 1)`,
				sess.UserID, HashRecoveryCode(code))
			if err != nil {
				return err
			}
			ok = tag.RowsAffected() == 1
		} else if sealed != nil {
			secret, err := s.sealer.Open(*sealed, totpAAD(sess.UserID))
			if err != nil {
				return fmt.Errorf("auth: opening totp secret: %w", err)
			}
			last := int64(-1)
			if lastStep != nil {
				last = *lastStep
			}
			step, valid := VerifyTOTP(string(secret), code, s.now(), last)
			if valid {
				ok = true
				if _, err := tx.Exec(ctx, `UPDATE users SET totp_last_step = $2 WHERE id = $1`, sess.UserID, step); err != nil {
					return err
				}
			}
		}
		if !ok {
			var failures int
			if err := tx.QueryRow(ctx, `UPDATE sessions SET mfa_failures = mfa_failures + 1 WHERE id = $1 RETURNING mfa_failures`, sess.ID).Scan(&failures); err != nil {
				return err
			}
			if failures >= s.cfg.MaxMFAFailures {
				if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = now(), revoked_reason = 'mfa_failures' WHERE id = $1`, sess.ID); err != nil {
					return err
				}
			}
			verifyErr = ErrInvalidCode
			return s.audit.Write(ctx, tx, audit.Event{Actor: userActor(sess.UserID, user.Email, meta), Action: "auth.mfa_verify", Outcome: audit.Failure,
				TargetType: "session", TargetID: sess.ID.String(), Details: map[string]any{"method": method, "failures": failures}})
		}
		var err error
		token, err = s.rotate(ctx, tx, sess.ID, StateActive)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET last_login_at = now() WHERE id = $1`, sess.UserID); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: userActor(sess.UserID, user.Email, meta), Action: "auth.mfa_verify", Outcome: audit.Success,
			TargetType: "session", TargetID: sess.ID.String(), Details: map[string]any{"method": method}})
	})
	if err != nil {
		return "", fmt.Errorf("auth: verifying mfa: %w", err)
	}
	if verifyErr != nil {
		return "", verifyErr
	}
	return token, nil
}

// canEnrollTOTP allows TOTP set-up while enrolling at sign-in, or from an
// active session for a user who has no TOTP configured yet.
func canEnrollTOTP(sess *Session, user *User) bool {
	return sess.State == StateMFAEnrollment || (sess.State == StateActive && !user.MFAEnabled)
}

func totpAAD(userID uuid.UUID) []byte { return []byte("user-totp:" + userID.String()) }

// TOTPEnrollment is what the user needs to configure an authenticator app.
type TOTPEnrollment struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

// BeginTOTPEnrollment generates a new pending TOTP secret. It is allowed
// while enrolling at sign-in, or from an active session for a user who has
// no TOTP configured yet.
func (s *Service) BeginTOTPEnrollment(ctx context.Context, sess *Session, user *User) (*TOTPEnrollment, error) {
	if !canEnrollTOTP(sess, user) {
		return nil, ErrWrongState
	}
	secret, err := NewTOTPSecret()
	if err != nil {
		return nil, err
	}
	sealed, err := s.sealer.Seal([]byte(secret), totpAAD(sess.UserID))
	if err != nil {
		return nil, err
	}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE users SET totp_secret_sealed = $2, totp_last_step = NULL
			WHERE id = $1 AND totp_enabled_at IS NULL`, sess.UserID, sealed)
		if err == nil && tag.RowsAffected() != 1 {
			return ErrWrongState
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return &TOTPEnrollment{Secret: secret, URI: TOTPURI(s.cfg.Issuer, user.Email, secret)}, nil
}

// ConfirmTOTPEnrollment activates the pending secret once the user proves
// their app produces correct codes. It returns one-time recovery codes and,
// when this completes sign-in, a rotated session token.
func (s *Service) ConfirmTOTPEnrollment(ctx context.Context, sess *Session, user *User, code string, meta RequestMeta) (codes []string, newToken string, err error) {
	if !canEnrollTOTP(sess, user) {
		return nil, "", ErrWrongState
	}
	if !s.mfaLimit.Allow("mfa:" + sess.UserID.String()) {
		return nil, "", ErrRateLimited
	}
	codes, err = NewRecoveryCodes()
	if err != nil {
		return nil, "", err
	}
	var bad bool
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var sealed *string
		var enabled *time.Time
		if err := tx.QueryRow(ctx, `SELECT totp_secret_sealed, totp_enabled_at FROM users WHERE id = $1 FOR UPDATE`, sess.UserID).Scan(&sealed, &enabled); err != nil {
			return err
		}
		if sealed == nil || enabled != nil {
			return ErrWrongState
		}
		secret, err := s.sealer.Open(*sealed, totpAAD(sess.UserID))
		if err != nil {
			return err
		}
		step, ok := VerifyTOTP(string(secret), code, s.now(), -1)
		if !ok {
			bad = true
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET totp_enabled_at = now(), totp_last_step = $2 WHERE id = $1`, sess.UserID, step); err != nil {
			return err
		}
		if err := replaceRecoveryCodes(ctx, tx, sess.UserID, codes); err != nil {
			return err
		}
		if sess.State == StateMFAEnrollment {
			if newToken, err = s.rotate(ctx, tx, sess.ID, StateActive); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE users SET last_login_at = now() WHERE id = $1`, sess.UserID); err != nil {
				return err
			}
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: userActor(sess.UserID, user.Email, meta), Action: "auth.mfa_enroll",
			Outcome: audit.Success, TargetType: "user", TargetID: sess.UserID.String(), Details: map[string]any{"method": "totp"}})
	})
	if err != nil {
		return nil, "", err
	}
	if bad {
		return nil, "", ErrInvalidCode
	}
	return codes, newToken, nil
}

func replaceRecoveryCodes(ctx context.Context, tx pgx.Tx, userID uuid.UUID, codes []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM user_recovery_codes WHERE user_id = $1`, userID); err != nil {
		return err
	}
	for _, c := range codes {
		if _, err := tx.Exec(ctx, `INSERT INTO user_recovery_codes (user_id, code_hash) VALUES ($1, $2)`, userID, HashRecoveryCode(c)); err != nil {
			return err
		}
	}
	return nil
}

// RegenerateRecoveryCodes replaces a user's recovery codes after confirming
// their password.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, sess *Session, user *User, password string, meta RequestMeta) ([]string, error) {
	if sess.State != StateActive || !user.MFAEnabled {
		return nil, ErrWrongState
	}
	if err := s.confirmPassword(ctx, sess.UserID, password); err != nil {
		return nil, err
	}
	codes, err := NewRecoveryCodes()
	if err != nil {
		return nil, err
	}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if err := replaceRecoveryCodes(ctx, tx, sess.UserID, codes); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: userActor(sess.UserID, user.Email, meta), Action: "auth.recovery_codes_regenerate",
			Outcome: audit.Success, TargetType: "user", TargetID: sess.UserID.String()})
	})
	return codes, err
}

func (s *Service) confirmPassword(ctx context.Context, userID uuid.UUID, password string) error {
	var hash *string
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT password_hash FROM users WHERE id = $1`, userID).Scan(&hash)
	})
	if err != nil {
		return err
	}
	if hash == nil {
		return ErrInvalidCredentials
	}
	ok, _, err := s.hasher.Verify(ctx, password, *hash)
	if err != nil {
		return err
	}
	if !ok {
		return ErrInvalidCredentials
	}
	return nil
}

// Logout revokes the current session.
func (s *Service) Logout(ctx context.Context, sess *Session, user *User, meta RequestMeta) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = now(), revoked_reason = 'logout' WHERE id = $1 AND revoked_at IS NULL`, sess.ID); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: userActor(sess.UserID, user.Email, meta), Action: "auth.logout",
			Outcome: audit.Success, TargetType: "session", TargetID: sess.ID.String()})
	})
}

// ListSessions returns a user's live sessions.
func (s *Service) ListSessions(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	var out []Session
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, state, created_at, last_seen_at, expires_at, idle_expires_at, source_ip, user_agent
			FROM sessions WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2 AND idle_expires_at > $2
			ORDER BY last_seen_at DESC`, userID, s.now())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var x Session
			var state string
			if err := rows.Scan(&x.ID, &state, &x.CreatedAt, &x.LastSeenAt, &x.ExpiresAt, &x.IdleExpiresAt, &x.SourceIP, &x.UserAgent); err != nil {
				return err
			}
			x.State, x.UserID = SessionState(state), userID
			out = append(out, x)
		}
		return rows.Err()
	})
	return out, err
}

// RevokeSession ends one of a user's sessions.
func (s *Service) RevokeSession(ctx context.Context, actor audit.Actor, userID, sessionID uuid.UUID) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = now(), revoked_reason = 'revoked' WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`, sessionID, userID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrInvalidSession
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: actor, Action: "auth.session_revoke", Outcome: audit.Success, TargetType: "session", TargetID: sessionID.String()})
	})
}

// RevokeAllSessions ends every session of a user, except one if given. It
// must be called inside the transaction that caused it (password change,
// account disable, role removal).
func RevokeAllSessions(ctx context.Context, tx pgx.Tx, userID, except uuid.UUID, reason string) error {
	_, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = now(), revoked_reason = $3
		WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL`, userID, except, reason)
	return err
}

// ChangePassword changes the signed-in user's password and signs out their
// other sessions.
func (s *Service) ChangePassword(ctx context.Context, sess *Session, user *User, current, next string, meta RequestMeta) error {
	if sess.State != StateActive {
		return ErrWrongState
	}
	if err := ValidatePassword(next, user.Email, user.DisplayName, strings.Split(user.Email, "@")[0]); err != nil {
		return err
	}
	if err := s.confirmPassword(ctx, sess.UserID, current); err != nil {
		_ = s.audit.Record(ctx, audit.Event{Actor: userActor(sess.UserID, user.Email, meta), Action: "auth.password_change", Outcome: audit.Failure})
		return err
	}
	hash, err := s.hasher.Hash(ctx, next)
	if err != nil {
		return err
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE users SET password_hash = $2, password_changed_at = now() WHERE id = $1`, sess.UserID, hash); err != nil {
			return err
		}
		if err := RevokeAllSessions(ctx, tx, sess.UserID, sess.ID, "password_change"); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: userActor(sess.UserID, user.Email, meta), Action: "auth.password_change",
			Outcome: audit.Success, TargetType: "user", TargetID: sess.UserID.String()})
	})
}

// IssueResetToken creates a password reset token for a user inside tx and
// returns the link to deliver. Used by self-service reset and by
// administrators helping a user who cannot sign in.
func (s *Service) IssueResetToken(ctx context.Context, tx pgx.Tx, userID uuid.UUID, meta RequestMeta) (string, error) {
	token, hash, err := NewToken()
	if err != nil {
		return "", err
	}
	// Only the newest link works.
	if _, err := tx.Exec(ctx, `DELETE FROM password_reset_tokens WHERE user_id = $1`, userID); err != nil {
		return "", err
	}
	var ip *netip.Addr
	if meta.IP.IsValid() {
		a := meta.IP.Unmap()
		ip = &a
	}
	if _, err := tx.Exec(ctx, `INSERT INTO password_reset_tokens (token_hash, user_id, expires_at, source_ip) VALUES ($1, $2, $3, $4)`,
		hash, userID, s.now().Add(s.cfg.PasswordResetTTL), ip); err != nil {
		return "", err
	}
	// The token travels in the URL fragment so it never reaches server or
	// proxy access logs.
	return strings.TrimRight(s.cfg.PublicURL, "/") + "/reset-password#token=" + token, nil
}

// RequestPasswordReset e-mails a reset link if the address belongs to an
// active account. It always appears to succeed.
func (s *Service) RequestPasswordReset(ctx context.Context, email string, meta RequestMeta) error {
	if s.mailer == nil {
		return ErrResetUnavailable
	}
	email = normaliseEmail(email)
	if meta.IP.IsValid() && !s.ipLimit.Allow("reset:"+meta.IP.String()) {
		return ErrRateLimited
	}
	var link string
	var userID uuid.UUID
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT id FROM users WHERE email = $1 AND status = 'active'`, email).Scan(&userID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		link, err = s.IssueResetToken(ctx, tx, userID, meta)
		if err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: userActor(userID, email, meta), Action: "auth.password_reset_request", Outcome: audit.Success,
			TargetType: "user", TargetID: userID.String()})
	})
	if err != nil || link == "" {
		return err
	}
	body := "A password reset was requested for your EasyRMM account.\n\n" +
		"Open this link within " + s.cfg.PasswordResetTTL.String() + " to choose a new password:\n\n" + link + "\n\n" +
		"If you did not request this, you can ignore this message. Your password has not changed.\n"
	// Send outside the transaction; a mail failure should not reveal anything
	// to the requester.
	return s.mailer.Send(context.WithoutCancel(ctx), email, "Reset your EasyRMM password", body)
}

// CompletePasswordReset sets a new password using a reset token. All of the
// user's sessions are revoked and any lockout is cleared. MFA is still
// required at the next sign-in.
func (s *Service) CompletePasswordReset(ctx context.Context, token, next string, meta RequestMeta) error {
	if meta.IP.IsValid() && !s.ipLimit.Allow("reset:"+meta.IP.String()) {
		return ErrRateLimited
	}
	if token == "" || len(token) > 128 {
		return ErrInvalidResetToken
	}
	var userID uuid.UUID
	var email, name string
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT u.id, u.email, u.display_name FROM password_reset_tokens t JOIN users u ON u.id = t.user_id
			WHERE t.token_hash = $1 AND t.used_at IS NULL AND t.expires_at > $2 AND u.status = 'active'`, HashToken(token), s.now()).
			Scan(&userID, &email, &name)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalidResetToken
	}
	if err != nil {
		return err
	}
	if err := ValidatePassword(next, email, name, strings.Split(email, "@")[0]); err != nil {
		return err
	}
	hash, err := s.hasher.Hash(ctx, next)
	if err != nil {
		return err
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE password_reset_tokens SET used_at = now() WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2`, HashToken(token), s.now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrInvalidResetToken // used concurrently
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET password_hash = $2, password_changed_at = now(), failed_logins = 0, locked_until = NULL WHERE id = $1`, userID, hash); err != nil {
			return err
		}
		if err := RevokeAllSessions(ctx, tx, userID, uuid.Nil, "password_reset"); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: userActor(userID, email, meta), Action: "auth.password_reset", Outcome: audit.Success,
			TargetType: "user", TargetID: userID.String()})
	})
}

// LoadPrincipal resolves a user's role assignments into a Principal.
func (s *Service) LoadPrincipal(ctx context.Context, userID uuid.UUID) (*rbac.Principal, error) {
	var as []rbac.Assignment
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT role, organization_id, site_id FROM role_assignments WHERE user_id = $1`, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var role string
			var org, site *uuid.UUID
			if err := rows.Scan(&role, &org, &site); err != nil {
				return err
			}
			a := rbac.Assignment{Role: rbac.Role(role)}
			if org != nil {
				a.OrganizationID = *org
			}
			if site != nil {
				a.SiteID = *site
			}
			as = append(as, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("auth: loading roles: %w", err)
	}
	return rbac.NewPrincipal(userID, as)
}

// DataScope converts a principal into the database scope that bounds every
// query made on its behalf.
func DataScope(p *rbac.Principal) database.Scope {
	if p == nil {
		return database.Scope{}
	}
	if p.IsSuperAdmin() {
		return database.Scope{All: true}
	}
	var s database.Scope
	orgs := map[uuid.UUID]bool{}
	for _, a := range p.Assignments {
		if a.Kind() == rbac.ScopeOrganization && !orgs[a.OrganizationID] {
			orgs[a.OrganizationID] = true
			s.Orgs = append(s.Orgs, a.OrganizationID)
		}
	}
	readOrgs := map[uuid.UUID]bool{}
	for _, a := range p.Assignments {
		if a.Kind() != rbac.ScopeSite || orgs[a.OrganizationID] {
			continue
		}
		s.Sites = append(s.Sites, a.SiteID)
		if !readOrgs[a.OrganizationID] {
			readOrgs[a.OrganizationID] = true
			s.ReadOrgs = append(s.ReadOrgs, a.OrganizationID)
		}
	}
	return s
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
