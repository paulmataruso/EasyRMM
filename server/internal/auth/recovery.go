package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// RecoveryLinkTTL is how long a link from `easyrmm-server recover` works.
const RecoveryLinkTTL = 15 * time.Minute

// RecoveryPath is the console page a recovery link opens; the token follows
// in the fragment, which browsers never send to a server.
const RecoveryPath = "/recover"

// RecoveryLink is a one-time sign-in link for a super administrator: the
// break-glass for when single sign-on is down (ADR-0044). Shell access to
// the server is the trust root anyway, and no standing password exists.
type RecoveryLink struct {
	Token     string
	UserID    uuid.UUID
	Email     string
	ExpiresAt time.Time
}

// RecoveryTargetError: no single super administrator is meant. Its message
// says what to give instead.
type RecoveryTargetError struct{ Reason string }

func (e *RecoveryTargetError) Error() string { return e.Reason }

// IssueRecoveryLink makes a recovery link for the active super
// administrator with this email, or, with no email, for the only one there
// is. It runs on the server (easyrmm-server recover), never over HTTP.
func IssueRecoveryLink(ctx context.Context, db *database.DB, auditLog *audit.Logger, email string, now time.Time) (*RecoveryLink, error) {
	email = normaliseEmail(email)
	var link *RecoveryLink
	err := db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT u.id, u.email FROM users u
			WHERE u.status = 'active' AND ($1 = '' OR u.email = $1)
			  AND EXISTS (SELECT 1 FROM role_assignments r WHERE r.user_id = u.id AND r.role = 'super_admin')
			ORDER BY u.email`, email)
		if err != nil {
			return err
		}
		type admin struct {
			id    uuid.UUID
			email string
		}
		var admins []admin
		for rows.Next() {
			var a admin
			if err := rows.Scan(&a.id, &a.email); err != nil {
				rows.Close()
				return err
			}
			admins = append(admins, a)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		switch {
		case len(admins) == 0 && email != "":
			return &RecoveryTargetError{Reason: email + " is not an active super administrator"}
		case len(admins) == 0:
			return &RecoveryTargetError{Reason: "there is no active super administrator"}
		case len(admins) > 1:
			names := make([]string, 0, len(admins))
			for _, a := range admins {
				names = append(names, a.email)
			}
			return &RecoveryTargetError{Reason: "choose a super administrator with --email: " + strings.Join(names, ", ")}
		}
		token, hash, err := NewToken()
		if err != nil {
			return err
		}
		link = &RecoveryLink{Token: token, UserID: admins[0].id, Email: admins[0].email, ExpiresAt: now.Add(RecoveryLinkTTL)}
		if _, err := tx.Exec(ctx, `INSERT INTO recovery_links (token_hash, user_id, created_at, expires_at) VALUES ($1, $2, $3, $4)`,
			hash, link.UserID, now, link.ExpiresAt); err != nil {
			return err
		}
		return auditLog.Write(ctx, tx, audit.Event{Actor: audit.SystemActor("recover command"), Action: "auth.recovery_link",
			TargetType: "user", TargetID: link.UserID.String(), Outcome: audit.Success,
			Details: map[string]any{"email": link.Email, "expiresAt": link.ExpiresAt}})
	})
	if err != nil {
		var target *RecoveryTargetError
		if errors.As(err, &target) {
			return nil, target
		}
		return nil, fmt.Errorf("auth: recovery link: %w", err)
	}
	return link, nil
}

// ErrRecoveryLinkInvalid: the link is unknown, used or expired.
var ErrRecoveryLinkInvalid = errors.New("the recovery link is not valid")

// RedeemRecoveryLink signs in with a recovery link, once. The session needs
// no second factor: whoever ran the command on the server vouches for it,
// and the account may have none of EasyRMM's own (it signs in through
// Authentik).
func (s *Service) RedeemRecoveryLink(ctx context.Context, token string, meta RequestMeta) (string, *Session, error) {
	if meta.IP.IsValid() && !s.ipLimit.Allow("recover:"+LimitKey(meta.IP)) {
		return "", nil, ErrRateLimited
	}
	var userID uuid.UUID
	var email string
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if token == "" || len(token) > 128 {
			return ErrRecoveryLinkInvalid
		}
		err := tx.QueryRow(ctx, `UPDATE recovery_links l SET used_at = $2 FROM users u
			WHERE l.token_hash = $1 AND l.used_at IS NULL AND l.expires_at > $2 AND u.id = l.user_id
			RETURNING l.user_id, u.email`, HashToken(token), s.now()).Scan(&userID, &email)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRecoveryLinkInvalid
		}
		return err
	})
	if errors.Is(err, ErrRecoveryLinkInvalid) {
		_ = s.audit.Record(ctx, audit.Event{Actor: anonymousActor("", meta), Action: "auth.login", Outcome: audit.Failure,
			Details: map[string]any{"method": "recovery_link", "reason": "invalid_link"}})
		return "", nil, err
	}
	if err != nil {
		return "", nil, fmt.Errorf("auth: recovery link: %w", err)
	}
	return s.SignInExternal(ctx, ExternalSignIn{UserID: userID, Email: email, Method: "recovery_link", SecondFactorDone: true}, meta)
}
