//go:build integration

package auth_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

func (e *env) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := e.db.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), sql, args...)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func (e *env) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := e.db.ReadTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), sql, args...).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *env) superAdmin(t *testing.T, email string) uuid.UUID {
	t.Helper()
	id := e.createUser(t, email)
	e.exec(t, `INSERT INTO role_assignments (user_id, role) VALUES ($1, 'super_admin')`, id)
	return id
}

func targetError(t *testing.T, err error, want string) {
	t.Helper()
	var target *auth.RecoveryTargetError
	if !errors.As(err, &target) || !strings.Contains(target.Error(), want) {
		t.Fatalf("error %v, want a target error containing %q", err, want)
	}
}

// TestRecoveryLinks is the break-glass of ADR-0044: easyrmm-server recover
// prints a one-time sign-in link for a super administrator.
func TestRecoveryLinks(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	issue := func(email string) (*auth.RecoveryLink, error) {
		return auth.IssueRecoveryLink(ctx, e.db, e.audit, email, e.now)
	}

	_, err := issue("")
	targetError(t, err, "there is no active super administrator")

	alex := e.superAdmin(t, "alex@example.com")
	e.createUser(t, "tech@example.com")
	link, err := issue("")
	if err != nil {
		t.Fatal(err)
	}
	if link.UserID != alex || link.Email != "alex@example.com" || len(link.Token) < 32 || !link.ExpiresAt.Equal(e.now.Add(auth.RecoveryLinkTTL)) {
		t.Fatalf("link %+v", link)
	}
	// Only its hash is stored, and the command is in the audit log.
	if n := e.count(t, `SELECT count(*) FROM recovery_links WHERE token_hash = $1 AND user_id = $2 AND used_at IS NULL`, auth.HashToken(link.Token), alex); n != 1 {
		t.Fatalf("stored links = %d", n)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_log WHERE action = 'auth.recovery_link' AND actor_type = 'system' AND target_id = $1`, alex.String()); n != 1 {
		t.Fatalf("audits = %d", n)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_log WHERE details::text LIKE '%' || $1 || '%'`, link.Token); n != 0 {
		t.Fatal("the token is in the audit log")
	}

	_, err = issue("tech@example.com")
	targetError(t, err, "tech@example.com is not an active super administrator")
	_, err = issue("nobody@example.com")
	targetError(t, err, "is not an active super administrator")

	sam := e.superAdmin(t, "sam@example.com")
	_, err = issue("")
	targetError(t, err, "choose a super administrator with --email: alex@example.com, sam@example.com")
	samLink, err := issue(" Sam@Example.com ")
	if err != nil || samLink.UserID != sam {
		t.Fatalf("sam's link %+v, %v", samLink, err)
	}

	t.Run("it signs in once, with no second factor asked", func(t *testing.T) {
		// Alex has an authenticator: the link does not ask for it.
		e.exec(t, `UPDATE users SET totp_secret_sealed = 'sealed', totp_enabled_at = now() WHERE id = $1`, alex)
		token, sess, err := e.svc.RedeemRecoveryLink(ctx, link.Token, meta)
		if err != nil {
			t.Fatal(err)
		}
		if sess.UserID != alex || sess.State != auth.StateActive || token == "" || !slices.Contains(sess.AMR, "mfa") {
			t.Fatalf("session %+v", sess)
		}
		if n := e.count(t, `SELECT count(*) FROM audit_log WHERE action = 'auth.login' AND outcome = 'success' AND details->>'method' = 'recovery_link'`); n != 1 {
			t.Fatalf("sign-in audits = %d", n)
		}
		if _, _, err := e.svc.RedeemRecoveryLink(ctx, link.Token, meta); !errors.Is(err, auth.ErrRecoveryLinkInvalid) {
			t.Fatalf("second use: %v", err)
		}
		if n := e.count(t, `SELECT count(*) FROM audit_log WHERE action = 'auth.login' AND outcome = 'failure' AND details->>'reason' = 'invalid_link'`); n != 1 {
			t.Fatalf("failure audits = %d", n)
		}
	})

	t.Run("an expired, unknown or malformed link does nothing", func(t *testing.T) {
		e.svc.ResetLimits()
		later := *e
		later.now = e.now.Add(auth.RecoveryLinkTTL + time.Second)
		later.svc.SetClock(func() time.Time { return later.now })
		defer e.svc.SetClock(func() time.Time { return e.now })
		if _, _, err := later.svc.RedeemRecoveryLink(ctx, samLink.Token, meta); !errors.Is(err, auth.ErrRecoveryLinkInvalid) {
			t.Fatalf("expired: %v", err)
		}
		for _, token := range []string{"", "not-a-token", strings.Repeat("x", 200)} {
			if _, _, err := e.svc.RedeemRecoveryLink(ctx, token, meta); !errors.Is(err, auth.ErrRecoveryLinkInvalid) {
				t.Fatalf("%q: %v", token, err)
			}
		}
	})

	t.Run("a disabled account stays out", func(t *testing.T) {
		e.svc.ResetLimits()
		l, err := issue("sam@example.com")
		if err != nil {
			t.Fatal(err)
		}
		e.exec(t, `UPDATE users SET status = 'disabled' WHERE id = $1`, sam)
		if _, _, err := e.svc.RedeemRecoveryLink(ctx, l.Token, meta); !errors.Is(err, auth.ErrAccountUnavailable) {
			t.Fatalf("disabled: %v", err)
		}
		_, err = issue("sam@example.com")
		targetError(t, err, "is not an active super administrator")
	})

	t.Run("guessing is rate-limited", func(t *testing.T) {
		e.svc.ResetLimits()
		limited := false
		for range 50 {
			if _, _, err := e.svc.RedeemRecoveryLink(ctx, "guess", meta); errors.Is(err, auth.ErrRateLimited) {
				limited = true
				break
			}
		}
		if !limited {
			t.Fatal("50 guesses were not rate-limited")
		}
	})
}
