//go:build integration

package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

func (e *env) userInt(t *testing.T, id uuid.UUID, column string) int {
	t.Helper()
	var n int
	err := e.db.ReadTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT `+column+` FROM users WHERE id = $1`, id).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// Someone who knows the password cannot guess authenticator codes for as
// long as they like by signing in again every five tries.
func TestWrongCodesLockTheAccount(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	id := e.createUser(t, "guess@example.com")
	secret, _, _ := e.enroll(t, "guess@example.com")
	e.now = e.now.Add(time.Minute)
	wrong := "000000"
	if codeFor(t, secret, e.now) == wrong {
		wrong = "111111"
	}
	half := func() (*auth.Session, *auth.User) {
		t.Helper()
		tok, s, err := e.svc.Login(ctx, "guess@example.com", goodPassword, meta)
		if err != nil || s.State != auth.StateMFARequired {
			t.Fatalf("login: %v %v", s, err)
		}
		sess, u, err := e.svc.Authenticate(ctx, tok)
		if err != nil {
			t.Fatal(err)
		}
		return sess, u
	}

	// Nine wrong codes over two sign-ins: five end a session, and signing in
	// again does not start the account's count over.
	var s *auth.Session
	var u *auth.User
	for i := range 9 {
		if i%5 == 0 {
			s, u = half()
		}
		e.svc.ResetLimits()
		if _, err := e.svc.VerifyMFA(ctx, s, u, wrong, meta); !errors.Is(err, auth.ErrInvalidCode) {
			t.Fatalf("wrong code %d: %v", i+1, err)
		}
	}
	if n := e.userInt(t, id, "mfa_failed_attempts"); n != 9 {
		t.Fatalf("mfa_failed_attempts = %d", n)
	}
	waiting, wu := half() // opened before the lock

	// The tenth in a row locks the account and ends the session.
	e.svc.ResetLimits()
	if _, err := e.svc.VerifyMFA(ctx, s, u, wrong, meta); !errors.Is(err, auth.ErrInvalidCode) {
		t.Fatalf("tenth wrong code: %v", err)
	}
	failures := e.audits(t, "auth.mfa_verify", "failure")
	if last := failures[len(failures)-1]; last["lockedUntil"] == nil || last["inARow"] != float64(10) {
		t.Fatalf("lock not audited: %v", last)
	}
	e.svc.ResetLimits()
	if _, _, err := e.svc.Login(ctx, "guess@example.com", goodPassword, meta); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("sign-in while locked: %v", err)
	}
	// A sign-in already waiting for its code cannot try one either, not even
	// the right one.
	if _, err := e.svc.VerifyMFA(ctx, waiting, wu, codeFor(t, secret, e.now), meta); !errors.Is(err, auth.ErrRateLimited) {
		t.Fatalf("code while locked: %v", err)
	}
	if denied := e.audits(t, "auth.mfa_verify", "denied"); len(denied) != 1 || denied[0]["reason"] != "locked" {
		t.Fatalf("refusal not audited: %v", denied)
	}

	// Once the lock ends, the right code signs in and the count starts over.
	e.now = e.now.Add(e.svc.Config().LockoutBase + time.Second)
	if _, err := e.svc.VerifyMFA(ctx, waiting, wu, codeFor(t, secret, e.now), meta); err != nil {
		t.Fatal(err)
	}
	if n := e.userInt(t, id, "mfa_failed_attempts"); n != 0 {
		t.Fatalf("mfa_failed_attempts after success = %d", n)
	}
}

// Every change that asks for the password again counts wrong passwords
// against the session; the fifth ends it.
func TestReauthentication(t *testing.T) {
	e := newEnv(t, func(c *auth.Config) { c.RequireMFA = false })
	ctx := context.Background()
	e.createUser(t, "re@example.com")
	tok, _, err := e.svc.Login(ctx, "re@example.com", goodPassword, meta)
	if err != nil {
		t.Fatal(err)
	}
	s, u, _ := e.svc.Authenticate(ctx, tok)
	tries := []func(string) error{
		func(p string) error {
			_, err := e.svc.ChangePassword(ctx, s, u, p, "another-strong-phrase-9", meta)
			return err
		},
		func(p string) error { _, err := e.svc.BeginTOTPEnrollment(ctx, s, u, p, meta); return err },
		func(p string) error { _, err := e.svc.BeginKeyRegistration(ctx, s, p, meta); return err },
		func(p string) error {
			_, err := e.svc.ChangePassword(ctx, s, u, p, "another-strong-phrase-9", meta)
			return err
		},
	}
	for i, try := range tries {
		err := try("wrong-password-" + string(rune('a'+i)))
		if i == 2 && errors.Is(err, auth.ErrWebAuthnUnavailable) {
			continue // no RP ID in this environment; covered in the WebAuthn tests
		}
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("try %d: %v", i, err)
		}
	}
	if _, _, err := e.svc.Authenticate(ctx, tok); err != nil {
		t.Fatalf("session ended early: %v", err)
	}
	wrong := len(e.audits(t, "auth.password_change", "failure")) + len(e.audits(t, "auth.mfa_enroll", "failure")) + len(e.audits(t, "auth.webauthn_add", "failure"))
	for wrong < 5 {
		if _, err := e.svc.ChangePassword(ctx, s, u, "wrong-again", "another-strong-phrase-9", meta); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatal(err)
		}
		wrong++
	}
	if _, _, err := e.svc.Authenticate(ctx, tok); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("session survived five wrong passwords: %v", err)
	}
	last := e.audits(t, "auth.password_change", "failure")
	if d := last[len(last)-1]; d["signedOut"] != true || d["reason"] != "wrong_password" {
		t.Fatalf("audit: %v", d)
	}
	// The right password, from the ended session, changes nothing.
	if _, err := e.svc.ChangePassword(ctx, s, u, goodPassword, "another-strong-phrase-9", meta); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("change from an ended session: %v", err)
	}
	if _, _, err := e.svc.Login(ctx, "re@example.com", goodPassword, meta); err != nil {
		t.Fatalf("password changed from an ended session: %v", err)
	}
}

func TestResetEmailIsLimitedPerAccount(t *testing.T) {
	e := newEnv(t, func(c *auth.Config) { c.RequireMFA = false })
	ctx := context.Background()
	e.createUser(t, "many@example.com")
	for range 5 {
		if err := e.svc.RequestPasswordReset(ctx, "many@example.com", meta); err != nil {
			t.Fatal(err)
		}
	}
	e.svc.Wait()
	if sent := e.mp.Received("many@example.com"); len(sent) != 3 {
		t.Fatalf("sent %d e-mails, want 3", len(sent))
	}
	if denied := e.audits(t, "auth.password_reset_request", "denied"); len(denied) != 2 || denied[0]["reason"] != "rate_limited" {
		t.Fatalf("limited requests not audited: %v", denied)
	}
}

// A reset requested for an invited user (by anyone) sends a new invitation
// rather than replacing it with a 30-minute reset link.
func TestResetForAnInvitedUserSendsANewInvitation(t *testing.T) {
	e := newEnv(t, func(c *auth.Config) { c.RequireMFA = false })
	ctx := context.Background()
	var id uuid.UUID
	var first string
	err := e.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO users (email, display_name) VALUES ('new@example.com', 'New Person') RETURNING id`).Scan(&id); err != nil {
			return err
		}
		var err error
		first, err = e.svc.IssueInviteToken(ctx, tx, id, meta)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RequestPasswordReset(ctx, "new@example.com", meta); err != nil {
		t.Fatal(err)
	}
	e.svc.Wait()
	sent := e.mp.Received("new@example.com")
	if len(sent) != 1 || sent[0].Subject != "Finish setting up your EasyRMM account" || !strings.Contains(sent[0].Text, "within 72 hours") {
		t.Fatalf("mail: %+v", sent)
	}
	_, after, ok := strings.Cut(sent[0].Text, "https://rmm.example.com/welcome#token=")
	if !ok {
		t.Fatalf("no invitation link: %s", sent[0].Text)
	}
	token := strings.Fields(after)[0]
	var expires time.Time
	err = e.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT expires_at FROM password_reset_tokens WHERE token_hash = $1`, auth.HashToken(token)).Scan(&expires)
	})
	if err != nil || expires.Sub(e.now) < auth.InviteTTL-time.Minute {
		t.Fatalf("new invitation expires %v (%v)", expires, err)
	}
	if invited := e.audits(t, "auth.password_reset_request", "success"); len(invited) != 1 || invited[0]["invitation"] != true {
		t.Fatalf("audit: %v", invited)
	}
	_, firstToken, _ := strings.Cut(first, "#token=")
	if err := e.svc.CompletePasswordReset(ctx, firstToken, "a-brand-new-passphrase-3", meta); !errors.Is(err, auth.ErrInvalidResetToken) {
		t.Fatalf("the earlier link still works: %v", err)
	}
	if err := e.svc.CompletePasswordReset(ctx, token, "a-brand-new-passphrase-3", meta); err != nil {
		t.Fatal(err)
	}
}
