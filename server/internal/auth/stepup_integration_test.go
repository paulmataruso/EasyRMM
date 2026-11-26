//go:build integration

package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// totpUser is a user with an authenticator app, signed in twice: two
// sessions of the same person.
func (e *env) totpUser(t *testing.T, email string) (secret string, codes []string, a, b string) {
	t.Helper()
	e.createUser(t, email)
	secret, a, codes = e.enroll(t, email)
	// A second sign-in elsewhere, with the next code.
	e.now = e.now.Add(31 * time.Second)
	e.svc.ResetLimits()
	tok, sess, err := e.svc.Login(context.Background(), email, goodPassword, meta)
	if err != nil || sess.State != auth.StateMFARequired {
		t.Fatalf("second sign-in: %v %v", sess, err)
	}
	s, u := e.session(t, tok)
	if b, err = e.svc.VerifyMFA(context.Background(), s, u, codeFor(t, secret, e.now), meta); err != nil {
		t.Fatal(err)
	}
	return secret, codes, a, b
}

func (e *env) stepUpTOTP(t *testing.T, token, code string) error {
	t.Helper()
	s, u := e.session(t, token)
	return e.svc.StepUpWithCode(context.Background(), s, u, code, meta)
}

func (e *env) stepped(t *testing.T, token string) bool {
	t.Helper()
	s, _ := e.session(t, token)
	return e.svc.CheckStepUp(s) == nil
}

func TestStepUpLastsFiveMinutes(t *testing.T) {
	e := newEnv(t, nil)
	secret, _, tok, _ := e.totpUser(t, "ann@example.com")
	if e.stepped(t, tok) {
		t.Fatal("a session that never stepped up is stepped up")
	}
	s, _ := e.session(t, tok)
	if err := e.svc.CheckStepUp(s); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("CheckStepUp: %v", err)
	}
	// Signing in (a code at sign-in) is not a step-up: stepped_up_at is its own.
	if s.SteppedUpAt != nil || s.AuthenticatedAt == nil {
		t.Fatalf("sign-in set stepped_up_at: %v", s.SteppedUpAt)
	}

	e.now = e.now.Add(31 * time.Second)
	at := e.now
	if err := e.stepUpTOTP(t, tok, codeFor(t, secret, e.now)); err != nil {
		t.Fatal(err)
	}
	s, _ = e.session(t, tok)
	if s.SteppedUpAt == nil || s.SteppedUpAt.Sub(at).Abs() > time.Millisecond {
		t.Fatalf("stepped_up_at = %v, want %v", s.SteppedUpAt, at)
	}
	e.now = at.Add(5*time.Minute - time.Second)
	if !e.stepped(t, tok) {
		t.Fatal("not stepped up 4:59 after the step-up")
	}
	e.now = at.Add(5 * time.Minute)
	if e.stepped(t, tok) {
		t.Fatal("still stepped up 5:00 after the step-up")
	}
	// Stepping up again starts a new window.
	e.now = e.now.Add(time.Minute)
	if err := e.stepUpTOTP(t, tok, codeFor(t, secret, e.now)); err != nil {
		t.Fatal(err)
	}
	if !e.stepped(t, tok) {
		t.Fatal("not stepped up after a second step-up")
	}
	if got := len(e.audits(t, "auth.step_up", "success")); got != 2 {
		t.Fatalf("%d success audit rows, want 2", got)
	}
}

func TestStepUpIsPerSession(t *testing.T) {
	e := newEnv(t, nil)
	secret, _, a, b := e.totpUser(t, "ben@example.com")
	e.now = e.now.Add(31 * time.Second)
	if err := e.stepUpTOTP(t, a, codeFor(t, secret, e.now)); err != nil {
		t.Fatal(err)
	}
	if !e.stepped(t, a) {
		t.Fatal("the session that stepped up is not stepped up")
	}
	if e.stepped(t, b) {
		t.Fatal("another session of the same user is stepped up")
	}
}

func TestStepUpRefusesRecoveryCodesAndPasswords(t *testing.T) {
	e := newEnv(t, nil)
	_, codes, tok, _ := e.totpUser(t, "cy@example.com")
	e.now = e.now.Add(31 * time.Second)

	if err := e.stepUpTOTP(t, tok, codes[0]); !errors.Is(err, auth.ErrRecoveryCodeRefused) {
		t.Fatalf("recovery code: %v", err)
	}
	if e.stepped(t, tok) {
		t.Fatal("a recovery code stepped the session up")
	}
	// The refused code was not used up.
	var unused int
	if err := e.db.ReadTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM user_recovery_codes WHERE used_at IS NULL`).Scan(&unused)
	}); err != nil || unused != 10 {
		t.Fatalf("%d unused recovery codes (%v), want 10", unused, err)
	}
	if got := len(e.audits(t, "auth.step_up", "denied")); got != 1 {
		t.Fatalf("%d denied rows for the recovery code, want 1", got)
	}

	// The password is not a second factor: typed as a code it is wrong, and
	// the password checks other actions make (reauthenticate) do not step up.
	if err := e.stepUpTOTP(t, tok, goodPassword); !errors.Is(err, auth.ErrInvalidCode) {
		t.Fatalf("password as a code: %v", err)
	}
	s, u := e.session(t, tok)
	if _, err := e.svc.RegenerateRecoveryCodes(context.Background(), s, u, goodPassword, meta); err != nil {
		t.Fatal(err)
	}
	if e.stepped(t, tok) {
		t.Fatal("a password check stepped the session up")
	}
	if got := len(e.audits(t, "auth.step_up", "failure")); got != 1 {
		t.Fatalf("%d failure rows, want 1", got)
	}
}

func TestStepUpRefusesAReplayedCode(t *testing.T) {
	e := newEnv(t, nil)
	secret, _, a, b := e.totpUser(t, "di@example.com")
	// The code the second session signed in with cannot step up.
	if err := e.stepUpTOTP(t, a, codeFor(t, secret, e.now)); !errors.Is(err, auth.ErrInvalidCode) {
		t.Fatalf("a code used at sign-in: %v", err)
	}
	e.now = e.now.Add(31 * time.Second)
	code := codeFor(t, secret, e.now)
	if err := e.stepUpTOTP(t, a, code); err != nil {
		t.Fatal(err)
	}
	// The same code, from this session or another, is a replay.
	if err := e.stepUpTOTP(t, a, code); !errors.Is(err, auth.ErrInvalidCode) {
		t.Fatalf("replay on the same session: %v", err)
	}
	if err := e.stepUpTOTP(t, b, code); !errors.Is(err, auth.ErrInvalidCode) {
		t.Fatalf("replay on another session: %v", err)
	}
	if e.stepped(t, b) {
		t.Fatal("a replayed code stepped a session up")
	}
}

func TestStepUpWrongCodesEndTheSession(t *testing.T) {
	e := newEnv(t, func(c *auth.Config) { c.MaxMFAFailures = 3 })
	_, _, tok, other := e.totpUser(t, "ed@example.com")
	e.now = e.now.Add(31 * time.Second)
	for i := 0; i < 3; i++ {
		e.svc.ResetLimits()
		if err := e.stepUpTOTP(t, tok, "000000"); !errors.Is(err, auth.ErrInvalidCode) {
			t.Fatalf("wrong code %d: %v", i, err)
		}
	}
	if _, _, err := e.svc.Authenticate(context.Background(), tok); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("the session survived %d wrong codes: %v", 3, err)
	}
	// Only that session: the other one is untouched.
	e.session(t, other)
	rows := e.audits(t, "auth.step_up", "failure")
	if len(rows) != 3 || rows[2]["signedOut"] != true || rows[0]["method"] != "totp" {
		t.Fatalf("failure rows: %v", rows)
	}
}

func TestStepUpIsRateLimited(t *testing.T) {
	e := newEnv(t, func(c *auth.Config) { c.MaxMFAFailures = 100 })
	_, _, tok, _ := e.totpUser(t, "flo@example.com")
	e.svc.ResetLimits()
	var limited bool
	for i := 0; i < 30 && !limited; i++ {
		limited = errors.Is(e.stepUpTOTP(t, tok, "000000"), auth.ErrRateLimited)
	}
	if !limited {
		t.Fatal("30 wrong codes at once were never limited")
	}
}

func TestStepUpNeedsASecondFactor(t *testing.T) {
	e := newEnv(t, func(c *auth.Config) { c.RequireMFA = false })
	e.createUser(t, "gus@example.com")
	tok, sess, err := e.svc.Login(context.Background(), "gus@example.com", goodPassword, meta)
	if err != nil || sess.State != auth.StateActive {
		t.Fatalf("login: %v %v", sess, err)
	}
	s, u := e.session(t, tok)
	st, err := e.svc.StepUpStatus(context.Background(), s, u)
	if err != nil || len(st.Methods) != 0 || st.ValidUntil != nil {
		t.Fatalf("status: %+v %v", st, err)
	}
	if err := e.svc.StepUpWithCode(context.Background(), s, u, "123456", meta); !errors.Is(err, auth.ErrNoSecondFactor) {
		t.Fatalf("code: %v", err)
	}
	if _, err := e.svc.BeginStepUpKey(context.Background(), s, meta); !errors.Is(err, auth.ErrNoSecondFactor) && !errors.Is(err, auth.ErrWebAuthnUnavailable) {
		t.Fatalf("key: %v", err)
	}
	if e.stepped(t, tok) {
		t.Fatal("an account with no second factor stepped up")
	}
}

func TestStepUpWithASecurityKey(t *testing.T) {
	e := newEnv(t, nil)
	_, key, tok := e.keyUser(t, "hal@example.com")
	ctx := context.Background()
	s, u := e.session(t, tok)
	st, err := e.svc.StepUpStatus(ctx, s, u)
	if err != nil || len(st.Methods) != 1 || st.Methods[0] != auth.StepUpWebAuthn {
		t.Fatalf("status: %+v %v", st, err)
	}
	e.svc.ResetLimits()
	assertion, err := e.svc.BeginStepUpKey(ctx, s, meta)
	if err != nil {
		t.Fatal(err)
	}
	answer := key.Get(t, asJSON(t, assertion))
	if err := e.svc.FinishStepUpKey(ctx, s, u, []byte(`{}`), meta); err == nil {
		t.Fatal("an empty answer stepped up")
	}
	e.svc.ResetLimits()
	if err := e.svc.FinishStepUpKey(ctx, s, u, answer, meta); err != nil {
		t.Fatal(err)
	}
	if !e.stepped(t, tok) {
		t.Fatal("not stepped up after a key")
	}
	// The answer cannot be used twice.
	e.now = e.now.Add(6 * time.Minute)
	if err := e.svc.FinishStepUpKey(ctx, s, u, answer, meta); !errors.Is(err, auth.ErrKeyRejected) {
		t.Fatalf("a replayed answer: %v", err)
	}
	rows := e.audits(t, "auth.step_up", "success")
	if len(rows) != 1 || rows[0]["method"] != "webauthn" {
		t.Fatalf("success rows: %v", rows)
	}
}
