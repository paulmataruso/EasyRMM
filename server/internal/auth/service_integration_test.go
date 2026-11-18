//go:build integration

package auth_test

import (
	"context"
	"crypto/rand"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

const goodPassword = "orbit-violet-canyon-42"

type env struct {
	db     *database.DB
	svc    *auth.Service
	audit  *audit.Logger
	hasher *auth.Hasher
	now    time.Time
	mail   *fakeMailer
}

type fakeMailer struct {
	mu   sync.Mutex
	sent []string
}

func (f *fakeMailer) Send(_ context.Context, to, subject, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, to+"|"+subject+"|"+body)
	return nil
}

func newEnv(t *testing.T, mutate func(*auth.Config)) *env {
	t.Helper()
	inst := testdb.New(t)
	key := make([]byte, secrets.KeySize)
	_, _ = rand.Read(key)
	sealer, err := secrets.NewSealer(secrets.Key{ID: "k1", Raw: key})
	if err != nil {
		t.Fatal(err)
	}
	cfg := auth.DefaultConfig()
	cfg.PublicURL = "https://rmm.example.com"
	if mutate != nil {
		mutate(&cfg)
	}
	e := &env{db: inst.DB, audit: audit.New(inst.DB, nil), now: time.Now(), mail: &fakeMailer{}}
	e.hasher = auth.NewHasher(auth.Argon2Params{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32}, 4)
	e.svc = auth.NewService(inst.DB, e.audit, e.hasher, sealer, e.mail, cfg)
	e.svc.SetClock(func() time.Time { return e.now })
	return e
}

func (e *env) createUser(t *testing.T, email string) uuid.UUID {
	t.Helper()
	hash, err := e.hasher.Hash(context.Background(), goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	err = e.db.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `INSERT INTO users (email, display_name, password_hash) VALUES ($1, 'Test User', $2) RETURNING id`, email, hash).Scan(&id)
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

var meta = auth.RequestMeta{IP: netip.MustParseAddr("198.51.100.10"), UserAgent: "go-test"}

func codeFor(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	c, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// enroll signs in, enrolls TOTP and returns the secret and an active token.
func (e *env) enroll(t *testing.T, email string) (secret, token string, codes []string) {
	t.Helper()
	ctx := context.Background()
	tok, sess, err := e.svc.Login(ctx, email, goodPassword, meta)
	if err != nil {
		t.Fatal(err)
	}
	if sess.State != auth.StateMFAEnrollment {
		t.Fatalf("want enrollment state, got %s", sess.State)
	}
	s, u, err := e.svc.Authenticate(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	enr, err := e.svc.BeginTOTPEnrollment(ctx, s, u, "", meta)
	if err != nil {
		t.Fatal(err)
	}
	codes, newTok, err := e.svc.ConfirmTOTPEnrollment(ctx, s, u, codeFor(t, enr.Secret, e.now), meta)
	if err != nil {
		t.Fatal(err)
	}
	if newTok == "" || newTok == tok {
		t.Fatal("token not rotated after enrollment")
	}
	if _, _, err := e.svc.Authenticate(ctx, tok); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatal("pre-enrollment token still valid")
	}
	return enr.Secret, newTok, codes
}

func TestLoginRequiresMFAEnrollmentThenTOTP(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	e.createUser(t, "jane@example.com")
	secret, token, codes := e.enroll(t, "jane@example.com")
	if len(codes) != 10 {
		t.Fatalf("got %d recovery codes", len(codes))
	}
	sess, user, err := e.svc.Authenticate(ctx, token)
	if err != nil || sess.State != auth.StateActive || !user.MFAEnabled {
		t.Fatalf("after enrollment: %+v %+v %v", sess, user, err)
	}
	// The session records how it signed in: a password, then a new authenticator's code.
	if !slices.Equal(sess.AMR, []string{"pwd", "otp"}) || !auth.MultiFactor(sess.AMR) || sess.AuthenticatedAt == nil {
		t.Fatalf("after enrollment: amr %v at %v", sess.AMR, sess.AuthenticatedAt)
	}

	// Second sign-in requires a code; e-mail matching is case-insensitive.
	e.now = e.now.Add(time.Minute)
	tok, sess, err := e.svc.Login(ctx, "  JANE@Example.com ", goodPassword, meta)
	if err != nil || sess.State != auth.StateMFARequired {
		t.Fatalf("login: state=%v err=%v", sess, err)
	}
	s, u, _ := e.svc.Authenticate(ctx, tok)
	if !slices.Equal(s.AMR, []string{"pwd"}) || auth.MultiFactor(s.AMR) || s.AuthenticatedAt != nil {
		t.Fatalf("before the code: amr %v at %v", s.AMR, s.AuthenticatedAt)
	}
	if _, err := e.svc.VerifyMFA(ctx, s, u, "000000", meta); !errors.Is(err, auth.ErrInvalidCode) {
		t.Fatalf("wrong code: %v", err)
	}
	active, err := e.svc.VerifyMFA(ctx, s, u, codeFor(t, secret, e.now), meta)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.Authenticate(ctx, tok); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatal("pre-MFA token survived rotation")
	}
	s2, _, err := e.svc.Authenticate(ctx, active)
	if err != nil || s2.State != auth.StateActive {
		t.Fatalf("rotated token: %v", err)
	}
	if !slices.Equal(s2.AMR, []string{"pwd", "otp"}) || s2.AuthenticatedAt == nil || s2.AuthenticatedAt.Sub(e.now).Abs() > time.Millisecond {
		t.Fatalf("after the code: amr %v at %v", s2.AMR, s2.AuthenticatedAt)
	}
}

// Sign-in methods count as two factors only together.
func TestMultiFactor(t *testing.T) {
	for _, c := range []struct {
		amr  []string
		want bool
	}{
		{nil, false}, {[]string{"pwd"}, false}, {[]string{"fed"}, false}, {[]string{"otp"}, false},
		{[]string{"pwd", "otp"}, true}, {[]string{"pwd", "hwk"}, true}, {[]string{"pwd", "rc"}, true}, {[]string{"fed", "otp"}, true},
		{[]string{"fed", "mfa"}, true}, {[]string{"hwk", "mfa"}, true},
	} {
		if got := auth.MultiFactor(c.amr); got != c.want {
			t.Errorf("%v: %v", c.amr, got)
		}
	}
}

func TestTOTPCodeCannotBeReplayed(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	e.createUser(t, "replay@example.com")
	secret, _, _ := e.enroll(t, "replay@example.com")
	e.now = e.now.Add(31 * time.Second)
	code := codeFor(t, secret, e.now)

	tok1, _, _ := e.svc.Login(ctx, "replay@example.com", goodPassword, meta)
	s1, u1, _ := e.svc.Authenticate(ctx, tok1)
	if _, err := e.svc.VerifyMFA(ctx, s1, u1, code, meta); err != nil {
		t.Fatal(err)
	}
	tok2, _, _ := e.svc.Login(ctx, "replay@example.com", goodPassword, meta)
	s2, u2, _ := e.svc.Authenticate(ctx, tok2)
	if _, err := e.svc.VerifyMFA(ctx, s2, u2, code, meta); !errors.Is(err, auth.ErrInvalidCode) {
		t.Fatalf("replayed code accepted: %v", err)
	}
}

func TestRecoveryCodesAreSingleUse(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	e.createUser(t, "rc@example.com")
	_, _, codes := e.enroll(t, "rc@example.com")

	for i, want := range []error{nil, auth.ErrInvalidCode} {
		tok, _, _ := e.svc.Login(ctx, "rc@example.com", goodPassword, meta)
		s, u, _ := e.svc.Authenticate(ctx, tok)
		active, err := e.svc.VerifyMFA(ctx, s, u, strings.ToUpper(codes[0]), meta)
		if !errors.Is(err, want) {
			t.Fatalf("attempt %d: got %v want %v", i, err, want)
		}
		if err == nil {
			if s, _, _ := e.svc.Authenticate(ctx, active); !slices.Equal(s.AMR, []string{"pwd", "rc"}) {
				t.Fatalf("recovery code: amr %v", s.AMR)
			}
		}
	}
}

func TestMFAFailuresRevokeTheSession(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	e.createUser(t, "mfa@example.com")
	e.enroll(t, "mfa@example.com")
	tok, _, _ := e.svc.Login(ctx, "mfa@example.com", goodPassword, meta)
	for i := 0; i < 5; i++ {
		s, u, err := e.svc.Authenticate(ctx, tok)
		if err != nil {
			t.Fatalf("session revoked too early (attempt %d)", i)
		}
		_, _ = e.svc.VerifyMFA(ctx, s, u, "123456", meta)
	}
	if _, _, err := e.svc.Authenticate(ctx, tok); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatal("session survives repeated MFA failures")
	}
}

func TestLoginFailuresAreGenericAndLockTheAccount(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	e.createUser(t, "lock@example.com")

	if _, _, err := e.svc.Login(ctx, "nobody@example.com", goodPassword, meta); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("unknown account: %v", err)
	}
	for i := 0; i < 5; i++ {
		other := auth.RequestMeta{IP: netip.AddrFrom4([4]byte{198, 51, 100, byte(20 + i)})}
		if _, _, err := e.svc.Login(ctx, "lock@example.com", "wrong-password-value", other); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	// The correct password is refused while locked, with the same error.
	if _, _, err := e.svc.Login(ctx, "lock@example.com", goodPassword, meta); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("locked account accepted correct password: %v", err)
	}
	e.now = e.now.Add(2 * time.Minute)
	if _, _, err := e.svc.Login(ctx, "lock@example.com", goodPassword, meta); err != nil {
		t.Fatalf("lock did not expire: %v", err)
	}

	var failures int
	_ = e.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'auth.login' AND outcome = 'failure'`).Scan(&failures)
	})
	if failures != 7 {
		t.Fatalf("expected 7 audited failures, got %d", failures)
	}
}

func TestLoginIsRateLimitedPerAddress(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	var limited bool
	for i := 0; i < 15; i++ {
		_, _, err := e.svc.Login(ctx, "spray@example.com", "x", meta)
		if errors.Is(err, auth.ErrRateLimited) {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("no rate limiting after 15 rapid attempts")
	}
}

func TestDisabledUserCannotSignInAndLosesSessions(t *testing.T) {
	e := newEnv(t, func(c *auth.Config) { c.RequireMFA = false })
	ctx := context.Background()
	id := e.createUser(t, "gone@example.com")
	tok, sess, err := e.svc.Login(ctx, "gone@example.com", goodPassword, meta)
	if err != nil || sess.State != auth.StateActive {
		t.Fatalf("login without MFA policy: %v", err)
	}
	_ = e.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET status = 'disabled' WHERE id = $1`, id)
		return err
	})
	if _, _, err := e.svc.Authenticate(ctx, tok); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatal("disabled user's session still valid")
	}
	if _, _, err := e.svc.Login(ctx, "gone@example.com", goodPassword, meta); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatal("disabled user signed in")
	}
}

func TestSessionIdleAndAbsoluteExpiry(t *testing.T) {
	e := newEnv(t, func(c *auth.Config) { c.RequireMFA = false; c.IdleTimeout = time.Hour; c.MaxSessionAge = 3 * time.Hour })
	ctx := context.Background()
	e.createUser(t, "idle@example.com")
	tok, _, _ := e.svc.Login(ctx, "idle@example.com", goodPassword, meta)

	// Activity every 50 minutes keeps the session alive until the absolute limit.
	for i := 0; i < 3; i++ {
		e.now = e.now.Add(50 * time.Minute)
		if _, _, err := e.svc.Authenticate(ctx, tok); err != nil {
			t.Fatalf("active session expired early at step %d", i)
		}
	}
	e.now = e.now.Add(40 * time.Minute) // 190 minutes total
	if _, _, err := e.svc.Authenticate(ctx, tok); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatal("session outlived its absolute lifetime")
	}

	tok2, _, _ := e.svc.Login(ctx, "idle@example.com", goodPassword, meta)
	e.now = e.now.Add(61 * time.Minute)
	if _, _, err := e.svc.Authenticate(ctx, tok2); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatal("idle session not expired")
	}
}

func TestPendingMFASessionExpiresQuickly(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	e.createUser(t, "slow@example.com")
	tok, _, _ := e.svc.Login(ctx, "slow@example.com", goodPassword, meta)
	e.now = e.now.Add(11 * time.Minute)
	if _, _, err := e.svc.Authenticate(ctx, tok); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatal("half-finished sign-in lives too long")
	}
}

func TestChangePasswordRevokesOtherSessions(t *testing.T) {
	e := newEnv(t, func(c *auth.Config) { c.RequireMFA = false })
	ctx := context.Background()
	e.createUser(t, "pw@example.com")
	tokA, _, _ := e.svc.Login(ctx, "pw@example.com", goodPassword, meta)
	tokB, _, _ := e.svc.Login(ctx, "pw@example.com", goodPassword, meta)
	s, u, _ := e.svc.Authenticate(ctx, tokA)
	if _, err := e.svc.ChangePassword(ctx, s, u, "not-my-password", "another-strong-phrase-9", meta); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("wrong current password: %v", err)
	}
	if _, err := e.svc.ChangePassword(ctx, s, u, goodPassword, "short", meta); !errors.Is(err, auth.ErrPasswordTooShort) {
		t.Fatalf("weak new password: %v", err)
	}
	e.now = e.now.Add(time.Minute)
	tokA2, err := e.svc.ChangePassword(ctx, s, u, goodPassword, "another-strong-phrase-9", meta)
	if err != nil {
		t.Fatal(err)
	}
	// The session goes on under a new token, with its lifetime unchanged;
	// a copy of the old token no longer works.
	if _, _, err := e.svc.Authenticate(ctx, tokA); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatal("the old token survived its own password change")
	}
	s2, _, err := e.svc.Authenticate(ctx, tokA2)
	if err != nil {
		t.Fatal("current session revoked by its own password change")
	}
	if s2.ID != s.ID || !s2.ExpiresAt.Equal(s.ExpiresAt) {
		t.Fatalf("session changed: %v %v -> %v %v", s.ID, s.ExpiresAt, s2.ID, s2.ExpiresAt)
	}
	if _, _, err := e.svc.Authenticate(ctx, tokB); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatal("other session survived password change")
	}
	if _, _, err := e.svc.Login(ctx, "pw@example.com", "another-strong-phrase-9", meta); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordResetFlow(t *testing.T) {
	e := newEnv(t, func(c *auth.Config) { c.RequireMFA = false })
	ctx := context.Background()
	e.createUser(t, "reset@example.com")
	oldTok, _, _ := e.svc.Login(ctx, "reset@example.com", goodPassword, meta)

	if err := e.svc.RequestPasswordReset(ctx, "unknown@example.com", meta); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RequestPasswordReset(ctx, "reset@example.com", meta); err != nil {
		t.Fatal(err)
	}
	e.svc.Wait()
	if len(e.mail.sent) != 1 {
		t.Fatalf("expected exactly one e-mail, got %d", len(e.mail.sent))
	}
	_, after, ok := strings.Cut(e.mail.sent[0], "#token=")
	if !ok {
		t.Fatal("reset link missing")
	}
	token := strings.Fields(after)[0]

	if err := e.svc.CompletePasswordReset(ctx, "bogus", "brand-new-passphrase-7", meta); !errors.Is(err, auth.ErrInvalidResetToken) {
		t.Fatalf("bogus token: %v", err)
	}
	if err := e.svc.CompletePasswordReset(ctx, token, "brand-new-passphrase-7", meta); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.CompletePasswordReset(ctx, token, "brand-new-passphrase-8", meta); !errors.Is(err, auth.ErrInvalidResetToken) {
		t.Fatal("reset token reused")
	}
	if _, _, err := e.svc.Authenticate(ctx, oldTok); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatal("session survived password reset")
	}
	if _, _, err := e.svc.Login(ctx, "reset@example.com", "brand-new-passphrase-7", meta); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordResetTokenExpires(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	id := e.createUser(t, "late@example.com")
	var link string
	_ = e.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var err error
		link, err = e.svc.IssueResetToken(ctx, tx, id, meta)
		return err
	})
	_, token, _ := strings.Cut(link, "#token=")
	e.now = e.now.Add(31 * time.Minute)
	if err := e.svc.CompletePasswordReset(ctx, token, "brand-new-passphrase-7", meta); !errors.Is(err, auth.ErrInvalidResetToken) {
		t.Fatalf("expired token accepted: %v", err)
	}
}

func TestLoadPrincipalAndDataScope(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	uid := e.createUser(t, "scope@example.com")
	var orgA, orgB, siteB uuid.UUID
	err := e.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO organizations (name) VALUES ('A') RETURNING id`).Scan(&orgA); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO organizations (name) VALUES ('B') RETURNING id`).Scan(&orgB); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO sites (organization_id, name) VALUES ($1, 'B1') RETURNING id`, orgB).Scan(&siteB); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO role_assignments (user_id, role, organization_id, site_id) VALUES
			($1, 'technician', $2, NULL), ($1, 'read_only', $3, $4)`, uid, orgA, orgB, siteB)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := e.svc.LoadPrincipal(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Can(rbac.PermTerminal, rbac.Site(orgA, uuid.New())) || p.Can(rbac.PermTerminal, rbac.Site(orgB, siteB)) {
		t.Fatal("principal permissions wrong")
	}
	s := auth.DataScope(p)
	if s.All || len(s.Orgs) != 1 || s.Orgs[0] != orgA || len(s.Sites) != 1 || s.Sites[0] != siteB || len(s.ReadOrgs) != 1 || s.ReadOrgs[0] != orgB {
		t.Fatalf("unexpected data scope %+v", s)
	}
}

func TestSessionListingLogoutAndRevocation(t *testing.T) {
	e := newEnv(t, func(c *auth.Config) { c.RequireMFA = false })
	ctx := context.Background()
	uid := e.createUser(t, "sessions@example.com")
	other := e.createUser(t, "other@example.com")
	tokA, _, _ := e.svc.Login(ctx, "sessions@example.com", goodPassword, meta)
	tokB, _, _ := e.svc.Login(ctx, "sessions@example.com", goodPassword, meta)
	sA, uA, _ := e.svc.Authenticate(ctx, tokA)
	sB, _, _ := e.svc.Authenticate(ctx, tokB)

	list, err := e.svc.ListSessions(ctx, uid)
	if err != nil || len(list) != 2 {
		t.Fatalf("ListSessions: %d sessions, err %v", len(list), err)
	}
	if list[0].SourceIP == nil || list[0].UserAgent != "go-test" {
		t.Fatalf("session metadata missing: %+v", list[0])
	}

	actor := audit.Actor{Type: audit.ActorUser, ID: uid, Label: "sessions@example.com"}
	// A user cannot revoke someone else's session by guessing its id.
	if err := e.svc.RevokeSession(ctx, actor, other, sB.ID); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("cross-user revoke: %v", err)
	}
	if err := e.svc.RevokeSession(ctx, actor, uid, sB.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.Authenticate(ctx, tokB); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatal("revoked session still valid")
	}
	if err := e.svc.RevokeSession(ctx, actor, uid, sB.ID); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatal("revoking twice should report an invalid session")
	}

	if err := e.svc.Logout(ctx, sA, uA, meta); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.Authenticate(ctx, tokA); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatal("logged-out session still valid")
	}
	if list, _ := e.svc.ListSessions(ctx, uid); len(list) != 0 {
		t.Fatalf("%d sessions listed after logout and revoke", len(list))
	}
}

func TestOptionalTOTPEnrollmentFromActiveSessionAndRegeneratingCodes(t *testing.T) {
	e := newEnv(t, func(c *auth.Config) { c.RequireMFA = false })
	ctx := context.Background()
	e.createUser(t, "opt@example.com")
	tok, sess, _ := e.svc.Login(ctx, "opt@example.com", goodPassword, meta)
	if sess.State != auth.StateActive {
		t.Fatal("expected an active session when MFA is optional")
	}
	s, u, _ := e.svc.Authenticate(ctx, tok)

	// Confirming before beginning is refused.
	if _, _, err := e.svc.ConfirmTOTPEnrollment(ctx, s, u, "123456", meta); !errors.Is(err, auth.ErrWrongState) {
		t.Fatalf("confirm without pending secret: %v", err)
	}
	// From a signed-in session, the password comes first.
	if _, err := e.svc.BeginTOTPEnrollment(ctx, s, u, "wrong password", meta); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("totp set-up with a wrong password: %v", err)
	}
	enr, err := e.svc.BeginTOTPEnrollment(ctx, s, u, goodPassword, meta)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enr.URI, "otpauth://totp/EasyRMM:") {
		t.Fatalf("unexpected URI %s", enr.URI)
	}
	if _, _, err := e.svc.ConfirmTOTPEnrollment(ctx, s, u, "000000", meta); !errors.Is(err, auth.ErrInvalidCode) {
		t.Fatalf("wrong confirmation code: %v", err)
	}
	codes, newTok, err := e.svc.ConfirmTOTPEnrollment(ctx, s, u, codeFor(t, enr.Secret, e.now), meta)
	if err != nil || len(codes) != 10 {
		t.Fatalf("confirm: %v", err)
	}
	if newTok != "" {
		t.Fatal("an already-active session must keep its token")
	}

	s, u, _ = e.svc.Authenticate(ctx, tok)
	if !u.MFAEnabled {
		t.Fatal("MFA not reported as enabled")
	}
	// Once enabled, a new secret cannot be started from a normal session.
	if _, err := e.svc.BeginTOTPEnrollment(ctx, s, u, goodPassword, meta); !errors.Is(err, auth.ErrWrongState) {
		t.Fatalf("re-enrollment while enabled: %v", err)
	}
	if _, err := e.svc.RegenerateRecoveryCodes(ctx, s, u, "wrong password", meta); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("regenerate with wrong password: %v", err)
	}
	fresh, err := e.svc.RegenerateRecoveryCodes(ctx, s, u, goodPassword, meta)
	if err != nil || len(fresh) != 10 {
		t.Fatalf("regenerate: %v", err)
	}

	// Old codes stop working; new ones work.
	tok2, _, _ := e.svc.Login(ctx, "opt@example.com", goodPassword, meta)
	s2, u2, _ := e.svc.Authenticate(ctx, tok2)
	if _, err := e.svc.VerifyMFA(ctx, s2, u2, codes[0], meta); !errors.Is(err, auth.ErrInvalidCode) {
		t.Fatal("recovery code from before regeneration accepted")
	}
	if _, err := e.svc.VerifyMFA(ctx, s2, u2, fresh[3], meta); err != nil {
		t.Fatalf("fresh recovery code rejected: %v", err)
	}
}

func TestStateGuards(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	e.createUser(t, "guard@example.com")
	tok, _, _ := e.svc.Login(ctx, "guard@example.com", goodPassword, meta)
	s, u, _ := e.svc.Authenticate(ctx, tok)
	if s.State != auth.StateMFAEnrollment {
		t.Fatal("expected enrollment state")
	}
	if _, err := e.svc.VerifyMFA(ctx, s, u, "123456", meta); !errors.Is(err, auth.ErrWrongState) {
		t.Fatalf("VerifyMFA during enrollment: %v", err)
	}
	if _, err := e.svc.ChangePassword(ctx, s, u, goodPassword, "another-strong-phrase-9", meta); !errors.Is(err, auth.ErrWrongState) {
		t.Fatalf("ChangePassword before MFA: %v", err)
	}
	if _, err := e.svc.RegenerateRecoveryCodes(ctx, s, u, goodPassword, meta); !errors.Is(err, auth.ErrWrongState) {
		t.Fatalf("RegenerateRecoveryCodes before MFA: %v", err)
	}
	if _, _, err := e.svc.Authenticate(ctx, ""); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatal("empty token accepted")
	}
	if _, _, err := e.svc.Authenticate(ctx, strings.Repeat("a", 200)); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatal("oversized token accepted")
	}
	if !e.svc.ResetAvailable() || !e.svc.Config().RequireMFA {
		t.Fatal("unexpected service configuration")
	}
}

func TestPasswordResetWithoutMailerAndWithWeakPassword(t *testing.T) {
	inst := testdb.New(t)
	key := make([]byte, secrets.KeySize)
	_, _ = rand.Read(key)
	sealer, _ := secrets.NewSealer(secrets.Key{ID: "k1", Raw: key})
	hasher := auth.NewHasher(auth.Argon2Params{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32}, 0)
	svc := auth.NewService(inst.DB, audit.New(inst.DB, nil), hasher, sealer, nil, auth.DefaultConfig())
	ctx := context.Background()
	if svc.ResetAvailable() {
		t.Fatal("reset reported available without a mailer")
	}
	if err := svc.RequestPasswordReset(ctx, "x@example.com", meta); !errors.Is(err, auth.ErrResetUnavailable) {
		t.Fatalf("want ErrResetUnavailable, got %v", err)
	}

	e := newEnv(t, nil)
	id := e.createUser(t, "weak@example.com")
	var link string
	_ = e.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var err error
		link, err = e.svc.IssueResetToken(ctx, tx, id, meta)
		return err
	})
	_, token, _ := strings.Cut(link, "#token=")
	if err := e.svc.CompletePasswordReset(ctx, token, "weak@example.com-pw", meta); err == nil {
		t.Fatal("password containing the e-mail address accepted")
	}
	if err := e.svc.CompletePasswordReset(ctx, "", "brand-new-passphrase-7", meta); !errors.Is(err, auth.ErrInvalidResetToken) {
		t.Fatal("empty reset token accepted")
	}
	// A failed attempt with a weak password must not consume the token.
	if err := e.svc.CompletePasswordReset(ctx, token, "brand-new-passphrase-7", meta); err != nil {
		t.Fatalf("token consumed by rejected attempt: %v", err)
	}
}

func TestLongUserAgentIsTruncated(t *testing.T) {
	e := newEnv(t, func(c *auth.Config) { c.RequireMFA = false })
	ctx := context.Background()
	uid := e.createUser(t, "ua@example.com")
	long := strings.Repeat("é", 400) // 800 bytes
	if _, _, err := e.svc.Login(ctx, "ua@example.com", goodPassword, auth.RequestMeta{UserAgent: long}); err != nil {
		t.Fatal(err)
	}
	list, _ := e.svc.ListSessions(ctx, uid)
	if len(list) != 1 || len(list[0].UserAgent) > 512 || !strings.HasPrefix(long, list[0].UserAgent) {
		t.Fatalf("user agent not truncated on a rune boundary: %d bytes", len(list[0].UserAgent))
	}
}

func TestInvitedUserWithoutPasswordCannotSignIn(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	err := e.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO users (email, display_name) VALUES ('invited@example.com', 'Invited')`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, pw := range []string{"", goodPassword} {
		if _, _, err := e.svc.Login(ctx, "invited@example.com", pw, meta); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("password-less account signed in with %q: %v", pw, err)
		}
	}
}

func TestLoginUpgradesWeakPasswordHashes(t *testing.T) {
	e := newEnv(t, func(c *auth.Config) { c.RequireMFA = false })
	ctx := context.Background()
	id := e.createUser(t, "legacy@example.com") // hashed with t=1
	stronger := auth.NewHasher(auth.Argon2Params{MemoryKiB: 8 * 1024, Iterations: 2, Parallelism: 1, SaltLen: 16, KeyLen: 32}, 2)
	key := make([]byte, secrets.KeySize)
	_, _ = rand.Read(key)
	sealer, _ := secrets.NewSealer(secrets.Key{ID: "k1", Raw: key})
	cfg := auth.DefaultConfig()
	cfg.RequireMFA = false
	svc := auth.NewService(e.db, e.audit, stronger, sealer, nil, cfg)
	if _, _, err := svc.Login(ctx, "legacy@example.com", goodPassword, meta); err != nil {
		t.Fatal(err)
	}
	var hash string
	_ = e.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT password_hash FROM users WHERE id = $1`, id).Scan(&hash)
	})
	if !strings.Contains(hash, "t=2") {
		t.Fatalf("hash not upgraded: %s", hash)
	}
	if _, _, err := svc.Login(ctx, "legacy@example.com", goodPassword, meta); err != nil {
		t.Fatalf("upgraded hash rejected: %v", err)
	}
}

func TestMFAVerificationIsRateLimitedPerUser(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	e.createUser(t, "brute@example.com")
	e.enroll(t, "brute@example.com")
	limited := false
	for i := 0; i < 4 && !limited; i++ {
		// Fresh sessions so the per-session failure cap does not end the loop first.
		tok, _, err := e.svc.Login(ctx, "brute@example.com", goodPassword, meta)
		if err != nil {
			t.Fatal(err)
		}
		s, u, _ := e.svc.Authenticate(ctx, tok)
		for j := 0; j < 4; j++ {
			if _, err := e.svc.VerifyMFA(ctx, s, u, "111111", meta); errors.Is(err, auth.ErrRateLimited) {
				limited = true
				break
			}
		}
	}
	if !limited {
		t.Fatal("unlimited MFA guessing across sessions")
	}
}
