//go:build integration

package auth_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/auth/webauthntest"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

const (
	rpID   = "rmm.example.com"
	origin = "https://rmm.example.com"
)

func asJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// session resolves a token, failing the test when it does not.
func (e *env) session(t *testing.T, token string) (*auth.Session, *auth.User) {
	t.Helper()
	s, u, err := e.svc.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	return s, u
}

// register adds key to the session's user; password is needed when signed in.
func (e *env) register(t *testing.T, token, password, name string, key *webauthntest.Authenticator) (*auth.KeyAdded, error) {
	t.Helper()
	ctx := context.Background()
	e.svc.ResetLimits()
	e.now = e.now.Add(time.Second) // keys are listed oldest first
	s, u := e.session(t, token)
	creation, err := e.svc.BeginKeyRegistration(ctx, s, password)
	if err != nil {
		return nil, err
	}
	return e.svc.FinishKeyRegistration(ctx, s, u, name, key.Create(t, asJSON(t, creation)), meta)
}

// keyUser creates a user whose only second factor is a security key, set up
// at their first sign-in. It returns the user, the key and a signed-in token.
func (e *env) keyUser(t *testing.T, email string) (uuid.UUID, *webauthntest.Authenticator, string) {
	t.Helper()
	id := e.createUser(t, email)
	tok, sess, err := e.svc.Login(context.Background(), email, goodPassword, meta)
	if err != nil || sess.State != auth.StateMFAEnrollment {
		t.Fatalf("login: %v %v", sess, err)
	}
	key := webauthntest.New(t, rpID, origin)
	added, err := e.register(t, tok, "", "YubiKey 5", key)
	if err != nil {
		t.Fatal(err)
	}
	if added.Token == "" || added.Token == tok || len(added.RecoveryCodes) != 10 {
		t.Fatalf("first factor: token rotated %v, %d codes", added.Token != tok, len(added.RecoveryCodes))
	}
	return id, key, added.Token
}

// mfa signs in with the password, then answers the second factor with key.
func (e *env) mfa(t *testing.T, email string, key *webauthntest.Authenticator) (string, error) {
	t.Helper()
	ctx := context.Background()
	e.svc.ResetLimits()
	tok, sess, err := e.svc.Login(ctx, email, goodPassword, meta)
	if err != nil || sess.State != auth.StateMFARequired {
		t.Fatalf("login: %v %v", sess, err)
	}
	s, u := e.session(t, tok)
	assertion, err := e.svc.BeginKeyMFA(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	return e.svc.FinishKeyMFA(ctx, s, u, key.Get(t, asJSON(t, assertion)), meta)
}

// passkey signs in with key alone.
func (e *env) passkey(t *testing.T, key *webauthntest.Authenticator, m auth.RequestMeta) (string, error) {
	t.Helper()
	ctx := context.Background()
	e.svc.ResetLimits()
	assertion, err := e.svc.BeginPasskeyLogin(ctx, m)
	if err != nil {
		return "", err
	}
	tok, _, err := e.svc.FinishPasskeyLogin(ctx, key.Get(t, asJSON(t, assertion)), m)
	return tok, err
}

func (e *env) audits(t *testing.T, action, outcome string) []map[string]any {
	t.Helper()
	var out []map[string]any
	err := e.db.ReadTx(context.Background(), database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT details FROM audit_log WHERE action = $1 AND outcome = $2 ORDER BY id`, action, outcome)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d map[string]any
			if err := rows.Scan(&d); err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestWebAuthnNeedsAName(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	if st := e.svc.WebAuthn(); !st.Available || st.Origin != origin || st.Reason != "" {
		t.Fatalf("named: %+v", st)
	}
	for _, url := range []string{"https://198.51.100.45", "https://[2001:db8::1]:8443", "", "::bad"} {
		ip := newEnv(t, func(c *auth.Config) { c.PublicURL = url })
		st := ip.svc.WebAuthn()
		if st.Available || st.Reason == "" {
			t.Fatalf("%q: %+v", url, st)
		}
		if _, err := ip.svc.BeginPasskeyLogin(ctx, meta); !errors.Is(err, auth.ErrWebAuthnUnavailable) {
			t.Errorf("%q passkey: %v", url, err)
		}
		if _, _, err := ip.svc.FinishPasskeyLogin(ctx, []byte("{}"), meta); !errors.Is(err, auth.ErrWebAuthnUnavailable) {
			t.Errorf("%q passkey finish: %v", url, err)
		}
		s := &auth.Session{State: auth.StateActive}
		if _, err := ip.svc.BeginKeyRegistration(ctx, s, ""); !errors.Is(err, auth.ErrWebAuthnUnavailable) {
			t.Errorf("%q register: %v", url, err)
		}
		if _, err := ip.svc.FinishKeyRegistration(ctx, s, &auth.User{}, "x", nil, meta); !errors.Is(err, auth.ErrWebAuthnUnavailable) {
			t.Errorf("%q register finish: %v", url, err)
		}
		s.State = auth.StateMFARequired
		if _, err := ip.svc.BeginKeyMFA(ctx, s); !errors.Is(err, auth.ErrWebAuthnUnavailable) {
			t.Errorf("%q mfa: %v", url, err)
		}
		if _, err := ip.svc.FinishKeyMFA(ctx, s, &auth.User{}, nil, meta); !errors.Is(err, auth.ErrWebAuthnUnavailable) {
			t.Errorf("%q mfa finish: %v", url, err)
		}
	}
	if st := newEnv(t, func(c *auth.Config) { c.PublicURL = "https://198.51.100.45" }).svc.WebAuthn(); !strings.Contains(st.Reason, "not an IP address") {
		t.Errorf("reason: %q", st.Reason)
	}
}

func TestSecurityKeyAsTheOnlySecondFactor(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	id, key, token := e.keyUser(t, "kim@example.com")
	s, u := e.session(t, token)
	if s.State != auth.StateActive || !u.MFAEnabled || u.TOTP || u.SecurityKeys != 1 {
		t.Fatalf("after set-up: %+v %+v", s, u)
	}
	if a := e.audits(t, "auth.webauthn_add", "success"); len(a) != 1 || a[0]["key"] != "YubiKey 5" || a[0]["firstFactor"] != true {
		t.Fatalf("audit: %+v", a)
	}
	keys, err := e.svc.SecurityKeys(ctx, id)
	if err != nil || len(keys) != 1 || keys[0].Name != "YubiKey 5" || keys[0].Synced || keys[0].LastUsedAt != nil {
		t.Fatalf("keys: %+v %v", keys, err)
	}

	// Next time the key is the second factor.
	e.now = e.now.Add(time.Minute)
	active, err := e.mfa(t, "kim@example.com", key)
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := e.session(t, active); s.State != auth.StateActive {
		t.Fatalf("state %s", s.State)
	}
	if a := e.audits(t, "auth.mfa_verify", "success"); len(a) != 1 || a[0]["method"] != "webauthn" || a[0]["key"] != "YubiKey 5" {
		t.Fatalf("audit: %+v", a)
	}
	if keys, _ := e.svc.SecurityKeys(ctx, id); keys[0].LastUsedAt == nil {
		t.Fatal("last use not recorded")
	}

	// A user with keys can still add an authenticator app, and keeps
	// working recovery codes.
	sess, user := e.session(t, active)
	if _, err := e.svc.BeginTOTPEnrollment(ctx, sess, user); err != nil {
		t.Fatalf("totp next to keys: %v", err)
	}
}

func TestSecurityKeyRefusals(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	_, key, _ := e.keyUser(t, "lee@example.com")
	failures := func(token string) int {
		var n int
		err := e.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT mfa_failures FROM sessions WHERE token_hash = $1`, auth.HashToken(token)).Scan(&n)
		})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	start := func() (string, *auth.Session, *auth.User, []byte) {
		e.svc.ResetLimits()
		tok, _, err := e.svc.Login(ctx, "lee@example.com", goodPassword, meta)
		if err != nil {
			t.Fatal(err)
		}
		s, u := e.session(t, tok)
		assertion, err := e.svc.BeginKeyMFA(ctx, s)
		if err != nil {
			t.Fatal(err)
		}
		return tok, s, u, asJSON(t, assertion)
	}

	// Another site (a phishing page relaying the request) gets nothing.
	tok, s, u, opts := start()
	key.Origin = "https://rmm.example.com.evil.test"
	if _, err := e.svc.FinishKeyMFA(ctx, s, u, key.Get(t, opts), meta); !errors.Is(err, auth.ErrKeyRejected) {
		t.Fatalf("wrong origin: %v", err)
	}
	key.Origin = origin
	if failures(tok) != 1 {
		t.Fatalf("failures %d", failures(tok))
	}
	a := e.audits(t, "auth.mfa_verify", "failure")
	if len(a) != 1 || a[0]["method"] != "webauthn" || !strings.Contains(a[0]["reason"].(string), "rigin") {
		t.Fatalf("audit: %+v", a)
	}

	// Each ceremony is used once: the challenge went with the failure.
	if _, err := e.svc.FinishKeyMFA(ctx, s, u, key.Get(t, opts), meta); !errors.Is(err, auth.ErrKeyRejected) {
		t.Fatalf("reused challenge: %v", err)
	}

	// A ceremony belongs to its sign-in session.
	_, s1, _, opts1 := start()
	_, s2, u2, _ := start()
	_ = s1
	if _, err := e.svc.FinishKeyMFA(ctx, s2, u2, key.Get(t, opts1), meta); !errors.Is(err, auth.ErrKeyRejected) {
		t.Fatalf("other session's challenge: %v", err)
	}

	// Too late.
	_, s, u, opts = start()
	e.now = e.now.Add(6 * time.Minute)
	if _, err := e.svc.FinishKeyMFA(ctx, s, u, key.Get(t, opts), meta); err == nil {
		t.Fatal("expired challenge accepted")
	}
	e.now = time.Now()

	// A registration answer is not a sign-in answer.
	_, s, u, opts = start()
	key.Type = "webauthn.create"
	if _, err := e.svc.FinishKeyMFA(ctx, s, u, key.Get(t, opts), meta); !errors.Is(err, auth.ErrKeyRejected) {
		t.Fatalf("wrong type: %v", err)
	}
	key.Type = ""

	// Answers to challenges the server never set.
	_, s, u, _ = start()
	for _, c := range []string{"", strings.Repeat("A", 200), "AAAAAAAAAAAAAAAAAAAAAA"} {
		forged := key.Get(t, asJSON(t, map[string]any{"publicKey": map[string]any{"challenge": c}}))
		if _, err := e.svc.FinishKeyMFA(ctx, s, u, forged, meta); !errors.Is(err, auth.ErrKeyRejected) {
			t.Fatalf("challenge %q: %v", c, err)
		}
	}

	// Garbage.
	_, s, u, _ = start()
	for _, body := range [][]byte{[]byte("{}"), []byte("not json"), []byte(`{"id":"x","rawId":"x","type":"public-key","response":{}}`), make([]byte, 70<<10)} {
		if _, err := e.svc.FinishKeyMFA(ctx, s, u, body, meta); !errors.Is(err, auth.ErrKeyRejected) && !errors.Is(err, auth.ErrInvalidSession) {
			t.Fatalf("garbage: %v", err)
		}
	}

	// A counter that does not move forward means a copied key.
	if _, err := e.mfa(t, "lee@example.com", key); err != nil {
		t.Fatal(err)
	}
	key.Counter -= 2
	if _, err := e.mfa(t, "lee@example.com", key); !errors.Is(err, auth.ErrKeyRejected) {
		t.Fatalf("counter went back: %v", err)
	}
	if a := e.audits(t, "auth.mfa_verify", "failure"); !strings.Contains(a[len(a)-1]["reason"].(string), "cloned") {
		t.Fatalf("clone audit: %+v", a[len(a)-1])
	}
	key.Counter += 10 // a genuine key's counter only rises

	// Enough refusals end the sign-in session, as wrong codes do.
	tok, s, u, _ = start()
	for i := 0; i < 5; i++ {
		_, _ = e.svc.FinishKeyMFA(ctx, s, u, []byte("{}"), meta)
	}
	if _, _, err := e.svc.Authenticate(ctx, tok); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("session survived: %v", err)
	}

	// Each user's attempts are rate-limited.
	_, s, u, _ = start()
	limited := false
	for i := 0; i < 15 && !limited; i++ {
		_, err := e.svc.FinishKeyMFA(ctx, s, u, []byte("{}"), meta)
		limited = errors.Is(err, auth.ErrRateLimited)
	}
	if !limited {
		t.Fatal("never rate-limited")
	}

	// The second-factor step is for sessions waiting for one.
	active, err := e.mfa(t, "lee@example.com", key)
	if err != nil {
		t.Fatal(err)
	}
	as, _ := e.session(t, active)
	if _, err := e.svc.BeginKeyMFA(ctx, as); !errors.Is(err, auth.ErrWrongState) {
		t.Errorf("begin when active: %v", err)
	}
	if _, err := e.svc.FinishKeyMFA(ctx, as, &auth.User{}, nil, meta); !errors.Is(err, auth.ErrWrongState) {
		t.Errorf("finish when active: %v", err)
	}
	// A TOTP-only user has no key to offer.
	e.createUser(t, "totp@example.com")
	_, _, _ = e.enroll(t, "totp@example.com")
	tok2, _, _ := e.svc.Login(ctx, "totp@example.com", goodPassword, meta)
	s3, _ := e.session(t, tok2)
	if _, err := e.svc.BeginKeyMFA(ctx, s3); !errors.Is(err, auth.ErrWrongState) {
		t.Errorf("no keys: %v", err)
	}
}

func TestPasskeySignIn(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	id, key, _ := e.keyUser(t, "pat@example.com")

	tok, err := e.passkey(t, key, meta)
	if err != nil {
		t.Fatal(err)
	}
	s, u := e.session(t, tok)
	if s.State != auth.StateActive || u.ID != id {
		t.Fatalf("session: %+v %+v", s, u)
	}
	if a := e.audits(t, "auth.login", "success"); a[len(a)-1]["method"] != "passkey" || a[len(a)-1]["key"] != "YubiKey 5" {
		t.Fatalf("audit: %+v", a[len(a)-1])
	}

	// Without user verification a passkey is only one factor.
	key.UV = false
	if _, err := e.passkey(t, key, meta); !errors.Is(err, auth.ErrKeyRejected) {
		t.Fatalf("no UV: %v", err)
	}
	key.UV = true

	// A credential claiming another user's handle.
	other, _, _ := e.keyUser(t, "other@example.com")
	key.SetUserHandle(other[:])
	if _, err := e.passkey(t, key, meta); !errors.Is(err, auth.ErrKeyRejected) {
		t.Fatalf("other handle: %v", err)
	}
	key.SetUserHandle([]byte("not a uuid"))
	if _, err := e.passkey(t, key, meta); !errors.Is(err, auth.ErrKeyRejected) {
		t.Fatalf("junk handle: %v", err)
	}
	key.SetUserHandle(id[:])

	// A disabled account.
	err = e.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET status = 'disabled' WHERE id = $1`, id)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.passkey(t, key, meta); !errors.Is(err, auth.ErrKeyRejected) {
		t.Fatalf("disabled: %v", err)
	}
	fails := e.audits(t, "auth.login", "failure")
	if r := fails[len(fails)-1]; r["method"] != "passkey" || r["reason"] != "the account is not active" {
		t.Fatalf("audit: %+v", r)
	}

	// Junk and expired answers.
	e.svc.ResetLimits()
	if _, _, err := e.svc.FinishPasskeyLogin(ctx, []byte("{}"), meta); !errors.Is(err, auth.ErrKeyRejected) {
		t.Fatalf("junk: %v", err)
	}
	assertion, err := e.svc.BeginPasskeyLogin(ctx, meta)
	if err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(6 * time.Minute)
	if _, _, err := e.svc.FinishPasskeyLogin(ctx, key.Get(t, asJSON(t, assertion)), meta); !errors.Is(err, auth.ErrKeyRejected) {
		t.Fatalf("expired: %v", err)
	}

	// Rate-limited per address.
	busy := auth.RequestMeta{IP: netip.MustParseAddr("203.0.113.9")}
	limited := false
	for i := 0; i < 15 && !limited; i++ {
		_, err := e.svc.BeginPasskeyLogin(ctx, busy)
		limited = errors.Is(err, auth.ErrRateLimited)
	}
	if !limited {
		t.Fatal("never rate-limited")
	}
	if _, _, err := e.svc.FinishPasskeyLogin(ctx, []byte("{}"), busy); !errors.Is(err, auth.ErrRateLimited) {
		t.Fatalf("finish rate limit: %v", err)
	}
}

func TestSecurityKeysFromTheAccountPage(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	id := e.createUser(t, "ann@example.com")
	_, token, _ := e.enroll(t, "ann@example.com")

	// Signed in, the password is needed.
	if _, err := e.register(t, token, "wrong-password-1", "Laptop", webauthntest.New(t, rpID, origin)); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	laptop := webauthntest.New(t, rpID, origin)
	laptop.Synced = true
	added, err := e.register(t, token, goodPassword, "  Laptop  ", laptop)
	if err != nil {
		t.Fatal(err)
	}
	// Not the first factor: no new recovery codes, no new token.
	if added.Token != "" || added.RecoveryCodes != nil || added.Key.Name != "Laptop" || !added.Key.Synced {
		t.Fatalf("added: %+v", added)
	}

	// Names: required, short, printable, and one of each per user.
	for _, name := range []string{"", "   ", strings.Repeat("k", 65), "bad\x00name"} {
		if _, err := e.register(t, token, goodPassword, name, webauthntest.New(t, rpID, origin)); !errors.Is(err, auth.ErrKeyName) {
			t.Errorf("name %q: %v", name, err)
		}
	}
	if _, err := e.register(t, token, goodPassword, "Laptop", webauthntest.New(t, rpID, origin)); !errors.Is(err, auth.ErrKeyNameTaken) {
		t.Fatalf("same name: %v", err)
	}
	if _, err := e.register(t, token, goodPassword, strings.Repeat("é", 64), webauthntest.New(t, rpID, origin)); err != nil {
		t.Fatalf("64 characters: %v", err)
	}

	// The browser is told which keys exist, so it does not make a second
	// credential on the same key.
	s, _ := e.session(t, token)
	creation, err := e.svc.BeginKeyRegistration(ctx, s, goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(asJSON(t, creation)), b64(laptop.CredentialID())) {
		t.Fatal("existing key not excluded")
	}

	// At most ten.
	for i := 0; i < 8; i++ {
		if _, err := e.register(t, token, goodPassword, "Key "+string(rune('A'+i)), webauthntest.New(t, rpID, origin)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.svc.BeginKeyRegistration(ctx, s, goodPassword); !errors.Is(err, auth.ErrTooManyKeys) {
		t.Fatalf("eleventh: %v", err)
	}
	keys, err := e.svc.SecurityKeys(ctx, id)
	if err != nil || len(keys) != 10 || keys[0].Name != "Laptop" {
		t.Fatalf("keys: %d %v", len(keys), err)
	}

	// The sign-in step offers the keys, and the app still works.
	e.now = e.now.Add(time.Minute)
	if _, err := e.mfa(t, "ann@example.com", laptop); err != nil {
		t.Fatal(err)
	}

	// Removing: the password again; someone else's key is not found.
	s, u := e.session(t, token)
	if err := e.svc.RemoveSecurityKey(ctx, s, u, keys[0].ID, "wrong-password-1", meta); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if err := e.svc.RemoveSecurityKey(ctx, s, u, uuid.New(), goodPassword, meta); !errors.Is(err, auth.ErrKeyNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	if err := e.svc.RemoveSecurityKey(ctx, s, u, keys[0].ID, goodPassword, meta); err != nil {
		t.Fatal(err)
	}
	if a := e.audits(t, "auth.webauthn_remove", "success"); len(a) != 1 || a[0]["key"] != "Laptop" {
		t.Fatalf("audit: %+v", a)
	}
	// Ann has the app, so every key can go.
	for _, k := range keys[1:] {
		e.svc.ResetLimits()
		if err := e.svc.RemoveSecurityKey(ctx, s, u, k.ID, goodPassword, meta); err != nil {
			t.Fatal(err)
		}
	}

	// Only while signed in.
	s.State = auth.StateMFARequired
	if _, err := e.svc.BeginKeyRegistration(ctx, s, goodPassword); !errors.Is(err, auth.ErrWrongState) {
		t.Errorf("register mid sign-in: %v", err)
	}
	if _, err := e.svc.FinishKeyRegistration(ctx, s, u, "x", nil, meta); !errors.Is(err, auth.ErrWrongState) {
		t.Errorf("finish mid sign-in: %v", err)
	}
	if err := e.svc.RemoveSecurityKey(ctx, s, u, keys[0].ID, goodPassword, meta); !errors.Is(err, auth.ErrWrongState) {
		t.Errorf("remove mid sign-in: %v", err)
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func TestTheLastSecondFactorStays(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	id, _, token := e.keyUser(t, "max@example.com")
	keys, _ := e.svc.SecurityKeys(ctx, id)
	s, u := e.session(t, token)
	if err := e.svc.RemoveSecurityKey(ctx, s, u, keys[0].ID, goodPassword, meta); !errors.Is(err, auth.ErrLastFactor) {
		t.Fatalf("last key: %v", err)
	}
	// With a second key, the first can go.
	if _, err := e.register(t, token, goodPassword, "Spare", webauthntest.New(t, rpID, origin)); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RemoveSecurityKey(ctx, s, u, keys[0].ID, goodPassword, meta); err != nil {
		t.Fatal(err)
	}

	// Where MFA is optional, sign-in is complete without one; a first key
	// added from the account page still brings recovery codes, and the last
	// key can go.
	o := newEnv(t, func(c *auth.Config) { c.RequireMFA = false })
	oid := o.createUser(t, "opt@example.com")
	otoken, sess, err := o.svc.Login(ctx, "opt@example.com", goodPassword, meta)
	if err != nil || sess.State != auth.StateActive {
		t.Fatalf("optional login: %v %v", sess, err)
	}
	added, err := o.register(t, otoken, goodPassword, "Only", webauthntest.New(t, rpID, origin))
	if err != nil || len(added.RecoveryCodes) != 10 || added.Token != "" {
		t.Fatalf("optional first key: %+v %v", added, err)
	}
	okeys, _ := o.svc.SecurityKeys(ctx, oid)
	os, ou := o.session(t, otoken)
	if err := o.svc.RemoveSecurityKey(ctx, os, ou, okeys[0].ID, goodPassword, meta); err != nil {
		t.Fatalf("optional MFA: %v", err)
	}
	// And then signing in needs no second factor.
	if _, sess, err := o.svc.Login(ctx, "opt@example.com", goodPassword, meta); err != nil || sess.State != auth.StateActive {
		t.Fatalf("login: %v %v", sess, err)
	}
}

func TestRegistrationRefusals(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	e.createUser(t, "zed@example.com")
	tok, _, err := e.svc.Login(ctx, "zed@example.com", goodPassword, meta)
	if err != nil {
		t.Fatal(err)
	}
	s, u := e.session(t, tok)
	try := func(mutate func(*webauthntest.Authenticator)) error {
		creation, err := e.svc.BeginKeyRegistration(ctx, s, "")
		if err != nil {
			t.Fatal(err)
		}
		k := webauthntest.New(t, rpID, origin)
		mutate(k)
		_, err = e.svc.FinishKeyRegistration(ctx, s, u, "Key", k.Create(t, asJSON(t, creation)), meta)
		return err
	}
	if err := try(func(k *webauthntest.Authenticator) { k.Origin = "https://evil.test" }); !errors.Is(err, auth.ErrKeyRejected) {
		t.Fatalf("origin: %v", err)
	}
	if err := try(func(k *webauthntest.Authenticator) { k.RPID = "evil.test" }); !errors.Is(err, auth.ErrKeyRejected) {
		t.Fatalf("rp id: %v", err)
	}
	if err := try(func(k *webauthntest.Authenticator) { k.Type = "webauthn.get" }); !errors.Is(err, auth.ErrKeyRejected) {
		t.Fatalf("type: %v", err)
	}
	if _, err := e.svc.FinishKeyRegistration(ctx, s, u, "Key", []byte("{}"), meta); !errors.Is(err, auth.ErrKeyRejected) {
		t.Fatalf("junk: %v", err)
	}
	if _, err := e.svc.FinishKeyRegistration(ctx, s, u, "Key", make([]byte, 70<<10), meta); !errors.Is(err, auth.ErrKeyRejected) {
		t.Fatalf("huge: %v", err)
	}
	if a := e.audits(t, "auth.webauthn_add", "failure"); len(a) < 4 {
		t.Fatalf("audit: %+v", a)
	}
	// Still waiting for a second factor.
	if s2, _ := e.session(t, tok); s2.State != auth.StateMFAEnrollment {
		t.Fatalf("state %s", s2.State)
	}
}

func TestRegistrationRaces(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	ivy, key, token := e.keyUser(t, "ivy@example.com")
	s, u := e.session(t, token)

	// Confirming the password is rate-limited.
	limited := false
	for i := 0; i < 15 && !limited; i++ {
		_, err := e.svc.BeginKeyRegistration(ctx, s, "wrong-password-1")
		limited = errors.Is(err, auth.ErrRateLimited)
	}
	if !limited {
		t.Fatal("never rate-limited")
	}

	// An answer is accepted once.
	e.svc.ResetLimits()
	creation, err := e.svc.BeginKeyRegistration(ctx, s, goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	spare := webauthntest.New(t, rpID, origin)
	answer := spare.Create(t, asJSON(t, creation))
	if _, err := e.svc.FinishKeyRegistration(ctx, s, u, "Spare", answer, meta); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.FinishKeyRegistration(ctx, s, u, "Spare 2", answer, meta); !errors.Is(err, auth.ErrKeyRejected) {
		t.Fatalf("replayed answer: %v", err)
	}

	// A credential can belong to one account only.
	e.createUser(t, "joe@example.com")
	jtok, _, err := e.svc.Login(ctx, "joe@example.com", goodPassword, meta)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.register(t, jtok, "", "Borrowed", key); !errors.Is(err, auth.ErrKeyExists) {
		t.Fatalf("another account's key: %v", err)
	}
	key.SetUserHandle(ivy[:]) // the attempt gave the key Joe's handle

	// Two registrations started at nine keys, from two signed-in sessions:
	// the second to finish is refused.
	for i := 0; i < 7; i++ {
		if _, err := e.register(t, token, goodPassword, "Key "+string(rune('A'+i)), webauthntest.New(t, rpID, origin)); err != nil {
			t.Fatal(err)
		}
	}
	second, err := e.mfa(t, "ivy@example.com", key)
	if err != nil {
		t.Fatal(err)
	}
	s2, u2 := e.session(t, second)
	e.svc.ResetLimits()
	c1, err := e.svc.BeginKeyRegistration(ctx, s, goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := e.svc.BeginKeyRegistration(ctx, s2, goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.FinishKeyRegistration(ctx, s, u, "Tenth", webauthntest.New(t, rpID, origin).Create(t, asJSON(t, c1)), meta); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.FinishKeyRegistration(ctx, s2, u2, "Eleventh", webauthntest.New(t, rpID, origin).Create(t, asJSON(t, c2)), meta); !errors.Is(err, auth.ErrTooManyKeys) {
		t.Fatalf("eleventh key: %v", err)
	}
}
