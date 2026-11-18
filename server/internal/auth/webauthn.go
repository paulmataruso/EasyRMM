package auth

// Security keys and passkeys (ADR-0032). go-webauthn checks the protocol:
// client data, authenticator data, keys and signatures. This file decides
// who may register a key, when a key counts, and what is stored and audited.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

const (
	// MaxSecurityKeys is how many keys one user may register.
	MaxSecurityKeys = 10
	// MaxKeyName is the longest key name, in characters.
	MaxKeyName = 64
	// ceremonyTTL is how long the browser has to answer.
	ceremonyTTL = 5 * time.Minute
	// maxCeremonyBody bounds what the browser sends back.
	maxCeremonyBody = 64 << 10
)

// Errors for security keys and passkeys.
var (
	ErrWebAuthnUnavailable = errors.New("security keys and passkeys are not available on this server")
	ErrKeyRejected         = errors.New("the security key or passkey was not accepted")
	ErrKeyName             = errors.New("invalid security key name")
	ErrKeyNameTaken        = errors.New("a security key with this name exists")
	ErrKeyExists           = errors.New("this security key is already registered")
	ErrTooManyKeys         = errors.New("too many security keys")
	ErrLastFactor          = errors.New("this is the account's last second factor")
	ErrKeyNotFound         = errors.New("security key not found")
)

const (
	ceremonyRegister = "register"
	ceremonyMFA      = "mfa"
	ceremonyPasskey  = "passkey"
)

// WebAuthnStatus says whether security keys and passkeys can be used, and
// where.
type WebAuthnStatus struct {
	Available bool `json:"available"`
	// Origin is the only address the browser may use them at.
	Origin string `json:"origin,omitempty"`
	// Reason explains why they are unavailable.
	Reason string `json:"reason,omitempty"`
}

// SecurityKey is a registered security key or passkey, as its owner sees it.
type SecurityKey struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	// Synced keys (backup eligible) are copied between a person's devices by
	// their password manager or platform.
	Synced bool `json:"synced"`
}

// KeyAdded is the result of registering a key.
type KeyAdded struct {
	Key SecurityKey
	// RecoveryCodes are issued when this is the user's first second factor.
	RecoveryCodes []string
	// Token is the rotated session token when this finished sign-in.
	Token string
}

// configureWebAuthn derives the relying party from the public URL. Browsers
// refuse WebAuthn on IP addresses, so an IP-only deployment goes without.
func (s *Service) configureWebAuthn() {
	s.waStatus = WebAuthnStatus{Reason: "EasyRMM's public address is not set."}
	u, err := url.Parse(s.cfg.PublicURL)
	if err != nil || u.Hostname() == "" {
		return
	}
	host := u.Hostname()
	if net.ParseIP(host) != nil {
		s.waStatus.Reason = "Security keys and passkeys need EasyRMM to be reached by a name (EASYRMM_PUBLIC_URL), not an IP address."
		return
	}
	origin := u.Scheme + "://" + u.Host
	wa, err := webauthn.New(&webauthn.Config{
		RPID:                  host,
		RPDisplayName:         "EasyRMM",
		RPOrigins:             []string{origin},
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			RequireResidentKey: protocol.ResidentKeyNotRequired(),
			ResidentKey:        protocol.ResidentKeyRequirementPreferred,
			UserVerification:   protocol.VerificationPreferred,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: ceremonyTTL, TimeoutUVD: ceremonyTTL},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: ceremonyTTL, TimeoutUVD: ceremonyTTL},
		},
	})
	if err != nil {
		s.waStatus.Reason = "Security keys and passkeys could not be set up for " + host + "."
		return
	}
	s.wa = wa
	s.waStatus = WebAuthnStatus{Available: true, Origin: origin}
}

// WebAuthn reports whether security keys and passkeys can be used.
func (s *Service) WebAuthn() WebAuthnStatus { return s.waStatus }

// waUser is a user as go-webauthn sees them. The user handle is the user's
// id: random, and nothing personal.
type waUser struct {
	id      uuid.UUID
	email   string
	name    string
	status  string
	creds   []webauthn.Credential
	rows    []uuid.UUID // the row of each credential
	names   []string
	hasTOTP bool
}

func (u *waUser) WebAuthnID() []byte                         { return u.id[:] }
func (u *waUser) WebAuthnName() string                       { return u.email }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }
func (u *waUser) WebAuthnDisplayName() string                { return u.name }

// row finds the stored row of a credential.
func (u *waUser) row(credID []byte) (uuid.UUID, string, bool) {
	for i, c := range u.creds {
		if string(c.ID) == string(credID) {
			return u.rows[i], u.names[i], true
		}
	}
	return uuid.Nil, "", false
}

func (s *Service) loadWAUser(ctx context.Context, q pgx.Tx, id uuid.UUID) (*waUser, error) {
	u := &waUser{id: id}
	var totp *time.Time
	err := q.QueryRow(ctx, `SELECT email, display_name, status, totp_enabled_at FROM users WHERE id = $1`, id).Scan(&u.email, &u.name, &u.status, &totp)
	if err != nil {
		return nil, err
	}
	u.hasTOTP = totp != nil
	rows, err := q.Query(ctx, `SELECT id, name, credential FROM user_webauthn_credentials WHERE user_id = $1 ORDER BY created_at`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var row uuid.UUID
		var name string
		var raw []byte
		if err := rows.Scan(&row, &name, &raw); err != nil {
			return nil, err
		}
		var c webauthn.Credential
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("auth: reading security key %s: %w", row, err)
		}
		u.creds = append(u.creds, c)
		u.rows = append(u.rows, row)
		u.names = append(u.names, name)
	}
	return u, rows.Err()
}

// readWAUser loads a user and their keys in a transaction of its own.
func (s *Service) readWAUser(ctx context.Context, id uuid.UUID) (*waUser, error) {
	var u *waUser
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		var err error
		u, err = s.loadWAUser(ctx, tx, id)
		return err
	})
	return u, err
}

// saveCeremony keeps what the browser was asked for until it answers. A
// session has one ceremony of each kind at a time.
func (s *Service) saveCeremony(ctx context.Context, kind string, session *uuid.UUID, data *webauthn.SessionData) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM webauthn_challenges WHERE expires_at < $1`, s.now()); err != nil {
			return err
		}
		if session != nil {
			if _, err := tx.Exec(ctx, `DELETE FROM webauthn_challenges WHERE session_id = $1 AND kind = $2`, *session, kind); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `INSERT INTO webauthn_challenges (challenge, kind, session_id, data, expires_at) VALUES ($1, $2, $3, $4, $5)`,
			data.Challenge, kind, session, raw, s.now().Add(ceremonyTTL))
		return err
	})
}

// takeCeremony finds the ceremony the browser answered, by the challenge in
// its answer, and removes it: each is used once. It must be of the expected
// kind, for the expected session, and not expired.
func (s *Service) takeCeremony(ctx context.Context, challenge, kind string, session *uuid.UUID) (*webauthn.SessionData, error) {
	if challenge == "" || len(challenge) > 128 {
		return nil, ErrKeyRejected
	}
	var gotKind string
	var gotSession *uuid.UUID
	var raw []byte
	var expires time.Time
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `DELETE FROM webauthn_challenges WHERE challenge = $1 RETURNING kind, session_id, data, expires_at`, challenge).
			Scan(&gotKind, &gotSession, &raw, &expires)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrKeyRejected
	}
	if err != nil {
		return nil, err
	}
	sameSession := (session == nil && gotSession == nil) || (session != nil && gotSession != nil && *session == *gotSession)
	if gotKind != kind || !sameSession || !s.now().Before(expires) {
		return nil, ErrKeyRejected
	}
	var data webauthn.SessionData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// checkKeyName tidies a key's name and says whether it is acceptable.
func checkKeyName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > MaxKeyName || !utf8.ValidString(name) {
		return "", ErrKeyName
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", ErrKeyName
		}
	}
	return name, nil
}

// canRegisterKey: while setting up a second factor at sign-in, or signed in.
func canRegisterKey(sess *Session) bool {
	return sess.State == StateMFAEnrollment || sess.State == StateActive
}

// BeginKeyRegistration asks the browser to create a credential. Signed-in
// users enter their password again, so a stolen session alone cannot add a
// key that outlives it; while setting up a second factor at sign-in the
// password was just entered.
func (s *Service) BeginKeyRegistration(ctx context.Context, sess *Session, password string, meta RequestMeta) (*protocol.CredentialCreation, error) {
	if s.wa == nil {
		return nil, ErrWebAuthnUnavailable
	}
	if !canRegisterKey(sess) {
		return nil, ErrWrongState
	}
	if sess.State == StateActive {
		if err := s.reauthenticate(ctx, sess, password, "auth.webauthn_add", meta); err != nil {
			return nil, err
		}
	}
	u, err := s.readWAUser(ctx, sess.UserID)
	if err != nil {
		return nil, err
	}
	if len(u.creds) >= MaxSecurityKeys {
		return nil, ErrTooManyKeys
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(u.creds))
	for _, c := range u.creds {
		exclude = append(exclude, c.Descriptor())
	}
	creation, data, err := s.wa.BeginRegistration(u, webauthn.WithExclusions(exclude))
	if err != nil {
		return nil, fmt.Errorf("auth: starting key registration: %w", err)
	}
	if err := s.saveCeremony(ctx, ceremonyRegister, &sess.ID, data); err != nil {
		return nil, err
	}
	return creation, nil
}

// PasskeyPromptDelay is how long "Not now" puts off the offer of a passkey.
const PasskeyPromptDelay = 30 * 24 * time.Hour

// AnswerPasskeyPrompt records the answer to the offer of a passkey after
// sign-in: later puts it off for PasskeyPromptDelay; otherwise it is not
// offered again. Keys can always be added from the Account page.
func (s *Service) AnswerPasskeyPrompt(ctx context.Context, sess *Session, never bool) error {
	if sess.State != StateActive {
		return ErrWrongState
	}
	q, at := `UPDATE users SET passkey_prompt_after = $2 WHERE id = $1`, s.now().Add(PasskeyPromptDelay)
	if never {
		q, at = `UPDATE users SET passkey_prompt_declined_at = $2 WHERE id = $1`, s.now()
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, q, sess.UserID, at)
		return err
	})
}

// FinishKeyRegistration checks the browser's new credential and stores it.
// A user's first second factor brings recovery codes, and finishes sign-in
// when it was set up at sign-in.
func (s *Service) FinishKeyRegistration(ctx context.Context, sess *Session, user *User, name string, body []byte, meta RequestMeta) (*KeyAdded, error) {
	if s.wa == nil {
		return nil, ErrWebAuthnUnavailable
	}
	if !canRegisterKey(sess) {
		return nil, ErrWrongState
	}
	name, err := checkKeyName(name)
	if err != nil {
		return nil, err
	}
	if len(body) > maxCeremonyBody {
		return nil, ErrKeyRejected
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		return nil, s.keyFailure(ctx, sess.UserID, user.Email, "auth.webauthn_add", meta, err)
	}
	data, err := s.takeCeremony(ctx, parsed.Response.CollectedClientData.Challenge, ceremonyRegister, &sess.ID)
	if err != nil {
		return nil, s.keyFailure(ctx, sess.UserID, user.Email, "auth.webauthn_add", meta, err)
	}
	u, err := s.readWAUser(ctx, sess.UserID)
	if err != nil {
		return nil, err
	}
	cred, err := s.wa.CreateCredential(u, *data, parsed)
	if err != nil {
		return nil, s.keyFailure(ctx, sess.UserID, user.Email, "auth.webauthn_add", meta, err)
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	out := &KeyAdded{Key: SecurityKey{Name: name, CreatedAt: s.now(), Synced: cred.Flags.BackupEligible}}
	codes, err := NewRecoveryCodes()
	if err != nil {
		return nil, err
	}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var hasTOTP bool
		var keys int
		if err := tx.QueryRow(ctx, `SELECT totp_enabled_at IS NOT NULL, (SELECT count(*) FROM user_webauthn_credentials WHERE user_id = u.id)
			FROM users u WHERE u.id = $1 FOR UPDATE`, sess.UserID).Scan(&hasTOTP, &keys); err != nil {
			return err
		}
		if keys >= MaxSecurityKeys {
			return ErrTooManyKeys
		}
		if err := tx.QueryRow(ctx, `INSERT INTO user_webauthn_credentials (user_id, credential_id, name, credential, created_at)
			VALUES ($1, $2, $3, $4, $5) RETURNING id`, sess.UserID, cred.ID, name, raw, out.Key.CreatedAt).Scan(&out.Key.ID); err != nil {
			var pg *pgconn.PgError
			if errors.As(err, &pg) && pg.Code == "23505" {
				if pg.ConstraintName == "user_webauthn_credentials_user_id_name_key" {
					return ErrKeyNameTaken
				}
				return ErrKeyExists
			}
			return err
		}
		first := !hasTOTP && keys == 0
		if first {
			if err := replaceRecoveryCodes(ctx, tx, sess.UserID, codes); err != nil {
				return err
			}
			out.RecoveryCodes = codes
		}
		if sess.State == StateMFAEnrollment {
			var err error
			if out.Token, err = s.rotate(ctx, tx, sess.ID, StateActive, MethodKey); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE users SET last_login_at = now() WHERE id = $1`, sess.UserID); err != nil {
				return err
			}
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: userActor(sess.UserID, user.Email, meta), Action: "auth.webauthn_add", Outcome: audit.Success,
			TargetType: "user", TargetID: sess.UserID.String(), Details: map[string]any{"key": name, "synced": out.Key.Synced, "firstFactor": first}})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// keyFailure audits a refused key and returns the error for the caller.
// Protocol details go to the audit log, never to the browser.
func (s *Service) keyFailure(ctx context.Context, userID uuid.UUID, email, action string, meta RequestMeta, cause error) error {
	actor := anonymousActor(email, meta)
	if userID != uuid.Nil {
		actor = userActor(userID, email, meta)
	}
	_ = s.audit.Record(ctx, audit.Event{Actor: actor, Action: action, Outcome: audit.Failure, Details: map[string]any{"reason": keyReason(cause)}})
	return ErrKeyRejected
}

// keyReason describes why a key was refused, for the audit log.
func keyReason(err error) string {
	var pe *protocol.Error
	switch {
	case errors.As(err, &pe):
		r := pe.Type
		if pe.Details != "" {
			r += ": " + pe.Details
		}
		return truncateString(r, 300)
	case errors.Is(err, ErrKeyRejected):
		return "unknown or expired ceremony"
	}
	return truncateString(err.Error(), 300)
}

// BeginKeyMFA asks the browser for one of the user's keys, as the second
// factor after their password.
func (s *Service) BeginKeyMFA(ctx context.Context, sess *Session) (*protocol.CredentialAssertion, error) {
	if s.wa == nil {
		return nil, ErrWebAuthnUnavailable
	}
	if sess.State != StateMFARequired {
		return nil, ErrWrongState
	}
	u, err := s.readWAUser(ctx, sess.UserID)
	if err != nil {
		return nil, err
	}
	if len(u.creds) == 0 {
		return nil, ErrWrongState
	}
	// The password was the first factor: presence is enough here.
	assertion, data, err := s.wa.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationDiscouraged))
	if err != nil {
		return nil, fmt.Errorf("auth: starting key sign-in: %w", err)
	}
	if err := s.saveCeremony(ctx, ceremonyMFA, &sess.ID, data); err != nil {
		return nil, err
	}
	return assertion, nil
}

// FinishKeyMFA completes sign-in with a security key. A refused key counts
// as a wrong code. It returns a new session token.
func (s *Service) FinishKeyMFA(ctx context.Context, sess *Session, user *User, body []byte, meta RequestMeta) (string, error) {
	if s.wa == nil {
		return "", ErrWebAuthnUnavailable
	}
	if sess.State != StateMFARequired {
		return "", ErrWrongState
	}
	if !s.mfaLimit.Allow("mfa:" + sess.UserID.String()) {
		return "", ErrRateLimited
	}
	var cred *webauthn.Credential
	var u *waUser
	verify := func() error {
		if len(body) > maxCeremonyBody {
			return ErrKeyRejected
		}
		parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
		if err != nil {
			return err
		}
		data, err := s.takeCeremony(ctx, parsed.Response.CollectedClientData.Challenge, ceremonyMFA, &sess.ID)
		if err != nil {
			return err
		}
		if u, err = s.readWAUser(ctx, sess.UserID); err != nil {
			return fmt.Errorf("loading keys: %w", err)
		}
		if cred, err = s.wa.ValidateLogin(u, *data, parsed); err != nil {
			return err
		}
		if cred.Authenticator.CloneWarning {
			return errCloned
		}
		return nil
	}
	failure := verify()
	var token string
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if failure != nil {
			// A key's answer cannot be guessed, so a refused key counts
			// against this session only, not the account (see codeFailed).
			failures, err := s.sessionMFAFailed(ctx, tx, sess.ID)
			if err != nil {
				return err
			}
			return s.audit.Write(ctx, tx, audit.Event{Actor: userActor(sess.UserID, user.Email, meta), Action: "auth.mfa_verify", Outcome: audit.Failure,
				TargetType: "session", TargetID: sess.ID.String(), Details: map[string]any{"method": "webauthn", "failures": failures, "reason": keyReason(failure)}})
		}
		name, err := s.keyUsed(ctx, tx, u, cred)
		if err != nil {
			return err
		}
		if token, err = s.rotate(ctx, tx, sess.ID, StateActive, MethodKey); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET last_login_at = now(), mfa_failed_attempts = 0 WHERE id = $1`, sess.UserID); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: userActor(sess.UserID, user.Email, meta), Action: "auth.mfa_verify", Outcome: audit.Success,
			TargetType: "session", TargetID: sess.ID.String(), Details: map[string]any{"method": "webauthn", "key": name}})
	})
	if err != nil {
		return "", fmt.Errorf("auth: verifying security key: %w", err)
	}
	if failure != nil {
		return "", ErrKeyRejected
	}
	return token, nil
}

// errCloned: the key's signature counter went backwards or stood still.
var errCloned = errors.New("the key's signature counter did not increase; it may have been cloned")

// keyUsed records a key's new counter, flags and last use, and returns its
// name.
func (s *Service) keyUsed(ctx context.Context, tx pgx.Tx, u *waUser, cred *webauthn.Credential) (string, error) {
	row, name, ok := u.row(cred.ID)
	if !ok {
		return "", ErrKeyRejected
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		return "", err
	}
	_, err = tx.Exec(ctx, `UPDATE user_webauthn_credentials SET credential = $2, last_used_at = $3 WHERE id = $1`, row, raw, s.now())
	return name, err
}

// BeginPasskeyLogin asks the browser for any passkey it holds for EasyRMM.
// The person must be verified (PIN or biometric): with the passkey, that
// is two factors, so no password is asked for.
func (s *Service) BeginPasskeyLogin(ctx context.Context, meta RequestMeta) (*protocol.CredentialAssertion, error) {
	if s.wa == nil {
		return nil, ErrWebAuthnUnavailable
	}
	if meta.IP.IsValid() && !s.ipLimit.Allow("passkey:"+LimitKey(meta.IP)) {
		return nil, ErrRateLimited
	}
	assertion, data, err := s.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, fmt.Errorf("auth: starting passkey sign-in: %w", err)
	}
	if err := s.saveCeremony(ctx, ceremonyPasskey, nil, data); err != nil {
		return nil, err
	}
	return assertion, nil
}

// FinishPasskeyLogin signs in with a passkey and opens a fully signed-in
// session. Failures are audited and rate-limited; they do not lock the
// account, since no password was tried.
func (s *Service) FinishPasskeyLogin(ctx context.Context, body []byte, meta RequestMeta) (string, *Session, error) {
	if s.wa == nil {
		return "", nil, ErrWebAuthnUnavailable
	}
	if meta.IP.IsValid() && !s.ipLimit.Allow("passkey:"+LimitKey(meta.IP)) {
		return "", nil, ErrRateLimited
	}
	var u *waUser
	var cred *webauthn.Credential
	verify := func() error {
		if len(body) > maxCeremonyBody {
			return ErrKeyRejected
		}
		parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
		if err != nil {
			return err
		}
		data, err := s.takeCeremony(ctx, parsed.Response.CollectedClientData.Challenge, ceremonyPasskey, nil)
		if err != nil {
			return err
		}
		find := func(_, handle []byte) (webauthn.User, error) {
			id, err := uuid.FromBytes(handle)
			if err != nil {
				return nil, errors.New("the user handle is not an EasyRMM user")
			}
			found, err := s.readWAUser(ctx, id)
			if err != nil {
				return nil, errors.New("no such user")
			}
			u = found
			return found, nil
		}
		if _, cred, err = s.wa.ValidatePasskeyLogin(find, *data, parsed); err != nil {
			return err
		}
		if cred.Authenticator.CloneWarning {
			return errCloned
		}
		if u.status != "active" {
			return errors.New("the account is not active")
		}
		return nil
	}
	if failure := verify(); failure != nil {
		var id uuid.UUID
		var email string
		if u != nil {
			id, email = u.id, u.email
		}
		_ = s.audit.Record(ctx, audit.Event{Actor: s.passkeyActor(id, email, meta), Action: "auth.login", Outcome: audit.Failure,
			Details: map[string]any{"method": "passkey", "reason": keyReason(failure)}})
		return "", nil, ErrKeyRejected
	}
	var token string
	var sess *Session
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		name, err := s.keyUsed(ctx, tx, u, cred)
		if err != nil {
			return err
		}
		// A passkey sign-in requires user verification: possession and a PIN or biometric.
		if token, sess, err = s.createSession(ctx, tx, u.id, StateActive, meta, MethodKey, MethodMultiFactor); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET last_login_at = now(), mfa_failed_attempts = 0 WHERE id = $1`, u.id); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: userActor(u.id, u.email, meta), Action: "auth.login", Outcome: audit.Success,
			TargetType: "session", TargetID: sess.ID.String(), Details: map[string]any{"state": string(StateActive), "method": "passkey", "key": name}})
	})
	if err != nil {
		return "", nil, fmt.Errorf("auth: passkey sign-in: %w", err)
	}
	return token, sess, nil
}

func (s *Service) passkeyActor(id uuid.UUID, email string, meta RequestMeta) audit.Actor {
	if id == uuid.Nil {
		return anonymousActor("passkey", meta)
	}
	return userActor(id, email, meta)
}

// SecurityKeys lists a user's keys, oldest first.
func (s *Service) SecurityKeys(ctx context.Context, userID uuid.UUID) ([]SecurityKey, error) {
	out := []SecurityKey{}
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, name, created_at, last_used_at, coalesce((credential->'flags'->>'backupEligible')::boolean, false)
			FROM user_webauthn_credentials WHERE user_id = $1 ORDER BY created_at, id`, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k SecurityKey
			if err := rows.Scan(&k.ID, &k.Name, &k.CreatedAt, &k.LastUsedAt, &k.Synced); err != nil {
				return err
			}
			out = append(out, k)
		}
		return rows.Err()
	})
	return out, err
}

// RemoveSecurityKey deletes one of the signed-in user's keys after they
// enter their password again. The last second factor stays while MFA is
// required.
func (s *Service) RemoveSecurityKey(ctx context.Context, sess *Session, user *User, keyID uuid.UUID, password string, meta RequestMeta) error {
	if sess.State != StateActive {
		return ErrWrongState
	}
	if err := s.reauthenticate(ctx, sess, password, "auth.webauthn_remove", meta); err != nil {
		return err
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var hasTOTP bool
		var keys int
		if err := tx.QueryRow(ctx, `SELECT totp_enabled_at IS NOT NULL, (SELECT count(*) FROM user_webauthn_credentials WHERE user_id = u.id)
			FROM users u WHERE u.id = $1 FOR UPDATE`, sess.UserID).Scan(&hasTOTP, &keys); err != nil {
			return err
		}
		var name string
		err := tx.QueryRow(ctx, `SELECT name FROM user_webauthn_credentials WHERE id = $1 AND user_id = $2`, keyID, sess.UserID).Scan(&name)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrKeyNotFound
		}
		if err != nil {
			return err
		}
		if s.cfg.RequireMFA && !hasTOTP && keys <= 1 {
			return ErrLastFactor
		}
		if _, err := tx.Exec(ctx, `DELETE FROM user_webauthn_credentials WHERE id = $1`, keyID); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: userActor(sess.UserID, user.Email, meta), Action: "auth.webauthn_remove", Outcome: audit.Success,
			TargetType: "user", TargetID: sess.UserID.String(), Details: map[string]any{"key": name}})
	})
}
