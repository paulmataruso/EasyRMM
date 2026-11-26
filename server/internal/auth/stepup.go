package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// Step-up authentication is defined in ADR-0055 ("Step-up authentication"):
// a second factor confirmed within the last StepUpWindow, recorded on the
// session as stepped_up_at, never a recovery code or a password alone. For
// an account signed in through a provider trusted to enforce MFA it is a
// fresh sign-in there (internal/sso).

// StepUpWindow is how long a step-up lasts.
const StepUpWindow = 5 * time.Minute

// Step-up methods, as the API names them.
const (
	StepUpTOTP     = "totp"
	StepUpWebAuthn = "webauthn"
	StepUpOIDC     = "oidc"
)

var (
	// ErrStepUpRequired: the action needs a step-up the session has not made,
	// or made too long ago.
	ErrStepUpRequired = errors.New("step-up authentication is required")
	// ErrNoSecondFactor: the account has nothing to step up with.
	ErrNoSecondFactor = errors.New("the account has no second factor to step up with")
	// ErrRecoveryCodeRefused: a recovery code is never a step-up.
	ErrRecoveryCodeRefused = errors.New("a recovery code cannot confirm a step-up")
)

// SteppedUp reports whether the session confirmed a second factor within
// StepUpWindow of now.
func (sess *Session) SteppedUp(now time.Time) bool {
	t := sess.SteppedUpAt
	return t != nil && !t.After(now) && now.Sub(*t) < StepUpWindow
}

// CheckStepUp is the one check every action that needs a step-up makes
// (RequireStepUp in httpapi calls it): nil when the session is stepped up,
// ErrStepUpRequired when not.
func (s *Service) CheckStepUp(sess *Session) error {
	if sess == nil || sess.State != StateActive || !sess.SteppedUp(s.now()) {
		return ErrStepUpRequired
	}
	return nil
}

// StepUpStatus is what the console asks before showing the step-up dialog.
type StepUpStatus struct {
	// ValidUntil is when the current step-up ends; nil when there is none.
	ValidUntil *time.Time `json:"validUntil"`
	// Methods lists what this account can step up with: totp, webauthn, oidc.
	Methods []string `json:"methods"`
	// Provider names the identity provider, when oidc is offered.
	Provider string `json:"provider,omitempty"`
}

// StepUpStatus lists how the session can step up and until when it is.
func (s *Service) StepUpStatus(ctx context.Context, sess *Session, user *User) (*StepUpStatus, error) {
	st := &StepUpStatus{Methods: []string{}}
	if sess.SteppedUp(s.now()) {
		t := sess.SteppedUpAt.Add(StepUpWindow)
		st.ValidUntil = &t
	}
	if user.TOTP {
		st.Methods = append(st.Methods, StepUpTOTP)
	}
	if user.SecurityKeys > 0 && s.wa != nil {
		st.Methods = append(st.Methods, StepUpWebAuthn)
	}
	if sess.SSOProviderID != nil {
		var name string
		var trusted bool
		err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT name, trust_mfa AND enabled FROM identity_providers WHERE id = $1`, *sess.SSOProviderID).Scan(&name, &trusted)
		})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		if err == nil && trusted {
			st.Methods = append(st.Methods, StepUpOIDC)
			st.Provider = name
		}
	}
	return st, nil
}

func (s *Service) stepUpAllowed(sess *Session, meta RequestMeta) error {
	if sess.State != StateActive {
		return ErrWrongState
	}
	if meta.IP.IsValid() && !s.ipLimit.Allow("stepup:"+LimitKey(meta.IP)) {
		return ErrRateLimited
	}
	if !s.mfaLimit.Allow("stepup:" + sess.UserID.String()) {
		return ErrRateLimited
	}
	return nil
}

// stepUpDone records a successful step-up on the session.
func (s *Service) stepUpDone(ctx context.Context, tx pgx.Tx, sess *Session, user *User, meta RequestMeta, details map[string]any) error {
	now := s.now()
	tag, err := tx.Exec(ctx, `UPDATE sessions SET stepped_up_at = $2, reauth_failures = 0 WHERE id = $1 AND revoked_at IS NULL`, sess.ID, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrInvalidSession
	}
	sess.SteppedUpAt = &now
	details["validUntil"] = now.Add(StepUpWindow)
	return s.audit.Write(ctx, tx, audit.Event{Actor: userActor(sess.UserID, user.Email, meta), Action: "auth.step_up", Outcome: audit.Success,
		TargetType: "session", TargetID: sess.ID.String(), Details: details})
}

// stepUpFailed records a refused step-up. It counts against the session as a
// wrong password does in reauthenticate, which ends after MaxMFAFailures.
func (s *Service) stepUpFailed(ctx context.Context, tx pgx.Tx, sess *Session, email, method, reason string, meta RequestMeta, extra map[string]any) error {
	var failures int
	if err := tx.QueryRow(ctx, `UPDATE sessions SET reauth_failures = reauth_failures + 1 WHERE id = $1 RETURNING reauth_failures`, sess.ID).Scan(&failures); err != nil {
		return err
	}
	ended := failures >= s.cfg.MaxMFAFailures
	if ended {
		if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = now(), revoked_reason = 'reauth_failures' WHERE id = $1 AND revoked_at IS NULL`, sess.ID); err != nil {
			return err
		}
	}
	d := map[string]any{"method": method, "reason": reason, "failures": failures, "signedOut": ended}
	for k, v := range extra {
		d[k] = v
	}
	return s.audit.Write(ctx, tx, audit.Event{Actor: userActor(sess.UserID, email, meta), Action: "auth.step_up", Outcome: audit.Failure,
		TargetType: "session", TargetID: sess.ID.String(), Details: d})
}

// StepUpWithCode steps the session up with an authenticator app's code. A
// recovery code is refused, and a code already used (at sign-in or by an
// earlier step-up) is a wrong one.
func (s *Service) StepUpWithCode(ctx context.Context, sess *Session, user *User, code string, meta RequestMeta) error {
	if err := s.stepUpAllowed(sess, meta); err != nil {
		return err
	}
	if LooksLikeRecoveryCode(code) {
		_ = s.audit.Record(ctx, audit.Event{Actor: userActor(sess.UserID, user.Email, meta), Action: "auth.step_up", Outcome: audit.Denied,
			TargetType: "session", TargetID: sess.ID.String(), Details: map[string]any{"method": "recovery_code", "reason": "recovery_code"}})
		return ErrRecoveryCodeRefused
	}
	var verifyErr error
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var sealed *string
		var lastStep *int64
		var enabled, lockedUntil *time.Time
		if err := tx.QueryRow(ctx, `SELECT totp_secret_sealed, totp_enabled_at, totp_last_step, locked_until FROM users WHERE id = $1 FOR UPDATE`, sess.UserID).
			Scan(&sealed, &enabled, &lastStep, &lockedUntil); err != nil {
			return err
		}
		if sealed == nil || enabled == nil {
			verifyErr = ErrNoSecondFactor
			return nil
		}
		if lockedUntil != nil && s.now().Before(*lockedUntil) {
			verifyErr = ErrRateLimited
			return s.audit.Write(ctx, tx, audit.Event{Actor: userActor(sess.UserID, user.Email, meta), Action: "auth.step_up", Outcome: audit.Denied,
				TargetType: "session", TargetID: sess.ID.String(), Details: map[string]any{"method": StepUpTOTP, "reason": "locked"}})
		}
		secret, err := s.sealer.Open(*sealed, totpAAD(sess.UserID))
		if err != nil {
			return fmt.Errorf("auth: opening totp secret: %w", err)
		}
		last := int64(-1)
		if lastStep != nil {
			last = *lastStep
		}
		step, valid := VerifyTOTP(string(secret), code, s.now(), last)
		if !valid {
			verifyErr = ErrInvalidCode
			return s.stepUpFailed(ctx, tx, sess, user.Email, StepUpTOTP, "wrong_code", meta, nil)
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET totp_last_step = $2 WHERE id = $1`, sess.UserID, step); err != nil {
			return err
		}
		return s.stepUpDone(ctx, tx, sess, user, meta, map[string]any{"method": StepUpTOTP})
	})
	if err != nil {
		return fmt.Errorf("auth: step-up with a code: %w", err)
	}
	return verifyErr
}

const ceremonyStepUp = "stepup"

// BeginStepUpKey asks the browser for one of the user's keys.
func (s *Service) BeginStepUpKey(ctx context.Context, sess *Session, meta RequestMeta) (*protocol.CredentialAssertion, error) {
	if s.wa == nil {
		return nil, ErrWebAuthnUnavailable
	}
	if err := s.stepUpAllowed(sess, meta); err != nil {
		return nil, err
	}
	u, err := s.readWAUser(ctx, sess.UserID)
	if err != nil {
		return nil, err
	}
	if len(u.creds) == 0 {
		return nil, ErrNoSecondFactor
	}
	assertion, data, err := s.wa.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationPreferred))
	if err != nil {
		return nil, fmt.Errorf("auth: starting key step-up: %w", err)
	}
	if err := s.saveCeremony(ctx, ceremonyStepUp, &sess.ID, data); err != nil {
		return nil, err
	}
	return assertion, nil
}

// FinishStepUpKey completes a step-up with a security key or passkey. A
// refused key counts against the session.
func (s *Service) FinishStepUpKey(ctx context.Context, sess *Session, user *User, body []byte, meta RequestMeta) error {
	if s.wa == nil {
		return ErrWebAuthnUnavailable
	}
	if err := s.stepUpAllowed(sess, meta); err != nil {
		return err
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
		data, err := s.takeCeremony(ctx, parsed.Response.CollectedClientData.Challenge, ceremonyStepUp, &sess.ID)
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
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if failure != nil {
			return s.stepUpFailed(ctx, tx, sess, user.Email, StepUpWebAuthn, "key_rejected", meta, map[string]any{"error": keyReason(failure)})
		}
		name, err := s.keyUsed(ctx, tx, u, cred)
		if err != nil {
			return err
		}
		return s.stepUpDone(ctx, tx, sess, user, meta, map[string]any{"method": StepUpWebAuthn, "key": name})
	})
	if err != nil {
		return fmt.Errorf("auth: step-up with a security key: %w", err)
	}
	if failure != nil {
		return ErrKeyRejected
	}
	return nil
}

// ExternalStepUpStart is a fresh sign-in at the session's identity provider
// that sso has built the request for.
type ExternalStepUpStart struct {
	ProviderID uuid.UUID
	State      string
	Nonce      string
	Verifier   string
	ReturnTo   string
}

func stateHash(state string) []byte {
	h := sha256.Sum256([]byte("easyrmm:step-up:state:" + state))
	return h[:]
}

// StartExternalStepUp keeps the state, nonce and verifier of a fresh sign-in
// at the provider on the session's row (replacing an earlier one), with the
// time it started.
func (s *Service) StartExternalStepUp(ctx context.Context, sess *Session, in ExternalStepUpStart, meta RequestMeta) error {
	if err := s.stepUpAllowed(sess, meta); err != nil {
		return err
	}
	tag, err := s.execSession(ctx, `UPDATE sessions SET step_up_state_hash = $2, step_up_nonce = $3, step_up_verifier = $4, step_up_provider_id = $5,
			step_up_started_at = $6, step_up_return = $7 WHERE id = $1 AND revoked_at IS NULL AND state = 'active'`,
		sess.ID, stateHash(in.State), in.Nonce, in.Verifier, in.ProviderID, s.now(), in.ReturnTo)
	if err != nil {
		return err
	}
	if tag != 1 {
		return ErrInvalidSession
	}
	return nil
}

func (s *Service) execSession(ctx context.Context, sql string, args ...any) (int64, error) {
	var n int64
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, sql, args...)
		n = tag.RowsAffected()
		return err
	})
	return n, err
}

// HasExternalStepUp reports whether state belongs to a step-up under way.
func (s *Service) HasExternalStepUp(ctx context.Context, state string) bool {
	if state == "" || len(state) > 256 {
		return false
	}
	var found bool
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sessions WHERE step_up_state_hash = $1)`, stateHash(state)).Scan(&found)
	})
	return err == nil && found
}

// ExternalStepUp is a fresh sign-in at the provider that came back.
type ExternalStepUp struct {
	Session    *Session
	User       *User
	ProviderID uuid.UUID
	Nonce      string
	Verifier   string
	StartedAt  time.Time
	ReturnTo   string
}

// TakeExternalStepUp finds the step-up a provider's answer belongs to by
// its state and consumes it in one conditional UPDATE … RETURNING, so it
// works whichever server the browser comes back to and cannot be replayed.
// ErrInvalidSession when there is none: unknown, used, expired, or on a
// session that has ended.
func (s *Service) TakeExternalStepUp(ctx context.Context, state string) (*ExternalStepUp, error) {
	if state == "" || len(state) > 256 {
		return nil, ErrInvalidSession
	}
	var st ExternalStepUp
	var sessionID, userID uuid.UUID
	var email string
	var started time.Time
	var provider *uuid.UUID
	var nonce, verifier, ret *string
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			WITH old AS (
				SELECT s.id, s.step_up_nonce, s.step_up_verifier, s.step_up_provider_id, s.step_up_started_at, s.step_up_return
				FROM sessions s WHERE s.step_up_state_hash = $1 AND s.revoked_at IS NULL AND s.state = 'active'
				  AND s.expires_at > $2 AND s.idle_expires_at > $2 AND s.step_up_started_at > $3
				FOR UPDATE)
			UPDATE sessions s SET step_up_state_hash = NULL, step_up_nonce = NULL, step_up_verifier = NULL, step_up_provider_id = NULL,
				step_up_started_at = NULL, step_up_return = NULL
			FROM old, users u
			WHERE s.id = old.id AND u.id = s.user_id AND u.status = 'active'
			RETURNING s.id, s.user_id, u.email, old.step_up_nonce, old.step_up_verifier, old.step_up_provider_id, old.step_up_started_at, old.step_up_return`,
			stateHash(state), s.now(), s.now().Add(-StepUpFlowTTL)).Scan(&sessionID, &userID, &email, &nonce, &verifier, &provider, &started, &ret)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalidSession
	}
	if err != nil {
		return nil, fmt.Errorf("auth: taking a step-up: %w", err)
	}
	if nonce == nil || verifier == nil || provider == nil || ret == nil {
		return nil, ErrInvalidSession
	}
	st.Session = &Session{ID: sessionID, UserID: userID, State: StateActive}
	st.User = &User{ID: userID, Email: email}
	st.ProviderID, st.Nonce, st.Verifier, st.StartedAt, st.ReturnTo = *provider, *nonce, *verifier, started, *ret
	return &st, nil
}

// StepUpFlowTTL is how long a fresh sign-in at the provider may take.
const StepUpFlowTTL = 10 * time.Minute

// CompleteExternalStepUp records the outcome of a fresh sign-in at the
// provider: failure empty steps the session up; otherwise it is a refused
// step-up, audited and counted against the session.
func (s *Service) CompleteExternalStepUp(ctx context.Context, st *ExternalStepUp, failure string, extra map[string]any, meta RequestMeta) error {
	details := map[string]any{"method": StepUpOIDC, "providerId": st.ProviderID.String()}
	for k, v := range extra {
		details[k] = v
	}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if failure != "" {
			return s.stepUpFailed(ctx, tx, st.Session, st.User.Email, StepUpOIDC, failure, meta, details)
		}
		return s.stepUpDone(ctx, tx, st.Session, st.User, meta, details)
	})
	if err != nil {
		return fmt.Errorf("auth: recording a provider step-up: %w", err)
	}
	return nil
}
