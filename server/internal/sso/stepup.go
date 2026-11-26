package sso

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// Step-up through a provider (ADR-0055, "Step-up authentication"): for an
// account signed in through a provider trusted to enforce MFA, a fresh
// sign-in there, requested with prompt=login and max_age=0. The state, nonce
// and verifier belong to the session's row (auth.StartExternalStepUp), and
// the ID token must be for the provider identity linked to the session's
// user, with an auth_time later than the start.

// FailStepUp codes, in the step-up's return address.
const (
	FailStepUpAuthTime = "auth_time" // no fresh sign-in: auth_time missing or older than the start
	FailStepUpIdentity = "identity"  // not the identity linked to this account
	FailStepUpTrust    = "trust"     // the provider is no longer trusted to enforce MFA
)

// StartStepUp returns the provider's address for a fresh sign-in. The
// session must have signed in through a provider trusted to enforce MFA.
func (s *Service) StartStepUp(ctx context.Context, sess *auth.Session, returnTo string, meta auth.RequestMeta) (string, error) {
	if sess.SSOProviderID == nil {
		return "", auth.ErrNoSecondFactor
	}
	p, err := s.load(ctx, *sess.SSOProviderID)
	if errors.Is(err, apperr.ErrNotFound) {
		return "", auth.ErrNoSecondFactor
	}
	if err != nil {
		return "", err
	}
	if !p.Enabled || !p.TrustMFA {
		return "", auth.ErrNoSecondFactor
	}
	op, err := s.providerFor(ctx, p)
	if err != nil {
		return "", fail(FailUnavailable, err)
	}
	cfg, err := s.oauthConfig(p, op)
	if err != nil {
		return "", fail(FailUnavailable, err)
	}
	in := auth.ExternalStepUpStart{ProviderID: p.ID, State: randomString(), Nonce: randomString(), Verifier: oauth2.GenerateVerifier(), ReturnTo: SafeReturn(returnTo)}
	if err := s.auth.StartExternalStepUp(ctx, sess, in, meta); err != nil {
		return "", err
	}
	return cfg.AuthCodeURL(in.State, oidc.Nonce(in.Nonce), oauth2.S256ChallengeOption(in.Verifier),
		oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0")), nil
}

// IsStepUp reports whether state is one a step-up started and has not yet
// used. The callback tells a step-up from a sign-in by it.
func (s *Service) IsStepUp(ctx context.Context, state string) bool {
	return s.auth.HasExternalStepUp(ctx, state)
}

// CompleteStepUp finishes a step-up from the provider's answer. It returns
// where the browser goes next (always inside the console), with a nil error
// when the session is now stepped up, otherwise a *Failure, which is
// audited and counted against the session.
func (s *Service) CompleteStepUp(ctx context.Context, in CallbackInput, meta auth.RequestMeta) (string, error) {
	st, err := s.auth.TakeExternalStepUp(ctx, in.State)
	if err != nil {
		return "/", fail(FailExpired, err)
	}
	refuse := func(code string, extra map[string]any, cause error) (string, error) {
		if extra == nil {
			extra = map[string]any{}
		}
		extra["code"] = code
		if rerr := s.auth.CompleteExternalStepUp(ctx, st, code, extra, meta); rerr != nil {
			return st.ReturnTo, rerr
		}
		return st.ReturnTo, fail(code, cause)
	}
	p, err := s.load(ctx, st.ProviderID)
	if err != nil {
		return refuse(FailUnavailable, nil, err)
	}
	if !p.Enabled {
		return refuse(FailUnavailable, nil, errors.New("provider is disabled"))
	}
	if !p.TrustMFA {
		return refuse(FailStepUpTrust, nil, errors.New("provider is not trusted to enforce MFA"))
	}
	if in.Error != "" {
		return refuse(FailProvider, map[string]any{"error": cut(in.Error, 100), "errorDescription": cut(in.ErrorDescription, 300)}, errors.New(in.Error))
	}
	if in.Code == "" {
		return refuse(FailProvider, map[string]any{"error": "no code"}, errors.New("no authorization code"))
	}
	op, err := s.providerFor(ctx, p)
	if err != nil {
		return refuse(FailUnavailable, map[string]any{"error": cut(err.Error(), 300)}, err)
	}
	cfg, err := s.oauthConfig(p, op)
	if err != nil {
		return refuse(FailUnavailable, map[string]any{"error": cut(err.Error(), 300)}, err)
	}
	hctx := oidc.ClientContext(ctx, s.clientFor(p.ID))
	tok, err := cfg.Exchange(hctx, in.Code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		return refuse(FailProvider, map[string]any{"error": "code exchange: " + cut(err.Error(), 300)}, err)
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		return refuse(FailProvider, map[string]any{"error": "no ID token"}, errors.New("no id_token in the token response"))
	}
	idt, err := op.VerifierContext(hctx, &oidc.Config{ClientID: p.ClientID, Now: s.now}).Verify(hctx, rawID)
	if err != nil {
		return refuse(FailProvider, map[string]any{"error": "ID token: " + cut(err.Error(), 300)}, err)
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(st.Nonce)) != 1 {
		return refuse(FailProvider, map[string]any{"error": "nonce does not match"}, errors.New("nonce mismatch"))
	}
	var c struct {
		AuthTime *float64 `json:"auth_time"`
	}
	if err := idt.Claims(&c); err != nil {
		return refuse(FailProvider, map[string]any{"error": "claims: " + cut(err.Error(), 300)}, err)
	}
	// The identity must be the one linked to the session's user at this
	// provider: neither a stolen session nor the attacker's own account at
	// the same provider passes.
	var linked string
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT subject FROM user_identities WHERE provider_id = $1 AND user_id = $2`, p.ID, st.User.ID).Scan(&linked)
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return st.ReturnTo, err
	}
	sameIssuer := strings.TrimSuffix(idt.Issuer, "/") == strings.TrimSuffix(p.Issuer, "/")
	if errors.Is(err, pgx.ErrNoRows) || !sameIssuer || subtle.ConstantTimeCompare([]byte(idt.Subject), []byte(linked)) != 1 {
		return refuse(FailStepUpIdentity, map[string]any{"subject": cut(idt.Subject, 100)}, errors.New("not the linked identity"))
	}
	if c.AuthTime == nil || int64(*c.AuthTime) < st.StartedAt.Unix() {
		return refuse(FailStepUpAuthTime, nil, errors.New("the ID token's auth_time is missing or not after the start of the step-up"))
	}
	if err := s.auth.CompleteExternalStepUp(ctx, st, "", map[string]any{"provider": p.Name, "authTime": int64(*c.AuthTime)}, meta); err != nil {
		return st.ReturnTo, err
	}
	return st.ReturnTo, nil
}
