package sso

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// FlowTTL is how long a sign-in may take at the provider.
const FlowTTL = 10 * time.Minute

// flowAD binds sealed flow cookies to their purpose.
var flowAD = []byte("easyrmm:sso:flow:v1")

// Failure is why a sign-in through a provider did not complete. Its Code
// goes to the sign-in page, which explains it.
type Failure struct {
	Code string
	err  error
}

func (f *Failure) Error() string {
	if f.err != nil {
		return "sso: " + f.Code + ": " + f.err.Error()
	}
	return "sso: " + f.Code
}

func (f *Failure) Unwrap() error { return f.err }

// Failure codes, shown on the sign-in page.
const (
	FailExpired      = "expired"      // no flow cookie, a different state, or too slow
	FailProvider     = "provider"     // the provider refused, or its answer did not verify
	FailUnavailable  = "unavailable"  // the provider is disabled, deleted or unreachable
	FailNoAccount    = "no_account"   // no EasyRMM account for this identity
	FailDomain       = "domain"       // the email's domain is not one of the provider's
	FailUnverified   = "unverified"   // the provider did not vouch for the email
	FailLinkedOther  = "linked_other" // the account is linked to another identity at this provider
	FailAccountState = "account"      // the account is disabled or locked
	FailRateLimited  = "rate_limited" // too many sign-ins from this address
)

func fail(code string, err error) error { return &Failure{Code: code, err: err} }

// flow is what the start step remembers in the browser, sealed.
type flow struct {
	Provider uuid.UUID `json:"p"`
	State    string    `json:"s"`
	Nonce    string    `json:"n"`
	Verifier string    `json:"v"`
	ReturnTo string    `json:"r"`
	Expires  int64     `json:"e"`
}

func randomString() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// SafeReturn keeps a return path inside the console: a path on this site,
// never another site (//host, /\host) or a scheme.
func SafeReturn(p string) string {
	if p == "" || len(p) > 1024 || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") ||
		strings.ContainsAny(p, "\r\n\t\\") {
		return "/"
	}
	return p
}

func (s *Service) oauthConfig(p *providerRow, op *oidc.Provider) (*oauth2.Config, error) {
	secret, err := s.sealer.Open(p.sealed, secretAD(p.ID))
	if err != nil {
		return nil, fmt.Errorf("the client secret cannot be opened with this server's secret key: %w", err)
	}
	return &oauth2.Config{
		ClientID: p.ClientID, ClientSecret: string(secret), Endpoint: op.Endpoint(),
		RedirectURL: s.RedirectURI(), Scopes: []string{oidc.ScopeOpenID, "email", "profile"},
	}, nil
}

// Start begins a sign-in through a provider. It returns the provider's
// authorization URL and the sealed flow to keep in a cookie until the
// callback.
func (s *Service) Start(ctx context.Context, providerID uuid.UUID, returnTo string) (authURL, sealed string, err error) {
	p, err := s.load(ctx, providerID)
	if errors.Is(err, apperr.ErrNotFound) {
		return "", "", fail(FailUnavailable, err)
	}
	if err != nil {
		return "", "", err
	}
	if !p.Enabled {
		return "", "", fail(FailUnavailable, errors.New("provider is disabled"))
	}
	op, err := s.providerFor(ctx, p)
	if err != nil {
		return "", "", fail(FailUnavailable, err)
	}
	cfg, err := s.oauthConfig(p, op)
	if err != nil {
		return "", "", fail(FailUnavailable, err)
	}
	f := flow{Provider: p.ID, State: randomString(), Nonce: randomString(), Verifier: oauth2.GenerateVerifier(),
		ReturnTo: SafeReturn(returnTo), Expires: s.now().Add(FlowTTL).Unix()}
	raw, err := json.Marshal(f)
	if err != nil {
		return "", "", err
	}
	if sealed, err = s.sealer.Seal(raw, flowAD); err != nil {
		return "", "", err
	}
	return cfg.AuthCodeURL(f.State, oidc.Nonce(f.Nonce), oauth2.S256ChallengeOption(f.Verifier)), sealed, nil
}

// CallbackInput is what the provider sent back, and the flow cookie.
type CallbackInput struct {
	Sealed           string
	State            string
	Code             string
	Error            string
	ErrorDescription string
}

// Result is a completed sign-in.
type Result struct {
	Token    string
	Session  *auth.Session
	ReturnTo string
}

// claims are the ID token claims EasyRMM reads.
type claims struct {
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified any    `json:"email_verified"`
	Name          string `json:"name"`
}

// verified reads email_verified, which some providers send as a string.
func (c claims) verified() bool {
	switch v := c.EmailVerified.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	}
	return false
}

// Callback completes a sign-in: it checks the flow, exchanges the code,
// verifies the ID token, finds or links the identity, and signs in. Every
// refusal after the flow checks out is audited.
func (s *Service) Callback(ctx context.Context, in CallbackInput, meta auth.RequestMeta) (*Result, error) {
	f, err := s.openFlow(in.Sealed)
	if err != nil {
		return nil, fail(FailExpired, err)
	}
	if subtle.ConstantTimeCompare([]byte(in.State), []byte(f.State)) != 1 {
		return nil, fail(FailExpired, errors.New("state does not match"))
	}
	p, err := s.load(ctx, f.Provider)
	if err != nil {
		return nil, fail(FailUnavailable, err)
	}
	details := map[string]any{"provider": p.Name, "providerId": p.ID.String()}
	refuse := func(code, label string, extra map[string]any, err error) (*Result, error) {
		d := map[string]any{"method": "oidc", "reason": code}
		for k, v := range details {
			d[k] = v
		}
		for k, v := range extra {
			d[k] = v
		}
		_ = s.audit.Record(ctx, audit.Event{Actor: audit.Actor{Type: audit.ActorUser, Label: label, SourceIP: meta.IP, UserAgent: meta.UserAgent},
			Action: "auth.login", Outcome: audit.Failure, Details: d})
		return nil, fail(code, err)
	}
	if !p.Enabled {
		return refuse(FailUnavailable, "", nil, errors.New("provider is disabled"))
	}
	if in.Error != "" {
		return refuse(FailProvider, "", map[string]any{"error": cut(in.Error, 100), "errorDescription": cut(in.ErrorDescription, 300)},
			errors.New(in.Error))
	}
	if in.Code == "" {
		return refuse(FailProvider, "", map[string]any{"error": "no code"}, errors.New("no authorization code"))
	}
	op, err := s.providerFor(ctx, p)
	if err != nil {
		return refuse(FailUnavailable, "", map[string]any{"error": cut(err.Error(), 300)}, err)
	}
	cfg, err := s.oauthConfig(p, op)
	if err != nil {
		return refuse(FailUnavailable, "", map[string]any{"error": cut(err.Error(), 300)}, err)
	}
	hctx := oidc.ClientContext(ctx, s.clientFor(p.ID))
	tok, err := cfg.Exchange(hctx, in.Code, oauth2.VerifierOption(f.Verifier))
	if err != nil {
		return refuse(FailProvider, "", map[string]any{"error": "code exchange: " + cut(err.Error(), 300)}, err)
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		return refuse(FailProvider, "", map[string]any{"error": "no ID token"}, errors.New("no id_token in the token response"))
	}
	idt, err := op.VerifierContext(hctx, &oidc.Config{ClientID: p.ClientID, Now: s.now}).Verify(hctx, rawID)
	if err != nil {
		return refuse(FailProvider, "", map[string]any{"error": "ID token: " + cut(err.Error(), 300)}, err)
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(f.Nonce)) != 1 {
		return refuse(FailProvider, "", map[string]any{"error": "nonce does not match"}, errors.New("nonce mismatch"))
	}
	var c claims
	if err := idt.Claims(&c); err != nil {
		return refuse(FailProvider, "", map[string]any{"error": "claims: " + cut(err.Error(), 300)}, err)
	}
	if c.Subject == "" || len(c.Subject) > 255 {
		return refuse(FailProvider, "", map[string]any{"error": "subject missing or too long"}, errors.New("bad subject"))
	}
	email := normalizeEmail(c.Email)
	details["subject"] = c.Subject
	details["email"] = email

	userID, linked, code, err := s.resolve(ctx, p, c, email, meta)
	if err != nil {
		return nil, err
	}
	if code != "" {
		return refuse(code, email, nil, errors.New(code))
	}
	if linked {
		details["linked"] = true
	}
	token, sess, err := s.auth.SignInExternal(ctx, auth.ExternalSignIn{
		UserID: userID, Email: email, Method: "oidc", Details: details, SecondFactorDone: p.TrustMFA, ProviderID: p.ID,
	}, meta)
	switch {
	case errors.Is(err, auth.ErrRateLimited):
		return nil, fail(FailRateLimited, err)
	case errors.Is(err, auth.ErrAccountUnavailable):
		return nil, fail(FailAccountState, err)
	case err != nil:
		return nil, err
	}
	return &Result{Token: token, Session: sess, ReturnTo: f.ReturnTo}, nil
}

func (s *Service) openFlow(sealed string) (*flow, error) {
	if sealed == "" {
		return nil, errors.New("no sign-in in progress in this browser")
	}
	raw, err := s.sealer.Open(sealed, flowAD)
	if err != nil {
		return nil, err
	}
	var f flow
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	if s.now().Unix() > f.Expires {
		return nil, errors.New("the sign-in took too long")
	}
	return &f, nil
}

// resolve finds the EasyRMM user for an identity, linking it at the first
// sign-in when the rules allow (ADR-0034). A non-empty code is a refusal.
func (s *Service) resolve(ctx context.Context, p *providerRow, c claims, email string, meta auth.RequestMeta) (uuid.UUID, bool, string, error) {
	var userID uuid.UUID
	linked := false
	code := ""
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `UPDATE user_identities SET last_used_at = now() WHERE provider_id = $1 AND subject = $2 RETURNING user_id`,
			p.ID, c.Subject).Scan(&userID)
		if err == nil {
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		// First sign-in through this provider: link by email, if allowed.
		at := strings.LastIndexByte(email, '@')
		switch {
		case email == "" || at < 1:
			code = FailNoAccount
			return nil
		case !containsDomain(p.AllowedDomains, email[at+1:]):
			code = FailDomain
			return nil
		case !c.verified() && !p.TrustEmail:
			code = FailUnverified
			return nil
		}
		var other bool
		err = tx.QueryRow(ctx, `SELECT u.id, EXISTS (SELECT 1 FROM user_identities i WHERE i.provider_id = $2 AND i.user_id = u.id)
			FROM users u WHERE u.email = $1 AND u.status = 'active' FOR UPDATE`, email, p.ID).Scan(&userID, &other)
		if errors.Is(err, pgx.ErrNoRows) {
			code = FailNoAccount
			return nil
		}
		if err != nil {
			return err
		}
		if other {
			code = FailLinkedOther
			return nil
		}
		if _, err := tx.Exec(ctx, `INSERT INTO user_identities (provider_id, subject, user_id, email, last_used_at)
			VALUES ($1, $2, $3, $4, now())`, p.ID, c.Subject, userID, email); err != nil {
			return err
		}
		linked = true
		return s.audit.Write(ctx, tx, audit.Event{
			Actor:  audit.Actor{Type: audit.ActorUser, ID: userID, Label: email, SourceIP: meta.IP, UserAgent: meta.UserAgent},
			Action: "auth.sso_link", TargetType: "user", TargetID: userID.String(), Outcome: audit.Success,
			Details: map[string]any{"provider": p.Name, "providerId": p.ID.String(), "subject": c.Subject, "email": email,
				"emailVerified": c.verified(), "trustEmail": p.TrustEmail},
		})
	})
	if database.IsUniqueViolation(err) {
		// Another sign-in linked the same identity at the same moment.
		return uuid.Nil, false, FailLinkedOther, nil
	}
	return userID, linked, code, err
}

func normalizeEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

func containsDomain(domains []string, d string) bool {
	d = strings.ToLower(d)
	for _, x := range domains {
		if x == d {
			return true
		}
	}
	return false
}

func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
