package idp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch"
)

// AuthRequest is an authorization request's parameters.
type AuthRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	// Bounced is set when the request already went through EasyRMM's
	// sign-in page once (the session cookie is SameSite=Strict, so it does
	// not come with EasyPatch's redirect).
	Bounced bool
}

// ParseAuthRequest reads an authorization request's parameters.
func ParseAuthRequest(q url.Values) AuthRequest {
	return AuthRequest{
		ResponseType: q.Get("response_type"), ClientID: q.Get("client_id"), RedirectURI: q.Get("redirect_uri"),
		Scope: q.Get("scope"), State: q.Get("state"), Nonce: q.Get("nonce"),
		CodeChallenge: q.Get("code_challenge"), CodeChallengeMethod: q.Get("code_challenge_method"),
		Bounced: q.Get("bounced") == "1",
	}
}

// Query is the request as a query string, with bounced set: what the
// sign-in page hands back to authorize.
func (r AuthRequest) Query() string {
	q := url.Values{}
	for k, v := range map[string]string{
		"response_type": r.ResponseType, "client_id": r.ClientID, "redirect_uri": r.RedirectURI, "scope": r.Scope,
		"state": r.State, "nonce": r.Nonce, "code_challenge": r.CodeChallenge, "code_challenge_method": r.CodeChallengeMethod,
	} {
		if v != "" {
			q.Set(k, v)
		}
	}
	q.Set("bounced", "1")
	return q.Encode()
}

// ErrUntrustedRedirect: the client or its redirect URI is not the
// registered one, so the browser is not sent back to it; EasyRMM shows the
// error itself (RFC 6749, 4.1.2.1).
var ErrUntrustedRedirect = errors.New("idp: unknown client or redirect URI")

// Signin is the browser's EasyRMM session, if any.
type Signin struct {
	Session *auth.Session
	User    *auth.User
}

// Decision is where to send the browser.
type Decision struct {
	// Location is the URL to redirect to.
	Location string
	// SignIn is true when Location is EasyRMM's sign-in page.
	SignIn bool
}

var pkceChallenge = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// Authorize decides an authorization request: a code for EasyPatch, an
// error for EasyPatch, or a trip through EasyRMM's sign-in page.
func (s *Service) Authorize(ctx context.Context, req AuthRequest, in Signin, actor audit.Actor) (Decision, error) {
	var cl *Client
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		var err error
		cl, err = loadClient(ctx, tx)
		return err
	})
	if err != nil {
		return Decision{}, err
	}
	if cl == nil || req.ClientID != cl.ClientID || req.RedirectURI != cl.RedirectURI {
		return Decision{}, ErrUntrustedRedirect
	}

	back := func(params url.Values) Decision {
		if req.State != "" {
			params.Set("state", req.State)
		}
		params.Set("iss", s.issuer) // RFC 9207
		return Decision{Location: cl.RedirectURI + "?" + params.Encode()}
	}
	refuse := func(code, description string) Decision {
		return back(url.Values{"error": {code}, "error_description": {description}})
	}

	// The request itself.
	switch {
	case req.ResponseType != "code":
		return refuse("unsupported_response_type", "Only the authorization code flow is supported."), nil
	case !slices.Contains(strings.Fields(req.Scope), "openid"):
		return refuse("invalid_scope", "The openid scope is required."), nil
	case req.State == "" || len(req.State) > 1024:
		return refuse("invalid_request", "A state is required."), nil
	case req.Nonce == "" || len(req.Nonce) > 512:
		return refuse("invalid_request", "A nonce is required."), nil
	case req.CodeChallengeMethod != "S256" || !pkceChallenge.MatchString(req.CodeChallenge):
		return refuse("invalid_request", "PKCE with S256 is required."), nil
	}

	// The person.
	if in.Session == nil || in.User == nil || in.Session.State != auth.StateActive {
		if req.Bounced {
			s.auditAuthorize(ctx, actor, audit.Denied, "login_required", nil)
			return refuse("login_required", "Sign in to EasyRMM first."), nil
		}
		return Decision{Location: "/login?returnTo=" + url.QueryEscape(PathAuthorize+"?"+req.Query()), SignIn: true}, nil
	}
	if !auth.MultiFactor(in.Session.AMR) {
		s.auditAuthorize(ctx, actor, audit.Denied, "no_second_factor", nil)
		return refuse("access_denied", "EasyPatch needs an EasyRMM sign-in with a second factor. Sign out of EasyRMM and sign in again."), nil
	}
	acc, err := s.access(ctx, in.User.ID)
	if err != nil {
		return Decision{}, err
	}
	if acc == nil {
		s.auditAuthorize(ctx, actor, audit.Denied, "no_access", nil)
		return refuse("access_denied", "Your EasyRMM roles give you no access to EasyPatch."), nil
	}

	// A code.
	code, err := randomToken(32)
	if err != nil {
		return Decision{}, err
	}
	h := sha256.Sum256([]byte(code))
	now := s.now()
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM idp_codes WHERE expires_at < $1`, now.Add(-time.Hour)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO idp_codes (code_hash, client_id, redirect_uri, session_id, user_id, nonce, code_challenge, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			h[:], cl.ClientID, cl.RedirectURI, in.Session.ID, in.User.ID, req.Nonce, req.CodeChallenge, now.Add(CodeLifetime)); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, authorizeEvent(actor, audit.Success, "", acc))
	})
	if err != nil {
		return Decision{}, err
	}
	return back(url.Values{"code": {code}}), nil
}

func authorizeEvent(actor audit.Actor, outcome audit.Outcome, reason string, acc *easypatch.Access) audit.Event {
	details := map[string]any{}
	if reason != "" {
		details["reason"] = reason
	}
	if acc != nil {
		details["role"] = acc.Role
		details["organizations"] = len(acc.Organizations)
	}
	return audit.Event{Actor: actor, Action: "idp.authorize", Outcome: outcome, TargetType: "idp_client", Details: details}
}

// auditAuthorize records a refusal; a failure to record it is logged, and
// the refusal stands.
func (s *Service) auditAuthorize(ctx context.Context, actor audit.Actor, outcome audit.Outcome, reason string, acc *easypatch.Access) {
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		return s.audit.Write(ctx, tx, authorizeEvent(actor, outcome, reason, acc))
	})
	if err != nil {
		s.log.Error("idp: recording a refused sign-in", "err", err)
	}
}

// TokenRequest is a token request's parameters, with the client's
// credentials from either the form or HTTP Basic authentication.
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	CodeVerifier string
	ClientID     string
	ClientSecret string
	// Basic is set when the credentials came by HTTP Basic authentication.
	Basic bool
	// Limit is the key the request is rate-limited by (the client address).
	Limit string
}

// TokenError is an error response from the token endpoint (RFC 6749, 5.2).
type TokenError struct {
	Status      int    `json:"-"`
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func (e *TokenError) Error() string { return "idp: token: " + e.Code }

func tokenError(status int, code, description string) *TokenError {
	return &TokenError{Status: status, Code: code, Description: description}
}

// TokenResponse is a successful token response. The access token is
// required by OAuth but grants nothing: EasyRMM has no userinfo endpoint
// or other API it opens. It is not stored.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
}

var pkceVerifier = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

// Token redeems a code for an ID token.
func (s *Service) Token(ctx context.Context, req TokenRequest) (TokenResponse, error) {
	if !s.tokenLimit.Allow(req.Limit) {
		return TokenResponse{}, tokenError(429, "slow_down", "Too many requests.")
	}
	// The client.
	var clientID, redirectURI string
	var hash []byte
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT client_id, secret_hash, redirect_uri FROM idp_clients`).Scan(&clientID, &hash, &redirectURI)
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return TokenResponse{}, err
	}
	if hash == nil || req.ClientID != clientID || !equalHash(req.ClientSecret, hash) {
		// Hashing an empty secret too keeps the time the same.
		if hash == nil {
			equalHash(req.ClientSecret, make([]byte, 32))
		}
		return TokenResponse{}, tokenError(401, "invalid_client", "Client authentication failed.")
	}
	if req.GrantType != "authorization_code" {
		return TokenResponse{}, tokenError(400, "unsupported_grant_type", "Only authorization_code is supported.")
	}
	if req.Code == "" || len(req.Code) > 128 {
		return TokenResponse{}, tokenError(400, "invalid_request", "A code is required.")
	}
	if !pkceVerifier.MatchString(req.CodeVerifier) {
		return TokenResponse{}, tokenError(400, "invalid_grant", "The code verifier is missing or malformed.")
	}

	grant := func(desc string) error { return tokenError(400, "invalid_grant", desc) }
	codeHash := sha256.Sum256([]byte(req.Code))
	now := s.now()
	var (
		userID, sessionID       uuid.UUID
		codeClient, codeURI     string
		nonce, challenge        string
		expires                 time.Time
		email, name, userStatus string
		amr                     []string
		authTime                *time.Time
		sessOK                  bool
	)
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		// Single use: the first redemption marks it, whatever happens next.
		err := tx.QueryRow(ctx, `UPDATE idp_codes SET used_at = $2 WHERE code_hash = $1 AND used_at IS NULL
			RETURNING client_id, redirect_uri, session_id, user_id, nonce, code_challenge, expires_at`, codeHash[:], now).
			Scan(&codeClient, &codeURI, &sessionID, &userID, &nonce, &challenge, &expires)
		if errors.Is(err, pgx.ErrNoRows) {
			return grant("The code is unknown or was already used.")
		}
		if err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT u.email, u.display_name, u.status, s.amr, s.authenticated_at,
				s.revoked_at IS NULL AND s.state = 'active' AND s.expires_at > $2 AND s.idle_expires_at > $2
			FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = $1`, sessionID, now).
			Scan(&email, &name, &userStatus, &amr, &authTime, &sessOK)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return TokenResponse{}, grant("The EasyRMM session ended.")
	}
	if err != nil {
		return TokenResponse{}, err
	}
	switch {
	case !now.Before(expires):
		return TokenResponse{}, grant("The code expired.")
	case codeClient != clientID || codeURI != req.RedirectURI:
		return TokenResponse{}, grant("The code was issued for another client or redirect URI.")
	case !pkceMatches(req.CodeVerifier, challenge):
		return TokenResponse{}, grant("The code verifier does not match.")
	case !sessOK || userStatus != "active" || !auth.MultiFactor(amr):
		return TokenResponse{}, grant("The EasyRMM session ended.")
	}
	// Access is decided again: roles may have changed in the last minute.
	acc, err := s.access(ctx, userID)
	if err != nil {
		return TokenResponse{}, err
	}
	if acc == nil {
		return TokenResponse{}, grant("No access to EasyPatch.")
	}
	idToken, err := s.idToken(ctx, idClaims{
		Issuer: s.issuer, Audience: clientID, Subject: userID.String(),
		IssuedAt: now.Unix(), Expiry: now.Add(IDTokenLifetime).Unix(), AuthTime: unixOrZero(authTime),
		Nonce: nonce, Name: name, Email: email, EmailVerified: false, AMR: tokenAMR(amr), EasyPatch: *acc,
	})
	if err != nil {
		return TokenResponse{}, err
	}
	access, err := randomToken(32)
	if err != nil {
		return TokenResponse{}, err
	}
	return TokenResponse{AccessToken: access, TokenType: "Bearer", ExpiresIn: int(IDTokenLifetime.Seconds()), IDToken: idToken, Scope: "openid"}, nil
}

func pkceMatches(verifier, challenge string) bool {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:]) == challenge
}

func unixOrZero(t *time.Time) int64 {
	if t == nil {
		return 0
	}
	return t.Unix()
}

// idClaims are the ID token's claims (integration plan, 6.3).
type idClaims struct {
	Issuer        string           `json:"iss"`
	Audience      string           `json:"aud"`
	Subject       string           `json:"sub"`
	IssuedAt      int64            `json:"iat"`
	Expiry        int64            `json:"exp"`
	AuthTime      int64            `json:"auth_time,omitempty"`
	Nonce         string           `json:"nonce"`
	Name          string           `json:"name"`
	Email         string           `json:"email"`
	EmailVerified bool             `json:"email_verified"`
	AMR           []string         `json:"amr"`
	EasyPatch     easypatch.Access `json:"easypatch"`
}

// tokenAMR is the session's methods with "mfa" added. Only multi-factor
// sessions get a token, and EasyPatch counts a second factor by "mfa" alone
// (ADR-0036): it cannot know that EasyRMM's "rc" is a second factor.
func tokenAMR(amr []string) []string {
	out := slices.Clone(amr)
	if !slices.Contains(out, auth.MethodMultiFactor) {
		out = append(out, auth.MethodMultiFactor)
	}
	return out
}

func (s *Service) idToken(ctx context.Context, claims idClaims) (string, error) {
	key, err := s.signingKey(ctx)
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: key.priv, KeyID: key.kid}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(claims).Serialize()
}
