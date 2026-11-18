// Package idp makes EasyRMM an OpenID Connect provider for one client: the
// EasyPatch it is connected to (ADR-0036; integration plan, section 6.3).
// Someone signed in to EasyRMM, with a second factor, signs in to EasyPatch
// without another password. EasyPatch learns who they are and, from
// EasyRMM's roles, what they may do there (the "easypatch" claim).
//
// It is deliberately small: the authorization code flow with PKCE (S256),
// one confidential client, ID tokens only. No consent screen, no refresh
// tokens, no userinfo, no dynamic registration.
package idp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
)

// The provider's paths under the issuer.
const (
	PathDiscovery = "/.well-known/openid-configuration"
	PathJWKS      = "/oauth2/jwks"
	PathAuthorize = "/oauth2/authorize"
	PathToken     = "/oauth2/token" //nolint:gosec // a path, not a credential
	// CallbackPath is where EasyPatch receives the browser back.
	CallbackPath = "/api/v1/auth/sso/callback"
)

// Lifetimes.
const (
	CodeLifetime    = 60 * time.Second
	IDTokenLifetime = 5 * time.Minute
)

// Access decides what a user may do in EasyPatch (easypatch.Access), or
// nil for nothing. It is asked again when a code is redeemed.
type Access func(ctx context.Context, userID uuid.UUID) (*easypatch.Access, error)

// EasyPatch is what the provider needs of the connector.
type EasyPatch interface {
	Connection(ctx context.Context) (easypatch.Connection, error)
}

// Service is the provider.
type Service struct {
	db         *database.DB
	audit      *audit.Logger
	sealer     *secrets.Sealer
	issuer     string
	access     Access
	easyPatch  EasyPatch
	now        func() time.Time
	tokenLimit *auth.KeyedLimiter
	log        *slog.Logger

	mu  sync.Mutex
	key *signingKey // the newest key, once read
}

type signingKey struct {
	kid  string
	priv *ecdsa.PrivateKey
}

// New builds the provider. issuer is EasyRMM's public address.
func New(db *database.DB, auditLog *audit.Logger, sealer *secrets.Sealer, issuer string, ep EasyPatch, accessFn Access, log *slog.Logger) *Service {
	return &Service{
		db: db, audit: auditLog, sealer: sealer, issuer: strings.TrimRight(issuer, "/"), easyPatch: ep, access: accessFn,
		now: time.Now, tokenLimit: auth.NewKeyedLimiter(2*time.Second, 30, 10_000), log: log,
	}
}

// SetClock replaces the clock, for tests.
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Issuer is the provider's issuer identifier.
func (s *Service) Issuer() string { return s.issuer }

// ------------------------------------------------------------------ client

// Client is EasyPatch's registration, without its secret.
type Client struct {
	ClientID    string     `json:"clientId"`
	RedirectURI string     `json:"redirectUri"`
	CreatedAt   time.Time  `json:"createdAt"`
	CreatedBy   string     `json:"createdBy,omitempty"`
	RotatedAt   *time.Time `json:"rotatedAt,omitempty"`
	RotatedBy   string     `json:"rotatedBy,omitempty"`
}

// Settings is what Settings → EasyPatch shows of single sign-on.
type Settings struct {
	// Available is true when EasyPatch is set up and lists the
	// easyrmm-sign-in capability; Reason says why not.
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	Issuer    string `json:"issuer"`
	// RedirectURI is where EasyPatch receives sign-ins, from its address.
	RedirectURI string  `json:"redirectUri,omitempty"`
	Client      *Client `json:"client"`
}

// Secret is a client with its secret, shown once.
type Secret struct {
	Client
	Issuer       string `json:"issuer"`
	ClientSecret string `json:"clientSecret"`
}

func requireSettings(c access.Caller) error {
	if !c.CanGlobal(rbac.PermSettingsManage) {
		return apperr.Forbidden()
	}
	return nil
}

// Settings reads the client and whether EasyPatch can use it.
func (s *Service) Settings(ctx context.Context, c access.Caller) (Settings, error) {
	if err := requireSettings(c); err != nil {
		return Settings{}, err
	}
	out := Settings{Issuer: s.issuer}
	uri, reason, err := s.redirectURI(ctx)
	if err != nil {
		return Settings{}, err
	}
	out.Available, out.Reason, out.RedirectURI = reason == "", reason, uri
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		cl, err := loadClient(ctx, tx)
		out.Client = cl
		return err
	})
	return out, err
}

// redirectURI is EasyPatch's callback, or why EasyPatch cannot sign in
// through EasyRMM.
func (s *Service) redirectURI(ctx context.Context) (string, string, error) {
	conn, err := s.easyPatch.Connection(ctx)
	if err != nil {
		return "", "", err
	}
	base := easypatch.ConsoleURL(conn)
	switch {
	case !conn.Configured || base == "":
		return "", "Set up EasyPatch first.", nil
	case !hasCapability(conn.Capabilities, easypatch.CapabilityEasyRMMSignIn):
		return "", "This EasyPatch cannot sign people in through EasyRMM; update it.", nil
	}
	return strings.TrimRight(base, "/") + CallbackPath, "", nil
}

func hasCapability(list []string, c string) bool {
	for _, x := range list {
		if x == c {
			return true
		}
	}
	return false
}

func loadClient(ctx context.Context, tx pgx.Tx) (*Client, error) {
	var cl Client
	var createdBy, rotatedBy *string
	err := tx.QueryRow(ctx, `SELECT c.client_id, c.redirect_uri, c.created_at, cu.email, c.rotated_at, ru.email
		FROM idp_clients c LEFT JOIN users cu ON cu.id = c.created_by LEFT JOIN users ru ON ru.id = c.rotated_by`).
		Scan(&cl.ClientID, &cl.RedirectURI, &cl.CreatedAt, &createdBy, &cl.RotatedAt, &rotatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if createdBy != nil {
		cl.CreatedBy = *createdBy
	}
	if rotatedBy != nil {
		cl.RotatedBy = *rotatedBy
	}
	return &cl, nil
}

// Create registers EasyPatch as the client, with a new secret.
func (s *Service) Create(ctx context.Context, c access.Caller) (Secret, error) {
	if err := requireSettings(c); err != nil {
		return Secret{}, err
	}
	uri, reason, err := s.redirectURI(ctx)
	if err != nil {
		return Secret{}, err
	}
	if reason != "" {
		return Secret{}, apperr.Conflict("easypatch_unavailable", reason)
	}
	if _, err := s.signingKey(ctx); err != nil {
		return Secret{}, err
	}
	id, err := randomToken(9)
	if err != nil {
		return Secret{}, err
	}
	clientID := "easypatch-" + id
	secret, hash, err := newSecret()
	if err != nil {
		return Secret{}, err
	}
	var out Secret
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if cl, err := loadClient(ctx, tx); err != nil || cl != nil {
			if err == nil {
				err = apperr.Conflict("client_exists", "EasyPatch is already set up to sign in through EasyRMM.")
			}
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO idp_clients (client_id, secret_hash, redirect_uri, created_by) VALUES ($1, $2, $3, $4)`,
			clientID, hash, uri, actorUser(c)); err != nil {
			return err
		}
		cl, err := loadClient(ctx, tx)
		if err != nil {
			return err
		}
		out = Secret{Client: *cl, Issuer: s.issuer, ClientSecret: secret}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "idp.client_create", Outcome: audit.Success,
			TargetType: "idp_client", TargetID: clientID, Details: map[string]any{"redirectUri": uri}})
	})
	return out, err
}

// Rotate replaces the client's secret. The old one stops working at once.
func (s *Service) Rotate(ctx context.Context, c access.Caller) (Secret, error) {
	if err := requireSettings(c); err != nil {
		return Secret{}, err
	}
	secret, hash, err := newSecret()
	if err != nil {
		return Secret{}, err
	}
	var out Secret
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE idp_clients SET secret_hash = $1, rotated_at = now(), rotated_by = $2`, hash, actorUser(c))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return apperr.NotFound()
		}
		cl, err := loadClient(ctx, tx)
		if err != nil {
			return err
		}
		out = Secret{Client: *cl, Issuer: s.issuer, ClientSecret: secret}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "idp.client_rotate", Outcome: audit.Success,
			TargetType: "idp_client", TargetID: cl.ClientID})
	})
	return out, err
}

// Delete removes the client: nobody signs in to EasyPatch through EasyRMM
// any more, and codes not yet redeemed stop working.
func (s *Service) Delete(ctx context.Context, c access.Caller) error {
	if err := requireSettings(c); err != nil {
		return err
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var id string
		err := tx.QueryRow(ctx, `DELETE FROM idp_clients RETURNING client_id`).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound()
		}
		if err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "idp.client_delete", Outcome: audit.Success,
			TargetType: "idp_client", TargetID: id})
	})
}

func actorUser(c access.Caller) *uuid.UUID {
	if c.Principal == nil || c.Principal.UserID == uuid.Nil {
		return nil
	}
	id := c.Principal.UserID
	return &id
}

// newSecret is a client secret (256 random bits) and its hash.
func newSecret() (string, []byte, error) {
	t, err := randomToken(32)
	if err != nil {
		return "", nil, err
	}
	secret := "erms_" + t
	h := sha256.Sum256([]byte(secret))
	return secret, h[:], nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ------------------------------------------------------------------ keys

func keyAAD(kid string) []byte { return []byte("idp-signing-key:" + kid) }

// signingKey is the newest signing key, made the first time it is needed.
func (s *Service) signingKey(ctx context.Context) (*signingKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key != nil {
		return s.key, nil
	}
	var key *signingKey
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		// One key is made, however many requests ask at once.
		if _, err := tx.Exec(ctx, `LOCK TABLE idp_signing_keys IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return err
		}
		var kid, sealed string
		err := tx.QueryRow(ctx, `SELECT kid, private_sealed FROM idp_signing_keys ORDER BY created_at DESC LIMIT 1`).Scan(&kid, &sealed)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return err
			}
			der, err := x509.MarshalECPrivateKey(priv)
			if err != nil {
				return err
			}
			b := make([]byte, 12)
			if _, err := rand.Read(b); err != nil {
				return err
			}
			kid = hex.EncodeToString(b)
			if sealed, err = s.sealer.Seal(der, keyAAD(kid)); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO idp_signing_keys (kid, private_sealed) VALUES ($1, $2)`, kid, sealed); err != nil {
				return err
			}
			key = &signingKey{kid: kid, priv: priv}
			return nil
		case err != nil:
			return err
		}
		key, err = s.openKey(kid, sealed)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("idp: signing key: %w", err)
	}
	s.key = key
	return key, nil
}

func (s *Service) openKey(kid, sealed string) (*signingKey, error) {
	der, err := s.sealer.Open(sealed, keyAAD(kid))
	if err != nil {
		return nil, err
	}
	priv, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, err
	}
	return &signingKey{kid: kid, priv: priv}, nil
}

// JWKS is the public keys ID tokens are signed with.
func (s *Service) JWKS(ctx context.Context) (jose.JSONWebKeySet, error) {
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT kid, private_sealed FROM idp_signing_keys ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var kid, sealed string
			if err := rows.Scan(&kid, &sealed); err != nil {
				return err
			}
			k, err := s.openKey(kid, sealed)
			if err != nil {
				return err
			}
			set.Keys = append(set.Keys, jose.JSONWebKey{Key: &k.priv.PublicKey, KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"})
		}
		return rows.Err()
	})
	return set, err
}

// Enabled reports whether a client is set up; the provider's routes answer
// only then.
func (s *Service) Enabled(ctx context.Context) (bool, error) {
	var ok bool
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM idp_clients)`).Scan(&ok)
	})
	return ok, err
}

// equalHash compares a value's SHA-256 with a stored hash in constant time.
func equalHash(value string, hash []byte) bool {
	h := sha256.Sum256([]byte(value))
	return subtle.ConstantTimeCompare(h[:], hash) == 1
}
