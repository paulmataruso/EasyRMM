// Package sso is single sign-on with OpenID Connect (ADR-0034): identity
// providers that super administrators set up, the authorization code flow
// with PKCE bound to a sealed cookie, and identities linked to invited
// EasyRMM accounts.
package sso

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/netguard"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
)

const (
	// CallbackPath is the one redirect URI for every provider: the flow
	// cookie says which provider a sign-in started with.
	CallbackPath = "/api/v1/auth/sso/callback"
	// MaxDomains is how many email domains a provider may list.
	MaxDomains = 50
	// discoveryTTL is how long a provider's discovery document is kept.
	discoveryTTL = time.Hour
)

// Provider is an identity provider as administrators see it. The client
// secret is never returned.
type Provider struct {
	ID             uuid.UUID `json:"id"`
	Name           string    `json:"name"`
	Issuer         string    `json:"issuer"`
	ClientID       string    `json:"clientId"`
	AllowedDomains []string  `json:"allowedDomains"`
	TrustEmail     bool      `json:"trustEmail"`
	TrustMFA       bool      `json:"trustMfa"`
	Enabled        bool      `json:"enabled"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// ProviderInput creates or changes a provider. An empty ClientSecret keeps
// the stored one when changing a provider.
type ProviderInput struct {
	Name           string   `json:"name"`
	Issuer         string   `json:"issuer"`
	ClientID       string   `json:"clientId"`
	ClientSecret   string   `json:"clientSecret"`
	AllowedDomains []string `json:"allowedDomains"`
	TrustEmail     bool     `json:"trustEmail"`
	TrustMFA       bool     `json:"trustMfa"`
	Enabled        bool     `json:"enabled"`
}

// Button is an enabled provider on the sign-in page.
type Button struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	// StartURL begins the sign-in, at the public URL.
	StartURL string `json:"startUrl"`
}

// Service runs single sign-on.
type Service struct {
	db     *database.DB
	audit  *audit.Logger
	sealer *secrets.Sealer
	auth   *auth.Service
	public *url.URL
	client *http.Client
	now    func() time.Time

	mu    sync.Mutex
	cache map[uuid.UUID]discovered
}

type discovered struct {
	updatedAt time.Time
	fetchedAt time.Time
	provider  *oidc.Provider
}

// New builds the service. public is EASYRMM_PUBLIC_URL: single sign-on
// works there only, as the redirect URI is registered with each provider.
func New(db *database.DB, auditLog *audit.Logger, sealer *secrets.Sealer, authSvc *auth.Service, public *url.URL) *Service {
	return &Service{
		db: db, audit: auditLog, sealer: sealer, auth: authSvc, public: public,
		client: providerClient(),
		now:    time.Now,
		cache:  map[uuid.UUID]discovered{},
	}
}

// providerClient reaches identity providers: never link-local or cloud
// metadata addresses (netguard), and no redirects, which could carry the
// client secret of a token request to another host.
func providerClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: netguard.Control}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			MaxIdleConnsPerHost:   2,
			IdleConnTimeout:       90 * time.Second,
			ForceAttemptHTTP2:     true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// RedirectURI is what administrators register with every provider.
func (s *Service) RedirectURI() string {
	return strings.TrimSuffix(s.public.String(), "/") + CallbackPath
}

func secretAD(id uuid.UUID) []byte { return []byte("easyrmm:sso:client_secret:" + id.String()) }

type providerRow struct {
	Provider
	sealed string
}

const providerColumns = `id, name, issuer, client_id, client_secret_sealed, allowed_domains, trust_email, trust_mfa, enabled, created_at, updated_at`

func scanProvider(row pgx.Row) (*providerRow, error) {
	var p providerRow
	err := row.Scan(&p.ID, &p.Name, &p.Issuer, &p.ClientID, &p.sealed, &p.AllowedDomains, &p.TrustEmail, &p.TrustMFA,
		&p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	return &p, err
}

func (s *Service) load(ctx context.Context, id uuid.UUID) (*providerRow, error) {
	var p *providerRow
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) (err error) {
		p, err = scanProvider(tx.QueryRow(ctx, `SELECT `+providerColumns+` FROM identity_providers WHERE id = $1`, id))
		return err
	})
	return p, err
}

// Providers lists every provider, for administrators.
func (s *Service) Providers(ctx context.Context) ([]Provider, error) {
	out := []Provider{}
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+providerColumns+` FROM identity_providers ORDER BY lower(name)`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			p, err := scanProvider(rows)
			if err != nil {
				return err
			}
			out = append(out, p.Provider)
		}
		return rows.Err()
	})
	return out, err
}

// Buttons lists the enabled providers for the sign-in page.
func (s *Service) Buttons(ctx context.Context) ([]Button, error) {
	out := []Button{}
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, name FROM identity_providers WHERE enabled ORDER BY lower(name)`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var b Button
			if err := rows.Scan(&b.ID, &b.Name); err != nil {
				return err
			}
			b.StartURL = strings.TrimSuffix(s.public.String(), "/") + "/api/v1/auth/sso/" + b.ID.String() + "/start"
			out = append(out, b)
		}
		return rows.Err()
	})
	return out, err
}

// issuerProblem says what is wrong with an issuer URL, or "". It must be
// HTTPS, or plain HTTP on a loopback address (tests).
func issuerProblem(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "Enter the provider's issuer URL, such as https://login.microsoftonline.com/<tenant id>/v2.0."
	}
	switch u.Scheme {
	case "https":
	case "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "Use HTTPS. Plain HTTP is accepted only on this server's own loopback address, for testing."
		}
	default:
		return "Use an https:// URL."
	}
	return ""
}

func domainRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.'
}

// normalizeDomain lower-cases an email domain and checks its form.
func normalizeDomain(d string) (string, bool) {
	d = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(d), "@")))
	if len(d) < 3 || len(d) > 253 || !strings.Contains(d, ".") || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") ||
		strings.Contains(d, "..") {
		return d, false
	}
	for _, r := range d {
		if !domainRune(r) {
			return d, false
		}
	}
	return d, true
}

func (s *Service) validate(in *ProviderInput, creating bool) apperr.Fields {
	f := apperr.Fields{}
	in.Name, in.Issuer, in.ClientID = strings.TrimSpace(in.Name), strings.TrimSpace(in.Issuer), strings.TrimSpace(in.ClientID)
	in.ClientSecret = strings.TrimSpace(in.ClientSecret)
	n := utf8.RuneCountInString(in.Name)
	f.Check(n >= 1 && n <= 64, "name", "Enter a name of up to 64 characters, such as Microsoft or Google.")
	if why := issuerProblem(in.Issuer); why != "" {
		f.Add("issuer", why)
	} else if len(in.Issuer) > 2048 {
		f.Add("issuer", "Use at most 2,048 characters.")
	}
	f.Check(in.ClientID != "" && len(in.ClientID) <= 512, "clientId", "Enter the client (application) ID the provider gave EasyRMM.")
	if creating {
		f.Check(in.ClientSecret != "", "clientSecret", "Enter the client secret the provider gave EasyRMM.")
	}
	f.Check(len(in.ClientSecret) <= 4096, "clientSecret", "Use at most 4,096 characters.")
	domains := []string{}
	for _, d := range in.AllowedDomains {
		if strings.TrimSpace(d) == "" {
			continue
		}
		nd, ok := normalizeDomain(d)
		if !ok {
			f.Add("allowedDomains", fmt.Sprintf("%q is not an email domain, such as example.com.", strings.TrimSpace(d)))
			continue
		}
		if !slices.Contains(domains, nd) {
			domains = append(domains, nd)
		}
	}
	in.AllowedDomains = domains
	if len(domains) == 0 {
		f.Add("allowedDomains", "List at least one email domain whose people may sign in through this provider.")
	}
	f.Check(len(domains) <= MaxDomains, "allowedDomains", fmt.Sprintf("List at most %d domains.", MaxDomains))
	return f
}

// discover fetches a provider's discovery document, which also checks that
// the issuer is what it claims to be.
func (s *Service) discover(ctx context.Context, issuer string) (*oidc.Provider, error) {
	ctx, cancel := context.WithTimeout(oidc.ClientContext(ctx, s.client), 15*time.Second)
	defer cancel()
	return oidc.NewProvider(ctx, issuer)
}

// providerFor returns the discovery for a provider, cached for an hour and
// refreshed when the provider changes.
func (s *Service) providerFor(ctx context.Context, p *providerRow) (*oidc.Provider, error) {
	s.mu.Lock()
	c, ok := s.cache[p.ID]
	s.mu.Unlock()
	if ok && c.updatedAt.Equal(p.UpdatedAt) && s.now().Sub(c.fetchedAt) < discoveryTTL {
		return c.provider, nil
	}
	op, err := s.discover(ctx, p.Issuer)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.cache[p.ID] = discovered{updatedAt: p.UpdatedAt, fetchedAt: s.now(), provider: op}
	s.mu.Unlock()
	return op, nil
}

func discoveryProblem(err error) error {
	return apperr.Invalid("issuer", "EasyRMM could not read this provider's OpenID configuration: "+err.Error())
}

func providerDetails(in ProviderInput) map[string]any {
	return map[string]any{"name": in.Name, "issuer": in.Issuer, "clientId": in.ClientID, "allowedDomains": in.AllowedDomains,
		"trustEmail": in.TrustEmail, "trustMfa": in.TrustMFA, "enabled": in.Enabled}
}

func nameTaken(err error) bool {
	return database.IsUniqueViolation(err)
}

// CreateProvider adds a provider after checking its discovery document.
func (s *Service) CreateProvider(ctx context.Context, actor audit.Actor, in ProviderInput) (Provider, error) {
	if err := s.validate(&in, true).Err(); err != nil {
		return Provider{}, err
	}
	if _, err := s.discover(ctx, in.Issuer); err != nil {
		return Provider{}, discoveryProblem(err)
	}
	id := uuid.New()
	sealed, err := s.sealer.Seal([]byte(in.ClientSecret), secretAD(id))
	if err != nil {
		return Provider{}, err
	}
	var out *providerRow
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		out, err = scanProvider(tx.QueryRow(ctx, `INSERT INTO identity_providers
				(id, name, issuer, client_id, client_secret_sealed, allowed_domains, trust_email, trust_mfa, enabled)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING `+providerColumns,
			id, in.Name, in.Issuer, in.ClientID, sealed, in.AllowedDomains, in.TrustEmail, in.TrustMFA, in.Enabled))
		if err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: actor, Action: "sso.provider_create", TargetType: "identity_provider",
			TargetID: id.String(), Outcome: audit.Success, Details: providerDetails(in)})
	})
	if nameTaken(err) {
		return Provider{}, apperr.Invalid("name", "Another provider has this name.")
	}
	if err != nil {
		return Provider{}, err
	}
	return out.Provider, nil
}

// UpdateProvider changes a provider. The discovery document is read again
// when the issuer changes.
func (s *Service) UpdateProvider(ctx context.Context, actor audit.Actor, id uuid.UUID, in ProviderInput) (Provider, error) {
	stored, err := s.load(ctx, id)
	if err != nil {
		return Provider{}, err
	}
	if err := s.validate(&in, false).Err(); err != nil {
		return Provider{}, err
	}
	if in.Issuer != stored.Issuer {
		if _, err := s.discover(ctx, in.Issuer); err != nil {
			return Provider{}, discoveryProblem(err)
		}
	}
	sealed := stored.sealed
	if in.ClientSecret != "" {
		if sealed, err = s.sealer.Seal([]byte(in.ClientSecret), secretAD(id)); err != nil {
			return Provider{}, err
		}
	}
	var out *providerRow
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		out, err = scanProvider(tx.QueryRow(ctx, `UPDATE identity_providers SET name = $2, issuer = $3, client_id = $4,
				client_secret_sealed = $5, allowed_domains = $6, trust_email = $7, trust_mfa = $8, enabled = $9, updated_at = now()
			WHERE id = $1 RETURNING `+providerColumns,
			id, in.Name, in.Issuer, in.ClientID, sealed, in.AllowedDomains, in.TrustEmail, in.TrustMFA, in.Enabled))
		if err != nil {
			return err
		}
		d := providerDetails(in)
		d["secretChanged"] = in.ClientSecret != ""
		return s.audit.Write(ctx, tx, audit.Event{Actor: actor, Action: "sso.provider_update", TargetType: "identity_provider",
			TargetID: id.String(), Outcome: audit.Success, Details: d})
	})
	if nameTaken(err) {
		return Provider{}, apperr.Invalid("name", "Another provider has this name.")
	}
	if err != nil {
		return Provider{}, err
	}
	return out.Provider, nil
}

// DeleteProvider removes a provider and every identity linked through it.
func (s *Service) DeleteProvider(ctx context.Context, actor audit.Actor, id uuid.UUID) error {
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var name string
		var linked int
		err := tx.QueryRow(ctx, `WITH d AS (DELETE FROM identity_providers WHERE id = $1 RETURNING name)
			SELECT d.name, (SELECT count(*) FROM user_identities WHERE provider_id = $1) FROM d`, id).Scan(&name, &linked)
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound()
		}
		if err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: actor, Action: "sso.provider_delete", TargetType: "identity_provider",
			TargetID: id.String(), Outcome: audit.Success, Details: map[string]any{"name": name, "identities": linked}})
	})
	s.mu.Lock()
	delete(s.cache, id)
	s.mu.Unlock()
	return err
}

// Identity is a provider account linked to an EasyRMM user.
type Identity struct {
	ProviderID   uuid.UUID  `json:"providerId"`
	ProviderName string     `json:"providerName"`
	Email        string     `json:"email"`
	CreatedAt    time.Time  `json:"createdAt"`
	LastUsedAt   *time.Time `json:"lastUsedAt"`
}

// Identities lists the identities linked to a user.
func (s *Service) Identities(ctx context.Context, userID uuid.UUID) ([]Identity, error) {
	out := []Identity{}
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT i.provider_id, p.name, i.email, i.created_at, i.last_used_at
			FROM user_identities i JOIN identity_providers p ON p.id = i.provider_id
			WHERE i.user_id = $1 ORDER BY lower(p.name)`, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var i Identity
			if err := rows.Scan(&i.ProviderID, &i.ProviderName, &i.Email, &i.CreatedAt, &i.LastUsedAt); err != nil {
				return err
			}
			out = append(out, i)
		}
		return rows.Err()
	})
	return out, err
}

// Unlink removes a user's identity at a provider. The next sign-in through
// that provider links again by the email rules.
func (s *Service) Unlink(ctx context.Context, actor audit.Actor, userID, providerID uuid.UUID) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var name, email string
		err := tx.QueryRow(ctx, `WITH d AS (DELETE FROM user_identities WHERE user_id = $1 AND provider_id = $2 RETURNING provider_id, email)
			SELECT p.name, d.email FROM d JOIN identity_providers p ON p.id = d.provider_id`, userID, providerID).Scan(&name, &email)
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound()
		}
		if err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: actor, Action: "auth.sso_unlink", TargetType: "user", TargetID: userID.String(),
			Outcome: audit.Success, Details: map[string]any{"provider": name, "providerId": providerID.String(), "email": email}})
	})
}
