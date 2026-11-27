// Package tlsaddname is slice 5b3 of ADR-0055: it adds a DNS name pair (the
// console's name and its remote-access name) to an installation set up on an IP
// address. Adding checks that both names point at this server, moves both to
// Let's Encrypt through tlsmove, has the authority issue a second certificate
// for agents (served for the names whenever the Let's Encrypt certificate is
// not trusted), and tells agents about the names through the trust service.
//
// The pair becomes trusted once this server holds a Let's Encrypt certificate
// for both names and has reached itself through them; reachability is checked
// every day, and a browser that loaded the console through the name counts as
// proof where the server cannot reach its own public address. Only when both
// have failed for the whole grace period is the name no longer trusted. The
// pair never enters the authority's addresses: the certificate every agent
// sees on the IP address is unchanged.
package tlsaddname

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/tlscert"
	"github.com/paulmataruso/easyrmm/server/internal/tlsmove"
	"github.com/paulmataruso/easyrmm/server/internal/tlstrust"
)

// Grace is how long a name stays reachable after its last success.
const Grace = 7 * 24 * time.Hour

// ReachPath is where the server answers its own reachability fetch.
const ReachPath = "/.well-known/easyrmm-reach"

// States of the pair.
const (
	StatePending   = "pending"   // the certificates are not both in hand and reached yet
	StateTrusted   = "trusted"   // the pair is an origin
	StateUntrusted = "untrusted" // it was trusted and no longer is; the agent route stays
)

// Errors a caller can tell apart.
var (
	ErrNotIPInstall = errors.New("tlsaddname: the installation already has a DNS name")
	ErrExists       = errors.New("tlsaddname: a name pair is added already")
	ErrNone         = errors.New("tlsaddname: no name pair is added")
	ErrBadName      = errors.New("tlsaddname: not a valid DNS name")
	ErrNotSameSite  = errors.New("tlsaddname: the remote-access name must be on the same site as the console's name")
	ErrNotReachable = errors.New("tlsaddname: a name does not point at this server")
	ErrUnavailable  = errors.New("tlsaddname: this server cannot obtain Let's Encrypt certificates")
)

// Resolver looks names up (net.DefaultResolver does).
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Moves is tlsmove as the pair needs it.
type Moves interface {
	Start(ctx context.Context, actor audit.Actor, name, target string) error
	Cancel(ctx context.Context, actor audit.Actor, name string) error
	Served(name string) string
}

// Asker is the agent trust service.
type Asker interface {
	Ask(ctx context.Context, devices []uuid.UUID, t tlstrust.Target, force bool) error
}

// Authority is the internal authority's second certificate.
type Authority interface {
	SecondCertificate(names []string) (*tls.Certificate, error)
}

// Deps are what the service uses. A nil Authority or Trust skips that step.
type Deps struct {
	DB    *database.DB
	Audit *audit.Logger
	Moves Moves
	Trust Asker
	Auth  Authority
	// Notices receives the warning for a name that cannot be reached.
	Notices tlscert.Publisher
	// IPInstall says whether EASYRMM_PUBLIC_URL is an IP address, and
	// ServerIPs are the addresses a name must point at.
	IPInstall func() bool
	ServerIPs func(ctx context.Context) []net.IP
	// Held says whether a Let's Encrypt certificate is held for a name.
	Held     func(ctx context.Context, name string) bool
	Resolver Resolver
	// Fetch asks the name for the reachability token (default: HTTPS to the
	// name, whose certificate is not what is being proven).
	Fetch func(ctx context.Context, name string) (string, error)
	// OnTrust is called, with the pair, whenever it becomes trusted or stops
	// being: the origins, MeshCentral's config and WebAuthn follow it.
	OnTrust func(console, mesh string, trusted bool)
	Log     *slog.Logger
	Now     func() time.Time
}

// Service holds the added pair.
type Service struct {
	deps  Deps
	token string
	mu    sync.Mutex
	// pair is the added names, for the edge, which asks at every handshake.
	pair    atomic.Pointer[[2]string]
	trusted atomic.Bool
}

// New builds the service.
func New(d Deps) *Service {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Resolver == nil {
		d.Resolver = net.DefaultResolver
	}
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	if d.Fetch == nil {
		d.Fetch = fetchHTTPS
	}
	return &Service{deps: d, token: hex.EncodeToString(b)}
}

// ServeReach answers the server's own fetch with this process's token. It is
// mounted without authentication; the token says only that the request reached
// this process.
func (s *Service) ServeReach(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, s.token)
}

// Token is what ServeReach answers, for tests.
func (s *Service) Token() string { return s.token }

func fetchHTTPS(ctx context.Context, name string) (string, error) {
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		// What is proven is that the name reaches this server, by the token;
		// the name's certificate may not be served yet.
		TLSClientConfig:   &tls.Config{ServerName: name, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // see above
		DisableKeepAlives: true,
	}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+name+ReachPath, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the name answered %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	return strings.TrimSpace(string(b)), err
}

func normName(n string) (string, error) {
	n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
	if n == "" || len(n) > 253 || net.ParseIP(n) != nil || !strings.Contains(n, ".") {
		return "", ErrBadName
	}
	for _, l := range strings.Split(n, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", ErrBadName
		}
		for _, r := range l {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "", ErrBadName
			}
		}
	}
	return n, nil
}

// sameSite holds when the remote-access name is under the console's parent
// domain, which must itself be a name (rmm.example.com and mesh.rmm.example.com
// share example.com), the rule .env's names follow.
func sameSite(console, mesh string) bool {
	_, parent, ok := strings.Cut(console, ".")
	if !ok || !strings.Contains(parent, ".") {
		return false
	}
	return mesh == parent || strings.HasSuffix(mesh, "."+parent)
}

// SuggestMesh is the remote-access name the page fills in.
func SuggestMesh(console string) string { return "mesh." + console }

// NameCheck is the findings for one name.
type NameCheck struct {
	Name string `json:"name"`
	// Addresses the name resolves to.
	Addresses []string `json:"addresses"`
	// Points says one of them is this server's.
	Points bool   `json:"points"`
	Error  string `json:"error,omitempty"`
}

// Preflight resolves both names and says whether they point at this server.
func (s *Service) Preflight(ctx context.Context, console, mesh string) ([]NameCheck, error) {
	console, mesh, err := s.names(console, mesh)
	if err != nil {
		return nil, err
	}
	var mine []net.IP
	if s.deps.ServerIPs != nil {
		mine = s.deps.ServerIPs(ctx)
	}
	out := make([]NameCheck, 0, 2)
	for _, n := range []string{console, mesh} {
		c := NameCheck{Name: n, Addresses: []string{}}
		addrs, err := s.deps.Resolver.LookupIPAddr(ctx, n)
		if err != nil {
			c.Error = "The name does not resolve yet. Create its A (and AAAA) record with this server's public address."
		}
		for _, a := range addrs {
			c.Addresses = append(c.Addresses, a.IP.String())
			if slices.ContainsFunc(mine, a.IP.Equal) {
				c.Points = true
			}
		}
		if err == nil && !c.Points {
			c.Error = "The name resolves, but not to an address of this server."
		}
		out = append(out, c)
	}
	return out, nil
}

func (s *Service) names(console, mesh string) (string, string, error) {
	c, err := normName(console)
	if err != nil {
		return "", "", err
	}
	if strings.TrimSpace(mesh) == "" {
		mesh = SuggestMesh(c)
	}
	m, err := normName(mesh)
	if err != nil {
		return "", "", err
	}
	if c == m {
		return "", "", ErrBadName
	}
	if !sameSite(c, m) {
		return "", "", ErrNotSameSite
	}
	return c, m, nil
}

// Pair is the added pair and what is known of it.
type Pair struct {
	Console string `json:"console"`
	Mesh    string `json:"mesh"`
	// State is pending, trusted or untrusted.
	State     string     `json:"state"`
	AddedAt   time.Time  `json:"addedAt"`
	TrustedAt *time.Time `json:"trustedAt,omitempty"`
	// Held says, per name, that a Let's Encrypt certificate is in hand.
	Held      map[string]bool `json:"held"`
	Reachable bool            `json:"reachable"`
	// The evidence of reachability.
	LastFetchAt     *time.Time `json:"lastFetchAt,omitempty"`
	LastFetchOKAt   *time.Time `json:"lastFetchOkAt,omitempty"`
	LastFetchError  string     `json:"lastFetchError,omitempty"`
	LastBrowserOKAt *time.Time `json:"lastBrowserOkAt,omitempty"`
	// Agents counts the devices asked to verify the authority's second
	// certificate, and how many have.
	AgentsAsked  int `json:"agentsAsked"`
	AgentsPassed int `json:"agentsPassed"`
}

func (s *Service) load(ctx context.Context) (*Pair, error) {
	p := &Pair{}
	err := s.deps.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		e := tx.QueryRow(ctx, `SELECT console_name, mesh_name, state, added_at, trusted_at, last_fetch_at, last_fetch_ok_at, last_fetch_error, last_browser_ok_at
			FROM tls_added_names`).Scan(&p.Console, &p.Mesh, &p.State, &p.AddedAt, &p.TrustedAt, &p.LastFetchAt, &p.LastFetchOKAt, &p.LastFetchError, &p.LastBrowserOKAt)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNone
		}
		return e
	})
	if err != nil {
		return nil, err
	}
	p.Held = map[string]bool{}
	for _, n := range []string{p.Console, p.Mesh} {
		p.Held[n] = s.held(ctx, n)
	}
	p.Reachable = reachable(p, s.deps.Now())
	return p, nil
}

func (s *Service) held(ctx context.Context, n string) bool {
	return s.deps.Held != nil && s.deps.Moves != nil && s.deps.Moves.Served(n) == tlsmove.SourceACME && s.deps.Held(ctx, n)
}

func reachable(p *Pair, now time.Time) bool {
	for _, t := range []*time.Time{p.LastFetchOKAt, p.LastBrowserOKAt} {
		if t != nil && now.Sub(*t) <= Grace {
			return true
		}
	}
	return false
}

// Status returns the added pair, or ErrNone.
func (s *Service) Status(ctx context.Context) (*Pair, error) {
	p, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	p.AgentsAsked, p.AgentsPassed = s.agentCounts(ctx, p)
	return p, nil
}

// Eligible says whether a pair can be added: the install's public URL is an IP
// address and there is no pair yet.
func (s *Service) Eligible(ctx context.Context) bool {
	if s.deps.IPInstall == nil || !s.deps.IPInstall() {
		return false
	}
	_, err := s.load(ctx)
	return errors.Is(err, ErrNone)
}

func (s *Service) record(ctx context.Context, actor audit.Actor, action string, d map[string]any) {
	if s.deps.Audit == nil {
		return
	}
	if err := s.deps.Audit.Record(ctx, audit.Event{Actor: actor, Action: action, TargetType: "tls_name", TargetID: fmt.Sprint(d["console"]),
		Outcome: audit.Success, Details: d}); err != nil {
		s.deps.Log.Error("tls: audit failed", "action", action, "error", err)
	}
}

func isUnique(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}

// Add adds the pair. The names must point at this server; both are moved to
// Let's Encrypt (the move holds each certificate until it is in hand), the
// authority's second certificate is issued, and agents are asked to verify it.
// The caller has already required step-up authentication.
func (s *Service) Add(ctx context.Context, actor audit.Actor, console, mesh string) error {
	c, m, err := s.names(console, mesh)
	if err != nil {
		return err
	}
	if s.deps.IPInstall == nil || !s.deps.IPInstall() {
		return ErrNotIPInstall
	}
	if s.deps.Moves == nil || s.deps.Held == nil {
		return ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.load(ctx); err == nil {
		return ErrExists
	} else if !errors.Is(err, ErrNone) {
		return err
	}
	checks, err := s.Preflight(ctx, c, m)
	if err != nil {
		return err
	}
	for _, k := range checks {
		if !k.Points {
			return fmt.Errorf("%w: %s", ErrNotReachable, k.Name)
		}
	}
	var by any
	if actor.ID != uuid.Nil {
		by = actor.ID
	}
	err = s.deps.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO tls_added_names (console_name, mesh_name, added_by) VALUES ($1, $2, $3)`, c, m, by)
		return e
	})
	if err != nil {
		if isUnique(err) {
			return ErrExists
		}
		return err
	}
	for i, n := range []string{c, m} {
		if err := s.deps.Moves.Start(ctx, actor, n, tlsmove.SourceACME); err != nil {
			if i == 1 {
				_ = s.deps.Moves.Cancel(ctx, actor, c)
			}
			_ = s.drop(ctx)
			return fmt.Errorf("getting a certificate for %s: %w", n, err)
		}
	}
	s.pair.Store(&[2]string{c, m})
	s.record(ctx, actor, "tls.name_added", map[string]any{"console": c, "mesh": m})
	if err := s.askAgents(ctx, c, m); err != nil {
		// The pair is added; Resend asks again.
		s.deps.Log.Warn("tls: asking agents about an added name failed", "error", err)
	}
	return nil
}

func (s *Service) drop(ctx context.Context) error {
	return s.deps.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM tls_added_names`)
		return err
	})
}

// askAgents has every enrolled device seen in the last 30 days, inside the
// development scope (ADR-0069), verify the authority's second certificate for
// each name. Agents enrolled on the IP address already trust the authority, so
// nothing is added to their trust.
func (s *Service) askAgents(ctx context.Context, c, m string) error {
	if s.deps.Trust == nil || s.deps.Auth == nil {
		return nil
	}
	cert, err := s.deps.Auth.SecondCertificate([]string{c, m})
	if err != nil {
		return err
	}
	ids, err := s.devices(ctx)
	if err != nil || len(ids) == 0 {
		return err
	}
	for _, n := range []string{c, m} {
		t := tlstrust.Target{Origin: n, Chains: []tlstrust.Chain{{Purpose: agentproto.TrustTarget, DER: cert.Certificate}}}
		if err := s.deps.Trust.Ask(ctx, ids, t, false); err != nil {
			return err
		}
	}
	return nil
}

// Resend asks the devices again, for those enrolled since.
func (s *Service) Resend(ctx context.Context) error {
	p, err := s.load(ctx)
	if err != nil {
		return err
	}
	return s.askAgents(ctx, p.Console, p.Mesh)
}

func (s *Service) devices(ctx context.Context) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	err := s.deps.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, organization_id FROM devices WHERE agent_public_key IS NOT NULL
			AND agent_last_seen_at > $1 ORDER BY id`, s.deps.Now().Add(-tlsmove.SeenWithin))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, org uuid.UUID
			if err := rows.Scan(&id, &org); err != nil {
				return err
			}
			if devscope.Allowed(org) {
				ids = append(ids, id)
			}
		}
		return rows.Err()
	})
	return ids, err
}

func (s *Service) agentCounts(ctx context.Context, p *Pair) (asked, passed int) {
	_ = s.deps.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(DISTINCT device_id), count(DISTINCT device_id) FILTER (WHERE state = 'passed')
			FROM device_tls_trust WHERE host = $1 AND purpose = 'target' AND scope = 'agent'`, p.Console).Scan(&asked, &passed)
	})
	return
}

// Remove drops the pair. A name served from Let's Encrypt goes back to the
// source .env gives it (a move, which waits for the devices that use it); the
// name keeps routing the agent API with the second certificate. The console,
// links, framing and allowed origins return to the IP address.
func (s *Service) Remove(ctx context.Context, actor audit.Actor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.load(ctx)
	if err != nil {
		return err
	}
	for _, n := range []string{p.Console, p.Mesh} {
		_ = s.deps.Moves.Cancel(ctx, actor, n) // nothing waiting is fine
		if s.deps.Moves.Served(n) == tlsmove.SourceACME {
			if err := s.deps.Moves.Start(ctx, actor, n, tlsmove.SourceEnv); err != nil && !errors.Is(err, tlsmove.ErrSameSource) {
				return fmt.Errorf("moving %s back: %w", n, err)
			}
		}
	}
	if err := s.drop(ctx); err != nil {
		return err
	}
	s.pair.Store(nil)
	s.trusted.Store(false)
	if p.State == StateTrusted && s.deps.OnTrust != nil {
		s.deps.OnTrust(p.Console, p.Mesh, false)
	}
	s.resolveNotice(ctx, p)
	s.record(ctx, actor, "tls.name_removed", map[string]any{"console": p.Console, "mesh": p.Mesh})
	return nil
}

// Load reads the added pair into the edge's cache; call it before the edge
// serves. The cache follows Add, Remove and Tick.
func (s *Service) Load(ctx context.Context) error {
	p, err := s.load(ctx)
	if errors.Is(err, ErrNone) {
		s.pair.Store(nil)
		return nil
	}
	if err != nil {
		return err
	}
	s.pair.Store(&[2]string{p.Console, p.Mesh})
	s.trusted.Store(p.State == StateTrusted)
	return nil
}

// IsAdded says whether name is one of the pair, without touching the database.
func (s *Service) IsAdded(name string) bool {
	p := s.pair.Load()
	name = strings.ToLower(name)
	return p != nil && (name == p[0] || name == p[1])
}

// SecondCertificate is the authority's certificate for the pair: the edge
// serves it for an added name whenever its Let's Encrypt certificate is not
// trusted or not valid.
func (s *Service) SecondCertificate() (*tls.Certificate, error) {
	p := s.pair.Load()
	if p == nil {
		return nil, ErrNone
	}
	if s.deps.Auth == nil {
		return nil, ErrUnavailable
	}
	return s.deps.Auth.SecondCertificate([]string{p[0], p[1]})
}

// Trusted says whether name is one of a trusted pair, without touching the
// database: the edge serves its Let's Encrypt certificate only then.
func (s *Service) Trusted(name string) bool {
	return s.IsAdded(name) && s.trusted.Load()
}

// BrowserConfirm records that a signed-in person loaded the console through
// host. It does nothing for any other host.
func (s *Service) BrowserConfirm(ctx context.Context, host string) error {
	host = strings.ToLower(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return s.deps.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE tls_added_names SET last_browser_ok_at = $2, updated_at = now() WHERE console_name = $1 OR mesh_name = $1`, host, s.deps.Now())
		return err
	})
}

// Tick runs the reachability fetch for both names, at most once an hour, and
// moves the pair between its states.
func (s *Service) Tick(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.load(ctx)
	if err != nil {
		if !errors.Is(err, ErrNone) {
			s.deps.Log.Warn("tls: reading the added name failed", "error", err)
		}
		return
	}
	now := s.deps.Now()
	if p.LastFetchAt == nil || now.Sub(*p.LastFetchAt) >= time.Hour {
		ferr := s.fetchBoth(ctx, p)
		msg := ""
		okAt := p.LastFetchOKAt
		if ferr != nil {
			msg = ferr.Error()
		} else {
			okAt = &now
		}
		err := s.deps.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `UPDATE tls_added_names SET last_fetch_at = $2, last_fetch_ok_at = $3, last_fetch_error = $4, updated_at = now() WHERE console_name = $1`,
				p.Console, now, okAt, msg)
			return e
		})
		if err != nil {
			s.deps.Log.Warn("tls: recording a reachability fetch failed", "error", err)
			return
		}
		p.LastFetchAt, p.LastFetchOKAt, p.LastFetchError = &now, okAt, msg
		p.Reachable = reachable(p, now)
	}
	s.advance(ctx, p)
	s.notice(ctx, p)
}

func (s *Service) fetchBoth(ctx context.Context, p *Pair) error {
	for _, n := range []string{p.Console, p.Mesh} {
		got, err := s.deps.Fetch(ctx, n)
		if err != nil {
			return fmt.Errorf("%s: %w", n, err)
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			return fmt.Errorf("%s: the name answers, but not from this server", n)
		}
	}
	return nil
}

// advance moves the state: pending becomes trusted when both certificates are
// held and the pair is reachable; a trusted pair stops being so when it is not
// reachable for the whole grace period or a certificate is gone.
func (s *Service) advance(ctx context.Context, p *Pair) {
	all := p.Held[p.Console] && p.Held[p.Mesh]
	next := p.State
	switch {
	case p.State != StateTrusted && all && p.Reachable:
		next = StateTrusted
	case p.State == StateTrusted && (!all || !p.Reachable):
		next = StateUntrusted
	}
	if next == p.State {
		s.trusted.Store(p.State == StateTrusted)
		return
	}
	err := s.deps.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE tls_added_names SET state = $2, trusted_at = CASE WHEN $2 = 'trusted' THEN $3::timestamptz ELSE trusted_at END, updated_at = now()
			WHERE console_name = $1`, p.Console, next, s.deps.Now())
		return e
	})
	if err != nil {
		s.deps.Log.Warn("tls: moving the added name's state failed", "error", err)
		return
	}
	p.State = next
	s.trusted.Store(next == StateTrusted)
	s.record(ctx, audit.SystemActor("tls"), "tls.name_"+next, map[string]any{"console": p.Console, "mesh": p.Mesh})
	if s.deps.OnTrust != nil {
		s.deps.OnTrust(p.Console, p.Mesh, next == StateTrusted)
	}
}

func noticeKey(p *Pair) string { return "tls:" + p.Console }

// notice opens a warning when the day's fetch failed and no browser confirmed
// it that day, and resolves it at the next success.
func (s *Service) notice(ctx context.Context, p *Pair) {
	if s.deps.Notices == nil {
		return
	}
	now := s.deps.Now()
	failing := p.LastFetchError != "" && (p.LastBrowserOKAt == nil || now.Sub(*p.LastBrowserOKAt) > 24*time.Hour)
	ev := tlscert.Event{Key: noticeKey(p), Name: p.Console, Open: failing, Link: "/settings?tab=certificates"}
	if failing {
		ev.Severity = "warning"
		ev.Summary = fmt.Sprintf("The added name %s cannot be reached through itself, and no browser has confirmed it today.", p.Console)
		ev.LastError = p.LastFetchError
	}
	if err := s.deps.Notices.Publish(ctx, ev); err != nil {
		s.deps.Log.Warn("tls: publishing an added name's notice failed", "error", err)
	}
}

func (s *Service) resolveNotice(ctx context.Context, p *Pair) {
	if s.deps.Notices != nil {
		_ = s.deps.Notices.Publish(ctx, tlscert.Event{Key: noticeKey(p), Name: p.Console})
	}
}

// Run ticks until ctx ends.
func (s *Service) Run(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 5 * time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Tick(ctx)
		}
	}
}
