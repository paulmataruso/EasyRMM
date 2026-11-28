// Package tlscert is the certificate service (ADR-0055, slice 5a): CertMagic
// obtains and renews the certificates of the names in .env, and EasyRMM
// decides every attempt. CertMagic's own retries would go to staging, forget
// everything at a restart and ignore the host updater's hold, so the
// scheduler here starts each attempt, one gate (CertMagic's cert_obtaining
// event) refuses any other, and the state lives in PostgreSQL. Certificates
// and the account's key are kept in PostgreSQL too, sealed with
// EASYRMM_SECRET_KEY; no key is logged or sent to the console.
package tlscert

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
)

// Settings are what the service reads from the environment.
type Settings struct {
	// Names are the DNS names to hold a certificate for; MeshName is
	// MeshCentral's, one of them, or empty.
	Names    []string
	MeshName string
	// Directory is the ACME directory (EASYRMM_ACME_DIRECTORY), Email the
	// optional contact address, RootsPEM the roots to trust for the
	// directory's own HTTPS (EASYRMM_ACME_CA_FILE).
	Directory string
	Email     string
	RootsPEM  []byte
	// HTTPPort and TLSPort are those of the edge's listeners (HTTPPort empty
	// when port 80 is off): where challenges are answered.
	HTTPPort string
	TLSPort  string
	// AutocertDir is where autocert kept its cache before this release.
	AutocertDir string
	// Instance names this server in tls_mesh_reads.
	Instance string
	// Interval is the scheduler's (a minute), RenewCheck CertMagic's
	// maintenance interval (ten minutes); tests shorten them.
	Interval   time.Duration
	RenewCheck time.Duration
	// Lookup resolves a name the way the server sees it; nil means the
	// system's resolver.
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// Own returns this server's addresses, which the checks accept and
	// compare a name's records with.
	Own func() []netip.Addr
	// CheckHTTPPort and CheckHTTPSPort are where the checks look for ports 80
	// and 443 at the name's addresses.
	CheckHTTPPort, CheckHTTPSPort string
	// AllowDial, when set, replaces the checks' address policy (tests).
	AllowDial func(netip.Addr) bool
	// CAAResolvers are the resolvers (host:port) the CAA check asks; none
	// means those of /etc/resolv.conf.
	CAAResolvers []string
	// Warnings are notes the page shows (an ignored EASYRMM_MESH_CERT_URL).
	Warnings []string
	// DNSSolver returns a DNS-01 solver for the named host, or nil when no
	// DNS credentials cover its zone (ADR-0055, 5b4).
	DNSSolver func(ctx context.Context, name string) (*certmagic.DNS01Solver, error)
}

// Event is what the service tells people about a name (ADR-0055, "When a
// certificate is missing or failing"): opened, or resolved, under the stable
// key tls:<name>.
type Event struct {
	Key       string
	Name      string
	Open      bool
	Severity  string // warning or critical, when opening
	Summary   string
	LastError string
	Link      string
}

// Publisher is the one interface through which the service reaches people:
// the console's banner and the notification sender's platform rules (ADR-0053)
// sit behind it. The console alone does until that sender exists.
type Publisher interface {
	Publish(ctx context.Context, e Event) error
}

// Deps are what the service uses.
type Deps struct {
	DB     *database.DB
	Sealer *secrets.Sealer
	Audit  *audit.Logger
	// Held reports the host updater's hold: no attempt is made during it.
	Held   func() bool
	Alerts Publisher
	Log    *slog.Logger
	Now    func() time.Time
}

// Service obtains and renews the certificates.
type Service struct {
	deps  Deps
	set   Settings
	store *Storage
	slot  *MeshSlot

	cache  *certmagic.Cache
	magic  *certmagic.Config
	issuer *certmagic.ACMEIssuer

	mu           sync.Mutex
	started      bool
	accountReady bool
	inflight     map[string]bool
	hashes       map[string]string // the hash of the certificate cached for each name
	lastChecked  map[string]time.Time
	acctURI      string
	serving      chan struct{}
	servingOnce  sync.Once
}

// New returns a service; Start prepares it.
func New(deps Deps, set Settings) *Service {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Held == nil {
		deps.Held = func() bool { return false }
	}
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	if set.Interval <= 0 {
		set.Interval = time.Minute
	}
	if set.RenewCheck <= 0 {
		set.RenewCheck = 10 * time.Minute
	}
	for i, n := range set.Names {
		set.Names[i] = strings.ToLower(n)
	}
	set.MeshName = strings.ToLower(set.MeshName)
	if set.Instance == "" {
		set.Instance = "server"
	}
	return &Service{deps: deps, set: set, store: NewStorage(deps.DB, deps.Sealer), slot: &MeshSlot{},
		inflight: map[string]bool{}, hashes: map[string]string{}, serving: make(chan struct{})}
}

// Close stops CertMagic's maintenance loop.
func (s *Service) Close() {
	if s.cache != nil {
		s.cache.Stop()
	}
}

// SetHeld tells the service how to learn of the host updater's hold, which is
// read after the service is built.
func (s *Service) SetHeld(f func() bool) { s.deps.Held = f }

// Storage returns the PostgreSQL storage, for tools and tests.
func (s *Service) Storage() *Storage { return s.store }

// Slot returns MeshCentral's certificate slot.
func (s *Service) Slot() *MeshSlot { return s.slot }

// Managed reports whether host is one of the names the service holds
// certificates for.
func (s *Service) Managed(host string) bool {
	return slices.Contains(s.set.Names, strings.ToLower(strings.TrimSuffix(host, ".")))
}

// Serving tells the service the edge's listeners are open: challenges can be
// answered, so attempts may begin.
func (s *Service) Serving() { s.servingOnce.Do(func() { close(s.serving) }) }

// Start prepares the service: storage re-sealed with the current key,
// autocert's state imported, CertMagic configured with the named account,
// and the certificates found loaded. It makes no attempt and talks to
// nobody; a failure to reach the CA waits for the scheduler.
func (s *Service) Start(ctx context.Context) error {
	if err := s.store.Reseal(ctx); err != nil {
		return err
	}
	zl := zapLogger(s.deps.Log)
	s.cache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert:   func(certmagic.Certificate) (*certmagic.Config, error) { return s.magic, nil },
		RenewCheckInterval: s.set.RenewCheck,
		Logger:             zl,
	})
	s.magic = certmagic.New(s.cache, certmagic.Config{
		Storage: s.store,
		Logger:  zl,
		OnEvent: s.onEvent,
		OCSP:    certmagic.OCSPConfig{DisableStapling: true},
	})
	imported, err := s.importAutocert(ctx)
	if err != nil {
		return fmt.Errorf("importing autocert's state: %w", err)
	}
	key, err := s.loadAccountKey(ctx)
	if err != nil {
		return err
	}
	iss := certmagic.NewACMEIssuer(s.magic, certmagic.ACMEIssuer{
		CA:                   s.set.Directory,
		TestCA:               s.set.Directory, // never staging: only EasyRMM's own trial order (5b) goes there
		Email:                s.set.Email,
		Agreed:               true, // the operator accepted the agreement by choosing acme
		AccountKeyPEM:        string(key),
		TrustedRoots:         s.set.roots(),
		DisableHTTPChallenge: s.set.HTTPPort == "",
		Logger:               zl,
	})
	if p := s.set.HTTPPort; p != "" {
		iss.AltHTTPPort = portNumber(p)
	}
	iss.AltTLSALPNPort = portNumber(s.set.TLSPort)
	if s.set.DNSSolver != nil {
		iss.DNS01Solver = newDNSSolverMux(s.set.DNSSolver)
	}
	s.issuer = iss
	s.magic.Issuers = []certmagic.Issuer{iss}

	dropped, err := s.ensureRows(ctx, s.set.Names)
	if err != nil {
		return err
	}
	for _, n := range dropped {
		s.publish(ctx, Event{Key: "tls:" + n, Name: n, Open: false})
	}
	if len(imported) > 0 {
		s.auditSystem(ctx, "tls.import", "", map[string]any{"names": imported, "source": "autocert"})
	}
	if t, ok := s.lastMeshRead(ctx); ok {
		s.slot.SetLastRead(t)
	}
	for _, n := range s.set.Names {
		if err := s.syncName(ctx, n); err != nil && !errors.Is(err, errNoCertificate) {
			s.deps.Log.Warn("tls: loading a stored certificate failed", "name", n, "error", err)
		}
	}
	if len(imported) > 0 {
		// Imported certificates are marked, so that the page says where they came from.
		for _, n := range imported {
			_ = s.markImported(ctx, n)
		}
	}
	s.mu.Lock()
	s.started = true
	s.mu.Unlock()
	return nil
}

func portNumber(p string) int {
	if _, port, err := net.SplitHostPort(p); err == nil {
		p = port
	}
	p = strings.TrimPrefix(p, ":")
	var n int
	_, _ = fmt.Sscanf(p, "%d", &n)
	return n
}

// GetCertificate answers a handshake. No name is ordered at a handshake:
// every certificate comes from storage, loaded at start and when renewed.
// MeshCentral's name is answered from the slot, which changes only by its own
// rule; a TLS-ALPN-01 challenge for any name is CertMagic's.
func (s *Service) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if s.magic == nil {
		return nil, errors.New("tls: the certificate service has not started")
	}
	if s.set.MeshName != "" && strings.EqualFold(hello.ServerName, s.set.MeshName) && !slices.Contains(hello.SupportedProtos, "acme-tls/1") {
		if c := s.slot.Served(); c != nil {
			return c, nil
		}
	}
	if !s.Managed(hello.ServerName) && !slices.Contains(hello.SupportedProtos, "acme-tls/1") {
		return nil, fmt.Errorf("tls: no certificate for %q", hello.ServerName)
	}
	return s.magic.GetCertificate(hello)
}

// HTTPHandler answers HTTP-01 challenges, for the names the service holds
// certificates for only; anything else under /.well-known/acme-challenge/ is
// refused and passed on to nothing. Other requests go to next.
func (s *Service) HTTPHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if certmagic.LooksLikeHTTPChallenge(r) {
			host := r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if s.issuer != nil && s.Managed(host) && s.issuer.HandleHTTPChallenge(w, r) {
				return
			}
			http.NotFound(w, r)
			return
		}
		s.checkProbe(w, r, func() { next.ServeHTTP(w, r) })
	})
}

// ErrBusy is returned when an attempt for the name is already running.
var ErrBusy = errors.New("tls: an attempt for this name is already running")

// ErrHeld is returned while the host updater's hold is on.
var ErrHeld = errors.New("tls: the server is held for an update; attempts wait for its end")

// ErrNoAccount is returned when the account is not established.
var ErrNoAccount = errors.New("tls: the ACME account is not established yet")

// RefusedError says why an attempt is refused and when it could run.
type RefusedError struct {
	Reason  string
	RetryAt time.Time
}

func (e *RefusedError) Error() string {
	if e.RetryAt.IsZero() {
		return "tls: " + e.Reason
	}
	return fmt.Sprintf("tls: %s; it can run at %s", e.Reason, e.RetryAt.UTC().Format(time.RFC3339))
}

// Attempt kinds.
const (
	kindScheduled   = "scheduled"
	kindRetry       = "retry"
	kindOrderAnyway = "order_anyway"
)

type attemptKey struct{}

type attemptInfo struct{ name, kind string }

// errGate is what the gate cancels an attempt with.
var errGate = errors.New("refused by EasyRMM's gate")

// permit decides whether an attempt of this kind may start now.
func (s *Service) permit(r Row, kind string, now time.Time) error {
	if s.deps.Held() {
		return ErrHeld
	}
	limit := retryBudget
	if kind == kindScheduled {
		limit = autoBudget
		if now.Before(r.NextAttemptAt) {
			return &RefusedError{Reason: "the next attempt is not due", RetryAt: r.NextAttemptAt}
		}
	}
	if ok, at := withinBudget(r.FailedAt, limit, now); !ok {
		return &RefusedError{Reason: fmt.Sprintf("%d validations of this name have failed within the last hour", len(pruneHour(r.FailedAt, now))), RetryAt: at}
	}
	return nil
}

// onEvent is the gate. Every attempt, whoever starts it, emits cert_obtaining
// under the name's storage lock; an error from here cancels it. Only the
// scheduler's (and a person's Retry now or Order anyway), within the budget
// and outside a hold, go on, and each is written down first.
func (s *Service) onEvent(ctx context.Context, event string, data map[string]any) error {
	if event != "cert_obtaining" {
		return nil
	}
	ai, _ := ctx.Value(attemptKey{}).(*attemptInfo)
	name, _ := data["identifier"].(string)
	if ai == nil || !strings.EqualFold(ai.name, name) {
		return fmt.Errorf("%w: the attempt was not started by the scheduler", errGate)
	}
	now := s.deps.Now()
	row, err := s.loadRow(ctx, ai.name)
	if err != nil {
		return fmt.Errorf("%w: %s", errGate, err.Error())
	}
	if err := s.permit(row, ai.kind, now); err != nil {
		return fmt.Errorf("%w: %s", errGate, err.Error())
	}
	if err := s.recordAttempt(ctx, ai.name, ai.kind, now); err != nil {
		return fmt.Errorf("%w: %s", errGate, err.Error())
	}
	return nil
}

// attempt makes one attempt for a name: an order when it has no certificate,
// a renewal otherwise.
func (s *Service) attempt(ctx context.Context, name, kind string) error {
	s.mu.Lock()
	if s.inflight[name] {
		s.mu.Unlock()
		return ErrBusy
	}
	s.inflight[name] = true
	ready := s.accountReady
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.inflight, name)
		s.mu.Unlock()
	}()
	if !ready {
		return ErrNoAccount
	}
	row, err := s.loadRow(ctx, name)
	if err != nil {
		return err
	}
	now := s.deps.Now()
	if err := s.permit(row, kind, now); err != nil {
		return err
	}
	actx, cancel := context.WithTimeout(context.WithValue(ctx, attemptKey{}, &attemptInfo{name: name, kind: kind}), 10*time.Minute)
	defer cancel()
	renew := s.store.Exists(ctx, certmagic.StorageKeys.SiteCert(s.issuerKey(), name))
	if renew {
		err = s.magic.RenewCertSync(actx, name, false)
	} else {
		err = s.magic.ObtainCertSync(actx, name)
	}
	if err != nil {
		if errors.Is(err, errGate) {
			return err
		}
		failed, ferr := s.recordFailure(ctx, name, err.Error(), s.deps.Now())
		if ferr != nil {
			s.deps.Log.Error("tls: recording a failed attempt failed", "name", name, "error", ferr)
		}
		s.deps.Log.Warn("tls: certificate attempt failed", "name", name, "kind", kind, "failures", failed.Failures, "next", failed.NextAttemptAt, "error", err)
		s.auditSystem(ctx, "tls.certificate_fail", name, map[string]any{"kind": kind, "renewal": renew, "failures": failed.Failures, "error": clip(err.Error(), 500)})
		s.evaluate(ctx, name)
		return err
	}
	if err := s.syncName(ctx, name); err != nil {
		return err
	}
	if row2, err := s.loadRow(ctx, name); err == nil && row2.Serial != row.Serial {
		action := "tls.certificate_obtain"
		if renew {
			action = "tls.certificate_renew"
		}
		s.auditSystem(ctx, action, name, map[string]any{"kind": kind, "serial": row2.Serial, "issuer": row2.Issuer,
			"not_before": row2.NotBefore, "not_after": row2.NotAfter})
	}
	s.evaluate(ctx, name)
	return nil
}

// RetryNow makes one attempt at once for a name that has none or is failing.
// It is refused, saying when it could run, once 4 validations have failed
// within the hour, and during the hold. The attempt runs in the background:
// the page shows it as renewing.
func (s *Service) RetryNow(ctx context.Context, actor audit.Actor, name string) error {
	return s.byPerson(ctx, actor, strings.ToLower(name), kindRetry, "tls.retry")
}

// OrderAnyway orders for a name the server cannot resolve (split-horizon
// resolvers, where it cannot see the public answer), without waiting for DNS.
func (s *Service) OrderAnyway(ctx context.Context, actor audit.Actor, name string) error {
	return s.byPerson(ctx, actor, strings.ToLower(name), kindOrderAnyway, "tls.order_anyway")
}

func (s *Service) byPerson(ctx context.Context, actor audit.Actor, name, kind, action string) error {
	if !s.Managed(name) {
		return ErrNoName
	}
	row, err := s.loadRow(ctx, name)
	if err != nil {
		return err
	}
	if err := s.permit(row, kind, s.deps.Now()); err != nil {
		return err
	}
	s.mu.Lock()
	busy, ready := s.inflight[name], s.accountReady
	s.mu.Unlock()
	if busy {
		return ErrBusy
	}
	if !ready {
		if err := s.ensureAccount(ctx); err != nil {
			return fmt.Errorf("%w: %s", ErrNoAccount, err.Error())
		}
	}
	if kind == kindOrderAnyway {
		if err := s.setOrderAnyway(ctx, name); err != nil {
			return err
		}
	}
	_ = s.deps.Audit.Record(ctx, audit.Event{Actor: actor, Action: action, TargetType: "tls_name", TargetID: name, Outcome: audit.Success,
		Details: map[string]any{"name": name}})
	go func() {
		bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 12*time.Minute)
		defer cancel()
		if err := s.attempt(bg, name, kind); err != nil {
			s.deps.Log.Info("tls: an attempt a person asked for did not succeed", "name", name, "error", err)
		}
	}()
	return nil
}

func (s *Service) setOrderAnyway(ctx context.Context, name string) error {
	return s.deps.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE tls_certificates SET order_anyway = true WHERE name = $1`, name)
		return err
	})
}

func (s *Service) markImported(ctx context.Context, name string) error {
	return s.deps.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE tls_certificates SET imported = true WHERE name = $1`, name)
		return err
	})
}

// auditSystem records what the system did, never a key or a credential.
func (s *Service) auditSystem(ctx context.Context, action, name string, details map[string]any) {
	s.audit(ctx, action, name, details, false)
}

func (s *Service) audit(ctx context.Context, action, name string, details map[string]any, _ bool) {
	if s.deps.Audit == nil {
		return
	}
	e := audit.Event{Actor: audit.SystemActor("tls"), Action: action, TargetType: "tls_name", TargetID: name, Outcome: audit.Success, Details: details}
	if strings.HasSuffix(action, "_fail") {
		e.Outcome = audit.Failure
	}
	if err := s.deps.Audit.Record(ctx, e); err != nil {
		s.deps.Log.Error("tls: audit failed", "action", action, "error", err)
	}
}

func (s *Service) publish(ctx context.Context, e Event) {
	if s.deps.Alerts == nil {
		return
	}
	if e.Link == "" {
		e.Link = "/settings?tab=certificates"
	}
	if err := s.deps.Alerts.Publish(ctx, e); err != nil {
		s.deps.Log.Error("tls: publishing an alert failed", "key", e.Key, "error", err)
	}
}
