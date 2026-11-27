package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/pki"
	"github.com/paulmataruso/easyrmm/server/internal/tlscert"
	"github.com/paulmataruso/easyrmm/server/internal/tlsmove"
	"github.com/paulmataruso/easyrmm/server/internal/tlstrust"
	"github.com/paulmataruso/easyrmm/server/internal/updater"
)

// edge owns the public listeners: HTTPS on 443 (with certificates from
// ACME, files or the internal certificate authority), HTTPS on MeshCentral's
// own port when it has one (4443 for IP access), the optional HTTP listener
// on 80 (ACME challenges and redirects to HTTPS), or, in offload mode, plain
// HTTP on loopback behind a proxy. While the updater holds the server,
// every listener answers 503, except to ACME's challenges (ADR-0052).
type edge struct {
	cfg     *config.Config
	handler http.Handler
	hold    *updater.Hold
	log     *slog.Logger
	pki     *pki.Authority
	// tls obtains and renews the certificates of the DNS names in acme mode
	// (ADR-0055); nil in the other modes.
	tls *tlscert.Service
	// trust learns from it what each host is served with, for the agents
	// that verify it (ADR-0055, slice 5b1).
	trust *tlstrust.Service
	// moves routes each name to the source the console chose for it (5b2);
	// nil leaves every name to .env's mode.
	moves     *tlsmove.Service
	moveCerts *moveCerts
	servers   []*http.Server
}

// listen opens every listener the server serves on: the edge's and the
// health endpoint's. This package's tests replace it once, at start-up, to
// hand the server listeners they opened beforehand (listen_test.go).
var listen = func(ctx context.Context, addr string) (net.Listener, error) {
	return (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
}

// knownHost reports whether host (without port) is one we serve.
func knownHost(cfg *config.Config, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	for _, o := range cfg.Origins() {
		if strings.EqualFold(host, o.Console.Hostname()) || (o.Mesh != nil && strings.EqualFold(host, o.Mesh.Hostname())) {
			return true
		}
	}
	return slices.Contains(cfg.ExtraHostnames(), host)
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// redirectHandler sends plain-HTTP visitors to HTTPS, for our hostnames only
// (never an open redirect).
func redirectHandler(cfg *config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := hostOnly(r.Host)
		if !knownHost(cfg, host) {
			http.Error(w, "unknown host", http.StatusMisdirectedRequest)
			return
		}
		port := ""
		if _, p, err := net.SplitHostPort(cfg.ListenHTTPS); err == nil && p != "443" {
			port = p
		}
		target := "https://" + hostWithPort(strings.ToLower(strings.Trim(host, "[]")), port)
		target += r.URL.RequestURI()
		w.Header().Set("Connection", "close")
		http.Redirect(w, r, target, http.StatusPermanentRedirect) //nolint:gosec // host checked against our own hostnames above
	})
}

func (e *edge) newServer(addr string, h http.Handler, tlsCfg *tls.Config) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(quietTLSErrors{e.log.Handler()}, slog.LevelDebug),
	}
}

func baseTLS() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}
}

// run starts the listeners and blocks until ctx is canceled or a listener
// fails, then shuts every listener down gracefully.
func (e *edge) run(ctx context.Context) error {
	handler := e.hold.Handler(e.handler)
	redirect := e.hold.Handler(redirectHandler(e.cfg))
	var plain http.Handler // what the port-80 listener serves, if enabled
	var primary getCertificate
	var acmeALPN bool
	switch e.cfg.TLSMode {
	case config.TLSOffload:
		e.servers = append(e.servers, e.newServer(e.cfg.ListenOffload, handler, nil))
	case config.TLSAcme:
		if e.tls == nil {
			return errors.New("acme TLS mode without the certificate service")
		}
		primary, acmeALPN = e.tls.GetCertificate, true
		// HTTP-01 challenges, answered while held too: a certificate can
		// then be issued or renewed during a held start. Every certificate
		// comes from storage: nothing is ordered at a handshake.
		plain = e.tls.HTTPHandler(redirect)
		handler = e.tls.CheckHandler(handler)
	case config.TLSManual:
		r, err := newCertReloader(e.cfg.CertFile, e.cfg.KeyFile, e.log)
		if err != nil {
			return err
		}
		if err := covers(r.cert, e.cfg.ExtraHostnames()); err != nil {
			return err
		}
		primary = r.get
		plain = redirect
	case config.TLSInternal:
		if e.pki == nil {
			return errors.New("internal TLS mode without a certificate authority")
		}
		primary = e.pki.GetCertificate
		plain = redirect
	default:
		return fmt.Errorf("unsupported TLS mode %q", e.cfg.TLSMode)
	}
	if primary != nil && e.moves != nil && e.moveCerts != nil {
		primary = e.moveCerts.route(e.moves, primary)
	}
	if primary != nil {
		get := e.certificates(primary)
		if e.trust != nil {
			e.trust.SetSource(edgeSource{get: get})
		}
		for _, addr := range append([]string{e.cfg.ListenHTTPS}, e.cfg.MeshListeners()...) {
			t := baseTLS()
			t.GetCertificate = get
			if acmeALPN {
				t.NextProtos = append(t.NextProtos, acme.ALPNProto) // TLS-ALPN-01 challenges
			}
			e.servers = append(e.servers, e.newServer(addr, handler, t))
		}
	}
	if plain != nil && e.cfg.ListenHTTP != "" {
		e.servers = append(e.servers, e.newServer(e.cfg.ListenHTTP, plain, nil))
	}

	errc := make(chan error, len(e.servers)+1)
	if primary != nil && e.cfg.Mesh.Enabled && e.cfg.ListenMeshCert != "" {
		ln, err := listen(ctx, e.cfg.ListenMeshCert)
		if err != nil {
			return fmt.Errorf("listening on %s: %w", e.cfg.ListenMeshCert, err)
		}
		e.log.Info("listening", "addr", ln.Addr().String(), "tls", true, "for", "MeshCentral's reads of its certificate")
		var onRead func(time.Time)
		if e.tls != nil {
			onRead = e.tls.RecordMeshRead
		}
		go func() {
			if err := tlscert.ServeMesh(ctx, ln, e.meshCertificate(primary), onRead); err != nil {
				errc <- fmt.Errorf("server on %s: %w", e.cfg.ListenMeshCert, err)
			}
		}()
	}
	for _, s := range e.servers {
		ln, err := listen(ctx, s.Addr)
		if err != nil {
			e.shutdown()
			return fmt.Errorf("listening on %s: %w", s.Addr, err)
		}
		tlsOn := s.TLSConfig != nil
		e.log.Info("listening", "addr", ln.Addr().String(), "tls", tlsOn)
		go func() {
			var err error
			if tlsOn {
				err = s.ServeTLS(ln, "", "")
			} else {
				err = s.Serve(ln)
			}
			if !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("server on %s: %w", s.Addr, err)
			}
		}()
	}
	if e.tls != nil {
		e.tls.Serving() // challenges can be answered: orders may begin
	}
	select {
	case <-ctx.Done():
		e.shutdown()
		return nil
	case err := <-errc:
		e.shutdown()
		return err
	}
}

// acmeHosts are the names ACME may get certificates for: the DNS origins'
// and the names served besides them.
func acmeHosts(cfg *config.Config) []string {
	var hosts []string
	for _, o := range cfg.Origins() {
		if !o.Internal {
			hosts = append(hosts, o.Console.Hostname())
			if o.Mesh != nil {
				hosts = append(hosts, o.Mesh.Hostname())
			}
		}
	}
	return append(hosts, cfg.ExtraHostnames()...)
}

type getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)

// covers checks that the operator's certificate is valid for the names the
// edge serves besides its origins: they share it, as manual mode has one.
func covers(c *tls.Certificate, names []string) error {
	if len(names) == 0 {
		return nil
	}
	leaf := c.Leaf
	if leaf == nil {
		var err error
		if leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
			return fmt.Errorf("reading TLS certificate: %w", err)
		}
	}
	var missing []string
	for _, n := range names {
		if leaf.VerifyHostname(n) != nil {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("the certificate in EASYRMM_TLS_CERT_FILE is not valid for %s, which this server also answers: add them to the certificate, or use EASYRMM_TLS_MODE=acme",
			strings.Join(missing, ", "))
	}
	return nil
}

// certificates picks the certificate for a connection. A server name means
// a DNS origin: the configured source (ACME or files). Without one the
// client connected to an IP address (browsers send no server name for
// those): IP access is served by the internal certificate authority. When
// the operator's own certificate is for the IP address (manual mode), it
// serves every connection. MeshCentral's reads of the certificate its agents
// see have a listener of their own (meshCertificate), not a rule here.
func (e *edge) certificates(primary getCertificate) getCertificate {
	if e.cfg.TLSMode == config.TLSInternal {
		return primary
	}
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName != "" && net.ParseIP(hello.ServerName) == nil {
			return primary(hello)
		}
		if e.pki != nil {
			return e.pki.GetCertificate(hello)
		}
		return primary(hello)
	}
}

// meshCertificate is what MeshCentral's dedicated listener serves, whatever
// server name it is sent: exactly the certificate the edge serves MeshAgents
// for MeshCentral's name at that moment, from the same function.
func (e *edge) meshCertificate(primary getCertificate) getCertificate {
	get := e.certificates(primary)
	name := ""
	if e.cfg.MeshPublicURL != nil && net.ParseIP(e.cfg.MeshPublicURL.Hostname()) == nil {
		name = e.cfg.MeshPublicURL.Hostname()
	}
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		h := *hello
		h.ServerName, h.SupportedProtos = name, nil
		return get(&h)
	}
}

// hostWithPort joins a host (IPv6 addresses bracketed) and an optional port.
func hostWithPort(host, port string) string {
	if port != "" {
		return net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

func (e *edge) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, s := range e.servers {
		wg.Go(func() { _ = s.Shutdown(ctx) })
	}
	wg.Wait()
}

// certReloader serves a certificate from files and picks up renewals
// (for example by certbot) without a restart.
type certReloader struct {
	certFile, keyFile string
	log               *slog.Logger

	mu       sync.Mutex
	cert     *tls.Certificate
	modTime  time.Time
	checked  time.Time
	interval time.Duration
}

func newCertReloader(certFile, keyFile string, log *slog.Logger) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile, log: log, interval: 30 * time.Second}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) load() error {
	st, err := os.Stat(r.certFile)
	if err != nil {
		return fmt.Errorf("reading TLS certificate: %w", err)
	}
	c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("loading TLS certificate: %w", err)
	}
	r.cert, r.modTime = &c, st.ModTime()
	return nil
}

func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now := time.Now(); now.Sub(r.checked) >= r.interval {
		r.checked = now
		if st, err := os.Stat(r.certFile); err == nil && !st.ModTime().Equal(r.modTime) {
			if err := r.load(); err != nil {
				// Keep serving the previous certificate; a half-written
				// renewal will be retried at the next check.
				r.log.Error("reloading TLS certificate failed; still serving the previous one", "error", err)
			} else {
				r.log.Info("reloaded TLS certificate", "file", r.certFile)
			}
		}
	}
	return r.cert, nil
}

// quietTLSErrors demotes the noise every Internet-facing TLS server sees
// (scanners, aborted handshakes) to debug level.
type quietTLSErrors struct{ slog.Handler }

// Enabled accepts every record: the level is decided per message in Handle.
// (slog.NewLogLogger consults Enabled with its fixed level before Handle,
// so delegating here would drop server errors along with the noise.)
func (q quietTLSErrors) Enabled(context.Context, slog.Level) bool { return true }

func (q quietTLSErrors) Handle(ctx context.Context, rec slog.Record) error {
	if strings.Contains(rec.Message, "TLS handshake error") {
		rec.Level = slog.LevelDebug
	} else {
		rec.Level = slog.LevelWarn
	}
	if !q.Handler.Enabled(ctx, rec.Level) {
		return nil
	}
	return q.Handler.Handle(ctx, rec)
}
