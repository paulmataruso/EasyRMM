package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/paulmataruso/easyrmm/server/internal/config"
)

// edge owns the public listeners: HTTPS on 443 (with certificates from ACME
// or files), the optional HTTP listener on 80 (ACME challenges and redirects
// to HTTPS), or, in offload mode, plain HTTP on loopback behind a proxy.
type edge struct {
	cfg     *config.Config
	handler http.Handler
	log     *slog.Logger
	servers []*http.Server
}

// knownHost reports whether host (without port) is one we serve.
func knownHost(cfg *config.Config, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if cfg.PublicURL != nil && host == strings.ToLower(cfg.PublicURL.Hostname()) {
		return true
	}
	return cfg.MeshPublicURL != nil && host == strings.ToLower(cfg.MeshPublicURL.Hostname())
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
		target := "https://" + strings.ToLower(host)
		if _, port, err := net.SplitHostPort(cfg.ListenHTTPS); err == nil && port != "443" && port != "" {
			target += ":" + port
		}
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
	var plain http.Handler // what the port-80 listener serves, if enabled
	switch e.cfg.TLSMode {
	case config.TLSOffload:
		e.servers = append(e.servers, e.newServer(e.cfg.ListenOffload, e.handler, nil))
	case config.TLSAcme:
		hosts := []string{e.cfg.PublicURL.Hostname()}
		if e.cfg.MeshPublicURL != nil {
			hosts = append(hosts, e.cfg.MeshPublicURL.Hostname())
		}
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(filepath.Join(e.cfg.DataDir, "acme")),
			HostPolicy: autocert.HostWhitelist(hosts...),
			Email:      e.cfg.ACMEEmail,
			Client:     &acme.Client{DirectoryURL: e.cfg.ACMEDirectory},
		}
		t := baseTLS()
		t.GetCertificate = m.GetCertificate
		t.NextProtos = append(t.NextProtos, acme.ALPNProto) // TLS-ALPN-01 challenges
		e.servers = append(e.servers, e.newServer(e.cfg.ListenHTTPS, e.handler, t))
		plain = m.HTTPHandler(redirectHandler(e.cfg)) // HTTP-01 challenges
	case config.TLSManual:
		r, err := newCertReloader(e.cfg.CertFile, e.cfg.KeyFile, e.log)
		if err != nil {
			return err
		}
		t := baseTLS()
		t.GetCertificate = r.get
		e.servers = append(e.servers, e.newServer(e.cfg.ListenHTTPS, e.handler, t))
		plain = redirectHandler(e.cfg)
	default:
		return fmt.Errorf("unsupported TLS mode %q", e.cfg.TLSMode)
	}
	if plain != nil && e.cfg.ListenHTTP != "" {
		e.servers = append(e.servers, e.newServer(e.cfg.ListenHTTP, plain, nil))
	}

	errc := make(chan error, len(e.servers))
	for _, s := range e.servers {
		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.Addr)
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
	select {
	case <-ctx.Done():
		e.shutdown()
		return nil
	case err := <-errc:
		e.shutdown()
		return err
	}
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

func (q quietTLSErrors) Handle(ctx context.Context, rec slog.Record) error {
	if strings.Contains(rec.Message, "TLS handshake error") {
		rec.Level = slog.LevelDebug
	} else {
		rec.Level = slog.LevelWarn
	}
	if !q.Enabled(ctx, rec.Level) {
		return nil
	}
	return q.Handler.Handle(ctx, rec)
}
