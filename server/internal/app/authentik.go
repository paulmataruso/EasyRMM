package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/pki"
	"github.com/paulmataruso/easyrmm/server/internal/sso"
	"github.com/paulmataruso/easyrmm/server/internal/users"
)

// Authentik in the deployment (one-product plan, phase A; ADR-0044): the
// first super administrator, the provider EasyRMM signs in through, and
// Authentik's own name on EasyRMM's edge.

// firstAdministrator creates the first super administrator from the
// administrator's email setup.sh asked for, without a password, before the
// first-run page could offer itself. Their first sign-in through Authentik
// links them by that address (ADR-0034).
func firstAdministrator(ctx context.Context, cfg *config.Config, u *users.Service, log *slog.Logger) error {
	if !cfg.Authentik.Enabled() {
		return nil
	}
	created, err := u.BootstrapDeployment(ctx, cfg.Authentik.AdminEmail)
	if err != nil {
		return fmt.Errorf("first administrator: %w", err)
	}
	if created {
		log.Info("created the first super administrator; they sign in through Authentik", "email", cfg.Authentik.AdminEmail)
	}
	return nil
}

// useAuthentik sets up, or releases, the provider the deployment manages.
func useAuthentik(ctx context.Context, cfg *config.Config, s *sso.Service, ca *pki.Authority) error {
	a := cfg.Authentik
	if !a.Enabled() {
		return s.UseDeployment(ctx, nil)
	}
	client, err := authentikClient(cfg, ca)
	if err != nil {
		return err
	}
	return s.UseDeployment(ctx, &sso.Deployment{
		Name: "Authentik", Issuer: a.Issuer(), ClientID: config.AuthentikClientID, ClientSecret: a.ClientSecret,
		Domains: []string{a.AdminDomain()}, Client: client,
	})
}

// edgeAddress is where this server's own HTTPS listener is reached from the
// host: its address, or loopback when it listens on every address.
func edgeAddress(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		port = "443"
	}
	if ip := net.ParseIP(host); ip == nil || ip.IsUnspecified() {
		if ip != nil && ip.To4() == nil {
			host = "::1"
		} else {
			host = "127.0.0.1"
		}
	}
	return net.JoinHostPort(host, port)
}

// authentikClient reaches Authentik's sign-in name for discovery, keys and
// tokens over loopback, through this server's own edge, still verifying
// TLS for that name: many routers do not loop a server's own public address
// back to it (hairpin NAT). With EasyRMM's own certificate authority, that
// authority is trusted too. It dials nothing else, and follows no
// redirects, which could carry the client secret of a token request away.
func authentikClient(cfg *config.Config, ca *pki.Authority) (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if cfg.TLSMode == config.TLSInternal && ca != nil && !roots.AppendCertsFromPEM(ca.CAPEM()) {
		return nil, fmt.Errorf("authentik: the internal certificate authority's certificate does not parse")
	}
	name, edge := cfg.Authentik.Hostname, edgeAddress(cfg.ListenHTTPS)
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(addr)
				if err != nil || !strings.EqualFold(strings.TrimSuffix(host, "."), name) {
					return nil, fmt.Errorf("authentik: %s is not %s", addr, name)
				}
				return dialer.DialContext(ctx, network, edge)
			},
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			MaxIdleConnsPerHost:   2,
			IdleConnTimeout:       90 * time.Second,
			ForceAttemptHTTP2:     true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// authentikProxy serves Authentik's sign-in name: every path, websockets
// included, to Authentik's listener on loopback, with the name kept and the
// client's address and HTTPS in forwarded headers, which Authentik trusts
// from loopback only.
func authentikProxy(upstream string, secure bool, log *slog.Logger) http.Handler {
	target := &url.URL{Scheme: "http", Host: upstream}
	return &httputil.ReverseProxy{
		// Rewrite starts from a request without X-Forwarded-* headers and
		// without hop-by-hop ones (an Upgrade is kept for websockets).
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			pr.Out.Header.Del("Forwarded")
			pr.Out.Header.Set("X-Forwarded-For", httpapi.ClientIP(pr.In).String())
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
		},
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns:          64,
			MaxIdleConnsPerHost:   32,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 2 * time.Minute,
		},
		ModifyResponse: func(resp *http.Response) error {
			if secure && resp.Header.Get("Strict-Transport-Security") == "" {
				resp.Header.Set("Strict-Transport-Security", "max-age=63072000")
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			httpapi.LoggerFrom(r.Context()).Warn("authentik unreachable", "error", err, "path", httpapi.LogSafe(r.URL.Path))
			w.Header().Set("Retry-After", "30")
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "Sign-in is not answering. Try again in a minute.", http.StatusBadGateway)
		},
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}
