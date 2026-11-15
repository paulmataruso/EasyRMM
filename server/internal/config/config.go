// Package config loads and validates the server configuration from
// environment variables. Secrets may instead be supplied through files by
// appending _FILE to the variable name (Docker secrets convention).
package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/paulmataruso/easyrmm/server/internal/secrets"
)

// TLSMode selects how HTTPS is provided.
type TLSMode string

const (
	// TLSAcme obtains certificates from an ACME CA (Let's Encrypt by default).
	TLSAcme TLSMode = "acme"
	// TLSManual uses certificate and key files supplied by the operator.
	TLSManual TLSMode = "manual"
	// TLSOffload serves plain HTTP on loopback behind an upstream proxy that
	// terminates TLS.
	TLSOffload TLSMode = "offload"
)

// Config is the complete server configuration.
type Config struct {
	PublicURL     *url.URL // https://rmm.example.com
	MeshPublicURL *url.URL // https://mesh.rmm.example.com

	TLSMode       TLSMode
	ListenHTTPS   string // ":443"
	ListenHTTP    string // ":80", or "" to disable
	ListenOffload string // "127.0.0.1:18080"
	// ListenHealth serves liveness and readiness probes on loopback.
	ListenHealth  string // "127.0.0.1:18081"
	CertFile      string
	KeyFile       string
	ACMEEmail     string
	ACMEDirectory string
	// TrustedProxies are the addresses whose X-Forwarded-For header is
	// believed. Only meaningful in offload mode.
	TrustedProxies []netip.Prefix

	DatabaseURL          string
	DatabaseMigrationURL string
	DatabaseMaxConns     int32

	SecretKeys []secrets.Key // first is primary
	DataDir    string

	RequireMFA        bool
	SessionIdle       time.Duration
	SessionMaxAge     time.Duration
	AuditRetention    time.Duration
	PasswordResetTTL  time.Duration
	LogLevel          string
	LogFormat         string // "json" or "text"
	ArgonMaxParallel  int
	WebDir            string // optional override of the embedded UI
	SMTP              SMTPConfig
	Mesh              MeshConfig
	DevInsecureCookie bool // only for local development over plain HTTP
}

// MeshConfig configures the MeshCentral remote-access integration.
type MeshConfig struct {
	// Enabled turns remote access on. MeshCentral must then run alongside
	// the server (the meshcentral service in the Compose file).
	Enabled bool
	// InternalURL is MeshCentral's plain-HTTP loopback listener.
	InternalURL *url.URL
	// ConfigDir is where the server writes MeshCentral's config.json; the
	// MeshCentral container mounts it read-only.
	ConfigDir string
	// CertURL is where MeshCentral reads the certificate agents pin: the TLS
	// listener serving the MeshCentral hostname, reached over loopback.
	CertURL string
}

// SMTPConfig configures outbound e-mail. Empty Host disables e-mail.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	// TLS: "starttls" (default), "implicit" or "none" (loopback relays only).
	TLS string
}

// Getenv abstracts environment lookup for tests.
type Getenv func(string) (string, bool)

// Load reads configuration from the process environment.
func Load() (*Config, error) { return LoadFrom(os.LookupEnv, os.ReadFile) }

// LoadFrom reads configuration through the given lookups.
func LoadFrom(getenv Getenv, readFile func(string) ([]byte, error)) (*Config, error) {
	l := &loader{getenv: getenv, readFile: readFile}
	c := &Config{
		TLSMode:           TLSMode(l.str("EASYRMM_TLS_MODE", string(TLSAcme))),
		ListenHTTPS:       l.str("EASYRMM_LISTEN_HTTPS", ":443"),
		ListenHTTP:        l.str("EASYRMM_LISTEN_HTTP", ":80"),
		ListenOffload:     l.str("EASYRMM_LISTEN_OFFLOAD", "127.0.0.1:18080"),
		ListenHealth:      l.str("EASYRMM_LISTEN_HEALTH", "127.0.0.1:18081"),
		CertFile:          l.str("EASYRMM_TLS_CERT_FILE", ""),
		KeyFile:           l.str("EASYRMM_TLS_KEY_FILE", ""),
		ACMEEmail:         l.str("EASYRMM_ACME_EMAIL", ""),
		ACMEDirectory:     l.str("EASYRMM_ACME_DIRECTORY", "https://acme-v02.api.letsencrypt.org/directory"),
		DatabaseURL:       l.secret("EASYRMM_DATABASE_URL"),
		DataDir:           l.str("EASYRMM_DATA_DIR", "/var/lib/easyrmm"),
		RequireMFA:        l.boolean("EASYRMM_REQUIRE_MFA", true),
		SessionIdle:       l.duration("EASYRMM_SESSION_IDLE_TIMEOUT", 2*time.Hour),
		SessionMaxAge:     l.duration("EASYRMM_SESSION_MAX_AGE", 12*time.Hour),
		AuditRetention:    l.duration("EASYRMM_AUDIT_RETENTION", 365*24*time.Hour),
		PasswordResetTTL:  l.duration("EASYRMM_PASSWORD_RESET_TTL", 30*time.Minute),
		LogLevel:          l.str("EASYRMM_LOG_LEVEL", "info"),
		LogFormat:         l.str("EASYRMM_LOG_FORMAT", "json"),
		ArgonMaxParallel:  l.integer("EASYRMM_ARGON2_MAX_PARALLEL", 4),
		WebDir:            l.str("EASYRMM_WEB_DIR", ""),
		DevInsecureCookie: l.boolean("EASYRMM_DEV_INSECURE_COOKIES", false),
		SMTP: SMTPConfig{
			Host:     l.str("EASYRMM_SMTP_HOST", ""),
			Port:     l.integer("EASYRMM_SMTP_PORT", 587),
			Username: l.str("EASYRMM_SMTP_USERNAME", ""),
			Password: l.secret("EASYRMM_SMTP_PASSWORD"),
			From:     l.str("EASYRMM_SMTP_FROM", ""),
			TLS:      l.str("EASYRMM_SMTP_TLS", "starttls"),
		},
	}
	c.DatabaseMigrationURL = l.secret("EASYRMM_DATABASE_MIGRATION_URL")
	c.Mesh = MeshConfig{
		Enabled:   l.boolean("EASYRMM_MESH_ENABLED", true),
		ConfigDir: l.str("EASYRMM_MESH_CONFIG_DIR", "/var/lib/easyrmm-meshcentral"),
	}
	if raw := l.str("EASYRMM_MESH_INTERNAL_URL", "http://127.0.0.1:14430"); raw != "" && c.Mesh.Enabled {
		u, err := url.Parse(raw)
		if err != nil {
			l.errs = append(l.errs, fmt.Errorf("EASYRMM_MESH_INTERNAL_URL: %w", err))
		} else {
			c.Mesh.InternalURL = u
		}
	}
	c.DatabaseMaxConns = int32(l.integer("EASYRMM_DATABASE_MAX_CONNS", 20)) //nolint:gosec // validated below

	c.PublicURL = l.httpsURL("EASYRMM_PUBLIC_URL", true)
	meshDefault := ""
	if c.PublicURL != nil {
		meshDefault = "https://mesh." + c.PublicURL.Host
	}
	if raw := l.str("EASYRMM_MESH_PUBLIC_URL", meshDefault); raw != "" {
		c.MeshPublicURL = l.parseHTTPS("EASYRMM_MESH_PUBLIC_URL", raw)
	}

	for _, p := range splitList(l.str("EASYRMM_TRUSTED_PROXIES", "")) {
		prefix, err := parsePrefix(p)
		if err != nil {
			l.errs = append(l.errs, fmt.Errorf("EASYRMM_TRUSTED_PROXIES: %w", err))
			continue
		}
		c.TrustedProxies = append(c.TrustedProxies, prefix)
	}

	if raw := l.secret("EASYRMM_SECRET_KEY"); raw != "" {
		k, err := secrets.ParseKey(l.str("EASYRMM_SECRET_KEY_ID", "k1"), raw)
		if err != nil {
			l.errs = append(l.errs, fmt.Errorf("EASYRMM_SECRET_KEY: %w", err))
		} else {
			c.SecretKeys = append(c.SecretKeys, k)
		}
	} else {
		l.errs = append(l.errs, errors.New("EASYRMM_SECRET_KEY is required (32 random bytes, base64; generate with `openssl rand -base64 32`)"))
	}
	// Previous keys, still accepted for decryption: "id:base64,id:base64".
	for _, entry := range splitList(l.secret("EASYRMM_SECRET_KEYS_PREVIOUS")) {
		id, raw, ok := strings.Cut(entry, ":")
		if !ok {
			l.errs = append(l.errs, errors.New("EASYRMM_SECRET_KEYS_PREVIOUS entries must be id:base64"))
			continue
		}
		k, err := secrets.ParseKey(id, raw)
		if err != nil {
			l.errs = append(l.errs, fmt.Errorf("EASYRMM_SECRET_KEYS_PREVIOUS: %w", err))
			continue
		}
		c.SecretKeys = append(c.SecretKeys, k)
	}

	c.Mesh.CertURL = l.str("EASYRMM_MESH_CERT_URL", defaultCertURL(c))
	c.validate(l)
	if len(l.errs) > 0 {
		return nil, errors.Join(l.errs...)
	}
	return c, nil
}

func (c *Config) validate(l *loader) {
	add := func(format string, args ...any) { l.errs = append(l.errs, fmt.Errorf(format, args...)) }
	switch c.TLSMode {
	case TLSAcme:
		if c.ACMEEmail == "" {
			add("EASYRMM_ACME_EMAIL is required when EASYRMM_TLS_MODE=acme")
		}
	case TLSManual:
		if c.CertFile == "" || c.KeyFile == "" {
			add("EASYRMM_TLS_CERT_FILE and EASYRMM_TLS_KEY_FILE are required when EASYRMM_TLS_MODE=manual")
		}
	case TLSOffload:
		if len(c.TrustedProxies) == 0 {
			add("EASYRMM_TRUSTED_PROXIES is required when EASYRMM_TLS_MODE=offload (the address of your reverse proxy, e.g. 127.0.0.1/32)")
		}
		// Plain HTTP must never be reachable from the network.
		requireLoopback(add, "EASYRMM_LISTEN_OFFLOAD", c.ListenOffload)
	default:
		add("EASYRMM_TLS_MODE must be acme, manual or offload, got %q", c.TLSMode)
	}
	if c.ListenHealth != "" {
		requireLoopback(add, "EASYRMM_LISTEN_HEALTH", c.ListenHealth)
	}
	if c.DatabaseURL == "" {
		add("EASYRMM_DATABASE_URL is required")
	}
	if c.DatabaseMigrationURL == "" {
		add("EASYRMM_DATABASE_MIGRATION_URL is required (connection string for the easyrmm_owner role)")
	}
	if c.DatabaseMaxConns < 2 || c.DatabaseMaxConns > 500 {
		add("EASYRMM_DATABASE_MAX_CONNS must be between 2 and 500")
	}
	if c.PublicURL != nil && c.MeshPublicURL != nil && strings.EqualFold(c.PublicURL.Hostname(), c.MeshPublicURL.Hostname()) {
		add("EASYRMM_MESH_PUBLIC_URL must use a different hostname from EASYRMM_PUBLIC_URL (see ADR-0004)")
	}
	if c.SessionIdle < 5*time.Minute || c.SessionIdle > 24*time.Hour {
		add("EASYRMM_SESSION_IDLE_TIMEOUT must be between 5m and 24h")
	}
	if c.SessionMaxAge < c.SessionIdle || c.SessionMaxAge > 30*24*time.Hour {
		add("EASYRMM_SESSION_MAX_AGE must be at least the idle timeout and at most 720h")
	}
	if c.AuditRetention < 30*24*time.Hour {
		add("EASYRMM_AUDIT_RETENTION must be at least 720h (30 days)")
	}
	if c.PasswordResetTTL < 5*time.Minute || c.PasswordResetTTL > 24*time.Hour {
		add("EASYRMM_PASSWORD_RESET_TTL must be between 5m and 24h")
	}
	if c.ArgonMaxParallel < 1 || c.ArgonMaxParallel > 64 {
		add("EASYRMM_ARGON2_MAX_PARALLEL must be between 1 and 64")
	}
	switch c.LogFormat {
	case "json", "text":
	default:
		add("EASYRMM_LOG_FORMAT must be json or text")
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		add("EASYRMM_LOG_LEVEL must be debug, info, warn or error")
	}
	if c.SMTP.Host != "" {
		if c.SMTP.From == "" {
			add("EASYRMM_SMTP_FROM is required when EASYRMM_SMTP_HOST is set")
		}
		switch c.SMTP.TLS {
		case "starttls", "implicit", "none":
		default:
			add("EASYRMM_SMTP_TLS must be starttls, implicit or none")
		}
		if c.SMTP.Port < 1 || c.SMTP.Port > 65535 {
			add("EASYRMM_SMTP_PORT is out of range")
		}
	}
	if c.DevInsecureCookie && c.TLSMode != TLSOffload {
		add("EASYRMM_DEV_INSECURE_COOKIES is only allowed with EASYRMM_TLS_MODE=offload")
	}
	c.validateMesh(add)
}

// defaultCertURL is the loopback address of the listener that serves the
// MeshCentral hostname: our own HTTPS listener, or in offload mode the
// reverse proxy, assumed on 443.
func defaultCertURL(c *Config) string {
	port := "443"
	if c.TLSMode != TLSOffload {
		if _, p, err := net.SplitHostPort(c.ListenHTTPS); err == nil && p != "" {
			port = p
		}
	}
	return "https://127.0.0.1:" + port
}

func (c *Config) validateMesh(add func(string, ...any)) {
	if !c.Mesh.Enabled {
		return
	}
	if c.MeshPublicURL == nil {
		add("EASYRMM_MESH_PUBLIC_URL is required when remote access is enabled (set EASYRMM_MESH_ENABLED=false to run without it)")
	} else if c.PublicURL != nil && !SameSite(c.PublicURL.Hostname(), c.MeshPublicURL.Hostname()) {
		add("EASYRMM_MESH_PUBLIC_URL (%s) must share a parent domain with EASYRMM_PUBLIC_URL (%s), for example rmm.example.com and mesh.rmm.example.com: browsers admit embedded remote sessions only from the same site",
			c.MeshPublicURL.Hostname(), c.PublicURL.Hostname())
	}
	if u := c.Mesh.InternalURL; u == nil || u.Scheme != "http" || u.Port() == "" || (u.Path != "" && u.Path != "/") {
		add("EASYRMM_MESH_INTERNAL_URL must be http://<loopback address>:<port>")
	} else if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
		add("EASYRMM_MESH_INTERNAL_URL must use a loopback address, got %q", u.Hostname())
	}
	if !filepath.IsAbs(c.Mesh.ConfigDir) {
		add("EASYRMM_MESH_CONFIG_DIR must be an absolute path")
	}
	if !strings.HasPrefix(c.Mesh.CertURL, "https://") && !strings.HasPrefix(c.Mesh.CertURL, "file:///") {
		add("EASYRMM_MESH_CERT_URL must be an https:// or file:/// URL")
	}
}

func requireLoopback(add func(string, ...any), key, addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		add("%s: %v", key, err)
		return
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		add("%s must bind a loopback address, got %q", key, host)
	}
}

type loader struct {
	getenv   Getenv
	readFile func(string) ([]byte, error)
	errs     []error
}

func (l *loader) str(key, def string) string {
	if v, ok := l.getenv(key); ok {
		return strings.TrimSpace(v)
	}
	return def
}

// secret reads KEY, or the contents of the file named by KEY_FILE.
func (l *loader) secret(key string) string {
	if path, ok := l.getenv(key + "_FILE"); ok && strings.TrimSpace(path) != "" {
		if _, direct := l.getenv(key); direct {
			l.errs = append(l.errs, fmt.Errorf("set either %s or %s_FILE, not both", key, key))
			return ""
		}
		b, err := l.readFile(strings.TrimSpace(path))
		if err != nil {
			l.errs = append(l.errs, fmt.Errorf("%s_FILE: %w", key, err))
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	return l.str(key, "")
}

func (l *loader) boolean(key string, def bool) bool {
	v, ok := l.getenv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		l.errs = append(l.errs, fmt.Errorf("%s must be true or false", key))
		return def
	}
	return b
}

func (l *loader) integer(key string, def int) int {
	v, ok := l.getenv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		l.errs = append(l.errs, fmt.Errorf("%s must be an integer", key))
		return def
	}
	return n
}

func (l *loader) duration(key string, def time.Duration) time.Duration {
	v, ok := l.getenv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil {
		l.errs = append(l.errs, fmt.Errorf("%s must be a duration such as 30m or 12h", key))
		return def
	}
	return d
}

func (l *loader) httpsURL(key string, required bool) *url.URL {
	raw := l.str(key, "")
	if raw == "" {
		if required {
			l.errs = append(l.errs, fmt.Errorf("%s is required (for example https://rmm.example.com)", key))
		}
		return nil
	}
	return l.parseHTTPS(key, raw)
}

func (l *loader) parseHTTPS(key, raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		l.errs = append(l.errs, fmt.Errorf("%s must be an https:// origin without a path, got %q", key, raw))
		return nil
	}
	u.Path = ""
	return u
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// SameSite reports whether browsers treat two host names as the same site:
// the same registrable domain under the Public Suffix List, or the same IP
// address.
func SameSite(a, b string) bool {
	a, b = strings.ToLower(strings.TrimSuffix(a, ".")), strings.ToLower(strings.TrimSuffix(b, "."))
	ipA, ipB := net.ParseIP(a), net.ParseIP(b)
	if ipA != nil || ipB != nil {
		return ipA != nil && ipB != nil && ipA.Equal(ipB)
	}
	da, errA := publicsuffix.EffectiveTLDPlusOne(a)
	db, errB := publicsuffix.EffectiveTLDPlusOne(b)
	return errA == nil && errB == nil && da == db
}
