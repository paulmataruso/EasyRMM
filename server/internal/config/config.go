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
	// TLSInternal uses certificates from the server's own certificate
	// authority, for servers reached by IP address or without public DNS
	// (ADR-0016).
	TLSInternal TLSMode = "internal"
)

// Config is the complete server configuration.
type Config struct {
	PublicURL     *url.URL // https://rmm.example.com, or https://203.0.113.10
	MeshPublicURL *url.URL // https://mesh.rmm.example.com, or https://203.0.113.10:4443

	// IPAccess also serves the console and remote sessions on the server's
	// IP addresses, for when DNS is unavailable (ADR-0016).
	IPAccess bool
	// IPAddresses are the addresses IP access answers on. Load detects the
	// server's primary addresses when none are configured.
	IPAddresses []netip.Addr
	// IPMeshPort is the port remote sessions use on an IP address.
	IPMeshPort   int
	ipConfigured bool

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

	RequireMFA     bool
	SessionIdle    time.Duration
	SessionMaxAge  time.Duration
	AuditRetention time.Duration
	// JobRetention is how long finished jobs and their output are kept.
	JobRetention time.Duration
	// MetricsRetention is how long devices' metric samples are kept.
	MetricsRetention time.Duration
	// AlertRetention is how long resolved alerts are kept.
	AlertRetention   time.Duration
	PasswordResetTTL time.Duration
	LogLevel         string
	LogFormat        string // "json" or "text"
	ArgonMaxParallel int
	WebDir           string // optional override of the embedded UI
	// AgentDir holds the EasyRMM agent builds the server hands out.
	AgentDir          string
	SMTP              SMTPConfig
	Mesh              MeshConfig
	DevInsecureCookie bool // only for local development over plain HTTP
	// EasyPatch is an EasyPatch server co-hosted behind EasyRMM's edge
	// (ADR-0035); zero when there is none.
	EasyPatch EasyPatchHost
}

// EasyPatchHost is an EasyPatch running on this server behind EasyRMM's
// edge (ADR-0035). EasyRMM keeps ports 80 and 443; connections for
// EasyPatch's hostname pass through, still encrypted, to its own TLS
// listener on loopback, so EasyPatch keeps its certificates and headers.
type EasyPatchHost struct {
	// Hostname is EasyPatch's public name; "" when it is not co-hosted.
	Hostname string
	// TLSUpstream is EasyPatch's HTTPS listener (its Caddy), on loopback.
	TLSUpstream string
	// HTTPUpstream is its plain-HTTP listener, for its ACME HTTP-01
	// challenges; "" sends them nowhere (TLS-ALPN-01 still works).
	HTTPUpstream string
	// ProxyProtocol sends a PROXY protocol v2 header with each connection,
	// so EasyPatch sees the client's address instead of EasyRMM's.
	ProxyProtocol bool
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

// Load reads configuration from the process environment. With IP access on
// and no EASYRMM_IP_ADDRESSES, it uses the server's primary addresses.
func Load() (*Config, error) {
	c, err := LoadFrom(os.LookupEnv, os.ReadFile)
	if err != nil {
		return nil, err
	}
	c.DetectAddresses(PrimaryAddresses)
	return c, nil
}

// LoadFrom reads configuration through the given lookups.
func LoadFrom(getenv Getenv, readFile func(string) ([]byte, error)) (*Config, error) {
	l := &loader{getenv: getenv, readFile: readFile}
	c := &Config{
		ListenHTTPS:       l.str("EASYRMM_LISTEN_HTTPS", ":443"),
		ListenHTTP:        l.str("EASYRMM_LISTEN_HTTP", ":80"),
		ListenOffload:     l.str("EASYRMM_LISTEN_OFFLOAD", "127.0.0.1:18080"),
		ListenHealth:      l.str("EASYRMM_LISTEN_HEALTH", "127.0.0.1:18081"),
		CertFile:          l.str("EASYRMM_TLS_CERT_FILE", ""),
		KeyFile:           l.str("EASYRMM_TLS_KEY_FILE", ""),
		ACMEEmail:         l.str("EASYRMM_ACME_EMAIL", ""),
		ACMEDirectory:     l.orDefault("EASYRMM_ACME_DIRECTORY", "https://acme-v02.api.letsencrypt.org/directory"),
		DatabaseURL:       l.secret("EASYRMM_DATABASE_URL"),
		DataDir:           l.str("EASYRMM_DATA_DIR", "/var/lib/easyrmm"),
		RequireMFA:        l.boolean("EASYRMM_REQUIRE_MFA", true),
		SessionIdle:       l.duration("EASYRMM_SESSION_IDLE_TIMEOUT", 2*time.Hour),
		SessionMaxAge:     l.duration("EASYRMM_SESSION_MAX_AGE", 12*time.Hour),
		AuditRetention:    l.duration("EASYRMM_AUDIT_RETENTION", 365*24*time.Hour),
		JobRetention:      l.duration("EASYRMM_JOB_RETENTION", 90*24*time.Hour),
		MetricsRetention:  l.duration("EASYRMM_METRICS_RETENTION", 7*24*time.Hour),
		AlertRetention:    l.duration("EASYRMM_ALERT_RETENTION", 90*24*time.Hour),
		PasswordResetTTL:  l.duration("EASYRMM_PASSWORD_RESET_TTL", 30*time.Minute),
		LogLevel:          l.str("EASYRMM_LOG_LEVEL", "info"),
		LogFormat:         l.str("EASYRMM_LOG_FORMAT", "json"),
		ArgonMaxParallel:  l.integer("EASYRMM_ARGON2_MAX_PARALLEL", 4),
		WebDir:            l.str("EASYRMM_WEB_DIR", ""),
		AgentDir:          l.str("EASYRMM_AGENT_DIR", "/usr/share/easyrmm/agents"),
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
	// Checked before the conversion, so a value past 32 bits cannot wrap into the allowed range.
	if n := l.integer("EASYRMM_DATABASE_MAX_CONNS", 20); n >= 2 && n <= 500 {
		c.DatabaseMaxConns = int32(n)
	}

	c.PublicURL = l.httpsURL("EASYRMM_PUBLIC_URL", true)
	publicIP := c.PublicURL != nil && isIP(c.PublicURL.Hostname())
	// A server known by its IP address cannot get a certificate from ACME.
	defaultMode := TLSAcme
	if publicIP {
		defaultMode = TLSInternal
	}
	c.TLSMode = TLSMode(l.str("EASYRMM_TLS_MODE", ""))
	if c.TLSMode == "" {
		c.TLSMode = defaultMode
	}
	c.IPAccess = l.boolean("EASYRMM_IP_ACCESS", true)
	c.IPMeshPort = l.integer("EASYRMM_IP_MESH_PORT", 4443)
	for _, raw := range splitList(l.str("EASYRMM_IP_ADDRESSES", "")) {
		a, err := netip.ParseAddr(raw)
		if err != nil {
			l.errs = append(l.errs, fmt.Errorf("EASYRMM_IP_ADDRESSES: %q is not an IP address", raw))
			continue
		}
		c.IPAddresses = append(c.IPAddresses, a.Unmap())
		c.ipConfigured = true
	}
	meshDefault := ""
	if c.PublicURL != nil {
		if publicIP {
			// Same address, its own port: browsers keep the two apart as
			// different origins of the same site.
			meshDefault = "https://" + net.JoinHostPort(c.PublicURL.Hostname(), strconv.Itoa(c.IPMeshPort))
		} else {
			meshDefault = "https://mesh." + c.PublicURL.Host
		}
	}
	if raw := l.orDefault("EASYRMM_MESH_PUBLIC_URL", meshDefault); raw != "" {
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

	c.Mesh.CertURL = l.orDefault("EASYRMM_MESH_CERT_URL", defaultCertURL(c))
	c.EasyPatch = EasyPatchHost{
		Hostname:      strings.ToLower(strings.TrimSuffix(l.str("EASYRMM_EASYPATCH_HOSTNAME", ""), ".")),
		TLSUpstream:   l.orDefault("EASYRMM_EASYPATCH_TLS_UPSTREAM", "127.0.0.1:19443"),
		HTTPUpstream:  l.str("EASYRMM_EASYPATCH_HTTP_UPSTREAM", "127.0.0.1:19080"),
		ProxyProtocol: l.boolean("EASYRMM_EASYPATCH_PROXY_PROTOCOL", true),
	}
	if !c.EasyPatch.Enabled() {
		c.EasyPatch = EasyPatchHost{}
	}
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
	case TLSInternal:
		// Nothing to supply: the server creates its certificate authority.
	case TLSOffload:
		if len(c.TrustedProxies) == 0 {
			add("EASYRMM_TRUSTED_PROXIES is required when EASYRMM_TLS_MODE=offload (the address of your reverse proxy, e.g. 127.0.0.1/32)")
		}
		// Plain HTTP must never be reachable from the network.
		requireLoopback(add, "EASYRMM_LISTEN_OFFLOAD", c.ListenOffload)
	default:
		add("EASYRMM_TLS_MODE must be acme, manual, internal or offload, got %q", c.TLSMode)
	}
	if c.TLSMode == TLSAcme && c.PublicURL != nil && isIP(c.PublicURL.Hostname()) {
		add("EASYRMM_PUBLIC_URL is an IP address, which cannot get a certificate from ACME: use EASYRMM_TLS_MODE=internal (the default for IP addresses) or manual")
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
	if c.PublicURL != nil && c.MeshPublicURL != nil && Authority(c.PublicURL) == Authority(c.MeshPublicURL) {
		add("EASYRMM_MESH_PUBLIC_URL must differ from EASYRMM_PUBLIC_URL: use another hostname (mesh.rmm.example.com) or, on an IP address, another port (see ADR-0004 and ADR-0016)")
	}
	c.validateIPAccess(add)
	if c.SessionIdle < 5*time.Minute || c.SessionIdle > 24*time.Hour {
		add("EASYRMM_SESSION_IDLE_TIMEOUT must be between 5m and 24h")
	}
	if c.SessionMaxAge < c.SessionIdle || c.SessionMaxAge > 30*24*time.Hour {
		add("EASYRMM_SESSION_MAX_AGE must be at least the idle timeout and at most 720h")
	}
	if c.AuditRetention < 30*24*time.Hour {
		add("EASYRMM_AUDIT_RETENTION must be at least 720h (30 days)")
	}
	if c.JobRetention < 24*time.Hour {
		add("EASYRMM_JOB_RETENTION must be at least 24h")
	}
	if c.MetricsRetention < 24*time.Hour {
		add("EASYRMM_METRICS_RETENTION must be at least 24h")
	}
	if c.AlertRetention < 24*time.Hour {
		add("EASYRMM_ALERT_RETENTION must be at least 24h")
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
	c.validateEasyPatch(add)
}

// Enabled reports whether EasyPatch is co-hosted.
func (e EasyPatchHost) Enabled() bool { return e.Hostname != "" }

func (c *Config) validateEasyPatch(add func(string, ...any)) {
	e := c.EasyPatch
	if !e.Enabled() {
		return
	}
	if isIP(e.Hostname) || !validHostname(e.Hostname) {
		add("EASYRMM_EASYPATCH_HOSTNAME must be a DNS name such as patch.example.com, got %q", e.Hostname)
	}
	if c.TLSMode == TLSOffload {
		add("EASYRMM_EASYPATCH_HOSTNAME needs EasyRMM to own ports 80 and 443 (EASYRMM_TLS_MODE acme, manual or internal); with a reverse proxy in front, route EasyPatch's name in the proxy instead")
	}
	for _, o := range c.Origins() {
		if strings.EqualFold(e.Hostname, o.Console.Hostname()) || (o.Mesh != nil && strings.EqualFold(e.Hostname, o.Mesh.Hostname())) {
			add("EASYRMM_EASYPATCH_HOSTNAME must differ from EasyRMM's own names, got %q", e.Hostname)
			break
		}
	}
	// EasyPatch's ports are published on loopback only: anything else
	// would let the network reach it around the edge.
	upstream := func(key, addr string) {
		host, _, err := net.SplitHostPort(addr)
		if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
			add("%s must be a loopback address and port such as 127.0.0.1:19443, got %q", key, addr)
		}
	}
	upstream("EASYRMM_EASYPATCH_TLS_UPSTREAM", e.TLSUpstream)
	if e.HTTPUpstream != "" {
		upstream("EASYRMM_EASYPATCH_HTTP_UPSTREAM", e.HTTPUpstream)
	}
}

// validHostname accepts DNS names: dot-separated labels of letters, digits
// and hyphens, at least two labels.
func validHostname(h string) bool {
	if len(h) > 253 || !strings.Contains(h, ".") {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

// defaultCertURL is a local address of the listener that serves the
// MeshCentral origin: our own HTTPS listener (or the one for MeshCentral's
// port), or in offload mode the reverse proxy, assumed on 443.
func defaultCertURL(c *Config) string {
	host, port := "127.0.0.1", "443"
	if c.TLSMode != TLSOffload {
		if h, p, err := net.SplitHostPort(c.ListenHTTPS); err == nil {
			if p != "" {
				port = p
			}
			if ip := net.ParseIP(h); ip != nil && !ip.IsUnspecified() {
				host = h
			}
		}
		if c.PublicURL != nil && c.MeshPublicURL != nil && PortOf(c.MeshPublicURL) != PortOf(c.PublicURL) {
			port = PortOf(c.MeshPublicURL)
		}
	}
	return "https://" + net.JoinHostPort(host, port)
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

// orDefault reads KEY like str, but a blank value also means the default.
// Docker Compose sets every variable its file lists, as an empty string
// where .env leaves it blank, as .env.example does for these.
func (l *loader) orDefault(key, def string) string {
	if v := l.str(key, ""); v != "" {
		return v
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
