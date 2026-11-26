// Package config loads and validates the server configuration from
// environment variables. Secrets may instead be supplied through files by
// appending _FILE to the variable name (Docker secrets convention).
package config

import (
	"encoding/base64"
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

	"github.com/google/uuid"
	"golang.org/x/net/publicsuffix"

	"github.com/paulmataruso/easyrmm/server/internal/m365"
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
	// JobRetention is how long finished jobs and their runs are kept.
	JobRetention time.Duration
	// JobOutputRetention is how long a run's output is kept after it
	// arrived (ADR-0063): DefaultJobOutputRetention, or JobRetention when
	// that is shorter.
	JobOutputRetention time.Duration
	// MetricsRetention is how long devices' metric samples are kept.
	MetricsRetention time.Duration
	// AlertRetention is how long resolved alerts are kept.
	AlertRetention time.Duration
	// HardwareRetention is how long one disk health sample per disk and day
	// is kept, once readings older than MetricsRetention are thinned
	// (ADR-0065).
	HardwareRetention time.Duration
	// AgentLogRetentionDays is how many days agents' log records are kept,
	// 1 to 90 (ADR-0069).
	AgentLogRetentionDays int
	PasswordResetTTL      time.Duration
	LogLevel              string
	LogFormat             string // "json" or "text"
	ArgonMaxParallel      int
	WebDir                string // optional override of the embedded UI
	// AgentDir holds the EasyRMM agent builds the server hands out.
	AgentDir string
	// DevScopeOrg limits test builds and automatic actions to one
	// organization (EASYRMM_DEV_SCOPE_ORG, a development-only control);
	// uuid.Nil when unset. Every other organization gets the builds in
	// AgentStableDir.
	DevScopeOrg uuid.UUID
	// AgentStableDir holds the stable agent builds, laid out like AgentDir
	// (EASYRMM_AGENT_STABLE_DIR). Only read while DevScopeOrg is set.
	AgentStableDir string
	// UpdaterStatusDir is the updater's status directory, mounted read-only
	// (ADR-0052): while its hold file exists the server answers its health
	// check and nothing else.
	UpdaterStatusDir  string
	SMTP              SMTPConfig
	Mesh              MeshConfig
	DevInsecureCookie bool // only for local development over plain HTTP
	// Patching is the patching engine in this deployment.
	Patching Patching
	// Authentik is the sign-in service in this deployment (ADR-0044); zero
	// when there is none.
	Authentik Authentik
}

// DefaultUpdaterStatusDir is where deploy/docker-compose.yml mounts the
// updater's status directory.
const DefaultUpdaterStatusDir = "/run/easyrmm-updater"

// DefaultJobOutputRetention is how long a run's output is kept by default
// (ADR-0063): 30 days, as ADR-0060 keeps collected logs.
const DefaultJobOutputRetention = 30 * 24 * time.Hour

// DefaultPatchingURL is where the patching engine listens
// (deploy/docker-compose.yml, easypatch-api).
const DefaultPatchingURL = "http://127.0.0.1:18180"

// Patching is the patching engine in this deployment: EasyPatch's server,
// called on loopback with statements signed by EASYRMM_PATCHING_KEY
// (ADR-0038).
type Patching struct {
	// URL is the engine's address: http, on loopback.
	URL string
	// Key signs EasyRMM's statements to the engine; at least 32 bytes.
	Key []byte
	// AgentHostnames are further names EasyPatch agents reach the engine
	// at: those of a standalone EasyPatch imported into this deployment,
	// whose agents keep the address they enrolled with (ADR-0045). EasyRMM's
	// edge serves the agents' paths there.
	AgentHostnames []string
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
	// Auth is how EasyRMM signs in (EASYRMM_SMTP_AUTH): "none", "password"
	// (the default with a user name) or "microsoft365", with an Entra
	// application (ADR-0053, slice 2).
	Auth string
	// The application's tenant (an ID or a domain name) and application
	// (client) ID, and its client secret, or certificate and private key
	// (PEM), each read from the file EASYRMM_SMTP_CLIENT_*_FILE names,
	// the only form they are taken in.
	TenantID     string
	ClientID     string
	ClientSecret string
	ClientCert   string
	ClientKey    string
	// The files they were read from, for messages.
	ClientSecretFile, ClientCertFile, ClientKeyFile string
	// unread is a file that could not be read, already an error.
	unread bool
}

// The ways EASYRMM_SMTP_AUTH signs in.
const (
	SMTPAuthNone         = "none"
	SMTPAuthPassword     = "password"
	SMTPAuthMicrosoft365 = "microsoft365"
)

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
		ListenHTTPS:           l.str("EASYRMM_LISTEN_HTTPS", ":443"),
		ListenHTTP:            l.str("EASYRMM_LISTEN_HTTP", ":80"),
		ListenOffload:         l.str("EASYRMM_LISTEN_OFFLOAD", "127.0.0.1:18080"),
		ListenHealth:          l.str("EASYRMM_LISTEN_HEALTH", "127.0.0.1:18081"),
		CertFile:              l.str("EASYRMM_TLS_CERT_FILE", ""),
		KeyFile:               l.str("EASYRMM_TLS_KEY_FILE", ""),
		ACMEEmail:             l.str("EASYRMM_ACME_EMAIL", ""),
		ACMEDirectory:         l.orDefault("EASYRMM_ACME_DIRECTORY", "https://acme-v02.api.letsencrypt.org/directory"),
		DatabaseURL:           l.secret("EASYRMM_DATABASE_URL"),
		DataDir:               l.str("EASYRMM_DATA_DIR", "/var/lib/easyrmm"),
		RequireMFA:            l.boolean("EASYRMM_REQUIRE_MFA", true),
		SessionIdle:           l.duration("EASYRMM_SESSION_IDLE_TIMEOUT", 2*time.Hour),
		SessionMaxAge:         l.duration("EASYRMM_SESSION_MAX_AGE", 12*time.Hour),
		AuditRetention:        l.duration("EASYRMM_AUDIT_RETENTION", 365*24*time.Hour),
		JobRetention:          l.duration("EASYRMM_JOB_RETENTION", 90*24*time.Hour),
		MetricsRetention:      l.duration("EASYRMM_METRICS_RETENTION", 7*24*time.Hour),
		AlertRetention:        l.duration("EASYRMM_ALERT_RETENTION", 90*24*time.Hour),
		HardwareRetention:     l.duration("EASYRMM_HARDWARE_RETENTION", 730*24*time.Hour),
		AgentLogRetentionDays: l.integer("EASYRMM_AGENT_LOG_RETENTION_DAYS", 14),
		PasswordResetTTL:      l.duration("EASYRMM_PASSWORD_RESET_TTL", 30*time.Minute),
		LogLevel:              l.str("EASYRMM_LOG_LEVEL", "info"),
		LogFormat:             l.str("EASYRMM_LOG_FORMAT", "json"),
		ArgonMaxParallel:      l.integer("EASYRMM_ARGON2_MAX_PARALLEL", 4),
		WebDir:                l.str("EASYRMM_WEB_DIR", ""),
		AgentDir:              l.str("EASYRMM_AGENT_DIR", "/usr/share/easyrmm/agents"),
		AgentStableDir:        l.orDefault("EASYRMM_AGENT_STABLE_DIR", "/usr/share/easyrmm/agents-stable"),
		UpdaterStatusDir:      l.orDefault("EASYRMM_UPDATER_STATUS_DIR", DefaultUpdaterStatusDir),
		DevInsecureCookie:     l.boolean("EASYRMM_DEV_INSECURE_COOKIES", false),
		SMTP: SMTPConfig{
			Host:     l.str("EASYRMM_SMTP_HOST", ""),
			Port:     l.integer("EASYRMM_SMTP_PORT", 587),
			Username: l.str("EASYRMM_SMTP_USERNAME", ""),
			Password: l.secret("EASYRMM_SMTP_PASSWORD"),
			From:     l.str("EASYRMM_SMTP_FROM", ""),
			TLS:      l.str("EASYRMM_SMTP_TLS", "starttls"),
			Auth:     l.str("EASYRMM_SMTP_AUTH", ""),
			TenantID: l.str("EASYRMM_SMTP_TENANT_ID", ""),
			ClientID: l.str("EASYRMM_SMTP_CLIENT_ID", ""),
		},
	}
	if raw := l.orDefault("EASYRMM_DEV_SCOPE_ORG", ""); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil || id == uuid.Nil {
			l.errs = append(l.errs, errors.New("EASYRMM_DEV_SCOPE_ORG must be an organization's UUID"))
		}
		c.DevScopeOrg = id
	}
	errs := len(l.errs)
	c.SMTP.ClientSecretFile, c.SMTP.ClientSecret = l.fileOnly("EASYRMM_SMTP_CLIENT_SECRET")
	c.SMTP.ClientCertFile, c.SMTP.ClientCert = l.fileOnly("EASYRMM_SMTP_CLIENT_CERT")
	c.SMTP.ClientKeyFile, c.SMTP.ClientKey = l.fileOnly("EASYRMM_SMTP_CLIENT_KEY")
	c.SMTP.unread = len(l.errs) > errs
	if c.SMTP.Auth == "" {
		// As before slice 2: a password when there is a user name.
		c.SMTP.Auth = SMTPAuthNone
		if c.SMTP.Username != "" {
			c.SMTP.Auth = SMTPAuthPassword
		}
	}
	c.DatabaseMigrationURL = l.secret("EASYRMM_DATABASE_MIGRATION_URL")
	c.JobOutputRetention = l.duration("EASYRMM_JOB_OUTPUT_RETENTION", min(DefaultJobOutputRetention, c.JobRetention))
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
	// EasyPatch on this server behind the edge (ADR-0035) was retired
	// (ADR-0046): an .env that still names it is refused, not ignored.
	if l.str("EASYRMM_EASYPATCH_HOSTNAME", "") != "" {
		l.errs = append(l.errs, errors.New("EASYRMM_EASYPATCH_HOSTNAME is no longer a setting: EasyPatch on this server is replaced by the patching engine in this deployment; remove it, then import that EasyPatch (deploy/scripts/import-easypatch.sh)"))
	}
	// Before the engine always ran here, EASYRMM_PATCHING chose between it
	// ("bundled", still harmless) and an EasyPatch server set up in Settings
	// (ADR-0046).
	if mode := l.str("EASYRMM_PATCHING", ""); mode != "" && !strings.EqualFold(mode, "bundled") {
		l.errs = append(l.errs, fmt.Errorf("EASYRMM_PATCHING is no longer a setting (patching always uses the engine in this deployment); remove it, got %q", mode))
	}
	c.Patching = Patching{URL: l.orDefault("EASYRMM_PATCHING_URL", DefaultPatchingURL)}
	for _, h := range splitList(l.str("EASYRMM_PATCHING_AGENT_HOSTNAMES", "")) {
		c.Patching.AgentHostnames = append(c.Patching.AgentHostnames, strings.ToLower(strings.TrimSuffix(h, ".")))
	}
	if raw := l.secret("EASYRMM_PATCHING_KEY"); raw != "" {
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			l.errs = append(l.errs, errors.New("EASYRMM_PATCHING_KEY must be base64 (setup.sh generates it)"))
		}
		c.Patching.Key = key
	}
	c.loadAuthentik(l)
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
	if !filepath.IsAbs(c.UpdaterStatusDir) {
		add("EASYRMM_UPDATER_STATUS_DIR must be an absolute path")
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
	if c.JobOutputRetention < 24*time.Hour || c.JobOutputRetention > c.JobRetention {
		add("EASYRMM_JOB_OUTPUT_RETENTION must be at least 24h and at most EASYRMM_JOB_RETENTION")
	}
	if c.MetricsRetention < 24*time.Hour {
		add("EASYRMM_METRICS_RETENTION must be at least 24h")
	}
	if c.AlertRetention < 24*time.Hour {
		add("EASYRMM_ALERT_RETENTION must be at least 24h")
	}
	if c.HardwareRetention < c.MetricsRetention {
		add("EASYRMM_HARDWARE_RETENTION must be at least EASYRMM_METRICS_RETENTION")
	}
	if c.AgentLogRetentionDays < 1 || c.AgentLogRetentionDays > 90 {
		add("EASYRMM_AGENT_LOG_RETENTION_DAYS must be between 1 and 90")
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
	c.validateSMTPAuth(add)
	if c.DevInsecureCookie && c.TLSMode != TLSOffload {
		add("EASYRMM_DEV_INSECURE_COOKIES is only allowed with EASYRMM_TLS_MODE=offload")
	}
	c.validateMesh(add)
	c.validatePatching(add)
	c.validateAuthentik(add)
	c.validateExtraHostnames(add)
}

func (c *Config) validatePatching(add func(string, ...any)) {
	p := c.Patching
	if len(p.Key) < 32 {
		add("EASYRMM_PATCHING_KEY must be at least 32 bytes, base64-encoded; run deploy/scripts/setup.sh to add it")
	}
	// The engine is reached on loopback only, without TLS: anything else
	// would send statements across the network in the clear.
	u, err := url.Parse(p.URL)
	host := ""
	if err == nil {
		host = u.Hostname()
	}
	if ip := net.ParseIP(host); err != nil || u.Scheme != "http" || ip == nil || !ip.IsLoopback() || u.Port() == "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil || u.Fragment != "" {
		add("EASYRMM_PATCHING_URL must be http:// on a loopback address and port, such as %s, got %q", DefaultPatchingURL, p.URL)
	}
}

// extraHost is a name the edge serves besides its origins, and the
// setting that names it.
type extraHost struct{ name, setting string }

func (c *Config) extraHosts() []extraHost {
	var out []extraHost
	for _, h := range c.Patching.AgentHostnames {
		out = append(out, extraHost{h, "EASYRMM_PATCHING_AGENT_HOSTNAMES"})
	}
	if c.Authentik.Enabled() {
		out = append(out, extraHost{c.Authentik.Hostname, "EASYRMM_AUTHENTIK_HOSTNAME"})
	}
	return out
}

// ExtraHostnames are the names the edge serves besides its origins, with
// TLS from the same source as theirs (ACME, the certificate file or the
// internal certificate authority): an imported EasyPatch's names, and
// Authentik's sign-in name.
func (c *Config) ExtraHostnames() []string {
	var out []string
	for _, h := range c.extraHosts() {
		out = append(out, h.name)
	}
	return out
}

// validateExtraHostnames checks that each further name is a DNS name that
// nothing else in the deployment already answers.
func (c *Config) validateExtraHostnames(add func(string, ...any)) {
	taken := map[string]string{}
	for _, o := range c.Origins() {
		taken[canonicalHost(o.Console.Hostname())] = "EASYRMM_PUBLIC_URL"
		if o.Mesh != nil {
			taken[canonicalHost(o.Mesh.Hostname())] = "EASYRMM_MESH_PUBLIC_URL"
		}
	}
	for _, h := range c.extraHosts() {
		if isIP(h.name) || !validHostname(h.name) {
			add("%s must list DNS names such as patch.example.com, got %q", h.setting, h.name)
			continue
		}
		if other, ok := taken[h.name]; ok {
			add("%s lists %s, which %s already uses", h.setting, h.name, other)
			continue
		}
		taken[h.name] = h.setting
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

// validateSMTPAuth checks how .env's mail server signs in: with
// EASYRMM_SMTP_AUTH=microsoft365, the tenant, the application and one
// credential, read from its files, and never the rest half set (ADR-0053,
// slice 2). The certificate's dates are not checked here: an expired one
// stops mail, not the server, and the server warns of it.
func (c *Config) validateSMTPAuth(add func(string, ...any)) {
	s := &c.SMTP
	app := s.TenantID != "" || s.ClientID != "" || s.ClientSecretFile != "" || s.ClientCertFile != "" || s.ClientKeyFile != ""
	switch s.Auth {
	case SMTPAuthNone:
		// A password alone was ignored before EASYRMM_SMTP_AUTH, and still is.
		if s.Username != "" {
			add("EASYRMM_SMTP_AUTH=none takes no EASYRMM_SMTP_USERNAME")
		}
	case SMTPAuthPassword:
		if s.Username == "" {
			add("EASYRMM_SMTP_AUTH=password needs EASYRMM_SMTP_USERNAME")
		}
	case SMTPAuthMicrosoft365:
		c.validateSMTPApplication(add)
		return
	default:
		add("EASYRMM_SMTP_AUTH must be none, password or microsoft365")
		return
	}
	if app {
		add("EASYRMM_SMTP_TENANT_ID, EASYRMM_SMTP_CLIENT_ID and EASYRMM_SMTP_CLIENT_*_FILE are read only with EASYRMM_SMTP_AUTH=microsoft365")
	}
}

// validateSMTPApplication checks EASYRMM_SMTP_AUTH=microsoft365.
func (c *Config) validateSMTPApplication(add func(string, ...any)) {
	s := &c.SMTP
	if s.Host == "" {
		add("EASYRMM_SMTP_AUTH=microsoft365 needs EASYRMM_SMTP_HOST (smtp.office365.com)")
	}
	switch {
	case s.TenantID == "":
		add("EASYRMM_SMTP_TENANT_ID is required with EASYRMM_SMTP_AUTH=microsoft365")
	case !m365.ValidTenant(s.TenantID):
		add("EASYRMM_SMTP_TENANT_ID must be the tenant's ID (a GUID) or one of its domain names")
	}
	switch {
	case s.ClientID == "":
		add("EASYRMM_SMTP_CLIENT_ID is required with EASYRMM_SMTP_AUTH=microsoft365")
	case !m365.ValidClientID(s.ClientID):
		add("EASYRMM_SMTP_CLIENT_ID must be the application (client) ID, a GUID")
	}
	if s.Username != "" || s.Password != "" {
		add("EASYRMM_SMTP_AUTH=microsoft365 signs in as EASYRMM_SMTP_FROM's mailbox: remove EASYRMM_SMTP_USERNAME and EASYRMM_SMTP_PASSWORD")
	}
	if s.TLS == "none" {
		add("EASYRMM_SMTP_AUTH=microsoft365 needs EASYRMM_SMTP_TLS=starttls or implicit: a token is sent only over TLS")
	}
	cert := s.ClientCertFile != "" || s.ClientKeyFile != ""
	switch {
	case s.ClientSecretFile != "" && cert:
		add("give EASYRMM_SMTP_CLIENT_SECRET_FILE, or EASYRMM_SMTP_CLIENT_CERT_FILE with EASYRMM_SMTP_CLIENT_KEY_FILE, not both")
	case s.unread:
		// A file that could not be read is already an error.
	case s.ClientSecretFile != "":
		if err := m365.CheckSecret(strings.TrimRight(s.ClientSecret, "\r\n")); err != nil {
			add("EASYRMM_SMTP_CLIENT_SECRET_FILE: %v", err)
		}
	case cert:
		if s.ClientCertFile == "" || s.ClientKeyFile == "" {
			add("EASYRMM_SMTP_CLIENT_CERT_FILE and EASYRMM_SMTP_CLIENT_KEY_FILE go together")
		} else {
			if _, err := m365.ParseCertificate(s.ClientCert, s.ClientKey); err != nil {
				add("EASYRMM_SMTP_CLIENT_CERT_FILE and EASYRMM_SMTP_CLIENT_KEY_FILE: %v", err)
			}
		}
	default:
		add("EASYRMM_SMTP_AUTH=microsoft365 needs EASYRMM_SMTP_CLIENT_SECRET_FILE, or EASYRMM_SMTP_CLIENT_CERT_FILE with EASYRMM_SMTP_CLIENT_KEY_FILE")
	}
}

// SMTPApplication is .env's Microsoft 365 application, nil without
// EASYRMM_SMTP_AUTH=microsoft365. Call it on a configuration Load passed.
func (s *SMTPConfig) SMTPApplication() (*m365.Credentials, error) {
	if s.Auth != SMTPAuthMicrosoft365 {
		return nil, nil
	}
	c := &m365.Credentials{TenantID: s.TenantID, ClientID: s.ClientID, Secret: strings.TrimRight(s.ClientSecret, "\r\n")}
	if s.ClientCertFile != "" {
		cert, err := m365.ParseCertificate(s.ClientCert, s.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("EASYRMM_SMTP_CLIENT_CERT_FILE: %w", err)
		}
		c.Secret, c.Certificate = "", cert
	}
	return c, c.Check()
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

// fileOnly reads the file named by KEY_FILE, a secret taken in no other
// form: KEY itself set is refused, so that the secret is never in .env or
// the process's environment. It returns the path and the contents.
func (l *loader) fileOnly(key string) (path, contents string) {
	if v, ok := l.getenv(key); ok && strings.TrimSpace(v) != "" {
		l.errs = append(l.errs, fmt.Errorf("%s is not read: put it in a file and name the file in %s_FILE", key, key))
	}
	path = l.str(key+"_FILE", "")
	if path == "" {
		return "", ""
	}
	b, err := l.readFile(path)
	if err != nil {
		l.errs = append(l.errs, fmt.Errorf("%s_FILE: %w", key, err))
		return path, ""
	}
	return path, string(b)
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
