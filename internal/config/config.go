package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Server       ServerConfig
	Database     DatabaseConfig
	Auth         AuthConfig
	MeshCentral  MeshCentralConfig
	EasyPatch    EasyPatchConfig
}

type ServerConfig struct {
	Host            string
	Port            int
	PublicURL       string
	TLSCert         string
	TLSKey          string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
}

type DatabaseConfig struct {
	Host     string
	Port     int
	Name     string
	User     string
	Password string
	SSLMode  string
	MaxConns int
}

type AuthConfig struct {
	SessionDuration   time.Duration
	BCryptCost        int
	MaxFailedLogins   int
	LockoutDurations  []time.Duration
	RateLimitPerMin   int
	CSRFSecret        string
	CookieDomain      string
	CookieSecure      bool
}

type MeshCentralConfig struct {
	URL           string
	InternalURL   string
	AdminUser     string
	AdminPassword string
	LoginTokenKey string
	TokenLifetime time.Duration
}

type EasyPatchConfig struct {
	Enabled     bool
	URL         string
	APIKey      string
}

func (d DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		d.User, d.Password, d.Host, d.Port, d.Name, d.SSLMode,
	)
}

func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Host:            envStr("EASYRM_HOST", "0.0.0.0"),
			Port:            envInt("EASYRM_PORT", 8443),
			PublicURL:        envStr("EASYRM_PUBLIC_URL", "https://localhost"),
			TLSCert:         envStr("EASYRM_TLS_CERT", ""),
			TLSKey:          envStr("EASYRM_TLS_KEY", ""),
			ReadTimeout:     30 * time.Second,
			WriteTimeout:    60 * time.Second,
			ShutdownTimeout: 15 * time.Second,
		},
		Database: DatabaseConfig{
			Host:     envStr("EASYRM_DB_HOST", "localhost"),
			Port:     envInt("EASYRM_DB_PORT", 5432),
			Name:     envStr("EASYRM_DB_NAME", "easyrm"),
			User:     envStr("EASYRM_DB_USER", "easyrm"),
			Password: envStr("EASYRM_DB_PASSWORD", ""),
			SSLMode:  envStr("EASYRM_DB_SSLMODE", "disable"),
			MaxConns: envInt("EASYRM_DB_MAX_CONNS", 25),
		},
		Auth: AuthConfig{
			SessionDuration:  24 * time.Hour,
			BCryptCost:       12,
			MaxFailedLogins:  5,
			LockoutDurations: []time.Duration{5 * time.Minute, 15 * time.Minute, time.Hour, 24 * time.Hour},
			RateLimitPerMin:  20,
			CSRFSecret:       envStr("EASYRM_CSRF_SECRET", ""),
			CookieDomain:     envStr("EASYRM_COOKIE_DOMAIN", ""),
			CookieSecure:     envBool("EASYRM_COOKIE_SECURE", true),
		},
		MeshCentral: MeshCentralConfig{
			URL:           envStr("EASYRM_MESH_URL", "https://localhost/mesh"),
			InternalURL:   envStr("EASYRM_MESH_INTERNAL_URL", "https://localhost:4430"),
			AdminUser:     envStr("EASYRM_MESH_ADMIN_USER", "easyrmadmin"),
			AdminPassword: envStr("EASYRM_MESH_ADMIN_PASSWORD", ""),
			LoginTokenKey: envStr("EASYRM_MESH_LOGIN_TOKEN_KEY", ""),
			TokenLifetime: 5 * time.Minute,
		},
		EasyPatch: EasyPatchConfig{
			Enabled: envBool("EASYRM_EASYPATCH_ENABLED", false),
			URL:     envStr("EASYRM_EASYPATCH_URL", ""),
			APIKey:  envStr("EASYRM_EASYPATCH_API_KEY", ""),
		},
	}

	if cfg.Database.Password == "" {
		if pwFile := envStr("EASYRM_DB_PASSWORD_FILE", ""); pwFile != "" {
			pw, err := os.ReadFile(pwFile)
			if err != nil {
				return nil, fmt.Errorf("reading db password file: %w", err)
			}
			cfg.Database.Password = string(pw)
		}
	}

	return cfg, nil
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}
