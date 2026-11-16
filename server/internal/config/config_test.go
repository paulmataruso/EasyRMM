package config

import (
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

var testKey = base64.StdEncoding.EncodeToString(make([]byte, 32))

func env(m map[string]string) Getenv {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func base() map[string]string {
	return map[string]string{
		"EASYRMM_PUBLIC_URL":             "https://rmm.example.com",
		"EASYRMM_ACME_EMAIL":             "ops@example.com",
		"EASYRMM_DATABASE_URL":           "postgres://easyrmm_app:x@127.0.0.1:15432/easyrmm",
		"EASYRMM_DATABASE_MIGRATION_URL": "postgres://easyrmm_owner:y@127.0.0.1:15432/easyrmm",
		"EASYRMM_SECRET_KEY":             testKey,
	}
}

func noFiles(string) ([]byte, error) { return nil, os.ErrNotExist }

func TestDefaults(t *testing.T) {
	c, err := LoadFrom(env(base()), noFiles)
	if err != nil {
		t.Fatal(err)
	}
	if c.TLSMode != TLSAcme || c.ListenHTTPS != ":443" || c.ListenHTTP != ":80" {
		t.Errorf("listener defaults: %+v", c)
	}
	if c.MeshPublicURL.String() != "https://mesh.rmm.example.com" {
		t.Errorf("mesh url default: %s", c.MeshPublicURL)
	}
	if !c.RequireMFA || c.SessionIdle != 2*time.Hour || c.SessionMaxAge != 12*time.Hour {
		t.Errorf("security defaults weakened: %+v", c)
	}
	if len(c.SecretKeys) != 1 || c.SecretKeys[0].ID != "k1" {
		t.Errorf("secret keys: %+v", c.SecretKeys)
	}
}

func TestMissingRequiredValuesAreAllReported(t *testing.T) {
	_, err := LoadFrom(env(map[string]string{}), noFiles)
	if err == nil {
		t.Fatal("empty environment accepted")
	}
	for _, want := range []string{"EASYRMM_PUBLIC_URL", "EASYRMM_SECRET_KEY", "EASYRMM_DATABASE_URL", "EASYRMM_DATABASE_MIGRATION_URL", "EASYRMM_ACME_EMAIL"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s: %v", want, err)
		}
	}
}

func TestRejectsUnsafeOrInvalidValues(t *testing.T) {
	cases := map[string]map[string]string{
		"http public url":          {"EASYRMM_PUBLIC_URL": "http://rmm.example.com"},
		"public url with path":     {"EASYRMM_PUBLIC_URL": "https://example.com/rmm"},
		"same mesh host":           {"EASYRMM_MESH_PUBLIC_URL": "https://rmm.example.com"},
		"short key":                {"EASYRMM_SECRET_KEY": base64.StdEncoding.EncodeToString([]byte("short"))},
		"unknown tls mode":         {"EASYRMM_TLS_MODE": "plaintext"},
		"manual without files":     {"EASYRMM_TLS_MODE": "manual"},
		"offload without proxies":  {"EASYRMM_TLS_MODE": "offload"},
		"offload on public ip":     {"EASYRMM_TLS_MODE": "offload", "EASYRMM_TRUSTED_PROXIES": "127.0.0.1", "EASYRMM_LISTEN_OFFLOAD": "0.0.0.0:18080"},
		"bad proxy":                {"EASYRMM_TLS_MODE": "offload", "EASYRMM_TRUSTED_PROXIES": "not-an-ip"},
		"idle too short":           {"EASYRMM_SESSION_IDLE_TIMEOUT": "1m"},
		"max age below idle":       {"EASYRMM_SESSION_IDLE_TIMEOUT": "3h", "EASYRMM_SESSION_MAX_AGE": "2h"},
		"short audit retention":    {"EASYRMM_AUDIT_RETENTION": "24h"},
		"short job retention":      {"EASYRMM_JOB_RETENTION": "1h"},
		"bad bool":                 {"EASYRMM_REQUIRE_MFA": "maybe"},
		"bad duration":             {"EASYRMM_SESSION_MAX_AGE": "forever"},
		"bad int":                  {"EASYRMM_DATABASE_MAX_CONNS": "lots"},
		"too many conns":           {"EASYRMM_DATABASE_MAX_CONNS": "5000"},
		"smtp without from":        {"EASYRMM_SMTP_HOST": "smtp.example.com"},
		"smtp bad tls":             {"EASYRMM_SMTP_HOST": "smtp.example.com", "EASYRMM_SMTP_FROM": "rmm@example.com", "EASYRMM_SMTP_TLS": "ssl3"},
		"insecure cookies in prod": {"EASYRMM_DEV_INSECURE_COOKIES": "true"},
		"bad log format":           {"EASYRMM_LOG_FORMAT": "xml"},
		"bad previous key":         {"EASYRMM_SECRET_KEYS_PREVIOUS": "nocolon"},
	}
	for name, overrides := range cases {
		t.Run(name, func(t *testing.T) {
			m := base()
			for k, v := range overrides {
				m[k] = v
			}
			if _, err := LoadFrom(env(m), noFiles); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestOffloadMode(t *testing.T) {
	m := base()
	delete(m, "EASYRMM_ACME_EMAIL")
	m["EASYRMM_TLS_MODE"] = "offload"
	m["EASYRMM_TRUSTED_PROXIES"] = "127.0.0.1, 10.0.0.0/8 ,::1"
	c, err := LoadFrom(env(m), noFiles)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.TrustedProxies) != 3 || c.TrustedProxies[0].String() != "127.0.0.1/32" || c.TrustedProxies[2].String() != "::1/128" {
		t.Fatalf("trusted proxies: %v", c.TrustedProxies)
	}
}

func TestSecretFilesAndKeyRotation(t *testing.T) {
	m := base()
	delete(m, "EASYRMM_SECRET_KEY")
	delete(m, "EASYRMM_DATABASE_URL")
	m["EASYRMM_SECRET_KEY_FILE"] = "/run/secrets/key"
	m["EASYRMM_SECRET_KEY_ID"] = "k2"
	m["EASYRMM_DATABASE_URL_FILE"] = "/run/secrets/db"
	m["EASYRMM_SECRET_KEYS_PREVIOUS"] = "k1:" + testKey
	files := map[string]string{"/run/secrets/key": testKey + "\n", "/run/secrets/db": "postgres://from-file\n"}
	read := func(p string) ([]byte, error) {
		if v, ok := files[p]; ok {
			return []byte(v), nil
		}
		return nil, os.ErrNotExist
	}
	c, err := LoadFrom(env(m), read)
	if err != nil {
		t.Fatal(err)
	}
	if c.DatabaseURL != "postgres://from-file" {
		t.Errorf("database url from file: %q", c.DatabaseURL)
	}
	if len(c.SecretKeys) != 2 || c.SecretKeys[0].ID != "k2" || c.SecretKeys[1].ID != "k1" {
		t.Errorf("key ring: %+v", c.SecretKeys)
	}

	m["EASYRMM_SECRET_KEY"] = testKey // both direct and _FILE
	if _, err := LoadFrom(env(m), read); err == nil {
		t.Error("ambiguous secret accepted")
	}
	delete(m, "EASYRMM_SECRET_KEY")
	m["EASYRMM_SECRET_KEY_FILE"] = "/missing"
	if _, err := LoadFrom(env(m), read); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing secret file: %v", err)
	}
}

func TestRemoteAccessSettings(t *testing.T) {
	c, err := LoadFrom(env(base()), noFiles)
	if err != nil {
		t.Fatal(err)
	}
	m := c.Mesh
	if !m.Enabled || m.InternalURL.String() != "http://127.0.0.1:14430" || m.ConfigDir != "/var/lib/easyrmm-meshcentral" || m.CertURL != "https://127.0.0.1:443" {
		t.Errorf("remote access defaults: %+v", m)
	}

	// The certificate is read from our own HTTPS listener...
	e := base()
	e["EASYRMM_LISTEN_HTTPS"] = ":8443"
	if c, err := LoadFrom(env(e), noFiles); err != nil || c.Mesh.CertURL != "https://127.0.0.1:8443" {
		t.Errorf("cert URL with a custom HTTPS port: %v %v", c, err)
	}
	// ...or, behind a proxy, from the proxy.
	e = base()
	e["EASYRMM_TLS_MODE"] = "offload"
	e["EASYRMM_TRUSTED_PROXIES"] = "127.0.0.1/32"
	e["EASYRMM_LISTEN_HTTPS"] = ":8443"
	if c, err := LoadFrom(env(e), noFiles); err != nil || c.Mesh.CertURL != "https://127.0.0.1:443" {
		t.Errorf("cert URL in offload mode: %v %v", c, err)
	}

	e = base()
	e["EASYRMM_MESH_ENABLED"] = "false"
	e["EASYRMM_MESH_INTERNAL_URL"] = "not a url at all ::"
	if c, err := LoadFrom(env(e), noFiles); err != nil || c.Mesh.Enabled {
		t.Errorf("disabled remote access still validated: %v", err)
	}

	for _, c := range []struct {
		key, value, want string
	}{
		{"EASYRMM_MESH_INTERNAL_URL", "http://10.0.0.5:14430", "loopback"},
		{"EASYRMM_MESH_INTERNAL_URL", "https://127.0.0.1:14430", "EASYRMM_MESH_INTERNAL_URL"},
		{"EASYRMM_MESH_INTERNAL_URL", "http://127.0.0.1", "EASYRMM_MESH_INTERNAL_URL"},
		{"EASYRMM_MESH_INTERNAL_URL", "http://127.0.0.1:14430/mesh", "EASYRMM_MESH_INTERNAL_URL"},
		{"EASYRMM_MESH_INTERNAL_URL", "http://%zz", "EASYRMM_MESH_INTERNAL_URL"},
		{"EASYRMM_MESH_CONFIG_DIR", "relative/dir", "EASYRMM_MESH_CONFIG_DIR"},
		{"EASYRMM_MESH_CERT_URL", "http://127.0.0.1:80", "EASYRMM_MESH_CERT_URL"},
		{"EASYRMM_MESH_PUBLIC_URL", "https://mesh.example.com/sub", "without a path"},
		{"EASYRMM_MESH_PUBLIC_URL", "", "EASYRMM_MESH_PUBLIC_URL is required"},
		{"EASYRMM_MESH_PUBLIC_URL", "https://remote.example.net", "must share a parent domain"},
	} {
		e := base()
		e[c.key] = c.value
		_, err := LoadFrom(env(e), noFiles)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s=%q: %v, want an error mentioning %q", c.key, c.value, err, c.want)
		}
	}
	e = base()
	e["EASYRMM_MESH_CERT_URL"] = "file:///etc/easyrmm/proxy.pem"
	if _, err := LoadFrom(env(e), noFiles); err != nil {
		t.Errorf("file certificate URL rejected: %v", err)
	}
}

func TestSameSite(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"rmm.example.com", "mesh.rmm.example.com", true},
		{"rmm.example.com", "remote.example.com", true},
		{"RMM.Example.com.", "mesh.example.COM", true},
		{"rmm.example.co.uk", "mesh.example.co.uk", true},
		{"rmm.example.com", "mesh.example.net", false},
		// A public suffix is not a shared parent domain.
		{"acme.co.uk", "globex.co.uk", false},
		{"a.github.io", "b.github.io", false},
		{"rmm.localhost", "mesh.rmm.localhost", true},
		{"192.0.2.10", "192.0.2.10", true},
		{"192.0.2.10", "192.0.2.11", false},
		{"192.0.2.10", "mesh.example.com", false},
		{"com", "com", false},
	} {
		if got := SameSite(c.a, c.b); got != c.want {
			t.Errorf("SameSite(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
