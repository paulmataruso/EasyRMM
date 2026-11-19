package config

import (
	"slices"
	"strings"
	"testing"
)

func TestAuthentik(t *testing.T) {
	secret := strings.Repeat("s", 48)
	load := func(overrides map[string]string) (*Config, error) {
		m := base()
		m["EASYRMM_AUTHENTIK_HOSTNAME"] = "Auth.Example.com."
		m["EASYRMM_AUTHENTIK_ADMIN_EMAIL"] = "Admin@Example.com"
		m["EASYRMM_AUTHENTIK_CLIENT_SECRET"] = secret
		for k, v := range overrides {
			m[k] = v
		}
		return LoadFrom(env(m), noFiles)
	}

	c, err := LoadFrom(env(base()), noFiles)
	if err != nil || c.Authentik.Enabled() || c.Authentik != (Authentik{}) || c.ExtraHostnames() != nil {
		t.Fatalf("none by default: %+v %v", c.Authentik, err)
	}
	// Without a name, the other settings are not read: an .env keeps its secret after Authentik is taken out.
	c, err = LoadFrom(env(map[string]string{
		"EASYRMM_PUBLIC_URL": "https://rmm.example.com", "EASYRMM_ACME_EMAIL": "ops@example.com",
		"EASYRMM_DATABASE_URL": "postgres://a@127.0.0.1/x", "EASYRMM_DATABASE_MIGRATION_URL": "postgres://o@127.0.0.1/x",
		"EASYRMM_SECRET_KEY": testKey, "EASYRMM_PATCHING_KEY": testKey, "EASYRMM_AUTHENTIK_CLIENT_SECRET": "short",
	}), noFiles)
	if err != nil || c.Authentik.Enabled() {
		t.Fatalf("a secret without a name: %+v %v", c.Authentik, err)
	}

	c, err = load(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := Authentik{Hostname: "auth.example.com", AdminEmail: "admin@example.com", ClientSecret: secret, Upstream: DefaultAuthentikUpstream}
	if c.Authentik != want {
		t.Fatalf("got %+v, want %+v", c.Authentik, want)
	}
	if got := c.Authentik.Issuer(); got != "https://auth.example.com/application/o/easyrmm/" {
		t.Errorf("issuer %s", got)
	}
	if got := c.Authentik.AdminDomain(); got != "example.com" {
		t.Errorf("admin domain %s", got)
	}
	if !slices.Equal(c.ExtraHostnames(), []string{"auth.example.com"}) {
		t.Errorf("the edge serves %v", c.ExtraHostnames())
	}
	// With an imported EasyPatch's names too.
	c, err = load(map[string]string{"EASYRMM_PATCHING": "bundled", "EASYRMM_PATCHING_KEY": testKey, "EASYRMM_PATCHING_AGENT_HOSTNAMES": "patch.example.com"})
	if err != nil || !slices.Equal(c.ExtraHostnames(), []string{"patch.example.com", "auth.example.com"}) {
		t.Fatalf("extra names %v, %v", c.ExtraHostnames(), err)
	}
	c, err = load(map[string]string{"EASYRMM_AUTHENTIK_UPSTREAM": "[::1]:28280"})
	if err != nil || c.Authentik.Upstream != "[::1]:28280" {
		t.Fatalf("upstream %q, %v", c.Authentik.Upstream, err)
	}

	for name, tc := range map[string]struct {
		env  map[string]string
		want string
	}{
		"offload":            {map[string]string{"EASYRMM_TLS_MODE": "offload", "EASYRMM_TRUSTED_PROXIES": "127.0.0.1"}, "EASYRMM_AUTHENTIK_HOSTNAME needs EasyRMM to own ports 80 and 443"},
		"no email":           {map[string]string{"EASYRMM_AUTHENTIK_ADMIN_EMAIL": ""}, "EASYRMM_AUTHENTIK_ADMIN_EMAIL must be the administrator's email address"},
		"no domain":          {map[string]string{"EASYRMM_AUTHENTIK_ADMIN_EMAIL": "admin@localhost"}, "EASYRMM_AUTHENTIK_ADMIN_EMAIL must be"},
		"two at signs":       {map[string]string{"EASYRMM_AUTHENTIK_ADMIN_EMAIL": "a@b@example.com"}, "EASYRMM_AUTHENTIK_ADMIN_EMAIL must be"},
		"a space":            {map[string]string{"EASYRMM_AUTHENTIK_ADMIN_EMAIL": "a b@example.com"}, "EASYRMM_AUTHENTIK_ADMIN_EMAIL must be"},
		"short secret":       {map[string]string{"EASYRMM_AUTHENTIK_CLIENT_SECRET": "short"}, "EASYRMM_AUTHENTIK_CLIENT_SECRET must be at least 32 characters"},
		"no secret":          {map[string]string{"EASYRMM_AUTHENTIK_CLIENT_SECRET": ""}, "EASYRMM_AUTHENTIK_CLIENT_SECRET must be"},
		"upstream elsewhere": {map[string]string{"EASYRMM_AUTHENTIK_UPSTREAM": "10.0.0.5:18280"}, "EASYRMM_AUTHENTIK_UPSTREAM must be a loopback address"},
		"upstream by name":   {map[string]string{"EASYRMM_AUTHENTIK_UPSTREAM": "localhost:18280"}, "EASYRMM_AUTHENTIK_UPSTREAM must be a loopback address"},
		"upstream no port":   {map[string]string{"EASYRMM_AUTHENTIK_UPSTREAM": "127.0.0.1"}, "EASYRMM_AUTHENTIK_UPSTREAM must be a loopback address"},
		"an IP address":      {map[string]string{"EASYRMM_AUTHENTIK_HOSTNAME": "192.0.2.4"}, "EASYRMM_AUTHENTIK_HOSTNAME must list DNS names"},
		"the console's":      {map[string]string{"EASYRMM_AUTHENTIK_HOSTNAME": "rmm.example.com"}, "EASYRMM_AUTHENTIK_HOSTNAME lists rmm.example.com, which EASYRMM_PUBLIC_URL already uses"},
		"remote access's":    {map[string]string{"EASYRMM_AUTHENTIK_HOSTNAME": "mesh.rmm.example.com"}, "which EASYRMM_MESH_PUBLIC_URL already uses"},
		"co-hosted EasyPatch's": {
			map[string]string{"EASYRMM_EASYPATCH_HOSTNAME": "auth.example.com"},
			"EASYRMM_AUTHENTIK_HOSTNAME lists auth.example.com, which EASYRMM_EASYPATCH_HOSTNAME already uses",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := load(tc.env)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want one containing %q", err, tc.want)
			}
		})
	}
}
