package config

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The deployment's files, from this package's directory.
const (
	composeFile = "../../../deploy/docker-compose.yml"
	envExample  = "../../../deploy/.env.example"
)

// TestComposeEnvironment loads the configuration Docker Compose hands the
// server: the server's environment in deploy/docker-compose.yml, interpolated
// from deploy/.env.example as deploy/scripts/setup.sh fills it in. Compose
// sets every variable the file lists, as an empty string where .env leaves
// it blank, so a blank value must mean the default wherever .env.example
// leaves one blank.
func TestComposeEnvironment(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup map[string]string // what setup.sh writes for this host
		mesh  string
		cert  string
		extra []string
		ak    Authentik
	}{
		{
			name: "DNS name",
			setup: map[string]string{
				"EASYRMM_PUBLIC_URL": "https://rmm.example.com", "EASYRMM_TLS_MODE": "acme",
				"EASYRMM_ACME_EMAIL": "ops@example.com",
			},
			mesh: "https://mesh.rmm.example.com",
			cert: "https://127.0.0.1:443",
		},
		{
			name: "IP address",
			setup: map[string]string{
				"EASYRMM_PUBLIC_URL": "https://192.0.2.10", "EASYRMM_TLS_MODE": "internal",
				"EASYRMM_ACME_EMAIL": "",
			},
			mesh: "https://192.0.2.10:4443",
			cert: "https://127.0.0.1:4443",
		},
		{
			name: "an imported EasyPatch's name",
			setup: map[string]string{
				"EASYRMM_PUBLIC_URL": "https://rmm.example.com", "EASYRMM_TLS_MODE": "acme",
				"EASYRMM_ACME_EMAIL": "ops@example.com", "EASYRMM_PATCHING_AGENT_HOSTNAMES": "patch.example.com",
			},
			mesh:  "https://mesh.rmm.example.com",
			cert:  "https://127.0.0.1:443",
			extra: []string{"patch.example.com"},
		},
		{
			name: "Authentik",
			setup: map[string]string{
				"EASYRMM_PUBLIC_URL": "https://rmm.example.com", "EASYRMM_TLS_MODE": "acme",
				"EASYRMM_ACME_EMAIL": "ops@example.com", "EASYRMM_AUTHENTIK_HOSTNAME": "auth.example.com",
				"EASYRMM_AUTHENTIK_ADMIN_EMAIL": "admin@example.com", "EASYRMM_AUTHENTIK_CLIENT_SECRET": strings.Repeat("c", 64),
			},
			mesh:  "https://mesh.rmm.example.com",
			cert:  "https://127.0.0.1:443",
			extra: []string{"auth.example.com"},
			ak: Authentik{Hostname: "auth.example.com", AdminEmail: "admin@example.com", ClientSecret: strings.Repeat("c", 64),
				Upstream: DefaultAuthentikUpstream},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			dotenv := readDotenv(t, envExample)
			for k, v := range map[string]string{
				"EASYRMM_MESH_PUBLIC_URL": "", "POSTGRES_PASSWORD": "p", "EASYRMM_DB_OWNER_PASSWORD": "o",
				"EASYRMM_DB_APP_PASSWORD": "a", "EASYRMM_SECRET_KEY": testKey, "EASYRMM_PATCHING_KEY": testKey,
			} {
				dotenv[k] = v
			}
			for k, v := range c.setup {
				dotenv[k] = v
			}
			got := map[string]string{}
			for k, raw := range composeEnvironment(t, "server") {
				v, err := interpolate(raw, dotenv)
				if err != nil {
					t.Fatalf("%s: %v", k, err)
				}
				got[k] = v
			}
			read := map[string]bool{}
			lookup := func(k string) (string, bool) {
				read[k] = true
				v, ok := got[k]
				return v, ok
			}
			cfg, err := LoadFrom(lookup, noFiles)
			if err != nil {
				t.Fatalf("the server refuses the environment Compose gives it:\n%v", err)
			}
			// A setting the server reads but Compose does not pass cannot be
			// changed from .env: it must be one fixed on purpose.
			for k := range read {
				if _, passed := got[k]; !passed && fixedInCompose[k] == "" && !strings.HasSuffix(k, "_FILE") {
					t.Errorf("the server reads %s, which deploy/docker-compose.yml does not pass: add it there, or to fixedInCompose with the reason", k)
				}
			}
			if cfg.MeshPublicURL == nil || cfg.MeshPublicURL.String() != c.mesh {
				t.Errorf("remote-access URL %v, want %s", cfg.MeshPublicURL, c.mesh)
			}
			if cfg.Mesh.CertURL != c.cert {
				t.Errorf("certificate URL %q, want %s", cfg.Mesh.CertURL, c.cert)
			}
			if cfg.Patching.URL != DefaultPatchingURL || len(cfg.Patching.Key) != 32 {
				t.Errorf("patching %+v: want the engine in this deployment", cfg.Patching)
			}
			if !slices.Equal(cfg.ExtraHostnames(), c.extra) {
				t.Errorf("further names %v, want %v", cfg.ExtraHostnames(), c.extra)
			}
			if cfg.Authentik != c.ak {
				t.Errorf("Authentik %+v, want %+v", cfg.Authentik, c.ak)
			}
		})
	}
}

// fixedInCompose are the settings the Compose deployment does not let .env
// change, and why. Settings read from files (KEY_FILE) are left out too:
// Compose passes the values themselves.
var fixedInCompose = map[string]string{
	"EASYRMM_DATA_DIR":             "the image's data directory, mounted from the data root",
	"EASYRMM_MESH_CONFIG_DIR":      "the directory the meshcentral service mounts",
	"EASYRMM_MESH_INTERNAL_URL":    "the port the meshcentral service's configuration names",
	"EASYRMM_LISTEN_HEALTH":        "the port the image's health check reads",
	"EASYRMM_LISTEN_OFFLOAD":       "a loopback port, used only behind a reverse proxy on the host",
	"EASYRMM_AGENT_DIR":            "the agent builds inside the image",
	"EASYRMM_AGENT_STABLE_DIR":     "the stable agent builds inside the image (development only, with EASYRMM_DEV_SCOPE_ORG)",
	"EASYRMM_DEV_SCOPE_ORG":        "development only: set by the local deploy, never in .env",
	"EASYRMM_WEB_DIR":              "the console is built into the binary",
	"EASYRMM_DATABASE_MAX_CONNS":   "sized to the postgres service's max_connections",
	"EASYRMM_LOG_FORMAT":           "JSON for docker logs",
	"EASYRMM_DEV_INSECURE_COOKIES": "development only",
	"EASYRMM_ARGON2_MAX_PARALLEL":  "bounds the memory password hashing takes; four suits the deployment",
	"EASYRMM_PATCHING_URL":         "where the easypatch-api service listens (TestComposeListeners checks they agree)",
	"EASYRMM_PATCHING":             "not a setting: the engine in this deployment always runs",
	"EASYRMM_AUTHENTIK_UPSTREAM":   "where the authentik-server service listens (TestComposeListeners checks they agree)",
	"EASYRMM_UPDATER_STATUS_DIR":   "where the server service mounts the updater's status directory (TestComposeUpdaterStatus checks they agree)",
	// Read only to be refused: these are taken from their files alone.
	"EASYRMM_SMTP_CLIENT_SECRET": "refused: the secret is read only from EASYRMM_SMTP_CLIENT_SECRET_FILE",
	"EASYRMM_SMTP_CLIENT_CERT":   "refused: the certificate is read only from EASYRMM_SMTP_CLIENT_CERT_FILE",
	"EASYRMM_SMTP_CLIENT_KEY":    "refused: the key is read only from EASYRMM_SMTP_CLIENT_KEY_FILE",
}

func TestInterpolate(t *testing.T) {
	vars := map[string]string{"SET": "v", "EMPTY": ""}
	for raw, want := range map[string]string{
		"${SET}": "v", "${UNSET}": "", "a${SET}b": "avb",
		"${EMPTY:-d}": "d", "${UNSET:-d}": "d", "${SET:-d}": "v",
		"${EMPTY-d}": "", "${UNSET-d}": "d", "${SET:?missing}": "v",
	} {
		if got, err := interpolate(raw, vars); err != nil || got != want {
			t.Errorf("%s: %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"${EMPTY:?missing}", "${UNSET:?missing}", "${UNSET?missing}"} {
		if _, err := interpolate(raw, vars); err == nil {
			t.Errorf("%s: no error", raw)
		}
	}
}

// readDotenv reads KEY=VALUE lines, as Compose reads an .env file without
// quotes or comments after values.
func readDotenv(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("%s: %q is not KEY=VALUE", path, line)
		}
		out[k] = v
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// composeEnvironment returns a service's environment mapping from the
// Compose file. It reads the file's layout (two spaces per level) rather
// than all of YAML.
func composeEnvironment(t *testing.T, service string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(composeFile)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	inService, inEnv := false, false
	for _, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		switch {
		case indent == 2:
			inService, inEnv = trimmed == service+":", false
		case inService && indent == 4:
			inEnv = trimmed == "environment:"
		case inEnv && indent == 6:
			k, v, ok := strings.Cut(trimmed, ": ")
			if !ok {
				t.Fatalf("%s: %q is not KEY: VALUE", composeFile, trimmed)
			}
			out[k] = strings.Trim(v, `"`)
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s: no environment for %s", composeFile, service)
	}
	return out
}

// composeVolumes returns a service's volumes from the Compose file, read
// as composeEnvironment reads its environment.
func composeVolumes(t *testing.T, service string) []string {
	t.Helper()
	b, err := os.ReadFile(composeFile)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	inService, inVolumes := false, false
	for _, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		switch {
		case indent == 2:
			inService, inVolumes = trimmed == service+":", false
		case inService && indent == 4:
			inVolumes = trimmed == "volumes:"
		case inVolumes && indent == 6 && strings.HasPrefix(trimmed, "- "):
			out = append(out, strings.TrimPrefix(trimmed, "- "))
		}
	}
	return out
}

// TestComposeUpdaterStatus mounts the updater's status directory read-only
// where the server looks for it, into the server and the engine's worker
// only (ADR-0052).
func TestComposeUpdaterStatus(t *testing.T) {
	c, err := LoadFrom(env(map[string]string{
		"EASYRMM_PUBLIC_URL": "https://rmm.example.com", "EASYRMM_ACME_EMAIL": "ops@example.com",
		"EASYRMM_DATABASE_URL": "postgres://a@127.0.0.1/x", "EASYRMM_DATABASE_MIGRATION_URL": "postgres://o@127.0.0.1/x",
		"EASYRMM_SECRET_KEY": testKey, "EASYRMM_PATCHING_KEY": testKey,
	}), noFiles)
	if err != nil {
		t.Fatal(err)
	}
	want := "${EASYRMM_DATA_ROOT:-/srv/easyrmm}/updater/status:" + c.UpdaterStatusDir + ":ro"
	b, err := os.ReadFile(composeFile)
	if err != nil {
		t.Fatal(err)
	}
	services := regexp.MustCompile(`(?m)^  ([a-z][a-z0-9-]*):$`).FindAllStringSubmatch(string(b), -1)
	var mounted []string
	for _, s := range services {
		for _, v := range composeVolumes(t, s[1]) {
			if strings.Contains(v, "/updater") {
				if v != want {
					t.Errorf("%s mounts %q, want %q", s[1], v, want)
				}
				mounted = append(mounted, s[1])
			}
		}
	}
	if !slices.Equal(mounted, []string{"server", "easypatch-worker"}) {
		t.Errorf("the updater's status is mounted into %v, want the server and the engine's worker", mounted)
	}
}

var variable = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)(?:(:?[-?])([^}]*))?\}`)

// interpolate substitutes ${VAR}, ${VAR:-default}, ${VAR-default},
// ${VAR:?message} and ${VAR?message} as Compose does.
func interpolate(raw string, vars map[string]string) (string, error) {
	var err error
	out := variable.ReplaceAllStringFunc(raw, func(m string) string {
		p := variable.FindStringSubmatch(m)
		v, set := vars[p[1]]
		switch p[2] {
		case ":-":
			if v == "" {
				return p[3]
			}
		case "-":
			if !set {
				return p[3]
			}
		case ":?", "?":
			if !set || (p[2] == ":?" && v == "") {
				err = fmt.Errorf("%s: %s", p[1], p[3])
			}
		}
		return v
	})
	return out, err
}

// TestComposeListeners keeps every service of deploy/docker-compose.yml on
// host networking, every listener but the server's public edge on loopback,
// and no two listeners on one port (docs/architecture/network.md):
// with host networking a collision is a service that fails to start, or a
// health check that reaches the wrong program.
func TestComposeListeners(t *testing.T) {
	b, err := os.ReadFile(composeFile)
	if err != nil {
		t.Fatal(err)
	}
	compose := string(b)

	// Every service runs on the host's network, and none maps ports.
	_, section, ok := strings.Cut(compose, "\nservices:\n")
	if !ok {
		t.Fatalf("no services in %s", composeFile)
	}
	if end := regexp.MustCompile(`(?m)^[a-z]`).FindStringIndex(section); end != nil {
		section = section[:end[0]]
	}
	services := regexp.MustCompile(`(?m)^  ([a-z][a-z0-9-]*):$`).FindAllStringSubmatch(section, -1)
	if len(services) < 7 {
		t.Fatalf("found %d services in %s", len(services), composeFile)
	}
	blocks := regexp.MustCompile(`(?m)^  [a-z][a-z0-9-]*:$`).Split(section, -1)[1:]
	for i, s := range services {
		if !strings.Contains(blocks[i], "\n    network_mode: host\n") {
			t.Errorf("service %s does not use host networking", s[1])
		}
		if strings.Contains(blocks[i], "\n    ports:") {
			t.Errorf("service %s maps ports", s[1])
		}
	}

	// A required variable (${X:?}) in the patching engine's services would
	// stop, with Compose's terse message, an install whose .env predates
	// it; setup.sh adds what is missing, and EasyRMM explains a missing key.
	if m := regexp.MustCompile(`\$\{EASYPATCH_[A-Z_]+:?\?`).FindString(compose); m != "" {
		t.Errorf("%s marks %s… required: an install whose .env predates it could not start", composeFile, m)
	}
	if m := regexp.MustCompile(`\$\{(?:EASYRMM_)?AUTHENTIK_[A-Z_]+:?\?`).FindString(compose); m != "" {
		t.Errorf("%s marks %s… required: an install without the authentik profile could not start", composeFile, m)
	}

	c, err := LoadFrom(env(map[string]string{
		"EASYRMM_PUBLIC_URL": "https://rmm.example.com", "EASYRMM_ACME_EMAIL": "ops@example.com",
		"EASYRMM_DATABASE_URL": "postgres://a@127.0.0.1/x", "EASYRMM_DATABASE_MIGRATION_URL": "postgres://o@127.0.0.1/x",
		"EASYRMM_SECRET_KEY": testKey, "EASYRMM_PATCHING_KEY": testKey,
	}), noFiles)
	if err != nil {
		t.Fatal(err)
	}
	url := func(service string) string {
		raw := composeEnvironment(t, service)["ASPNETCORE_URLS"]
		if empty, ok := composeEnvironment(t, service)["ASPNETCORE_HTTP_PORTS"]; !ok || empty != `""` && empty != "" {
			t.Errorf("%s does not empty ASPNETCORE_HTTP_PORTS, which binds every interface", service)
		}
		return strings.TrimPrefix(raw, "http://")
	}
	mesh := regexp.MustCompile(`http://(127\.0\.0\.1:\d+)/health\.ashx`).FindStringSubmatch(compose)
	pg := regexp.MustCompile(`listen_addresses=(\S+)\n\s+- -c\n\s+- port=(\d+)`).FindStringSubmatch(compose)
	if mesh == nil || pg == nil {
		t.Fatalf("cannot find MeshCentral's or PostgreSQL's listener in %s", composeFile)
	}
	loopback := map[string]string{
		"EasyRMM health":         c.ListenHealth,
		"EasyRMM offload":        c.ListenOffload,
		"MeshCentral":            mesh[1],
		"PostgreSQL":             net.JoinHostPort(pg[1], pg[2]),
		"patching engine API":    url("easypatch-api"),
		"patching engine worker": url("easypatch-worker"),
		"Authentik, HTTP":        composeEnvironment(t, "authentik-server")["AUTHENTIK_LISTEN__HTTP"],
		"Authentik, HTTPS":       composeEnvironment(t, "authentik-server")["AUTHENTIK_LISTEN__HTTPS"],
		"Authentik's worker":     composeEnvironment(t, "authentik-worker")["AUTHENTIK_LISTEN__HTTP"],
	}
	byPort := map[string]string{}
	for name, addr := range loopback {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			t.Errorf("%s: %q: %v", name, addr, err)
			continue
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			t.Errorf("%s listens on %s, beyond loopback", name, addr)
		}
		if other, taken := byPort[port]; taken {
			t.Errorf("%s and %s both listen on port %s", name, other, port)
		}
		byPort[port] = name
	}
	for _, public := range []string{c.ListenHTTPS, c.ListenHTTP} {
		_, port, _ := net.SplitHostPort(public)
		if other, taken := byPort[port]; taken {
			t.Errorf("the public edge and %s both use port %s", other, port)
		}
	}
	// Authentik has no metrics listener, and the edge forwards its name where
	// it listens.
	if !strings.Contains(compose, "\n  AUTHENTIK_LISTEN__METRICS: \"\"\n") {
		t.Errorf("%s does not empty AUTHENTIK_LISTEN__METRICS, which would listen on every interface", composeFile)
	}
	if got := composeEnvironment(t, "authentik-server")["AUTHENTIK_LISTEN__HTTP"]; got != DefaultAuthentikUpstream {
		t.Errorf("Authentik listens on %s, but EasyRMM's edge forwards to %s", got, DefaultAuthentikUpstream)
	}
	// EasyRMM calls the engine where Compose has it listen.
	if engine := "http://" + url("easypatch-api"); engine != DefaultPatchingURL {
		t.Errorf("the engine listens on %s, but EasyRMM calls %s", engine, DefaultPatchingURL)
	}
	// Both programs read the one key. The engine always runs: no profile
	// leaves it out, and EASYRMM_PATCHING is not a setting.
	server := composeEnvironment(t, "server")
	if got := server["EASYRMM_PATCHING_KEY"]; got != "${EASYRMM_PATCHING_KEY:-}" {
		t.Errorf("server: EASYRMM_PATCHING_KEY is %q", got)
	}
	if _, ok := server["EASYRMM_PATCHING"]; ok {
		t.Error("server: EASYRMM_PATCHING is passed, but it is no longer a setting")
	}
	if strings.Contains(compose, "[patching]") {
		t.Errorf("%s puts the patching engine in a profile: it runs in every install", composeFile)
	}
	if got := composeEnvironment(t, "easypatch-api")["EasyRmm__GatewayKey"]; got != "${EASYRMM_PATCHING_KEY:-}" {
		t.Errorf("easypatch-api: EasyRmm__GatewayKey is %q", got)
	}
	// Only the API checks statements: nothing else of the engine holds the key.
	if n := strings.Count(compose, "${EASYRMM_PATCHING_KEY"); n != 2 {
		t.Errorf("EASYRMM_PATCHING_KEY is passed %d times in %s, want 2 (server and easypatch-api)", n, composeFile)
	}
}
