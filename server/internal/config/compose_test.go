package config

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
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
	} {
		t.Run(c.name, func(t *testing.T) {
			dotenv := readDotenv(t, envExample)
			for k, v := range map[string]string{
				"EASYRMM_MESH_PUBLIC_URL": "", "POSTGRES_PASSWORD": "p", "EASYRMM_DB_OWNER_PASSWORD": "o",
				"EASYRMM_DB_APP_PASSWORD": "a", "EASYRMM_SECRET_KEY": testKey,
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
	"EASYRMM_WEB_DIR":              "the console is built into the binary",
	"EASYRMM_DATABASE_MAX_CONNS":   "sized to the postgres service's max_connections",
	"EASYRMM_LOG_FORMAT":           "JSON for docker logs",
	"EASYRMM_DEV_INSECURE_COOKIES": "development only",
	"EASYRMM_ARGON2_MAX_PARALLEL":  "bounds the memory password hashing takes; four suits the deployment",
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
