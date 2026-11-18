// Package meshtest locates the disposable MeshCentral that integration tests
// run against (scripts/test-meshcentral.sh, `make test-mesh`).
package meshtest

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Environment variables printed by scripts/test-meshcentral.sh.
const (
	DirVar = "EASYRMM_TEST_MESH_DIR"
	URLVar = "EASYRMM_TEST_MESH_URL"
)

// Env is a running test MeshCentral.
type Env struct {
	// URL is its loopback HTTP address.
	URL string
	// Key is the login-cookie key it was configured with.
	Key []byte
	// Dir holds its config.json.
	Dir string
	// Hostname and PublicPort are where agents are told to connect: the
	// test serves the EasyRMM gateway there, with CertFile and KeyFile.
	Hostname   string
	PublicPort int
	CertFile   string
	KeyFile    string
}

// Get returns the test MeshCentral. Like the database helper, a missing
// environment fails the test rather than skipping it, so CI cannot pass
// without running the MeshCentral tests.
func Get(t testing.TB) Env {
	t.Helper()
	dir, url := os.Getenv(DirVar), os.Getenv(URLVar)
	if dir == "" || url == "" {
		t.Fatalf("%s and %s are not set; run `make test-mesh` and export the printed values", DirVar, URLVar)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "key.hex")) //nolint:gosec // test environment directory from the test runner
	if err != nil {
		t.Fatalf("meshtest: reading key: %v", err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("meshtest: decoding key: %v", err)
	}
	var cfg struct {
		Settings struct {
			Cert      string `json:"cert"`
			AliasPort int    `json:"aliasPort"`
		} `json:"settings"`
	}
	raw, err = os.ReadFile(filepath.Join(dir, "config.json")) //nolint:gosec // test environment directory from the test runner
	if err == nil {
		err = json.Unmarshal(raw, &cfg)
	}
	if err != nil {
		t.Fatalf("meshtest: reading config.json: %v", err)
	}
	return Env{
		URL: strings.TrimRight(url, "/"), Key: key, Dir: dir,
		Hostname: cfg.Settings.Cert, PublicPort: cfg.Settings.AliasPort,
		CertFile: filepath.Join(dir, "proxy-cert.pem"), KeyFile: filepath.Join(dir, "proxy-key.pem"),
	}
}
