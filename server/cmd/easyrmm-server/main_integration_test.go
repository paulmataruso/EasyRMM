//go:build integration

package main

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

// setEnv configures a complete, valid offload-mode server against a fresh
// test database and returns the offload and health addresses.
func setEnv(t *testing.T) (offload, health string) {
	t.Helper()
	inst := testdb.New(t)
	sep := "?"
	if strings.Contains(inst.SuperDSN, "?") {
		sep = "&"
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	offload, health = freeAddr(t), freeAddr(t)
	for k, v := range map[string]string{
		"EASYRMM_PUBLIC_URL":             "https://rmm.test",
		"EASYRMM_TLS_MODE":               "offload",
		"EASYRMM_TRUSTED_PROXIES":        "127.0.0.1",
		"EASYRMM_LISTEN_OFFLOAD":         offload,
		"EASYRMM_LISTEN_HEALTH":          health,
		"EASYRMM_SECRET_KEY":             base64.StdEncoding.EncodeToString(key),
		"EASYRMM_PATCHING_KEY":           base64.StdEncoding.EncodeToString(key),
		"EASYRMM_PATCHING_URL":           "http://" + freeAddr(t), // no engine: patching is unavailable
		"EASYRMM_DATABASE_URL":           inst.SuperDSN + sep + "role=easyrmm_app",
		"EASYRMM_DATABASE_MIGRATION_URL": inst.SuperDSN + sep + "role=easyrmm_owner",
		"EASYRMM_DATA_DIR":               t.TempDir(),
		"EASYRMM_LOG_FORMAT":             "text",
		"EASYRMM_LOG_LEVEL":              "error",
	} {
		t.Setenv(k, v)
	}
	return offload, health
}

func TestMigrateCommand(t *testing.T) {
	setEnv(t)
	if got := run([]string{"migrate"}); got != 0 {
		t.Fatalf("migrate = %d", got)
	}
	t.Setenv("EASYRMM_DATABASE_MIGRATION_URL", "postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=2")
	if got := run([]string{"migrate"}); got != 1 {
		t.Fatalf("migrate against an unreachable database = %d", got)
	}
}

func TestServeCommandStopsOnSignal(t *testing.T) {
	offload, _ := setEnv(t)
	done := make(chan int, 1)
	go func() { done <- run([]string{"serve"}) }()

	ready := false
	for i := 0; i < 200 && !ready; i++ {
		time.Sleep(50 * time.Millisecond)
		ready = run([]string{"healthcheck"}) == 0
	}
	if !ready {
		t.Fatal("server never became ready")
	}
	req, _ := http.NewRequest(http.MethodGet, "http://"+offload+"/api/v1/health", nil)
	req.Host = "rmm.test"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health through the server: %d", resp.StatusCode)
	}

	// The server traps SIGTERM (as sent by `docker stop`) and shuts down.
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exited %d", code)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("server did not stop on SIGTERM")
	}
}

func TestServeCommandFailsWithoutDatabase(t *testing.T) {
	setEnv(t)
	t.Setenv("EASYRMM_DATABASE_MIGRATION_URL", "postgres://%zz")
	if got := run(nil); got != 1 {
		t.Fatalf("serve with a broken migration URL = %d", got)
	}
}
