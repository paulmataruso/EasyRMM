//go:build integration

package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

// setEnv configures a complete, valid offload-mode server against a fresh
// test database. The server listens on ports the kernel picks when it binds
// them (serverListeners reads them back): a port picked here and closed for
// the server to bind later can be taken in between, by a test in another
// package, whose server then answers this test's requests.
func setEnv(t *testing.T) {
	t.Helper()
	inst := testdb.New(t)
	sep := "?"
	if strings.Contains(inst.SuperDSN, "?") {
		sep = "&"
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	for k, v := range map[string]string{
		"EASYRMM_PUBLIC_URL":             "https://rmm.test",
		"EASYRMM_TLS_MODE":               "offload",
		"EASYRMM_TRUSTED_PROXIES":        "127.0.0.1",
		"EASYRMM_LISTEN_OFFLOAD":         "127.0.0.1:0",
		"EASYRMM_LISTEN_HEALTH":          "127.0.0.1:0",
		"EASYRMM_SECRET_KEY":             base64.StdEncoding.EncodeToString(key),
		"EASYRMM_PATCHING_KEY":           base64.StdEncoding.EncodeToString(key),
		"EASYRMM_PATCHING_URL":           "http://" + unusedAddr(t), // no engine: patching is unavailable
		"EASYRMM_DATABASE_URL":           inst.SuperDSN + sep + "role=easyrmm_app",
		"EASYRMM_DATABASE_MIGRATION_URL": inst.SuperDSN + sep + "role=easyrmm_owner",
		"EASYRMM_DATA_DIR":               t.TempDir(),
		"EASYRMM_LOG_FORMAT":             "text",
		"EASYRMM_LOG_LEVEL":              "error",
	} {
		t.Setenv(k, v)
	}
}

// serverListeners captures what the server logs to os.Stderr, as JSON from
// the info level, until the test ends, and sends the addresses its edge and
// its health endpoint report listening on. Errors, and output that is not a
// log record, still reach os.Stderr.
func serverListeners(t *testing.T) (edge, health <-chan string) {
	t.Helper()
	t.Setenv("EASYRMM_LOG_FORMAT", "json")
	t.Setenv("EASYRMM_LOG_LEVEL", "info")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := os.Stderr
	os.Stderr = w
	e, h := make(chan string, 1), make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(r)
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			var rec struct{ Level, Msg, Addr string }
			if json.Unmarshal(sc.Bytes(), &rec) != nil || strings.HasPrefix(rec.Level, "ERROR") {
				_, _ = fmt.Fprintln(stderr, sc.Text())
				continue
			}
			var to chan string // nil for any other record: never sent to
			switch rec.Msg {
			case "listening":
				to = e
			case "health endpoint listening":
				to = h
			}
			select {
			case to <- rec.Addr:
			default: // another record, or a second listener of the kind
			}
		}
		_, _ = io.Copy(stderr, r) // after a line too long to scan
	}()
	t.Cleanup(func() {
		os.Stderr = stderr
		_ = w.Close()
		<-done
		_ = r.Close()
	})
	return e, h
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
	setEnv(t)
	edgeAddr, healthAddr := serverListeners(t)
	done := make(chan int, 1)
	go func() { done <- run([]string{"serve"}) }()

	var offload, health string
	timeout := time.After(2 * time.Minute)
	for offload == "" || health == "" {
		select {
		case offload = <-edgeAddr:
		case health = <-healthAddr:
		case code := <-done:
			t.Fatalf("serve exited %d before listening", code)
		case <-timeout:
			t.Fatal("the server never reported its listeners")
		}
	}
	t.Setenv("EASYRMM_LISTEN_HEALTH", health) // for the healthcheck command
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
