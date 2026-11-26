//go:build integration

package tlscert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

// Pebble is Let's Encrypt's test CA (ARI included); the tests never contact
// the real one. Both containers run on host networking, never a bridge.
const (
	pebbleImage    = "ghcr.io/letsencrypt/pebble:2.8.0@sha256:d9080f68f6cb6af8d82134ab26de0aaaf312ac9cba42aecc6d3aede6cb63007b"
	challtestImage = "ghcr.io/letsencrypt/pebble-challtestsrv:2.8.0@sha256:c6ea5f6193517b3c7a02431b928234caf9db29a7a8abca4c0b337403468b650d"
)

// pebbleEnv is a Pebble with its mock DNS, and the ports the edge under test
// answers challenges on.
type pebbleEnv struct {
	t         *testing.T
	Directory string
	RootsPEM  []byte
	HTTPPort  string // Pebble validates HTTP-01 here
	TLSPort   string // and TLS-ALPN-01 here
	mgmt      string // the mock DNS's management API
	name      string // the container's name, for its log
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	return p
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// startPebble runs Pebble and the mock DNS it validates names through, where
// a name resolves to 127.0.0.1 unless made to point elsewhere. validity is
// the lifetime of the certificates it issues, in seconds.
func startPebble(t *testing.T, validity int) *pebbleEnv {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not available: the Pebble tests need it")
	}
	if os.Getenv("EASYRMM_TEST_NO_PEBBLE") != "" {
		t.Skip("EASYRMM_TEST_NO_PEBBLE is set")
	}
	e := &pebbleEnv{t: t, HTTPPort: freePort(t), TLSPort: freePort(t)}
	acmePort, mgmtPort, dnsPort, dnsMgmt := freePort(t), freePort(t), freePort(t), freePort(t)
	dir := t.TempDir()
	cfg := map[string]any{"pebble": map[string]any{
		"listenAddress": "127.0.0.1:" + acmePort, "managementListenAddress": "127.0.0.1:" + mgmtPort,
		"certificate": "test/certs/localhost/cert.pem", "privateKey": "test/certs/localhost/key.pem",
		"httpPort": atoi(e.HTTPPort), "tlsPort": atoi(e.TLSPort), "ocspResponderURL": "", "externalAccountBindingRequired": false,
		"domainBlocklist": []string{"blocked-domain.example"},
		"retryAfter":      map[string]int{"authz": 1, "order": 1},
		"profiles":        map[string]any{"default": map[string]any{"description": "test", "validityPeriod": validity}},
	}}
	raw, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(dir, "pebble-config.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprint(time.Now().UnixNano() % 1e9)
	dnsName, pebbleName := "le1-challtest-"+suffix, "le1-pebble-"+suffix
	e.name = pebbleName
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", "--tail", "60", pebbleName).CombinedOutput()
			t.Logf("pebble's log:\n%s", out)
		}
		_ = exec.Command("docker", "rm", "-f", dnsName, pebbleName).Run()
	})
	docker(t, "run", "-d", "--name", dnsName, "--network", "host", challtestImage,
		"-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", "", "-dns01", "127.0.0.1:"+dnsPort, "-management", "127.0.0.1:"+dnsMgmt, "-defaultIPv6", "")
	docker(t, "run", "-d", "--name", pebbleName, "--network", "host", "-e", "PEBBLE_VA_NOSLEEP=1", "-e", "PEBBLE_WFE_NONCEREJECT=0",
		"-v", dir+":/cfg:ro", pebbleImage, "-config", "/cfg/pebble-config.json", "-dnsserver", "127.0.0.1:"+dnsPort)
	e.Directory = "https://127.0.0.1:" + acmePort + "/dir"
	e.mgmt = "http://127.0.0.1:" + dnsMgmt
	// The roots to trust for Pebble's own HTTPS.
	id := docker(t, "create", pebbleImage)
	if out, err := exec.Command("docker", "cp", id+":/test/certs/pebble.minica.pem", filepath.Join(dir, "minica.pem")).CombinedOutput(); err != nil {
		t.Fatalf("docker cp: %v\n%s", err, out)
	}
	docker(t, "rm", id)
	e.RootsPEM, _ = os.ReadFile(filepath.Join(dir, "minica.pem"))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(e.RootsPEM)
	c := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	deadline := time.Now().Add(40 * time.Second)
	for {
		resp, err := c.Get(e.Directory)
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pebble did not come up: %v", err)
		}
		time.Sleep(300 * time.Millisecond)
	}
	return e
}

func atoi(s string) int {
	var n int
	_, _ = fmt.Sscanf(s, "%d", &n)
	return n
}

// pointAt makes the mock DNS answer an address for a name.
func (e *pebbleEnv) pointAt(name, addr string) {
	e.t.Helper()
	body := fmt.Sprintf(`{"host":%q,"addresses":[%q]}`, name, addr)
	resp, err := http.Post(e.mgmt+"/add-a", "application/json", strings.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
}

func (e *pebbleEnv) pointBack(name string) {
	e.t.Helper()
	resp, err := http.Post(e.mgmt+"/clear-a", "application/json", strings.NewReader(fmt.Sprintf(`{"host":%q}`, name)))
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
}

// log is what Pebble has logged so far.
func (e *pebbleEnv) log() string {
	out, _ := exec.Command("docker", "logs", e.name).CombinedOutput()
	return string(out)
}

// orders counts the orders Pebble has been asked for.
func (e *pebbleEnv) orders() int { return strings.Count(e.log(), "Added order") }

// recorder collects what the service tells people.
type recorder struct {
	events []Event
}

func (r *recorder) Publish(_ context.Context, e Event) error {
	r.events = append(r.events, e)
	return nil
}

func (r *recorder) last(name string) *Event {
	for i := len(r.events) - 1; i >= 0; i-- {
		if r.events[i].Name == name {
			return &r.events[i]
		}
	}
	return nil
}

// fixture is a service against a real database and Pebble, behind the edge's
// own handlers on the ports Pebble validates through.
type fixture struct {
	t      *testing.T
	ctx    context.Context
	pb     *pebbleEnv
	inst   *testdb.Instance
	sealer *secrets.Sealer
	audit  *audit.Logger
	rec    *recorder
	svc    *Service
	held   bool
}

func newFixture(t *testing.T, pb *pebbleEnv, names []string, edit func(*Settings)) *fixture {
	t.Helper()
	f := &fixture{t: t, ctx: context.Background(), pb: pb, inst: testdb.New(t), rec: &recorder{}}
	f.sealer, _ = newSealer(t, "k1")
	f.audit = audit.New(f.inst.DB, nil)
	f.svc = f.build(names, edit)
	t.Cleanup(func() { f.svc.Close() })
	return f
}

// build makes a service over the same database, as a restart does.
func (f *fixture) build(names []string, edit func(*Settings)) *Service {
	set := Settings{
		Names: names, Directory: f.pb.Directory, RootsPEM: f.pb.RootsPEM, HTTPPort: f.pb.HTTPPort, TLSPort: f.pb.TLSPort,
		Interval: time.Second, RenewCheck: 400 * time.Millisecond, Instance: "test",
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
		Own: func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("127.0.0.1")} },
	}
	if edit != nil {
		edit(&set)
	}
	return New(Deps{DB: f.inst.DB, Sealer: f.sealer, Audit: f.audit, Alerts: f.rec, Log: discardLog(), Held: func() bool { return f.held }}, set)
}

// serve opens what the edge opens for the service: TLS with ALPN challenges
// on Pebble's TLS port, and HTTP-01 on its HTTP port. It stops with the test.
func (f *fixture) serve(svc *Service) {
	f.t.Helper()
	ctx, cancel := context.WithCancel(f.ctx)
	tlsLn, err := net.Listen("tcp", "127.0.0.1:"+f.pb.TLSPort)
	if err != nil {
		f.t.Fatal(err)
	}
	httpLn, err := net.Listen("tcp", "127.0.0.1:"+f.pb.HTTPPort)
	if err != nil {
		f.t.Fatal(err)
	}
	cfg := &tls.Config{GetCertificate: svc.GetCertificate, NextProtos: []string{"h2", "http/1.1", "acme-tls/1"}, MinVersion: tls.VersionTLS12}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	hs := &http.Server{Handler: svc.CheckHandler(ok), TLSConfig: cfg, ReadHeaderTimeout: 5 * time.Second}
	ps := &http.Server{Handler: svc.HTTPHandler(ok), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = hs.ServeTLS(tlsLn, "", "") }()
	go func() { _ = ps.Serve(httpLn) }()
	f.t.Cleanup(func() { cancel(); _ = hs.Close(); _ = ps.Close() })
	_ = ctx
	svc.Serving()
}

// alwaysLead is a scheduler that leads.
type alwaysLead struct{}

func (alwaysLead) Lead(context.Context) (bool, error) { return true, nil }

// tick makes one pass of the scheduler.
func (f *fixture) tick(svc *Service) { svc.tick(f.ctx, alwaysLead{}) }

// until runs tick until cond holds, failing at the deadline.
func (f *fixture) until(svc *Service, what string, within time.Duration, cond func() bool) {
	f.t.Helper()
	deadline := time.Now().Add(within)
	for {
		f.tick(svc)
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			f.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (f *fixture) row(svc *Service, name string) Row {
	f.t.Helper()
	r, err := svc.loadRow(f.ctx, name)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

// served is the serial a handshake for the name gets.
func (f *fixture) served(svc *Service, name string) string {
	f.t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c, err := svc.GetCertificate(&tls.ClientHelloInfo{ServerName: name, Conn: a})
	if err != nil {
		return ""
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		f.t.Fatal(err)
	}
	return serialHex(leaf)
}

func (f *fixture) auditCount(action string) int {
	var n int
	if err := f.inst.DB.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT count(*) FROM audit_log WHERE action = $1`, action).Scan(&n)
	}); err != nil {
		f.t.Fatal(err)
	}
	return n
}
