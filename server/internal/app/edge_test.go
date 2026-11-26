package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/tlscert"
	"github.com/paulmataruso/easyrmm/server/internal/updater"
)

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	pub, _ := url.Parse("https://rmm.test")
	mesh, _ := url.Parse("https://mesh.rmm.test")
	return &config.Config{PublicURL: pub, MeshPublicURL: mesh, ListenHTTPS: ":443", DataDir: t.TempDir(), Mesh: config.MeshConfig{Enabled: true}, IPMeshPort: 4443}
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// notHeld is the hold of a server without the updater.
func notHeld(t *testing.T) *updater.Hold {
	t.Helper()
	return updater.NewHold(filepath.Join(t.TempDir(), "no-updater"), discard())
}

// held is the hold of a server the updater held before it started.
func held(t *testing.T) *updater.Hold {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, updater.HoldFile), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h := updater.NewHold(dir, discard())
	if !h.Held() {
		t.Fatal("not held")
	}
	return h
}

// wantHeld checks that a listener answered as a held server does.
func wantHeld(t *testing.T, what string, resp httpResult, body string) {
	t.Helper()
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" || !strings.Contains(body, `"code":"held"`) {
		t.Errorf("%s while held: %d %q %q", what, resp.StatusCode, resp.Header.Get("Retry-After"), body)
	}
}

func TestKnownHostAndHostOnly(t *testing.T) {
	cfg := testConfig(t)
	for host, want := range map[string]bool{
		"rmm.test": true, "RMM.Test": true, "rmm.test.": true, "mesh.rmm.test": true,
		"evil.test": false, "": false, "rmm.test.evil": false,
	} {
		if got := knownHost(cfg, host); got != want {
			t.Errorf("knownHost(%q) = %v, want %v", host, got, want)
		}
	}
	cfg.Patching.AgentHostnames = []string{"patch.old.test"}
	if !knownHost(cfg, "Patch.Old.Test.") || knownHost(cfg, "old.test") {
		t.Error("an imported EasyPatch's name")
	}
	cfg.MeshPublicURL = nil
	if knownHost(cfg, "mesh.rmm.test") {
		t.Error("mesh host known without a mesh URL")
	}
	cfg.PublicURL = nil
	if knownHost(cfg, "rmm.test") {
		t.Error("host known without a public URL")
	}
	if hostOnly("rmm.test:8080") != "rmm.test" || hostOnly("rmm.test") != "rmm.test" || hostOnly("[::1]:80") != "::1" {
		t.Error("hostOnly")
	}
}

func TestRedirectHandler(t *testing.T) {
	cfg := testConfig(t)
	cases := []struct {
		listen, host, path string
		status             int
		location           string
	}{
		{":443", "rmm.test", "/a?b=1", http.StatusPermanentRedirect, "https://rmm.test/a?b=1"},
		{":443", "RMM.test:80", "/", http.StatusPermanentRedirect, "https://rmm.test/"},
		{":443", "mesh.rmm.test", "/x", http.StatusPermanentRedirect, "https://mesh.rmm.test/x"},
		{":8443", "rmm.test", "/a", http.StatusPermanentRedirect, "https://rmm.test:8443/a"},
		{"bogus", "rmm.test", "/a", http.StatusPermanentRedirect, "https://rmm.test/a"},
		{":443", "evil.test", "/", http.StatusMisdirectedRequest, ""},
	}
	for _, c := range cases {
		cfg.ListenHTTPS = c.listen
		req := httptest.NewRequest(http.MethodGet, c.path, nil)
		req.Host = c.host
		rec := httptest.NewRecorder()
		redirectHandler(cfg).ServeHTTP(rec, req)
		if rec.Code != c.status || rec.Header().Get("Location") != c.location {
			t.Errorf("%s %s%s: %d %q", c.listen, c.host, c.path, rec.Code, rec.Header().Get("Location"))
		}
	}
}

// writeCert writes a self-signed certificate and key for name.
func writeCert(t *testing.T, dir, name string) (certFile, keyFile string, der []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, der
}

func TestCertReloader(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, der1 := writeCert(t, dir, "rmm.test")
	var logs bytes.Buffer
	r, err := newCertReloader(certFile, keyFile, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := r.get(nil)
	if !bytes.Equal(c.Certificate[0], der1) {
		t.Fatal("initial certificate not served")
	}

	// A renewed certificate is picked up once the check interval passes.
	r.interval = 0
	_, _, der2 := writeCert(t, dir, "rmm.test")
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(certFile, future, future); err != nil {
		t.Fatal(err)
	}
	c, _ = r.get(nil)
	if !bytes.Equal(c.Certificate[0], der2) {
		t.Fatal("renewed certificate not picked up")
	}
	if !strings.Contains(logs.String(), "reloaded TLS certificate") {
		t.Fatalf("reload not logged: %s", logs.String())
	}

	// A broken renewal keeps the previous certificate in service.
	if err := os.WriteFile(certFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	later := future.Add(time.Minute)
	if err := os.Chtimes(certFile, later, later); err != nil {
		t.Fatal(err)
	}
	c, _ = r.get(nil)
	if !bytes.Equal(c.Certificate[0], der2) {
		t.Fatal("broken renewal replaced the working certificate")
	}
	if !strings.Contains(logs.String(), "still serving the previous one") {
		t.Fatalf("failed reload not logged: %s", logs.String())
	}

	// Within the interval, the file is not even checked.
	r.interval = time.Hour
	r.checked = time.Now()
	if c, _ = r.get(nil); !bytes.Equal(c.Certificate[0], der2) {
		t.Fatal("certificate changed within the check interval")
	}

	if _, err := newCertReloader(filepath.Join(dir, "missing.pem"), keyFile, discard()); err == nil {
		t.Fatal("missing certificate accepted")
	}
	if _, err := newCertReloader(certFile, keyFile, discard()); err == nil {
		t.Fatal("broken certificate accepted")
	}
}

func TestQuietTLSErrors(t *testing.T) {
	var buf bytes.Buffer
	warnOnly := slog.NewLogLogger(quietTLSErrors{slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})}, slog.LevelDebug)
	warnOnly.Print("http: TLS handshake error from 1.2.3.4:5: EOF")
	if buf.Len() != 0 {
		t.Fatalf("handshake noise logged at warn level: %s", buf.String())
	}
	warnOnly.Print("http: Accept error: too many open files")
	if !strings.Contains(buf.String(), "level=WARN") || !strings.Contains(buf.String(), "Accept error") {
		t.Fatalf("server error not logged as warning: %s", buf.String())
	}
	buf.Reset()
	debug := slog.NewLogLogger(quietTLSErrors{slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})}, slog.LevelInfo)
	debug.Print("http: TLS handshake error from 1.2.3.4:5: EOF")
	if !strings.Contains(buf.String(), "level=DEBUG") {
		t.Fatalf("handshake noise not kept at debug level: %s", buf.String())
	}
}

func TestBaseTLSAndLogger(t *testing.T) {
	c := baseTLS()
	if c.MinVersion != tls.VersionTLS12 || len(c.NextProtos) != 2 || c.NextProtos[0] != "h2" {
		t.Fatalf("baseTLS = %+v", c)
	}
	if l := NewLogger("text", "debug"); !l.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("debug level not applied")
	}
	if l := NewLogger("json", "warn"); l.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("warn level not applied")
	}
	if l := NewLogger("json", "nonsense"); !l.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("unknown level should default to info")
	}
}

func TestWaitFor(t *testing.T) {
	calls := 0
	err := waitFor(context.Background(), discard(), "thing", func(context.Context) error { calls++; return nil })
	if err != nil || calls != 1 {
		t.Fatalf("immediate success: %v after %d calls", err, calls)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls = 0
	err = waitFor(ctx, discard(), "thing", func(context.Context) error { calls++; return errors.New("down") })
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("canceled wait: %v after %d calls", err, calls)
	}

	// One retry after the initial one-second delay.
	calls = 0
	start := time.Now()
	err = waitFor(context.Background(), discard(), "thing", func(context.Context) error {
		calls++
		if calls == 1 {
			return errors.New("not yet")
		}
		return nil
	})
	if err != nil || calls != 2 || time.Since(start) < 900*time.Millisecond {
		t.Fatalf("retry: %v after %d calls in %v", err, calls, time.Since(start))
	}
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("edge-ok")) })
}

// runEdge starts e in the background and returns a stop function that
// cancels it and waits for a clean return.
func runEdge(t *testing.T, e *edge) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.run(ctx) }()
	return func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("edge.run returned %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("edge did not shut down")
		}
	}
}

// httpResult is the part of a response the tests inspect; the body is read
// and closed inside get.
type httpResult struct {
	StatusCode int
	Header     http.Header
	TLS        *tls.ConnectionState
}

func get(t *testing.T, c *http.Client, rawURL, host string) (httpResult, string) {
	t.Helper()
	var resp *http.Response
	var err error
	for i := 0; i < 50; i++ { // the listener may not be up yet
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
		req.Host = host
		resp, err = c.Do(req)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return httpResult{StatusCode: resp.StatusCode, Header: resp.Header, TLS: resp.TLS}, string(b)
}

func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func TestEdgeOffload(t *testing.T) {
	cfg := testConfig(t)
	cfg.TLSMode = config.TLSOffload
	cfg.ListenOffload = reserveAddr(t)
	// Nobody else can take a reserved port before the edge listens on it.
	if ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", cfg.ListenOffload); err == nil {
		_ = ln.Close()
		t.Fatal("another listener took the reserved port")
	}
	stop := runEdge(t, &edge{cfg: cfg, handler: okHandler(), hold: notHeld(t), log: discard()})
	_, body := get(t, noRedirect(), "http://"+cfg.ListenOffload+"/", "rmm.test")
	if body != "edge-ok" {
		t.Fatalf("offload body %q", body)
	}
	stop()
}

func TestEdgeManualTLS(t *testing.T) {
	cfg := testConfig(t)
	cfg.TLSMode = config.TLSManual
	cfg.CertFile, cfg.KeyFile, _ = writeCert(t, t.TempDir(), "rmm.test")
	cfg.ListenHTTPS = reserveAddr(t)
	cfg.ListenHTTP = reserveAddr(t)
	stop := runEdge(t, &edge{cfg: cfg, handler: okHandler(), hold: notHeld(t), log: discard()})

	c := noRedirect()
	c.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "rmm.test"}} //nolint:gosec // self-signed test certificate
	resp, body := get(t, c, "https://"+cfg.ListenHTTPS+"/", "rmm.test")
	if body != "edge-ok" || resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		t.Fatalf("manual TLS: %q %+v", body, resp.TLS)
	}
	resp, _ = get(t, noRedirect(), "http://"+cfg.ListenHTTP+"/path", "rmm.test")
	_, port, _ := net.SplitHostPort(cfg.ListenHTTPS)
	if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != "https://rmm.test:"+port+"/path" {
		t.Fatalf("redirect: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	stop()

	// A name served besides the origins shares the certificate, which must
	// be valid for it.
	cfg.Patching.AgentHostnames = []string{"patch.old.test"}
	err := (&edge{cfg: cfg, handler: okHandler(), hold: notHeld(t), log: discard()}).run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not valid for patch.old.test") {
		t.Fatalf("manual mode with a certificate that does not cover every name: %v", err)
	}
	cfg.Patching.AgentHostnames = nil

	cfg.CertFile = filepath.Join(t.TempDir(), "missing.pem")
	if err := (&edge{cfg: cfg, handler: okHandler(), hold: notHeld(t), log: discard()}).run(context.Background()); err == nil {
		t.Fatal("manual mode without a certificate started")
	}
}

func TestCovers(t *testing.T) {
	certFile, keyFile, _ := writeCert(t, t.TempDir(), "*.old.test")
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := covers(&c, nil); err != nil {
		t.Fatal(err)
	}
	if err := covers(&c, []string{"patch.old.test", "agents.old.test"}); err != nil {
		t.Fatalf("a wildcard: %v", err)
	}
	c.Leaf = nil // parsed from the chain then
	err = covers(&c, []string{"patch.old.test", "a.b.old.test", "other.test"})
	if err == nil || !strings.Contains(err.Error(), "not valid for a.b.old.test, other.test") {
		t.Fatalf("names it does not cover: %v", err)
	}
	if err := covers(&tls.Certificate{Certificate: [][]byte{{1, 2}}}, []string{"x.test"}); err == nil {
		t.Fatal("a certificate that cannot be read")
	}
}

func TestEdgeACMEServesChallengesAndRedirects(t *testing.T) {
	cfg := testConfig(t)
	cfg.TLSMode = config.TLSAcme
	cfg.ACMEEmail = "ops@rmm.test"
	cfg.ACMEDirectory = "https://127.0.0.1:1/directory" // never contacted by this test
	cfg.ListenHTTPS = reserveAddr(t)
	cfg.ListenHTTP = reserveAddr(t)
	stop := runEdge(t, &edge{cfg: cfg, handler: okHandler(), hold: notHeld(t), log: discard()})
	resp, _ := get(t, noRedirect(), "http://"+cfg.ListenHTTP+"/x", "mesh.rmm.test")
	if resp.StatusCode != http.StatusPermanentRedirect || !strings.HasPrefix(resp.Header.Get("Location"), "https://mesh.rmm.test:") {
		t.Fatalf("acme redirect: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// Unknown challenge tokens are not served.
	resp, _ = get(t, noRedirect(), "http://"+cfg.ListenHTTP+"/.well-known/acme-challenge/nope", "rmm.test")
	if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unknown challenge: %d", resp.StatusCode)
	}
	stop()
}

// TestEdgeHeld: while the updater holds the server, every listener answers
// 503 with Retry-After: HTTPS, MeshCentral's port and the redirects on
// port 80, but not ACME's challenges (ADR-0052).
func TestEdgeHeld(t *testing.T) {
	consoleAddr, meshAddr, httpAddr := reserveAddr(t), reserveAddr(t), reserveAddr(t)
	_, consolePort, _ := net.SplitHostPort(consoleAddr)
	_, meshPort, _ := net.SplitHostPort(meshAddr)
	cfg := testConfig(t)
	cfg.TLSMode = config.TLSManual
	cfg.CertFile, cfg.KeyFile, _ = writeCert(t, t.TempDir(), "127.0.0.1")
	cfg.PublicURL = mustURL("https://127.0.0.1:" + consolePort)
	cfg.MeshPublicURL = mustURL("https://127.0.0.1:" + meshPort)
	cfg.ListenHTTPS, cfg.ListenHTTP = consoleAddr, httpAddr
	stop := runEdge(t, &edge{cfg: cfg, handler: okHandler(), hold: held(t), log: discard()})
	c := noRedirect()
	c.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // self-signed test certificate
	for _, u := range []string{cfg.PublicURL.String() + "/", cfg.MeshPublicURL.String() + "/"} {
		resp, body := get(t, c, u, "")
		wantHeld(t, u, resp, body)
	}
	resp, body := get(t, noRedirect(), "http://"+httpAddr+"/devices", "127.0.0.1")
	wantHeld(t, "the redirect", resp, body)
	stop()

	acmeCfg := testConfig(t)
	acmeCfg.TLSMode = config.TLSAcme
	acmeCfg.ACMEEmail = "ops@rmm.test"
	acmeCfg.ACMEDirectory = "https://127.0.0.1:1/directory" // never contacted by this test
	acmeCfg.ListenHTTPS = reserveAddr(t)
	acmeCfg.ListenHTTP = reserveAddr(t)
	// The certificate service is not started: no challenge is known to it.
	svc := tlscert.New(tlscert.Deps{}, tlscert.Settings{Names: []string{"rmm.test"}})
	stop = runEdge(t, &edge{cfg: acmeCfg, handler: okHandler(), hold: held(t), log: discard(), tls: svc})
	defer stop()
	resp, body = get(t, noRedirect(), "http://"+acmeCfg.ListenHTTP+"/x", "rmm.test")
	wantHeld(t, "ACME's redirect", resp, body)
	// ACME's challenges are answered: this token is unknown.
	resp, _ = get(t, noRedirect(), "http://"+acmeCfg.ListenHTTP+"/.well-known/acme-challenge/nope", "rmm.test")
	if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("an ACME challenge while held: %d", resp.StatusCode)
	}
}

func TestEdgeErrors(t *testing.T) {
	cfg := testConfig(t)
	cfg.TLSMode = "bogus"
	if err := (&edge{cfg: cfg, handler: okHandler(), hold: notHeld(t), log: discard()}).run(context.Background()); err == nil {
		t.Fatal("unsupported mode started")
	}

	// A port already in use fails start-up cleanly.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg.TLSMode = config.TLSOffload
	cfg.ListenOffload = ln.Addr().String()
	err = (&edge{cfg: cfg, handler: okHandler(), hold: notHeld(t), log: discard()}).run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "listening on") {
		t.Fatalf("busy port: %v", err)
	}
}
