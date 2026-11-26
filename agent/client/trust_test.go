package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return testCA{cert: c, key: key}
}

func (ca testCA) pemFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// server answers 204 to everything over TLS with a certificate this CA
// issued for localhost.
func (ca testCA) server(t *testing.T) *httptest.Server {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func reaches(c *Client, s *httptest.Server) error {
	resp, err := c.http.Load().Get(s.URL)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

func newClientFor(t *testing.T, s *httptest.Server, caFile string, system bool) *Client {
	t.Helper()
	c, err := New(Options{Server: "https://" + s.Listener.Addr().String(), CAFile: caFile, TrustSystem: system, Version: "t"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// With a CA file alone only that authority is trusted; widened (Retrust), the
// system's roots are trusted too and the file still is.
func TestRetrustTrustsTheSystemAndTheFileTogether(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the system's roots come from the platform here; the Windows job covers it")
	}
	if os.Getenv("EASYRMM_TEST_SYSTEM_ROOTS_CHILD") == "" {
		// Go reads the system's roots once per process, and other tests may
		// have: run this one alone in a process of its own.
		cmd := exec.Command(os.Args[0], "-test.run", "^TestRetrustTrustsTheSystemAndTheFileTogether$", "-test.count=1") //nolint:gosec // this test binary
		cmd.Env = append(os.Environ(), "EASYRMM_TEST_SYSTEM_ROOTS_CHILD=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return
	}
	private, public := newTestCA(t), newTestCA(t)
	other := newTestCA(t)
	// The "system": the roots Go reads from SSL_CERT_FILE, loaded at first use.
	t.Setenv("SSL_CERT_FILE", public.pemFile(t))
	t.Setenv("SSL_CERT_DIR", t.TempDir())
	onPrivate, onPublic, onOther := private.server(t), public.server(t), other.server(t)

	c := newClientFor(t, onPrivate, private.pemFile(t), false)
	if reaches(c, onPrivate) != nil {
		t.Fatal("a server under the CA file is refused")
	}
	if reaches(c, onPublic) == nil {
		t.Fatal("the system's authority is trusted before the trust is widened")
	}

	if err := c.Retrust(private.pemFile(t), true); err != nil {
		t.Fatal(err)
	}
	if err := reaches(c, onPrivate); err != nil {
		t.Errorf("the CA file stopped being trusted: %v", err)
	}
	if err := reaches(c, onPublic); err != nil {
		t.Errorf("the system's roots are not trusted after widening: %v", err)
	}
	if reaches(c, onOther) == nil {
		t.Error("an unknown authority is trusted after widening")
	}

	// The same from the start, as a restart reads the saved configuration.
	c2 := newClientFor(t, onPrivate, private.pemFile(t), true)
	if reaches(c2, onPublic) != nil || reaches(c2, onPrivate) != nil || reaches(c2, onOther) == nil {
		t.Error("a client made widened does not trust both and nothing else")
	}
}

// The widened check names the host the client was made for, an IP address
// included, and not the connection's server name.
func TestWidenedTrustChecksTheHost(t *testing.T) {
	ca := newTestCA(t)
	s := ca.server(t)
	// The certificate is valid for localhost and 127.0.0.1.
	c := newClientFor(t, s, ca.pemFile(t), true)
	if err := reaches(c, s); err != nil {
		t.Fatalf("by IP address: %v", err)
	}
	port := s.Listener.Addr().(*net.TCPAddr).Port
	byName, err := New(Options{Server: "https://localhost:" + itoa(port), CAFile: ca.pemFile(t), TrustSystem: true, Version: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if err := reaches(byName, s); err != nil {
		t.Fatalf("by name: %v", err)
	}
	elsewhere, err := New(Options{Server: "https://other.example.com:" + itoa(port), CAFile: ca.pemFile(t), TrustSystem: true, Version: "t"})
	if err != nil {
		t.Fatal(err)
	}
	// Dialed at the test server, but the client was made for another name.
	elsewhere.http.Load().Transport.(*http.Transport).DialContext = func(ctx context.Context, n, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, n, s.Listener.Addr().String())
	}
	resp, err := elsewhere.http.Load().Get("https://other.example.com:" + itoa(port))
	if err == nil {
		_ = resp.Body.Close()
		t.Error("a certificate for another host was accepted")
	}
	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{ca.cert}}
	if verifyEither(x509.NewCertPool(), "localhost")(tls.ConnectionState{}) == nil || verifyEither(x509.NewCertPool(), "")(cs) == nil {
		t.Error("a connection with no certificate, or a client with no host, verified")
	}
}

func TestRetrustKeepsATestTransport(t *testing.T) {
	c, err := New(Options{Server: "https://example.com", Transport: http.DefaultTransport, Version: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Retrust("/does/not/exist", true); err != nil {
		t.Errorf("a client with a transport of its own was changed: %v", err)
	}
}

func TestRetrustFailsOnAMissingCAFile(t *testing.T) {
	c, err := New(Options{Server: "https://example.com", Version: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Retrust(filepath.Join(t.TempDir(), "none.pem"), true) == nil {
		t.Error("no error for a CA file that is not there")
	}
}

func itoa(n int) string { return big.NewInt(int64(n)).String() }
