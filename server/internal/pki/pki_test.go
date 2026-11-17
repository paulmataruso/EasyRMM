package pki

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

func newAuthority(t *testing.T, now time.Time) *Authority {
	t.Helper()
	m, err := generate(now)
	if err != nil {
		t.Fatal(err)
	}
	a, err := fromMaterial(m, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestServerCertificateChainsToAuthority(t *testing.T) {
	a := newAuthority(t, time.Now())
	if err := a.SetAddresses(context.Background(), []string{"RMM.example.com.", "rmm.example.com", "203.0.113.9", ""}, []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("::ffff:203.0.113.10"), net.ParseIP("2001:db8::10"), nil}); err != nil {
		t.Fatal(err)
	}
	c, err := a.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	leaf := c.Leaf
	if got := strings.Join(leaf.DNSNames, ","); got != "rmm.example.com" {
		t.Errorf("DNS names = %q", got)
	}
	if len(leaf.IPAddresses) != 2 {
		t.Errorf("IP addresses = %v", leaf.IPAddresses)
	}
	block, _ := pem.Decode(a.CAPEM())
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("CA PEM")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.IsCA || ca.MaxPathLen != 0 || !ca.MaxPathLenZero {
		t.Errorf("CA constraints: isCA=%v maxPath=%d", ca.IsCA, ca.MaxPathLen)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, name := range []string{"rmm.example.com", "203.0.113.10", "2001:db8::10"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); err != nil {
			t.Errorf("verify for %s: %v", name, err)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "203.0.113.11"}); err == nil {
		t.Error("certificate valid for an address it does not name")
	}
	if len(c.Certificate) != 2 {
		t.Errorf("chain length = %d, want leaf and CA", len(c.Certificate))
	}
	if got, _ := a.GetCertificate(&tls.ClientHelloInfo{}); got != c {
		t.Error("GetCertificate serves another certificate")
	}
}

// TestKeyPin checks the PowerShell pin: the hex SHA-256 of the public key
// point, the bytes .NET's X509Certificate.GetPublicKey returns.
func TestKeyPin(t *testing.T) {
	a := newAuthority(t, time.Now())
	pub, err := a.serverKey.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pub)
	if want := strings.ToUpper(hex.EncodeToString(sum[:])); a.KeyPin() != want || len(pub) != 65 {
		t.Errorf("KeyPin = %s, want %s", a.KeyPin(), want)
	}
	for _, bad := range [][]byte{nil, []byte("not DER"), append(append([]byte{}, mustSPKI(t, a)...), 0)} {
		if _, err := SPKIKeyPin(bad); err == nil {
			t.Errorf("SPKIKeyPin(%x) accepted", bad)
		}
	}
}

func mustSPKI(t *testing.T, a *Authority) []byte {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(&a.serverKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSetAddressesReissuesWithTheSameKey(t *testing.T) {
	a := newAuthority(t, time.Now())
	pin := a.Pin()
	if !regexp.MustCompile(`^sha256//[A-Za-z0-9+/]{43}=$`).MatchString(pin) {
		t.Fatalf("pin = %q", pin)
	}
	if err := a.SetAddresses(context.Background(), nil, []net.IP{net.ParseIP("203.0.113.10")}); err != nil {
		t.Fatal(err)
	}
	first, _ := a.Certificate()
	// The same addresses keep the certificate.
	if err := a.SetAddresses(context.Background(), nil, []net.IP{net.ParseIP("203.0.113.10")}); err != nil {
		t.Fatal(err)
	}
	if again, _ := a.Certificate(); again != first {
		t.Error("certificate reissued for unchanged addresses")
	}
	if err := a.SetAddresses(context.Background(), nil, []net.IP{net.ParseIP("203.0.113.11")}); err != nil {
		t.Fatal(err)
	}
	second, _ := a.Certificate()
	if second == first || second.Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber) == 0 {
		t.Fatal("certificate not reissued for new addresses")
	}
	if SPKIPin(second.Leaf.RawSubjectPublicKeyInfo) != pin || SPKIPin(first.Leaf.RawSubjectPublicKeyInfo) != pin {
		t.Error("the server key changed, so the pin did")
	}
	if kp, err := SPKIKeyPin(second.Leaf.RawSubjectPublicKeyInfo); err != nil || kp != a.KeyPin() {
		t.Errorf("key pin of the reissued certificate = %s, %v; want %s", kp, err, a.KeyPin())
	}
}

func TestCertificateRenewsBeforeExpiry(t *testing.T) {
	now := time.Now()
	a := newAuthority(t, now)
	first, err := a.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(leafLifetime); !first.Leaf.NotAfter.Equal(want.Truncate(time.Second)) && first.Leaf.NotAfter.Sub(want).Abs() > time.Second {
		t.Errorf("not after = %v, want about %v", first.Leaf.NotAfter, want)
	}
	a.now = func() time.Time { return now.Add(leafLifetime - renewBefore - time.Hour) }
	if c, _ := a.Certificate(); c != first {
		t.Error("renewed too early")
	}
	a.now = func() time.Time { return now.Add(leafLifetime - renewBefore + time.Hour) }
	renewed, _ := a.Certificate()
	if renewed == first || !renewed.Leaf.NotAfter.After(first.Leaf.NotAfter) {
		t.Error("not renewed within the renewal window")
	}
	// The server certificate never outlives the authority.
	a.now = func() time.Time { return now.Add(caLifetime - 24*time.Hour) }
	if err := a.SetAddresses(context.Background(), []string{"x.test"}, nil); err != nil {
		t.Fatal(err)
	}
	last, _ := a.Certificate()
	if last.Leaf.NotAfter.After(a.ca.NotAfter) {
		t.Errorf("leaf ends %v after the CA %v", last.Leaf.NotAfter, a.ca.NotAfter)
	}
}

func TestFingerprintAndMaterial(t *testing.T) {
	a := newAuthority(t, time.Now())
	if !regexp.MustCompile(`^([0-9A-F]{2}:){31}[0-9A-F]{2}$`).MatchString(a.Fingerprint()) {
		t.Errorf("fingerprint = %q", a.Fingerprint())
	}
	if _, err := fromMaterial(material{CACert: []byte("x")}, time.Now); err == nil {
		t.Error("bad CA certificate accepted")
	}
	m, _ := generate(time.Now())
	if _, err := fromMaterial(material{CACert: m.CACert, CAKey: []byte("x"), ServerKey: m.ServerKey}, time.Now); err == nil {
		t.Error("bad CA key accepted")
	}
	if _, err := fromMaterial(material{CACert: m.CACert, CAKey: m.CAKey, ServerKey: []byte("x")}, time.Now); err == nil {
		t.Error("bad server key accepted")
	}
}

// TestPinMatchesCurl checks the pin against curl itself: with the pin, curl
// connects although no CA vouches for the server (--insecure skips only
// that check); with another pin it refuses.
func TestPinMatchesCurl(t *testing.T) {
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl is not installed")
	}
	a := newAuthority(t, time.Now())
	if err := a.SetAddresses(context.Background(), nil, []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		t.Fatal(err)
	}
	// Not httptest's StartTLS: it adds its own certificate, which Go serves
	// to clients that send no server name, as clients of an IP address do.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: a.GetCertificate, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("pinned")) })}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()
	srvURL := "https://" + ln.Addr().String()

	run := func(pin string) (string, error) {
		out, err := exec.CommandContext(t.Context(), curl, "-fsS", "--insecure", "--pinnedpubkey", pin, srvURL).CombinedOutput() //nolint:gosec // test-controlled arguments
		return string(out), err
	}
	if out, err := run(a.Pin()); err != nil || out != "pinned" {
		t.Fatalf("curl with the pin: %v %q", err, out)
	}
	other := newAuthority(t, time.Now())
	if out, err := run(other.Pin()); err == nil {
		t.Fatalf("curl accepted another key's pin: %q", out)
	}
	// And the CA certificate is enough without --insecure.
	dir := t.TempDir()
	if err := writeFile(dir+"/ca.pem", a.CAPEM()); err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(t.Context(), curl, "-fsS", "--cacert", dir+"/ca.pem", srvURL).CombinedOutput() //nolint:gosec // test-controlled arguments
	if err != nil || string(out) != "pinned" {
		t.Fatalf("curl trusting the CA: %v %q", err, out)
	}
}

func writeFile(path string, b []byte) error { return os.WriteFile(path, b, 0o600) }
