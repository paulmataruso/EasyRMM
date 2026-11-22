// Package m365test has stand-ins for Microsoft, for tests of signing in to
// Microsoft 365 for mail (ADR-0053, slice 2): a token endpoint that grants
// an application's client credentials as the Microsoft identity platform
// does, and an SMTP server that takes AUTH XOAUTH2 with its tokens as
// Exchange Online does. Neither is Microsoft: their replies follow
// Microsoft's documentation and what its forums report, and the real ones
// are checked by hand against a tenant.
//
// Their certificates come from an authority made for the test process,
// which Trust adds to the system's for that process (SSL_CERT_FILE), so
// that EasyRMM's code trusts them as it trusts Microsoft's: through the
// system's roots, with nothing configured.
package m365test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TenantID, ClientID and Mailbox are made up: an obviously fake tenant and
// application, and a mailbox at a reserved domain.
const (
	TenantID = "00000000-0000-4000-8000-00000000a001"
	ClientID = "00000000-0000-4000-8000-00000000c001"
	Mailbox  = "rmm@m365.example.com"
	// Secret is the application's client secret, as Entra makes them: 40
	// characters.
	Secret = "STAND-IN~secret.0123456789abcdefghijklmn"
)

// authority is the process's certificate authority for the stand-ins.
type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

var ca = sync.OnceValue(func() *authority {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "EasyRMM test stand-ins for Microsoft"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return &authority{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
})

// CAPEM is the stand-ins' certificate authority.
func CAPEM() []byte { return ca().pem }

// Trust has the process trust the stand-ins' authority, and extra (PEM),
// in place of the system's roots: it writes them to a file and names it in
// SSL_CERT_FILE. Call it from TestMain, before anything reads the system's
// roots.
func Trust(extra ...[]byte) error {
	dir, err := os.MkdirTemp("", "easyrmm-m365test-")
	if err != nil {
		return err
	}
	bundle := append([]byte{}, CAPEM()...)
	for _, e := range extra {
		bundle = append(append(bundle, '\n'), e...)
	}
	path := filepath.Join(dir, "roots.pem")
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		return err
	}
	return os.Setenv("SSL_CERT_FILE", path)
}

var serial = struct {
	sync.Mutex
	n int64
}{n: 1}

func nextSerial() *big.Int {
	serial.Lock()
	defer serial.Unlock()
	serial.n++
	return big.NewInt(serial.n)
}

// ServerTLS is a TLS configuration with a certificate for this machine's
// loopback addresses and localhost, from the stand-ins' authority.
func ServerTLS() *tls.Config {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	a := ca()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		panic(err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

// rsaKeys are the applications' keys: made once a process, as RSA keys are
// slow to make.
var rsaKeys = sync.OnceValue(func() [2]*rsa.PrivateKey {
	var keys [2]*rsa.PrivateKey
	for i := range keys {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		keys[i] = k
	}
	return keys
})

// AppCertificate is a self-signed RSA certificate for the application,
// valid from notBefore to notAfter, as an administrator makes one to
// upload to Entra, and its key, PEM. Every certificate uses the same key;
// OtherKey is another.
func AppCertificate(t testing.TB, notBefore, notAfter time.Time) (certPEM, keyPEM string) {
	t.Helper()
	key := rsaKeys()[0]
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      pkix.Name{CommonName: "EasyRMM mail (stand-in)"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}))
}

// OtherKey is an RSA key that is no AppCertificate's, PEM (PKCS #1).
func OtherKey() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKeys()[1])}))
}

// ParsePEMCertificate reads the first certificate of a PEM.
func ParsePEMCertificate(t testing.TB, certPEM string) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode([]byte(certPEM))
	if b == nil {
		t.Fatal("no PEM certificate")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// x5tS256 is a certificate's SHA-256 thumbprint, base64url.
func x5tS256(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// verifyPS256 checks a PS256 signature over signed.
func verifyPS256(pub *rsa.PublicKey, signed string, sig []byte) error {
	sum := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPSS(pub, crypto.SHA256, sum[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		return fmt.Errorf("PS256: %w", err)
	}
	return nil
}
