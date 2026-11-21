// Command meshtestenv prepares the configuration for a disposable MeshCentral
// used by integration tests (scripts/test-meshcentral.sh). It writes
// config.json, the shared key (key.hex) and, unless a certificate URL is
// given, a self-signed certificate and key for the test's TLS front end,
// which MeshCentral reports to agents. Besides its public origin, the
// MeshCentral serves the IP-access origins in meshtest.IPOrigins, as
// EasyRMM's does with IP access.
//
// Test use only: the key is written in the clear.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral/meshtest"
)

func main() {
	dir := flag.String("dir", "", "directory to write into")
	listen := flag.String("listen", "127.0.0.1:24430", "MeshCentral listen address")
	host := flag.String("host", "mesh.rmm.localhost", "MeshCentral public hostname")
	origin := flag.String("origin", "https://rmm.localhost", "EasyRMM application origin")
	certURL := flag.String("cert-url", "", "certificate URL; default: a generated self-signed certificate")
	mountedAt := flag.String("mounted-at", "/easyrmm/config", "where dir is mounted inside the container")
	publicPort := flag.Int("public-port", 443, "HTTPS port agents are told to connect to")
	flag.Parse()
	if *dir == "" {
		fail(fmt.Errorf("-dir is required"))
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		fail(err)
	}
	key, err := meshcentral.NewKey()
	if err != nil {
		fail(err)
	}
	session := make([]byte, 32)
	if _, err := rand.Read(session); err != nil {
		fail(err)
	}
	if *certURL == "" {
		if err := writeCert(*dir, *host); err != nil {
			fail(err)
		}
		*certURL = "file://" + *mountedAt + "/proxy-cert.pem"
	}
	meshOrigins := append([]string{"https://" + net.JoinHostPort(*host, strconv.Itoa(*publicPort))}, meshtest.IPOrigins...)
	cfg := meshcentral.ServerConfig{
		Hostname: *host, Listen: *listen, PublicPort: *publicPort, TrustedProxy: "127.0.0.1",
		FramingOrigins: []string{*origin}, MeshOrigins: meshOrigins, CertURL: *certURL, LoginKey: key,
		SessionKey: hex.EncodeToString(session), ConfigMount: *mountedAt,
	}
	out, err := cfg.Render()
	if err != nil {
		fail(err)
	}
	if _, err := meshcentral.WriteWeb(*dir); err != nil {
		fail(err)
	}
	if _, err := meshcentral.WriteConfig(*dir, out); err != nil {
		fail(err)
	}
	// The container may run as another user; the files are test-only.
	if err := os.Chmod(filepath.Join(*dir, "config.json"), 0o644); err != nil { //nolint:gosec // test-only configuration with a throwaway key, read by the container
		fail(err)
	}
	for _, p := range []string{"web", "web/scripts"} {
		if err := os.Chmod(filepath.Join(*dir, p), 0o755); err != nil { //nolint:gosec // public scripts, read by the container
			fail(err)
		}
	}
	if err := os.Chmod(filepath.Join(*dir, "web", "scripts", "custom.js"), 0o644); err != nil { //nolint:gosec // a public script, read by the container
		fail(err)
	}
	if err := os.WriteFile(filepath.Join(*dir, "key.hex"), []byte(meshcentral.KeyHex(key)), 0o600); err != nil {
		fail(err)
	}
}

// writeCert writes a self-signed certificate (proxy-cert.pem) and its key
// (proxy-key.pem), which tests serve the EasyRMM gateway with. It names the
// public hostname and the addresses of meshtest.IPOrigins.
func writeCert(dir, host string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	var ips []net.IP
	for _, o := range meshtest.IPOrigins {
		u, err := url.Parse(o)
		if err != nil {
			return err
		}
		ips = append(ips, net.ParseIP(u.Hostname()))
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		IPAddresses:  ips,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "proxy-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "proxy-cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644) //nolint:gosec // a public certificate
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "meshtestenv:", err)
	os.Exit(1)
}
