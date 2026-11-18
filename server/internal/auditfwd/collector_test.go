package auditfwd

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// collector is a syslog receiver on loopback: octet-counted frames over TCP
// or TLS, datagrams over UDP.
type collector struct {
	t        testing.TB
	port     int
	msgs     chan string
	ln       net.Listener
	pc       net.PacketConn
	mu       sync.Mutex
	conns    []net.Conn
	accepted atomic.Int32
	// closeOnAccept makes it close every connection at once.
	closeOnAccept atomic.Bool
}

func newCollector(t testing.TB, transport string, cfg *tls.Config) *collector {
	t.Helper()
	c := &collector{t: t, msgs: make(chan string, 10000)}
	if transport == UDP {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		c.pc, c.port = pc, pc.LocalAddr().(*net.UDPAddr).Port
		go func() {
			buf := make([]byte, 65536)
			for {
				n, _, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				c.msgs <- string(buf[:n])
			}
		}()
		t.Cleanup(c.close)
		return c
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if transport == TLS {
		ln = tls.NewListener(ln, cfg)
	}
	c.serve(ln)
	return c
}

// listenTCP starts a TCP collector on a given loopback port.
func listenTCP(t testing.TB, port int) (*collector, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	c := &collector{t: t, msgs: make(chan string, 10000)}
	c.serve(ln)
	return c, nil
}

func (c *collector) serve(ln net.Listener) {
	c.ln, c.port = ln, ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			c.accepted.Add(1)
			if c.closeOnAccept.Load() {
				_ = nc.Close()
				continue
			}
			c.mu.Lock()
			c.conns = append(c.conns, nc)
			c.mu.Unlock()
			go c.read(nc)
		}
	}()
	c.t.Cleanup(c.close)
}

func (c *collector) addr() string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(c.port)) }

// read parses octet-counted frames: LEN SP MSG.
func (c *collector) read(nc net.Conn) {
	r := bufio.NewReader(nc)
	for {
		digits, err := r.ReadString(' ')
		if err != nil {
			return
		}
		n, err := strconv.Atoi(digits[:len(digits)-1])
		if err != nil || n <= 0 || n > maxFrame {
			c.msgs <- "BAD FRAME " + digits
			_ = nc.Close()
			return
		}
		m := make([]byte, n)
		if _, err := io.ReadFull(r, m); err != nil {
			return
		}
		c.msgs <- string(m)
	}
}

func (c *collector) next(t testing.TB) string {
	t.Helper()
	select {
	case m := <-c.msgs:
		return m
	case <-time.After(10 * time.Second):
		t.Fatal("collector received nothing")
		return ""
	}
}

func (c *collector) none(t testing.TB, wait time.Duration) {
	t.Helper()
	select {
	case m := <-c.msgs:
		t.Fatalf("collector received %q", m)
	case <-time.After(wait):
	}
}

// drop closes the open connections, as a collector restarting would.
func (c *collector) drop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, nc := range c.conns {
		_ = nc.Close()
	}
	c.conns = nil
}

func (c *collector) close() {
	if c.ln != nil {
		_ = c.ln.Close()
	}
	if c.pc != nil {
		_ = c.pc.Close()
	}
	c.drop()
}

// testPKI is a certificate authority made for one test.
type testPKI struct {
	caPEM string
	ca    *x509.Certificate
	key   *ecdsa.PrivateKey
}

func newPKI(t testing.TB) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test collector CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	return &testPKI{caPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), ca: ca, key: key}
}

var serial atomic.Int64

// issue returns a certificate and key in PEM, and as a tls.Certificate.
func (p *testPKI) issue(t testing.TB, dns []string, ips []net.IP, client bool) (string, string, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	usage := x509.ExtKeyUsageServerAuth
	if client {
		usage = x509.ExtKeyUsageClientAuth
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1) + 1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: dns, IPAddresses: ips, ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}))
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, keyPEM, pair
}

// serverTLS is a collector's TLS configuration for 127.0.0.1, optionally
// requiring client certificates from the same authority.
func (p *testPKI) serverTLS(t testing.TB, requireClient bool) *tls.Config {
	_, _, pair := p.issue(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, false)
	cfg := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	if requireClient {
		pool := x509.NewCertPool()
		pool.AddCert(p.ca)
		cfg.ClientCAs, cfg.ClientAuth = pool, tls.RequireAndVerifyClientCert
	}
	return cfg
}

// closedPort returns a loopback port nothing listens on.
func closedPort(t testing.TB, network string) int {
	t.Helper()
	if network == "udp" {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := pc.LocalAddr().(*net.UDPAddr).Port
		_ = pc.Close()
		return port
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

var errTest = errors.New("test")
